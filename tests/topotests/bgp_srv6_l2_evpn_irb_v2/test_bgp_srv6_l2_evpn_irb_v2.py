#!/usr/bin/env python
# SPDX-License-Identifier: ISC
# Copyright (c) 2026 Aviz Networks
#
# Test suite: SRv6 L2 EVPN IRB v2 -- Anycast GW + IPv6 IRB
#
# Topology:
#
#  CE1(10.0.1.10/24) CE4(2001:db8:1::10/64)    CE3(10.0.1.20/24) CE2(2001:db8:2::10/64)
#       |eth0              |eth0                      |eth0              |eth0
#       |eth1              |eth2                      |eth2              |eth1
#  PE1 (r1, AS 65001) ===SRv6 underlay=== PE2 (r2, AS 65002)
#    eth0 fd00::1/64                          eth0 fd00::2/64
#    br100 10.0.1.1/24  [anycast GW VLAN 100] br100 10.0.1.1/24  [anycast GW VLAN 100]
#    br200 2001:db8:1::1/64  [IPv6 VLAN 200]  br200 2001:db8:2::1/64  [IPv6 VLAN 200]
#    VRF-A (table 10)                          VRF-A (table 10)
#    locator fc00:1::/48                       locator fc00:2::/48
#
# Anycast GW (VLAN 100, IPv4):
#   Both PEs share the same GW IP (10.0.1.1/24) and MAC (00:00:5e:00:01:64) on br100.
#   CE1 (PE1) and CE3 (PE2) are in the same L2/L3 domain via EVI 100.
#
# Anycast GW (VLAN 100, IPv6):
#   Both PEs also share an IPv6 anycast GW (2001:db8:100::1/64, same MAC) on the
#   SAME br100 dual-stack bridge, to validate advertise-svi-ip over IPv6.
#
# IPv6 IRB (VLAN 200, pure IPv6):
#   PE1 br200: 2001:db8:1::1/64  CE4: 2001:db8:1::10/64
#   PE2 br200: 2001:db8:2::1/64  CE2: 2001:db8:2::10/64
#   Inter-subnet IPv6 routing via DT46 End.DT46 SID.
#
# SID allocation (VRF-level pool [1,999], per-EVI pool [1000,...), EVI order: 100 then 200):
#   PE1: DT46=fc00:1:0:1::
#        DT2U(100)=fc00:1:0:3e8::  DT2M(100)=fc00:1:0:3e9::
#        DT2U(200)=fc00:1:0:3ea::  DT2M(200)=fc00:1:0:3eb::
#   PE2: DT46=fc00:2:0:1::
#        DT2U(100)=fc00:2:0:3e8::  DT2M(100)=fc00:2:0:3e9::
#        DT2U(200)=fc00:2:0:3ea::  DT2M(200)=fc00:2:0:3eb::
#
# Route Targets:
#   EVI 100 L2:  65001:100   EVI 200 L2:  65001:150   VRF-A IRB: 65001:200
#
# Test cases:
#   --- Anycast GW (VLAN 100, IPv4) ---
#   TC16 - SID allocation: all 5 SIDs per PE (EVI 100 + EVI 200 + DT46)
#   TC17 - Anycast GW advertised: both PEs send Type-2 for 10.0.1.1 with GW flag
#   TC18 - CE3 local GW reachability: ARP for 10.0.1.1 resolved by PE2 (no BUM)
#   TC19 - CE1 <-> CE3 intra-subnet L2 ping (same VLAN 100, different PEs via DT2U)
#   TC20 - CE3 MAC appears in PE1 br100 FDB (installed from BGP Type-2)
#   TC21 - Anycast GW suppression: PE1 does NOT install PE2 anycast GW as remote neigh
#   --- IPv6 IRB (VLAN 200, pure IPv6) ---
#   TC22 - Type-2 MAC+IPv6 advertised with dual SIDs (DT2U EVI200 + DT46 VRF-A)
#   TC23 - VRF-A /128 IPv6 host route with SRv6 encap (no MPLS label)
#   TC24 - VRF-A /128 IPv6 nexthop resolves via VRF_DEFAULT (fd00::2)
#   TC25 - Inter-subnet IPv6 ping CE4 -> CE2 (2001:db8:1::10 -> 2001:db8:2::10)
#   TC26 - NDP: remote CE IPv6 neigh installed as PERMANENT on PE1 br200
#   --- Anycast GW (VLAN 100, IPv6) ---
#   TC27 - Anycast GW IPv6 advertised: both PEs send Type-2 for 2001:db8:100::1
#   TC28 - CE3 local IPv6 GW reachability: NDP for 2001:db8:100::1 resolved by PE2
#   TC29 - Anycast GW IPv6 suppression: PE1 does NOT install PE2 anycast GW as remote neigh

import os
import sys
import json
import time
import ipaddress
import subprocess
import pytest

CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

from lib import topotest
from lib.topogen import Topogen, TopoRouter, get_topogen
from lib.topolog import logger
from lib.common_config import required_linux_kernel_version
from lib.checkping import check_ping

pytestmark = [pytest.mark.bgpd]

ANYCAST_MAC = "00:00:5e:00:01:64"  # shared GW MAC on both PEs for VLAN 100
ANYCAST_GW_V6 = "2001:db8:100::1"  # shared IPv6 anycast GW on br100, same MAC


def _sr6_kernel_supported():
    """The End.DT2U/DT2M dataplane needs the out-of-tree `sr6` netdev driver,
    which is not in mainline Linux. Probe with a bare `ip link add type sr6`,
    which the kernel rejects *because* sr6 needs a segment list ("SRH with
    segment list is required") when the driver IS present, and reports an
    unknown link type when it is NOT. SR6_SUPPORTED=0/1 overrides."""
    env = os.environ.get("SR6_SUPPORTED")
    if env in ("0", "1"):
        return env == "1"
    probe = "sr6probe%d" % os.getpid()
    try:
        res = subprocess.run(["ip", "link", "add", "name", probe, "type", "sr6"],
                             capture_output=True, text=True)
    except OSError:
        return False
    finally:
        subprocess.run(["ip", "link", "del", probe],
                       capture_output=True, text=True)
    # Driver present -> rejected for a missing segment list, not unknown type.
    return "segment list" in (res.stderr or "").lower()


sr6_supported = _sr6_kernel_supported()


# -----------------------------------------------------------------------------
# Topology builder
# -----------------------------------------------------------------------------

def build_topo(tgen):
    for name in ("pe1", "pe2", "ce1", "ce2", "ce3", "ce4"):
        tgen.add_router(name)

    # SRv6 underlay
    tgen.add_link(tgen.gears["pe1"], tgen.gears["pe2"], "eth0", "eth0")

    # VLAN 100 access (Anycast GW, IPv4)
    tgen.add_link(tgen.gears["ce1"], tgen.gears["pe1"], "eth0", "eth1")  # CE1 -> PE1 br100
    tgen.add_link(tgen.gears["ce3"], tgen.gears["pe2"], "eth0", "eth2")  # CE3 -> PE2 br100

    # VLAN 200 access (IPv6 IRB)
    tgen.add_link(tgen.gears["ce4"], tgen.gears["pe1"], "eth0", "eth2")  # CE4 -> PE1 br200
    tgen.add_link(tgen.gears["ce2"], tgen.gears["pe2"], "eth0", "eth1")  # CE2 -> PE2 br200


_SR6_DUMMY_SID = "2001:db8:5262::1"


def _add_sr6(pe, name, br, is_bum, vid=None):
    # Operator-owned sr6 decap/encap netdev (OCT8): zebra discovers it by name on
    # the EVI bridge and programs the zebra-assigned End.DT2U/DT2M SID in place.
    pe.run("ip link add name %s type sr6 mode full segs %s" % (name, _SR6_DUMMY_SID))
    pe.run("ip link set %s addrgenmode none" % name)
    pe.run("ip link set %s master %s" % (name, br))
    if vid:
        pe.run("bridge vlan add dev %s vid %d" % (name, vid))
    fl = "on" if is_bum else "off"
    pe.run("bridge link set dev %s learning off flood %s mcast_flood %s "
           "bcast_flood %s isolated on" % (name, fl, fl, fl))
    pe.run("ip link set %s up" % name)

def _setup_pe_kernel(pe, underlay_ip, locator, router_id,
                     anycast_gw_ip, ipv6_gw_ip, ce_ipv4_port, ce_ipv6_port):
    """Configure bridges, VRF-A, anycast MAC, and SRv6 sysctls on a PE."""
    # VRF-A
    pe.run("ip link add VRF-A type vrf table 10")
    pe.run("ip link set VRF-A up")

    # br100 -- VLAN 100, anycast GW (IPv4 only)
    pe.run("ip link add br100 type bridge vlan_filtering 1")
    pe.run("ip link set br100 master VRF-A")
    pe.run("ip link set br100 up")
    # Set the anycast MAC -- same on both PEs so CEs always get the same GW MAC
    pe.run("ip link set br100 address %s" % ANYCAST_MAC)
    pe.run("ip addr add %s/24 dev br100" % anycast_gw_ip)
    # Dual-stack anycast: same GW MAC also carries an IPv6 anycast GW address,
    # identical on both PEs, to validate advertise-svi-ip over IPv6.
    pe.run("ip -6 addr add %s/64 dev br100" % ANYCAST_GW_V6)
    pe.run("bridge vlan add vid 100 dev br100 self untagged")

    # CE access port into br100 (VLAN 100)
    pe.run("ip link set %s master br100" % ce_ipv4_port)
    pe.run("ip link set %s up" % ce_ipv4_port)
    pe.run("bridge vlan add vid 100 dev %s pvid untagged" % ce_ipv4_port)

    _add_sr6(pe, "sr6-100", "br100", is_bum=False, vid=100)
    _add_sr6(pe, "bum-sr6-100", "br100", is_bum=True, vid=100)

    # br200 -- VLAN 200, IPv6 IRB (no IPv4)
    pe.run("ip link add br200 type bridge vlan_filtering 1")
    pe.run("ip link set br200 master VRF-A")
    pe.run("ip link set br200 up")
    pe.run("ip addr add %s/64 dev br200" % ipv6_gw_ip)
    pe.run("bridge vlan add vid 200 dev br200 self untagged")

    # CE access port into br200 (VLAN 200)
    pe.run("ip link set %s master br200" % ce_ipv6_port)
    pe.run("ip link set %s up" % ce_ipv6_port)
    pe.run("bridge vlan add vid 200 dev %s pvid untagged" % ce_ipv6_port)

    _add_sr6(pe, "sr6-200", "br200", is_bum=False, vid=200)
    _add_sr6(pe, "bum-sr6-200", "br200", is_bum=True, vid=200)

    # SRv6 sysctls
    pe.run("sysctl -w net.ipv6.conf.all.forwarding=1")
    pe.run("sysctl -w net.ipv6.conf.all.seg6_enabled=1")
    pe.run("sysctl -w net.ipv6.conf.eth0.seg6_enabled=1")
    pe.run("sysctl -w net.vrf.strict_mode=1")

    # Underlay address
    pe.run("ip addr add %s/64 dev eth0" % underlay_ip)
    pe.run("ip link set eth0 up")

    # Locator on loopback for IS-IS redistribution
    net = ipaddress.IPv6Network(locator)
    lo_addr = "%s/%d" % (net.network_address + 1, net.prefixlen)
    pe.run("ip addr add %s dev lo" % lo_addr)

    # BGP router-ID on loopback
    pe.run("ip addr add %s/32 dev lo" % router_id)


def _setup_ce_ipv4(ce, ip, gw):
    """Configure a CE with IPv4 only (for VLAN 100 anycast tests)."""
    ce.run("ip addr add %s/24 dev eth0" % ip)
    ce.run("ip link set eth0 up")
    ce.run("ip route add default via %s" % gw)


def _add_ce_ipv6_anycast(ce, ip6):
    """Add a secondary IPv6 address on a VLAN-100 CE's existing eth0, to
    reach the dual-stack anycast GW (ANYCAST_GW_V6) on the same bridge."""
    ce.run("ip -6 addr add %s/64 dev eth0" % ip6)
    ce.run("sysctl -w net.ipv6.conf.all.forwarding=1")
    ce.run("ip -6 route add default via %s" % ANYCAST_GW_V6)


def _setup_ce_ipv6(ce, ip6, gw6):
    """Configure a CE with IPv6 only (for VLAN 200 IPv6 tests)."""
    ce.run("ip addr add %s/64 dev eth0" % ip6)
    ce.run("ip link set eth0 up")
    ce.run("ip -6 route add default via %s" % gw6)
    ce.run("sysctl -w net.ipv6.conf.all.forwarding=1")


# -----------------------------------------------------------------------------
# Module setup / teardown
# -----------------------------------------------------------------------------

def setup_module(mod):
    if required_linux_kernel_version("5.14") is not True:
        pytest.skip("Kernel >= 5.14 required for SRv6 seg6local End.DT46")
    if not sr6_supported:
        pytest.skip("kernel lacks the out-of-tree SRv6 sr6 netdev "
                    "(End.DT2U/DT2M dataplane)")

    tgen = Topogen(build_topo, mod.__name__)
    tgen.start_topology()

    for rname in ("pe1", "pe2"):
        tgen.gears[rname].load_frr_config(os.path.join(CWD, "%s/frr.conf" % rname))

    _setup_pe_kernel(
        tgen.gears["pe1"],
        underlay_ip="fd00::1",
        locator="fc00:1::/48",
        router_id="1.1.1.1",
        anycast_gw_ip="10.0.1.1",
        ipv6_gw_ip="2001:db8:1::1",
        ce_ipv4_port="eth1",
        ce_ipv6_port="eth2",
    )
    _setup_pe_kernel(
        tgen.gears["pe2"],
        underlay_ip="fd00::2",
        locator="fc00:2::/48",
        router_id="2.2.2.2",
        anycast_gw_ip="10.0.1.1",
        ipv6_gw_ip="2001:db8:2::1",
        ce_ipv4_port="eth2",
        ce_ipv6_port="eth1",
    )

    tgen.start_router()

    # CE setup after router start (Mininet resets namespaces at start_router)
    _setup_ce_ipv4(tgen.gears["ce1"], "10.0.1.10", "10.0.1.1")   # VLAN 100, PE1
    _setup_ce_ipv4(tgen.gears["ce3"], "10.0.1.20", "10.0.1.1")   # VLAN 100, PE2
    _setup_ce_ipv6(tgen.gears["ce4"], "2001:db8:1::10", "2001:db8:1::1")  # VLAN 200, PE1
    _setup_ce_ipv6(tgen.gears["ce2"], "2001:db8:2::10", "2001:db8:2::1")  # VLAN 200, PE2
    _add_ce_ipv6_anycast(tgen.gears["ce1"], "2001:db8:100::10")  # VLAN 100 anycast GW, PE1
    _add_ce_ipv6_anycast(tgen.gears["ce3"], "2001:db8:100::20")  # VLAN 100 anycast GW, PE2

    def _converged():
        try:
            tgen = get_topogen()
            s1 = json.loads(tgen.gears["pe1"].vtysh_cmd(
                "show bgp l2vpn evpn summary json"))
            s2 = json.loads(tgen.gears["pe2"].vtysh_cmd(
                "show bgp l2vpn evpn summary json"))
            if s1["peers"]["fd00::2"]["state"] != "Established":
                return False
            if s2["peers"]["fd00::1"]["state"] != "Established":
                return False
            r1loc = tgen.gears["pe1"].run("ip -6 route show fc00:2::/48")
            r2loc = tgen.gears["pe2"].run("ip -6 route show fc00:1::/48")
            return "fc00:2::" in r1loc and "fc00:1::" in r2loc
        except (KeyError, ValueError, TypeError):
            return False

    _, ok = topotest.run_and_expect(_converged, True, count=90, wait=1)
    assert ok, "Topology did not converge within 90s"

    # Re-assert both EVI->bridge bindings after start_router().  At startup zebra
    # may parse frr.conf before the kernel interface dump delivers br100/br200,
    # and the initial config commit can lose a race with another northbound
    # transaction, leaving the EVIs uncreated on one PE (intermittent).  Re-
    # applying once interfaces are up commits cleanly (idempotent).
    evi_block = (
        "configure terminal\n"
        "segment-routing\n srv6\n  l2-evpn\n"
        "   evi 100 locator MAIN bridge br100\n"
        "    service-type vlan-based\n    vlan 100\n    vrf VRF-A\n   exit\n"
        "   evi 200 locator MAIN bridge br200\n"
        "    service-type vlan-based\n    vlan 200\n    vrf VRF-A\n   exit\n"
    )
    for r in ("pe1", "pe2"):
        tgen.gears[r].vtysh_cmd(evi_block)

    # Best-effort dataplane warm-up: drive the VLAN-100 L2 (CE1<->CE3) and the
    # VLAN-200 IPv6 L3 (CE4<->CE2) flows the tests check, so MAC/neigh learning
    # and Type-2 advertisement converge before the per-test checks run.
    for _ in range(120):
        tgen.gears["ce1"].run("ping -c1 -W1 10.0.1.1")              # CE1 -> anycast GW
        tgen.gears["ce3"].run("ping -c1 -W1 10.0.1.1")              # CE3 -> anycast GW
        o_l2 = tgen.gears["ce1"].run("ping -c2 -W1 10.0.1.20")      # CE1 -> CE3 (intra-subnet L2)
        tgen.gears["ce4"].run("ping6 -c1 -W1 2001:db8:1::1")        # CE4 -> GW
        tgen.gears["ce2"].run("ping6 -c1 -W1 2001:db8:2::1")        # CE2 -> GW
        o_v6 = tgen.gears["ce4"].run("ping6 -c2 -W1 2001:db8:2::10")  # CE4 -> CE2 (IPv6 inter-subnet)
        if "bytes from 10.0.1.20" in o_l2 and "bytes from 2001:db8:2::10" in o_v6:
            logger.info("irb_v2 dataplane warm-up converged")
            break
        time.sleep(1)

def teardown_module(mod):
    if os.environ.get("TOPO_PAUSE", "0") == "1":
        logger.info("TOPO_PAUSE=1: topology is UP -- inspect in another terminal. Press Enter to tear down.")
        input("\n*** Topology is live. Press Enter to tear down ***\n")
    get_topogen().stop_topology()


# -----------------------------------------------------------------------------
# Helpers
# -----------------------------------------------------------------------------

def _expect_text(router, cmd, needles, count=30, wait=1):
    def _check():
        out = get_topogen().gears[router].vtysh_cmd(cmd)
        missing = [n for n in needles if n not in out]
        return None if not missing else missing
    _, res = topotest.run_and_expect(_check, None, count=count, wait=wait)
    assert res is None, "%s: missing in '%s': %s" % (router, cmd, res)


def _expect_kernel(router, cmd, needles, count=30, wait=1):
    def _check():
        out = get_topogen().gears[router].run(cmd)
        missing = [n for n in needles if n not in out]
        return None if not missing else missing
    _, res = topotest.run_and_expect(_check, None, count=count, wait=wait)
    assert res is None, "%s: missing in '%s': %s" % (router, cmd, res)


def _absent_kernel(router, cmd, forbidden, count=10, wait=1):
    def _check():
        out = get_topogen().gears[router].run(cmd)
        found = [f for f in forbidden if f in out]
        return None if not found else found
    _, res = topotest.run_and_expect(_check, None, count=count, wait=wait)
    assert res is None, "%s: forbidden strings found in '%s': %s" % (router, cmd, res)


# -----------------------------------------------------------------------------
# TC16 - SID Allocation: EVI 100 + EVI 200 + DT46 on Both PEs
# -----------------------------------------------------------------------------

def test_tc16_srv6_sid_allocation_dual_evi():
    """TC16: With EVI 100 and EVI 200, each PE must allocate 5 SIDs:
    DT2U+DT2M for each EVI, plus DT46 for VRF-A."""
    logger.info("TC16: dual-EVI SID allocation")
    # VRF-A's DT46 allocates from the general pool (:1::), then EVI 100's
    # DT2U/DT2M and EVI 200's DT2U/DT2M allocate from the reserved per-EVI
    # range starting at :3e8:: - verified against live system state.
    _expect_text("pe1", "show bgp segment-routing srv6 evpn",
                 ["fc00:1:0:1::",                         # VRF-A DT46
                  "fc00:1:0:3e8::", "fc00:1:0:3e9::",     # EVI 100 DT2U/DT2M
                  "fc00:1:0:3ea::", "fc00:1:0:3eb::"])    # EVI 200 DT2U/DT2M
    # PE2: same structure under fc00:2::/48
    _expect_text("pe2", "show bgp segment-routing srv6 evpn",
                 ["fc00:2:0:1::",
                  "fc00:2:0:3e8::", "fc00:2:0:3e9::",
                  "fc00:2:0:3ea::", "fc00:2:0:3eb::"])


# -----------------------------------------------------------------------------
# TC17 - Anycast GW Advertised: Both PEs Send Type-2 for 10.0.1.1
# -----------------------------------------------------------------------------

def test_tc17_anycast_gw_type2_advertised():
    """TC17: Both PEs advertise a BGP Type-2 MAC+IP for the anycast GW address
    (10.0.1.1 with MAC 00:00:5e:00:01:64) via advertise-svi-ip."""
    logger.info("TC17: anycast GW Type-2 advertised from both PEs")
    tgen = get_topogen()

    # Trigger GW advertisement by pinging the GW from each CE
    tgen.gears["ce1"].run("ping -c2 -W1 10.0.1.1")
    tgen.gears["ce3"].run("ping -c2 -W1 10.0.1.1")

    # PE1 must see PE2's anycast GW MAC+IP in received EVPN routes
    _expect_text("pe1", "show bgp l2vpn evpn route detail type macip",
                 ["10.0.1.1", ANYCAST_MAC])
    # PE2 must see PE1's anycast GW MAC+IP
    _expect_text("pe2", "show bgp l2vpn evpn route detail type macip",
                 ["10.0.1.1", ANYCAST_MAC])


# -----------------------------------------------------------------------------
# TC18 - CE3 Local GW Reachability (Anycast Resolved by Local PE)
# -----------------------------------------------------------------------------

def test_tc18_anycast_gw_local_resolution():
    """TC18: CE3 on PE2 sends ARP for 10.0.1.1. PE2 must answer locally
    (the anycast GW IP is on PE2's own br100) -- no BUM flood cross-PE."""
    logger.info("TC18: anycast GW resolved locally by PE2 for CE3")
    tgen = get_topogen()

    # CE3 pings GW -- must succeed immediately (PE2 owns 10.0.1.1 on br100)
    result = tgen.gears["ce3"].run("ping -c3 -W1 10.0.1.1")
    assert "0 received" not in result, "CE3 cannot reach anycast GW on PE2: %s" % result

    # Verify PE2's br100 has the anycast MAC as its own address (not learned remotely)
    out = tgen.gears["pe2"].run("ip link show br100")
    assert ANYCAST_MAC in out.lower(), \
        "PE2 br100 does not have anycast MAC %s configured" % ANYCAST_MAC

    # CE3 ARP cache must show 10.0.1.1 resolved to the anycast MAC
    def _check_arp():
        out = tgen.gears["ce3"].run("ip neigh show dev eth0")
        if "10.0.1.1" not in out:
            return "ARP for GW not resolved"
        if ANYCAST_MAC not in out.lower():
            return "GW resolved to wrong MAC: %s" % out
        return None

    _, res = topotest.run_and_expect(_check_arp, None, count=15, wait=1)
    assert res is None, "TC18 failed: %s" % res


# -----------------------------------------------------------------------------
# TC19 - CE1 <-> CE3 Intra-Subnet L2 Ping (Same VLAN 100, Different PEs)
# -----------------------------------------------------------------------------

def test_tc19_anycast_intra_subnet_l2_ping():
    """TC19: CE1 (PE1, 10.0.1.10) must ping CE3 (PE2, 10.0.1.20).
    Same VLAN 100, different PEs -- traffic uses L2 EVPN DT2U path (not IRB)."""
    logger.info("TC19: CE1 <-> CE3 intra-subnet L2 ping via DT2U")
    check_ping("ce1", "10.0.1.20", True, count=30, wait=1)
    check_ping("ce3", "10.0.1.10", True, count=30, wait=1)


# -----------------------------------------------------------------------------
# TC20 - CE3 MAC in PE1 br100 FDB (Remote MAC from BGP Type-2)
# -----------------------------------------------------------------------------

def test_tc20_anycast_remote_mac_fdb():
    """TC20: CE3's MAC must appear in PE1's br100 FDB, installed by zebra
    from the BGP Type-2 route for CE3 (extern_learn, via sr6 slave port)."""
    logger.info("TC20: CE3 MAC in PE1 br100 FDB")
    tgen = get_topogen()

    ce3_mac = tgen.gears["ce3"].run(
        "ip link show eth0").split("link/ether")[1].split()[0].strip()
    logger.info("CE3 MAC: %s" % ce3_mac)

    def _check_fdb():
        out = tgen.gears["pe1"].run("bridge fdb show master br100")
        if ce3_mac.lower() not in out.lower():
            return "CE3 MAC not in PE1 br100 FDB"
        return None

    _, res = topotest.run_and_expect(_check_fdb, None, count=30, wait=1)
    assert res is None, "TC20 failed: %s" % res


# -----------------------------------------------------------------------------
# TC21 - Anycast GW Suppression: PE1 Does Not Install PE2's GW as Remote Neigh
# -----------------------------------------------------------------------------

def test_tc21_anycast_gw_suppression():
    """TC21: The anycast GW MAC (00:00:5e:00:01:64) is the same on both PEs.
    PE1 must NOT install 10.0.1.1 as a PERMANENT remote neighbor on br100
    (it is PE1's own GW address -- installing it remotely would cause a loop)."""
    logger.info("TC21: anycast GW not installed as remote neigh on PE1")
    tgen = get_topogen()

    out = tgen.gears["pe1"].run("ip neigh show dev br100")
    logger.info("PE1 br100 neigh: %s", out)

    # 10.0.1.1 should NOT appear as a PERMANENT remote neighbor on PE1 br100.
    # (PE1 owns this IP locally -- it is the GW, not a remote host.)
    lines_with_gw = [l for l in out.splitlines() if "10.0.1.1" in l]
    for line in lines_with_gw:
        assert "PERMANENT" not in line or "extern_learn" not in line, \
            "TC21: anycast GW 10.0.1.1 incorrectly installed as remote PERMANENT neigh: %s" % line


# -----------------------------------------------------------------------------
# TC22 - Type-2 MAC+IPv6 Advertised with Dual SIDs
# -----------------------------------------------------------------------------

def test_tc22_type2_ipv6_dual_sids():
    """TC22: After CE2 NDP, PE1 must receive Type-2 with CE2's IPv6 address
    (2001:db8:2::10) plus both SIDs: DT2U (EVI 200) and DT46 (VRF-A)."""
    logger.info("TC22: Type-2 MAC+IPv6 with dual SIDs")
    tgen = get_topogen()

    # Trigger NDP on CE2 so PE2 learns CE2's MAC+IPv6 and advertises Type-2
    tgen.gears["ce2"].run("ping6 -c3 -W1 2001:db8:2::1")

    _expect_text("pe1", "show bgp l2vpn evpn route detail type macip",
                 ["2001:db8:2::10",
                  "fc00:2:0:3ea::",   # DT2U EVI 200 (L2 SID)
                  "fc00:2:0:1::"])    # DT46 VRF-A (L3/IRB SID)


# -----------------------------------------------------------------------------
# TC23 - VRF-A /128 IPv6 Host Route with SRv6 Encap (No MPLS)
# -----------------------------------------------------------------------------

def test_tc23_vrf_ipv6_host_route_seg6():
    """TC23: CE2's IPv6 address (2001:db8:2::10/128) must appear in PE1's
    VRF-A (table 10) with seg6 encap toward PE2's DT46 SID -- no MPLS label."""
    logger.info("TC23: VRF-A /128 IPv6 host route with SRv6 encap")
    _expect_kernel("pe1", "ip -6 route show table 10",
                   ["2001:db8:2::10", "encap seg6", "fc00:2:0:1::"])
    _absent_kernel("pe1", "ip -6 route show table 10",
                   ["label", "mpls"])


# -----------------------------------------------------------------------------
# TC24 - VRF-A /128 IPv6 Nexthop Resolves via VRF_DEFAULT
# -----------------------------------------------------------------------------

def test_tc24_vrf_ipv6_nexthop_default_vrf():
    """TC24: The /128 IPv6 host route in VRF-A must use fd00::2 (BGP session
    address in VRF default) as nexthop -- not the DT46 SID which is unreachable
    inside VRF-A."""
    logger.info("TC24: VRF-A /128 IPv6 nexthop via VRF default (fd00::2)")
    _expect_kernel("pe1", "ip -6 route show table 10",
                   ["2001:db8:2::10", "fd00::2", "eth0"])
    _absent_kernel("pe1", "ip -6 route show table 10 2001:db8:2::10",
                   ["via fc00:2:0:5::"])


# -----------------------------------------------------------------------------
# TC25 - Inter-Subnet IPv6 Ping: CE4 -> CE2
# -----------------------------------------------------------------------------

def test_tc25_inter_subnet_ipv6_ping():
    """TC25: CE4 (2001:db8:1::10, PE1 VLAN 200) must ping CE2 (2001:db8:2::10,
    PE2 VLAN 200) via SRv6 IRB -- pure IPv6 inter-subnet forwarding."""
    logger.info("TC25: inter-subnet IPv6 ping CE4 -> CE2")
    check_ping("ce4", "2001:db8:2::10", True, count=30, wait=1)
    check_ping("ce2", "2001:db8:1::10", True, count=30, wait=1)


# -----------------------------------------------------------------------------
# TC26 - NDP: Remote CE IPv6 Neigh Installed as PERMANENT on PE1 br200
# -----------------------------------------------------------------------------

def test_tc26_remote_ndp_neigh_permanent():
    """TC26: CE2's IPv6 address (2001:db8:2::10) must appear as a PERMANENT
    neighbor on PE1's br200, installed by zebra from the BGP Type-2 MAC+IPv6
    route (equivalent to TC11 but for IPv6 overlay on VLAN 200)."""
    logger.info("TC26: remote IPv6 neigh PERMANENT on PE1 br200")

    def _check_permanent():
        out = get_topogen().gears["pe1"].run("ip -6 neigh show dev br200")
        if "2001:db8:2::10" not in out:
            return "remote IPv6 neigh missing"
        lines = [l for l in out.splitlines() if "2001:db8:2::10" in l]
        if not lines or "PERMANENT" not in lines[0]:
            return "not PERMANENT: %s" % lines
        return None

    _, res = topotest.run_and_expect(_check_permanent, None, count=30, wait=1)
    assert res is None, "TC26 failed: %s" % res


# -----------------------------------------------------------------------------
# TC27 - Anycast GW IPv6 Advertised: Both PEs Send Type-2 for 2001:db8:100::1
# -----------------------------------------------------------------------------

def test_tc27_anycast_gw_ipv6_type2_advertised():
    """TC27: Both PEs advertise a BGP Type-2 MAC+IPv6 for the dual-stack
    anycast GW address (2001:db8:100::1 with MAC 00:00:5e:00:01:64) via
    advertise-svi-ip - same mechanism as TC17, exercised over IPv6."""
    logger.info("TC27: anycast GW IPv6 Type-2 advertised from both PEs")
    tgen = get_topogen()

    # Trigger GW advertisement by pinging the GW from each CE
    tgen.gears["ce1"].run("ping -6 -c2 -W1 %s" % ANYCAST_GW_V6)
    tgen.gears["ce3"].run("ping -6 -c2 -W1 %s" % ANYCAST_GW_V6)

    # PE1 must see PE2's anycast GW MAC+IPv6 in received EVPN routes
    _expect_text("pe1", "show bgp l2vpn evpn route detail type macip",
                 [ANYCAST_GW_V6, ANYCAST_MAC])
    # PE2 must see PE1's anycast GW MAC+IPv6
    _expect_text("pe2", "show bgp l2vpn evpn route detail type macip",
                 [ANYCAST_GW_V6, ANYCAST_MAC])


# -----------------------------------------------------------------------------
# TC28 - CE3 Local IPv6 GW Reachability (Anycast Resolved by Local PE)
# -----------------------------------------------------------------------------

def test_tc28_anycast_gw_ipv6_local_resolution():
    """TC28: CE3 on PE2 sends NDP NS for 2001:db8:100::1. PE2 must answer
    locally (the anycast GW address is on PE2's own br100) - no BUM flood
    cross-PE. Same as TC18, exercised over IPv6."""
    logger.info("TC28: anycast GW IPv6 resolved locally by PE2 for CE3")
    tgen = get_topogen()

    # CE3 pings GW -- must succeed immediately (PE2 owns the GW on br100)
    result = tgen.gears["ce3"].run("ping -6 -c3 -W1 %s" % ANYCAST_GW_V6)
    assert "0 received" not in result, \
        "CE3 cannot reach anycast GW IPv6 on PE2: %s" % result

    # Verify PE2's br100 has the anycast MAC as its own address (not learned remotely)
    out = tgen.gears["pe2"].run("ip link show br100")
    assert ANYCAST_MAC in out.lower(), \
        "PE2 br100 does not have anycast MAC %s configured" % ANYCAST_MAC

    # CE3 NDP cache must show the GW resolved to the anycast MAC
    def _check_ndp():
        out = tgen.gears["ce3"].run("ip -6 neigh show dev eth0")
        if ANYCAST_GW_V6 not in out:
            return "NDP for GW not resolved"
        if ANYCAST_MAC not in out.lower():
            return "GW resolved to wrong MAC: %s" % out
        return None

    _, res = topotest.run_and_expect(_check_ndp, None, count=15, wait=1)
    assert res is None, "TC28 failed: %s" % res


# -----------------------------------------------------------------------------
# TC29 - Anycast GW IPv6 Suppression: PE1 Does Not Install PE2's GW as Remote Neigh
# -----------------------------------------------------------------------------

def test_tc29_anycast_gw_ipv6_suppression():
    """TC29: The anycast GW MAC is the same on both PEs for the IPv6 GW too.
    PE1 must NOT install 2001:db8:100::1 as a PERMANENT remote neighbor on
    br100 (it is PE1's own GW address). Same as TC21, exercised over IPv6."""
    logger.info("TC29: anycast GW IPv6 not installed as remote neigh on PE1")
    tgen = get_topogen()

    out = tgen.gears["pe1"].run("ip -6 neigh show dev br100")
    logger.info("PE1 br100 IPv6 neigh: %s", out)

    lines_with_gw = [l for l in out.splitlines() if ANYCAST_GW_V6 in l]
    for line in lines_with_gw:
        assert "PERMANENT" not in line or "extern_learn" not in line, \
            "TC29: anycast GW IPv6 %s incorrectly installed as remote PERMANENT neigh: %s" % (
                ANYCAST_GW_V6, line)


# -----------------------------------------------------------------------------
# TC30 - Remote IPv6 subnet route via Type-5, remote IPv6 gateway reachable
# -----------------------------------------------------------------------------

def test_tc30_remote_ipv6_subnet_route_via_type5():
    """TC30: Each PE's IPv6 subnet must reach the other PE's VRF-A as a Type-5
    route imported through the VPN leak ('import vpn' + 'rt vpn import') and
    installed with SRv6 encap toward the DT46 SID; CE4 must reach PE2's br200
    address (2001:db8:2::1) and CE2 PE1's (2001:db8:1::1) through it."""
    logger.info("TC30: remote IPv6 subnet route via Type-5 import")
    _expect_kernel("pe1", "ip -6 route show table 10 2001:db8:2::/64",
                   ["2001:db8:2::/64", "encap seg6", "fc00:2:0:1::"])
    _expect_kernel("pe2", "ip -6 route show table 10 2001:db8:1::/64",
                   ["2001:db8:1::/64", "encap seg6", "fc00:1:0:1::"])
    check_ping("ce4", "2001:db8:2::1", True, count=30, wait=1)
    check_ping("ce2", "2001:db8:1::1", True, count=30, wait=1)


# -----------------------------------------------------------------------------
# Entry point
# -----------------------------------------------------------------------------

if __name__ == "__main__":
    sys.exit(pytest.main([os.path.basename(__file__)] + sys.argv[1:]))
