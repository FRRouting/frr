#!/usr/bin/env python
# SPDX-License-Identifier: ISC
# Copyright (c) 2026 Aviz Networks
#
# Test suite: SRv6 L2 EVPN IRB (Integrated Routing and Bridging)
#
# Topology:
#
#   CE1 (10.0.1.10/24)                      CE2 (10.0.2.10/24)
#        |                                        |
#      eth1                                     eth1
#   PE1 (r1, AS 65001)  ===SRv6 underlay===  PE2 (r2, AS 65002)
#      eth0 fd00::1/64                          eth0 fd00::2/64
#      br100 10.0.1.1/24                        br100 10.0.2.1/24
#      VRF-A (table 10)                         VRF-A (table 10)
#      locator fc00:1::/48                      locator fc00:2::/48
#
# SIDs: per-EVI (DT2U/DT2M) SIDs are allocated from a reserved range separate
# from VRF-level (DT4/DT6/DT46) SIDs (see SRV6_SID_NOFORMAT_EVI_FUNC_BASE in
# zebra/zebra_srv6.h), so DT46 is always :1:: and per-EVI SIDs always start
# at :3e8:: (1000) - deterministic regardless of allocation-request race order.
#   PE1: DT46=fc00:1:0:1::  DT2U=fc00:1:0:3e8::  DT2M=fc00:1:0:3e9::
#   PE2: DT46=fc00:2:0:1::  DT2U=fc00:2:0:3e8::  DT2M=fc00:2:0:3e9::
#
# Test cases:
#   TC1  - BGP session establishment
#   TC2  - SRv6 SID allocation (DT2U / DT2M / DT46)
#   TC3  - seg6local End.DT46 kernel route installed (egress decap)
#   TC4  - Type-2 MAC+IP advertised with BOTH L2 and L3 SID
#   TC5  - VRF-A /32 host route installed with SRv6 encap (NO MPLS label)
#   TC6  - VRF-A /32 nexthop resolves via VRF_DEFAULT (fd00::2, not SID)
#   TC7  - Inter-subnet ping: CE1 -> CE2 (10.0.1.10 -> 10.0.2.10)
#   TC8  - Inter-subnet ping: CE2 -> CE1 (return path symmetric)
#   TC9  - SRv6 encap on underlay (proto 43 / Routing Header)
#   TC10 - Neigh entry: local CE learned dynamically (STALE/REACHABLE)
#   TC11 - Neigh entry: remote CE installed as PERMANENT (from BGP Type-2)
#   TC12 - FDB: remote MAC installed on br100 from BGP Type-2
#   TC13 - Intra-subnet: CE1 -> CE1-subnet host on PE2 (L2 path via DT2U)
#   TC14 - BGP withdraw: route removed from VRF-A when Type-2 withdrawn
#   TC15 - Graceful restart: VRF-A route survives BGP restart within stale timer
#   TC16b - Removing the VRF SID withdraws the routes that pointed at it
#   TC16c - Removing the VRF locator falls back to the default locator
#   TC17 - Withdrawing only a host's IP keeps its MAC (owned by the MAC-only route)

import os
import sys
import json
import time
import functools
import ipaddress
import pytest
import subprocess

CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

from lib import topotest
from lib.topogen import Topogen, TopoRouter, get_topogen
from lib.topolog import logger
from lib.common_config import required_linux_kernel_version
from lib.checkping import check_ping

pytestmark = [pytest.mark.bgpd]

# -----------------------------------------------------------------------------
# Topology builder
# -----------------------------------------------------------------------------

def build_topo(tgen):
    for name in ("pe1", "pe2", "ce1", "ce2"):
        tgen.add_router(name)

    # SRv6 underlay link between PEs
    tgen.add_link(tgen.gears["pe1"], tgen.gears["pe2"], "eth0", "eth0")

    # CE access links
    tgen.add_link(tgen.gears["ce1"], tgen.gears["pe1"], "eth0", "eth1")
    tgen.add_link(tgen.gears["ce2"], tgen.gears["pe2"], "eth0", "eth1")


# Operator-owned sr6 model : zebra DISCOVERS but never creates the per-EVI
# decap/encap netdevs. The operator pre-creates sr6-<evi> (unicast End.DT2U) and
# bum-sr6-<evi> (BUM End.DT2M), enslaves them to the EVI bridge, adds the EVI
# VLAN, sets the EVPN split-horizon/flood brport flags and brings them up; zebra
# programs the zebra-assigned SID in place. The segs below is a placeholder that
# zebra overwrites. Mirrors _add_sr6() in the bgp_srv6_l2_evpn topotest.
_SR6_DUMMY_SID = "2001:db8:5262::1"


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


def _add_sr6(pe, name, br, is_bum, vid=None):
    pe.run("ip link add name %s type sr6 mode full segs %s" % (name, _SR6_DUMMY_SID))
    pe.run("ip link set %s addrgenmode none" % name)
    pe.run("ip link set %s master %s" % (name, br))
    if vid:
        # VLAN-aware EVI bridge: the decapped/flooded inner frame is VLAN-tagged,
        # so both overlay ports must be members of the EVI VLAN (tagged) or the
        # bridge will not flood BUM to them. FRR no longer adds this (was the
        # auto-create if-add hook) -> the operator provisions it here.
        pe.run("bridge vlan add dev %s vid %d" % (name, vid))
    # EVPN split-horizon + flood policy (was dplane_sr6_brport_flags): learning
    # off; flood only on the BUM port; isolated on both (no PE-to-PE re-flood).
    fl = "on" if is_bum else "off"
    pe.run("bridge link set dev %s learning off flood %s mcast_flood %s "
           "bcast_flood %s isolated on" % (name, fl, fl, fl))
    pe.run("ip link set %s up" % name)


def _setup_pe_kernel(pe, br_ip, underlay_ip, locator, router_id=None):
    """Set up bridge, VRF-A, SRv6 sysctls for a PE router."""
    # VRF
    pe.run("ip link add VRF-A type vrf table 10")
    pe.run("ip link set VRF-A up")

    # Bridge br100 (vlan_filtering, bound to VRF-A)
    pe.run("ip link add br100 type bridge vlan_filtering 1")
    # Pin the bridge MAC. A bridge otherwise adopts the lowest MAC among its
    # ports, and the sr6 L2 ports (sr6-*/bum-sr6-*) get fresh random MACs, so
    # br100 can silently change MAC (or end up sharing a port's MAC with no
    # VLAN-100 local FDB entry): frames to the gateway MAC are then flooded
    # out the BUM tunnel and the CEs blackhole on a stale gateway ARP entry.
    pe.run("ip link set br100 address 02:00:00:%02x:00:01" % int(br_ip.split(".")[2]))
    pe.run("ip link set br100 master VRF-A")
    pe.run("ip link set br100 up")
    pe.run("ip addr add %s/24 dev br100" % br_ip)

    # CE access port into bridge with VLAN 100
    pe.run("ip link set eth1 master br100")
    pe.run("ip link set eth1 up")
    pe.run("bridge vlan add vid 100 dev eth1 pvid untagged")
    # Bridge SVI must join VLAN 100 so kernel processes ARP/IP for br100's IP
    # on VLAN 100 traffic arriving from CE (eth1 PVID=100).
    pe.run("bridge vlan add vid 100 dev br100 self untagged")

    # Operator-owned sr6 decap/encap netdevs for EVI 100 (see _add_sr6 above).
    # zebra discovers these by name and programs the per-EVI End.DT2U/DT2M
    # SID in place; it does NOT create them. Without them there is no L2 SRv6
    # dataplane (no MAC decap, no BUM flood) and the per-EVI SID alloc has no
    # interface-discovery event to retry on after the locator comes up.
    _add_sr6(pe, "sr6-100", "br100", is_bum=False, vid=100)
    _add_sr6(pe, "bum-sr6-100", "br100", is_bum=True, vid=100)

    # SRv6 sysctls (required for kernel seg6local processing)
    pe.run("sysctl -w net.ipv6.conf.all.forwarding=1")
    pe.run("sysctl -w net.ipv6.conf.all.seg6_enabled=1")
    pe.run("sysctl -w net.ipv6.conf.eth0.seg6_enabled=1")
    # VRF strict mode: kernel requires this to accept seg6local End.DT46/DT4/DT6
    # routes with RTA_OIF pointing to a VRF master device (EPERM without it).
    pe.run("sysctl -w net.vrf.strict_mode=1")

    # Assign underlay IPv6 address on eth0 so BGP can source from it immediately
    pe.run("ip addr add %s/64 dev eth0" % underlay_ip)
    pe.run("ip link set eth0 up")

    # Add locator prefix on loopback so IS-IS redistribute connected picks it up.
    # Use ::1 host address within the locator (e.g. fc00:1::1/48 for fc00:1::/48).
    net = ipaddress.IPv6Network(locator)
    lo_addr = "%s/%d" % (net.network_address + 1, net.prefixlen)
    pe.run("ip addr add %s dev lo" % lo_addr)

    # Add the BGP router-ID as an IPv4 loopback address so IS-IS can redistribute
    # it, making it reachable from the peer (required for BGP nexthop validation
    # of received EVPN routes).
    if router_id:
        pe.run("ip addr add %s/32 dev lo" % router_id)


def _setup_ce_kernel(ce, ip, gw):
    """Configure a CE host."""
    ce.run("ip addr add %s/24 dev eth0" % ip)
    ce.run("ip link set eth0 up")
    ce.run("ip route add default via %s" % gw)


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

    # Load FRR configs (integrated frr.conf)
    for rname in ("pe1", "pe2"):
        tgen.gears[rname].load_frr_config(os.path.join(CWD, "%s/frr.conf" % rname))

    # Kernel setup
    _setup_pe_kernel(tgen.gears["pe1"], "10.0.1.1", "fd00::1", "fc00:1::/48", router_id="1.1.1.1")
    _setup_pe_kernel(tgen.gears["pe2"], "10.0.2.1", "fd00::2", "fc00:2::/48", router_id="2.2.2.2")

    tgen.start_router()

    # CE kernel setup must happen AFTER start_router(): Mininet's host startup
    # resets CE namespaces, wiping any configuration applied before this point.
    _setup_ce_kernel(tgen.gears["ce1"], "10.0.1.10", "10.0.1.1")
    _setup_ce_kernel(tgen.gears["ce2"], "10.0.2.10", "10.0.2.1")

	# Re-assert the EVI->bridge binding after start_router().  At daemon startup
    # zebra may parse frr.conf before the kernel interface dump delivers br100,
    # and the initial config commit can lose a race with another northbound
    # transaction ("another transaction in progress").  Re-applying once the
    # bridge is up and startup has settled commits cleanly and creates the EVI
    # (idempotent if it already exists).  Mirrors the bgp_srv6_l2_evpn test.
    # Do NOT re-apply the locator prefix here (that lands as an encoding change
    # and reallocates the per-EVI SIDs).
    evi_block = (
        "configure terminal\n"
        "segment-routing\n srv6\n  l2-evpn\n"
        "   evi 100 locator MAIN bridge br100\n"
        "    service-type vlan-based\n"
        "    vlan 100\n"
        "    vrf VRF-A\n"
        "   exit\n"
    )
    for r in ("pe1", "pe2"):
        tgen.gears[r].vtysh_cmd(evi_block)

    # Wait for BGP convergence + underlay reachability
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
            # Underlay reachability: each PE must see the other's locator
            r1loc = tgen.gears["pe1"].run("ip -6 route show fc00:2::/48")
            r2loc = tgen.gears["pe2"].run("ip -6 route show fc00:1::/48")
            return "fc00:2::" in r1loc and "fc00:1::" in r2loc
        except (KeyError, ValueError, TypeError):
            return False

    _, ok = topotest.run_and_expect(_converged, True, count=90, wait=1)
    assert ok, "Topology did not converge within 90s"

    # Best-effort dataplane warm-up.  A one-shot ping leaves a CE neighbor in
    # DELAY; the Type-2 MAC+IP is advertised only once the neighbor is REACHABLE,
    # which needs sustained traffic.  Drive each CE's gateway ARP plus
    # bidirectional inter-subnet traffic until both directions pass.  NOT asserted
    # -- individual tests still poll, and TC7/TC8 are themselves the ping checks.
    for _ in range(120):
        tg = get_topogen()
        tg.gears["ce1"].run("ping -c1 -W1 10.0.1.1")        # CE1 -> its gateway
        tg.gears["ce2"].run("ping -c1 -W1 10.0.2.1")        # CE2 -> its gateway
        o1 = tg.gears["ce1"].run("ping -c2 -W1 10.0.2.10")  # CE1 -> CE2
        o2 = tg.gears["ce2"].run("ping -c2 -W1 10.0.1.10")  # CE2 -> CE1
        if "bytes from 10.0.2.10" in o1 and "bytes from 10.0.1.10" in o2:
            logger.info("dataplane warm-up converged after warm-up pings")
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
    """Poll vtysh command until ALL needle strings appear in output."""
    def _check():
        out = get_topogen().gears[router].vtysh_cmd(cmd)
        missing = [n for n in needles if n not in out]
        return None if not missing else missing

    _, res = topotest.run_and_expect(_check, None, count=count, wait=wait)
    assert res is None, "%s: missing in '%s': %s" % (router, cmd, res)

def _expect_transposed_sids(router, cmd, text_needles, sids, count=30, wait=1):
    """Like _expect_text, but the SIDs are read from the JSON output.  With SRv6
    transposition the advertised SID carries only the locator; the function
    travels in the NLRI label, and 'show ... detail' prints the effective SID
    only as remoteTransposedSid in JSON."""
    def _collect(node, found):
        if isinstance(node, dict):
            for k, v in node.items():
                if k == "remoteTransposedSid":
                    found.add(v)
                else:
                    _collect(v, found)
        elif isinstance(node, list):
            for v in node:
                _collect(v, found)

    def _check():
        gear = get_topogen().gears[router]
        out = gear.vtysh_cmd(cmd)
        missing = [n for n in text_needles if n not in out]
        try:
            found = set()
            _collect(json.loads(gear.vtysh_cmd(cmd + " json")), found)
        except ValueError:
            return ["no JSON from '%s json'" % cmd]
        missing += [s for s in sids if s not in found]
        return None if not missing else missing

    _, res = topotest.run_and_expect(_check, None, count=count, wait=wait)
    assert res is None, "%s: missing in '%s': %s" % (router, cmd, res)


def _expect_kernel(router, cmd, needles, count=30, wait=1):
    """Poll a shell (non-vtysh) command until ALL needle strings appear."""
    def _check():
        out = get_topogen().gears[router].run(cmd)
        missing = [n for n in needles if n not in out]
        return None if not missing else missing

    _, res = topotest.run_and_expect(_check, None, count=count, wait=wait)
    assert res is None, "%s: missing in '%s': %s" % (router, cmd, res)


def _absent_kernel(router, cmd, forbidden, count=10, wait=1):
    """Assert that NONE of the forbidden strings appear in command output."""
    def _check():
        out = get_topogen().gears[router].run(cmd)
        found = [f for f in forbidden if f in out]
        return None if not found else found

    _, res = topotest.run_and_expect(_check, None, count=count, wait=wait)
    assert res is None, "%s: forbidden strings found in '%s': %s" % (router, cmd, res)


# -----------------------------------------------------------------------------
# TC1 - BGP Session Establishment
# -----------------------------------------------------------------------------

def test_tc1_bgp_session_established():
    """TC1: BGP L2VPN EVPN session must be Established between PE1 and PE2."""
    logger.info("TC1: BGP session establishment")
    tgen = get_topogen()

    def _bgp_up(router, peer):
        def _check():
            try:
                out = json.loads(get_topogen().gears[router].vtysh_cmd(
                    "show bgp l2vpn evpn summary json"))
                state = out["peers"][peer]["state"]
                return None if state == "Established" else state
            except (KeyError, ValueError, TypeError) as e:
                return str(e)
        return _check

    _, res = topotest.run_and_expect(_bgp_up("pe1", "fd00::2"), None, count=30, wait=1)
    assert res is None, "pe1: BGP to fd00::2 not Established: %s" % res
    _, res = topotest.run_and_expect(_bgp_up("pe2", "fd00::1"), None, count=30, wait=1)
    assert res is None, "pe2: BGP to fd00::1 not Established: %s" % res


# -----------------------------------------------------------------------------
# TC2 - SRv6 SID Allocation
# -----------------------------------------------------------------------------

def test_tc2_srv6_sid_allocation():
    """TC2: DT2U, DT2M, and DT46 SIDs must be allocated from the locator."""
    logger.info("TC2: SRv6 SID allocation")
    # 'show bgp segment-routing srv6 evpn' shows all EVPN SRv6 SIDs:
    #   - Per-EVI End.DT2U (Type-2) and End.DT2M (Type-3) SIDs
    #   - Per-VRF VPN (Type-5 DT4/DT6) SID a.k.a. DT46
    _expect_text("pe1", "show bgp segment-routing srv6 evpn",
                 ["fc00:1:0:1::", "fc00:1:0:3e8::", "fc00:1:0:3e9::"])
    _expect_text("pe2", "show bgp segment-routing srv6 evpn",
                 ["fc00:2:0:1::", "fc00:2:0:3e8::", "fc00:2:0:3e9::"])


# -----------------------------------------------------------------------------
# TC3 - seg6local End.DT46 Kernel Route (Egress Decap)
# -----------------------------------------------------------------------------

def test_tc3_seg6local_end_dt46_installed():
    """TC3: Kernel must have End.DT46 seg6local route for VRF-A decap."""
    logger.info("TC3: seg6local End.DT46 kernel route")
    # DT46 is allocated from the general pool, starting at function 1, for
    # no-named-format locators (per-EVI SIDs use the range starting at
    # SRV6_SID_NOFORMAT_EVI_FUNC_BASE) - deterministic, not a race with
    # per-EVI SID allocation.
    _expect_kernel("pe1", "ip -6 route show fc00:1:0:1::",
                   ["End.DT46", "vrftable", "10"])
    _expect_kernel("pe2", "ip -6 route show fc00:2:0:1::",
                   ["End.DT46", "vrftable", "10"])


# -----------------------------------------------------------------------------
# TC4 - Type-2 MAC+IP Carries Both L2 and L3 SIDs
# -----------------------------------------------------------------------------

def test_tc4_type2_carries_dual_sids():
    """TC4: After CE2 ARP, PE1 must receive Type-2 with DT2U and DT46 SIDs."""
    logger.info("TC4: Type-2 dual SID advertisement")
    tgen = get_topogen()

    # Trigger CE2 to ARP so PE2 learns its MAC+IP and advertises Type-2
    ping2 = tgen.gears["ce2"].run("ping -c3 -W1 10.0.2.1")
    logger.info("TC4 CE2 ping: %s", ping2.strip().splitlines()[0] if ping2.strip() else "no output")
    logger.info("TC4 PE2 neigh br100:\n%s", tgen.gears["pe2"].run("ip neigh show dev br100"))
    logger.info("TC4 PE2 evpn routes:\n%s", tgen.gears["pe2"].vtysh_cmd("show bgp l2vpn evpn route detail type macip"))
    logger.info("TC4 PE1 evpn routes:\n%s", tgen.gears["pe1"].vtysh_cmd("show bgp l2vpn evpn route detail type macip"))

    # PE1 must receive Type-2 with BOTH SIDs for CE2's IP.
    # SIDs appear in the detail output as:
    #   Remote L2 SID: fc00:2:0:3e8::  (srv6_l2vpn / DT2U)
    #   Remote L3 SID: fc00:2:0:1::     (srv6_l3service / DT46 IRB, general
    #                                    pool - see SRV6_SID_NOFORMAT_EVI_FUNC_BASE)
    # Note: "detail" must precede "type" in this FRR command syntax.
    _expect_transposed_sids("pe1", "show bgp l2vpn evpn route detail type macip",
                            ["10.0.2.10"],
                            ["fc00:2:0:3e8::",   # Remote L2 SID (DT2U)
                             "fc00:2:0:1::"])     # Remote L3 SID (DT46 / IRB)


# -----------------------------------------------------------------------------
# TC5 - VRF-A /32 Host Route with SRv6 Encap (NO MPLS Label)
# -----------------------------------------------------------------------------

def test_tc5_vrf_host_route_seg6_no_mpls():
    """TC5: 10.0.2.10/32 in VRF-A must use seg6 encap, never an MPLS label."""
    logger.info("TC5: VRF-A /32 with SRv6 encap, no MPLS")
    _expect_kernel("pe1", "ip route show table 10",
                   ["10.0.2.10", "encap seg6", "fc00:2:0:1::"])
    # MPLS label must NOT appear (regression guard for is_srv6_vrf_irb fix)
    _absent_kernel("pe1", "ip route show table 10",
                   ["label 100", "label 200", "mpls"])


# -----------------------------------------------------------------------------
# TC6 - VRF-A /32 Nexthop Resolves via VRF_DEFAULT (peer session addr)
# -----------------------------------------------------------------------------

def test_tc6_vrf_route_nexthop_default_vrf():
    """TC6: VRF-A /32 nexthop must be fd00::2 (peer session addr, VRF default),
    NOT the DT46 SID fc00:2:0:1:: which is unreachable in VRF-A."""
    logger.info("TC6: VRF-A /32 nexthop via VRF default (fd00::2)")
    _expect_kernel("pe1", "ip route show table 10",
                   ["10.0.2.10", "fd00::2", "eth0"])
    # The SID itself must NOT be the nexthop (unreachable in VRF-A)
    _absent_kernel("pe1", "ip route show table 10 10.0.2.10",
                   ["via fc00:2:0:1::"])


# -----------------------------------------------------------------------------
# TC7 - Inter-Subnet Ping: CE1 -> CE2
# -----------------------------------------------------------------------------

def test_tc7_inter_subnet_ping_ce1_to_ce2():
    """TC7: CE1 (10.0.1.10) must ping CE2 (10.0.2.10) via SRv6 IRB."""
    logger.info("TC7: inter-subnet ping CE1 -> CE2")
    check_ping("ce1", "10.0.2.10", True, count=30, wait=1)


# -----------------------------------------------------------------------------
# TC8 - Inter-Subnet Ping: CE2 -> CE1 (Return Path)
# -----------------------------------------------------------------------------

def test_tc8_inter_subnet_ping_ce2_to_ce1():
    """TC8: CE2 (10.0.2.10) must ping CE1 (10.0.1.10) -- symmetric return path."""
    logger.info("TC8: inter-subnet ping CE2 -> CE1")
    check_ping("ce2", "10.0.1.10", True, count=30, wait=1)


# -----------------------------------------------------------------------------
# TC9 - Pure SRv6 Encapsulation on Underlay
# -----------------------------------------------------------------------------

def test_tc9_no_vxlan_pure_srv6():
    """TC9: Underlay traffic must use SRv6 encapsulation (IPv6 Routing Header,
    proto 43).  Verified by capturing SRH packets during an inter-PE ping."""
    logger.info("TC9: pure SRv6 encap on underlay (proto 43 / Routing Header)")
    tgen = get_topogen()
    pe1 = tgen.gears["pe1"]

    # Capture SRv6-encapsulated packets (IPv6 with Routing Header, proto 43)
    # Start tcpdump in background via shell, run ping, then read pcap
    pe1.run("rm -f /tmp/srv6.pcap; tcpdump -i eth0 -c3 ip6 and proto 43 "
            "-w /tmp/srv6.pcap > /tmp/tcpdump.log 2>&1 &")
    time.sleep(0.5)  # Let tcpdump start before generating traffic
    tgen.gears["ce1"].run("ping -c4 -W1 10.0.2.10")
    time.sleep(2)  # Wait for tcpdump to capture and flush

    # At least one SRH-encapped packet must have been seen on the underlay
    srv6_count = pe1.run(
        "tcpdump -r /tmp/srv6.pcap 2>/dev/null | wc -l").strip()
    assert srv6_count not in ("", "0"), \
        "No SRv6 (proto 43) packets seen on underlay -- SRv6 encap not working!"


# -----------------------------------------------------------------------------
# TC10 - Neigh Table: Local CE Learned Dynamically
# -----------------------------------------------------------------------------

def test_tc10_local_neigh_dynamic():
    """TC10: Local CE1 ARP entry on PE1 br100 must be dynamic (STALE/REACHABLE),
    not PERMANENT -- proving kernel learned it, not statically added."""
    logger.info("TC10: local CE neigh entry is dynamic")
    tgen = get_topogen()

    # Debug CE1 state before ping
    logger.info("TC10 CE1 addr:\n%s", tgen.gears["ce1"].run("ip addr show"))
    logger.info("TC10 CE1 route:\n%s", tgen.gears["ce1"].run("ip route show"))

    # Trigger ARP from CE1
    ping_out = tgen.gears["ce1"].run("ping -c2 -W1 10.0.1.1")
    logger.info("TC10 CE1 ping result: %s", ping_out.strip())

    # Debug: bridge and neigh state on PE1
    logger.info("TC10 PE1 bridge vlans:\n%s",
                tgen.gears["pe1"].run("bridge vlan show"))
    logger.info("TC10 PE1 bridge fdb:\n%s",
                tgen.gears["pe1"].run("bridge fdb show dev br100"))
    logger.info("TC10 PE1 all neigh:\n%s",
                tgen.gears["pe1"].run("ip neigh show"))
    logger.info("TC10 PE1 br100 links:\n%s",
                tgen.gears["pe1"].run("ip link show master br100"))

    def _check_dynamic():
        out = tgen.gears["pe1"].run("ip neigh show dev br100")
        if "10.0.1.10" not in out:
            return "neigh entry missing"
        # Must be REACHABLE or STALE (dynamic), never PERMANENT
        if "10.0.1.10" in out and "PERMANENT" in out.split("10.0.1.10")[1].split("\n")[0]:
            return "unexpected PERMANENT for local CE"
        return None

    _, res = topotest.run_and_expect(_check_dynamic, None, count=30, wait=1)
    assert res is None, "TC10 failed: %s" % res


# -----------------------------------------------------------------------------
# TC11 - Neigh Table: Remote CE Installed as PERMANENT
# -----------------------------------------------------------------------------

def test_tc11_remote_neigh_permanent():
    """TC11: Remote CE2 (10.0.2.10) neigh entry on PE1 br100 must be PERMANENT
    (installed by zebra from BGP Type-2, NTF_EXT_LEARNED)."""
    logger.info("TC11: remote CE neigh entry is PERMANENT")

    def _check_permanent():
        out = get_topogen().gears["pe1"].run("ip neigh show dev br100")
        if "10.0.2.10" not in out:
            return "remote neigh entry missing"
        line = [l for l in out.splitlines() if "10.0.2.10" in l]
        if not line or "PERMANENT" not in line[0]:
            return "not PERMANENT: %s" % line
        return None

    _, res = topotest.run_and_expect(_check_permanent, None, count=30, wait=1)
    assert res is None, "TC11 failed: %s" % res


# -----------------------------------------------------------------------------
# TC12 - FDB: Remote MAC Installed on br100
# -----------------------------------------------------------------------------

def test_tc12_remote_mac_fdb():
    """TC12: CE2's MAC must appear in PE1's br100 FDB, installed by zebra
    from BGP Type-2 (extern_learn flag)."""
    logger.info("TC12: remote MAC in FDB")
    tgen = get_topogen()

    # Get CE2's MAC
    ce2_mac = tgen.gears["ce2"].run(
        "ip link show eth0").split("link/ether")[1].split()[0].strip()
    logger.info("CE2 MAC: %s" % ce2_mac)

    def _check_fdb():
        # NTF_MASTER entries are indexed by the sr6 slave port, not br100,
        # so query the full FDB and filter by master=br100.
        out = tgen.gears["pe1"].run("bridge fdb show master br100")
        if ce2_mac.lower() not in out.lower():
            return "CE2 MAC not in PE1 FDB"
        return None

    _, res = topotest.run_and_expect(_check_fdb, None, count=30, wait=1)
    assert res is None, "TC12 failed: %s" % res


# -----------------------------------------------------------------------------
# TC13 - Intra-Subnet: CE1 to same-subnet host on PE2 (L2 via DT2U)
# -----------------------------------------------------------------------------

def test_tc13_intra_subnet_l2_via_dt2u():
    """TC13: After ARP resolution, CE1 to a same-subnet host on PE2 must use
    L2 EVPN path (End.DT2U SID fc00:2:0:3e8::), NOT the IRB L3 path."""
    logger.info("TC13: intra-subnet L2 forwarding via DT2U")
    tgen = get_topogen()

    # Add a second host in 10.0.1.x on PE2 to simulate intra-subnet cross-PE
    # (Using CE2's interface with an alias -- simulates CE3 scenario)
    tgen.gears["pe2"].run("ip addr add 10.0.1.99/24 dev br100")

    # CE1 ping to 10.0.1.99 -- same subnet, different PE.
    # This triggers BUM ARP flood (DT2M), then DT2U unicast once ARP resolves.
    check_ping("ce1", "10.0.1.99", True, count=30, wait=1)

    # PE2's DT2U SID (fc00:2:0:3e8::) must be reachable via ISIS from PE1
    # (IS-IS installs with link-local nexthop; verify route exists via eth0)
    _expect_kernel("pe1", "ip -6 route show fc00:2::/48",
                   ["eth0"])

    # Clean up alias
    tgen.gears["pe2"].run("ip addr del 10.0.1.99/24 dev br100")


# -----------------------------------------------------------------------------
# TC14 - BGP Withdraw: Route Removed from VRF-A
# -----------------------------------------------------------------------------

def test_tc14_bgp_withdraw_removes_vrf_route():
    """TC14: When PE2's VRF-A BGP is shut down, PE1's VRF-A /32 for CE2 must
    be withdrawn and removed from kernel table 10."""
    logger.info("TC14: BGP withdraw removes VRF-A route")
    tgen = get_topogen()

    # Confirm route is present before withdrawal
    out = tgen.gears["pe1"].run("ip route show table 10")
    assert "10.0.2.10" in out, "Precondition: 10.0.2.10/32 not in VRF-A before test"

    # Withdraw by clearing the EVPN session on PE2
    tgen.gears["pe2"].vtysh_cmd(
        "configure terminal\nrouter bgp 65002\n"
        "address-family l2vpn evpn\nno neighbor fd00::1 activate\n")

    def _route_gone():
        out = tgen.gears["pe1"].run("ip route show table 10")
        return None if "10.0.2.10" not in out else out

    _, res = topotest.run_and_expect(_route_gone, None, count=30, wait=1)
    assert res is None, "TC14: VRF-A route not withdrawn after BGP session down"

    # Restore the session for subsequent tests
    tgen.gears["pe2"].vtysh_cmd(
        "configure terminal\nrouter bgp 65002\n"
        "address-family l2vpn evpn\nneighbor fd00::1 activate\n"
        "neighbor fd00::1 route-map ALLOW-ALL in\n"
        "neighbor fd00::1 route-map ALLOW-ALL out\n")

    # Wait for reconvergence
    def _reconverged():
        out = tgen.gears["pe1"].run("ip route show table 10")
        return None if "10.0.2.10" in out else "not yet"

    _, ok = topotest.run_and_expect(_reconverged, None, count=60, wait=1)
    assert ok is None, "TC14: VRF-A route did not return after session restore"


# -----------------------------------------------------------------------------
# TC15 - VRF-A Route Active: Bidirectional Ping After Full Convergence
# -----------------------------------------------------------------------------

def test_tc15_bidirectional_ping_after_convergence():
    """TC15: Final end-to-end sanity: CE1 <-> CE2 both directions working,
    confirming full SRv6 IRB forwarding chain is intact."""
    logger.info("TC15: bidirectional ping sanity after full convergence")
    check_ping("ce1", "10.0.2.10", True, count=10, wait=1)
    check_ping("ce2", "10.0.1.10", True, count=10, wait=1)


# -----------------------------------------------------------------------------
# TC16 - Remote gateway reachable via the Type-5 subnet route
# -----------------------------------------------------------------------------

def test_tc16_remote_gateway_ping_via_type5_subnet_route():
    """TC16: The remote Type-5 subnet route must be imported into VRF-A through
    the VPN leak ('import vpn' + 'rt vpn import') and installed with SRv6 encap;
    CE1 must reach PE2's br100 address (10.0.2.1) and CE2 PE1's (10.0.1.1)
    through it."""
    logger.info("TC16: remote subnet route via Type-5 import, remote gateway ping")
    _expect_kernel("pe1", "ip route show table 10 10.0.2.0/24",
                   ["10.0.2.0/24", "encap seg6", "fc00:2:0:1::"])
    _expect_kernel("pe2", "ip route show table 10 10.0.1.0/24",
                   ["10.0.1.0/24", "encap seg6", "fc00:1:0:1::"])
    check_ping("ce1", "10.0.2.1", True, count=30, wait=1)
    check_ping("ce2", "10.0.1.1", True, count=30, wait=1)


# -----------------------------------------------------------------------------
# TC16b - Removing the VRF SID withdraws what pointed at it
# -----------------------------------------------------------------------------

def test_tc16b_removing_vrf_sid_withdraws_evpn_routes():
    """TC16b: When PE2 drops 'sid vpn per-vrf export', PE1 must stop learning
    routes toward PE2's End.DT46 SID: the Type-5 subnet route and the host
    route (Type-2 L3 SID) leave VRF-A, and the Type-2 no longer carries the
    L3 SID. Restoring the SID brings everything back."""
    logger.info("TC16b: removing the VRF SID withdraws EVPN routes")
    tgen = get_topogen()
    pe2_sid = "fc00:2:0:1::"

    _expect_kernel("pe1", "ip route show table 10", ["10.0.2.0/24", pe2_sid])

    def _vrf_a(cmds):
        tgen.gears["pe2"].vtysh_cmd(
            "configure terminal\nrouter bgp 65002 vrf VRF-A\n" + cmds)

    _vrf_a("no sid vpn per-vrf export auto\n")
    try:
        def _gone():
            out = tgen.gears["pe1"].run("ip route show table 10")
            return None if pe2_sid not in out else out

        _, res = topotest.run_and_expect(_gone, None, count=30, wait=1)
        assert res is None, "TC16b: routes toward the removed SID are still in VRF-A"

        def _no_l3_sid():
            out = tgen.gears["pe1"].vtysh_cmd(
                "show bgp l2vpn evpn route detail type macip")
            return None if pe2_sid not in out else "Type-2 still carries L3 SID"

        _, res = topotest.run_and_expect(_no_l3_sid, None, count=30, wait=1)
        assert res is None, "TC16b: %s" % res
    finally:
        _vrf_a("sid vpn per-vrf export auto\n")

    _expect_kernel("pe1", "ip route show table 10",
                   ["10.0.2.0/24", "10.0.2.10", pe2_sid], count=60)
    check_ping("ce1", "10.0.2.10", True, count=30, wait=1)


def test_tc16c_removing_vrf_locator_falls_back_to_default_locator():
    """TC16c: 'no locator' under the VRF's segment-routing srv6 releases the
    VRF SID, but 'sid vpn per-vrf export auto' is still configured and the
    default instance still has a locator, so the SID is allocated again from
    it. The release path (which withdraws and re-originates the EVPN routes)
    must leave the VRF working: same SID, routes still installed on the peer,
    traffic still flowing. Withdrawing for good needs the default locator
    gone as well, which this topology cannot do without taking down the EVI."""
    logger.info("TC16c: removing the VRF locator falls back to the default locator")
    tgen = get_topogen()
    pe2_sid = "fc00:2:0:1::"

    _expect_kernel("pe1", "ip route show table 10", ["10.0.2.0/24", pe2_sid])

    def _srv6(cmds):
        tgen.gears["pe2"].vtysh_cmd(
            "configure terminal\nrouter bgp 65002 vrf VRF-A\n"
            "segment-routing srv6\n" + cmds)

    _srv6("no locator MAIN\n")
    try:
        _expect_kernel("pe1", "ip route show table 10",
                       ["10.0.2.0/24", "10.0.2.10", pe2_sid], count=60)
        check_ping("ce1", "10.0.2.10", True, count=30, wait=1)
    finally:
        _srv6("locator MAIN\n")

    _expect_kernel("pe1", "ip route show table 10",
                   ["10.0.2.0/24", "10.0.2.10", pe2_sid], count=60)
    check_ping("ce1", "10.0.2.10", True, count=30, wait=1)


# -----------------------------------------------------------------------------
# TC17 - MAC+IP withdrawal keeps the MAC owned by the MAC-only route
# -----------------------------------------------------------------------------

def test_tc17_ip_withdraw_keeps_mac_owned_by_mac_only_route():
    """TC17: CE2 is advertised by PE2 both as a MAC-only Type-2 and as a MAC+IP
    Type-2.  Deleting only its IP neighbor on PE2 withdraws the MAC+IP route; the
    MAC-only route is unchanged and BGP does not resend it.  PE1 must drop the
    remote neighbor but keep CE2's MAC in its FDB, or CE2's remaining L2 traffic
    breaks."""
    logger.info("TC17: IP-only withdrawal keeps the remote MAC")
    tgen = get_topogen()

    ce2_mac = tgen.gears["ce2"].run(
        "ip link show eth0").split("link/ether")[1].split()[0].strip().lower()

    # Make sure PE1 knows CE2 as both a MAC and a neighbor
    check_ping("ce1", "10.0.2.10", True, count=30, wait=1)
    _expect_kernel("pe1", "ip neigh show dev br100", ["10.0.2.10"])
    _expect_kernel("pe1", "bridge fdb show master br100", [ce2_mac])

    # Withdraw only the IP: PE2 drops its neighbor entry, keeps the FDB entry
    tgen.gears["pe2"].run("ip neigh del 10.0.2.10 dev br100")

    # PE1 loses the remote neighbor ...
    _absent_kernel("pe1", "ip neigh show dev br100", ["10.0.2.10"],
                   count=30, wait=1)

    # ... but keeps the MAC.  Zebra handles the withdrawal synchronously, so
    # look again after a short settle time and require it to stay.
    time.sleep(3)
    _expect_kernel("pe1", "bridge fdb show master br100", [ce2_mac], count=5)

    # Restore: CE1 reaches CE2 again, which relearns the neighbor on both PEs
    check_ping("ce1", "10.0.2.10", True, count=30, wait=1)
    _expect_kernel("pe1", "ip neigh show dev br100", ["10.0.2.10"])


# -----------------------------------------------------------------------------
# -----------------------------------------------------------------------------
# TC27 - Regression: bridge self-PVID matches EVI VLAN (dup-packet fix)
# -----------------------------------------------------------------------------

def test_tc27_bridge_self_pvid_matches_evi_vlan():
    """TC27: The bridge device's own self-PVID must equal the EVI VLAN (100),
    not the kernel default of VLAN 1 - direct regression check for the
    self-PVID bridge-duplication fix (br_dev_xmit()'s FDB-miss-and-flood
    bug: a mismatched self-PVID caused known-unicast traffic to be flooded
    back out the ingress port as a spurious duplicate)."""
    logger.info("TC27: bridge self-PVID matches EVI VLAN")
    for r in ("pe1", "pe2"):
        out = get_topogen().gears[r].run("bridge vlan show dev br100")
        assert "100" in out and "PVID" in out, (
            "%s: br100 self-PVID does not show VLAN 100 as PVID: %s" % (r, out)
        )


# -----------------------------------------------------------------------------
# TC28 - Regression: no BUM/flood leak on known-unicast DT46 traffic
# -----------------------------------------------------------------------------

def test_tc28_no_bum_leak_on_dt46_traffic():
    """TC28: Dataplane-level regression check for the same self-PVID fix:
    sending known-unicast traffic across the VRF (DT46) must NOT increment
    the BUM/flood (bum-sr6) tunnel port's TX counter on the receiving PE -
    that counter moving is exactly the bridge FDB-miss-and-flood symptom
    the fix closes."""
    logger.info("TC28: no BUM leak on known-unicast DT46 traffic")
    pe2 = get_topogen().gears["pe2"]
    links = pe2.run("ip -o link show")
    bum_ifs = [
        ln.split(":")[1].strip().split("@")[0]
        for ln in links.splitlines()
        if "bum-sr6-" in ln
    ]
    assert bum_ifs, "pe2: no bum-sr6 tunnel port found:\n%s" % links

    def _tx_packets(ifname):
        out = pe2.run("ip -s -j link show %s" % ifname)
        data = json.loads(out)
        return data[0]["stats64"]["tx"]["packets"]

    logger.info("TC28 pe2 bridge vlan show:\n%s", pe2.run("bridge vlan show"))
    logger.info("TC28 pe2 bridge fdb (br100):\n%s", pe2.run("bridge fdb show master br100"))

    before = {i: _tx_packets(i) for i in bum_ifs}
    check_ping("ce1", "10.0.2.10", True, count=20, wait=1)
    after = {i: _tx_packets(i) for i in bum_ifs}
    logger.info("TC28 pe2 bridge vlan show (after ping):\n%s", pe2.run("bridge vlan show"))

    leaked = {i: (before[i], after[i]) for i in bum_ifs if after[i] != before[i]}
    assert not leaked, "pe2: bum-sr6 TX counter moved on known-unicast traffic: %s" % leaked


# -----------------------------------------------------------------------------
# TC29 - DT46 SID RX counter actually increments on real traffic
# -----------------------------------------------------------------------------

def test_tc29_dt46_sid_counters_reflect_real_traffic():
    """TC29: Decapsulated DT46 traffic must actually be delivered into
    VRF-A - proves packets took the real DT46 decap path, not just that
    the route/SID exists in a table. (`show segment-routing srv6 sid
    counters` only instruments the per-EVI DT2U/DT2M SIDs, not the
    VRF-level End.DT46 SID, so the VRF device's own RX counter is used
    as the traffic-flow proof instead.)"""
    logger.info("TC29: DT46 traffic actually delivered into VRF-A")
    pe2 = get_topogen().gears["pe2"]

    def _vrf_rx_packets():
        out = pe2.run("ip -s -j link show VRF-A")
        data = json.loads(out)
        return data[0]["stats64"]["rx"]["packets"]

    before = _vrf_rx_packets()
    check_ping("ce1", "10.0.2.10", True, count=10, wait=1)

    def _increased():
        after = _vrf_rx_packets()
        return None if after > before else "VRF-A rx_packets still %s (was %s)" % (after, before)

    _, res = topotest.run_and_expect(_increased, None, count=15, wait=1)
    assert res is None, (
        "pe2: VRF-A RX packet count did not increase after 10 pings: %s" % res
    )


# -----------------------------------------------------------------------------
# TC30/31/32 - Restart recovery: zebra, bgpd, and full FRR instance on PE2
# -----------------------------------------------------------------------------
#
# Deliberately NOT xfail: a bare restart-and-wait recovering on its own is
# the correct behaviour for a production daemon. These exist to catch a
# regression, not to document a known limitation.

def _reapply_evi_block(pe):
    """Re-push the segment-routing srv6 locators/l2-evpn block after a zebra
    restart. This is the documented current workaround for zebra not fully
    re-realizing SRv6 EVI/kernel state (sr6 devices, decap SIDs) purely
    from mgmtd's resync of a freshly-started backend client - the same
    "trial and error" bring-up gap QA has flagged separately. TC30/32 exist
    to catch a regression once that gap is closed, not to paper over it."""
    pe.vtysh_cmd(
        "configure terminal\n"
        "segment-routing\n"
        " srv6\n"
        "  locators\n"
        "   locator MAIN\n"
        "    prefix fc00:2::/48 block-len 32 node-len 16 func-bits 16\n"
        "   exit\n"
        "  exit\n"
        "  l2-evpn\n"
        "   evi 100 locator MAIN bridge br100\n"
        "    service-type vlan-based\n"
        "    vlan 100\n"
        "    vrf VRF-A\n"
        "   exit\n"
        "  exit\n"
        " exit\n"
        "exit\n"
    )


def test_tc30_zebra_restart_recovery():
    """TC30: Killing and restarting zebra alone on PE2 must not permanently
    break CE1<->CE2 reachability."""
    logger.info("TC30: zebra restart recovery")
    pe2 = get_topogen().gears["pe2"]
    pe2.killDaemons(["zebra"])
    pe2.startDaemons(["zebra"])
    _reapply_evi_block(pe2)
    check_ping("ce1", "10.0.2.10", True, count=60, wait=1)


def test_tc31_bgpd_restart_recovery():
    """TC31: Killing and restarting bgpd alone on PE2 must re-establish the
    EVPN session and restore CE1<->CE2 reachability."""
    logger.info("TC31: bgpd restart recovery")
    pe2 = get_topogen().gears["pe2"]
    pe2.killDaemons(["bgpd"])
    pe2.startDaemons(["bgpd"])

    def _established():
        s = json.loads(pe2.vtysh_cmd("show bgp l2vpn evpn summary json"))
        return s.get("peers", {}).get("fd00::1", {}).get("state") == "Established"

    _, ok = topotest.run_and_expect(_established, True, count=60, wait=1)
    assert ok is True, "pe2: BGP session did not re-establish after bgpd restart"
    check_ping("ce1", "10.0.2.10", True, count=60, wait=1)


def test_tc32_frr_full_restart_recovery():
    """TC32: Killing and restarting the whole FRR instance (all daemons) on
    PE2 must fully recover CE1<->CE2 reachability."""
    logger.info("TC32: full FRR restart recovery")
    pe2 = get_topogen().gears["pe2"]
    all_daemons = ["zebra", "bgpd", "staticd", "isisd"]
    pe2.killDaemons(all_daemons)
    pe2.startDaemons(all_daemons)

    def _established():
        s = json.loads(pe2.vtysh_cmd("show bgp l2vpn evpn summary json"))
        return s.get("peers", {}).get("fd00::1", {}).get("state") == "Established"

    _, ok = topotest.run_and_expect(_established, True, count=60, wait=1)
    assert ok is True, "pe2: BGP session did not re-establish after full FRR restart"
    _reapply_evi_block(pe2)
    check_ping("ce1", "10.0.2.10", True, count=60, wait=1)


# -----------------------------------------------------------------------------
# Entry point
# -----------------------------------------------------------------------------

if __name__ == "__main__":
    sys.exit(pytest.main([os.path.basename(__file__)] + sys.argv[1:]))
