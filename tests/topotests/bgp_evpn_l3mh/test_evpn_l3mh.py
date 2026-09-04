#!/usr/bin/env python
# SPDX-License-Identifier: ISC

#
# test_evpn_l3mh.py
#
# Copyright (c) 2026 by
# Cisco Systems, Inc.
# Patrice Brissette
#
# EVPN L3 multihoming -- RT-2 without L2VNI, pure-L3 ARP/ND neighbor sync.
#
#
# The base-convergence tests below pass against the current code; the pure-L3
# RT-2 acceptance tests are enabled as the feature lands (origination, ES-peer
# neighbor sync, and the non-peer type-5-route / no-sync-neighbor checks now
# pass).
#

"""
EVPN L3 multihoming (RT-2 without L2VNI) -- reference topology

    +--------+        +--------+
    | spine1 |        | spine2 |      full leaf-spine mesh (eBGP)
    +--------+        +--------+
       |    \\        /     |
       |     \\      /      |
    +-------+ +-------+ +-------+
    | leaf1 | | leaf2 | | leaf3 |     VTEPs, L3VNI per VRF, NO L2VNI
    +-------+ +-------+ +-------+
        \\       /          |
         \\ ESI /           |          host1 dual-homed to leaf1+leaf2
        +-------+       +-------+       host2 single-homed to leaf3
        | host1 |       | host2 |
        +-------+       +-------+

Dataplane model: FRR drives the Linux kernel in *VLAN-aware* bridge mode (a
single VLAN-filtering bridge carrying multiple VLANs). Each VLAN is a broadcast
domain; the per-VLAN SVI (vlanNNN) provides the VLAN id that becomes the RT-2
Ethernet Tag (ETAG) used to select the destination BD/SVI on receive:

  * VLAN 4000 : the L3VNI broadcast domain. SVI vlan4000 (dummy, no host IP) in
                vrf1; realized as a per-VNI VXLAN device vni4000 (id 4000)
                enslaved to the VLAN-aware bridge.
  * VLAN 100  : host1's access broadcast domain on the MH pair (leaf1/leaf2).
                SVI vlan100 holds the anycast gateway in vrf1 and is NOT mapped
                to any VNI -> NO L2VNI. leaf3 uses its own access BD VLAN 200
                (SVI vlan200, a different subnet) for the single-homed host2, so
                host2 -> host1 is inter-subnet routed over the L3VNI.

VLAN 100 having an SVI but no VNI mapping is the "acc_bd->zevpn == NULL"
precondition the feature under test targets. Because the bridge is VLAN-aware,
the access BD carries a real vid (100), which the feature emits as the RT-2 ETAG
so a receiving leaf knows which SVI to install the synced neighbor on.
"""

import os
import sys
import json
import platform
import contextlib
from functools import partial

import pytest

# Save the Current Working Directory to find configuration files.
CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

# pylint: disable=C0413
from lib import topotest
from lib.topogen import Topogen, TopoRouter, get_topogen
from lib.topolog import logger

pytestmark = [
    pytest.mark.bgpd,
    pytest.mark.evpn,
]

#####################################################
##
##   Topology
##
#####################################################

# VTEP loopback / router-id addresses.
LEAF_LO = {
    "leaf1": "10.0.0.11",
    "leaf2": "10.0.0.12",
    "leaf3": "10.0.0.13",
}

# ESI bond system-mac shared by the leaf1/leaf2 multihoming pair (es-id 1).
# The resulting type-3 ESI is 03:44:38:39:ff:ff:01:00:00:01.
ES_SYS_MAC = "44:38:39:ff:ff:01"
ES1_ID = "03:44:38:39:ff:ff:01:00:00:01"
# Reprogrammed ESI (es-id 2, same sys-mac) used by the ESI-change tests.
ES2_ID = "03:44:38:39:ff:ff:01:00:00:02"

# Tenant VRF / L3VNI / host broadcast-domain layout.
VRF = "vrf1"
VRF_TABLE = 1001
L3VNI = 4000
HOST_VID = 100  # host access BD VLAN -- has an SVI but is NOT mapped to any L2VNI
ANYCAST_GW = "45.0.0.1"

# leaf3 / host2 live in a DIFFERENT subnet from host1, so host2 -> host1 is
# inter-subnet routed: host2 resolves its own gateway, leaf3 routes over the
# L3VNI fabric, and the last hop to host1 uses the ES-peer's synced neighbor.
LEAF3_VID = 200
LEAF3_GW = "46.0.0.1"

HOST_IP = {
    "host1": "45.0.0.101",
    "host2": "46.0.0.102",
}

# Additional no-L2VNI BDs on the MH pair (leaf1/leaf2), same VRF/L3VNI, to prove
# per-BD/ETAG isolation. VLAN 101 carries host3 (a second IP on host1's bond,
# tagged); VLAN 102 exists as an SVI only (a third BD with no sync traffic).
HOST_VID2 = 101
HOST_VID3 = 102
ANYCAST_GW2 = "45.0.1.1"
ANYCAST_GW3 = "45.0.2.1"
HOST3_IP = "45.0.1.103"

# L2VNI mapped to VLAN100 at runtime for the ML3<->ML2 transition tests.
L2VNI_100 = 10100

# run_and_expect polling bounds: max retries and per-retry wait (seconds).
# run_and_expect returns as soon as the check passes, so these are upper bounds.
WAIT_COUNT = 30
WAIT_STEP = 2


def build_topo(tgen):
    """
    2 spines, 3 leaves (VTEPs), host1 dual-homed to leaf1+leaf2 via an ESI bond,
    host2 single-homed to leaf3.
    """
    for name in (
        "spine1",
        "spine2",
        "leaf1",
        "leaf2",
        "leaf3",
        "host1",
        "host2",
    ):
        tgen.add_router(name)

    # Leaf-spine mesh. Order of add_link determines interface numbering, so we
    # create the switches so that:
    #   leaf1/2/3-eth0 -> spine1, -eth1 -> spine2, -eth2 -> host
    #   spine1-eth0/1/2 -> leaf1/2/3, spine2-eth0/1/2 -> leaf1/2/3
    def link(swname, a, b):
        sw = tgen.add_switch(swname)
        sw.add_link(tgen.gears[a])
        sw.add_link(tgen.gears[b])

    link("sw1", "spine1", "leaf1")
    link("sw2", "spine1", "leaf2")
    link("sw3", "spine1", "leaf3")
    link("sw4", "spine2", "leaf1")
    link("sw5", "spine2", "leaf2")
    link("sw6", "spine2", "leaf3")

    # Access side: host1 dual-homed (leaf1-eth2 + leaf2-eth2), host2 on leaf3.
    link("sw7", "leaf1", "host1")
    link("sw8", "leaf2", "host1")
    link("sw9", "leaf3", "host2")


#####################################################
##
##   Kernel dataplane setup
##
#####################################################


def config_leaf_base(
    node, lo_ip, host_vid=HOST_VID, gw_ip=ANYCAST_GW, extra_host_bds=None
):
    """VLAN-aware bridge (single VLAN-filtering bridge), tenant VRF, and a
    per-VNI VXLAN device for the L3VNI only. host_vid is the host access BD (its
    SVI has no VXLAN device -> no L2VNI): VLAN 100 for host1 on the MH pair,
    VLAN 200 for host2 on leaf3. VLAN 4000 is the L3VNI (SVI vlan4000, carried
    by the per-VNI device vni4000). Both SVIs are in the tenant VRF.

    extra_host_bds is an optional list of (vid, gw_ip) additional no-L2VNI BDs
    in the same VRF (used on the MH pair to test per-BD/ETAG isolation).
    """
    # Loopback (VTEP source). Applied in the kernel so the VXLAN 'local' address
    # exists before the device is created and so redistribute-connected has it.
    node.run("ip addr add %s/32 dev lo 2>/dev/null || true" % lo_ip)

    # VLAN-aware bridge.
    node.run("ip link del br_default 2>/dev/null || true")
    node.run("ip link add dev br_default type bridge stp_state 0")
    node.run("ip link set dev br_default type bridge vlan_filtering 1")
    node.run("ip link set dev br_default up")

    # Tenant VRF.
    node.run("ip link add %s type vrf table %d 2>/dev/null || true" % (VRF, VRF_TABLE))
    node.run("ip link set dev %s up" % VRF)

    # L3VNI VXLAN device (per-VNI device layout): one netdev per VNI, added to
    # the VLAN-aware bridge as an access port on its VLAN. The host access VLAN
    # (100) deliberately has NO VXLAN device, hence NO L2VNI.
    node.run("ip link del vni%d 2>/dev/null || true" % L3VNI)
    node.run(
        "ip link add vni%d type vxlan id %d dstport 4789 local %s nolearning"
        % (L3VNI, L3VNI, lo_ip)
    )
    node.run("ip link set dev vni%d master br_default" % L3VNI)
    node.run("/sbin/bridge link set dev vni%d learning off" % L3VNI)
    node.run("/sbin/bridge vlan del vid 1 dev vni%d" % L3VNI)
    node.run("/sbin/bridge vlan add vid %d dev vni%d pvid untagged" % (L3VNI, L3VNI))
    node.run("ip link set dev vni%d up" % L3VNI)

    # Bridge self VLAN membership.
    node.run("/sbin/bridge vlan add vid %d dev br_default self" % host_vid)
    node.run("/sbin/bridge vlan add vid %d dev br_default self" % L3VNI)

    # L3VNI SVI in the VRF.
    node.run("ip link add link br_default name vlan%d type vlan id %d" % (L3VNI, L3VNI))
    node.run("ip link set dev vlan%d master %s" % (L3VNI, VRF))
    node.run("ip link set dev vlan%d up" % L3VNI)

    # Host access-BD SVI in the VRF, with the anycast gateway. This VLAN has an
    # SVI but NO VNI mapping -- it is the "acc_bd->zevpn == NULL" (no-L2VNI)
    # case the feature targets. Its vid is the RT-2 ETAG source.
    node.run(
        "ip link add link br_default name vlan%d type vlan id %d" % (host_vid, host_vid)
    )
    node.run("ip link set dev vlan%d master %s" % (host_vid, VRF))
    node.run("ip link set dev vlan%d up" % host_vid)
    node.run("ip addr add %s/24 dev vlan%d" % (gw_ip, host_vid))
    node.run("/sbin/sysctl -w net.ipv4.conf.vlan%d.proxy_arp=1" % host_vid)

    # Additional no-L2VNI BDs (extra VLANs/SVIs) in the same VRF.
    for bd_vid, bd_gw in extra_host_bds or ():
        node.run("/sbin/bridge vlan add vid %d dev br_default self" % bd_vid)
        node.run(
            "ip link add link br_default name vlan%d type vlan id %d" % (bd_vid, bd_vid)
        )
        node.run("ip link set dev vlan%d master %s" % (bd_vid, VRF))
        node.run("ip link set dev vlan%d up" % bd_vid)
        node.run("ip addr add %s/24 dev vlan%d" % (bd_gw, bd_vid))
        node.run("/sbin/sysctl -w net.ipv4.conf.vlan%d.proxy_arp=1" % bd_vid)


def config_esi_bond(node, member, extra_vids=()):
    """Leaf-side ESI bond (es-id 1) facing the dual-homed host1, added to the
    VLAN-aware bridge as an access port on host1's VLAN 100."""
    node.run("ip link add dev hostbond1 type bond mode 802.3ad")
    node.run("ip link set dev hostbond1 type bond lacp_rate 1")
    node.run("ip link set dev hostbond1 type bond miimon 100")
    node.run("ip link set dev hostbond1 type bond xmit_hash_policy layer3+4")
    node.run("ip link set dev hostbond1 type bond min_links 1")
    node.run("ip link set dev hostbond1 type bond ad_actor_system %s" % ES_SYS_MAC)
    node.run("ip link set dev %s down" % member)
    node.run("ip link set dev %s master hostbond1" % member)
    node.run("ip link set dev %s up" % member)
    node.run("ip link set dev hostbond1 up")
    node.run("ip link set dev hostbond1 master br_default")
    node.run("/sbin/bridge vlan del vid 1 dev hostbond1")
    node.run("/sbin/bridge vlan add vid %d dev hostbond1 pvid untagged" % HOST_VID)
    # Trunk the extra BDs (tagged) so host1's bond can carry a second BD.
    for v in extra_vids:
        node.run("/sbin/bridge vlan add vid %d dev hostbond1" % v)


def config_access_port(node, member, vid=HOST_VID):
    """Leaf-side single-homed access port (no ESI), added to the VLAN-aware
    bridge as an access port on its VLAN."""
    node.run("ip link set dev %s master br_default" % member)
    node.run("/sbin/bridge vlan del vid 1 dev %s" % member)
    node.run("/sbin/bridge vlan add vid %d dev %s pvid untagged" % (vid, member))


def config_add_l2vni(node, lo_ip, vid, vni):
    """Map an L2VNI to an existing access VLAN at runtime (ML3 -> ML2): a per-VNI
    VXLAN device added to the bridge as an access port on that VLAN."""
    node.run(
        "ip link add vni%d type vxlan id %d dstport 4789 local %s nolearning"
        % (vni, vni, lo_ip)
    )
    node.run("ip link set dev vni%d master br_default" % vni)
    node.run("/sbin/bridge link set dev vni%d learning off" % vni)
    node.run("/sbin/bridge vlan del vid 1 dev vni%d" % vni)
    node.run("/sbin/bridge vlan add vid %d dev vni%d pvid untagged" % (vid, vni))
    node.run("ip link set dev vni%d up" % vni)


def config_del_l2vni(node, vni):
    """Remove the L2VNI mapping, returning the BD to pure-L3 (ML2 -> ML3)."""
    node.run("ip link del vni%d 2>/dev/null || true" % vni)


def config_host_bond(node, members, ip):
    """Host-side LACP bond across two uplinks (dual-homed host)."""
    node.run("ip link add dev bond0 type bond mode 802.3ad")
    node.run("ip link set dev bond0 type bond lacp_rate 1")
    node.run("ip link set dev bond0 type bond miimon 100")
    node.run("ip link set dev bond0 type bond xmit_hash_policy layer3+4")
    for member in members:
        node.run("ip link set dev %s down" % member)
        node.run("ip link set dev %s master bond0" % member)
        node.run("ip link set dev %s up" % member)
    node.run("ip link set dev bond0 up")
    node.run("ip addr add %s/24 dev bond0" % ip)
    node.run("ip route add default via %s" % ANYCAST_GW)


def config_host_single(node, member, ip, gw):
    """Host-side single uplink (single-homed host)."""
    node.run("ip link set dev %s up" % member)
    node.run("ip addr add %s/24 dev %s" % (ip, member))
    node.run("ip route add default via %s" % gw)


def config_dataplane(tgen):
    leaf1 = tgen.gears["leaf1"]
    leaf2 = tgen.gears["leaf2"]
    leaf3 = tgen.gears["leaf3"]

    config_leaf_base(
        leaf1,
        LEAF_LO["leaf1"],
        extra_host_bds=[(HOST_VID2, ANYCAST_GW2), (HOST_VID3, ANYCAST_GW3)],
    )
    config_leaf_base(
        leaf2,
        LEAF_LO["leaf2"],
        extra_host_bds=[(HOST_VID2, ANYCAST_GW2), (HOST_VID3, ANYCAST_GW3)],
    )
    config_leaf_base(leaf3, LEAF_LO["leaf3"], LEAF3_VID, LEAF3_GW)

    # ESI bonds on the multihoming pair; single access port on leaf3.
    config_esi_bond(leaf1, "leaf1-eth2", extra_vids=(HOST_VID2, HOST_VID3))
    config_esi_bond(leaf2, "leaf2-eth2", extra_vids=(HOST_VID2, HOST_VID3))
    config_access_port(leaf3, "leaf3-eth2", LEAF3_VID)


def config_hosts(tgen):
    # Host addressing is applied after the routers start so it is not lost when
    # the framework finishes bringing the host veths up.
    config_host_bond(
        tgen.gears["host1"], ["host1-eth0", "host1-eth1"], HOST_IP["host1"]
    )
    # host3: a second BD on host1's bond (VLAN 101, tagged) in the same VRF.
    h1 = tgen.gears["host1"]
    h1.run(
        "ip link add link bond0 name bond0.%d type vlan id %d" % (HOST_VID2, HOST_VID2)
    )
    h1.run("ip link set dev bond0.%d up" % HOST_VID2)
    h1.run("ip addr add %s/24 dev bond0.%d" % (HOST3_IP, HOST_VID2))
    config_host_single(tgen.gears["host2"], "host2-eth0", HOST_IP["host2"], LEAF3_GW)


#####################################################
##
##   setup / teardown
##
#####################################################


def setup_module(module):
    tgen = Topogen(build_topo, module.__name__)
    tgen.start_topology()

    krel = platform.release()
    if topotest.version_cmp(krel, "4.19") < 0:
        tgen.errors = "kernel 4.19+ needed for EVPN multihoming tests"
        pytest.skip(tgen.errors)

    config_dataplane(tgen)

    # Load a single unified frr.conf per FRR-running router (no split
    # zebra.conf/evpn.conf). Hosts run no FRR daemons.
    frr_routers = ["spine1", "spine2", "leaf1", "leaf2", "leaf3"]
    for rname in frr_routers:
        router = tgen.gears[rname]
        router.load_frr_config(os.path.join(CWD, "%s/frr.conf" % rname))

    tgen.start_router()

    # Host IPs are applied last so the framework's veth bring-up does not wipe
    # a single-homed host's address.
    config_hosts(tgen)


def teardown_module(_mod):
    tgen = get_topogen()
    tgen.stop_topology()


#####################################################
##
##   Verification helpers
##
#####################################################


def _bgp_peers_established(dut, afi_key, neighbors):
    out = dut.vtysh_cmd("show bgp %s summary json" % afi_key)
    try:
        js = json.loads(out)
    except Exception as exc:  # pragma: no cover - defensive
        return "%s: cannot parse '%s summary': %s" % (dut.name, afi_key, exc)

    # summary json is keyed per-afi (e.g. "ipv4Unicast" / "l2VpnEvpn") or flat.
    peers = None
    for key in ("ipv4Unicast", "l2VpnEvpn", "peers"):
        block = js.get(key)
        if isinstance(block, dict):
            peers = block.get("peers", block) if key != "peers" else block
            if isinstance(peers, dict) and peers:
                break
    if not isinstance(peers, dict):
        return "%s: no peers block in '%s summary'" % (dut.name, afi_key)

    for neigh in neighbors:
        state = peers.get(neigh, {}).get("state", "")
        if state != "Established":
            return "%s: neighbor %s not Established (state=%s)" % (
                dut.name,
                neigh,
                state,
            )
    return None


def check_underlay_bgp(dut, neighbors):
    return _bgp_peers_established(dut, "ipv4 unicast", neighbors)


def check_evpn_bgp(dut, neighbors):
    return _bgp_peers_established(dut, "l2vpn evpn", neighbors)


def check_local_es(dut, esi):
    """Verify `esi` is present and flagged local in bgpd's ES table."""
    out = dut.vtysh_cmd("show bgp l2vpn evpn es json")
    try:
        js = json.loads(out)
    except Exception as exc:  # pragma: no cover - defensive
        return "%s: cannot parse ES json: %s" % (dut.name, exc)

    entries = js if isinstance(js, list) else js.get("es", [])
    for es in entries:
        if es.get("esi") == esi:
            types = es.get("type", [])
            if "local" in types:
                return None
            return "%s: ES %s present but not local (type=%s)" % (dut.name, esi, types)
    return "%s: local ES %s not found" % (dut.name, esi)


def check_local_es_zebra(dut, esi):
    """Verify `esi` is a local, oper-up ES in zebra (bond/ESI substrate).

    This validates the multihoming substrate at the zebra level and does NOT
    depend on the ES being advertised to bgpd -- which, with no L2VNI, requires
    the L3VNI-sourced base EVPN provided by the feature.
    """
    out = dut.vtysh_cmd("show evpn es json")
    try:
        js = json.loads(out)
    except Exception as exc:  # pragma: no cover - defensive
        return "%s: cannot parse zebra ES json: %s" % (dut.name, exc)

    entries = js if isinstance(js, list) else js.get("es", [])
    for es in entries:
        if es.get("esi") == esi:
            flags = es.get("flags", [])
            if "local" not in flags:
                return "%s: ES %s present but not local (flags=%s)" % (
                    dut.name,
                    esi,
                    flags,
                )
            state = es.get("state", "")
            if state != "up":
                return "%s: local ES %s not oper-up (state=%s)" % (dut.name, esi, state)
            return None
    return "%s: local ES %s not found in zebra" % (dut.name, esi)


#####################################################
##
##   Base convergence tests (pass with current code)
##
#####################################################


def test_underlay_bgp_established():
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    checks = {
        "leaf1": ["192.168.1.1", "192.168.4.1"],
        "leaf2": ["192.168.2.1", "192.168.5.1"],
        "leaf3": ["192.168.3.1", "192.168.6.1"],
    }
    for rname, neighbors in checks.items():
        dut = tgen.gears[rname]
        test_fn = partial(check_underlay_bgp, dut, neighbors)
        _, result = topotest.run_and_expect(
            test_fn, None, count=WAIT_COUNT, wait=WAIT_STEP
        )
        assert result is None, result


def test_evpn_sessions_established():
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    checks = {
        "leaf1": ["192.168.1.1", "192.168.4.1"],
        "leaf2": ["192.168.2.1", "192.168.5.1"],
        "leaf3": ["192.168.3.1", "192.168.6.1"],
    }
    for rname, neighbors in checks.items():
        dut = tgen.gears[rname]
        test_fn = partial(check_evpn_bgp, dut, neighbors)
        _, result = topotest.run_and_expect(
            test_fn, None, count=WAIT_COUNT, wait=WAIT_STEP
        )
        assert result is None, result


def test_evpn_mh_local_es():
    """leaf1 and leaf2 recognise the shared ESI as a local Ethernet Segment.

    Checked at the zebra level (show evpn es), which reflects the bond/ESI
    substrate independent of any L2VNI.
    """
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    for rname in ("leaf1", "leaf2"):
        dut = tgen.gears[rname]
        test_fn = partial(check_local_es_zebra, dut, ES1_ID)
        _, result = topotest.run_and_expect(
            test_fn, None, count=WAIT_COUNT, wait=WAIT_STEP
        )
        assert result is None, result


#####################################################
##
##   Pure-L3 RT-2 acceptance tests
##
##   These encode the section-5 acceptance targets. Tests for features that are
##   not yet implemented carry an xfail/skip marker; the markers are removed as
##   each phase lands (the remaining proxy-ARP/ND responder work is pending).
##
#####################################################


def _ping(host, dst, count=2):
    return host.run("ping -c %d -W 1 %s" % (count, dst))


@contextlib.contextmanager
def _active_host(host, dst):
    """Keep a host's SVI ARP continuously reachable across a bridge reconfig by
    sending a steady ping stream, modelling a normally-active host. A one-shot
    ARP can be flushed by the bridge reconfig before the L2VNI is associated;
    a continuously-active host keeps the neighbor present for the handoff."""
    p = host.popen(["ping", "-i", "0.3", "-w", "70", str(dst)])
    try:
        yield
    finally:
        p.terminate()
        p.wait()


def _pure_l3_rt2_path(dut, asn, ip=None, eth_tag=HOST_VID):
    """Return the pure-L3 RT-2 path dict for ip/eth_tag on dut, or None.

    A pure-L3 RT-2 is a routeType-2 macip route for the host IP with ethTag =
    the host VLAN, vni "0/L3VNI" (label[0]=0 Explicit NULL / label[1]=L3VNI)
    and the IP-VRF route-target.
    """
    if ip is None:
        ip = HOST_IP["host1"]
    out = dut.vtysh_cmd("show bgp l2vpn evpn route detail type macip json")
    try:
        js = json.loads(out)
    except Exception:  # pragma: no cover - defensive
        return None

    want_rt = "RT:%d:%d" % (asn, L3VNI)
    want_vni = "0/%d" % L3VNI
    for rdval in js.values():
        if not isinstance(rdval, dict):
            continue
        for entry in rdval.values():
            if not isinstance(entry, dict) or "paths" not in entry:
                continue
            if (
                entry.get("routeType") != 2
                or entry.get("ip") != ip
                or entry.get("ethTag") != eth_tag
            ):
                continue
            for pathset in entry["paths"]:
                for path in pathset:
                    ec = path.get("extendedCommunity", {}).get("string", "")
                    if path.get("vni") == want_vni and want_rt in ec:
                        return path
    return None


def _l2vni_present(dut, vni=None):
    """True if the L2VNI is live and mapped to the host VLAN on `dut`.

    Ownership of the BD moves to the L2VNI when it appears.
    """
    if vni is None:
        vni = L2VNI_100
    out = dut.vtysh_cmd("show evpn vni %d json" % vni)
    try:
        js = json.loads(out)
    except Exception:  # pragma: no cover - defensive
        return False
    return (
        js.get("vni") == vni and js.get("type") == "L2" and js.get("vlan") == HOST_VID
    )


def _l2vni_rt2_path(dut, vni, asn, ip=None, eth_tag=0):
    """Return the locally-originated L2VNI MAC-IP RT-2 path for `ip`, or None.

    vni == the plain L2VNI (e.g. "10100") vs the pure-L3 "0/L3VNI". The route
    target (AS:VNI) is filtered to `asn` so a remote peer's path is not mistaken
    for the local side's L2VNI ownership.
    """
    if ip is None:
        ip = HOST_IP["host1"]
    out = dut.vtysh_cmd("show bgp l2vpn evpn route detail type macip json")
    try:
        js = json.loads(out)
    except Exception:  # pragma: no cover - defensive
        return None

    want_vni = str(vni)
    want_rt = "RT:%d:%d" % (asn, vni)
    for rdval in js.values():
        if not isinstance(rdval, dict):
            continue
        for entry in rdval.values():
            if not isinstance(entry, dict) or "paths" not in entry:
                continue
            if (
                entry.get("routeType") != 2
                or entry.get("ip") != ip
                or entry.get("ethTag") != eth_tag
            ):
                continue
            for pathset in entry["paths"]:
                for path in pathset:
                    ec = path.get("extendedCommunity", {}).get("string", "")
                    # Symmetric-IRB MAC-IP vni is "<L2VNI>/<L3VNI>"; match the
                    # L2VNI component.
                    pvni = path.get("vni", "")
                    if pvni.split("/")[0] == want_vni and want_rt in ec:
                        return path
    return None


def _host1_synced(dut, vid=HOST_VID):
    """True if host1 is installed as a pure-L3 extern_learn (synced) neighbor
    on dev vlan<vid>."""
    out = dut.run("ip neigh show dev vlan%d" % vid)
    return HOST_IP["host1"] in out and "extern_learn" in out


def _synced_neigh_on_vlan_only(dut, ip, want_vid, all_vids):
    """Assert `ip` is an extern_learn (synced) neighbor on exactly `dev
    vlan<want_vid>` and on none of the other `all_vids`. Returns None on
    success or an error string. This catches a VRF-wide replay that programs
    the neighbor without ETAG filtering.
    """
    for vid in all_vids:
        out = dut.run("ip neigh show dev vlan%d" % vid)
        present = ip in out and "extern_learn" in out
        if vid == want_vid and not present:
            return "IP %s not extern_learn on vlan%d: %s" % (ip, vid, out)
        if vid != want_vid and present:
            return "IP %s wrongly extern_learn on vlan%d (ETAG leak): %s" % (
                ip,
                vid,
                out,
            )
    return None


def _host1_mac(dut, vid=HOST_VID):
    """Return host1's neighbor lladdr on dev vlan<vid>, or None."""
    for line in dut.run("ip neigh show dev vlan%d" % vid).splitlines():
        if HOST_IP["host1"] in line and "lladdr" in line:
            return line.split("lladdr")[1].split()[0]
    return None


def _mac_static_pinned(dut, mac, vid, dev="hostbond1"):
    """True if `mac` is a static (sync-MAC pin) FDB entry on `dev` for vlan
    <vid>.

    The pin is programmed NUD_NOARP -> rendered "static"; a dynamically learned
    entry lacks that flag. Matching the VLAN too avoids a same-MAC pin on a
    different BD (host1's bond carries VLAN 100 and 101) satisfying the check.
    """
    for line in dut.run("bridge fdb show dev %s" % dev).splitlines():
        toks = line.split()
        if mac.lower() not in line.lower() or "static" not in toks:
            continue
        if "vlan" in toks:
            i = toks.index("vlan")
            if i + 1 < len(toks) and toks[i + 1] == str(vid):
                return True
    return False


def test_advertise_l3vni_neigh_cli():
    """The advertise-l3vni-neigh knob is accepted, persists, and reaches zebra.

    Pure CLI + ZAPI plumbing; no dataplane behavior yet. We verify the bgpd
    running-config, that the flag propagated over ZAPI to zebra's per-VRF state
    (show evpn -> advertiseL3vniNeigh), and that the bgpd per-L3VNI view
    (show bgp l2vpn evpn vni <vni>) reflects the knob.
    """
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    leaf1 = tgen.gears["leaf1"]
    leaf1.vtysh_cmd(
        "configure terminal\n"
        "router bgp 65011\n"
        " address-family l2vpn evpn\n"
        "  advertise-l3vni-neigh\n"
    )
    running = leaf1.vtysh_cmd("show running-config")
    assert (
        "advertise-l3vni-neigh" in running
    ), "advertise-l3vni-neigh not present in running-config"

    # The flag must reach zebra over ZAPI (bgpd -> zebra) and land in zvrf.
    def _zebra_has_flag(dut):
        out = dut.vtysh_cmd("show evpn json")
        try:
            js = json.loads(out)
        except Exception as exc:  # pragma: no cover - defensive
            return "cannot parse 'show evpn json': %s" % exc
        if js.get("advertiseL3vniNeigh") == "Yes":
            return None
        return "zebra advertiseL3vniNeigh=%s (expected Yes)" % js.get(
            "advertiseL3vniNeigh"
        )

    test_fn = partial(_zebra_has_flag, leaf1)
    _, result = topotest.run_and_expect(test_fn, None, count=WAIT_COUNT, wait=WAIT_STEP)
    assert result is None, result

    # The bgpd per-L3VNI view must reflect the knob as well.
    def _bgp_vni_has_flag(dut):
        out = dut.vtysh_cmd("show bgp l2vpn evpn vni %d json" % L3VNI)
        try:
            js = json.loads(out)
        except Exception as exc:  # pragma: no cover - defensive
            return "cannot parse 'show bgp l2vpn evpn vni' json: %s" % exc
        state = js.get("advertiseL3vniNeigh")
        if state == "Active":
            return None
        return "bgp vni %d advertiseL3vniNeigh=%s (expected Active)" % (L3VNI, state)

    test_fn = partial(_bgp_vni_has_flag, leaf1)
    _, result = topotest.run_and_expect(test_fn, None, count=WAIT_COUNT, wait=WAIT_STEP)
    assert result is None, result


def test_l3vni_neigh_debug_cli():
    """The l3vni-neigh debug selectors are accepted in bgpd and zebra.

    Both daemons expose the sync-neighbor tracing under the existing EVPN-MH
    debug tree: 'debug bgp evpn mh l3vni-neigh' and 'debug zebra evpn mh
    l3vni-neigh'. Enabling them from config mode must persist to running-config
    and be reflected in 'show debugging'.
    """
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    leaf1 = tgen.gears["leaf1"]

    leaf1.vtysh_cmd(
        "configure terminal\n"
        "debug bgp evpn mh l3vni-neigh\n"
        "debug zebra evpn mh l3vni-neigh\n"
    )

    try:
        running = leaf1.vtysh_cmd("show running-config")
        assert (
            "debug bgp evpn mh l3vni-neigh" in running
        ), "bgp l3vni-neigh debug not persisted to running-config"
        assert (
            "debug zebra evpn mh l3vni-neigh" in running
        ), "zebra l3vni-neigh debug not persisted to running-config"

        dbg = leaf1.vtysh_cmd("show debugging")
        assert (
            "BGP EVPN-MH l3vni-neigh debugging is on" in dbg
        ), "bgp l3vni-neigh debug not shown in 'show debugging'"
        assert (
            "Zebra EVPN-MH l3vni-neigh debugging is on" in dbg
        ), "zebra l3vni-neigh debug not shown in 'show debugging'"
    finally:
        # Turn it back off so the debug state does not leak into later tests.
        leaf1.vtysh_cmd(
            "configure terminal\n"
            "no debug bgp evpn mh l3vni-neigh\n"
            "no debug zebra evpn mh l3vni-neigh\n"
        )


def test_evpn_mh_local_es_in_bgp():
    """The local ES reaches bgpd (BGP_EVPNES_LOCAL) so RX ESI-match can work.

    With no L2VNI, zebra has no L2VNI base EVPN to derive the ES originator IP.
    The feature sources the base EVPN / originator IP from the L3VNI (gated on
    advertise-l3vni-neigh), so the local ES is advertised to bgpd.
    """
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    for rname in ("leaf1", "leaf2"):
        dut = tgen.gears[rname]
        test_fn = partial(check_local_es, dut, ES1_ID)
        _, result = topotest.run_and_expect(
            test_fn, None, count=WAIT_COUNT, wait=WAIT_STEP
        )
        assert result is None, result


def test_pure_l3_rt2_origination():
    """
    With the knob on and no L2VNI, a local ARP entry for host1 is originated as
    a pure-L3 RT-2 in the global EVPN table under the VRF's RD, carrying the
    L3VNI route-target, ETAG = the access VLAN id, and label[0]=0 (Explicit
    NULL) / label[1]=L3VNI -- rendered "0/<L3VNI>" in the "vni" field.
    """
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    leaf_asn = {"leaf1": 65011, "leaf2": 65012}
    for rname, asn in leaf_asn.items():
        tgen.gears[rname].vtysh_cmd(
            "configure terminal\n"
            "router bgp %d\n"
            " address-family l2vpn evpn\n"
            "  advertise-l3vni-neigh\n" % asn
        )

    # Trigger local ARP learning for host1 on the leaf SVIs.
    _ping(tgen.gears["host1"], ANYCAST_GW)

    def _has_pure_l3_rt2(dut, asn):
        path = _pure_l3_rt2_path(dut, asn)
        if path is None:
            return "no pure-L3 RT-2 for %s (ethTag %d, vni 0/%d, RT:%d:%d)" % (
                HOST_IP["host1"],
                HOST_VID,
                L3VNI,
                asn,
                L3VNI,
            )
        if path.get("esi") != ES1_ID:
            return "pure-L3 RT-2 has esi %s, want %s" % (
                path.get("esi"),
                ES1_ID,
            )
        return None

    dut = tgen.gears["leaf1"]
    test_fn = partial(_has_pure_l3_rt2, dut, leaf_asn["leaf1"])
    _, result = topotest.run_and_expect(test_fn, None, count=WAIT_COUNT, wait=WAIT_STEP)
    assert result is None, result


def test_pure_l3_rt2_esi_cleared_on_es_removal():
    """
    Removing the local ES from host1's access port clears the ESI on its
    pure-L3 RT-2 -- it must NOT fall back to any other BD member's ES -- and
    restoring the ES brings the ESI back. Exercises the per-port re-advertise
    on ES local-info clear/set and the MAC/ES cache membership check.
    """
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    leaf1 = tgen.gears["leaf1"]
    _ping(tgen.gears["host1"], ANYCAST_GW)

    def _esi_is(want):
        path = _pure_l3_rt2_path(leaf1, 65011)
        if path is None:
            return "pure-L3 RT-2 missing"
        got = path.get("esi")  # absent when zero ESI
        if got != want:
            return "esi is %s, want %s" % (got, want)
        return None

    # Baseline: the ESI is present.
    _, result = topotest.run_and_expect(
        partial(_esi_is, ES1_ID), None, count=WAIT_COUNT, wait=WAIT_STEP
    )
    assert result is None, result

    # Remove the local ES from the access port.
    leaf1.vtysh_cmd(
        "configure terminal\n"
        "interface hostbond1\n"
        " no evpn mh es-id 1\n"
        " no evpn mh es-sys-mac 44:38:39:ff:ff:01\n"
    )
    try:
        # The RT-2 stays but its ESI clears (no esi field == zero ESI).
        _, result = topotest.run_and_expect(
            partial(_esi_is, None), None, count=WAIT_COUNT, wait=WAIT_STEP
        )
        assert result is None, result
    finally:
        # Restore the ES for subsequent tests.
        leaf1.vtysh_cmd(
            "configure terminal\n"
            "interface hostbond1\n"
            " evpn mh es-id 1\n"
            " evpn mh es-sys-mac 44:38:39:ff:ff:01\n"
        )

    # The ESI returns once the local ES is back.
    _, result = topotest.run_and_expect(
        partial(_esi_is, ES1_ID), None, count=WAIT_COUNT, wait=WAIT_STEP
    )
    assert result is None, result


def test_pure_l3_knob_toggle_cleans_and_replays_local_and_remote():
    """
    Bidirectional advertise-l3vni-neigh lifecycle: toggling the knob must clean
    up and replay the TX (origination) and RX (install) sides together.

      * leaf1 (TX) off -> withdraws its local pure-L3 RT-2, and the peer (leaf2)
        removes the synced neighbor + static sync-MAC pin.
      * leaf1 (TX) on  -> re-originates from zebra's existing in-memory L3
        neighbor DB (no new ARP), and leaf2 reinstalls neighbor + pin.
      * leaf2 (RX) off -> flushes only leaf2's RX-installed neighbor + pin;
        leaf1's local RT-2 stays advertised (the RX gate is local to the peer).
      * leaf2 (RX) on  -> reimports the still-present RT-2 from the BGP RIB and
        reinstalls neighbor + pin.
    """
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    leaf1 = tgen.gears["leaf1"]
    leaf2 = tgen.gears["leaf2"]
    _ping(tgen.gears["host1"], ANYCAST_GW)

    # host1's real (bond) MAC -- stable regardless of sync state, so the pin
    # check is robust even after the neighbor is withdrawn.
    host1_mac = tgen.gears["host1"].run("cat /sys/class/net/bond0/address").strip()

    def _knob(leaf, asn, enable):
        leaf.vtysh_cmd(
            "configure terminal\n"
            "router bgp %d\n"
            " address-family l2vpn evpn\n"
            "  %sadvertise-l3vni-neigh\n" % (asn, "" if enable else "no ")
        )

    def _leaf1_rt2(present):
        path = _pure_l3_rt2_path(leaf1, 65011)
        if present and path is None:
            return "leaf1 pure-L3 RT-2 missing"
        if not present and path is not None:
            return "leaf1 pure-L3 RT-2 still present"
        return None

    def _leaf2_synced(present):
        out = leaf2.run("ip neigh show dev vlan%d" % HOST_VID)
        has_neigh = HOST_IP["host1"] in out and "extern_learn" in out
        has_pin = _mac_static_pinned(leaf2, host1_mac, HOST_VID)
        if present:
            if not has_neigh:
                return "leaf2 synced neighbor missing: %s" % out
            if not has_pin:
                return "leaf2 sync-MAC pin missing"
        else:
            if has_neigh:
                return "leaf2 synced neighbor still present: %s" % out
            if has_pin:
                return "leaf2 sync-MAC pin still present"
        return None

    def _expect(fn, *args):
        _, result = topotest.run_and_expect(
            partial(fn, *args), None, count=WAIT_COUNT, wait=WAIT_STEP
        )
        assert result is None, result

    try:
        # 1) Baseline: leaf1 originates; leaf2 has the synced neighbor + pin.
        _expect(_leaf1_rt2, True)
        _expect(_leaf2_synced, True)

        # 2) leaf1 TX off -> RT-2 withdrawn -> leaf2 cleans up neighbor + pin.
        _knob(leaf1, 65011, False)
        _expect(_leaf1_rt2, False)
        _expect(_leaf2_synced, False)

        # 3) leaf1 TX on -> re-originates from existing zebra state (no new ARP);
        #    leaf2 reinstalls neighbor + pin.
        _knob(leaf1, 65011, True)
        _expect(_leaf1_rt2, True)
        _expect(_leaf2_synced, True)

        # 4) leaf2 RX off while leaf1 still advertises -> leaf2 flushes its
        #    install; leaf1's RT-2 stays (RX gate is local to the receiver).
        _knob(leaf2, 65012, False)
        _expect(_leaf2_synced, False)
        _expect(_leaf1_rt2, True)

        # 5) leaf2 RX on -> reimports the stored RT-2 and reinstalls.
        _knob(leaf2, 65012, True)
        _expect(_leaf2_synced, True)
    finally:
        # Ensure both knobs are back on for later tests.
        _knob(leaf1, 65011, True)
        _knob(leaf2, 65012, True)


def test_pure_l3_sync_neighbor_install():
    """
    The multihoming peer (leaf2) installs host1's ARP entry as a sync neighbor
    (NTF_EXT_LEARNED) learned from the ESI-matched pure-L3 RT-2. Because the ESI
    is local and the BD has no L2VNI, leaf2 also pins host1's MAC to the local
    ES bond (hostbond1) in the bridge FDB so routed delivery reaches the exact
    port instead of flooding the VLAN.
    """
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)
    _ping(tgen.gears["host1"], ANYCAST_GW)

    dut = tgen.gears["leaf2"]

    def _has_sync_neigh(dut):
        out = dut.run("ip neigh show dev vlan%d" % HOST_VID)
        if HOST_IP["host1"] in out and "extern_learn" in out:
            return None
        return "no extern_learn neighbor for %s: %s" % (HOST_IP["host1"], out)

    test_fn = partial(_has_sync_neigh, dut)
    _, result = topotest.run_and_expect(test_fn, None, count=WAIT_COUNT, wait=WAIT_STEP)
    assert result is None, result

    # The neighbor's lladdr is host1's MAC; it must also be pinned to the local
    # ES bond (hostbond1) in the bridge FDB (the local-ES sync-MAC).
    neigh = dut.run("ip neigh show dev vlan%d" % HOST_VID)
    host1_mac = None
    for line in neigh.splitlines():
        if HOST_IP["host1"] in line and "lladdr" in line:
            host1_mac = line.split("lladdr")[1].split()[0]
            break
    assert host1_mac is not None, "could not find host1 MAC in: %s" % neigh

    def _has_sync_mac(dut):
        if _mac_static_pinned(dut, host1_mac, HOST_VID):
            return None
        return "host1 MAC %s not pinned (static) to hostbond1" % host1_mac

    _, result = topotest.run_and_expect(
        partial(_has_sync_mac, dut), None, count=WAIT_COUNT, wait=WAIT_STEP
    )
    assert result is None, result


@pytest.mark.parametrize("proxy_arp", [1, 0], ids=["proxy_arp_on", "proxy_arp_off"])
def test_pure_l3_sync_neigh_independent_of_proxy_arp(proxy_arp):
    """
    The synced-neighbor install is orthogonal to the SVI's ARP responder mode.
    With proxy_arp=1 the peer SVI answers ARP for the host subnet with its own
    MAC; with proxy_arp=0 it answers nothing and only routes toward the host.
    The responder mode is set first, then leaf2's RX knob is bounced so the sync
    neighbor is (re)installed under that mode -- proving install-time, not just
    survival, independence. leaf2 must install host1's sync neighbor
    (NTF_EXT_LEARNED) and pin its MAC to the local ES bond either way.
    Kernel-state assertions only.
    """
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)
    _ping(tgen.gears["host1"], ANYCAST_GW)

    dut = tgen.gears["leaf2"]
    svi = "vlan%d" % HOST_VID

    try:
        # Set the responder mode BEFORE the sync neighbor is (re)installed.
        dut.run("/sbin/sysctl -w net.ipv4.conf.%s.proxy_arp=%d" % (svi, proxy_arp))
        got = dut.run("/sbin/sysctl -n net.ipv4.conf.%s.proxy_arp" % svi).strip()
        assert got == str(proxy_arp), "proxy_arp not %d on %s: %s" % (
            proxy_arp,
            svi,
            got,
        )

        # Bounce leaf2's RX knob so the sync neighbor is flushed and reinstalled
        # under the responder mode set above (deterministic control-plane replay).
        dut.vtysh_cmd(
            "configure terminal\n"
            "router bgp 65012\n"
            " address-family l2vpn evpn\n"
            "  no advertise-l3vni-neigh\n"
        )
        dut.vtysh_cmd(
            "configure terminal\n"
            "router bgp 65012\n"
            " address-family l2vpn evpn\n"
            "  advertise-l3vni-neigh\n"
        )

        def _has_sync_neigh(dut):
            out = dut.run("ip neigh show dev %s" % svi)
            if HOST_IP["host1"] in out and "extern_learn" in out:
                return None
            return "no extern_learn neighbor for %s: %s" % (HOST_IP["host1"], out)

        _, result = topotest.run_and_expect(
            partial(_has_sync_neigh, dut), None, count=WAIT_COUNT, wait=WAIT_STEP
        )
        assert result is None, result

        host1_mac = None
        for line in dut.run("ip neigh show dev %s" % svi).splitlines():
            if HOST_IP["host1"] in line and "lladdr" in line:
                host1_mac = line.split("lladdr")[1].split()[0]
                break
        assert host1_mac is not None, "could not find host1 MAC on %s" % svi

        def _has_sync_mac(dut):
            if _mac_static_pinned(dut, host1_mac, HOST_VID):
                return None
            return "host1 MAC %s not pinned (static) to hostbond1" % host1_mac

        _, result = topotest.run_and_expect(
            partial(_has_sync_mac, dut), None, count=WAIT_COUNT, wait=WAIT_STEP
        )
        assert result is None, result
    finally:
        # Restore the base-config responder mode for later tests.
        dut.run("/sbin/sysctl -w net.ipv4.conf.%s.proxy_arp=1" % svi)


def test_pure_l3_sync_multiple_bds_same_vrf():
    """
    Three no-L2VNI BDs (VLANs 100/101/102) share one VRF/L3VNI on the MH pair.
    host1 (VLAN100) and host3 (VLAN101) are learned locally and synced to the
    peer; VLAN102 carries no host. leaf1 originates a distinct pure-L3 RT-2 per
    BD (ETAG 100 vs 101), and the peer installs each synced neighbor on ITS OWN
    SVI only. The key guard is per-ETAG isolation: a VRF-wide replay that
    programmed neighbors without ETAG filtering would leak host1 onto vlan101/
    vlan102 (and host3 onto vlan100/vlan102) -- asserted absent here.
    """
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    all_vids = [HOST_VID, HOST_VID2, HOST_VID3]

    # Learn both hosts: host1 on VLAN100, host3 on host1's tagged VLAN101 subif.
    _ping(tgen.gears["host1"], ANYCAST_GW)
    tgen.gears["host1"].run("ping -c 2 -W 1 -I %s %s" % (HOST3_IP, ANYCAST_GW2))

    leaf1 = tgen.gears["leaf1"]
    leaf2 = tgen.gears["leaf2"]

    # leaf1 originates a distinct pure-L3 RT-2 per BD (different ETAG).
    def _rt2(ip, etag):
        return partial(
            lambda dut, i, e: (
                None
                if _pure_l3_rt2_path(dut, 65011, ip=i, eth_tag=e) is not None
                else "no pure-L3 RT-2 for %s ETAG %d" % (i, e)
            ),
            leaf1,
            ip,
            etag,
        )

    for ip, etag in ((HOST_IP["host1"], HOST_VID), (HOST3_IP, HOST_VID2)):
        _, result = topotest.run_and_expect(
            _rt2(ip, etag), None, count=WAIT_COUNT, wait=WAIT_STEP
        )
        assert result is None, result

    # leaf2 installs each synced neighbor on exactly its own SVI, nowhere else.
    for ip, want_vid in ((HOST_IP["host1"], HOST_VID), (HOST3_IP, HOST_VID2)):
        _, result = topotest.run_and_expect(
            partial(_synced_neigh_on_vlan_only, leaf2, ip, want_vid, all_vids),
            None,
            count=WAIT_COUNT,
            wait=WAIT_STEP,
        )
        assert result is None, result

    # The sync-MAC/FDB pin exists for each synced host's MAC (both on hostbond1).
    for ip, vid in ((HOST_IP["host1"], HOST_VID), (HOST3_IP, HOST_VID2)):
        mac = None
        for line in leaf2.run("ip neigh show dev vlan%d" % vid).splitlines():
            if ip in line and "lladdr" in line:
                mac = line.split("lladdr")[1].split()[0]
                break
        assert mac is not None, "no MAC for %s on vlan%d" % (ip, vid)

        def _pinned(dut, m, v):
            return (
                None
                if _mac_static_pinned(dut, m, v)
                else "MAC %s not pinned (static) on vlan%d" % (m, v)
            )

        _, result = topotest.run_and_expect(
            partial(_pinned, leaf2, mac, vid), None, count=WAIT_COUNT, wait=WAIT_STEP
        )
        assert result is None, result


def test_pure_l3_sync_esi_removed_on_peer_withdraws():
    """
    Removing the local ES from the sync-receiving peer (leaf2) means leaf2 is no
    longer an ES peer for host1, so the ESI-matched sync no longer applies: both
    the synced (extern_learn) neighbor AND its local-ES sync-MAC pin are removed.
    Restoring the ES re-establishes the sync.
    """
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    _ping(tgen.gears["host1"], ANYCAST_GW)
    leaf2 = tgen.gears["leaf2"]

    def _synced(dut):
        out = dut.run("ip neigh show dev vlan%d" % HOST_VID)
        if HOST_IP["host1"] in out and "extern_learn" in out:
            return None
        return "host1 not synced on leaf2: %s" % out

    # Baseline: host1 synced, and its MAC pinned (static) to hostbond1.
    _, result = topotest.run_and_expect(
        partial(_synced, leaf2), None, count=WAIT_COUNT, wait=WAIT_STEP
    )
    assert result is None, result
    host1_mac = _host1_mac(leaf2)
    assert host1_mac is not None, "no host1 MAC on leaf2"
    assert _mac_static_pinned(leaf2, host1_mac, HOST_VID), (
        "baseline sync-MAC pin for %s missing on hostbond1" % host1_mac
    )

    # Remove the local ES from leaf2's access port -> leaf2 is no longer a peer.
    leaf2.vtysh_cmd(
        "configure terminal\n"
        "interface hostbond1\n"
        " no evpn mh es-id 1\n"
        " no evpn mh es-sys-mac 44:38:39:ff:ff:01\n"
    )
    try:
        # Both the synced neighbor and the static sync-MAC pin must be gone.
        def _withdrawn(dut):
            out = dut.run("ip neigh show dev vlan%d" % HOST_VID)
            if HOST_IP["host1"] in out and "extern_learn" in out:
                return "host1 still synced on leaf2 after ES removal: %s" % out
            if _mac_static_pinned(dut, host1_mac, HOST_VID):
                return "host1 sync-MAC still pinned to hostbond1 after ES removal"
            return None

        _, result = topotest.run_and_expect(
            partial(_withdrawn, leaf2), None, count=WAIT_COUNT, wait=WAIT_STEP
        )
        assert result is None, result
    finally:
        # Restore the ES for subsequent tests.
        leaf2.vtysh_cmd(
            "configure terminal\n"
            "interface hostbond1\n"
            " evpn mh es-id 1\n"
            " evpn mh es-sys-mac 44:38:39:ff:ff:01\n"
        )

    # The sync -- neighbor AND static sync-MAC pin -- returns once leaf2 is an
    # ES peer again.
    def _synced_pinned(dut):
        err = _synced(dut)
        if err:
            return err
        mac = _host1_mac(dut)
        if mac is None or not _mac_static_pinned(dut, mac, HOST_VID):
            return "host1 sync-MAC pin not restored on hostbond1"
        return None

    _ping(tgen.gears["host1"], ANYCAST_GW)
    _, result = topotest.run_and_expect(
        partial(_synced_pinned, leaf2), None, count=WAIT_COUNT, wait=WAIT_STEP
    )
    assert result is None, result


def test_pure_l3_sync_esi_reprogrammed_reconciles():
    """
    Reprogramming the ES to a new ESI on both MH peers re-originates host1's
    pure-L3 RT-2 with the corrected ESI, and the peer's synced state reconciles.
    Because ES1 and ES2 use the same physical bond, the final kernel result
    would be indistinguishable from stale state, so this drives an explicit
    teardown in between: the ES is fully removed (RX must withdraw the neighbor
    and its static sync-MAC pin), then re-added as es-id 2 (RX must reinstall
    under the corrected ESI). NOTE: cross-port sync-MAC movement (the pin
    relocating to a *different* local ES bond) is NOT covered here -- the peer
    has a single ES bond (hostbond1); that case is deferred (would need a second
    local ES bond facing host1).
    """
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    leaf1 = tgen.gears["leaf1"]
    leaf2 = tgen.gears["leaf2"]
    _ping(tgen.gears["host1"], ANYCAST_GW)

    def _rt2_esi(dut, want):
        path = _pure_l3_rt2_path(dut, 65011)
        if path is None:
            return "pure-L3 RT-2 missing"
        if path.get("esi") != want:
            return "esi is %s, want %s" % (path.get("esi"), want)
        return None

    def _synced_pinned(dut):
        out = dut.run("ip neigh show dev vlan%d" % HOST_VID)
        if not (HOST_IP["host1"] in out and "extern_learn" in out):
            return "host1 not synced on leaf2: %s" % out
        mac = _host1_mac(dut)
        if mac is None:
            return "no host1 MAC on leaf2"
        if not _mac_static_pinned(dut, mac, HOST_VID):
            return "host1 MAC %s not pinned (static) to hostbond1" % mac
        return None

    def _torn_down(dut):
        out = dut.run("ip neigh show dev vlan%d" % HOST_VID)
        if HOST_IP["host1"] in out and "extern_learn" in out:
            return "host1 still synced during ES teardown: %s" % out
        if host1_mac and _mac_static_pinned(dut, host1_mac, HOST_VID):
            return "host1 sync-MAC still pinned during ES teardown"
        return None

    # Baseline: ESI is ES1 and leaf2 has the synced neighbor + static pin.
    _, result = topotest.run_and_expect(
        partial(_rt2_esi, leaf1, ES1_ID), None, count=WAIT_COUNT, wait=WAIT_STEP
    )
    assert result is None, result
    _, result = topotest.run_and_expect(
        partial(_synced_pinned, leaf2), None, count=WAIT_COUNT, wait=WAIT_STEP
    )
    assert result is None, result
    host1_mac = _host1_mac(leaf2)

    # Fully remove the ES on both peers so RX must tear the synced state down.
    for leaf in (leaf1, leaf2):
        leaf.vtysh_cmd(
            "configure terminal\n"
            "interface hostbond1\n"
            " no evpn mh es-id 1\n"
            " no evpn mh es-sys-mac 44:38:39:ff:ff:01\n"
        )
    try:
        _, result = topotest.run_and_expect(
            partial(_torn_down, leaf2), None, count=WAIT_COUNT, wait=WAIT_STEP
        )
        assert result is None, result

        # Re-add as es-id 2 -> RX must reinstall under the corrected ESI.
        for leaf in (leaf1, leaf2):
            leaf.vtysh_cmd(
                "configure terminal\n"
                "interface hostbond1\n"
                " evpn mh es-id 2\n"
                " evpn mh es-sys-mac 44:38:39:ff:ff:01\n"
            )
        _ping(tgen.gears["host1"], ANYCAST_GW)
        _, result = topotest.run_and_expect(
            partial(_rt2_esi, leaf1, ES2_ID), None, count=WAIT_COUNT, wait=WAIT_STEP
        )
        assert result is None, result
        _, result = topotest.run_and_expect(
            partial(_synced_pinned, leaf2), None, count=WAIT_COUNT, wait=WAIT_STEP
        )
        assert result is None, result
    finally:
        # Restore es-id 1 on both peers.
        for leaf in (leaf1, leaf2):
            leaf.vtysh_cmd(
                "configure terminal\n"
                "interface hostbond1\n"
                " no evpn mh es-id 2\n"
                " evpn mh es-id 1\n"
                " evpn mh es-sys-mac 44:38:39:ff:ff:01\n"
            )

    # Original ESI restored, and leaf2's synced neighbor + pin return under ES1.
    _ping(tgen.gears["host1"], ANYCAST_GW)
    _, result = topotest.run_and_expect(
        partial(_rt2_esi, leaf1, ES1_ID), None, count=WAIT_COUNT, wait=WAIT_STEP
    )
    assert result is None, result
    _, result = topotest.run_and_expect(
        partial(_synced_pinned, leaf2), None, count=WAIT_COUNT, wait=WAIT_STEP
    )
    assert result is None, result


def test_pure_l3_bd_gains_l2vni_transfers_ownership():
    """
    When a pure-L3 (no-L2VNI) BD gains an L2VNI, ownership of host1 moves from
    the pure-L3 singleton to the L2VNI EVI. Model: delete the old owner's state,
    then rebuild under the new owner. Asserted end-to-end: the pure-L3 RT-2
    (vni=0/L3VNI) is withdrawn, leaf2's pure-L3 synced extern_learn neighbor is
    cleaned up, the L2VNI becomes live/mapped to VLAN100, and the L2VNI MAC-IP
    RT-2 (vni=<L2VNI>) is originated for host1 -- so no host is left with zebra
    ownership but no BGP route.
    """
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    leaf1 = tgen.gears["leaf1"]
    leaf2 = tgen.gears["leaf2"]
    _ping(tgen.gears["host1"], ANYCAST_GW)
    host1_mac = tgen.gears["host1"].run("cat /sys/class/net/bond0/address").strip()

    def _expect(fn):
        _, result = topotest.run_and_expect(fn, None, count=WAIT_COUNT, wait=WAIT_STEP)
        assert result is None, result

    # Baseline: the pure-L3 singleton owns host1 (RT-2 + synced neighbor + pin).
    _expect(
        lambda: (
            None
            if _pure_l3_rt2_path(leaf1, 65011) is not None
            else "pure-L3 RT-2 missing at baseline"
        )
    )
    _expect(
        lambda: (
            None if _host1_synced(leaf2) else "host1 not synced on leaf2 at baseline"
        )
    )
    _expect(
        lambda: (
            None
            if _mac_static_pinned(leaf2, host1_mac, HOST_VID)
            else "host1 sync-MAC pin missing on leaf2 at baseline"
        )
    )

    # Refresh host1's ARP so it is REACHABLE (not stale) when the VXLAN device
    # is added: a stale SVI neighbor can be flushed by the bridge reconfig
    # before the L2VNI is associated, leaving nothing to hand off.
    _ping(tgen.gears["host1"], ANYCAST_GW)

    # Add an L2VNI to VLAN100 on both peers while host1 stays active so its ARP
    # survives the bridge reconfig and hands off to the L2VNI EVI.
    with _active_host(tgen.gears["host1"], ANYCAST_GW):
        for leaf, lo in ((leaf1, LEAF_LO["leaf1"]), (leaf2, LEAF_LO["leaf2"])):
            config_add_l2vni(leaf, lo, HOST_VID, L2VNI_100)
        try:
            # Old owner (pure-L3) relinquishes: RT-2 withdrawn on leaf1 and the
            # pure-L3 synced neighbor cleaned up on leaf2.
            _expect(
                lambda: (
                    None
                    if _pure_l3_rt2_path(leaf1, 65011) is None
                    else "pure-L3 RT-2 still present after L2VNI added"
                )
            )
            _expect(
                lambda: (
                    None
                    if not _host1_synced(leaf2)
                    else "leaf2 pure-L3 synced neighbor not cleaned after L2VNI added"
                )
            )
            # New owner (L2VNI) live/mapped to VLAN100 and originates host1's
            # MAC-IP (no host left with zebra ownership but no BGP route).
            _expect(
                lambda: None if _l2vni_present(leaf1) else "L2VNI not live on VLAN100"
            )
            _expect(
                lambda: (
                    None
                    if _l2vni_rt2_path(leaf1, L2VNI_100, 65011) is not None
                    else "L2VNI MAC-IP RT-2 missing after L2VNI added"
                )
            )
        finally:
            for leaf in (leaf1, leaf2):
                config_del_l2vni(leaf, L2VNI_100)

    # Sanity: pure-L3 ownership returns once the L2VNI is gone. The reverse
    # transition requests kernel neighbor discovery and the reachable host is
    # re-learned via NEWNEIGH; the full ML2->ML3 rebuild is asserted by
    # test_l2vni_bd_loses_l2vni_returns_to_pure_l3.
    _expect(
        lambda: (
            None
            if _pure_l3_rt2_path(leaf1, 65011) is not None
            else "pure-L3 RT-2 did not return after L2VNI removed"
        )
    )


def test_l2vni_bd_loses_l2vni_returns_to_pure_l3():
    """
    The reverse transition (ML2 -> ML3): when VLAN100 loses its L2VNI, ownership
    of host1's MAC-IP returns from the L2VNI EVI to the pure-L3 singleton.
    Delete the old (L2VNI) owner, then rebuild under the pure-L3 owner: the
    L2VNI MAC-IP RT-2 disappears, the pure-L3 RT-2 (vni=0/L3VNI, correct ESI)
    returns, and leaf2 rebuilds the synced extern_learn neighbor + static
    sync-MAC pin on vlan100.
    """
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    leaf1 = tgen.gears["leaf1"]
    leaf2 = tgen.gears["leaf2"]
    _ping(tgen.gears["host1"], ANYCAST_GW)
    host1_mac = tgen.gears["host1"].run("cat /sys/class/net/bond0/address").strip()

    def _expect(fn):
        _, result = topotest.run_and_expect(fn, None, count=WAIT_COUNT, wait=WAIT_STEP)
        assert result is None, result

    # Enter ML2: add the L2VNI with host1 active so its ARP survives the bridge
    # reconfig and hands off; the L2 owner then originates host1's MAC-IP.
    with _active_host(tgen.gears["host1"], ANYCAST_GW):
        for leaf, lo in ((leaf1, LEAF_LO["leaf1"]), (leaf2, LEAF_LO["leaf2"])):
            config_add_l2vni(leaf, lo, HOST_VID, L2VNI_100)
        _expect(
            lambda: (
                None
                if _l2vni_rt2_path(leaf1, L2VNI_100, 65011) is not None
                else "L2VNI MAC-IP RT-2 missing in ML2 setup"
            )
        )

    # ML2 -> ML3: remove the L2VNI. The transition requests kernel neighbor
    # discovery for the BD's local hosts; the reachable host responds and is
    # re-learned via NEWNEIGH, re-originating pure-L3 (no stale replay).
    for leaf in (leaf1, leaf2):
        config_del_l2vni(leaf, L2VNI_100)

    # Old owner (L2VNI) gone: its MAC-IP RT-2 is withdrawn.
    _expect(
        lambda: (
            None
            if _l2vni_rt2_path(leaf1, L2VNI_100, 65011) is None
            else "L2VNI MAC-IP RT-2 still present after L2VNI removed"
        )
    )

    # New owner (pure-L3) rebuilt after the transition probes the kernel and the
    # host is re-learned via NEWNEIGH: RT-2 (0/L3VNI, correct ESI) re-originated.
    def _pure_l3_back():
        path = _pure_l3_rt2_path(leaf1, 65011)
        if path is None:
            return "pure-L3 RT-2 did not return after L2VNI removed"
        if path.get("esi") != ES1_ID:
            return "pure-L3 RT-2 esi is %s, want %s" % (path.get("esi"), ES1_ID)
        return None

    _expect(_pure_l3_back)
    # leaf2 rebuilds the synced neighbor + static sync-MAC pin on vlan100.
    _expect(
        lambda: (None if _host1_synced(leaf2) else "leaf2 synced neighbor not rebuilt")
    )
    _expect(
        lambda: (
            None
            if _mac_static_pinned(leaf2, host1_mac, HOST_VID)
            else "leaf2 static sync-MAC pin not rebuilt after ML2->ML3"
        )
    )


def test_pure_l3_non_peer_leaf_type5_route_no_sync_neigh():
    """
    leaf3 is a non-ES-peer of host1: it installs host1's subnet as a type-5
    route (so it can route toward host1 over the L3VNI) but never receives a
    re-originated pure-L3 synced neighbor for host1. Control-plane assertions
    only; the topotest dataplane forwarding path is not exercised.
    """
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    # Make host1 known so it is synced on the ES peers (leaf1/leaf2).
    _ping(tgen.gears["host1"], ANYCAST_GW)

    dut = tgen.gears["leaf3"]
    host1_net = "45.0.0.0/24"

    def _has_type5_route(dut):
        out = dut.vtysh_cmd("show ip route vrf %s %s json" % (VRF, host1_net))
        try:
            routes = json.loads(out)
        except ValueError:
            return "invalid json: %s" % out
        entry = routes.get(host1_net)
        if not entry or entry[0].get("protocol") != "bgp":
            return "leaf3 has no type-5 route to %s: %s" % (host1_net, out)
        return None

    test_fn = partial(_has_type5_route, dut)
    _, result = topotest.run_and_expect(test_fn, None, count=WAIT_COUNT, wait=WAIT_STEP)
    assert result is None, result

    # leaf3 (non-peer) must never install a synced (extern_learn) neighbor for
    # host1; poll a short window to also rule out a delayed install.
    def _no_sync_neigh(dut):
        neigh = dut.run("ip neigh show")
        for line in neigh.splitlines():
            if HOST_IP["host1"] in line and "extern_learn" in line:
                return "leaf3 (non-peer) has a synced neighbor for host1: %s" % line
        return None

    for _ in range(5):
        err = _no_sync_neigh(dut)
        assert err is None, err
        topotest.sleep(1)


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
