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
import re
import platform
import contextlib
import subprocess
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

# IPv6 dual-stack overlay on host1's BD (VLAN 100), used by the ND-sync smoke
# test. Only the MH pair's host BD is dual-stacked; leaf3/host2 stay IPv4-only.
ANYCAST_GW6 = "fd00:45::1"
HOST_IP6 = {"host1": "fd00:45::101"}

# Additional no-L2VNI BDs on the MH pair (leaf1/leaf2), same VRF/L3VNI, to prove
# per-BD/ETAG isolation. VLAN 101 carries host3 (a second IP on host1's bond,
# tagged); VLAN 102 exists as an SVI only (a third BD with no sync traffic).
HOST_VID2 = 101
HOST_VID3 = 102
ANYCAST_GW2 = "45.0.1.1"
ANYCAST_GW3 = "45.0.2.1"
HOST3_IP = "45.0.1.103"

# L2VNI mapped to VLAN100 at runtime by the tests where the VLAN gains or loses
# an L2VNI.
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


def _bridge_mac(lo_ip, alt=False):
    """Per-leaf bridge MAC derived from its loopback; alt gives a second one."""
    return "44:38:39:00:%02x:%02x" % (int(alt), int(lo_ip.split(".")[-1]))


def config_leaf_base(
    node, lo_ip, host_vid=HOST_VID, gw_ip=ANYCAST_GW, gw_ip6=None, extra_host_bds=None
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
    # A fixed MAC stops ports added by tests from changing it, which would
    # bounce the L3VNI (see test_pure_l3_bridge_mac_change_resyncs).
    node.run("ip link set dev br_default address %s" % _bridge_mac(lo_ip))
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
    # Set, not inherited: the SVI MAC (the router MAC) must not follow a bridge
    # MAC change.
    node.run("ip link set dev vlan%d address %s" % (L3VNI, _bridge_mac(lo_ip)))
    node.run("ip link set dev vlan%d master %s" % (L3VNI, VRF))
    node.run("ip link set dev vlan%d up" % L3VNI)

    # Host access-BD SVI in the VRF, with the anycast gateway. This VLAN has an
    # SVI but NO VNI mapping -- it is the "acc_bd->zevpn == NULL" (no-L2VNI)
    # case the feature targets. Its vid is the RT-2 ETAG source.
    node.run(
        "ip link add link br_default name vlan%d type vlan id %d" % (host_vid, host_vid)
    )
    node.run("ip link set dev vlan%d address %s" % (host_vid, _bridge_mac(lo_ip)))
    node.run("ip link set dev vlan%d master %s" % (host_vid, VRF))
    node.run("ip link set dev vlan%d up" % host_vid)
    node.run("ip addr add %s/24 dev vlan%d" % (gw_ip, host_vid))
    node.run("/sbin/sysctl -w net.ipv4.conf.vlan%d.proxy_arp=1" % host_vid)

    # Optional IPv6 anycast gateway on the host BD (ND-sync smoke coverage).
    if gw_ip6:
        node.run("/sbin/sysctl -w net.ipv6.conf.vlan%d.forwarding=1" % host_vid)
        node.run("/sbin/sysctl -w net.ipv6.conf.vlan%d.proxy_ndp=1" % host_vid)
        # nodad: the anycast GW is intentionally identical on both MH leaves.
        node.run("ip addr add %s/64 dev vlan%d nodad" % (gw_ip6, host_vid))

    # Additional no-L2VNI BDs (extra VLANs/SVIs) in the same VRF.
    for bd_vid, bd_gw in extra_host_bds or ():
        node.run("/sbin/bridge vlan add vid %d dev br_default self" % bd_vid)
        node.run(
            "ip link add link br_default name vlan%d type vlan id %d" % (bd_vid, bd_vid)
        )
        node.run("ip link set dev vlan%d address %s" % (bd_vid, _bridge_mac(lo_ip)))
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
    """Map an L2VNI to an existing access VLAN at runtime: a per-VNI
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


def config_del_l2vni(node, vni, unslave_first=False):
    """Remove the L2VNI mapping, returning the BD to pure-L3. unslave_first
    makes the kernel report the device leaving the bridge before its delete,
    as some kernels do on a plain delete."""
    if unslave_first:
        node.run("ip link set dev vni%d nomaster 2>/dev/null || true" % vni)
    node.run("ip link del vni%d 2>/dev/null || true" % vni)


def config_host_bond(node, members, ip, ip6=None):
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
    if ip6:
        node.run("ip -6 addr add %s/64 dev bond0" % ip6)


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
        gw_ip6=ANYCAST_GW6,
        extra_host_bds=[(HOST_VID2, ANYCAST_GW2), (HOST_VID3, ANYCAST_GW3)],
    )
    config_leaf_base(
        leaf2,
        LEAF_LO["leaf2"],
        gw_ip6=ANYCAST_GW6,
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
        tgen.gears["host1"],
        ["host1-eth0", "host1-eth1"],
        HOST_IP["host1"],
        ip6=HOST_IP6["host1"],
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


_BARRIER_SEQ = [0]


def _barrier_round(leaves):
    _BARRIER_SEQ[0] += 1
    pfx = {
        leaf.name: "198.51.%d.%d" % (idx + 100, _BARRIER_SEQ[0] % 250 + 1)
        for idx, leaf in enumerate(leaves)
    }

    def _installed():
        for src in leaves:
            for dst in leaves:
                if dst is src:
                    continue
                p = pfx[src.name]
                out = dst.vtysh_cmd(
                    "show bgp vrf %s ipv4 unicast %s/32 json" % (VRF, p)
                )
                paths = json.loads(out).get("paths", []) if out.strip() else []
                # One path per spine: the spine sessions are not ordered.
                if len(paths) < 2:
                    return "%s has %d paths for %s from %s" % (
                        dst.name,
                        len(paths),
                        p,
                        src.name,
                    )
                if p not in dst.run("ip route show vrf %s %s/32" % (VRF, p)):
                    return "%s has not installed %s from %s" % (dst.name, p, src.name)
        return None

    for leaf in leaves:
        leaf.run("ip addr add %s/32 dev %s" % (pfx[leaf.name], VRF))
    try:
        _, result = topotest.run_and_expect(
            _installed, None, count=WAIT_COUNT, wait=WAIT_STEP
        )
        assert result is None, "event barrier: %s" % result
    finally:
        for leaf in leaves:
            leaf.run("ip addr del %s/32 dev %s 2>/dev/null" % (pfx[leaf.name], VRF))


def _settle():
    """Event barrier: wait until every leaf has processed everything already
    queued. Each leaf adds a new /32 to its VRF; it is exported as a type-5
    behind any earlier event on that leaf, so once every other leaf has it via
    both spines and in its kernel, all earlier effects have been sent. A
    second round, started only after that, proves each receiver's zebra has
    also applied what its own bgpd sent before.
    """
    tgen = get_topogen()
    leaves = [tgen.gears[n] for n in ("leaf1", "leaf2", "leaf3")]
    _barrier_round(leaves)
    _barrier_round(leaves)


def _assert_settled(bad_fn, msg):
    """Assert bad_fn() is false once every earlier event has been processed:
    no fixed observation window, so neither a slow nor a fast platform can let
    a delayed churn or withdraw slip through."""
    _settle()
    assert not bad_fn(), msg() if callable(msg) else msg


def _pure_l3_rt2_path(dut, asn, ip=None, eth_tag=HOST_VID, mac=None):
    """Return the pure-L3 RT-2 path dict for ip/eth_tag on dut, or None.

    A pure-L3 RT-2 is a routeType-2 macip route for the host IP with ethTag =
    the host VLAN, vni "0/L3VNI" (label[0]=0 Explicit NULL / label[1]=L3VNI)
    and the IP-VRF route-target. When `mac` is given the path's MAC must match
    too (the RT-2 NLRI key is (MAC, IP, ETAG)), so a mobility move can assert
    the old-key route is gone and the new-key route is present.
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
            if mac is not None and entry.get("mac", "").lower() != mac.lower():
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


def _host1_neigh_line(dut, vid=HOST_VID):
    """host1's own `ip neigh` line on dev vlan<vid>, or None. Other entries on
    the VLAN (e.g. a remote anycast-gateway neighbor) may be extern_learn."""
    for line in dut.run("ip neigh show dev vlan%d" % vid).splitlines():
        if line.split()[:1] == [HOST_IP["host1"]]:
            return line
    return None


def _host1_synced(dut, vid=HOST_VID):
    """True if host1 is installed as a pure-L3 extern_learn (synced) neighbor
    on dev vlan<vid>."""
    line = _host1_neigh_line(dut, vid)
    return line is not None and "extern_learn" in line


def _host1_local(dut, vid=HOST_VID):
    """True if host1 is learned locally (not synced) on dev vlan<vid>: present
    with an lladdr but without the extern_learn flag."""
    line = _host1_neigh_line(dut, vid)
    return line is not None and "lladdr" in line and "extern_learn" not in line


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


def _host_bond_mac(host):
    """Return host1's bond0 MAC (its neighbor lladdr on the leaves)."""
    return host.run("cat /sys/class/net/bond0/address").strip()


def host_move_ip_to_macvlan(host, ip, mac, plen=24):
    """Give host1's IP a new, legitimately reachable MAC without disturbing the
    LACP bond: move the address onto a macvlan over bond0 with `mac`. The host
    keeps answering ARP (new lladdr) so the moved adjacency is real, not stale.
    Reverse with host_restore_ip_to_bond()."""
    host.run("ip addr del %s/%d dev bond0" % (ip, plen))
    host.run("ip link add hmv link bond0 address %s type macvlan mode bridge" % mac)
    host.run("ip link set dev hmv up")
    host.run("ip addr add %s/%d dev hmv" % (ip, plen))


def host_restore_ip_to_bond(host, ip, plen=24):
    """Undo host_move_ip_to_macvlan(): move the IP back onto bond0."""
    host.run("ip link del hmv 2>/dev/null || true")
    host.run("ip addr add %s/%d dev bond0 2>/dev/null || true" % (ip, plen))


def leaf_move_host_bd(node, old_vid, new_vid, gw=ANYCAST_GW, plen=24):
    """Move host1's untagged access VLAN (the RT-2 ETAG) old_vid -> new_vid on a
    leaf, carrying the anycast-GW subnet to the new SVI so the same host IP still
    resolves under the new ETAG. Reverse with leaf_move_host_bd(new, old).

    The old vid is deleted from the ES bond (not left tagged). After reversing a
    move onto an extra BD, call leaf_trunk_extra_bd() so later tests still have
    that access BD — zebra frees it once the last member leaves, and a remote
    L3VNI-neigh ADD is then held instead of programmed.
    """
    node.run("/sbin/bridge vlan add vid %d dev hostbond1 pvid untagged" % new_vid)
    node.run("/sbin/bridge vlan del vid %d dev hostbond1" % old_vid)
    node.run("ip addr del %s/%d dev vlan%d 2>/dev/null || true" % (gw, plen, old_vid))
    # The subnet left this SVI; drop leftover ARP so a later extra-BD trunk
    # restore cannot re-originate the old ETAG from a stale kernel neighbor.
    node.run("ip neigh flush dev vlan%d" % old_vid)
    node.run("ip addr add %s/%d dev vlan%d" % (gw, plen, new_vid))
    node.run("/sbin/sysctl -w net.ipv4.conf.vlan%d.proxy_arp=1" % new_vid)


def leaf_trunk_extra_bd(node, vid):
    """Re-add vid as a tagged extra BD on the ES bond after a PVID move."""
    node.run("/sbin/bridge vlan add vid %d dev hostbond1" % vid)


def test_advertise_l3vni_neigh_cli():
    """The advertise-all-vni l3vni-neigh token is accepted, persists, and
    reaches zebra.

    Pure CLI + ZAPI plumbing; no dataplane behavior yet. We verify the bgpd
    running-config, that the flag propagated to zebra's per-VRF state inside
    ZEBRA_ADVERTISE_ALL_VNI (show evpn -> advertiseL3vniNeigh), and that the
    bgpd per-L3VNI view (show bgp l2vpn evpn vni <vni>) reflects the token.
    Re-entering advertise-all-vni without the token must clear the flag in
    both daemons while keeping EVPN enabled.
    """
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    leaf1 = tgen.gears["leaf1"]

    def _set_token(enable):
        leaf1.vtysh_cmd(
            "configure terminal\n"
            "router bgp 65011\n"
            " address-family l2vpn evpn\n"
            "  advertise-all-vni%s\n" % (" l3vni-neigh" if enable else "")
        )

    # The flag must reach zebra over ZAPI (bgpd -> zebra) and land in zvrf.
    def _zebra_flag_is(dut, want):
        out = dut.vtysh_cmd("show evpn json")
        try:
            js = json.loads(out)
        except Exception as exc:  # pragma: no cover - defensive
            return "cannot parse 'show evpn json': %s" % exc
        # 'show evpn json' is empty when EVPN itself is disabled.
        if "advertiseL3vniNeigh" not in js:
            return "zebra EVPN not enabled: %s" % js
        if js.get("advertiseL3vniNeigh") == want:
            return None
        return "zebra advertiseL3vniNeigh=%s (expected %s)" % (
            js.get("advertiseL3vniNeigh"),
            want,
        )

    # The bgpd per-L3VNI view must reflect the token as well.
    def _bgp_vni_flag_is(dut, want):
        out = dut.vtysh_cmd("show bgp l2vpn evpn vni %d json" % L3VNI)
        try:
            js = json.loads(out)
        except Exception as exc:  # pragma: no cover - defensive
            return "cannot parse 'show bgp l2vpn evpn vni' json: %s" % exc
        state = js.get("advertiseL3vniNeigh")
        if state == want:
            return None
        return "bgp vni %d advertiseL3vniNeigh=%s (expected %s)" % (L3VNI, state, want,)

    def _expect(fn, *args):
        _, result = topotest.run_and_expect(
            partial(fn, *args), None, count=WAIT_COUNT, wait=WAIT_STEP
        )
        assert result is None, result

    try:
        _set_token(True)
        running = leaf1.vtysh_cmd("show running-config")
        assert (
            "advertise-all-vni l3vni-neigh" in running
        ), "advertise-all-vni l3vni-neigh not present in running-config"
        _expect(_zebra_flag_is, leaf1, "Yes")
        _expect(_bgp_vni_flag_is, leaf1, "Active")

        # Token off: EVPN stays on, L3MH neighbor sync goes off in both daemons.
        _set_token(False)
        running = leaf1.vtysh_cmd("show running-config")
        assert (
            "advertise-all-vni l3vni-neigh" not in running
            and "advertise-all-vni" in running
        ), "expected plain advertise-all-vni in running-config"
        _expect(_zebra_flag_is, leaf1, "No")
        _expect(_bgp_vni_flag_is, leaf1, "Disabled")

        # 'no advertise-all-vni l3vni-neigh' also drops only the token.
        _set_token(True)
        _expect(_zebra_flag_is, leaf1, "Yes")
        leaf1.vtysh_cmd(
            "configure terminal\n"
            "router bgp 65011\n"
            " address-family l2vpn evpn\n"
            "  no advertise-all-vni l3vni-neigh\n"
        )
        running = leaf1.vtysh_cmd("show running-config")
        assert (
            "advertise-all-vni l3vni-neigh" not in running
            and "advertise-all-vni" in running
        ), "'no advertise-all-vni l3vni-neigh' must keep advertise-all-vni"
        _expect(_zebra_flag_is, leaf1, "No")
        _expect(_bgp_vni_flag_is, leaf1, "Disabled")
    finally:
        _set_token(True)

    _expect(_zebra_flag_is, leaf1, "Yes")


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
    advertise-all-vni l3vni-neigh), so the local ES is advertised to bgpd.
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
            "  advertise-all-vni l3vni-neigh\n" % asn
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
            return "pure-L3 RT-2 has esi %s, want %s" % (path.get("esi"), ES1_ID,)
        return None

    dut = tgen.gears["leaf1"]
    test_fn = partial(_has_pure_l3_rt2, dut, leaf_asn["leaf1"])
    _, result = topotest.run_and_expect(test_fn, None, count=WAIT_COUNT, wait=WAIT_STEP)
    assert result is None, result


def test_pure_l3_rt2_withdrawn_on_es_removal():
    """
    Removing the local ES from host1's access port withdraws its pure-L3 RT-2:
    the route needs a non-zero ESI and must NOT fall back to any other BD
    member's ES. Restoring the ES originates it again with the ESI. Exercises
    the per-port re-advertise on ES local-info clear/set and the MAC/ES cache
    membership check.
    """
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    leaf1 = tgen.gears["leaf1"]
    _ping(tgen.gears["host1"], ANYCAST_GW)

    def _esi_is(want):
        path = _pure_l3_rt2_path(leaf1, 65011)
        if want is None:
            return None if path is None else "RT-2 still advertised: %s" % path
        if path is None:
            return "pure-L3 RT-2 missing"
        if path.get("esi") != want:
            return "esi is %s, want %s" % (path.get("esi"), want)
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
        # No ES on the port: the RT-2 is withdrawn.
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
    Bidirectional l3vni-neigh lifecycle: toggling the token must clean
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
            "  advertise-all-vni%s\n" % (asn, " l3vni-neigh" if enable else "")
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
            "  advertise-all-vni\n"
        )
        dut.vtysh_cmd(
            "configure terminal\n"
            "router bgp 65012\n"
            " address-family l2vpn evpn\n"
            "  advertise-all-vni l3vni-neigh\n"
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


def test_pure_l3_etag_svi_in_other_vrf_not_installed():
    """
    The RT-2 ETAG is only the originator's VLAN number. If leaf2's SVI for that
    VLAN is in another VRF than the route's L3VNI (ES peers disagree on the
    VLAN->VRF mapping), the synced neighbor must not be installed on it. Once
    the SVI is back in the L3VNI's VRF, a re-import installs it again.
    """
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    leaf2 = tgen.gears["leaf2"]
    svi = "vlan%d" % HOST_VID2

    def _knob(enable):
        leaf2.vtysh_cmd(
            "configure terminal\n"
            "router bgp 65012\n"
            " address-family l2vpn evpn\n"
            "  advertise-all-vni%s\n" % (" l3vni-neigh" if enable else "")
        )

    def _synced(ip, dev):
        for line in leaf2.run("ip neigh show dev %s" % dev).splitlines():
            if line.split()[:1] == [ip] and "extern_learn" in line:
                return True
        return False

    def _expect(fn, msg):
        _, result = topotest.run_and_expect(
            lambda: None if fn() else msg, None, count=WAIT_COUNT, wait=WAIT_STEP
        )
        assert result is None, result

    def _reimport():
        _knob(False)
        _knob(True)

    _ping(tgen.gears["host1"], ANYCAST_GW)
    tgen.gears["host1"].run("ping -c 2 -W 1 -I %s %s" % (HOST3_IP, ANYCAST_GW2))
    _expect(
        lambda: _synced(HOST_IP["host1"], "vlan%d" % HOST_VID),
        "host1 not synced on leaf2 at baseline",
    )
    _expect(lambda: _synced(HOST3_IP, svi), "host3 not synced on leaf2 at baseline")

    leaf2.run("ip link add vrf2 type vrf table 1002")
    leaf2.run("ip link set dev vrf2 up")
    try:
        leaf2.run("ip link set dev %s master vrf2" % svi)
        # A re-import sends zebra a fresh ADD for host3 (ETAG 101, L3VNI 4000).
        _reimport()
        # host1's VLAN is consistent, so its re-install shows the ADDs were sent.
        _expect(
            lambda: _synced(HOST_IP["host1"], "vlan%d" % HOST_VID),
            "host1 not re-synced after the re-import",
        )
        _assert_settled(
            lambda: _synced(HOST3_IP, svi),
            lambda: "host3 installed on %s in vrf2: %s"
            % (svi, leaf2.run("ip neigh show dev %s" % svi)),
        )
    finally:
        leaf2.run("ip link set dev %s master %s" % (svi, VRF))
        leaf2.run("ip link del vrf2")
        _knob(True)

    _reimport()
    _expect(
        lambda: _synced(HOST3_IP, svi),
        "host3 not synced once %s is back in %s" % (svi, VRF),
    )


@pytest.mark.parametrize("late", ["svi", "bd_then_svi", "svi_then_bd"])
def test_pure_l3_sync_waits_for_svi(late):
    """
    leaf1 advertises a host on a VLAN that leaf2 is not yet set up for: either
    only the SVI is missing, or the whole access BD (bond VLAN membership and
    SVI) is configured afterwards, in either order. zebra must keep the RT-2 and
    install the synced neighbor and its static sync-MAC FDB entry once the VLAN
    is complete, with no new route update.
    """
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    leaf1 = tgen.gears["leaf1"]
    leaf2 = tgen.gears["leaf2"]
    vid = 104
    mac, ip = "00:00:5e:00:53:e3", "45.0.4.10"

    def _expect(step, fn):
        _, result = topotest.run_and_expect(fn, None, count=WAIT_COUNT, wait=WAIT_STEP)
        assert result is None, "%s: %s" % (step, result)

    def _bd_add(dut):
        dut.run("/sbin/bridge vlan add vid %d dev br_default self" % vid)
        dut.run("/sbin/bridge vlan add vid %d dev hostbond1" % vid)

    def _svi_add(dut):
        dut.run("ip link add link br_default name vlan%d type vlan id %d" % (vid, vid))
        dut.run("ip link set dev vlan%d master %s" % (vid, VRF))
        dut.run("ip link set dev vlan%d up" % vid)

    def _bd_del(dut):
        dut.run("ip link del vlan%d 2>/dev/null" % vid)
        dut.run("/sbin/bridge vlan del vid %d dev hostbond1" % vid)
        dut.run("/sbin/bridge vlan del vid %d dev br_default self" % vid)

    def _leaf2_synced():
        for line in leaf2.run("ip neigh show %s" % ip).splitlines():
            if "extern_learn" in line.split():
                return line
        return None

    _bd_add(leaf1)
    _svi_add(leaf1)
    if late == "svi":
        _bd_add(leaf2)
    try:
        leaf1.run(
            "/sbin/bridge fdb add %s dev hostbond1 master vlan %d dynamic" % (mac, vid)
        )
        leaf1.run("ip neigh replace %s lladdr %s dev vlan%d nud stale" % (ip, mac, vid))
        _expect(
            "RT-2 on leaf2",
            lambda: (
                None
                if _pure_l3_rt2_path(leaf2, 65011, ip=ip, eth_tag=vid)
                else "leaf2 has no pure-L3 RT-2 for %s" % ip
            ),
        )
        _assert_settled(
            lambda: _leaf2_synced() is not None,
            lambda: "%s synced on leaf2 with no SVI: %s" % (ip, _leaf2_synced()),
        )

        if late == "svi_then_bd":
            _svi_add(leaf2)
            _bd_add(leaf2)
        else:
            if late == "bd_then_svi":
                _bd_add(leaf2)
            _svi_add(leaf2)
        _expect(
            "VLAN completed",
            lambda: (
                None
                if _leaf2_synced()
                and "vlan%d" % vid in _leaf2_synced()
                and _mac_static_pinned(leaf2, mac, vid)
                else "%s not synced on leaf2 vlan%d with its static sync-MAC"
                % (ip, vid)
            ),
        )
    finally:
        leaf1.run("ip neigh del %s dev vlan%d 2>/dev/null" % (ip, vid))
        leaf1.run(
            "/sbin/bridge fdb del %s dev hostbond1 master vlan %d 2>/dev/null"
            % (mac, vid)
        )
        _expect(
            "cleanup",
            lambda: (
                None
                if _pure_l3_rt2_path(leaf2, 65011, ip=ip, eth_tag=vid) is None
                else "leaf2 still has the RT-2 for %s" % ip
            ),
        )
        _bd_del(leaf2)
        _bd_del(leaf1)


def test_pure_l3_local_learn_over_synced_keeps_neigh():
    """
    host1's synced (extern_learn) neighbor on leaf2 is replaced by a locally
    learned entry on the same SVI. zebra must keep that local entry and
    advertise it, not delete it as if it were the old synced copy.
    """
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    leaf2 = tgen.gears["leaf2"]
    svi = "vlan%d" % HOST_VID
    _ping(tgen.gears["host1"], ANYCAST_GW)
    host1_mac = tgen.gears["host1"].run("cat /sys/class/net/bond0/address").strip()

    def _knob(enable):
        leaf2.vtysh_cmd(
            "configure terminal\n"
            "router bgp 65012\n"
            " address-family l2vpn evpn\n"
            "  advertise-all-vni%s\n" % (" l3vni-neigh" if enable else "")
        )

    def _expect(fn, msg):
        _, result = topotest.run_and_expect(
            lambda: None if fn() else msg, None, count=WAIT_COUNT, wait=WAIT_STEP
        )
        assert result is None, result

    _expect(lambda: _host1_synced(leaf2), "host1 not synced on leaf2 at baseline")

    try:
        # Without extern_learn, the kernel reports it to zebra as a local learn.
        leaf2.run(
            "ip neigh replace %s lladdr %s dev %s nud reachable"
            % (HOST_IP["host1"], host1_mac, svi)
        )
        _expect(
            lambda: _pure_l3_rt2_path(leaf2, 65012) is not None,
            "leaf2 does not advertise host1 after the local learn",
        )
        _assert_settled(
            lambda: not _host1_local(leaf2),
            lambda: "local host1 entry deleted on leaf2: %s"
            % leaf2.run("ip neigh show dev %s" % svi),
        )
        assert (
            _pure_l3_rt2_path(leaf2, 65012) is not None
        ), "leaf2 withdrew host1's local RT-2"
    finally:
        leaf2.run("ip neigh del %s dev %s" % (HOST_IP["host1"], svi))
        _knob(False)
        _knob(True)

    _expect(lambda: _host1_synced(leaf2), "host1 not re-synced on leaf2")


def test_pure_l3_peer_with_local_arp_handles_origin_withdraw():
    """A peer leaf's local ARP remains authoritative when the origin withdraws.

    leaf2 first installs leaf1's pure-L3 RT-2, then learns the same ARP entry
    locally and originates its own RT-2. When leaf1 loses its ARP and withdraws,
    leaf2 must keep its local neighbor and route, clear only the peer-active
    marker, and avoid peer-proxy or hold-timer behavior.
    """
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    leaf1 = tgen.gears["leaf1"]
    leaf2 = tgen.gears["leaf2"]
    host1 = tgen.gears["host1"]
    svi = "vlan%d" % HOST_VID
    ip = HOST_IP["host1"]
    mac = _host_bond_mac(host1)
    _ping(host1, ANYCAST_GW)

    def _expect(fn, msg):
        _, result = topotest.run_and_expect(
            lambda: None if fn() else msg, None, count=WAIT_COUNT, wait=WAIT_STEP
        )
        assert result is None, result

    def _leaf2_detail():
        out = leaf2.vtysh_cmd("show evpn arp-cache vni %d ip %s json" % (L3VNI, ip))
        try:
            return json.loads(out)
        except Exception:  # pragma: no cover - defensive
            return {}

    _expect(lambda: _host1_synced(leaf2), "leaf2 not synced at baseline")
    try:
        # Convert leaf2's synced entry into a local ARP entry. The origin's
        # still-present RT-2 is recorded as peer-active on that local entry.
        leaf2.run("ip neigh replace %s lladdr %s dev %s nud reachable" % (ip, mac, svi))
        _expect(
            lambda: _host1_local(leaf2) and _pure_l3_rt2_path(leaf2, 65012) is not None,
            "leaf2 did not learn and advertise its local ARP",
        )
        _expect(
            lambda: bool(_leaf2_detail().get("peerActive")),
            "leaf2 did not record the origin's peer-active copy",
        )

        # The origin loses its ARP entry and withdraws. leaf2's own local ARP
        # and RT-2 must survive; the remote withdraw only clears peer-active.
        leaf1.run("ip neigh del %s dev %s" % (ip, svi))
        _expect(
            lambda: _pure_l3_rt2_path(leaf1, 65011) is None,
            "leaf1's local RT-2 was not withdrawn",
        )
        _expect(
            lambda: _host1_local(leaf2)
            and _pure_l3_rt2_path(leaf2, 65012) is not None
            and not _leaf2_detail().get("peerActive", False)
            and not _leaf2_detail().get("peerProxy", False)
            and not _leaf2_detail().get("peerActiveHold"),
            "leaf2 did not retain only its local neighbor without peer/proxy timer state: %s"
            % _leaf2_detail(),
        )
    finally:
        # Restore the shared-host baseline for later topotests.
        leaf2.run("ip neigh del %s dev %s 2>/dev/null" % (ip, svi))
        _ping(host1, ANYCAST_GW)

    _expect(
        lambda: _pure_l3_rt2_path(leaf1, 65011) is not None and _host1_synced(leaf2),
        "baseline pure-L3 route and peer sync were not restored",
    )


def _l3mh_knob(dut, asn, enable):
    dut.vtysh_cmd(
        "configure terminal\n"
        "router bgp %d\n"
        " address-family l2vpn evpn\n"
        "  advertise-all-vni%s\n" % (asn, " l3vni-neigh" if enable else "")
    )


def test_pure_l3_local_delete_falls_back_to_peer_sync():
    """
    leaf2 learns host1 locally on top of leaf1's sync, then loses that local
    ARP entry while leaf1 still advertises host1. leaf2 must fall back to the
    synced neighbor and static sync-MAC FDB entry; bgpd sends no new ADD
    because leaf1's RT-2 did not change.
    """
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    leaf2 = tgen.gears["leaf2"]
    svi = "vlan%d" % HOST_VID
    _ping(tgen.gears["host1"], ANYCAST_GW)
    host1_mac = _host_bond_mac(tgen.gears["host1"])

    def _expect(fn, msg):
        _, result = topotest.run_and_expect(
            lambda: None if fn() else msg, None, count=WAIT_COUNT, wait=WAIT_STEP
        )
        assert result is None, result

    _expect(lambda: _host1_synced(leaf2), "host1 not synced on leaf2 at baseline")

    try:
        leaf2.run(
            "ip neigh replace %s lladdr %s dev %s nud reachable"
            % (HOST_IP["host1"], host1_mac, svi)
        )
        _expect(
            lambda: _pure_l3_rt2_path(leaf2, 65012) is not None,
            "leaf2 does not advertise host1 after the local learn",
        )
        leaf2.run("ip neigh del %s dev %s" % (HOST_IP["host1"], svi))
        _expect(
            lambda: _pure_l3_rt2_path(leaf2, 65012) is None,
            "leaf2 still advertises host1 after the local delete",
        )
        _expect(
            lambda: _host1_synced(leaf2)
            and _mac_static_pinned(leaf2, host1_mac, HOST_VID),
            "leaf2 did not fall back to leaf1's sync: %s"
            % leaf2.run("ip neigh show dev %s" % svi),
        )
    finally:
        if not _host1_synced(leaf2):
            _l3mh_knob(leaf2, 65012, False)
            _l3mh_knob(leaf2, 65012, True)

    _ping(tgen.gears["host1"], ANYCAST_GW)
    _expect(lambda: _host1_synced(leaf2), "host1 not re-synced on leaf2")


def test_pure_l3_local_delete_on_both_leaves_leaves_no_sync():
    """
    host1 is local on both leaves, so each one's entry is backed by the
    other's RT-2. Deleting both local entries at once may briefly leave both
    synced, but neither originates an RT-2, so the withdrawals must clear both:
    no host1 neighbor and no static sync-MAC FDB entry may remain on either.
    """
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    host1 = tgen.gears["host1"]
    leaves = {"leaf1": 65011, "leaf2": 65012}
    svi = "vlan%d" % HOST_VID
    _ping(host1, ANYCAST_GW)
    host1_mac = _host_bond_mac(host1)
    gw_mac = tgen.gears["leaf1"].run("cat /sys/class/net/%s/address" % svi).strip()

    def _expect(fn, msg):
        _, result = topotest.run_and_expect(
            lambda: None if fn() else msg, None, count=WAIT_COUNT, wait=WAIT_STEP
        )
        assert result is None, result

    def _host1_state(name):
        dut = tgen.gears[name]
        return _host1_neigh_line(dut), _mac_static_pinned(dut, host1_mac, HOST_VID)

    try:
        # A permanent gateway entry stops host1 from ARPing and being relearned.
        host1.run(
            "ip neigh replace %s lladdr %s dev bond0 nud permanent"
            % (ANYCAST_GW, gw_mac)
        )
        for name in leaves:
            tgen.gears[name].run(
                "ip neigh replace %s lladdr %s dev %s nud reachable"
                % (HOST_IP["host1"], host1_mac, svi)
            )
        for name, asn in leaves.items():
            _expect(
                lambda n=name, a=asn: _pure_l3_rt2_path(tgen.gears[n], a) is not None,
                "%s does not advertise host1" % name,
            )

        for name in leaves:
            tgen.gears[name].run("ip neigh del %s dev %s" % (HOST_IP["host1"], svi))

        _expect(
            lambda: all(_host1_state(n) == (None, False) for n in leaves),
            "host1 state left behind: %s" % {n: _host1_state(n) for n in leaves},
        )
        _assert_settled(
            lambda: any(_host1_state(n) != (None, False) for n in leaves),
            lambda: "host1 state came back: %s" % {n: _host1_state(n) for n in leaves},
        )
    finally:
        host1.run("ip neigh del %s dev bond0" % ANYCAST_GW)

    _ping(host1, ANYCAST_GW)
    _expect(
        lambda: _host1_synced(tgen.gears["leaf2"])
        or _host1_synced(tgen.gears["leaf1"]),
        "host1 not re-synced after the test",
    )


def test_pure_l3_import_rt_change_updates_sync_neigh():
    """
    The synced neighbor follows the VRF's import RTs, not only route updates.
    A manual import RT on leaf2's vrf1 replaces the auto RT, so host1's
    pure-L3 RT-2 is no longer imported: its synced neighbor and sync-MAC must
    be removed. Removing the manual RT restores the auto RT: host1 must be
    synced again, with no new advertisement from leaf1.
    """
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    leaf2 = tgen.gears["leaf2"]
    _ping(tgen.gears["host1"], ANYCAST_GW)
    host1_mac = tgen.gears["host1"].run("cat /sys/class/net/bond0/address").strip()

    def _import_rt(present):
        leaf2.vtysh_cmd(
            "configure terminal\n"
            "router bgp 65012 vrf %s\n"
            " address-family l2vpn evpn\n"
            "  %sroute-target import 1:1\n" % (VRF, "" if present else "no ")
        )

    def _synced_state(want):
        has_neigh = _host1_synced(leaf2)
        has_pin = _mac_static_pinned(leaf2, host1_mac, HOST_VID)
        if want and not (has_neigh and has_pin):
            return "host1 not synced: neigh %s pin %s" % (has_neigh, has_pin)
        if not want and (has_neigh or has_pin):
            return "host1 still synced: neigh %s pin %s" % (has_neigh, has_pin)
        return None

    def _expect(want):
        _, result = topotest.run_and_expect(
            partial(_synced_state, want), None, count=WAIT_COUNT, wait=WAIT_STEP
        )
        assert result is None, result

    _expect(True)
    try:
        _import_rt(True)
        _expect(False)
    finally:
        _import_rt(False)
    _expect(True)


def test_pure_l3_vrf_rd_and_export_rt_change_refresh():
    """
    leaf1's pure-L3 RT-2 for host1 uses vrf1's RD and export RTs. Changing
    either must re-originate it: the route moves to the new RD and the old-RD
    copy is withdrawn (also on the peer), and an export-RT change replaces the
    RT. Restoring the auto RD/RT moves it back; host1 stays synced on leaf2.
    """
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    leaf1 = tgen.gears["leaf1"]
    leaf2 = tgen.gears["leaf2"]
    new_rd = "%s:99" % LEAF_LO["leaf1"]
    auto_rt = "RT:65011:%d" % L3VNI
    new_rt = "RT:65011:%d" % (L3VNI + 1)
    _ping(tgen.gears["host1"], ANYCAST_GW)

    def _vrf_cfg(line):
        leaf1.vtysh_cmd(
            "configure terminal\n"
            "router bgp 65011 vrf %s\n"
            " address-family l2vpn evpn\n"
            "  %s\n" % (VRF, line)
        )

    def _host1_rt2_ecs(dut, rd):
        """Ext-community string of host1's pure-L3 RT-2 under rd, or None."""
        js = json.loads(
            dut.vtysh_cmd("show bgp l2vpn evpn route detail type macip json")
        )
        rdval = js.get(rd)
        if not isinstance(rdval, dict):
            return None
        for entry in rdval.values():
            if not isinstance(entry, dict) or entry.get("ip") != HOST_IP["host1"]:
                continue
            for pathset in entry.get("paths", []):
                for path in pathset:
                    if path.get("vni") == "0/%d" % L3VNI:
                        return path.get("extendedCommunity", {}).get("string", "")
        return None

    def _expect(fn, msg):
        _, result = topotest.run_and_expect(
            lambda: None if fn() else msg, None, count=WAIT_COUNT, wait=WAIT_STEP
        )
        assert result is None, result

    old_rd = json.loads(leaf1.vtysh_cmd("show bgp l2vpn evpn vni %d json" % L3VNI))[
        "rd"
    ]
    _expect(
        lambda: _host1_rt2_ecs(leaf1, old_rd) is not None, "no host1 RT-2 at baseline"
    )

    try:
        _vrf_cfg("rd %s" % new_rd)
        for dut in (leaf1, leaf2):
            _expect(
                lambda: _host1_rt2_ecs(dut, new_rd) is not None,
                "%s: host1 RT-2 not under new RD %s" % (dut.name, new_rd),
            )
            _expect(
                lambda: _host1_rt2_ecs(dut, old_rd) is None,
                "%s: host1 RT-2 still under old RD %s" % (dut.name, old_rd),
            )
        _expect(lambda: _host1_synced(leaf2), "host1 not synced after RD change")

        _vrf_cfg("route-target export %s" % new_rt[3:])
        _expect(
            lambda: new_rt in (_host1_rt2_ecs(leaf1, new_rd) or "")
            and auto_rt not in (_host1_rt2_ecs(leaf1, new_rd) or ""),
            "host1 RT-2 does not carry only the new export RT %s" % new_rt,
        )
    finally:
        _vrf_cfg("no route-target export %s" % new_rt[3:])
        _vrf_cfg("no rd %s" % new_rd)

    _expect(
        lambda: auto_rt in (_host1_rt2_ecs(leaf1, old_rd) or ""),
        "host1 RT-2 not back under %s with %s" % (old_rd, auto_rt),
    )
    _expect(
        lambda: _host1_rt2_ecs(leaf2, new_rd) is None, "RT-2 left under %s" % new_rd
    )
    _expect(lambda: _host1_synced(leaf2), "host1 not synced after restore")


def test_pure_l3_l3vni_down_withdraws_local_rt2():
    """
    When leaf1's L3VNI goes down, zebra sends the L3VNI delete before the
    per-host deletes, so bgpd must withdraw leaf1's local pure-L3 RT-2s itself.
    leaf2 must lose leaf1's host1 route and its synced neighbor, and get both
    back once the L3VNI is up again.
    """
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    leaf1 = tgen.gears["leaf1"]
    leaf2 = tgen.gears["leaf2"]
    _ping(tgen.gears["host1"], ANYCAST_GW)

    def _expect(fn, msg):
        _, result = topotest.run_and_expect(
            lambda: None if fn() else msg, None, count=WAIT_COUNT, wait=WAIT_STEP
        )
        assert result is None, result

    _expect(
        lambda: _pure_l3_rt2_path(leaf2, 65011) is not None,
        "no leaf1 host1 RT-2 at baseline",
    )
    _expect(lambda: _host1_synced(leaf2), "host1 not synced at baseline")

    try:
        leaf1.run("ip link set dev vni%d down" % L3VNI)
        _expect(
            lambda: _pure_l3_rt2_path(leaf2, 65011) is None,
            "leaf2 still has leaf1's host1 RT-2 after leaf1's L3VNI went down",
        )
        _expect(lambda: not _host1_synced(leaf2), "host1 still synced on leaf2")
    finally:
        leaf1.run("ip link set dev vni%d up" % L3VNI)

    _ping(tgen.gears["host1"], ANYCAST_GW)
    _expect(
        lambda: _pure_l3_rt2_path(leaf2, 65011) is not None, "leaf1 host1 RT-2 not back"
    )
    _expect(lambda: _host1_synced(leaf2), "host1 not re-synced on leaf2")


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


def test_pure_l3_arp_delete_withdraws_sync():
    """
    ARP delete / age-out withdraw. Removing the locally-learned ARP entry for
    host1 on its local owner (leaf1) -- as happens on neighbor delete or kernel
    age-out -- makes leaf1 withdraw the pure-L3 RT-2, and the ES peer (leaf2)
    removes both the synced extern_learn neighbor and the static sync-MAC pin.
    Re-learning host1 restores the full sync. An explicit `ip neigh del` drives
    the DELNEIGH -> withdraw -> peer-cleanup path deterministically (waiting for
    kernel aging would only add timing flakes to the same code path).
    """
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    leaf1 = tgen.gears["leaf1"]
    leaf2 = tgen.gears["leaf2"]
    host1 = tgen.gears["host1"]
    _ping(host1, ANYCAST_GW)

    def _expect(fn):
        _, result = topotest.run_and_expect(fn, None, count=WAIT_COUNT, wait=WAIT_STEP)
        assert result is None, result

    ip = HOST_IP["host1"]
    host1_mac = _host_bond_mac(host1)

    def _synced_pinned(dut):
        if not _host1_synced(dut):
            return "host1 not synced on leaf2: %s" % dut.run(
                "ip neigh show dev vlan%d" % HOST_VID
            )
        if not _mac_static_pinned(dut, host1_mac, HOST_VID):
            return "host1 sync-MAC pin missing on hostbond1"
        return None

    # Baseline: leaf1 owns the local ARP + originates the RT-2; leaf2 syncs + pins.
    _expect(
        lambda: (
            None
            if _pure_l3_rt2_path(leaf1, 65011) is not None
            else "baseline pure-L3 RT-2 missing"
        )
    )
    _expect(lambda: _synced_pinned(leaf2))
    # host1's ARP must be a local (not synced) entry on leaf1 -- that is the
    # entry whose deletion drives the withdraw.
    _expect(
        lambda: (
            None
            if _host1_local(leaf1)
            else "host1 not learned locally on leaf1: %s"
            % leaf1.run("ip neigh show dev vlan%d" % HOST_VID)
        )
    )

    try:
        # host1's ARP probe for the gateway would let leaf1 re-learn it at once.
        gw_mac = leaf1.run("cat /sys/class/net/vlan%d/address" % HOST_VID).strip()
        host1.run(
            "ip neigh replace %s lladdr %s dev bond0 nud permanent"
            % (ANYCAST_GW, gw_mac)
        )

        # Delete host1's local ARP entry on leaf1 (models neighbor del/age-out).
        leaf1.run("ip neigh del %s dev vlan%d" % (ip, HOST_VID))

        # leaf1 withdraws its RT-2 ...
        _expect(
            lambda: (
                None
                if _pure_l3_rt2_path(leaf1, 65011) is None
                else "pure-L3 RT-2 not withdrawn after ARP delete"
            )
        )

        # ... and leaf2 clears both the synced neighbor and the static pin.
        def _cleaned(dut):
            if _host1_synced(dut):
                return "leaf2 synced neighbor still present after ARP delete"
            if _mac_static_pinned(dut, host1_mac, HOST_VID):
                return "leaf2 sync-MAC pin still present after ARP delete"
            return None

        _expect(lambda: _cleaned(leaf2))
    finally:
        # Re-learn host1 so the baseline is restored for later tests.
        host1.run("ip neigh del %s dev bond0 2>/dev/null" % ANYCAST_GW)
        _ping(host1, ANYCAST_GW)

    # Baseline restored: RT-2 re-originated and leaf2 re-syncs neighbor + pin.
    _expect(
        lambda: (
            None
            if _pure_l3_rt2_path(leaf1, 65011) is not None
            else "pure-L3 RT-2 did not return after re-learn"
        )
    )
    _expect(lambda: _synced_pinned(leaf2))


def test_pure_l3_synced_neigh_survives_kernel_flush():
    """
    A synced (remote) pure-L3 neighbor is owned by BGP, not the kernel. On the
    ES peer (leaf2), an `ip neigh del`, an SVI down/up, and a BD remove/re-add
    all lose kernel state while leaf1 keeps advertising the same RT-2; zebra
    must re-install the neighbor and its sync-MAC pin without any route change.
    """
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    leaf1 = tgen.gears["leaf1"]
    leaf2 = tgen.gears["leaf2"]
    host1 = tgen.gears["host1"]
    _ping(host1, ANYCAST_GW)

    def _expect(fn):
        _, result = topotest.run_and_expect(fn, None, count=WAIT_COUNT, wait=WAIT_STEP)
        assert result is None, result

    ip = HOST_IP["host1"]
    host1_mac = _host_bond_mac(host1)

    def _synced_pinned(dut):
        if not _host1_synced(dut):
            return "host1 not synced on leaf2: %s" % dut.run(
                "ip neigh show dev vlan%d" % HOST_VID
            )
        if not _mac_static_pinned(dut, host1_mac, HOST_VID):
            return "host1 sync-MAC pin missing on hostbond1"
        return None

    _expect(
        lambda: (
            None
            if _pure_l3_rt2_path(leaf1, 65011) is not None
            else "baseline pure-L3 RT-2 missing"
        )
    )
    _expect(lambda: _synced_pinned(leaf2))

    # Kernel delete of the synced entry is re-installed by zebra.
    leaf2.run("ip neigh del %s dev vlan%d" % (ip, HOST_VID))
    _expect(lambda: _synced_pinned(leaf2))

    # SVI down holds the entry; SVI up re-installs it from zebra.
    try:
        leaf2.run("ip link set dev vlan%d down" % HOST_VID)
        _expect(
            lambda: (
                None
                if not _host1_synced(leaf2)
                else "synced neighbor still in kernel with SVI down"
            )
        )
    finally:
        leaf2.run("ip link set dev vlan%d up" % HOST_VID)
    _expect(lambda: _synced_pinned(leaf2))

    # BD remove/re-add: the kernel keeps static FDB entries on a VLAN delete
    # (and rejects deleting them after), so drop the pin first; re-adding the
    # bond to the BD must re-pin it.
    try:
        leaf2.run(
            "/sbin/bridge fdb del %s dev hostbond1 master vlan %d"
            % (host1_mac, HOST_VID)
        )
        leaf2.run("/sbin/bridge vlan del vid %d dev hostbond1" % HOST_VID)
        _expect(
            lambda: (
                None
                if not _mac_static_pinned(leaf2, host1_mac, HOST_VID)
                else "sync-MAC pin still present with BD removed"
            )
        )
    finally:
        leaf2.run("/sbin/bridge vlan add vid %d dev hostbond1 pvid untagged" % HOST_VID)
    _expect(lambda: _synced_pinned(leaf2))


def _neigh_synced(dut, ip, vid=HOST_VID):
    """True if `ip` is an extern_learn (synced) neighbor on dev vlan<vid>."""
    fam = "-6 " if ":" in ip else ""
    for line in dut.run("ip %sneigh show dev vlan%d" % (fam, vid)).splitlines():
        if line.split()[:1] == [ip] and "extern_learn" in line:
            return True
    return False


def test_pure_l3_esi_from_sync_mac():
    """
    The static sync-MAC FDB entry leaf2 installs for a synced host is never
    reported to zebra as an FDB learn, and it stops the bridge from learning
    the MAC dynamically. On a multi-member BD, a local IP of the same host must
    still resolve the ES from that entry rather than go out with a zero ESI.
    Synthetic hosts (kernel neighbors with made-up MACs) make the order of the
    sync and the local learn deterministic:
      A. IPv6 synced first, then IPv4 learned locally on leaf2.
      B. IPv4 learned locally on leaf2 first (no RT-2: port unknown), then
         IPv6 synced.
      C. Two synced IPs share one sync-MAC: withdrawing one keeps the entry.
      D. A synced IP becomes local on the same SVI: its RT-2 keeps the ESI.
    """
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    leaf1 = tgen.gears["leaf1"]
    leaf2 = tgen.gears["leaf2"]

    def _expect(fn):
        _, result = topotest.run_and_expect(fn, None, count=WAIT_COUNT, wait=WAIT_STEP)
        assert result is None, result

    def _neigh_add(dut, ip, mac):
        fam = "-6 " if ":" in ip else ""
        dut.run(
            "ip %sneigh replace %s lladdr %s dev vlan%d nud stale"
            % (fam, ip, mac, HOST_VID)
        )

    def _neigh_del(dut, ip):
        fam = "-6 " if ":" in ip else ""
        dut.run("ip %sneigh del %s dev vlan%d 2>/dev/null" % (fam, ip, HOST_VID))

    def _leaf2_rt2_esi(ip, want):
        path = _pure_l3_rt2_path(leaf2, 65012, ip=ip)
        if path is None:
            return "leaf2 has no pure-L3 RT-2 for %s" % ip
        if path.get("esi") != want:
            return "leaf2 RT-2 %s esi %s, want %s" % (ip, path.get("esi"), want)
        return None

    def _synced_with_sync_mac(dut, ip, mac):
        if not _neigh_synced(dut, ip):
            return "%s not synced on %s" % (ip, dut.name)
        if not _mac_static_pinned(dut, mac, HOST_VID):
            return "static sync-MAC %s missing on %s hostbond1" % (mac, dut.name)
        return None

    mac_a, ip4_a, ip6_a = "00:00:5e:00:53:a1", "45.0.0.161", "fd00:45::1a1"
    mac_b, ip4_b, ip6_b = "00:00:5e:00:53:b1", "45.0.0.162", "fd00:45::1b1"
    mac_c, ip4_c, ip6_c = "00:00:5e:00:53:c1", "45.0.0.163", "fd00:45::1c1"
    mac_d, ip4_d = "00:00:5e:00:53:d1", "45.0.0.164"
    added = [(leaf1, ip6_a), (leaf2, ip4_a), (leaf2, ip4_b), (leaf1, ip6_b)]
    added += [(leaf1, ip4_c), (leaf1, ip6_c), (leaf1, ip4_d), (leaf2, ip4_d)]
    leaf1_macs = (mac_a, mac_b, mac_c, mac_d)

    # A second bond on leaf2's BD: the ESI must come from the MAC's port.
    leaf2.run("ip link add l3mhbond type bond mode active-backup")
    leaf2.run("ip link set dev l3mhbond master br_default")
    leaf2.run("/sbin/bridge vlan del vid 1 dev l3mhbond")
    leaf2.run("/sbin/bridge vlan add vid %d dev l3mhbond pvid untagged" % HOST_VID)
    leaf2.run("ip link set dev l3mhbond up")
    # leaf1 originates these hosts with the ESI only if it knows their port.
    for mac in leaf1_macs:
        leaf1.run(
            "/sbin/bridge fdb add %s dev hostbond1 master vlan %d dynamic"
            % (mac, HOST_VID)
        )
    try:
        # A: sync first, then local learn of another IP of the same host.
        _neigh_add(leaf1, ip6_a, mac_a)
        _expect(lambda: _synced_with_sync_mac(leaf2, ip6_a, mac_a))
        _neigh_add(leaf2, ip4_a, mac_a)
        _expect(lambda: _leaf2_rt2_esi(ip4_a, ES1_ID))
        _expect(
            lambda: (
                None if _neigh_synced(leaf1, ip4_a) else "leaf1 did not sync %s" % ip4_a
            )
        )

        # B: local learn first (port unknown, no RT-2), then the sync gives it
        # its port and ESI.
        _neigh_add(leaf2, ip4_b, mac_b)
        _assert_settled(
            lambda: _pure_l3_rt2_path(leaf2, 65012, ip=ip4_b) is not None,
            "leaf2 advertised %s with its port unknown" % ip4_b,
        )
        _neigh_add(leaf1, ip6_b, mac_b)
        _expect(lambda: _leaf2_rt2_esi(ip4_b, ES1_ID))
        _expect(
            lambda: (
                None if _neigh_synced(leaf1, ip4_b) else "leaf1 did not sync %s" % ip4_b
            )
        )

        # C: withdrawing one of two synced IPs keeps the shared sync-MAC.
        _neigh_add(leaf1, ip4_c, mac_c)
        _neigh_add(leaf1, ip6_c, mac_c)
        _expect(lambda: _synced_with_sync_mac(leaf2, ip4_c, mac_c))
        _expect(lambda: _synced_with_sync_mac(leaf2, ip6_c, mac_c))
        _neigh_del(leaf1, ip6_c)
        _expect(
            lambda: (
                None
                if not _neigh_synced(leaf2, ip6_c)
                else "leaf2 still has %s synced after withdraw" % ip6_c
            )
        )
        _assert_settled(
            lambda: _synced_with_sync_mac(leaf2, ip4_c, mac_c) is not None,
            "shared static sync-MAC or %s sync lost after %s withdraw" % (ip4_c, ip6_c),
        )

        # D: the synced IP itself is learned locally; removing its sync-MAC
        # must not lose the only MAC->port binding before the ESI is resolved.
        _neigh_add(leaf1, ip4_d, mac_d)
        _expect(lambda: _synced_with_sync_mac(leaf2, ip4_d, mac_d))
        _neigh_add(leaf2, ip4_d, mac_d)
        _expect(lambda: _leaf2_rt2_esi(ip4_d, ES1_ID))
    finally:
        for dut, ip in added:
            _neigh_del(dut, ip)
        for mac in leaf1_macs:
            leaf1.run(
                "/sbin/bridge fdb del %s dev hostbond1 master vlan %d 2>/dev/null"
                % (mac, HOST_VID)
            )
        leaf2.run("ip link del l3mhbond")


@pytest.mark.parametrize("with_l2vni", [False, True])
def test_pure_l3_esi_from_fdb_learn(with_l2vni):
    """
    A bridge FDB learn on a VLAN without an L2VNI must reach the L3MH MAC->port
    cache, so a local neighbor on a multi-member BD is advertised with its ESI.
    Also run with an L2VNI on an unrelated VLAN, whose VXLAN device must not
    claim the L3MH VLAN's MACs.
    """
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    leaf1 = tgen.gears["leaf1"]
    leaf2 = tgen.gears["leaf2"]
    mac, ip = "00:00:5e:00:53:d1", "45.0.0.171"
    vid, vni = 103, 10103

    def _expect(fn):
        _, result = topotest.run_and_expect(fn, None, count=WAIT_COUNT, wait=WAIT_STEP)
        assert result is None, result

    def _leaf2_rt2_esi():
        path = _pure_l3_rt2_path(leaf2, 65012, ip=ip)
        if path is None:
            return "leaf2 has no pure-L3 RT-2 for %s" % ip
        if path.get("esi") != ES1_ID:
            return "leaf2 RT-2 %s esi %s, want %s" % (ip, path.get("esi"), ES1_ID)
        return None

    # A second bond on the BD: the ESI must come from the MAC's port.
    leaf2.run("ip link add l3mhbond type bond mode active-backup")
    leaf2.run("ip link set dev l3mhbond master br_default")
    leaf2.run("/sbin/bridge vlan del vid 1 dev l3mhbond")
    leaf2.run("/sbin/bridge vlan add vid %d dev l3mhbond pvid untagged" % HOST_VID)
    leaf2.run("ip link set dev l3mhbond up")
    if with_l2vni:
        config_add_l2vni(leaf2, LEAF_LO["leaf2"], vid, vni)
    try:
        leaf2.run(
            "/sbin/bridge fdb add %s dev hostbond1 master vlan %d dynamic"
            % (mac, HOST_VID)
        )
        leaf2.run(
            "ip neigh replace %s lladdr %s dev vlan%d nud stale" % (ip, mac, HOST_VID)
        )
        _expect(_leaf2_rt2_esi)
        _expect(
            lambda: None if _neigh_synced(leaf1, ip) else "leaf1 did not sync %s" % ip
        )
    finally:
        leaf2.run("ip neigh del %s dev vlan%d 2>/dev/null" % (ip, HOST_VID))
        leaf2.run(
            "/sbin/bridge fdb del %s dev hostbond1 master vlan %d 2>/dev/null"
            % (mac, HOST_VID)
        )
        if with_l2vni:
            config_del_l2vni(leaf2, vni)
        leaf2.run("ip link del l3mhbond")


def test_pure_l3_no_esi_without_mac_port():
    """
    zebra tracks BD membership on bonds only, so an ES bond plus a plain
    Ethernet port on the BD looks single-member. A host behind the plain port
    must never carry the bond's ESI, and a pure-L3 RT-2 needs a non-zero ESI:
    the host is not advertised with its port unknown (ARP before the FDB learn,
    or after the FDB entry is deleted) nor once its FDB entry names the plain
    port.
    """
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    leaf1 = tgen.gears["leaf1"]
    leaf2 = tgen.gears["leaf2"]
    mac, ip = "00:00:5e:00:53:e1", "45.0.0.181"

    def _expect(fn):
        _, result = topotest.run_and_expect(fn, None, count=WAIT_COUNT, wait=WAIT_STEP)
        assert result is None, result

    def _leaf2_rt2_absent():
        path = _pure_l3_rt2_path(leaf2, 65012, ip=ip)
        if path is None:
            return None
        return "leaf2 advertises %s (esi %s)" % (ip, path.get("esi"))

    def _check(when):
        _expect(_leaf2_rt2_absent)
        _assert_settled(
            lambda: _leaf2_rt2_absent() is not None or _neigh_synced(leaf1, ip),
            "%s: %s advertised or synced on leaf1" % (when, ip),
        )

    leaf2.run("ip link add l3mhport type dummy")
    config_access_port(leaf2, "l3mhport")
    leaf2.run("ip link set dev l3mhport up")
    try:
        leaf2.run(
            "ip neigh replace %s lladdr %s dev vlan%d nud stale" % (ip, mac, HOST_VID)
        )
        _check("no FDB entry")

        leaf2.run(
            "/sbin/bridge fdb add %s dev l3mhport master vlan %d dynamic"
            % (mac, HOST_VID)
        )
        _check("FDB entry on the plain port")

        leaf2.run(
            "/sbin/bridge fdb del %s dev l3mhport master vlan %d" % (mac, HOST_VID)
        )
        _check("FDB entry deleted")
    finally:
        leaf2.run("ip neigh del %s dev vlan%d 2>/dev/null" % (ip, HOST_VID))
        leaf2.run("ip link del l3mhport")


def test_pure_l3_fdb_ageout_withdraws_until_relearn():
    """
    A local host's FDB entry goes away while its ARP entry stays (the kernel
    probes it). With its port unknown, leaf1 must withdraw the pure-L3 RT-2
    rather than advertise it with no ESI, keep the neighbor, and originate it
    again once the FDB entry is relearned. The final ARP delete removes the
    neighbor and the RT-2 stays withdrawn.
    """
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    leaf1 = tgen.gears["leaf1"]
    mac, ip = "00:00:5e:00:53:e5", "45.0.0.192"

    def _expect(step, fn):
        _, result = topotest.run_and_expect(fn, None, count=WAIT_COUNT, wait=WAIT_STEP)
        assert result is None, "%s: %s" % (step, result)

    def _fdb(op):
        leaf1.run(
            "/sbin/bridge fdb %s %s dev hostbond1 master vlan %d%s"
            % (op, mac, HOST_VID, " dynamic" if op == "add" else "")
        )

    def _zebra_type():
        out = leaf1.vtysh_cmd("show evpn arp-cache vni %d ip %s json" % (L3VNI, ip))
        try:
            return json.loads(out).get("type")
        except Exception:  # pragma: no cover - defensive
            return None

    def _rt2(want_esi):
        path = _pure_l3_rt2_path(leaf1, 65011, ip=ip)
        if want_esi is None:
            return None if path is None else "leaf1 still advertises %s" % ip
        if path is None:
            return "leaf1 has no pure-L3 RT-2 for %s" % ip
        if path.get("esi") != want_esi:
            return "leaf1 RT-2 %s esi %s, want %s" % (ip, path.get("esi"), want_esi)
        return None

    _fdb("add")
    try:
        leaf1.run(
            "ip neigh replace %s lladdr %s dev vlan%d nud stale" % (ip, mac, HOST_VID)
        )
        _expect("learned", lambda: _rt2(ES1_ID))

        _fdb("del")
        _expect("FDB gone", lambda: _rt2(None))
        _assert_settled(
            lambda: _rt2(None) is not None or _zebra_type() != "local",
            lambda: "FDB gone: %s re-advertised or dropped from zebra (type %s)"
            % (ip, _zebra_type()),
        )

        _fdb("add")
        _expect("FDB relearned", lambda: _rt2(ES1_ID))

        _fdb("del")
        _expect("FDB gone again", lambda: _rt2(None))
        leaf1.run("ip neigh del %s dev vlan%d" % (ip, HOST_VID))
        _expect(
            "ARP deleted",
            lambda: None if _zebra_type() is None else "zebra still has %s" % ip,
        )
        _assert_settled(
            lambda: _rt2(None) is not None, "%s re-advertised after its delete" % ip
        )
    finally:
        leaf1.run("ip neigh del %s dev vlan%d 2>/dev/null" % (ip, HOST_VID))
        _fdb("del")


def test_pure_l3_reimport_with_l2vni_es_base():
    """
    On a leaf that also has an L2VNI, the ES base EVPN comes from that L2VNI,
    so turning l3vni-neigh off/on or bouncing the L3VNI does not change the
    local ES in bgpd. bgpd must still re-send the stored pure-L3 RT-2s to zebra
    so the synced neighbor and its static sync-MAC come back.
    """
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    leaf2 = tgen.gears["leaf2"]
    host1 = tgen.gears["host1"]
    _ping(host1, ANYCAST_GW)
    host1_mac = _host_bond_mac(host1)
    vid, vni = 103, 10103

    def _expect(fn):
        _, result = topotest.run_and_expect(fn, None, count=WAIT_COUNT, wait=WAIT_STEP)
        assert result is None, result

    def _knob(enable):
        leaf2.vtysh_cmd(
            "configure terminal\nrouter bgp 65012\n"
            " address-family l2vpn evpn\n  advertise-all-vni%s\n"
            % (" l3vni-neigh" if enable else "")
        )

    def _synced(present):
        has = _host1_synced(leaf2) and _mac_static_pinned(leaf2, host1_mac, HOST_VID)
        if has == present:
            return None
        return "leaf2 host1 sync %s: %s" % (
            "missing" if present else "still present",
            leaf2.run("ip neigh show dev vlan%d" % HOST_VID),
        )

    def _l2vni_up():
        try:
            js = json.loads(leaf2.vtysh_cmd("show evpn vni %d json" % vni))
        except ValueError:
            return "bad json"
        return None if js.get("type") == "L2" else "L2VNI %d not up: %s" % (vni, js)

    config_add_l2vni(leaf2, LEAF_LO["leaf2"], vid, vni)
    try:
        _expect(_l2vni_up)
        _expect(lambda: _synced(True))

        _knob(False)
        _expect(lambda: _synced(False))
        _knob(True)
        _expect(lambda: _synced(True))

        leaf2.run("ip link set dev vni%d down" % L3VNI)
        _expect(lambda: _synced(False))
        leaf2.run("ip link set dev vni%d up" % L3VNI)
        _expect(lambda: _synced(True))
    finally:
        _knob(True)
        leaf2.run("ip link set dev vni%d up" % L3VNI)
        config_del_l2vni(leaf2, vni)


def test_pure_l3_sync_mac_mobility_reoriginates():
    """
    Host mobility -- same IP and VLAN, new MAC. host1's IP is relocated to a
    macvlan over bond0 with a new MAC, so the RT-2 NLRI key (MAC, IP, ETAG)
    changes only in MAC. leaf1 must withdraw the old-MAC RT-2 and originate the
    new-MAC RT-2; leaf2's synced neighbor lladdr and its static sync-MAC pin
    must move from the old MAC to the new MAC. A trailing withdraw of the old
    key must not evict the new synced state.
    """
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    leaf1 = tgen.gears["leaf1"]
    leaf2 = tgen.gears["leaf2"]
    host1 = tgen.gears["host1"]
    _ping(host1, ANYCAST_GW)

    def _expect(fn):
        _, result = topotest.run_and_expect(fn, None, count=WAIT_COUNT, wait=WAIT_STEP)
        assert result is None, result

    ip = HOST_IP["host1"]
    old_mac = _host_bond_mac(host1)
    new_mac = "02:00:00:00:0a:01"

    # Baseline: leaf1 originates the old-MAC RT-2; leaf2 syncs + pins old MAC.
    _expect(
        lambda: (
            None
            if _pure_l3_rt2_path(leaf1, 65011, mac=old_mac) is not None
            else "baseline old-MAC RT-2 missing"
        )
    )
    _expect(
        lambda: (
            None
            if _mac_static_pinned(leaf2, old_mac, HOST_VID)
            else "baseline old-MAC pin missing on leaf2"
        )
    )

    try:
        # Real MAC move for the same IP: relocate 45.0.0.101 onto a macvlan over
        # bond0 with new_mac so the host genuinely answers with the new lladdr
        # (a live adjacency, not a synthetic neighbor) without bouncing LACP. A
        # single ARP is used (not continuous traffic): the moved neighbor stays
        # advertised while STALE, and only leaf1 learns it locally so leaf2 is a
        # stable sync peer (continuous traffic can hash to leaf2 and flap it).
        host_move_ip_to_macvlan(host1, ip, new_mac)
        _ping(host1, ANYCAST_GW)

        # Old-key RT-2 withdrawn; new-key RT-2 originated (IP + ETAG + ESI).
        _expect(
            lambda: (
                None
                if _pure_l3_rt2_path(leaf1, 65011, mac=old_mac) is None
                else "old-MAC RT-2 not withdrawn after MAC move"
            )
        )

        def _new_rt2():
            path = _pure_l3_rt2_path(leaf1, 65011, mac=new_mac)
            if path is None:
                return "new-MAC RT-2 not originated after MAC move"
            if path.get("esi") != ES1_ID:
                return "new-MAC RT-2 esi %s, want %s" % (path.get("esi"), ES1_ID)
            return None

        _expect(_new_rt2)

        # leaf1 is the authoritative TX check (asserted above). On leaf2, local
        # learn wins over peer sync -- the dual-homed host can also land locally
        # on leaf2 -- so tolerate either ownership. Invariants that always hold
        # after the move: leaf2's BGP carries the new-key RT-2 from leaf1, no
        # stale old-MAC sync pin remains, and if leaf2 did not learn host1
        # locally its synced neighbor carries the new MAC.
        def _leaf2_reconverged():
            if _pure_l3_rt2_path(leaf2, 65011, mac=new_mac) is None:
                return "new-MAC RT-2 absent in leaf2 BGP"
            if _mac_static_pinned(leaf2, old_mac, HOST_VID):
                return "stale old-MAC sync pin remains on leaf2"
            if not _host1_local(leaf2) and (_host1_mac(leaf2) or "").lower() != new_mac:
                return "leaf2 not synced with new MAC: %s" % _host1_mac(leaf2)
            return None

        _expect(_leaf2_reconverged)

        # Stale-withdraw guard: after the move, the leaf1 new-key RT-2 and the
        # reconverged leaf2 state must not churn across a polled settle window
        # (a delayed old-key withdraw must not evict them).
        _assert_settled(
            lambda: _pure_l3_rt2_path(leaf1, 65011, mac=new_mac) is None
            or _leaf2_reconverged() is not None,
            "leaf1/leaf2 state churned after move",
        )
    finally:
        host_restore_ip_to_bond(host1, ip)
        _ping(host1, ANYCAST_GW)

    # Baseline restored: old-MAC RT-2 and pin return.
    _expect(
        lambda: (
            None
            if _pure_l3_rt2_path(leaf1, 65011, mac=old_mac) is not None
            else "old-MAC RT-2 did not return after restore"
        )
    )
    _expect(
        lambda: (
            None
            if _mac_static_pinned(leaf2, old_mac, HOST_VID)
            else "old-MAC pin did not return on leaf2"
        )
    )


def test_pure_l3_sync_etag_mobility_reoriginates():
    """
    Host mobility -- same IP and MAC, new VLAN (ETAG). host1's untagged access
    VLAN moves 100 -> 102 on the MH pair (carrying the anycast-GW subnet to the
    new SVI), so the RT-2 NLRI key (MAC, IP, ETAG) changes only in ETAG. leaf1
    withdraws the ETAG-100 RT-2 and originates the ETAG-102 RT-2; leaf2's synced
    neighbor moves from vlan100 to vlan102. A trailing DELNEIGH for the old SVI
    must not evict the moved route (zebra stale-DEL guard).
    """
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    leaf1 = tgen.gears["leaf1"]
    leaf2 = tgen.gears["leaf2"]
    host1 = tgen.gears["host1"]
    _ping(host1, ANYCAST_GW)

    def _expect(fn):
        _, result = topotest.run_and_expect(fn, None, count=WAIT_COUNT, wait=WAIT_STEP)
        assert result is None, result

    ip = HOST_IP["host1"]
    old_vid = HOST_VID  # 100
    new_vid = HOST_VID3  # 102 (spare BD, no host)
    all_vids = [HOST_VID, HOST_VID2, HOST_VID3]

    # Baseline: leaf1 originates the ETAG-100 RT-2; leaf2 synced only on vlan100.
    _expect(
        lambda: (
            None
            if _pure_l3_rt2_path(leaf1, 65011, eth_tag=old_vid) is not None
            else "baseline ETAG-100 RT-2 missing"
        )
    )
    _expect(lambda: _synced_neigh_on_vlan_only(leaf2, ip, old_vid, all_vids))

    try:
        # Move host1's access VLAN 100 -> 102 on both peers, carrying the GW
        # subnet so the same IP resolves under the new ETAG.
        for leaf in (leaf1, leaf2):
            leaf_move_host_bd(leaf, old_vid, new_vid)
        _ping(host1, ANYCAST_GW)

        # Old ETAG withdrawn; new ETAG originated (same IP + MAC + ESI).
        _expect(
            lambda: (
                None
                if _pure_l3_rt2_path(leaf1, 65011, eth_tag=old_vid) is None
                else "ETAG-100 RT-2 not withdrawn after VLAN move"
            )
        )

        def _new_etag():
            path = _pure_l3_rt2_path(leaf1, 65011, eth_tag=new_vid)
            if path is None:
                return "ETAG-102 RT-2 not originated after VLAN move"
            if path.get("esi") != ES1_ID:
                return "ETAG-102 RT-2 esi %s, want %s" % (path.get("esi"), ES1_ID)
            return None

        _expect(_new_etag)

        # leaf2's synced neighbor exists only on vlan102 (ETAG isolation): the
        # trailing old-SVI DELNEIGH must not evict it.
        _expect(lambda: _synced_neigh_on_vlan_only(leaf2, ip, new_vid, all_vids))
    finally:
        for leaf in (leaf1, leaf2):
            leaf_move_host_bd(leaf, new_vid, old_vid)
            leaf_trunk_extra_bd(leaf, new_vid)
        _ping(host1, ANYCAST_GW)

    # Baseline restored: ETAG-100 RT-2 and vlan100 sync return.
    _expect(
        lambda: (
            None
            if _pure_l3_rt2_path(leaf1, 65011, eth_tag=old_vid) is not None
            else "ETAG-100 RT-2 did not return after restore"
        )
    )
    _expect(lambda: _synced_neigh_on_vlan_only(leaf2, ip, old_vid, all_vids))


def test_pure_l3_local_on_es_peer_yields_to_etag_mobility():
    """
    leaf2 has a local ARP for host1 (same IP/MAC/ETAG as the peer's RT-2) when
    the host's access VLAN moves. leaf1 withdraws ETAG-100 and originates
    ETAG-102. A peer RT-2 whose (MAC, ETAG) key differs from the local copy
    must supersede it: skipping that ADD leaves zebra LOCAL with no kernel
    neighbor once the old SVI's DELNEIGH arrives (Debian 12 ARM CI).
    """
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    leaf1 = tgen.gears["leaf1"]
    leaf2 = tgen.gears["leaf2"]
    host1 = tgen.gears["host1"]
    _ping(host1, ANYCAST_GW)

    def _expect(fn):
        _, result = topotest.run_and_expect(fn, None, count=WAIT_COUNT, wait=WAIT_STEP)
        assert result is None, result

    ip = HOST_IP["host1"]
    host1_mac = _host_bond_mac(host1)
    old_vid = HOST_VID
    new_vid = HOST_VID3
    all_vids = [HOST_VID, HOST_VID2, HOST_VID3]
    svi100 = "vlan%d" % old_vid

    _expect(
        lambda: (
            None
            if _pure_l3_rt2_path(leaf1, 65011, eth_tag=old_vid) is not None
            else "baseline ETAG-100 RT-2 missing"
        )
    )
    _expect(lambda: _synced_neigh_on_vlan_only(leaf2, ip, old_vid, all_vids))

    try:
        # Local learn on leaf2 while still on ETAG 100. Do not move leaf2's
        # PVID: its local neigh must still be present when leaf1's ETAG-102
        # RT-2 arrives. Skipping that ADD is the CI failure. Keep VLAN 102
        # tagged on leaf2 so the access BD still exists for the remote install.
        leaf_trunk_extra_bd(leaf2, new_vid)
        leaf2.run(
            "ip neigh replace %s lladdr %s dev %s nud reachable"
            % (ip, host1_mac, svi100)
        )
        _expect(
            lambda: (
                None
                if _pure_l3_rt2_path(leaf2, 65012, eth_tag=old_vid) is not None
                else "leaf2 did not originate a local ETAG-100 RT-2"
            )
        )
        _expect(
            lambda: (
                None
                if _host1_local(leaf2, old_vid)
                else "leaf2 lost the local ETAG-100 neighbor before the move"
            )
        )

        leaf_move_host_bd(leaf1, old_vid, new_vid)
        _ping(host1, ANYCAST_GW)

        _expect(
            lambda: (
                None
                if _pure_l3_rt2_path(leaf1, 65011, eth_tag=new_vid) is not None
                else "ETAG-102 RT-2 not originated after leaf1 VLAN move"
            )
        )
        # leaf2 is still on VLAN 100 and still local. The peer's new-key ADD
        # must install ETAG 102; a skip leaves vlan102 empty.
        _expect(lambda: _synced_neigh_on_vlan_only(leaf2, ip, new_vid, all_vids))
    finally:
        leaf_move_host_bd(leaf1, new_vid, old_vid)
        leaf_trunk_extra_bd(leaf1, new_vid)
        if not _host1_synced(leaf2) and not _host1_local(leaf2):
            _l3mh_knob(leaf2, 65012, False)
            _l3mh_knob(leaf2, 65012, True)
        _ping(host1, ANYCAST_GW)

    _expect(
        lambda: (
            None
            if _pure_l3_rt2_path(leaf1, 65011, eth_tag=old_vid) is not None
            else "ETAG-100 RT-2 did not return after restore"
        )
    )
    _expect(lambda: _synced_neigh_on_vlan_only(leaf2, ip, old_vid, all_vids))


def test_pure_l3_sync_mac_and_etag_mobility_reoriginates():
    """
    Host mobility -- same IP, new MAC AND new VLAN together. host1's IP moves to
    a macvlan (new MAC) and its access VLAN moves 100 -> 102 on the MH pair, so
    both the MAC and the ETAG of the RT-2 NLRI change at once. leaf1 withdraws
    the (old MAC, ETAG 100) RT-2 and originates the (new MAC, ETAG 102) RT-2;
    leaf2's synced neighbor and sync-MAC pin move to vlan102 with the new MAC.
    The old vlan100 sync-MAC pin is NOT asserted gone: removing vlan100 from the
    ES bond can leave an orphaned static FDB entry the kernel keeps (same-VLAN
    pin move is covered by the MAC-mobility test). The reconverged state stays
    stable (the trailing old-key withdraws must not evict it).
    """
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    leaf1 = tgen.gears["leaf1"]
    leaf2 = tgen.gears["leaf2"]
    host1 = tgen.gears["host1"]
    _ping(host1, ANYCAST_GW)

    def _expect(fn):
        _, result = topotest.run_and_expect(fn, None, count=WAIT_COUNT, wait=WAIT_STEP)
        assert result is None, result

    ip = HOST_IP["host1"]
    old_mac = _host_bond_mac(host1)
    new_mac = "02:00:00:00:0b:02"
    old_vid = HOST_VID  # 100
    new_vid = HOST_VID3  # 102
    all_vids = [HOST_VID, HOST_VID2, HOST_VID3]

    # Baseline: leaf1 originates (old MAC, ETAG 100); leaf2 synced on vlan100.
    _expect(
        lambda: (
            None
            if _pure_l3_rt2_path(leaf1, 65011, mac=old_mac, eth_tag=old_vid) is not None
            else "baseline (old MAC, ETAG 100) RT-2 missing"
        )
    )
    _expect(lambda: _synced_neigh_on_vlan_only(leaf2, ip, old_vid, all_vids))

    try:
        # Change MAC (macvlan) and ETAG (access VLAN) together.
        host_move_ip_to_macvlan(host1, ip, new_mac)
        for leaf in (leaf1, leaf2):
            leaf_move_host_bd(leaf, old_vid, new_vid)
        _ping(host1, ANYCAST_GW)

        # Old (MAC, ETAG) key withdrawn; new (MAC, ETAG) key originated + ESI.
        _expect(
            lambda: (
                None
                if _pure_l3_rt2_path(leaf1, 65011, mac=old_mac, eth_tag=old_vid) is None
                else "old (MAC, ETAG) RT-2 not withdrawn after combined move"
            )
        )

        def _new_key():
            path = _pure_l3_rt2_path(leaf1, 65011, mac=new_mac, eth_tag=new_vid)
            if path is None:
                return "new (MAC, ETAG) RT-2 not originated after combined move"
            if path.get("esi") != ES1_ID:
                return "new RT-2 esi %s, want %s" % (path.get("esi"), ES1_ID)
            return None

        _expect(_new_key)

        # leaf2's synced neighbor + sync-MAC pin move to vlan102 with new MAC.
        # (The old pin's FDB entry on vlan100 is not asserted absent here: this
        # test removes vlan100 from the ES bond, so the kernel keeps that static
        # entry orphaned; same-VLAN pin move is covered by the MAC-mobility
        # test.) The trailing old-key DELs/withdraws must not evict new state.
        def _leaf2_moved():
            err = _synced_neigh_on_vlan_only(leaf2, ip, new_vid, all_vids)
            if err:
                return err
            if (_host1_mac(leaf2, new_vid) or "").lower() != new_mac:
                return "leaf2 lladdr not new MAC: %s" % _host1_mac(leaf2, new_vid)
            if not _mac_static_pinned(leaf2, new_mac, new_vid):
                return "new sync-MAC pin missing on leaf2 vlan102"
            return None

        _expect(_leaf2_moved)

        # Stale-withdraw guard: the reconverged state must not churn across a
        # polled settle window (a delayed old-key withdraw must not evict it).
        _assert_settled(
            lambda: _pure_l3_rt2_path(leaf1, 65011, mac=new_mac, eth_tag=new_vid)
            is None
            or _leaf2_moved() is not None,
            "leaf2 state churned after combined move",
        )
    finally:
        for leaf in (leaf1, leaf2):
            leaf_move_host_bd(leaf, new_vid, old_vid)
            leaf_trunk_extra_bd(leaf, new_vid)
        host_restore_ip_to_bond(host1, ip)
        _ping(host1, ANYCAST_GW)

    # Baseline restored.
    _expect(
        lambda: (
            None
            if _pure_l3_rt2_path(leaf1, 65011, mac=old_mac, eth_tag=old_vid) is not None
            else "baseline (old MAC, ETAG 100) RT-2 did not return"
        )
    )
    _expect(lambda: _synced_neigh_on_vlan_only(leaf2, ip, old_vid, all_vids))


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
                config_del_l2vni(leaf, L2VNI_100, unslave_first=True)

    # Sanity: pure-L3 ownership returns once the L2VNI is gone; the full
    # rebuild is asserted by test_l2vni_bd_loses_l2vni_returns_to_pure_l3.
    # The bridge reconfig can flush host1's ARP, so keep it active to re-learn.
    with _active_host(tgen.gears["host1"], ANYCAST_GW):
        _expect(
            lambda: (
                None
                if _pure_l3_rt2_path(leaf1, 65011) is not None
                else "pure-L3 RT-2 did not return after L2VNI removed"
            )
        )


def test_l2vni_bd_loses_l2vni_returns_to_pure_l3():
    """
    The reverse transition: when VLAN100 loses its L2VNI, ownership
    of host1's MAC-IP returns from the L2VNI EVI to the pure-L3 singleton.
    Delete the old (L2VNI) owner, then rebuild under the pure-L3 owner: the
    L2VNI MAC-IP RT-2 disappears, the pure-L3 RT-2 (vni=0/L3VNI, correct ESI)
    returns, and leaf2 rebuilds the synced extern_learn neighbor and its static
    sync-MAC FDB entry on vlan100.
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

    # Add the L2VNI with host1 active so its ARP survives the bridge reconfig
    # and hands off; the L2 owner then originates host1's MAC-IP.
    with _active_host(tgen.gears["host1"], ANYCAST_GW):
        for leaf, lo in ((leaf1, LEAF_LO["leaf1"]), (leaf2, LEAF_LO["leaf2"])):
            config_add_l2vni(leaf, lo, HOST_VID, L2VNI_100)
        _expect(
            lambda: (
                None
                if _l2vni_rt2_path(leaf1, L2VNI_100, 65011) is not None
                else "L2VNI MAC-IP RT-2 missing after the L2VNI was added"
            )
        )

    def _pure_l3_back():
        path = _pure_l3_rt2_path(leaf1, 65011)
        if path is None:
            return "pure-L3 RT-2 did not return after L2VNI removed"
        if path.get("esi") != ES1_ID:
            return "pure-L3 RT-2 esi is %s, want %s" % (path.get("esi"), ES1_ID)
        return None

    # Remove the L2VNI. The bridge reconfig can flush host1's ARP
    # before the discovery probe, so keep host1 active and let it be re-learned
    # via NEWNEIGH, re-originating pure-L3 (RT-2 0/L3VNI, correct ESI).
    with _active_host(tgen.gears["host1"], ANYCAST_GW):
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
        _expect(_pure_l3_back)
    # leaf2 rebuilds the synced neighbor and its static sync-MAC FDB entry.
    _expect(
        lambda: (None if _host1_synced(leaf2) else "leaf2 synced neighbor not rebuilt")
    )
    _expect(
        lambda: (
            None
            if _mac_static_pinned(leaf2, host1_mac, HOST_VID)
            else "leaf2 static sync-MAC FDB entry not rebuilt after the L2VNI was "
            "removed"
        )
    )


def test_l2vni_loss_handoffs_local_neigh_without_relearn():
    """
    L2VNI removal must re-originate host1's pure-L3 RT-2 from the L2 neighbor
    table. It must not depend on a kernel neighbor probe: NUD_INCOMPLETE drops
    the MAC, and with no ARP reply (host ARP disabled here; LACP-hash on a live
    host) the originator never re-learns. That is the netdef failure of
    test_l2vni_bd_loses_l2vni_returns_to_pure_l3.

    Do not use run_and_expect() for the post-delete check: its floor is 15s,
    which is long enough for a probe or bridge reconfig to invent a NEWNEIGH.
    """
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    leaf1 = tgen.gears["leaf1"]
    leaf2 = tgen.gears["leaf2"]
    host1 = tgen.gears["host1"]
    _ping(host1, ANYCAST_GW)

    def _expect(fn):
        _, result = topotest.run_and_expect(fn, None, count=WAIT_COUNT, wait=WAIT_STEP)
        assert result is None, result

    l2vni_on = False
    arp_off = False
    with _active_host(host1, ANYCAST_GW):
        for leaf, lo in ((leaf1, LEAF_LO["leaf1"]), (leaf2, LEAF_LO["leaf2"])):
            config_add_l2vni(leaf, lo, HOST_VID, L2VNI_100)
        l2vni_on = True
        _expect(
            lambda: (
                None
                if _l2vni_rt2_path(leaf1, L2VNI_100, 65011) is not None
                else "L2VNI MAC-IP RT-2 missing after the L2VNI was added"
            )
        )
        # The leftover pure-L3 RT-2 from before the L2VNI was added must be
        # gone; otherwise the post-delete check would pass without a handoff.
        _expect(
            lambda: (
                None
                if _pure_l3_rt2_path(leaf1, 65011) is None
                else "pure-L3 RT-2 still present after L2VNI added"
            )
        )

    # Host stays on the ES but will not answer ARP, so a kernel probe cannot
    # re-learn it. The handoff must originate from zebra's L2 neighbor table.
    try:
        host1.run("ip link set dev bond0 arp off")
        host1.run("sysctl -w net.ipv4.conf.bond0.arp_ignore=8")
        host1.run("sysctl -w net.ipv4.conf.all.arp_ignore=8")
        arp_off = True
        for leaf in (leaf1, leaf2):
            config_del_l2vni(leaf, L2VNI_100)
        l2vni_on = False

        # Drain zebra/bgpd queues from the VXLAN delete, then one observation:
        # the RT-2 must already be there from the in-memory handoff.
        _settle()
        path = _pure_l3_rt2_path(leaf1, 65011)
        neigh = leaf1.run("ip neigh show %s dev vlan%d" % (HOST_IP["host1"], HOST_VID))
        assert path is not None, (
            "pure-L3 RT-2 did not return from L2VNI handoff without host ARP "
            "(leaf1 neigh %s)" % neigh.strip()
        )
        assert path.get("esi") == ES1_ID, "pure-L3 RT-2 esi is %s, want %s" % (
            path.get("esi"),
            ES1_ID,
        )
    finally:
        if arp_off:
            host1.run("sysctl -w net.ipv4.conf.bond0.arp_ignore=0")
            host1.run("sysctl -w net.ipv4.conf.all.arp_ignore=0")
            host1.run("ip link set dev bond0 arp on")
        if l2vni_on:
            for leaf in (leaf1, leaf2):
                config_del_l2vni(leaf, L2VNI_100)
        _ping(host1, ANYCAST_GW)


def test_pure_l3_rolling_l2vni_holds_peer_sync():
    """
    Rolling L2VNI add: only leaf2 gains the L2VNI on VLAN100, so leaf1 keeps
    advertising host1's pure-L3 RT-2. A re-sent ADD (here from a hard EVPN
    clear on leaf2) must not install a pure-L3 neighbor on the L2VNI-owned
    VLAN. leaf2 holds it instead, and re-installs the synced neighbor and its
    static sync-MAC FDB entry when the L2VNI is removed again.
    """
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    leaf2 = tgen.gears["leaf2"]
    _ping(tgen.gears["host1"], ANYCAST_GW)
    host1_mac = _host_bond_mac(tgen.gears["host1"])

    def _expect(fn, msg):
        _, result = topotest.run_and_expect(
            lambda: None if fn() else msg, None, count=WAIT_COUNT, wait=WAIT_STEP
        )
        assert result is None, result

    _expect(
        lambda: _host1_synced(leaf2) and _mac_static_pinned(leaf2, host1_mac, HOST_VID),
        "host1 not synced on leaf2 at baseline",
    )

    l2vni_on = True
    config_add_l2vni(leaf2, LEAF_LO["leaf2"], HOST_VID, L2VNI_100)
    try:
        _expect(lambda: _l2vni_present(leaf2), "L2VNI not live on leaf2")
        _expect(
            lambda: not _host1_synced(leaf2),
            "leaf2 kept host1's pure-L3 neighbor after gaining the L2VNI",
        )

        leaf2.vtysh_cmd("clear bgp l2vpn evpn *")
        _expect(
            lambda: _pure_l3_rt2_path(leaf2, 65011) is not None,
            "leaf1's pure-L3 RT-2 not re-learned on leaf2",
        )
        _assert_settled(
            lambda: _host1_synced(leaf2),
            lambda: "pure-L3 neighbor installed on leaf2's L2VNI-owned VLAN: %s"
            % leaf2.run("ip neigh show dev vlan%d" % HOST_VID),
        )

        config_del_l2vni(leaf2, L2VNI_100)
        l2vni_on = False
        _expect(
            lambda: _host1_synced(leaf2)
            and _mac_static_pinned(leaf2, host1_mac, HOST_VID),
            "leaf2 did not re-install host1 after losing the L2VNI: %s"
            % leaf2.run("ip neigh show dev vlan%d" % HOST_VID),
        )
    finally:
        if l2vni_on:
            config_del_l2vni(leaf2, L2VNI_100)

    _ping(tgen.gears["host1"], ANYCAST_GW)
    _expect(lambda: _host1_synced(leaf2), "host1 not re-synced on leaf2")


def test_l2vni_low_vni_rt2_not_pure_l3():
    """
    A symmetric-IRB RT-2 of an L2VNI numbered 1-15 carries that VNI in label-1
    and the L3VNI in label-2. Only the full 24-bit label-1 tells it apart from
    a pure-L3 RT-2 (label-1 = Explicit NULL), so leaf2 must not take it as an
    L3 neighbor sync.
    """
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    leaf1 = tgen.gears["leaf1"]
    leaf2 = tgen.gears["leaf2"]
    vni = 5
    ip = HOST_IP["host1"]

    def _expect(step, fn):
        _, result = topotest.run_and_expect(fn, None, count=WAIT_COUNT, wait=WAIT_STEP)
        assert result is None, "%s: %s" % (step, result)

    def _l3_sync_type():
        out = leaf2.vtysh_cmd("show evpn arp-cache vni %d ip %s json" % (L3VNI, ip))
        try:
            return json.loads(out).get("type")
        except Exception:  # pragma: no cover - defensive
            return None

    with _active_host(tgen.gears["host1"], ANYCAST_GW):
        for leaf, lo in ((leaf1, LEAF_LO["leaf1"]), (leaf2, LEAF_LO["leaf2"])):
            config_add_l2vni(leaf, lo, HOST_VID, vni)
        try:
            _expect(
                "L2VNI RT-2 on leaf2",
                lambda: (
                    None
                    if _l2vni_rt2_path(leaf2, vni, 65011) is not None
                    else "leaf1's VNI %d RT-2 for %s not on leaf2" % (vni, ip)
                ),
            )
            _expect(
                "no L3 sync",
                lambda: (
                    None
                    if _l3_sync_type() != "remote"
                    else "leaf2 holds %s as an L3VNI %d sync" % (ip, L3VNI)
                ),
            )
            _assert_settled(
                lambda: _l3_sync_type() == "remote",
                "leaf2 took the VNI %d RT-2 for %s as an L3 neighbor sync" % (vni, ip),
            )
        finally:
            for leaf in (leaf1, leaf2):
                config_del_l2vni(leaf, vni)

        _expect(
            "pure-L3 back",
            lambda: (
                None
                if _pure_l3_rt2_path(leaf1, 65011) is not None and _host1_synced(leaf2)
                else "host1's pure-L3 RT-2 and sync not restored"
            ),
        )


def test_pure_l3_rt2_not_replayed_into_l2vni_with_same_rt():
    """
    An L2VNI may import the IP-VRF's RT (e.g. one RT per tenant). When it comes
    up, its import replay must skip pure-L3 RT-2s exactly like the normal
    import does: host1's RT-2 (RT 65011:L3VNI) must not land in leaf2's L2VNI
    table or as a remote MAC in zebra.
    """
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    leaf1 = tgen.gears["leaf1"]
    leaf2 = tgen.gears["leaf2"]
    vni = 7
    ip = HOST_IP["host1"]
    host1_mac = _host_bond_mac(tgen.gears["host1"])

    def _evpn_cfg(cmds):
        leaf2.vtysh_cmd(
            "configure terminal\nrouter bgp 65012\n address-family l2vpn evpn\n" + cmds
        )

    def _in_l2vni():
        rt = leaf2.vtysh_cmd("show bgp l2vpn evpn route vni %d type macip" % vni)
        if ip in rt:
            return "host1's pure-L3 RT-2 in leaf2's VNI %d table:\n%s" % (vni, rt)
        macs = leaf2.vtysh_cmd("show evpn mac vni %d" % vni)
        if host1_mac.lower() in macs.lower():
            return "host1's MAC in leaf2's zebra VNI %d:\n%s" % (vni, macs)
        return None

    def _vni_up():
        out = leaf2.vtysh_cmd("show bgp l2vpn evpn vni %d json" % vni)
        try:
            return json.loads(out).get("inKernel") == "True"
        except Exception:  # pragma: no cover - defensive
            return False

    with _active_host(tgen.gears["host1"], ANYCAST_GW):
        _, result = topotest.run_and_expect(
            lambda: _pure_l3_rt2_path(leaf1, 65011) is not None
            and _host1_synced(leaf2),
            True,
            count=WAIT_COUNT,
            wait=WAIT_STEP,
        )
        assert result, "host1's pure-L3 RT-2 and sync not present"

        _evpn_cfg("  vni %d\n   route-target import 65011:%d\n" % (vni, L3VNI))
        config_add_l2vni(leaf2, LEAF_LO["leaf2"], HOST_VID2, vni)
        try:
            _, result = topotest.run_and_expect(
                _vni_up, True, count=WAIT_COUNT, wait=WAIT_STEP
            )
            assert result, "leaf2 VNI %d not up" % vni
            _assert_settled(lambda: _in_l2vni() is not None, _in_l2vni)
            assert _host1_synced(leaf2), "host1 sync lost on leaf2"
        finally:
            config_del_l2vni(leaf2, vni)
            _evpn_cfg("  no vni %d\n" % vni)


@contextlib.contextmanager
def _raw_evpn_peer(leaf2, leaf3, mac, ip):
    """Run evpn_rawpeer.py on leaf3's loopback as an eBGP EVPN peer of leaf2
    advertising ES1 pure-L3 RT-2s; yields a function sending one command."""
    peer_ip, peer_as = LEAF_LO["leaf3"], 65099

    def _established():
        out = leaf2.vtysh_cmd("show bgp neighbor %s json" % peer_ip)
        state = json.loads(out).get(peer_ip, {}).get("bgpState")
        return None if state == "Established" else "raw peer %s" % state

    leaf2.vtysh_cmd(
        "configure terminal\n"
        "router bgp 65012\n"
        " neighbor %s remote-as %d\n"
        " neighbor %s passive\n"
        " neighbor %s ebgp-multihop 5\n"
        " address-family l2vpn evpn\n"
        "  neighbor %s activate\n" % (peer_ip, peer_as, peer_ip, peer_ip, peer_ip)
    )
    logfile = os.path.join(leaf3.logdir, "leaf3", "evpn_rawpeer.log")
    speaker = leaf3.popen(
        [
            "python3",
            os.path.join(CWD, "evpn_rawpeer.py"),
            peer_ip,
            str(peer_as),
            LEAF_LO["leaf2"],
            ES1_ID,
            str(HOST_VID),
            mac,
            ip,
            str(L3VNI),
        ],
        stdin=subprocess.PIPE,
        stdout=open(logfile, "a"),
        stderr=subprocess.STDOUT,
        text=True,
    )

    def _send(cmd):
        speaker.stdin.write(cmd + "\n")
        speaker.stdin.flush()

    try:
        _, result = topotest.run_and_expect(
            _established, None, count=WAIT_COUNT, wait=WAIT_STEP
        )
        assert result is None, result
        yield _send
    finally:
        speaker.stdin.close()
        speaker.terminate()
        speaker.wait()
        leaf2.vtysh_cmd(
            "configure terminal\nrouter bgp 65012\n no neighbor %s\n" % peer_ip
        )


def test_pure_l3_label_only_update_reimports():
    """
    A peer re-sends a pure-L3 RT-2 with the same attributes and only its labels
    changed. leaf2 must re-evaluate the route: label-2 naming another L3VNI, or
    label-1 leaving Explicit NULL, removes the synced neighbor; changing back to
    0/L3VNI installs it again. An update that drops every extended community
    (so no RT) must remove it too. A raw speaker on leaf3's loopback sends the
    updates, since a FRR originator withdraws before re-announcing.
    """
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    leaf2 = tgen.gears["leaf2"]
    leaf3 = tgen.gears["leaf3"]
    mac, ip = "00:00:5e:00:53:e8", "45.0.0.195"

    def _expect(step, synced):
        _, result = topotest.run_and_expect(
            lambda: (
                None
                if _neigh_synced(leaf2, ip) == synced
                else "%s synced on leaf2: %s" % (ip, not synced)
            ),
            None,
            count=WAIT_COUNT,
            wait=WAIT_STEP,
        )
        assert result is None, "%s: %s" % (step, result)

    with _raw_evpn_peer(leaf2, leaf3, mac, ip) as _send:
        try:
            _send("announce 0 %d" % L3VNI)
            _expect("0/L3VNI", True)

            _send("announce 0 %d" % (L3VNI + 1))
            _expect("label-2 another L3VNI", False)

            _send("announce 0 %d" % L3VNI)
            _expect("0/L3VNI again", True)

            _send("announce-nort 0 %d" % L3VNI)
            _expect("no extended communities", False)

            _send("announce 0 %d" % L3VNI)
            _expect("RT back", True)

            _send("announce %d %d" % (HOST_VID, L3VNI))
            _expect("label-1 not Explicit NULL", False)
        finally:
            _send("withdraw")
    _expect("cleanup", False)


def test_pure_l3_stale_key_withdraw_keeps_newer_key():
    """
    A host's IP moves to a new MAC while the old (MAC, IP, ETAG) route is still
    backed by two paths (e.g. one per spine). Withdrawing the first old path
    must not re-send the old key to zebra: the surviving path has the same ESI
    and router flag, and the re-send would replace the newer key on leaf2 so
    that the second withdraw then deletes the neighbor for good.
    """
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    leaf2 = tgen.gears["leaf2"]
    leaf3 = tgen.gears["leaf3"]
    ip, old_mac, new_mac = "45.0.0.196", "00:00:5e:00:53:e9", "00:00:5e:00:53:ea"
    marker = "45.0.0.197"
    labels = "0 %d" % L3VNI

    def _lladdr(addr):
        for line in leaf2.run("ip neigh show dev vlan%d" % HOST_VID).splitlines():
            words = line.split()
            if words[:1] == [addr] and "extern_learn" in words and "lladdr" in words:
                return words[words.index("lladdr") + 1]
        return None

    def _expect(step, addr, want):
        _, result = topotest.run_and_expect(
            lambda: (
                None
                if _lladdr(addr) == want
                else "%s on leaf2: %s, want %s" % (addr, _lladdr(addr), want)
            ),
            None,
            count=WAIT_COUNT,
            wait=WAIT_STEP,
        )
        assert result is None, "%s: %s" % (step, result)

    with _raw_evpn_peer(leaf2, leaf3, old_mac, ip) as _send:
        try:
            _send("announce %s rd=5" % labels)
            _send("announce %s rd=6" % labels)
            _expect("old key on two RDs", ip, old_mac)

            _send("announce %s rd=7 mac=%s" % (labels, new_mac))
            _expect("newer key", ip, new_mac)

            _send("withdraw rd=5")
            _send("withdraw rd=6")
            # Sent after the withdraws: once it is installed they were processed.
            _send("announce %s rd=8 ip=%s" % (labels, marker))
            _expect("barrier", marker, old_mac)
            assert _lladdr(ip) == new_mac, "%s on leaf2 after old-key withdraws: %s" % (
                ip,
                _lladdr(ip),
            )
        finally:
            for rd in (5, 6):
                _send("withdraw rd=%d" % rd)
            _send("withdraw rd=7 mac=%s" % new_mac)
            _send("withdraw rd=8 ip=%s" % marker)
            _expect("cleanup", marker, None)
    _expect("cleanup", ip, None)


def _local_rt2_version(dut, ip=None):
    """Table version of dut's own pure-L3 RT-2 for ip on HOST_VID, or None."""
    ip = ip or HOST_IP["host1"]
    out = dut.vtysh_cmd("show bgp l2vpn evpn route detail type macip json")
    for rd, rdval in json.loads(out).items():
        if not rd.startswith(LEAF_LO[dut.name] + ":") or not isinstance(rdval, dict):
            continue
        for entry in rdval.values():
            if not isinstance(entry, dict) or entry.get("ip") != ip:
                continue
            if entry.get("ethTag") != HOST_VID:
                continue
            for pathset in entry.get("paths", []):
                for path in pathset:
                    if path.get("vni") == "0/%d" % L3VNI:
                        return path.get("version")
    return None


def test_pure_l3_unchanged_readvertise_not_resent():
    """
    A port joining host1's BD makes zebra re-advertise host1's pure-L3
    neighbor with the same ESI and flags. bgpd must see the local RT-2 as
    unchanged and not refresh it, which would send a new UPDATE to every peer.
    """
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    leaf1 = tgen.gears["leaf1"]

    with _active_host(tgen.gears["host1"], ANYCAST_GW):
        _, found = topotest.run_and_expect(
            lambda: _local_rt2_version(leaf1) is not None,
            True,
            count=WAIT_COUNT,
            wait=WAIT_STEP,
        )
        assert found, "leaf1 has no pure-L3 RT-2 for host1"
        _settle()
        before = _local_rt2_version(leaf1)

        _es2_bond_add(leaf1)
        try:
            _assert_settled(
                lambda: _local_rt2_version(leaf1) != before,
                lambda: "leaf1 refreshed host1's unchanged RT-2: version %s -> %s"
                % (before, _local_rt2_version(leaf1)),
            )
        finally:
            _es2_bond_del(leaf1)


def test_pure_l3_bridge_mac_change_resyncs():
    """
    A bridge MAC change makes zebra bounce the L3VNI (oper-down then oper-up):
    pure-L3 neighbors are flushed, then replayed and re-imported. Bounce leaf1
    (originator), then leaf2 (ES peer), changing the MAC and changing it back:
    after each change host1's RT-2 must be back on leaf1 and leaf2 must hold
    the synced neighbor and its static sync-MAC FDB entry, and stay so. The
    SVIs have their own MAC, so this is one bounce with an unchanged router MAC.
    Then change leaf1's router MAC (its L3VNI SVI MAC): host1's RT-2 must be
    re-originated carrying the new Rmac, with leaf2 still synced.
    """
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    leaf1 = tgen.gears["leaf1"]
    leaf2 = tgen.gears["leaf2"]
    host1_mac = _host_bond_mac(tgen.gears["host1"])

    def _synced():
        if _pure_l3_rt2_path(leaf1, 65011) is None:
            return "leaf1 has no pure-L3 RT-2 for host1"
        if not _host1_synced(leaf2):
            return "host1 not synced on leaf2"
        if not _mac_static_pinned(leaf2, host1_mac, HOST_VID):
            return "leaf2 static sync-MAC for host1 missing on hostbond1"
        return None

    def _set_mac(dut, alt):
        dut.run(
            "ip link set dev br_default address %s"
            % _bridge_mac(LEAF_LO[dut.name], alt)
        )

    with _active_host(tgen.gears["host1"], ANYCAST_GW):
        _, result = topotest.run_and_expect(
            _synced, None, count=WAIT_COUNT, wait=WAIT_STEP
        )
        assert result is None, "before bridge MAC changes: %s" % result
        for dut in (leaf1, leaf2):
            try:
                for alt in (True, False):
                    step = "%s bridge MAC %s" % (dut.name, "changed" if alt else "back")
                    _set_mac(dut, alt)
                    # The MAC change is queued ahead of the barrier, so the
                    # L3VNI bounce has been fully processed once it settles.
                    _assert_settled(
                        lambda: _synced() is not None,
                        lambda s=step: "%s: %s" % (s, _synced()),
                    )
            finally:
                _set_mac(dut, False)

        def _rmac_is(mac):
            path = _pure_l3_rt2_path(leaf1, 65011)
            ec = path.get("extendedCommunity", {}).get("string", "") if path else ""
            if "Rmac:%s" % mac not in ec:
                return "leaf1 RT-2 for host1 lacks Rmac %s: %s" % (mac, ec)
            return _synced()

        lo1 = LEAF_LO["leaf1"]
        try:
            for mac in (_bridge_mac(lo1, 2), _bridge_mac(lo1)):
                leaf1.run("ip link set dev vlan%d address %s" % (L3VNI, mac))
                _assert_settled(
                    lambda m=mac: _rmac_is(m) is not None,
                    lambda m=mac: "leaf1 router MAC %s: %s" % (m, _rmac_is(m)),
                )
        finally:
            leaf1.run("ip link set dev vlan%d address %s" % (L3VNI, _bridge_mac(lo1)))


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
    def _sync_neigh_present(dut):
        for line in dut.run("ip neigh show").splitlines():
            if HOST_IP["host1"] in line and "extern_learn" in line:
                return True
        return False

    _assert_settled(
        partial(_sync_neigh_present, dut),
        "leaf3 (non-peer) installed a synced neighbor for host1",
    )


def test_pure_l3_rt2_not_imported_into_vrf_on_l3vni_flap():
    """
    A pure-L3 RT-2 never becomes a VRF host route, including through the VRF
    walk that runs when an L3VNI comes up. On leaf3 (not an ES peer, so the
    local-ES import skip does not apply) bounce the L3VNI and check host1's
    /32 does not appear in the BGP VRF table.
    """
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    leaf3 = tgen.gears["leaf3"]
    _ping(tgen.gears["host1"], ANYCAST_GW)
    host1_pfx = "%s/32" % HOST_IP["host1"]
    host1_net = "45.0.0.0/24"

    def _expect(fn):
        _, result = topotest.run_and_expect(fn, None, count=WAIT_COUNT, wait=WAIT_STEP)
        assert result is None, result

    def _vrf_host_route_present():
        out = leaf3.vtysh_cmd("show bgp vrf %s ipv4 unicast %s json" % (VRF, host1_pfx))
        try:
            return bool(json.loads(out).get("paths"))
        except ValueError:
            return False

    def _type5_installed():
        out = leaf3.vtysh_cmd("show ip route vrf %s %s json" % (VRF, host1_net))
        try:
            entry = json.loads(out).get(host1_net)
        except ValueError:
            return "invalid json: %s" % out
        if not entry or entry[0].get("protocol") != "bgp":
            return "leaf3 has no type-5 route to %s" % host1_net
        return None

    _expect(
        lambda: (
            None
            if _pure_l3_rt2_path(leaf3, 65011) is not None
            else "leaf3 has no pure-L3 RT-2 for host1"
        )
    )
    _assert_settled(_vrf_host_route_present, "host1 /32 in leaf3 VRF before flap")

    try:
        leaf3.run("ip link set dev vni%d down" % L3VNI)
        _expect(
            lambda: (
                "leaf3 type-5 route still present"
                if _type5_installed() is None
                else None
            )
        )
    finally:
        leaf3.run("ip link set dev vni%d up" % L3VNI)
    _expect(_type5_installed)

    _assert_settled(
        _vrf_host_route_present,
        "leaf3 imported host1's pure-L3 RT-2 as a VRF host route",
    )


def test_pure_l3_nd_sync_smoke():
    """
    IPv6 ND sync smoke test. VLAN 100 is dual-stacked with an IPv6 anycast
    gateway, so host1 also has an IPv6 address on its bond. Repeated ping6
    during polling drives ND learning on leaf1, whose entry must originate as a
    pure-L3 RT-2 with the same family-agnostic marker (vni 0/L3VNI, ETAG = VLAN,
    local ESI), and leaf2 (the ES peer) must install it as an extern_learn
    neighbor on vlan100. Light coverage only -- the full IPv6 delete/aging/mixed
    matrix is a separate PR.
    """
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    leaf1 = tgen.gears["leaf1"]
    leaf2 = tgen.gears["leaf2"]
    host1 = tgen.gears["host1"]
    ip6 = HOST_IP6["host1"]

    def _expect(fn):
        _, result = topotest.run_and_expect(fn, None, count=WAIT_COUNT, wait=WAIT_STEP)
        assert result is None, result

    # leaf1 originates the IPv6 pure-L3 RT-2 (0/L3VNI marker, ETAG 100, ES1).
    # Re-trigger ND each poll: v6 origination is event-driven (NEWNEIGH), and a
    # single initial ping can resolve the neighbor as STALE without originating.
    def _v6_rt2():
        host1.run("ping -6 -c 1 -W 1 %s" % ANYCAST_GW6)
        path = _pure_l3_rt2_path(leaf1, 65011, ip=ip6)
        if path is None:
            return "no IPv6 pure-L3 RT-2 for %s" % ip6
        if path.get("esi") != ES1_ID:
            return "IPv6 pure-L3 RT-2 esi %s, want %s" % (path.get("esi"), ES1_ID)
        return None

    _expect(_v6_rt2)

    # leaf2 installs host1's IPv6 as an extern_learn (synced) neighbor on vlan100.
    def _v6_synced(dut):
        out = dut.run("ip -6 neigh show dev vlan%d" % HOST_VID)
        if ip6 in out and "extern_learn" in out:
            return None
        return "host1 IPv6 not synced on leaf2: %s" % out

    _expect(lambda: _v6_synced(leaf2))


def test_pure_l3_ipv6_router_flag_synced():
    """
    An IPv6 router neighbor's R-bit rides the pure-L3 RT-2 as the ND extended
    community, and the ES peer installs the synced neighbor as a router. Clearing
    the R-bit locally clears it on the route and on the peer.
    """
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    leaf1 = tgen.gears["leaf1"]
    leaf2 = tgen.gears["leaf2"]
    mac, ip6 = "00:00:5e:00:53:f1", "fd00:45::1f1"

    def _expect(fn):
        _, result = topotest.run_and_expect(fn, None, count=WAIT_COUNT, wait=WAIT_STEP)
        assert result is None, result

    def _neigh_add(router):
        leaf1.run(
            "ip -6 neigh replace %s lladdr %s dev vlan%d nud stale%s"
            % (ip6, mac, HOST_VID, " router" if router else "")
        )

    def _check(router):
        path = _pure_l3_rt2_path(leaf1, 65011, ip=ip6)
        if path is None:
            return "leaf1 has no pure-L3 RT-2 for %s" % ip6
        ec = path.get("extendedCommunity", {}).get("string", "")
        if ("ND:Router Flag" in ec) != router:
            return "leaf1 RT-2 %s extcomm %r, want router=%s" % (ip6, ec, router)
        for line in leaf2.run("ip -6 neigh show dev vlan%d" % HOST_VID).splitlines():
            words = line.split()
            if words[:1] == [ip6] and "extern_learn" in words:
                if ("router" in words) != router:
                    return "leaf2 synced %s: %r, want router=%s" % (ip6, line, router)
                return None
        return "%s not synced on leaf2" % ip6

    leaf1.run(
        "/sbin/bridge fdb add %s dev hostbond1 master vlan %d dynamic" % (mac, HOST_VID)
    )
    try:
        _neigh_add(True)
        _expect(lambda: _check(True))
        _neigh_add(False)
        _expect(lambda: _check(False))
    finally:
        leaf1.run("ip -6 neigh del %s dev vlan%d 2>/dev/null" % (ip6, HOST_VID))
        leaf1.run(
            "/sbin/bridge fdb del %s dev hostbond1 master vlan %d 2>/dev/null"
            % (mac, HOST_VID)
        )


def _es2_bond_add(dut):
    """A second ES bond (es-id 2) on VLAN 100, kept up by a veth member."""
    dut.run("ip link add l3mhes2 type bond mode active-backup")
    dut.run("ip link add l3mhv0 type veth peer name l3mhv1")
    dut.run("ip link set dev l3mhv0 master l3mhes2")
    dut.run("ip link set dev l3mhv1 up")
    dut.run("ip link set dev l3mhes2 master br_default")
    dut.run("/sbin/bridge vlan del vid 1 dev l3mhes2")
    dut.run("/sbin/bridge vlan add vid %d dev l3mhes2 pvid untagged" % HOST_VID)
    dut.run("ip link set dev l3mhes2 up")
    dut.vtysh_cmd(
        "configure terminal\n"
        "interface l3mhes2\n"
        " evpn mh es-id 2\n"
        " evpn mh es-sys-mac %s\n" % ES_SYS_MAC
    )


def _es2_bond_del(dut):
    dut.vtysh_cmd(
        "configure terminal\n"
        "interface l3mhes2\n"
        " no evpn mh es-id 2\n"
        " no evpn mh es-sys-mac %s\n" % ES_SYS_MAC
    )
    dut.run("ip link del l3mhes2")
    dut.run("ip link del l3mhv0")


def _leaf3_es2_add(leaf3):
    """leaf3: VLAN 100 SVI in vrf1, an ES2 bond on it, and l3vni-neigh."""
    leaf3.run("/sbin/bridge vlan add vid %d dev br_default self" % HOST_VID)
    leaf3.run(
        "ip link add link br_default name vlan%d type vlan id %d" % (HOST_VID, HOST_VID)
    )
    leaf3.run("ip link set dev vlan%d master %s" % (HOST_VID, VRF))
    leaf3.run("ip link set dev vlan%d up" % HOST_VID)
    _es2_bond_add(leaf3)
    _l3mh_knob(leaf3, 65013, True)


def _leaf3_es2_del(leaf3):
    _l3mh_knob(leaf3, 65013, False)
    _es2_bond_del(leaf3)
    leaf3.run("ip link del vlan%d" % HOST_VID)
    leaf3.run("/sbin/bridge vlan del vid %d dev br_default self" % HOST_VID)


def test_pure_l3_sync_falls_back_to_surviving_route():
    """
    leaf1 (ES1, router) and leaf3 (ES2, not a router) advertise the same host;
    leaf2 has both ESes. The last ADD wins, so leaf2 follows leaf3. When leaf3
    withdraws, leaf2 must switch to leaf1's route: static sync-MAC FDB entry back
    on hostbond1 and the neighbor flagged as a router again.
    """
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    leaf1 = tgen.gears["leaf1"]
    leaf2 = tgen.gears["leaf2"]
    leaf3 = tgen.gears["leaf3"]
    mac, ip6 = "00:00:5e:00:53:e2", "fd00:45::1e2"

    def _expect(step, fn):
        _, result = topotest.run_and_expect(fn, None, count=WAIT_COUNT, wait=WAIT_STEP)
        assert result is None, "%s: %s" % (step, result)

    def _neigh_add(dut, dev, router):
        dut.run(
            "/sbin/bridge fdb replace %s dev %s master vlan %d dynamic"
            % (mac, dev, HOST_VID)
        )
        dut.run(
            "ip -6 neigh replace %s lladdr %s dev vlan%d nud stale%s"
            % (ip6, mac, HOST_VID, " router" if router else "")
        )

    def _neigh_del(dut, dev):
        dut.run("ip -6 neigh del %s dev vlan%d 2>/dev/null" % (ip6, HOST_VID))
        dut.run(
            "/sbin/bridge fdb del %s dev %s master vlan %d 2>/dev/null"
            % (mac, dev, HOST_VID)
        )

    def _leaf2_follows(dev, router):
        if not _mac_static_pinned(leaf2, mac, HOST_VID, dev=dev):
            return "leaf2 static sync-MAC for %s not on %s" % (mac, dev)
        for line in leaf2.run("ip -6 neigh show dev vlan%d" % HOST_VID).splitlines():
            words = line.split()
            if words[:1] == [ip6] and "extern_learn" in words:
                if ("router" in words) != router:
                    return "leaf2 synced %s: %r, want router=%s" % (ip6, line, router)
                return None
        return "%s not synced on leaf2" % ip6

    _leaf3_es2_add(leaf3)
    _es2_bond_add(leaf2)
    try:
        _neigh_add(leaf1, "hostbond1", True)
        _expect("leaf1 only", lambda: _leaf2_follows("hostbond1", True))

        _neigh_add(leaf3, "l3mhes2", False)
        _expect("leaf3 added", lambda: _leaf2_follows("l3mhes2", False))

        _neigh_del(leaf3, "l3mhes2")
        _expect("leaf3 withdrawn", lambda: _leaf2_follows("hostbond1", True))
    finally:
        _neigh_del(leaf1, "hostbond1")
        _neigh_del(leaf3, "l3mhes2")
        _es2_bond_del(leaf2)
        _leaf3_es2_del(leaf3)


def test_pure_l3_shared_sync_mac_survives_other_address_move():
    """
    A host's IPv4 (from leaf1, ES1) and IPv6 (from leaf3, ES2) share one MAC, so
    leaf2 (which has both ESes) keeps a single static sync-MAC FDB entry for
    them; the last ADD moves it to l3mhes2. When the IPv6 route is withdrawn,
    or leaf2 learns the IPv6 address locally, the IPv4 neighbor still synced
    on leaf2 must get its static entry back on hostbond1 instead of being left
    with none or with a dynamic one.
    """
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    leaf1 = tgen.gears["leaf1"]
    leaf2 = tgen.gears["leaf2"]
    leaf3 = tgen.gears["leaf3"]
    mac, ip4, ip6 = "00:00:5e:00:53:e7", "45.0.0.194", "fd00:45::1e7"

    def _expect(step, fn):
        _, result = topotest.run_and_expect(fn, None, count=WAIT_COUNT, wait=WAIT_STEP)
        assert result is None, "%s: %s" % (step, result)

    def _host_add(dut, dev, ip):
        fam = "-6 " if ":" in ip else ""
        dut.run(
            "/sbin/bridge fdb replace %s dev %s master vlan %d dynamic"
            % (mac, dev, HOST_VID)
        )
        dut.run(
            "ip %sneigh replace %s lladdr %s dev vlan%d nud stale"
            % (fam, ip, mac, HOST_VID)
        )

    def _host_del(dut, dev, ip):
        fam = "-6 " if ":" in ip else ""
        dut.run("ip %sneigh del %s dev vlan%d 2>/dev/null" % (fam, ip, HOST_VID))
        dut.run(
            "/sbin/bridge fdb del %s dev %s master vlan %d 2>/dev/null"
            % (mac, dev, HOST_VID)
        )

    def _leaf2(synced, dev):
        for ip in synced:
            if not _neigh_synced(leaf2, ip):
                return "%s not synced on leaf2" % ip
        if not _mac_static_pinned(leaf2, mac, HOST_VID, dev=dev):
            return "leaf2 static sync-MAC for %s not on %s: %s" % (
                mac,
                dev,
                leaf2.run("bridge fdb show | grep -i %s" % mac),
            )
        return None

    _leaf3_es2_add(leaf3)
    _es2_bond_add(leaf2)
    try:
        _host_add(leaf1, "hostbond1", ip4)
        _expect("IPv4 on ES1", lambda: _leaf2([ip4], "hostbond1"))

        _host_add(leaf3, "l3mhes2", ip6)
        _expect("IPv6 on ES2", lambda: _leaf2([ip4, ip6], "l3mhes2"))

        _host_del(leaf3, "l3mhes2", ip6)
        _expect("IPv6 withdrawn", lambda: _leaf2([ip4], "hostbond1"))

        _host_add(leaf3, "l3mhes2", ip6)
        _expect("IPv6 back on ES2", lambda: _leaf2([ip4, ip6], "l3mhes2"))

        # Without extern_learn, the kernel reports it to zebra as a local learn.
        leaf2.run(
            "ip -6 neigh replace %s lladdr %s dev vlan%d nud reachable"
            % (ip6, mac, HOST_VID)
        )
        _expect("IPv6 learned on leaf2", lambda: _leaf2([ip4], "hostbond1"))
    finally:
        leaf2.run("ip -6 neigh del %s dev vlan%d 2>/dev/null" % (ip6, HOST_VID))
        _host_del(leaf1, "hostbond1", ip4)
        _host_del(leaf3, "l3mhes2", ip6)
        _es2_bond_del(leaf2)
        _leaf3_es2_del(leaf3)


def test_pure_l3_local_host_moves_between_es_bonds():
    """
    A host's MAC moves from hostbond1 (ES1) to another local ES bond (ES2) on
    leaf1 and back, with the same IP and MAC. leaf1's RT-2 must follow the MAC's
    port to the new ESI each time, and leaf2 (which has both ESes) must move its
    static sync-MAC FDB entry to the matching bond.
    """
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    leaf1 = tgen.gears["leaf1"]
    leaf2 = tgen.gears["leaf2"]
    mac, ip = "00:00:5e:00:53:e6", "45.0.0.193"

    def _expect(step, fn):
        _, result = topotest.run_and_expect(fn, None, count=WAIT_COUNT, wait=WAIT_STEP)
        assert result is None, "%s: %s" % (step, result)

    def _fdb_on(dev):
        leaf1.run(
            "/sbin/bridge fdb replace %s dev %s master vlan %d dynamic"
            % (mac, dev, HOST_VID)
        )

    def _follows(esi, dev):
        path = _pure_l3_rt2_path(leaf1, 65011, ip=ip)
        if path is None:
            return "leaf1 has no pure-L3 RT-2 for %s" % ip
        if path.get("esi") != esi:
            return "leaf1 RT-2 %s esi %s, want %s" % (ip, path.get("esi"), esi)
        if not _neigh_synced(leaf2, ip):
            return "%s not synced on leaf2" % ip
        if not _mac_static_pinned(leaf2, mac, HOST_VID, dev=dev):
            return "leaf2 static sync-MAC for %s not on %s" % (mac, dev)
        return None

    _es2_bond_add(leaf1)
    _es2_bond_add(leaf2)
    try:
        _fdb_on("hostbond1")
        leaf1.run(
            "ip neigh replace %s lladdr %s dev vlan%d nud stale" % (ip, mac, HOST_VID)
        )
        _expect("on ES1", lambda: _follows(ES1_ID, "hostbond1"))

        _fdb_on("l3mhes2")
        _expect("moved to ES2", lambda: _follows(ES2_ID, "l3mhes2"))

        _fdb_on("hostbond1")
        _expect("back on ES1", lambda: _follows(ES1_ID, "hostbond1"))
    finally:
        leaf1.run("ip neigh del %s dev vlan%d 2>/dev/null" % (ip, HOST_VID))
        for dev in ("hostbond1", "l3mhes2"):
            leaf1.run(
                "/sbin/bridge fdb del %s dev %s master vlan %d 2>/dev/null"
                % (mac, dev, HOST_VID)
            )
        _es2_bond_del(leaf2)
        _es2_bond_del(leaf1)


def test_pure_l3_dual_stack_sync_mac_shared():
    """
    host1's IPv4 and IPv6 addresses are both synced on leaf2 and share one
    static sync-MAC FDB entry for host1's MAC on hostbond1. Withdrawing one
    address must keep the entry and the other synced neighbor; the entry goes
    only with the last address. Done in both orders (v4 then v6, v6 then v4).
    """
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    leaf1 = tgen.gears["leaf1"]
    leaf2 = tgen.gears["leaf2"]
    host1 = tgen.gears["host1"]
    ip4, ip6 = HOST_IP["host1"], HOST_IP6["host1"]
    host1_mac = _host_bond_mac(host1)

    def _expect(fn, msg):
        _, result = topotest.run_and_expect(
            lambda: None if fn() else msg, None, count=WAIT_COUNT, wait=WAIT_STEP
        )
        assert result is None, result

    def _state():
        return (
            _neigh_synced(leaf2, ip4),
            _neigh_synced(leaf2, ip6),
            _mac_static_pinned(leaf2, host1_mac, HOST_VID),
        )

    def _sync_both():
        def _ping_both():
            host1.run("ping -c 1 -W 1 %s" % ANYCAST_GW)
            host1.run("ping -6 -c 1 -W 1 %s" % ANYCAST_GW6)
            return _state() == (True, True, True)

        _expect(_ping_both, "host1 v4/v6 not both synced on leaf2: %s" % (_state(),))

    def _withdraw(ip):
        # Remove it from host1 first so leaf1 cannot re-learn it via ARP/ND.
        fam, plen = ("-6 ", 64) if ":" in ip else ("", 24)
        host1.run("ip %saddr del %s/%d dev bond0" % (fam, ip, plen))
        leaf1.run("ip %sneigh del %s dev vlan%d" % (fam, ip, HOST_VID))

    def _restore():
        host1.run("ip addr replace %s/24 dev bond0" % ip4)
        host1.run("ip -6 addr replace %s/64 dev bond0 nodad" % ip6)
        host1.run("ip route replace default via %s" % ANYCAST_GW)

    try:
        for first, second in ((ip4, ip6), (ip6, ip4)):
            _restore()
            _sync_both()

            _withdraw(first)
            _expect(
                lambda f=first: not _neigh_synced(leaf2, f),
                "leaf2 still has %s synced after its withdraw" % first,
            )
            _assert_settled(
                lambda s=second: not _neigh_synced(leaf2, s)
                or not _mac_static_pinned(leaf2, host1_mac, HOST_VID),
                lambda f=first, s=second: "withdrawing %s removed the shared sync-MAC or %s: %s"
                % (f, s, _state()),
            )

            _withdraw(second)
            _expect(
                lambda: _state() == (False, False, False),
                "sync-MAC or a synced neighbor left after the last withdraw: %s"
                % (_state(),),
            )
    finally:
        _restore()

    _sync_both()


def test_pure_l3_ipv6_link_local_not_synced():
    """
    An IPv6 link-local address is only unique per link, so the same fe80::
    address can sit on several no-L2VNI VLANs of the VRF. Like L2VNI, which
    adds no L3 attributes to link-local MAC/IP routes, pure-L3 sync skips it:
    a leaf that learns host1's link-local neighbor originates no pure-L3 RT-2
    for it, and the ES peer installs no synced neighbor.
    """
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    leaves = {"leaf1": 65011, "leaf2": 65012}
    host1 = tgen.gears["host1"]
    out = host1.run("ip -6 -o addr show dev bond0 scope link")
    m = re.search(r"inet6 (fe80::[0-9a-f:]+)/", out)
    assert m, "host1 has no IPv6 link-local address: %s" % out
    ll = m.group(1)

    def _ll_neighs(extern):
        found = []
        for name in leaves:
            out = tgen.gears[name].run("ip -6 neigh show dev vlan%d" % HOST_VID)
            for line in out.splitlines():
                if line.startswith(ll + " ") and ("extern_learn" in line) == extern:
                    found.append(name)
        return found

    def _learned():
        host1.run("ping -6 -c 1 -W 1 -I bond0 ff02::1")
        return None if _ll_neighs(False) else "no leaf learned host1 %s" % ll

    _, result = topotest.run_and_expect(
        _learned, None, count=WAIT_COUNT, wait=WAIT_STEP
    )
    assert result is None, result

    def _synced():
        host1.run("ping -6 -c 1 -W 1 -I bond0 ff02::1")
        for name in leaves:
            for asn in leaves.values():
                if _pure_l3_rt2_path(tgen.gears[name], asn, ip=ll) is not None:
                    return True
        return bool(_ll_neighs(True))

    _assert_settled(
        _synced, "host1 link-local %s was synced as a pure-L3 neighbor" % ll
    )


def test_pure_l3_fdb_sync_mac_delete_reconciles():
    """
    Out-of-band delete of the local-ES sync-MAC pin reconciles. The pin leaf2
    programs for a synced host (a static `master` FDB entry on the ES bond) is
    zebra-owned derived state: if zebra observes the delete it re-pins right
    away (DB still owns the synced neighbor), and any RX-side sync event
    (l3vni-neigh token reimport) re-resolves the ESI and restores it too.
    Either way the synced extern_learn neighbor is never disturbed and the pin
    ends up back in place. Deterministic kernel-state assertions; no aging waits.
    """
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    leaf2 = tgen.gears["leaf2"]
    host1 = tgen.gears["host1"]
    _ping(host1, ANYCAST_GW)
    mac = _host_bond_mac(host1)

    def _expect(fn):
        _, result = topotest.run_and_expect(fn, None, count=WAIT_COUNT, wait=WAIT_STEP)
        assert result is None, result

    # Baseline: host1 synced and its MAC pinned (static) to the ES bond.
    _expect(
        lambda: (
            None
            if _host1_synced(leaf2) and _mac_static_pinned(leaf2, mac, HOST_VID)
            else "baseline sync neighbor/pin missing on leaf2"
        )
    )

    # Delete the static sync-MAC pin (a `master` bridge FDB entry) by hand, then
    # drive a RX-side sync event so reconciliation is guaranteed regardless of
    # whether zebra also observed the kernel delete directly.
    leaf2.run("bridge fdb del %s dev hostbond1 master vlan %d" % (mac, HOST_VID))
    assert _host1_synced(leaf2), "synced neighbor lost after FDB pin delete"
    leaf2.vtysh_cmd(
        "configure terminal\nrouter bgp 65012\n"
        " address-family l2vpn evpn\n  advertise-all-vni\n"
    )
    leaf2.vtysh_cmd(
        "configure terminal\nrouter bgp 65012\n"
        " address-family l2vpn evpn\n  advertise-all-vni l3vni-neigh\n"
    )

    # Reconciled: neighbor and pin are both back.
    _expect(
        lambda: (
            None
            if _host1_synced(leaf2) and _mac_static_pinned(leaf2, mac, HOST_VID)
            else "sync neighbor/pin not reconciled after FDB pin delete"
        )
    )


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
