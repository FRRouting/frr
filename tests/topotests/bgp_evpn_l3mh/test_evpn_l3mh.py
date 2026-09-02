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
# RT-2 acceptance tests are marked xfail and flip to pass as the feature is
# implemented.
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
  * VLAN 100  : the host access broadcast domain. SVI vlan100 holds the anycast
                gateway in vrf1 and is NOT mapped to any VNI -> NO L2VNI. A
                second access BD would simply be another VLAN (101, ...) sharing
                the same L3VNI (N:1).

VLAN 100 having an SVI but no VNI mapping is the "acc_bd->zevpn == NULL"
precondition the feature under test targets. Because the bridge is VLAN-aware,
the access BD carries a real vid (100), which the feature emits as the RT-2 ETAG
so a receiving leaf knows which SVI to install the synced neighbor on.
"""

import os
import sys
import json
import platform
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

# Tenant VRF / L3VNI / host broadcast-domain layout.
VRF = "vrf1"
VRF_TABLE = 1001
L3VNI = 4000
HOST_VID = 100  # host access BD VLAN -- has an SVI but is NOT mapped to any L2VNI
ANYCAST_GW = "45.0.0.1"

HOST_IP = {
    "host1": "45.0.0.101",
    "host2": "45.0.0.102",
}

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


def config_leaf_base(node, lo_ip):
    """VLAN-aware bridge (single VLAN-filtering bridge), tenant VRF, and a
    per-VNI VXLAN device for the L3VNI only. VLAN 100 is the host access BD (SVI
    vlan100, no VXLAN device -> no L2VNI); VLAN 4000 is the L3VNI (SVI vlan4000,
    carried by the per-VNI device vni4000). Both SVIs are in the tenant VRF.
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
    node.run("/sbin/bridge vlan add vid %d dev br_default self" % HOST_VID)
    node.run("/sbin/bridge vlan add vid %d dev br_default self" % L3VNI)

    # L3VNI SVI in the VRF.
    node.run("ip link add link br_default name vlan%d type vlan id %d" % (L3VNI, L3VNI))
    node.run("ip link set dev vlan%d master %s" % (L3VNI, VRF))
    node.run("ip link set dev vlan%d up" % L3VNI)

    # Host access-BD SVI (VLAN 100) in the VRF, with the anycast gateway. This
    # VLAN has an SVI but NO VNI mapping -- it is the "acc_bd->zevpn == NULL"
    # (no-L2VNI) case the feature targets. Its vid (100) is the RT-2 ETAG source.
    node.run(
        "ip link add link br_default name vlan%d type vlan id %d" % (HOST_VID, HOST_VID)
    )
    node.run("ip link set dev vlan%d master %s" % (HOST_VID, VRF))
    node.run("ip link set dev vlan%d up" % HOST_VID)
    node.run("ip addr add %s/24 dev vlan%d" % (ANYCAST_GW, HOST_VID))
    node.run("/sbin/sysctl -w net.ipv4.conf.vlan%d.proxy_arp=1" % HOST_VID)


def config_esi_bond(node, member):
    """Leaf-side ESI bond (es-id 1) facing the dual-homed host, added to the
    VLAN-aware bridge as an access port on VLAN 100."""
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


def config_access_port(node, member):
    """Leaf-side single-homed access port (no ESI), added to the VLAN-aware
    bridge as an access port on VLAN 100."""
    node.run("ip link set dev %s master br_default" % member)
    node.run("/sbin/bridge vlan del vid 1 dev %s" % member)
    node.run("/sbin/bridge vlan add vid %d dev %s pvid untagged" % (HOST_VID, member))


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


def config_host_single(node, member, ip):
    """Host-side single uplink (single-homed host)."""
    node.run("ip addr add %s/24 dev %s" % (ip, member))


def config_dataplane(tgen):
    leaf1 = tgen.gears["leaf1"]
    leaf2 = tgen.gears["leaf2"]
    leaf3 = tgen.gears["leaf3"]

    config_leaf_base(leaf1, LEAF_LO["leaf1"])
    config_leaf_base(leaf2, LEAF_LO["leaf2"])
    config_leaf_base(leaf3, LEAF_LO["leaf3"])

    # ESI bonds on the multihoming pair; single access port on leaf3.
    config_esi_bond(leaf1, "leaf1-eth2")
    config_esi_bond(leaf2, "leaf2-eth2")
    config_access_port(leaf3, "leaf3-eth2")

    # Hosts.
    config_host_bond(
        tgen.gears["host1"], ["host1-eth0", "host1-eth1"], HOST_IP["host1"]
    )
    config_host_single(tgen.gears["host2"], "host2-eth0", HOST_IP["host2"])


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
##   These encode the section-5 acceptance targets. Tests for features that
##   are not yet implemented carry an xfail/skip marker; the markers are
##   removed as each phase lands.
##
#####################################################


def _ping(host, dst, count=2):
    return host.run("ping -c %d -W 1 %s" % (count, dst))


def _pure_l3_rt2_path(dut, asn):
    """Return host1's pure-L3 RT-2 path dict on dut, or None if not present.

    A pure-L3 RT-2 is a routeType-2 macip route for host1's IP with ethTag =
    the host VLAN, vni "0/L3VNI" (label[0]=0 Explicit NULL / label[1]=L3VNI)
    and the IP-VRF route-target.
    """
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
                or entry.get("ip") != HOST_IP["host1"]
                or entry.get("ethTag") != HOST_VID
            ):
                continue
            for pathset in entry["paths"]:
                for path in pathset:
                    ec = path.get("extendedCommunity", {}).get("string", "")
                    if path.get("vni") == want_vni and want_rt in ec:
                        return path
    return None


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


def test_pure_l3_rt2_replay_on_knob_toggle():
    """
    Toggling advertise-l3vni-neigh off then on withdraws and then replays
    host1's pure-L3 RT-2 with its ESI. Knob-off flushes the pure-L3 neighbors
    (the RT-2 is withdrawn) but deliberately keeps the MAC->port cache; knob-on
    replays zebra's in-memory L3 neighbor database and re-originates, resolving
    the ESI from the preserved cache -- the same replay a bgpd GR reconnect
    relies on.
    """
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    leaf1 = tgen.gears["leaf1"]
    _ping(tgen.gears["host1"], ANYCAST_GW)

    def _rt2_absent():
        if _pure_l3_rt2_path(leaf1, 65011) is None:
            return None
        return "pure-L3 RT-2 still present"

    def _esi_present():
        path = _pure_l3_rt2_path(leaf1, 65011)
        if path is None:
            return "pure-L3 RT-2 missing"
        if path.get("esi") != ES1_ID:
            return "esi is %s, want %s" % (path.get("esi"), ES1_ID)
        return None

    # Baseline present.
    _, result = topotest.run_and_expect(
        _esi_present, None, count=WAIT_COUNT, wait=WAIT_STEP
    )
    assert result is None, result

    # Knob off: the pure-L3 RT-2 is withdrawn.
    leaf1.vtysh_cmd(
        "configure terminal\n"
        "router bgp 65011\n"
        " address-family l2vpn evpn\n"
        "  no advertise-l3vni-neigh\n"
    )
    try:
        _, result = topotest.run_and_expect(
            _rt2_absent, None, count=WAIT_COUNT, wait=WAIT_STEP
        )
        assert result is None, result
    finally:
        # Knob on: zebra replays its in-memory L3 neighbor database and
        # re-originates the pure-L3 RT-2, resolving the ESI from the preserved
        # MAC->port cache.
        leaf1.vtysh_cmd(
            "configure terminal\n"
            "router bgp 65011\n"
            " address-family l2vpn evpn\n"
            "  advertise-l3vni-neigh\n"
        )

    _, result = topotest.run_and_expect(
        _esi_present, None, count=WAIT_COUNT, wait=WAIT_STEP
    )
    assert result is None, result


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
        out = dut.run("bridge fdb show dev hostbond1")
        if host1_mac.lower() in out.lower():
            return None
        return "host1 MAC %s not pinned to hostbond1: %s" % (host1_mac, out)

    _, result = topotest.run_and_expect(
        partial(_has_sync_mac, dut), None, count=WAIT_COUNT, wait=WAIT_STEP
    )
    assert result is None, result


@pytest.mark.xfail(
    reason="pure-L3 proxy-ARP responder not yet implemented",
    strict=False,
)
def test_pure_l3_proxy_arp_responder():
    """
    On the peer leaf (no local copy of host1), an ARP for host1 is answered
    locally from the synced neighbor -- the no-L2VNI fabric has no flood path.
    """
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    # host2 (on leaf3) resolving host1 must succeed via the proxy responder.
    out = _ping(tgen.gears["host2"], HOST_IP["host1"], count=3)
    assert " 0% packet loss" in out, "host2 could not reach host1: %s" % out


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
