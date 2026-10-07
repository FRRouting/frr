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
        _, result = topotest.run_and_expect(test_fn, None, count=30, wait=2)
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
        _, result = topotest.run_and_expect(test_fn, None, count=30, wait=2)
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
        _, result = topotest.run_and_expect(test_fn, None, count=30, wait=2)
        assert result is None, result


#####################################################
##
##   Pure-L3 RT-2 acceptance tests (xfail until the feature lands)
##
##   These encode the section-5 acceptance targets. They are expected to fail
##   until the feature is implemented, at which point the xfail markers are
##   removed one by one.
##
#####################################################


def _ping(host, dst, count=2):
    return host.run("ping -c %d -W 1 %s" % (count, dst))


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
        return "bgp vni %d advertiseL3vniNeigh=%s (expected %s)" % (
            L3VNI,
            state,
            want,
        )

    def _expect(fn, *args):
        _, result = topotest.run_and_expect(
            partial(fn, *args), None, count=15, wait=1
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

    # Turn it back off so the debug state does not leak into later tests.
    leaf1.vtysh_cmd(
        "configure terminal\n"
        "no debug bgp evpn mh l3vni-neigh\n"
        "no debug zebra evpn mh l3vni-neigh\n"
    )


@pytest.mark.xfail(
    reason="local ES not advertised to bgpd without an L2VNI base EVPN; "
    "needs the L3VNI-sourced base EVPN",
    strict=False,
)
def test_evpn_mh_local_es_in_bgp():
    """The local ES reaches bgpd (BGP_EVPNES_LOCAL) so RX ESI-match can work.

    With no L2VNI, zebra has no base EVPN to derive the ES originator IP, so the
    local ES never reaches bgpd today. The feature must source the base EVPN /
    originator IP from the L3VNI, after which this passes.
    """
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    for rname in ("leaf1", "leaf2"):
        dut = tgen.gears[rname]
        test_fn = partial(check_local_es, dut, ES1_ID)
        _, result = topotest.run_and_expect(test_fn, None, count=30, wait=2)
        assert result is None, result


@pytest.mark.xfail(
    reason="pure-L3 RT-2 (label[0]=0) origination not yet implemented",
    strict=False,
)
def test_pure_l3_rt2_origination():
    """
    With the knob on and no L2VNI, a local ARP entry for host1 produces an RT-2
    with label[0]=0 / label[1]=L3VNI on the multihoming leaf.
    """
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    for rname in ("leaf1", "leaf2"):
        r = tgen.gears[rname]
        r.vtysh_cmd(
            "configure terminal\n"
            "router bgp 650%s\n"
            " address-family l2vpn evpn\n"
            "  advertise-all-vni l3vni-neigh\n" % ("11" if rname == "leaf1" else "12")
        )

    # Trigger local ARP learning for host1 on the leaf SVIs.
    _ping(tgen.gears["host1"], ANYCAST_GW)

    def _has_pure_l3_rt2(dut):
        out = dut.vtysh_cmd("show bgp l2vpn evpn route type macip json")
        try:
            js = json.loads(out)
        except Exception as exc:  # pragma: no cover - defensive
            return "cannot parse macip routes: %s" % exc
        blob = json.dumps(js)
        if HOST_IP["host1"] in blob and '"label1":0' in blob.replace(" ", ""):
            return None
        return "no label[0]=0 RT-2 for %s" % HOST_IP["host1"]

    dut = tgen.gears["leaf1"]
    test_fn = partial(_has_pure_l3_rt2, dut)
    _, result = topotest.run_and_expect(test_fn, None, count=20, wait=2)
    assert result is None, result


@pytest.mark.xfail(
    reason="ESI-match sync-neighbor install not yet implemented",
    strict=False,
)
def test_pure_l3_sync_neighbor_install():
    """
    The multihoming peer (leaf2) installs host1's ARP entry as a sync neighbor
    (NTF_EXT_LEARNED) learned from the ESI-matched pure-L3 RT-2, with NO bridge
    FDB entry for host1's MAC.
    """
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    _ping(tgen.gears["host1"], ANYCAST_GW)

    def _has_sync_neigh(dut):
        out = dut.run("ip neigh show dev vlan%d" % HOST_VID)
        if HOST_IP["host1"] in out and "extern_learn" in out:
            return None
        return "no extern_learn neighbor for %s: %s" % (HOST_IP["host1"], out)

    dut = tgen.gears["leaf2"]
    test_fn = partial(_has_sync_neigh, dut)
    _, result = topotest.run_and_expect(test_fn, None, count=20, wait=2)
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
