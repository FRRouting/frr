#!/usr/bin/env python
# SPDX-License-Identifier: ISC

#
# test_anycast_gw_neigh_linkage.py
#
# Copyright (c) 2026 Robin Christ for partimus GmbH
#

"""
test_anycast_gw_neigh_linkage.py:

Regression test for zebra's EVPN neigh-MAC linkage on gateway MACIP
takeover.

Two VTEPs share an anycast gateway subnet, each with its own gateway
MAC (no macvlan, no EVPN-MH). leaf1 carries the anycast gateway IPs
on its SVIs and runs advertise-default-gw from the start. leaf2
starts without the anycast addresses, so it installs leaf1's
default-gw MAC+IP binding (which leaf1 advertises as Route Type 2 with 
Default Gateway Extended Community) as an ordinary remote neighbor.
The test is built so that it should also be valid later when FRR gains
proper support for RFC 7432 "Default Gateway Extended Community"
on received routes (basically MAC aliasing of remote default-gw MACs),
which at the time of writing this text is not the case.

The test works through the following steps:

1. leaf1 configures the anycast addresses on its SVIs and has
   advertise-default-gw enabled in its startup config. It will thus
   advertise Route Type 2 with Default Gateway Extended Community
   for those anycast addresses, which leaf2 installs as ordinary
   remote neighbors (leaf2 does NOT yet have the anycast addresses
   configured or advertise-default-gw enabled)
   
2. leaf2 configures the anycast addresses on its SVIs and then
   enables advertise-default-gw while the anycast addresses advertised
   by leaf1 are installed as ordinary remote neighbors.
   zebra's zebra_evpn_neigh_gw_macip_add reuses the existing neighbor
   entry and rewrites its MAC binding.

3. leaf1 issues "no advertise-default-gw" and thus withdraws the
   Route Type 2 with the anycast gateway MACIP bindings and the
   Default Gateway Extended Community.
   zebra's zebra_evpn_neigh_del on leaf2 deletes the reused neighbor.

zebra used to rewrite n->emac in step 2 without re-parenting the
neighbor onto the gateway MAC, so step 3 freed the neighbor while the
old MAC's neigh_list still pointed at it. This results in a
heap-use-after-free in remote_neigh_count, which under ASAN will
make zebra abort while processing the withdrawal.

The test runs the sequence twice and checks that leaf2 processes the
withdrawal and stays alive.
"""

import json
import os
import sys
from functools import partial

import pytest

CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

# pylint: disable=C0413
from lib import topotest
from lib.evpn import evpn_verify_bgp_vni_state, evpn_verify_vni_remote_vteps
from lib.topogen import Topogen, get_topogen
from lib.topolog import logger

pytestmark = [pytest.mark.bgpd]

VNIS = [100, 200]
GW_IPS = {100: "10.0.100.1", 200: "10.0.200.1"}
GW_PLEN = 24
LEAF_LO = {"leaf1": "10.10.10.10", "leaf2": "10.30.30.30"}
LEAF_MACS = {
    "leaf1": "00:be:ef:00:00:01",
    "leaf2": "00:be:ef:00:00:02",
}


def build_topo(tgen):
    "Two leaves back to back over the underlay, no hosts needed."
    tgen.add_router("leaf1")
    tgen.add_router("leaf2")

    switch = tgen.add_switch("s1")
    switch.add_link(tgen.gears["leaf1"])
    switch.add_link(tgen.gears["leaf2"])


def config_leaf_dataplane(leaf, name, svi_mac, with_gw_addrs):
    """
    Set up the VTEP dataplane on one leaf: vlan-aware bridge, a single
    vxlan device carrying every VNI, and one SVI per vlan. With
    with_gw_addrs the SVI carries the anycast gateway address directly.
    svi_mac is used for the bridge and every SVI of this leaf, so each
    leaf owns the shared gateway IPs with its own MAC.

    The vlan to VNI mapping lives on the single vxlan device as per-vlan
    tunnel_info, so vlan N carries VNI N.
    """
    lo_ip = LEAF_LO[name]

    leaf.run("ip link add dev bridge type bridge stp_state 0")
    leaf.run("ip link set dev bridge type bridge vlan_filtering 1")
    leaf.run("ip link set dev bridge type bridge mcast_snooping 0")
    leaf.run("ip link set dev bridge address %s" % svi_mac)
    leaf.run("ip link set dev bridge up")

    leaf.run(
        "ip link add dev vxlan0 type vxlan dstport 4789 local %s nolearning external"
        % lo_ip
    )
    leaf.run("ip link set dev vxlan0 master bridge")
    leaf.run("/sbin/bridge link set dev vxlan0 vlan_tunnel on")
    leaf.run("/sbin/bridge link set dev vxlan0 neigh_suppress on")
    leaf.run("/sbin/bridge link set dev vxlan0 learning off")
    leaf.run("/sbin/bridge vlan del vid 1 dev vxlan0")
    leaf.run("ip link set dev vxlan0 up")

    for vni in VNIS:
        leaf.run("/sbin/bridge vlan add vid %d dev vxlan0" % vni)
        leaf.run(
            "/sbin/bridge vlan add vid %d dev vxlan0 tunnel_info id %d" % (vni, vni)
        )

        leaf.run("/sbin/bridge vlan add vid %d dev bridge self" % vni)
        svi = "vlan%d" % vni
        leaf.run(
            "ip link add link bridge name %s type vlan id %d protocol 802.1q"
            % (svi, vni)
        )
        leaf.run("ip link set dev %s address %s" % (svi, svi_mac))
        if with_gw_addrs:
            leaf.run("ip addr add %s/%d dev %s" % (GW_IPS[vni], GW_PLEN, svi))
        leaf.run("ip link set dev %s up" % svi)

    leaf.run("/sbin/sysctl -w net.ipv4.ip_forward=1")


def setup_module(mod):
    tgen = Topogen(build_topo, mod.__name__)
    tgen.start_topology()

    # only leaf1 owns the anycast addresses from the start; leaf2 gains
    # them at runtime right before it advertises (see module docstring)
    config_leaf_dataplane(tgen.gears["leaf1"], "leaf1", LEAF_MACS["leaf1"], True)
    config_leaf_dataplane(tgen.gears["leaf2"], "leaf2", LEAF_MACS["leaf2"], False)

    # only leaf1 starts with advertise-default-gw; see module docstring
    for rname, router in tgen.routers().items():
        router.load_frr_config(
            os.path.join(CWD, "{}/frr.conf".format(rname)),
            daemons=["zebra", "staticd", "bgpd"],
        )
    tgen.start_router()


def teardown_module(_mod):
    tgen = get_topogen()
    tgen.stop_topology()


def set_advertise_default_gw(leaf, enable):
    cfg = "" if enable else "no "
    leaf.vtysh_cmd(
        "conf t\nrouter bgp 65000\naddress-family l2vpn evpn\n"
        "%sadvertise-default-gw" % cfg
    )


def set_gw_addrs(leaf, present):
    "add or remove the anycast gateway addresses on the leaf's SVIs"
    op = "add" if present else "del"
    for vni in VNIS:
        leaf.run("ip addr %s %s/%d dev vlan%d" % (op, GW_IPS[vni], GW_PLEN, vni))


def check_zebra_gw_addrs(leaf, expect_present):
    """
    run_and_expect-compatible: zebra's view of every SVI does (not)
    carry the anycast gateway address. The tests order address changes
    against advertisement changes, so they must wait until zebra has
    processed the netlink address event.
    """
    for vni in VNIS:
        out = leaf.vtysh_cmd("show interface vlan%d json" % vni, isjson=True)
        info = out.get("vlan%d" % vni, {})
        addrs = [c.get("address") for c in info.get("ipAddresses", [])]
        present = "%s/%d" % (GW_IPS[vni], GW_PLEN) in addrs
        if present != expect_present:
            return "vni %d: %s" % (vni, json.dumps(addrs))
    return None


def _tgen_or_skip():
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)
    return tgen


#
# EVPN / BGP state helpers
#


def get_vni_rd(leaf, vni):
    out = leaf.vtysh_cmd("show bgp l2vpn evpn vni %d json" % vni, isjson=True)
    return out["rd"]


def bgp_macip_route(dut, rd, mac, ip=None):
    """
    Look up a type-2 route in the global EVPN table under the origin's RD.
    Returns the parsed JSON dict, or None when the route is absent.
    Imported routes are not visible in the per-VNI table, hence the
    RD-based lookup.
    """
    cmd = "show bgp l2vpn evpn route rd %s mac %s" % (rd, mac)
    if ip:
        cmd += " ip %s" % ip
    out = dut.vtysh_cmd(cmd + " json")
    try:
        parsed = json.loads(out)
    except ValueError:
        # "% Network not in table" and friends
        return None
    return parsed or None


def check_bgp_macip(dut, origin, vni, mac, ip, expect_present):
    """
    run_and_expect-compatible: None on success, offending output otherwise.
    """
    try:
        rd = get_vni_rd(origin, vni)
    except (KeyError, ValueError):
        return "no rd for vni %d on %s" % (vni, origin.name)
    route = bgp_macip_route(dut, rd, mac, ip)
    present = route is not None
    if present == expect_present:
        return None
    return "rd %s mac %s ip %s: %s" % (rd, mac, ip, json.dumps(route))


def zebra_mac_entry(leaf, vni, mac):
    "zebra's view of one EVPN MAC entry, or None when absent"
    out = leaf.vtysh_cmd("show evpn mac vni %d mac %s json" % (vni, mac))
    try:
        parsed = json.loads(out)
    except ValueError:
        return None
    return parsed or None


def check_zebra_mac(leaf, vni, mac, expect_present, expect_type=None):
    """
    run_and_expect-compatible: None on success, offending output otherwise.
    """
    entry = zebra_mac_entry(leaf, vni, mac)
    present = entry is not None
    if present != expect_present:
        return "vni %d mac %s: %s" % (vni, mac, json.dumps(entry))
    if present and expect_type:
        # entry may be keyed by the MAC or flat
        info = entry.get(mac, entry)
        if info.get("type") != expect_type:
            return "vni %d mac %s type %s != %s" % (
                vni,
                mac,
                info.get("type"),
                expect_type,
            )
    return None


def zebra_neigh_entry(leaf, vni, ip):
    "zebra's view of one EVPN neighbor entry, or None when absent"
    out = leaf.vtysh_cmd("show evpn arp-cache vni %d ip %s json" % (vni, ip))
    try:
        parsed = json.loads(out)
    except ValueError:
        # the command prints nothing at all when the entry is absent
        return None
    return parsed or None


def check_gw_neigh_binding(leaf, mac, neigh_type):
    """
    run_and_expect-compatible: the neighbor entry for the anycast
    gateway IP of every VNI is bound to `mac` and has type
    `neigh_type`.
    """
    for vni in VNIS:
        entry = zebra_neigh_entry(leaf, vni, GW_IPS[vni])
        if entry is None:
            return "vni %d ip %s: no neighbor entry" % (vni, GW_IPS[vni])
        if entry.get("mac") != mac or entry.get("type") != neigh_type:
            return "vni %d ip %s: %s/%s != %s/%s" % (
                vni,
                GW_IPS[vni],
                entry.get("type"),
                entry.get("mac"),
                neigh_type,
                mac,
            )
    return None


def check_own_gw_mac(leaf, expect_present):
    """
    run_and_expect-compatible: the leaf's own gateway MAC is (not) a
    local MAC of every VNI. zebra creates that MAC entry as part of the
    gateway MACIP add, in the same event that rebinds the anycast
    neighbors, and unlike the neighbors it stays put.
    """
    mac = LEAF_MACS[leaf.name]
    for vni in VNIS:
        result = check_zebra_mac(
            leaf, vni, mac, expect_present, "local" if expect_present else None
        )
        if result is not None:
            return result
    return None


def check_vni_remote_vteps(tgen):
    """
    run_and_expect-compatible convergence check: each leaf sees exactly
    the other leaf as remote VTEP on every VNI, in zebra and in the
    bridge FDB. The single vxlan device makes the HREP entries carry a
    src_vni, which is what the library helper matches on.
    """
    for lname, peer in (("leaf1", "leaf2"), ("leaf2", "leaf1")):
        result = evpn_verify_vni_remote_vteps(tgen.gears[lname], VNIS, [LEAF_LO[peer]])
        if result is not None:
            return "%s: %s" % (lname, result)
    return None


def check_leaf1_gw_bindings_on_leaf2(tgen, expect_present):
    """
    run_and_expect-compatible: leaf1's gateway MAC is (not) a remote
    MAC in leaf2's zebra and its MAC+IP route is (not) in leaf2's BGP
    table, for every VNI.
    """
    leaf1 = tgen.gears["leaf1"]
    leaf2 = tgen.gears["leaf2"]
    mac = LEAF_MACS["leaf1"]

    for vni in VNIS:
        result = check_zebra_mac(
            leaf2, vni, mac, expect_present, "remote" if expect_present else None
        )
        if result is not None:
            return "zebra: %s" % result
        result = check_bgp_macip(leaf2, leaf1, vni, mac, GW_IPS[vni], expect_present)
        if result is not None:
            return "bgp: %s" % result
    return None


#
# Tests
#


def test_evpn_convergence():
    "Both leaves see each other as remote VTEP on both VNIs"
    tgen = _tgen_or_skip()
    test_fn = partial(check_vni_remote_vteps, tgen)
    _, result = topotest.run_and_expect(test_fn, None, count=60, wait=1)
    assert result is None, "EVPN did not converge: %s" % result


def test_gw_bindings_installed_on_peer():
    """
    leaf1 advertises its SVI MAC + anycast IP per VNI as a default-gw
    type-2 route and leaf2 installs the binding: leaf1's gateway MAC
    is a remote MAC in leaf2's zebra. This is the remote neighbor
    state the takeover in the next test builds on.
    """
    tgen = _tgen_or_skip()
    test_fn = partial(check_leaf1_gw_bindings_on_leaf2, tgen, True)
    _, result = topotest.run_and_expect(test_fn, None, count=30, wait=1)
    assert result is None, "leaf1 gateway bindings missing on leaf2: %s" % result


def test_gw_withdraw_after_local_takeover():
    """
    leaf2 configures the anycast addresses and enables
    advertise-default-gw while leaf1's gateway binding for the anycast
    IP is installed as a remote neighbor, then leaf1 withdraws its
    gateway bindings. leaf2 must process the withdrawal and stay
    alive. zebra used to free the taken-over neighbor while it was
    still linked on the old MAC's neigh_list, which aborts leaf2's
    zebra under ASAN right here. The addresses arrive only now so that
    the remote neighbor install above stays valid under the RFC 7432
    coexistence guards, which refuse to displace an already configured
    gateway binding.
    """
    tgen = _tgen_or_skip()
    leaf1 = tgen.gears["leaf1"]
    leaf2 = tgen.gears["leaf2"]

    for cycle in (1, 2):
        logger.info("takeover/withdraw cycle %d", cycle)

        # leaf1's gateway bindings are installed on leaf2
        test_fn = partial(check_leaf1_gw_bindings_on_leaf2, tgen, True)
        _, result = topotest.run_and_expect(test_fn, None, count=30, wait=1)
        assert (
            result is None
        ), "cycle %d: leaf1 gateway bindings missing on leaf2: %s" % (cycle, result)

        # the shared anycast IPs are remote neighbors bound to leaf1's
        # gateway MAC. These are the entries the gateway MACIP add on
        # leaf2 reuses.
        test_fn = partial(check_gw_neigh_binding, leaf2, LEAF_MACS["leaf1"], "remote")
        _, result = topotest.run_and_expect(test_fn, None, count=30, wait=1)
        assert (
            result is None
        ), "cycle %d: anycast IPs are not remote neighbors of leaf1: %s" % (
            cycle,
            result,
        )

        # leaf2 has not run a gateway MACIP add yet, so its own gateway
        # MAC is not in the VNIs
        test_fn = partial(check_own_gw_mac, leaf2, False)
        _, result = topotest.run_and_expect(test_fn, None, count=30, wait=1)
        assert result is None, "cycle %d: leaf2 gateway MAC already present: %s" % (
            cycle,
            result,
        )

        # leaf2 now gains the anycast addresses. The advertisement knob
        # is still off, so nothing is advertised yet and the remote
        # neighbors stay put.
        set_gw_addrs(leaf2, True)
        test_fn = partial(check_zebra_gw_addrs, leaf2, True)
        _, result = topotest.run_and_expect(test_fn, None, count=30, wait=1)
        assert result is None, "cycle %d: zebra did not pick up the addresses: %s" % (
            cycle,
            result,
        )

        # Enabling the gateway advertisement rebinds those neighbors to
        # leaf2's own gateway MAC. The rebinding itself is not a state
        # that can be polled for: leaf1's route is still there and wins
        # the anycast IP back within the same second. Poll instead for
        # leaf2's own gateway MAC, which the same event creates and
        # which stays, so it tells us the rebinding has happened.
        set_advertise_default_gw(leaf2, True)

        # bgpd has taken the knob (it is set globally, so the per-VNI
        # state reads "Active"). This only says the configuration
        # arrived, the zebra-side effect is checked right after.
        test_fn = partial(
            evpn_verify_bgp_vni_state,
            leaf2,
            VNIS,
            expected_fields={"advertiseGatewayMacip": "Active"},
        )
        _, result = topotest.run_and_expect(test_fn, None, count=30, wait=1)
        assert result is None, "cycle %d: leaf2 did not enable gateway MACIP: %s" % (
            cycle,
            result,
        )

        test_fn = partial(check_own_gw_mac, leaf2, True)
        _, result = topotest.run_and_expect(test_fn, None, count=30, wait=1)
        assert (
            result is None
        ), "cycle %d: leaf2 did not process the gateway MACIP add: %s" % (
            cycle,
            result,
        )

        # leaf1 withdraws; the remote MACIP del on leaf2 deletes the
        # reused neighbor. This step used to be the use-after-free.
        set_advertise_default_gw(leaf1, False)

        test_fn = partial(check_leaf1_gw_bindings_on_leaf2, tgen, False)
        _, result = topotest.run_and_expect(test_fn, None, count=30, wait=1)
        assert result is None, (
            "cycle %d: leaf1 gateway bindings still on leaf2 after "
            "withdrawal: %s" % (cycle, result)
        )

        assert (
            not tgen.routers_have_failure()
        ), "cycle %d: a daemon died processing the withdrawal: %s" % (
            cycle,
            tgen.errors,
        )

        # Restore the initial single-advertiser state for the next
        # cycle. leaf1 must only re-advertise after zebra on leaf2 has
        # processed the address removal: a gateway route that arrives
        # while the address is still known would be treated as a claim
        # of a configured gateway binding and never become the remote
        # neighbor the next cycle builds on.
        set_advertise_default_gw(leaf2, False)
        set_gw_addrs(leaf2, False)
        test_fn = partial(check_zebra_gw_addrs, leaf2, False)
        _, result = topotest.run_and_expect(test_fn, None, count=30, wait=1)
        assert result is None, "cycle %d: zebra kept the removed addresses: %s" % (
            cycle,
            result,
        )
        set_advertise_default_gw(leaf1, True)

    # leaf2's zebra is still fully responsive
    test_fn = partial(check_vni_remote_vteps, tgen)
    _, result = topotest.run_and_expect(test_fn, None, count=30, wait=1)
    assert result is None, "EVPN state gone after the churn: %s" % result


def test_memory_leak():
    "Run the memory leak test and report results."
    tgen = get_topogen()
    if not tgen.is_memleak_enabled():
        pytest.skip("Memory leak test/report is disabled")
    tgen.report_memory_leaks()


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
