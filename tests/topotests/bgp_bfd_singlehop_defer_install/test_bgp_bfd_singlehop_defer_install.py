#!/usr/bin/env python
# SPDX-License-Identifier: ISC

#
# test_bgp_bfd_singlehop_defer_install.py
#
# Copyright (c) 2026 by
# NVIDIA Corporation
#

"""
Single-hop BGP BFD sessions must be registered with bfdd already carrying
their egress interface and local address.

Before the fix bgpd registered single-hop sessions at config time without an
interface/local address and filled them in once the TCP connection came up.
bfdd keys sessions on those fields, so the (already Up) session was deleted
and re-created with a new discriminator: the remote saw BFD go Down and, in
the field, reset BGP.

Topology (r2/r3 are passive, their BFD sessions are static so their counters
only reflect what r1 does; link-local addresses are pinned to fe80::<n>:1 on
r1 and fe80::<n>:2 on r2):

  r1-eth0 192.0.2.1/30       ---- r2-eth0 192.0.2.2/30        IPv4, no update-
                                                              source: waits for
                                                              the TCP source
  r1-eth1 2001:db8:2::1/64   ---- r2-eth1 2001:db8:2::2/64    IPv6, peer-group,
                                                              update-source if
  r1-eth2 192.0.2.5/30       ---- r2-eth2 192.0.2.6/30        IPv4, strict
  r1-eth3 2001:db8:4::1/64   ---- r2-eth3 2001:db8:4::2/64    IPv6, strict
                                                              inherited from pg
  r1-eth4 192.0.2.9/30       ---- r2-eth4 192.0.2.10/30       r2 lo .2, egress
                                                              unknown pre-TCP
  r1-eth5 192.0.2.13/30      ---- r2-eth5 192.0.2.14/30       r2 lo .4, same,
                                                              strict inherited
                                                              from pg (fallback)
  r1-eth6 2001:db8:6::1/64   ---- r2-eth6 2001:db8:6::2/64    IPv6, no update-
                                                              source
  r1-eth7 fe80::7:1          ---- r2-eth7 fe80::7:2           unnumbered
  r1-eth8 fe80::8:1          ---- r2-eth8 fe80::8:2           unnumbered, strict
  r1-eth9 fe80::9:1          ---- r2-eth9 fe80::9:2           link-local
                                                              neighbor
  r1-eth10 fe80::a:1         ---- r2-eth10 fe80::a:2          link-local
                                                              neighbor, strict
  r1-eth11.{100,101} fe80::b:1 -- r2-eth11.{100,101} fe80::b:2
                                                              unnumbered VLAN
                                                              sub-interfaces,
                                                              same link-local,
                                                              peer-group
  r1-eth12 192.0.2.21/30     ---- r3-eth0 192.0.2.22/30       iBGP, connected
  r1-eth13 192.0.2.17/30     ---- r2-eth12 192.0.2.18/30      VRF RED on r1,
                                                              update-source if,
                                                              BFD profile
  r1-eth14 192.0.2.25/30     ---- r2-eth13 192.0.2.26/30      update-source
                                                              r1 lo .11: TCP
                                                              local address is
                                                              on lo, BFD egress
                                                              stays r1-eth14
  r1 lo 198.51.100.1 ---(via eth0)--- r2 lo 198.51.100.3      multihop
  r1 lo 2001:db8:ff::1 ---(via eth1)--- r2 lo 2001:db8:ff::3  IPv6 multihop
"""

import os
import sys
import json
import time
import pytest
import functools

CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

# pylint: disable=C0413
from lib import topotest
from lib.topogen import Topogen, TopoRouter, get_topogen
from lib.common_config import step

pytestmark = [pytest.mark.bfdd, pytest.mark.bgpd, pytest.mark.staticd]

VLANS = (100, 101)
LINK_LOCAL = {
    "r1": {
        "r1-eth7": "fe80::7:1",
        "r1-eth8": "fe80::8:1",
        "r1-eth9": "fe80::9:1",
        "r1-eth10": "fe80::a:1",
        "r1-eth11.100": "fe80::b:1",
        "r1-eth11.101": "fe80::b:1",
    },
    "r2": {
        "r2-eth7": "fe80::7:2",
        "r2-eth8": "fe80::8:2",
        "r2-eth9": "fe80::9:2",
        "r2-eth10": "fe80::a:2",
        "r2-eth11.100": "fe80::b:2",
        "r2-eth11.101": "fe80::b:2",
    },
}

# BFD sessions are identified by "<peer>" or, for link-local peers that can
# share an address, "<peer>%<interface>".  Remote side is (router, session).

# Keyed before TCP is up.
# r1 neighbor -> (r1 BFD session, expected interface, expected local, remote)
RESOLVABLE = {
    "2001:db8:2::2": ("2001:db8:2::2", "r1-eth1", "2001:db8:2::1", ("r2", "2001:db8:2::1")),
    "192.0.2.6": ("192.0.2.6", "r1-eth2", "192.0.2.5", ("r2", "192.0.2.5")),
    "2001:db8:4::2": ("2001:db8:4::2", "r1-eth3", "2001:db8:4::1", ("r2", "2001:db8:4::1")),
    "fe80::a:2": ("fe80::a:2%r1-eth10", "r1-eth10", "fe80::a:1", ("r2", "fe80::a:1%r2-eth10")),
    "192.0.2.18": ("192.0.2.18", "r1-eth13", "192.0.2.17", ("r2", "192.0.2.17")),
    "192.0.2.26": ("192.0.2.26", "r1-eth14", "198.51.100.11", ("r2", "198.51.100.11")),
}
# Installed only once TCP is up.
DEFERRED = {
    "192.0.2.2": ("192.0.2.2", "r1-eth0", "192.0.2.1", ("r2", "192.0.2.1")),
    "198.51.100.2": ("198.51.100.2", "r1-eth4", "192.0.2.9", ("r2", "192.0.2.9")),
    "2001:db8:6::2": ("2001:db8:6::2", "r1-eth6", "2001:db8:6::1", ("r2", "2001:db8:6::1")),
    "r1-eth7": ("fe80::7:2%r1-eth7", "r1-eth7", "fe80::7:1", ("r2", "fe80::7:1%r2-eth7")),
    "fe80::9:2": ("fe80::9:2%r1-eth9", "r1-eth9", "fe80::9:1", ("r2", "fe80::9:1%r2-eth9")),
    "r1-eth11.100": (
        "fe80::b:2%r1-eth11.100",
        "r1-eth11.100",
        "fe80::b:1",
        ("r2", "fe80::b:1%r2-eth11.100"),
    ),
    "r1-eth11.101": (
        "fe80::b:2%r1-eth11.101",
        "r1-eth11.101",
        "fe80::b:1",
        ("r2", "fe80::b:1%r2-eth11.101"),
    ),
    "192.0.2.22": ("192.0.2.22", "r1-eth12", "192.0.2.21", ("r3", "192.0.2.21")),
}
# Strict, but the peer address is only learnt when BGP starts.
STRICT_UNNUMBERED = {
    "r1-eth8": ("fe80::8:2%r1-eth8", "r1-eth8", "fe80::8:1", ("r2", "fe80::8:1%r2-eth8")),
}
SINGLEHOP = dict(RESOLVABLE, **DEFERRED, **STRICT_UNNUMBERED)
MULTIHOP = ("198.51.100.3", "2001:db8:ff::3")
STRICT_FALLBACK = "198.51.100.4"
PENDING_REMOVE = "198.51.100.5"
PENDING_GROUP = ("PGP", "198.51.100.6")
VRF_NEIGHBORS = {"192.0.2.18": "RED"}
ALL_NEIGHBORS = list(SINGLEHOP) + list(MULTIHOP) + [STRICT_FALLBACK]

# r1 BFD ids / remote session-down counters once the held-down sessions are Up
BASELINE = {}
DOWN_BASELINE = {}


def build_topo(tgen):
    for routern in range(1, 4):
        tgen.add_router("r{}".format(routern))

    for switchn in range(1, 13):
        switch = tgen.add_switch("s{}".format(switchn))
        switch.add_link(tgen.gears["r1"])
        switch.add_link(tgen.gears["r2"])

    switch = tgen.add_switch("s13")
    switch.add_link(tgen.gears["r1"])
    switch.add_link(tgen.gears["r3"])

    for switchn in (14, 15):
        switch = tgen.add_switch("s{}".format(switchn))
        switch.add_link(tgen.gears["r1"])
        switch.add_link(tgen.gears["r2"])


def setup_module(mod):
    tgen = Topogen(build_topo, mod.__name__)
    tgen.start_topology()

    for rname in ("r1", "r2"):
        router = tgen.gears[rname]
        for vlan in VLANS:
            router.net.add_vlan(
                "{}-eth11.{}".format(rname, vlan), "{}-eth11".format(rname), vlan
            )
        for ifname, addr in LINK_LOCAL[rname].items():
            router.cmd_raises(
                "echo 1 > /proc/sys/net/ipv6/conf/{0}/addr_gen_mode && "
                "ip -6 addr flush dev {0} scope link && "
                "ip -6 addr add {1}/64 dev {0} nodad".format(ifname, addr)
            )

    tgen.gears["r1"].cmd_raises(
        "ip link add RED type vrf table 10 && ip link set RED up && "
        "ip link set r1-eth13 master RED"
    )

    for rname, router in tgen.routers().items():
        router.load_frr_config(
            os.path.join(CWD, "{}/frr.conf".format(rname)),
            [
                (TopoRouter.RD_ZEBRA, None),
                (TopoRouter.RD_MGMTD, None),
                (TopoRouter.RD_STATIC, None),
                (TopoRouter.RD_BFD, None),
                (TopoRouter.RD_BGP, None),
            ],
        )

    tgen.start_router()


def teardown_module(mod):
    tgen = get_topogen()
    tgen.stop_topology()


def bfd_key(p):
    if p["peer"].startswith("fe80") and p.get("interface"):
        return "{}%{}".format(p["peer"], p["interface"])
    return p["peer"]


def bfd_peers(router):
    output = json.loads(router.vtysh_cmd("show bfd peers json"))
    return {bfd_key(p): p for p in output}


def bfd_counters(router):
    output = json.loads(router.vtysh_cmd("show bfd peers counters json"))
    return {bfd_key(p): p for p in output}


def remote_downs():
    tgen = get_topogen()
    downs = {}
    for rname in ("r2", "r3"):
        for peer, values in bfd_counters(tgen.gears[rname]).items():
            downs[(rname, peer)] = values["session-down"]
    return downs


def bgp_neighbors(router):
    output = json.loads(router.vtysh_cmd("show bgp vrf all neighbors json"))
    neighbors = {}
    for vrf in output.values():
        neighbors.update({n: v for n, v in vrf.items() if isinstance(v, dict)})
    return neighbors


def r1_neighbors_cmd(fmt, neighbors):
    r1 = get_topogen().gears["r1"]
    cmds = ["configure terminal"]
    for n in neighbors:
        vrf = VRF_NEIGHBORS.get(n)
        cmds.append("router bgp 65001" + (" vrf {}".format(vrf) if vrf else ""))
        cmds.append(fmt.format(n))
        cmds.append("exit")
    r1.vtysh_multicmd("\n".join(cmds), pretty_output=False)


def record_baseline():
    "Wait for the held-down single-hop sessions to be Up, remember their ids."
    r1 = get_topogen().gears["r1"]

    def _up():
        expected = {peer: {"status": "up"} for peer, _, _, _ in RESOLVABLE.values()}
        return topotest.json_cmp(bfd_peers(r1), expected)

    topotest.run_and_expect(_up, None, count=60, wait=1)

    peers = bfd_peers(r1)
    for peer, _, _, _ in RESOLVABLE.values():
        if peers.get(peer, {}).get("status") == "up":
            BASELINE[peer] = peers[peer]["id"]
    DOWN_BASELINE.update(remote_downs())


def test_bfd_installed_with_interface_before_bgp_connects():
    "While BGP is held down, single-hop sessions are Up and already keyed."
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]

    def _sessions_up():
        peers = bfd_peers(r1)
        expected = {
            peer: {"status": "up", "interface": ifname, "local": local}
            for peer, ifname, local, _ in RESOLVABLE.values()
        }
        expected[STRICT_FALLBACK] = {"status": "up"}
        expected[RESOLVABLE["192.0.2.18"][0]]["vrf"] = "RED"
        return topotest.json_cmp(peers, expected)

    step("BFD sessions of BGP-down single-hop peers come Up with interface/local")
    _, result = topotest.run_and_expect(_sessions_up, None, count=60, wait=1)
    assert result is None, "single-hop BFD session not installed with egress interface: {}".format(result)

    record_baseline()
    peers = bfd_peers(r1)

    step("Non-strict sessions that cannot be keyed yet are deferred, not installed")
    for peer, _, _, _ in DEFERRED.values():
        assert peer not in peers, "BFD session for {} installed before keyed: {}".format(
            peer, peers.get(peer)
        )

    step("Strict mode with unresolvable egress falls back to an interface-less install")
    assert peers[STRICT_FALLBACK].get("interface") is None

    step("BFD profile applied to the VRF session")
    vrf_peer = peers[RESOLVABLE["192.0.2.18"][0]]
    assert vrf_peer["receive-interval"] == 600, vrf_peer


def test_bgp_up_does_not_recreate_bfd_session():
    "Bringing BGP up must not delete/re-create the Up BFD session."
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]

    if not BASELINE:
        record_baseline()

    step("Bring all r1 neighbors up")
    r1_neighbors_cmd("no neighbor {} shutdown", ALL_NEIGHBORS)

    def _bgp_up():
        expected = {
            n: {"bgpState": "Established", "peerBfdInfo": {"status": "Up"}}
            for n in ALL_NEIGHBORS
        }
        return topotest.json_cmp(bgp_neighbors(r1), expected)

    _, result = topotest.run_and_expect(_bgp_up, None, count=90, wait=1)
    assert result is None, "BGP/BFD did not converge (strict deadlock?): {}".format(result)

    # Let any re-created session's old instance time out on the remote.
    time.sleep(5)

    peers = bfd_peers(r1)
    downs = remote_downs()
    neighbors = bgp_neighbors(r1)

    problems = []

    step("Local discriminator unchanged across BGP establishment")
    for peer, _, _, _ in RESOLVABLE.values():
        if peer not in BASELINE:
            problems.append("r1 {}: BFD session not Up before BGP connected".format(peer))
        elif peers[peer]["id"] != BASELINE[peer]:
            problems.append(
                "r1 {}: BFD session re-created (id {} -> {})".format(
                    peer, BASELINE[peer], peers[peer]["id"]
                )
            )

    step("Every single-hop session keyed with its egress interface and source")
    for peer, ifname, local, _ in SINGLEHOP.values():
        session = peers.get(peer, {})
        if (session.get("interface"), session.get("local"), session.get("multihop")) != (
            ifname,
            local,
            False,
        ):
            problems.append("r1 {}: keyed {}".format(peer, session))

    step("Sub-interfaces sharing a link-local get distinct sessions")
    sub_ids = {peers.get(DEFERRED[n][0], {}).get("id") for n in ("r1-eth11.100", "r1-eth11.101")}
    if len(sub_ids) != 2:
        problems.append("r1 sub-interface sessions collapsed: {}".format(sub_ids))

    step("Remote never saw BFD go Down")
    for _, _, _, remote in SINGLEHOP.values():
        count = downs[remote] - DOWN_BASELINE.get(remote, 0)
        if count:
            problems.append("{} {}: saw BFD Down {} time(s)".format(remote[0], remote[1], count))

    step("BGP came up exactly once on every non-fallback peer")
    for n in list(SINGLEHOP) + list(MULTIHOP):
        if neighbors[n]["connectionsEstablished"] != 1:
            problems.append(
                "r1 {}: BGP established {} times, last reset '{}'".format(
                    n, neighbors[n]["connectionsEstablished"], neighbors[n].get("lastResetDueTo")
                )
            )

    step("Multihop sessions are unaffected")
    for peer in MULTIHOP:
        if not peers[peer]["multihop"] or peers[peer]["status"] != "up":
            problems.append("r1 {}: multihop session {}".format(peer, peers[peer]))

    assert not problems, "\n".join(problems)


def test_bgp_peer_reset_keeps_bfd_session():
    "Clearing BGP re-uses the existing, already keyed BFD session."
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]
    cleared = ("192.0.2.2", "2001:db8:2::2", "r1-eth7", "r1-eth11.100")

    before = {p: v["id"] for p, v in bfd_peers(r1).items()}
    down_before = remote_downs()

    step("Clear numbered and unnumbered single-hop sessions")
    for n in cleared:
        r1.vtysh_cmd("clear bgp {}".format(n))

    def _bgp_up():
        expected = {
            n: {"bgpState": "Established", "connectionsEstablished": 2} for n in cleared
        }
        return topotest.json_cmp(bgp_neighbors(r1), expected)

    _, result = topotest.run_and_expect(_bgp_up, None, count=60, wait=1)
    assert result is None, "BGP did not re-establish after clear: {}".format(result)
    time.sleep(3)

    after = bfd_peers(r1)
    down_after = remote_downs()
    for n in cleared:
        peer, _, _, remote = SINGLEHOP[n]
        assert after[peer]["id"] == before[peer], "{} re-created".format(peer)
        assert after[peer]["status"] == "up"
        assert down_after[remote] == down_before[remote], "{} saw BFD Down".format(remote)


def test_bfd_config_change_while_pending():
    "Removing BFD while deferred is clean; enabling strict installs it."
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]

    step("Add a held-down peer whose egress interface is unknown, with BFD")
    r1_neighbors_cmd(
        "{}",
        [
            "neighbor {} remote-as external".format(PENDING_REMOVE),
            "neighbor {} shutdown".format(PENDING_REMOVE),
            "neighbor {} disable-connected-check".format(PENDING_REMOVE),
            "neighbor {} bfd".format(PENDING_REMOVE),
        ],
    )
    time.sleep(2)
    assert PENDING_REMOVE not in bfd_peers(r1), "pending session was installed"

    step("Remove BFD while the install is pending")
    r1_neighbors_cmd("no neighbor {} bfd", [PENDING_REMOVE])
    time.sleep(2)
    assert PENDING_REMOVE not in bfd_peers(r1)
    neighbor = json.loads(r1.vtysh_cmd("show bgp neighbors {} json".format(PENDING_REMOVE)))
    assert PENDING_REMOVE in neighbor, neighbor

    step("Re-enable BFD (pending again), then strict: must install now")
    r1_neighbors_cmd("neighbor {} bfd", [PENDING_REMOVE])
    time.sleep(2)
    assert PENDING_REMOVE not in bfd_peers(r1)
    r1_neighbors_cmd("neighbor {} bfd strict", [PENDING_REMOVE])

    def _installed():
        return PENDING_REMOVE in bfd_peers(r1)

    _, result = topotest.run_and_expect(_installed, True, count=10, wait=1)
    assert result, "strict mode left the BFD session uninstalled (BGP would deadlock)"

    step("Pending peer-group member: enabling strict on the group installs it")
    group, member = PENDING_GROUP
    r1_neighbors_cmd(
        "{}",
        [
            "neighbor {} peer-group".format(group),
            "neighbor {} remote-as external".format(group),
            "neighbor {} disable-connected-check".format(group),
            "neighbor {} bfd".format(group),
            "neighbor {} peer-group {}".format(member, group),
            "neighbor {} shutdown".format(member),
        ],
    )
    time.sleep(2)
    assert member not in bfd_peers(r1), "pending member session was installed"
    r1_neighbors_cmd("neighbor {} bfd strict", [group])

    def _member_installed():
        return member in bfd_peers(r1)

    _, result = topotest.run_and_expect(_member_installed, True, count=10, wait=1)
    assert result, "strict inherited from the peer-group left the member uninstalled"

    step("Delete the neighbors, sessions go away")
    r1_neighbors_cmd("no neighbor {}", [PENDING_REMOVE, member, group])

    def _gone():
        peers = bfd_peers(r1)
        return PENDING_REMOVE not in peers and member not in peers

    _, result = topotest.run_and_expect(_gone, True, count=10, wait=1)
    assert result, "BFD session leaked after neighbor removal"


def test_memory_leak():
    "Run the memory leak test and report results."
    tgen = get_topogen()
    if not tgen.is_memleak_enabled():
        pytest.skip("Memory leak test/report is disabled")

    tgen.report_memory_leaks()


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
