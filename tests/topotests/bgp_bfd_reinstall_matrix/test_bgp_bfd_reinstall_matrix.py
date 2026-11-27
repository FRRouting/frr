#!/usr/bin/env python
# SPDX-License-Identifier: ISC

#
# test_bgp_bfd_reinstall_matrix.py
#
# Copyright (c) 2026 by NVIDIA Corporation
#                       Sougata Barik <sougatab@nvidia.com>
#

"""
BGP BFD session after a reset caused by update-source / disable-connected-check
changes, across peer types and bfd strict combinations.

r1 and r2 are connected by one link per scenario (link k: r1-eth<k-1>
10.0.k.1/24, 2001:db8:k::1/64 <-> r2-eth<k-1> 10.0.k.2/24, 2001:db8:k::2/64).
Each scenario has its own BGP + BFD peer on its link, changes r1 while BGP is
Established, then checks BGP Established and BFD Up on both routers.  Links 19
and 20 are in VRF blue (iBGP, AS 65010).
"""

import os
import sys
import json
import time
import functools
import pytest

CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

# pylint: disable=C0413
from lib import topotest
from lib.topogen import Topogen, get_topogen
from lib.common_config import step

pytestmark = [pytest.mark.bgpd, pytest.mark.bfdd]

NLINKS = 20
VRF_LINKS = (19, 20)
TIMERS = ["timers 3 10", "timers connect 1"]


def v4(k, r, net=0):
    return "10.{}.{}.{}".format(net, k, r)


def v6(k, r, net=0):
    return "2001:db8:{}::{}".format(k + 100 * net, r)


def ifname(rname, k):
    return "{}-eth{}".format(rname, k - 1)


def nbr(name, *lines, timers=True):
    out = ["neighbor {} {}".format(name, line) for line in lines]
    if timers:
        out += ["neighbor {} {}".format(name, t) for t in TIMERS]
    return out


# name: r1/r2 BGP lines, address families, the change on r1 and the checks.
#   up:      [(router, vrf, peer, local)] that must be Established + BFD Up
#            (peer "if:<ifname>" matches the BFD session by interface).
#   initial: same, before the change (defaults to up without local).
#   no_down: (router, vrf, peer) whose BFD session-down counter must not move.
#   no_reset:(router, vrf, peer) whose BGP connectionsEstablished must not move.
#   no_bfd:  (router, vrf, peer) that must have no BFD session at the end.
SCENARIOS = {
    "strict_r1_only": {
        "k": 1,
        "r1": nbr(v4(1, 2), "remote-as external", "bfd", "bfd strict"),
        "r2": nbr(v4(1, 1), "remote-as external", "bfd"),
        "change": ["neighbor {} update-source {}".format(v4(1, 2), v4(1, 1))],
        "up": [("r1", None, v4(1, 2), v4(1, 1)), ("r2", None, v4(1, 1), None)],
        "no_down": ("r2", None, v4(1, 1)),
    },
    "strict_r2_only": {
        "k": 2,
        "r1": nbr(v4(2, 2), "remote-as external", "bfd"),
        "r2": nbr(v4(2, 1), "remote-as external", "bfd", "bfd strict"),
        "change": ["neighbor {} update-source {}".format(v4(2, 2), v4(2, 1))],
        "up": [("r1", None, v4(2, 2), v4(2, 1)), ("r2", None, v4(2, 1), None)],
    },
    "strict_disable_connected_check": {
        "k": 3,
        "r1": nbr(v4(3, 2), "remote-as external", "bfd", "bfd strict"),
        "r2": nbr(v4(3, 1), "remote-as external", "bfd", "bfd strict"),
        "change": ["neighbor {} disable-connected-check".format(v4(3, 2))],
        "up": [("r1", None, v4(3, 2), None), ("r2", None, v4(3, 1), None)],
        "no_down": ("r2", None, v4(3, 1)),
    },
    "strict_peer_group": {
        "k": 4,
        "r1": nbr("PGS", "peer-group", timers=False)
        + nbr("PGS", "remote-as external", "bfd", "bfd strict")
        + nbr(v4(4, 2), "peer-group PGS", timers=False),
        "r2": nbr(v4(4, 1), "remote-as external", "bfd", "bfd strict"),
        "v4": ["PGS"],
        "change": ["neighbor PGS update-source {}".format(v4(4, 1))],
        "up": [("r1", None, v4(4, 2), v4(4, 1)), ("r2", None, v4(4, 1), None)],
        "no_down": ("r2", None, v4(4, 1)),
    },
    "strict_new_address": {
        "k": 5,
        "second": True,
        "r1": nbr(
            v4(5, 2),
            "remote-as external",
            "update-source " + v4(5, 1),
            "bfd",
            "bfd strict",
        ),
        "r2": nbr(v4(5, 1), "remote-as external", "passive", "bfd", "bfd strict")
        + nbr(
            v4(5, 1, 1),
            "remote-as external",
            "passive",
            "update-source " + v4(5, 2),
            "bfd",
            "bfd strict",
        ),
        "v4_r2": [v4(5, 1, 1)],
        "change": ["neighbor {} update-source {}".format(v4(5, 2), v4(5, 1, 1))],
        "initial": [("r1", None, v4(5, 2), None), ("r2", None, v4(5, 1), None)],
        "up": [("r1", None, v4(5, 2), v4(5, 1, 1)), ("r2", None, v4(5, 1, 1), None)],
    },
    "strict_ipv6": {
        "k": 6,
        "r1": nbr(v6(6, 2), "remote-as external", "bfd", "bfd strict"),
        "r2": nbr(v6(6, 1), "remote-as external", "bfd", "bfd strict"),
        "af": "ipv6",
        "change": ["neighbor {} update-source {}".format(v6(6, 2), v6(6, 1))],
        "up": [("r1", None, v6(6, 2), v6(6, 1)), ("r2", None, v6(6, 1), None)],
        "no_down": ("r2", None, v6(6, 1)),
    },
    "strict_hold_time": {
        "k": 7,
        "r1": nbr(
            v4(7, 2),
            "remote-as external",
            "bfd",
            "bfd strict",
            "bfd strict hold-time 5",
        ),
        "r2": nbr(
            v4(7, 1),
            "remote-as external",
            "bfd",
            "bfd strict",
            "bfd strict hold-time 5",
        ),
        "change": ["neighbor {} update-source {}".format(v4(7, 2), v4(7, 1))],
        "up": [("r1", None, v4(7, 2), v4(7, 1)), ("r2", None, v4(7, 1), None)],
        "no_down": ("r2", None, v4(7, 1)),
    },
    "update_source_ifname": {
        "k": 8,
        "r1": nbr(v4(8, 2), "remote-as external", "bfd"),
        "r2": nbr(v4(8, 1), "remote-as external", "bfd"),
        "change": ["neighbor {} update-source {}".format(v4(8, 2), ifname("r1", 8))],
        "up": [("r1", None, v4(8, 2), v4(8, 1)), ("r2", None, v4(8, 1), None)],
    },
    "update_source_unset": {
        "k": 9,
        "r1": nbr(v4(9, 2), "remote-as external", "update-source " + v4(9, 1), "bfd"),
        "r2": nbr(v4(9, 1), "remote-as external", "bfd"),
        "change": ["no neighbor {} update-source".format(v4(9, 2))],
        "up": [("r1", None, v4(9, 2), v4(9, 1)), ("r2", None, v4(9, 1), None)],
    },
    "disable_connected_check_unset": {
        "k": 10,
        "r1": nbr(v4(10, 2), "remote-as external", "disable-connected-check", "bfd"),
        "r2": nbr(v4(10, 1), "remote-as external", "bfd"),
        "change": ["no neighbor {} disable-connected-check".format(v4(10, 2))],
        "up": [("r1", None, v4(10, 2), None), ("r2", None, v4(10, 1), None)],
    },
    "ebgp_multihop_new_address": {
        "k": 11,
        "r1": nbr(
            "10.255.11.2",
            "remote-as external",
            "ebgp-multihop 2",
            "update-source 10.255.11.1",
            "bfd",
        ),
        "r2": nbr(
            "10.255.11.1",
            "remote-as external",
            "passive",
            "ebgp-multihop 2",
            "update-source 10.255.11.2",
            "bfd",
        )
        + nbr(
            "10.255.11.11",
            "remote-as external",
            "passive",
            "ebgp-multihop 2",
            "update-source 10.255.11.2",
            "bfd",
        ),
        "v4": ["10.255.11.2"],
        "v4_r2": ["10.255.11.1", "10.255.11.11"],
        "change": ["neighbor 10.255.11.2 update-source 10.255.11.11"],
        "initial": [
            ("r1", None, "10.255.11.2", None),
            ("r2", None, "10.255.11.1", None),
        ],
        "up": [
            ("r1", None, "10.255.11.2", "10.255.11.11"),
            ("r2", None, "10.255.11.11", None),
        ],
    },
    "ipv6_peer_group": {
        "k": 12,
        "r1": nbr("PG6", "peer-group", timers=False)
        + nbr("PG6", "remote-as external", "bfd")
        + nbr(v6(12, 2), "peer-group PG6", timers=False),
        "r2": nbr(v6(12, 1), "remote-as external", "bfd"),
        "af": "ipv6",
        "v6": ["PG6"],
        "change": ["neighbor PG6 update-source {}".format(v6(12, 1))],
        "up": [("r1", None, v6(12, 2), v6(12, 1)), ("r2", None, v6(12, 1), None)],
    },
    "ipv6_new_address": {
        "k": 13,
        "second": True,
        "r1": nbr(v6(13, 2), "remote-as external", "update-source " + v6(13, 1), "bfd"),
        "r2": nbr(v6(13, 1), "remote-as external", "passive", "bfd")
        + nbr(v6(13, 1, 1), "remote-as external", "passive", "bfd"),
        "af": "ipv6",
        "v6_r2": [v6(13, 1, 1)],
        "change": ["neighbor {} update-source {}".format(v6(13, 2), v6(13, 1, 1))],
        "initial": [("r1", None, v6(13, 2), None), ("r2", None, v6(13, 1), None)],
        "up": [("r1", None, v6(13, 2), v6(13, 1, 1)), ("r2", None, v6(13, 1, 1), None)],
    },
    "peer_group_member_override": {
        "k": 14,
        "r1": nbr("PGO", "peer-group", timers=False)
        + nbr("PGO", "remote-as external", "bfd")
        + nbr(v4(14, 2), "peer-group PGO", "update-source " + v4(14, 1), timers=False),
        "r2": nbr(v4(14, 1), "remote-as external", "bfd"),
        "v4": ["PGO"],
        "change": ["neighbor PGO update-source {}".format(ifname("r1", 14))],
        "up": [("r1", None, v4(14, 2), v4(14, 1)), ("r2", None, v4(14, 1), None)],
        "no_down": ("r2", None, v4(14, 1)),
        "no_reset": ("r1", None, v4(14, 2)),
    },
    "repeated_changes": {
        "k": 15,
        "second": True,
        "r1": nbr(v4(15, 2), "remote-as external", "bfd"),
        "r2": nbr(v4(15, 1), "remote-as external", "passive", "bfd")
        + nbr(v4(15, 1, 1), "remote-as external", "passive", "bfd"),
        "v4_r2": [v4(15, 1, 1)],
        "change": [
            "neighbor {} update-source {}".format(v4(15, 2), v4(15, 1)),
            "neighbor {} update-source {}".format(v4(15, 2), v4(15, 1, 1)),
            "no neighbor {} update-source".format(v4(15, 2)),
        ],
        "up": [("r1", None, v4(15, 2), v4(15, 1)), ("r2", None, v4(15, 1), None)],
    },
    "bfd_removed_while_pending": {
        "k": 16,
        "r1": nbr(v4(16, 2), "remote-as external", "bfd"),
        "r2": nbr(v4(16, 1), "remote-as external", "bfd"),
        "change": [
            "neighbor {} update-source {}".format(v4(16, 2), v4(16, 1)),
            "no neighbor {} bfd".format(v4(16, 2)),
        ],
        "initial": [("r1", None, v4(16, 2), None), ("r2", None, v4(16, 1), None)],
        "up": [],
        "established": [("r1", None, v4(16, 2))],
        "no_bfd": ("r1", None, v4(16, 2)),
    },
    "r1_passive": {
        "k": 17,
        "r1": nbr(v4(17, 2), "remote-as external", "passive", "bfd"),
        "r2": nbr(v4(17, 1), "remote-as external", "bfd"),
        "change": ["neighbor {} update-source {}".format(v4(17, 2), v4(17, 1))],
        "up": [("r1", None, v4(17, 2), v4(17, 1)), ("r2", None, v4(17, 1), None)],
    },
    "interface_peer": {
        "k": 18,
        "r1": nbr(ifname("r1", 18), "interface remote-as external", "bfd"),
        "r2": nbr(ifname("r2", 18), "interface remote-as external", "bfd"),
        "af": "ipv6",
        "change": ["neighbor {} disable-connected-check".format(ifname("r1", 18))],
        "up": [
            ("r1", None, "if:" + ifname("r1", 18), None),
            ("r2", None, "if:" + ifname("r2", 18), None),
        ],
    },
    "vrf_ibgp_single_hop": {
        "k": 19,
        "vrf": "blue",
        "r1": nbr(v4(19, 2), "remote-as internal", "bfd"),
        "r2": nbr(v4(19, 1), "remote-as internal", "bfd"),
        "change": ["neighbor {} update-source {}".format(v4(19, 2), v4(19, 1))],
        "up": [("r1", "blue", v4(19, 2), v4(19, 1)), ("r2", "blue", v4(19, 1), None)],
    },
    "vrf_ibgp_multihop_new_address": {
        "k": 20,
        "vrf": "blue",
        "r1": nbr(
            "10.254.20.2", "remote-as internal", "update-source 10.254.20.1", "bfd"
        ),
        "r2": nbr(
            "10.254.20.1",
            "remote-as internal",
            "passive",
            "update-source 10.254.20.2",
            "bfd",
        )
        + nbr(
            "10.254.20.11",
            "remote-as internal",
            "passive",
            "update-source 10.254.20.2",
            "bfd",
        ),
        "v4": ["10.254.20.2"],
        "v4_r2": ["10.254.20.1", "10.254.20.11"],
        "change": ["neighbor 10.254.20.2 update-source 10.254.20.11"],
        "initial": [
            ("r1", "blue", "10.254.20.2", None),
            ("r2", "blue", "10.254.20.1", None),
        ],
        "up": [
            ("r1", "blue", "10.254.20.2", "10.254.20.11"),
            ("r2", "blue", "10.254.20.11", None),
        ],
    },
}


def _activations(s, rname):
    """Address family and neighbors to activate for a scenario on a router."""
    af = s.get("af", "ipv4")
    key = "v4" if af == "ipv4" else "v6"
    first = s[rname][0].split()[1]
    if rname == "r1":
        return af, s.get(key) or [first]
    return af, [first] + [n for n in s.get(key + "_r2", []) if n != first]


def _config(rname):
    me = 1 if rname == "r1" else 2
    lines = ["!"]
    for k in range(1, NLINKS + 1):
        if k in VRF_LINKS:
            lines += ["interface {} vrf blue".format(ifname(rname, k))]
            lines += [" ip address {}/24".format(v4(k, me)), "!"]
            continue
        lines += ["interface {}".format(ifname(rname, k))]
        lines += [" ip address {}/24".format(v4(k, me))]
        lines += [" ipv6 address {}/64".format(v6(k, me))]
        if SCENARIOS_BY_K.get(k, {}).get("second"):
            lines += [" ip address {}/24".format(v4(k, me, 1))]
            lines += [" ipv6 address {}/64".format(v6(k, me, 1))]
        lines += ["!"]
    if rname == "r1":
        lines += ["ip route 10.255.11.2/32 {}".format(v4(11, 2))]
        lines += [
            "vrf blue",
            " ip route 10.254.20.2/32 {}".format(v4(20, 2)),
            "exit-vrf",
        ]
    else:
        lines += ["ip route 10.255.11.1/32 {}".format(v4(11, 1))]
        lines += ["ip route 10.255.11.11/32 {}".format(v4(11, 1))]
        lines += ["vrf blue"]
        lines += [" ip route 10.254.20.1/32 {}".format(v4(20, 1))]
        lines += [" ip route 10.254.20.11/32 {}".format(v4(20, 1))]
        lines += ["exit-vrf"]
    lines += ["!"]

    for vrf, asn in ((None, 65000 + me), ("blue", 65010)):
        head = "router bgp {}".format(asn) + (" vrf {}".format(vrf) if vrf else "")
        lines += [head]
        lines += [" bgp router-id 10.0.{}.{}".format(19 if vrf else 1, me)]
        lines += [" no bgp ebgp-requires-policy", " no bgp default ipv4-unicast"]
        afs = {"ipv4": [], "ipv6": []}
        for s in SCENARIOS.values():
            if s.get("vrf") != vrf:
                continue
            lines += [" " + line for line in s[rname]]
            af, names = _activations(s, rname)
            afs[af] += names
        for af, names in afs.items():
            if not names:
                continue
            lines += [" address-family {} unicast".format(af)]
            lines += ["  neighbor {} activate".format(n) for n in names]
            lines += [" exit-address-family"]
        lines += ["!"]
    return "\n".join(lines) + "\n"


SCENARIOS_BY_K = {s["k"]: s for s in SCENARIOS.values()}


def build_topo(tgen):
    tgen.add_router("r1")
    tgen.add_router("r2")
    for k in range(1, NLINKS + 1):
        switch = tgen.add_switch("s{}".format(k))
        switch.add_link(tgen.gears["r1"])
        switch.add_link(tgen.gears["r2"])


def setup_module(mod):
    tgen = Topogen(build_topo, mod.__name__)
    tgen.start_topology()

    for rname, router in tgen.routers().items():
        me = 1 if rname == "r1" else 2
        router.cmd("ip link add blue type vrf table 10 && ip link set blue up")
        for k in VRF_LINKS:
            dev = ifname(rname, k)
            router.cmd("ip link set {} master blue".format(dev))
        router.cmd("ip addr add 10.254.20.{}/32 dev blue".format(me))
        router.cmd("ip addr add 10.255.11.{}/32 dev lo".format(me))
        if rname == "r1":
            router.cmd("ip addr add 10.254.20.11/32 dev blue")
            router.cmd("ip addr add 10.255.11.11/32 dev lo")

        path = os.path.join(tgen.logdir, rname, "frr.conf")
        with open(path, "w") as f:
            f.write(_config(rname))
        router.load_frr_config(path)

    tgen.start_router()


def teardown_module(mod):
    tgen = get_topogen()
    tgen.stop_topology()


def _vrf(vrf):
    return " vrf {}".format(vrf) if vrf else ""


def _bfd_sessions(router, vrf, peer):
    bfd = json.loads(router.vtysh_cmd("show bfd{} peers json".format(_vrf(vrf))))
    if peer.startswith("if:"):
        return [s for s in bfd if s.get("interface") == peer[3:]]
    return [s for s in bfd if s.get("peer") == peer]


def _bgp_neighbor(router, vrf, peer):
    name = peer[3:] if peer.startswith("if:") else peer
    out = json.loads(
        router.vtysh_cmd("show bgp{} neighbors {} json".format(_vrf(vrf), name))
    )
    return out.get(name, {})


def _state(checks, with_local):
    tgen = get_topogen()
    output = {}
    expected = {}
    for rname, vrf, peer, local in checks:
        router = tgen.gears[rname]
        sessions = _bfd_sessions(router, vrf, peer)
        key = "{}:{}".format(rname, peer)
        output[key] = {
            "bgpState": _bgp_neighbor(router, vrf, peer).get("bgpState"),
            "bfd": [s.get("status") for s in sessions],
        }
        expected[key] = {"bgpState": "Established", "bfd": ["up"]}
        if with_local and local:
            output[key]["local"] = [s.get("local") for s in sessions]
            expected[key]["local"] = [local]
    return topotest.json_cmp(output, expected)


def _wait(checks, message, with_local=True):
    test_func = functools.partial(_state, checks, with_local)
    _, result = topotest.run_and_expect(test_func, None, count=40, wait=1)
    assert result is None, "{}: {}".format(message, result)


def _down_count(rname, vrf, peer):
    router = get_topogen().gears[rname]
    counters = json.loads(
        router.vtysh_cmd("show bfd{} peers counters json".format(_vrf(vrf)))
    )
    return [c.get("session-down") for c in counters if c.get("peer") == peer]


def test_all_up():
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    step("BGP Established and BFD Up for every scenario")
    checks = []
    for s in SCENARIOS.values():
        checks += s.get("initial", s["up"])
    _wait(checks, "initial state", with_local=False)


@pytest.mark.parametrize("name", list(SCENARIOS))
def test_scenario(name):
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    s = SCENARIOS[name]
    vrf = s.get("vrf")
    r1 = tgen.gears["r1"]
    down_before = _down_count(*s["no_down"]) if s.get("no_down") else None
    if s.get("no_reset"):
        rname, nvrf, peer = s["no_reset"]
        resets_before = _bgp_neighbor(tgen.gears[rname], nvrf, peer).get(
            "connectionsEstablished"
        )

    step("{}: {}".format(name, "; ".join(s["change"])))
    head = "router bgp {}".format("65010 vrf blue" if vrf else "65001")
    r1.vtysh_cmd("configure terminal\n{}\n{}".format(head, "\n".join(s["change"])))

    if s.get("no_reset") or s.get("no_bfd"):
        time.sleep(5)

    _wait(s["up"], "{}: not back up".format(name))

    for rname, nvrf, peer in s.get("established", []):
        test_func = functools.partial(
            lambda r, v, p: _bgp_neighbor(tgen.gears[r], v, p).get("bgpState"),
            rname,
            nvrf,
            peer,
        )
        _, result = topotest.run_and_expect(test_func, "Established", count=40, wait=1)
        assert result == "Established", "{}: {} not Established".format(name, peer)

    if s.get("no_bfd"):
        rname, nvrf, peer = s["no_bfd"]
        sessions = _bfd_sessions(tgen.gears[rname], nvrf, peer)
        assert sessions == [], "{}: BFD session left after removal: {}".format(
            name, sessions
        )

    if s.get("no_reset"):
        rname, nvrf, peer = s["no_reset"]
        resets_after = _bgp_neighbor(tgen.gears[rname], nvrf, peer).get(
            "connectionsEstablished"
        )
        assert (
            resets_after == resets_before
        ), "{}: peer was reset: connectionsEstablished {} -> {}".format(
            name, resets_before, resets_after
        )

    if down_before is not None:
        down_after = _down_count(*s["no_down"])
        assert (
            down_after == down_before
        ), "{}: {} BFD session went down across the reset: {} -> {}".format(
            name, s["no_down"][0], down_before, down_after
        )


def test_memory_leak():
    "Run the memory leak test and report results."
    tgen = get_topogen()
    if not tgen.is_memleak_enabled():
        pytest.skip("Memory leak test/report is disabled")

    tgen.report_memory_leaks()


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
