#!/usr/bin/env python
# SPDX-License-Identifier: ISC
#
# test_babel_nexthop_parser_state.py
#
# Copyright (c) 2026
# Bing Shui
#

"""
test_babel_nexthop_parser_state.py
==================================

Regression for babeld not updating the Next Hop parser state when a Next
Hop TLV is silently ignored due to an unknown mandatory sub-TLV.

RFC 8966 s4.5: "parsing a TLV MUST update the parser state even if the TLV
is otherwise ignored due to an unknown mandatory sub-TLV or for any other
reason."  RFC 8966 s4.6.8: a Next Hop TLV "sets up the next hop for
subsequent Update TLVs even if it is otherwise ignored due to an unknown
mandatory sub-TLV."

Code path (babeld/message.c, unfixed): the MESSAGE_NH handler called
parse_subtlv_no_special_action() first and did `goto done` on -2, skipping
the v4_nh/v6_nh update, so subsequent Update TLVs in the same packet used
the previous next hop (or the packet source address).  The reference
implementation (jech/babeld) updates the next-hop state before parsing
sub-TLVs.

Topology
--------

    a1 (attacker) ---- sw1 ---- r1 ---- sw2 ---- r2

Each scenario is one Babel packet from a1 to r1 (multicast ff02::1:6,
UDP/6696) carrying a Router-Id TLV, zero or more Next Hop TLVs, and one
Update TLV, in that order.  r2 is on a separate segment: whatever appears
in its table arrived through r1's re-advertisement.

Test plan
---------

1. test_converge
     Baseline: r1 and r2 form a Babel adjacency on r1-eth1/r2-eth0.

2. test_mandatory_nexthop_updates_parser_state
     S2: NH(A) NH(B)+mandatory + Update  -> route must use B (bug: A)
     S3: NH(B)+mandatory + Update v4     -> route must use B (bug: absent)
     S4: NH(B6)+mandatory + Update v6    -> route must use B6 (bug: src)

3. test_legitimate_nexthop_and_controls
     S1: NH(A) + Update                  -> via A
     C1: NH(B)+optional sub-TLV + Update -> via B (TLV not ignored)
     C2: NH(AE=0, malformed) + Update    -> no route (fail path unchanged)
     C3: Update v6, no explicit NH       -> via packet source
     C4: NH(B6, AE=3, no sub-TLV) + Update v6 -> via B6

4. test_routes_propagate
     r2 learns the control prefixes from r1 (C2's prefix correctly never
     exists, so it is not expected on r2 either).
"""

import os
import re
import shlex
import sys
import time
from functools import partial

import pytest

from lib import topotest
from lib.topogen import Topogen, TopoRouter, get_topogen
from lib.topolog import logger


CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

pytestmark = [pytest.mark.babeld]

A1_LL = "fe80::a1"
NH_A = "10.13.0.3"
NH_B = "10.13.0.5"
NH_B6 = "fe80::b6"

# (scenario, prefix, address family, expected via or None for "absent")
CORE_CASES = [
    ("S2-multi-nh", "10.99.2.0/24", 4, NH_B),
    ("S3-single-v4", "10.99.3.0/24", 4, NH_B),
    ("S4-single-v6", "2001:db8:99:4::/64", 6, NH_B6),
]
CONTROL_CASES = [
    ("S1-legit", "10.99.1.0/24", 4, NH_A),
    ("C1-optional", "10.99.5.0/24", 4, NH_B),
    ("C2-malformed", "10.99.6.0/24", 4, None),
    ("C3-no-explicit", "2001:db8:99:7::/64", 6, A1_LL),
    ("C4-legit-v6", "2001:db8:99:8::/64", 6, NH_B6),
]


def build_topo(tgen):
    a1 = tgen.add_host("a1", "10.13.0.2/24", "via 10.13.0.1")
    r1 = tgen.add_router("r1")
    r2 = tgen.add_router("r2")

    sw1 = tgen.add_switch("sw1")
    sw1.add_link(a1)
    sw1.add_link(r1)

    sw2 = tgen.add_switch("sw2")
    sw2.add_link(r1)
    sw2.add_link(r2)


def setup_module(mod):
    tgen = Topogen(build_topo, mod.__name__)
    tgen.start_topology()

    router_list = tgen.routers()
    for rname, router in router_list.items():
        router.load_config(
            TopoRouter.RD_ZEBRA, os.path.join(CWD, "{}/zebra.conf".format(rname))
        )
        router.load_config(
            TopoRouter.RD_BABEL, os.path.join(CWD, "{}/babeld.conf".format(rname))
        )

    a1 = tgen.gears["a1"]
    a1.cmd("sysctl -qw net.ipv6.conf.all.disable_ipv6=0")
    a1.cmd("sysctl -qw net.ipv6.conf.a1-eth0.disable_ipv6=0")
    a1.cmd("ip -6 addr add {}/64 dev a1-eth0 2>/dev/null || true".format(A1_LL))

    tgen.start_router()


def teardown_module(_mod):
    tgen = get_topogen()
    tgen.stop_topology()


ROUTE_RE = re.compile(
    r"^(\S+) metric (\d+) refmetric (\d+) id ((?:[0-9a-f]{2}:){7}[0-9a-f]{2}) "
    r"seqno (\d+).*via (\S+) neigh (\S+)(.*)$"
)


def _routes(router):
    out = router.vtysh_cmd("show babel route")
    routes = {}
    for ln in out.splitlines():
        m = ROUTE_RE.match(ln.strip())
        if m:
            tail = m.group(8)
            nh = re.search(r"nexthop (\S+)", tail)
            routes[m.group(1)] = {
                "via": m.group(6),
                "neigh": m.group(7),
                # effective next hop: explicit "nexthop" field when it
                # differs from the neighbour address, else the neighbour
                "nexthop": nh.group(1) if nh else m.group(7),
                "installed": "installed" in tail,
            }
    return routes


def _send(tgen, scenario):
    a1 = tgen.gears["a1"]
    cmd = (
        "python3 {cwd}/send_nh_update.py --iface a1-eth0 --src {src} "
        "--scenario {sc}".format(cwd=shlex.quote(CWD), src=A1_LL, sc=scenario)
    )
    a1.cmd_raises(cmd)


def _check_route(router, prefix, expect_via):
    """Return None when the route matches the expectation, else a reason."""
    routes = _routes(router)
    if expect_via is None:
        if prefix not in routes:
            return None
        return "route {} must be absent, present via {}".format(prefix, routes[prefix])
    if prefix not in routes:
        return "route {} not present".format(prefix)
    if not routes[prefix]["installed"]:
        return "route {} not installed".format(prefix)
    if routes[prefix]["nexthop"] != expect_via:
        return "route {} nexthop {} (expected {})".format(
            prefix, routes[prefix]["nexthop"], expect_via
        )
    return None


def test_converge():
    "Baseline: r1 and r2 form a Babel adjacency"

    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]

    def check_adjacency():
        out = r1.vtysh_cmd("show babel neighbor r1-eth1")
        for ln in out.splitlines():
            m = re.search(r"reach ([0-9a-f]{4})", ln)
            if m and m.group(1) != "0000":
                return None
        return "no r1-eth1 neighbour with nonzero reach yet"

    _, result = topotest.run_and_expect(check_adjacency, None, count=90, wait=1)
    assert result is None, "r1-r2 babel adjacency did not come up"

    # attacker hello+ihu so the injected routes get a finite metric and
    # r1 re-advertises them to r2 (propagation check)
    _send(tgen, "warmup")
    time.sleep(1.5)


def test_mandatory_nexthop_updates_parser_state():
    "An ignored Next Hop TLV (unknown mandatory sub-TLV) still updates the parser state"

    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]
    for scenario, prefix, _af, expect_via in CORE_CASES:
        _send(tgen, scenario)
        _, result = topotest.run_and_expect(
            partial(_check_route, r1, prefix, expect_via), None, count=15, wait=1
        )
        assert result is None, "{}: {}".format(scenario, result)


def test_legitimate_nexthop_and_controls():
    "Legitimate Next Hop TLVs and the optional/malformed/absent controls"

    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]
    for scenario, prefix, _af, expect_via in CONTROL_CASES:
        _send(tgen, scenario)
        if expect_via is None:
            time.sleep(3)
            _, result = topotest.run_and_expect(
                partial(_check_route, r1, prefix, None), None, count=1, wait=1
            )
        else:
            _, result = topotest.run_and_expect(
                partial(_check_route, r1, prefix, expect_via), None, count=15, wait=1
            )
        assert result is None, "{}: {}".format(scenario, result)


def test_routes_propagate():
    "Control prefixes are re-advertised by r1 and installed by r2"

    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r2 = tgen.gears["r2"]
    expected = [c[1] for c in CONTROL_CASES if c[3] is not None]

    def check_all():
        routes = _routes(r2)
        missing = [p for p in expected if p not in routes]
        if missing:
            return "r2 still missing: {}".format(missing)
        return None

    _, result = topotest.run_and_expect(check_all, None, count=60, wait=1)
    assert result is None, "propagation to r2 failed: {}".format(result)
    logger.info("r2 routes: %s", _routes(r2))


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
