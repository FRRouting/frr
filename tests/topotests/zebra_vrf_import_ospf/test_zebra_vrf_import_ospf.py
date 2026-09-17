#!/usr/bin/env python
# SPDX-License-Identifier: ISC

#
# test_zebra_vrf_import_ospf.py
#
# Copyright (c) 2026 Proxmox Server Solutions GmbH
# Gabriel Goller
#

"""
test_zebra_vrf_import_ospf.py: Test zebra VRF route import over an OSPF core.

The leaking counterpart of ospf_metric_propagation, which does the same job
with BGP VRF import.  Zebra imports a copy of the source route instead of
readvertising it, so the two differ in what the destination VRF ends up with:

* the copy keeps the source metric, which here is the OSPF cost of the path
  blue picked, so the core topology still drives the metric seen in green
* the copy is installed at the import distance rather than the source one
* the copied nexthop loses the source VRF interface and is resolved again in
  the destination VRF, so green needs its own route to the blue nexthop

The last point is why green has an uplink of its own to each transit router and
a static route to the transit subnet behind it.  Those are what resolve the
copied nexthops, and taking one of them down leaves a copy without a resolver.
"""

TOPOLOGY = r"""
                                    +-----+
                      10.0.60.0/24  | rc  |  10.0.70.0/24
                         cost 50    +--+--+    cost 50
                     +--------------+     +--------------+
                     |                                   |
                  +--+--+         10.0.50.0/24        +--+--+
        10.0.11.0 | ra  +-----------------------------+ rb  | 10.0.12.0/24
        /24 green +--+--+           cost 10           +--+--+ green
          +-------+  |                                   |  +-------+
          |          | 10.0.40.0/24       10.0.30.0/24   |          |
          |          |    cost 10           cost 10      |          |
          |          |         +----------------+        |          |
          |          +---------+  r4   (blue)   +--------+          |
          |                    +-------+--------+                   |
          |                            |.4                          |
          |                     10.0.94.0/24 cost 10                 |
          |                            |.2                          |
          |                         +--+--+                         |
          |                         | h2  |                         |
          |                         +-----+                         |
          |     10.0.10.0/24                     10.0.20.0/24       |
          |       cost 10                          cost 100         |
          |          |                                   |          |
      .1 eth2     .1 eth1                             .1 eth3    .1 eth4
        green        blue                                blue       green
        +----+----------+-----------------------------------+---------+----+
        |                               r1                                 |
        +--------+-------------------------------------------------+-------+
             .1 eth0 green                                  .1 eth5 red
                 |                                                 |
           10.0.91.0/24                                      10.0.92.0/24
                 |.2                                               |.2
                 +--------------------+  h1  +---------------------+
"""

import functools
import json
import os
import sys

import pytest

CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

# pylint: disable=C0413
from lib import topotest
from lib.common_config import step
from lib.topogen import Topogen, TopoRouter, get_topogen
from lib.topolog import logger

pytestmark = [pytest.mark.ospfd, pytest.mark.staticd]

# The prefix green has to learn from blue, and the source route behind it.
H2_PREFIX = "10.0.94.0/24"
# A green route that exists on its own, used to tell an import apart from it.
GREEN_STATIC = "10.48.48.0/24"

VRF_TABLES = (("blue", 11), ("green", 12), ("red", 13))

# Which VRF each r1 interface belongs to.  The pairs on the transit segments
# are what lets green resolve a nexthop blue selected.
R1_VRF_INTERFACES = (
    ("r1-eth0", "green"),
    ("r1-eth1", "blue"),
    ("r1-eth2", "green"),
    ("r1-eth3", "blue"),
    ("r1-eth4", "green"),
    ("r1-eth5", "red"),
)

R4_VRF_INTERFACES = (
    ("r4-eth0", "blue"),
    ("r4-eth1", "blue"),
    ("r4-eth2", "blue"),
)


def build_topo(tgen):
    "Build function"

    for router in ("r1", "r4", "ra", "rb", "rc", "h1", "h2"):
        tgen.add_router(router)

    # h1 is reachable from green and from red over separate subnets.
    switch = tgen.add_switch("s1")
    switch.add_link(tgen.gears["r1"], nodeif="r1-eth0")
    switch.add_link(tgen.gears["h1"], nodeif="h1-eth0")

    switch = tgen.add_switch("s2")
    switch.add_link(tgen.gears["r1"], nodeif="r1-eth5")
    switch.add_link(tgen.gears["h1"], nodeif="h1-eth1")

    # Blue peers with ra and rb over the transit subnets, and green has an
    # uplink of its own to each of them.
    switch = tgen.add_switch("s3")
    switch.add_link(tgen.gears["r1"], nodeif="r1-eth1")
    switch.add_link(tgen.gears["ra"], nodeif="ra-eth0")

    switch = tgen.add_switch("s4")
    switch.add_link(tgen.gears["r1"], nodeif="r1-eth2")
    switch.add_link(tgen.gears["ra"], nodeif="ra-eth4")

    switch = tgen.add_switch("s5")
    switch.add_link(tgen.gears["r1"], nodeif="r1-eth3")
    switch.add_link(tgen.gears["rb"], nodeif="rb-eth0")

    switch = tgen.add_switch("s6")
    switch.add_link(tgen.gears["r1"], nodeif="r1-eth4")
    switch.add_link(tgen.gears["rb"], nodeif="rb-eth4")

    switch = tgen.add_switch("s7")
    switch.add_link(tgen.gears["r4"], nodeif="r4-eth1")
    switch.add_link(tgen.gears["ra"], nodeif="ra-eth1")

    switch = tgen.add_switch("s8")
    switch.add_link(tgen.gears["r4"], nodeif="r4-eth2")
    switch.add_link(tgen.gears["rb"], nodeif="rb-eth1")

    switch = tgen.add_switch("s9")
    switch.add_link(tgen.gears["ra"], nodeif="ra-eth2")
    switch.add_link(tgen.gears["rb"], nodeif="rb-eth2")

    switch = tgen.add_switch("s10")
    switch.add_link(tgen.gears["ra"], nodeif="ra-eth3")
    switch.add_link(tgen.gears["rc"], nodeif="rc-eth0")

    switch = tgen.add_switch("s11")
    switch.add_link(tgen.gears["rb"], nodeif="rb-eth3")
    switch.add_link(tgen.gears["rc"], nodeif="rc-eth1")

    switch = tgen.add_switch("s12")
    switch.add_link(tgen.gears["r4"], nodeif="r4-eth0")
    switch.add_link(tgen.gears["h2"], nodeif="h2-eth0")


def setup_module(mod):
    logger.info("Zebra VRF import over OSPF:\n {}".format(TOPOLOGY))

    tgen = Topogen(build_topo, mod.__name__)
    tgen.start_topology()

    for router, interfaces in (("r1", R1_VRF_INTERFACES), ("r4", R4_VRF_INTERFACES)):
        net = tgen.net[router]
        for vrf, table in VRF_TABLES:
            net.cmd_raises("ip link add name {} type vrf table {}".format(vrf, table))
            net.cmd_raises("ip link set dev {} up".format(vrf))
        for ifname, vrf in interfaces:
            net.cmd_raises("ip link set dev {} master {} up".format(ifname, vrf))

    for router in tgen.routers().values():
        router.load_frr_config(
            daemons=[
                (TopoRouter.RD_ZEBRA, None),
                (TopoRouter.RD_STATIC, None),
                (TopoRouter.RD_OSPF, None),
            ]
        )

    tgen.start_router()


def teardown_module():
    "Teardown the pytest environment"
    tgen = get_topogen()
    tgen.stop_topology()


def set_link_states(tgen, r4_ra_up, ra_rb_up, r1_rb_green_up):
    """
    Drive the three links the tests move, always to an explicit state so each
    test starts from a known topology regardless of what ran before it.

    r4_ra_up:       r4-eth1, the direct blue link from r4 to ra
    ra_rb_up:       ra-eth2, the core link between ra and rb
    r1_rb_green_up: r1-eth4, green's resolver for the nexthop behind rb
    """
    for router, ifname, up in (
        ("r4", "r4-eth1", r4_ra_up),
        ("ra", "ra-eth2", ra_rb_up),
        ("r1", "r1-eth4", r1_rb_green_up),
    ):
        tgen.net[router].cmd(
            "ip link set dev {} {}".format(ifname, "up" if up else "down")
        )


def check_route_json(router, vrf, prefix, json_file):
    "Compare the route for prefix in vrf against the expectation in json_file"
    command = "show ip route vrf {} {} json".format(vrf, prefix)
    expected = json.loads(open("{}/{}".format(CWD, json_file)).read())
    test_func = functools.partial(topotest.router_json_cmp, router, command, expected)
    _, result = topotest.run_and_expect(test_func, None, count=90, wait=1)
    assert result is None, "{} JSON output mismatches {}".format(router.name, json_file)


def check_route_absent(router, vrf, prefix, protocol):
    "Wait until no route for prefix from protocol is left in vrf"
    command = "show ip route vrf {} {} json".format(vrf, prefix)

    def _check():
        output = router.vtysh_cmd(command, isjson=True)
        routes = [
            route
            for route in output.get(prefix, [])
            if route.get("protocol") == protocol
        ]
        if routes:
            return "{} is still present: {}".format(prefix, routes)
        return None

    _, result = topotest.run_and_expect(_check, None, count=60, wait=1)
    assert result is None, result


def check_route_unresolved(router, vrf, prefix):
    "Wait until the imported route for prefix is left without an active nexthop"
    command = "show ip route vrf {} {} json".format(vrf, prefix)

    def _check():
        output = router.vtysh_cmd(command, isjson=True)
        routes = [
            route
            for route in output.get(prefix, [])
            if route.get("protocol") == "vrf-import"
        ]
        if not routes:
            return "{} was withdrawn instead of going inactive".format(prefix)
        for route in routes:
            if route.get("installed"):
                return "{} is still installed: {}".format(prefix, route)
            active = [
                nexthop
                for nexthop in route.get("nexthops", [])
                if nexthop.get("active")
            ]
            if active:
                return "{} still has active nexthops: {}".format(prefix, active)
        return None

    _, result = topotest.run_and_expect(_check, None, count=60, wait=1)
    assert result is None, result


def config(router, lines):
    "Apply configuration and fail on anything vtysh did not accept"
    output = router.vtysh_cmd(lines)
    for error in ("% Unknown command", "% Ambiguous command", "% Command incomplete"):
        assert error not in output, output
    return output


def test_import_over_ospf_core():
    "Green imports the blue route to h2 over the shortest core path"
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip("skipped because of router(s) failure")

    set_link_states(tgen, r4_ra_up=True, ra_rb_up=True, r1_rb_green_up=True)
    r1 = tgen.gears["r1"]

    step("Blue reaches h2 through ra, at the cost of that path")
    check_route_json(r1, "blue", H2_PREFIX, "r1/show_ip_route_blue-1.json")

    step("Green holds a copy at the import distance, resolved on its own link")
    check_route_json(r1, "green", H2_PREFIX, "r1/show_ip_route_green-1.json")


def test_import_is_not_transitive():
    "Red imports green's own routes but not what green imported from blue"
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip("skipped because of router(s) failure")

    r1 = tgen.gears["r1"]

    step("The green static route reaches red")
    check_route_json(r1, "red", GREEN_STATIC, "r1/show_ip_route_red_static.json")

    step("What green imported from blue stops there")
    check_route_absent(r1, "red", H2_PREFIX, "vrf-import")


def test_import_copies_ecmp_nexthops():
    "An ECMP source route arrives in green with both nexthops resolved"
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip("skipped because of router(s) failure")

    r1 = tgen.gears["r1"]

    step("Make the two transit segments equal cost in blue")
    config(
        r1,
        """
        configure terminal
         interface r1-eth3 vrf blue
          ip ospf cost 10
        """,
    )
    check_route_json(r1, "green", H2_PREFIX, "r1/show_ip_route_green-ecmp.json")

    step("Restore the original cost")
    config(
        r1,
        """
        configure terminal
         interface r1-eth3 vrf blue
          ip ospf cost 100
        """,
    )
    check_route_json(r1, "green", H2_PREFIX, "r1/show_ip_route_green-1.json")


def test_metric_follows_source_vrf():
    "A longer core path raises the metric of the copy without moving it"
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip("skipped because of router(s) failure")

    # Blue now reaches r4 through ra and rb instead of ra alone.  The nexthop
    # is still ra, so only the metric changes.
    set_link_states(tgen, r4_ra_up=False, ra_rb_up=True, r1_rb_green_up=True)
    r1 = tgen.gears["r1"]

    check_route_json(r1, "green", H2_PREFIX, "r1/show_ip_route_green-2.json")


def test_nexthop_follows_source_vrf():
    "When blue changes first hop the copy moves to green's other segment"
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip("skipped because of router(s) failure")

    # Without the ra-rb link, going through ra means a detour over rc, and the
    # expensive direct link to rb wins instead.
    set_link_states(tgen, r4_ra_up=False, ra_rb_up=False, r1_rb_green_up=True)
    r1 = tgen.gears["r1"]

    check_route_json(r1, "green", H2_PREFIX, "r1/show_ip_route_green-3.json")


def test_import_inactive_without_resolver():
    "The copy goes inactive when green loses the route to the blue nexthop"
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip("skipped because of router(s) failure")

    # Blue keeps its route through rb, but green no longer has a subnet the
    # copied nexthop can resolve against.
    set_link_states(tgen, r4_ra_up=False, ra_rb_up=False, r1_rb_green_up=False)
    r1 = tgen.gears["r1"]

    step("Blue is unaffected")
    check_route_json(r1, "blue", H2_PREFIX, "r1/show_ip_route_blue-3.json")

    step("Green keeps the copy but cannot install it")
    check_route_unresolved(r1, "green", H2_PREFIX)


def test_import_recovers_with_resolver():
    "The copy is installed again once green can resolve the nexthop"
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip("skipped because of router(s) failure")

    set_link_states(tgen, r4_ra_up=False, ra_rb_up=False, r1_rb_green_up=True)
    r1 = tgen.gears["r1"]

    check_route_json(r1, "green", H2_PREFIX, "r1/show_ip_route_green-3.json")


def test_import_follows_core_recovery():
    "Restoring the core brings the copy back to the shortest path"
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip("skipped because of router(s) failure")

    set_link_states(tgen, r4_ra_up=True, ra_rb_up=True, r1_rb_green_up=True)
    r1 = tgen.gears["r1"]

    check_route_json(r1, "green", H2_PREFIX, "r1/show_ip_route_green-1.json")


def test_import_route_map():
    "A route-map filters the import and rewrites which uplink green uses"
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip("skipped because of router(s) failure")

    r1 = tgen.gears["r1"]

    step("Filtering out the prefix withdraws the copy")
    config(
        r1,
        """
        configure terminal
         ip prefix-list H2 seq 5 permit {}
         route-map IMPORT deny 10
          match ip address prefix-list H2
         exit
         route-map IMPORT permit 20
         exit
         vrf green
          ip import-vrf blue route-map IMPORT
        """.format(
            H2_PREFIX
        ),
    )
    check_route_absent(r1, "green", H2_PREFIX, "vrf-import")

    step("Rewriting the nexthop pins green to the segment towards rb")
    # Blue still prefers ra.  The rewrite replaces the copied nexthop, so the
    # copy leaves green over the other transit segment.
    config(
        r1,
        """
        configure terminal
         route-map IMPORT permit 10
          match ip address prefix-list H2
          set ip next-hop 10.0.20.6
        """,
    )
    check_route_json(r1, "green", H2_PREFIX, "r1/show_ip_route_green-rewrite.json")

    step("Removing the route-map restores the copied nexthop")
    config(
        r1,
        """
        configure terminal
         vrf green
          ip import-vrf blue
        """,
    )
    check_route_json(r1, "green", H2_PREFIX, "r1/show_ip_route_green-1.json")


def test_import_distance():
    "The import distance decides against a route green has of its own"
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip("skipped because of router(s) failure")

    r1 = tgen.gears["r1"]

    step("A static route below the import distance wins")
    config(
        r1,
        """
        configure terminal
         vrf green
          ip route {} 10.0.91.2 10
        """.format(
            H2_PREFIX
        ),
    )
    check_route_json(r1, "green", H2_PREFIX, "r1/show_ip_route_green-static.json")

    step("Lowering the import distance takes the prefix back")
    config(
        r1,
        """
        configure terminal
         vrf green
          ip import-vrf blue distance 5
        """,
    )
    check_route_json(r1, "green", H2_PREFIX, "r1/show_ip_route_green-distance.json")

    step("Restore the default import and drop the static route")
    config(
        r1,
        """
        configure terminal
         vrf green
          no ip route {} 10.0.91.2 10
          ip import-vrf blue
        """.format(
            H2_PREFIX
        ),
    )
    check_route_json(r1, "green", H2_PREFIX, "r1/show_ip_route_green-1.json")


def test_memory_leak():
    "Run the memory leak test and report results."
    tgen = get_topogen()
    if not tgen.is_memleak_enabled():
        pytest.skip("Memory leak test/report is disabled")

    tgen.report_memory_leaks()


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
