#!/usr/bin/env python
# SPDX-License-Identifier: ISC

#
# test_zebra_nhg_inactive_skip.py
#
# Copyright (c) 2026 by
# Alibaba Inc.
# Yuqing Zhao
#

"""
test_zebra_nhg_inactive_skip.py:

Verify that when one nexthop in a nexthop group becomes inactive (due to
recursive resolution failure), the remaining active nexthops can still be
installed into the kernel without EINVAL failure.

Topology:
    r1 ---eth0--- s1
    r1 ---eth1--- s2

r1 has an ECMP static route 10.0.0.0/24 with recursive nexthops 172.16.1.1
and 172.16.2.1. Each recursive nexthop is resolved via a /32 route:
  172.16.1.1/32 via 192.168.1.2 (eth0)
  172.16.2.1/32 via 192.168.2.2 (eth1)

When the resolving route for 172.16.2.1 is removed, that recursive nexthop
becomes unresolvable (inactive). The test verifies that the route remains
installed with the surviving nexthop and no kernel NHG programming error.
"""

import os
import sys
import json
import pytest

CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

# pylint: disable=C0413
from lib import topotest
from lib.topogen import Topogen, TopoRouter, get_topogen
from lib.topolog import logger
from lib.common_config import step

pytestmark = [pytest.mark.staticd]


def build_topo(tgen):
    "Build function"
    tgen.add_router("r1")

    switch = tgen.add_switch("s1")
    switch.add_link(tgen.gears["r1"])

    switch = tgen.add_switch("s2")
    switch.add_link(tgen.gears["r1"])


def setup_module(mod):
    "Sets up the pytest environment"
    tgen = Topogen(build_topo, mod.__name__)
    tgen.start_topology()

    router_list = tgen.routers()
    for rname, router in router_list.items():
        router.load_frr_config(
            os.path.join(CWD, "{}/frr.conf".format(rname)),
            [
                (TopoRouter.RD_ZEBRA, None),
                (TopoRouter.RD_STATIC, None),
            ],
        )

    tgen.start_router()


def teardown_module():
    "Teardown the pytest environment"
    tgen = get_topogen()
    tgen.stop_topology()


def test_ecmp_route_installed():
    "Test that the ECMP static route is installed with both recursive nexthops"
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]

    step("Verify ECMP route 10.0.0.0/24 is installed with 2 FIB nexthops")

    def check_ecmp_installed():
        output = r1.vtysh_cmd("show ip route 10.0.0.0/24 json")
        try:
            route_json = json.loads(output)
        except json.JSONDecodeError:
            return "Failed to parse JSON"

        if "10.0.0.0/24" not in route_json:
            return "Route 10.0.0.0/24 not found"

        route = route_json["10.0.0.0/24"][0]
        if not route.get("installed", False):
            return "Route not installed"

        nexthops = route.get("nexthops", [])
        fib_nhs = [nh for nh in nexthops if nh.get("fib", False)]
        if len(fib_nhs) != 2:
            return "Expected 2 FIB nexthops, got {}".format(len(fib_nhs))

        return None

    _, result = topotest.run_and_expect(check_ecmp_installed, None, count=30, wait=1)
    assert result is None, "ECMP route not properly installed: {}".format(result)


def test_nhg_after_resolve_removed():
    "Test that NHG installs successfully after one recursive nexthop becomes unresolvable"
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]

    step("Remove resolving route for 172.16.2.1 to make it unresolvable")
    r1.vtysh_cmd("configure terminal\nno ip route 172.16.2.1/32 192.168.2.2\nexit")

    step("Verify route remains installed with only the active nexthop")

    def check_route_with_one_nh():
        output = r1.vtysh_cmd("show ip route 10.0.0.0/24 json")
        try:
            route_json = json.loads(output)
        except json.JSONDecodeError:
            return "Failed to parse JSON"

        if "10.0.0.0/24" not in route_json:
            return "Route 10.0.0.0/24 not found"

        route = route_json["10.0.0.0/24"][0]
        if not route.get("installed", False):
            return "Route not installed - NHG kernel programming may have failed"

        nexthops = route.get("nexthops", [])
        fib_nhs = [nh for nh in nexthops if nh.get("fib", False)]
        if len(fib_nhs) != 1:
            return "Expected 1 FIB nexthop, got {}".format(len(fib_nhs))

        return None

    _, result = topotest.run_and_expect(
        check_route_with_one_nh, None, count=30, wait=1
    )
    assert result is None, "Route not correctly installed after nexthop became inactive: {}".format(
        result
    )

    step("Verify no NHG kernel install errors in zebra log")
    log_file = os.path.join(tgen.logdir, "r1", "zebra.log")
    assert os.path.isfile(log_file), "zebra log file {} not found".format(log_file)
    with open(log_file) as f:
        error_count = sum(1 for line in f if "Failed to install Nexthop" in line)
    assert error_count == 0, "Found {} NHG kernel install failures in zebra log".format(
        error_count
    )


def test_nhg_after_resolve_restored():
    "Test that NHG restores both nexthops after resolving route is re-added"
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]

    step("Re-add resolving route for 172.16.2.1")
    r1.vtysh_cmd("configure terminal\nip route 172.16.2.1/32 192.168.2.2\nexit")

    step("Verify route restores with 2 nexthops")

    def check_ecmp_restored():
        output = r1.vtysh_cmd("show ip route 10.0.0.0/24 json")
        try:
            route_json = json.loads(output)
        except json.JSONDecodeError:
            return "Failed to parse JSON"

        if "10.0.0.0/24" not in route_json:
            return "Route 10.0.0.0/24 not found"

        route = route_json["10.0.0.0/24"][0]
        if not route.get("installed", False):
            return "Route not installed"

        nexthops = route.get("nexthops", [])
        fib_nhs = [nh for nh in nexthops if nh.get("fib", False)]
        if len(fib_nhs) != 2:
            return "Expected 2 FIB nexthops after restore, got {}".format(len(fib_nhs))

        return None

    _, result = topotest.run_and_expect(check_ecmp_restored, None, count=30, wait=1)
    assert result is None, "ECMP route not restored after resolving route re-added: {}".format(result)
