#!/usr/bin/env python
# SPDX-License-Identifier: ISC
# Copyright (c) 2023 by
# Abhishek Naik <bhini@amazon.com>
#

"""
Test static route resolution over recursive nexthop
"""

import os
import re
import sys
import json
import pytest
import functools

pytestmark = pytest.mark.staticd

CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

from lib import topotest
from lib.topogen import Topogen, TopoRouter, get_topogen
from lib.common_config import step


def build_topo(tgen):
    for router in range(1, 5):
        tgen.add_router("r{}".format(router))

    switch = tgen.add_switch("s1")
    switch.add_link(tgen.gears["r1"])
    switch.add_link(tgen.gears["r2"])

    switch = tgen.add_switch("s2")
    switch.add_link(tgen.gears["r1"])
    switch.add_link(tgen.gears["r3"])

    switch = tgen.add_switch("s3")
    switch.add_link(tgen.gears["r1"])
    switch.add_link(tgen.gears["r4"])


@pytest.fixture(scope="module")
def tgen(request):
    "Setup/Teardown the environment and provide tgen argument to tests"

    tgen = Topogen(build_topo, request.module.__name__)
    tgen.start_topology()

    router_list = tgen.routers()
    for _, (rname, router) in enumerate(router_list.items(), 1):
        router.load_frr_config(os.path.join(CWD, "{}/frr.conf".format(rname)))
    tgen.start_router()
    yield tgen
    tgen.stop_topology()


def test_static_routing_multipath_nexthops(tgen):
    """
    This test adds a static route with multiple nexthops.
    Each nexthop resolves over a directly connected route configured on an interface
    When one of the interfaces goes down, that nexthop gateway resolves over a blackhole aggregate
    route.
    This should result in that nexthop being withdrawn from the kernel, resulting in one fewer nexthop.
    """
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]

    def _verify_multipath_static_configuration():
        output = json.loads(r1.vtysh_cmd("show ip route static json"))
        reffile = os.path.join(CWD, "r1/baseline_configuration.json")
        with open(reffile) as json_data:
            file_contents = json_data.read()
        expected = json.loads(file_contents)
        return topotest.json_cmp(output, expected)

    test_func = functools.partial(_verify_multipath_static_configuration)

    _, result = topotest.run_and_expect(test_func, None, count=1, wait=5)
    assert result is None, "Baseline configuration failed"

    def _verify_multipath_kernel_routes():
        actual = r1.run("ip route show")
        output = "\n".join(line.strip() for line in actual.splitlines())

        reffile = os.path.join(CWD, "r1/baseline_kernel_routes.txt")
        file_op = open(reffile).read().rstrip()
        expected = "\n".join(line.strip() for line in actual.splitlines())

        return topotest.get_textdiff(
            output,
            expected,
            title1="Actual ip route show",
            title2="Expected ip route show",
        )

    ok, result = topotest.run_and_expect(
        _verify_multipath_kernel_routes, "", count=1, wait=5
    )
    assert ok, result

    def _link_down_and_verify_multipath_kernel_routes():
        r1.peer_link_enable("r1-eth0", False)

        actual = r1.run("ip route show")
        output = "\n".join(line.strip() for line in actual.splitlines())

        reffile = os.path.join(CWD, "r1/eth0_down_kernel_routes.txt")
        file_op = open(reffile).read().rstrip()
        expected = "\n".join(line.strip() for line in actual.splitlines())
        return topotest.get_textdiff(
            output,
            expected,
            title1="Actual ip route show",
            title2="Expected ip route show",
        )

    ok, result = topotest.run_and_expect(
        _link_down_and_verify_multipath_kernel_routes, "", count=1, wait=5
    )
    assert ok, result
