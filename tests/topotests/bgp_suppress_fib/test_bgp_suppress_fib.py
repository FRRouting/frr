#!/usr/bin/env python
# SPDX-License-Identifier: ISC

#
# test_bgp_suppress_fib.py
#
# Copyright (c) 2019 by
#

"""
"""

import os
import sys
import json
import pytest
from functools import partial
from time import sleep
from lib.topolog import logger

CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

# pylint: disable=C0413
from lib import topotest
from lib.topogen import Topogen, TopoRouter, get_topogen

pytestmark = [pytest.mark.bgpd]


def build_topo(tgen):
    for routern in range(1, 4):
        tgen.add_router("r{}".format(routern))

    switch = tgen.add_switch("s1")
    switch.add_link(tgen.gears["r1"])
    switch.add_link(tgen.gears["r2"])

    switch = tgen.add_switch("s2")
    switch.add_link(tgen.gears["r2"])
    switch.add_link(tgen.gears["r3"])


def setup_module(mod):
    tgen = Topogen(build_topo, mod.__name__)
    tgen.start_topology()

    router_list = tgen.routers()

    for i, (rname, router) in enumerate(router_list.items(), 1):
        router.load_config(
            TopoRouter.RD_ZEBRA, os.path.join(CWD, "{}/zebra.conf".format(rname))
        )
        router.load_config(
            TopoRouter.RD_BGP, os.path.join(CWD, "{}/bgpd.conf".format(rname))
        )

    tgen.start_router()


def teardown_module(mod):
    tgen = get_topogen()
    tgen.stop_topology()


def test_bgp_route():
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r3 = tgen.gears["r3"]

    json_file = "{}/r3/v4_route.json".format(CWD)
    expected = json.loads(open(json_file).read())

    test_func = partial(
        topotest.router_json_cmp,
        r3,
        "show ip route 40.0.0.0 json",
        expected,
    )
    _, result = topotest.run_and_expect(test_func, None, count=20, wait=0.5)
    assertmsg = '"r3" JSON output mismatches'
    assert result is None, assertmsg

    json_file = "{}/r3/v4_route2.json".format(CWD)
    expected = json.loads(open(json_file).read())

    test_func = partial(
        topotest.router_json_cmp,
        r3,
        "show ip route 50.0.0.0 json",
        expected,
    )
    _, result = topotest.run_and_expect(test_func, None, count=10, wait=0.5)
    assert result is None, assertmsg

    json_file = "{}/r3/v4_route3.json".format(CWD)
    expected = json.loads(open(json_file).read())

    test_func = partial(
        topotest.router_json_cmp,
        r3,
        "show ip route 60.0.0.0 json",
        expected,
    )
    _, result = topotest.run_and_expect(test_func, None, count=10, wait=0.5)
    assert result is None, assertmsg


def test_bgp_better_admin_won():
    "A better Admin distance protocol may come along and knock us out"

    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r2 = tgen.gears["r2"]
    r2.vtysh_cmd("conf\nip route 40.0.0.0/8 10.0.0.10")

    json_file = "{}/r2/v4_override.json".format(CWD)
    expected = json.loads(open(json_file).read())

    logger.info(expected)
    test_func = partial(
        topotest.router_json_cmp, r2, "show ip route 40.0.0.0 json", expected
    )

    _, result = topotest.run_and_expect(test_func, None, count=10, wait=0.5)
    assertmsg = '"r2" static route did not take over'
    assert result is None, assertmsg

    r3 = tgen.gears["r3"]

    json_file = "{}/r3/v4_override.json".format(CWD)
    expected = json.loads(open(json_file).read())

    test_func = partial(
        topotest.router_json_cmp, r3, "show ip route 40.0.0.0 json", expected
    )

    _, result = topotest.run_and_expect(test_func, None, count=30, wait=1)
    assertmsg = '"r3" route to 40.0.0.0 should have been lost'
    assert result is None, assertmsg

    r2.vtysh_cmd("conf\nno ip route 40.0.0.0/8 10.0.0.10")

    json_file = "{}/r3/v4_route.json".format(CWD)
    expected = json.loads(open(json_file).read())

    test_func = partial(
        topotest.router_json_cmp,
        r3,
        "show ip route 40.0.0.0 json",
        expected,
    )
    _, result = topotest.run_and_expect(test_func, None, count=30, wait=1)
    assertmsg = '"r3" route to 40.0.0.0 did not come back'
    assert result is None, assertmsg


def test_bgp_allow_as_in():
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r2 = tgen.gears["r2"]

    config_file = "{}/r2/bgpd.allowas_in.conf".format(CWD)
    r2.run("vtysh -f {}".format(config_file))

    json_file = "{}/r2/bgp_ipv4_allowas.json".format(CWD)
    expected = json.loads(open(json_file).read())

    test_func = partial(
        topotest.router_json_cmp,
        r2,
        "show bgp ipv4 uni 192.168.1.1/32 json",
        expected,
    )
    _, result = topotest.run_and_expect(test_func, None, count=10, wait=0.5)
    assertmsg = '"r2" static redistribution failed into bgp'
    assert result is None, assertmsg

    r1 = tgen.gears["r1"]

    json_file = "{}/r1/bgp_ipv4_allowas.json".format(CWD)
    expected = json.loads(open(json_file).read())

    test_func = partial(
        topotest.router_json_cmp,
        r1,
        "show bgp ipv4 uni 192.168.1.1/32 json",
        expected,
    )

    _, result = topotest.run_and_expect(test_func, None, count=30, wait=1)
    assertmsg = '"r1" 192.168.1.1/32 route should have arrived'
    assert result is None, assertmsg

    r2.vtysh_cmd("conf\nno ip route 192.168.1.1/32 10.0.0.10")

    json_file = "{}/r2/no_bgp_ipv4_allowas.json".format(CWD)
    expected = json.loads(open(json_file).read())

    test_func = partial(
        topotest.router_json_cmp,
        r2,
        "show bgp ipv4 uni 192.168.1.1/32 json",
        expected,
    )

    _, result = topotest.run_and_expect(test_func, None, count=30, wait=1)
    assertmsg = '"r2" 192.168.1.1/32 route should be gone'
    assert result is None, assertmsg


def test_local_vs_non_local():
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r2 = tgen.gears["r2"]

    output = json.loads(r2.vtysh_cmd("show bgp ipv4 uni 60.0.0.0/24 json"))
    paths = output["paths"]
    for i in range(len(paths)):
        if "fibPending" in paths[i]:
            assert False, "Route 60.0.0.0/24 should not have fibPending"


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
