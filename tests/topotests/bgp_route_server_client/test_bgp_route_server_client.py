#!/usr/bin/env python
# SPDX-License-Identifier: ISC

# Copyright (c) 2021 by
# Donatas Abraitis <donatas.abraitis@gmail.com>
#

"""
Test if we send ONLY GUA address for route-server-client peers.
"""

import os
import sys
import json
import pytest
from functools import partial
import functools

pytestmark = [pytest.mark.bgpd]

CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

# pylint: disable=C0413
from lib import topotest
from lib.topogen import Topogen, TopoRouter, get_topogen


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

    for _, (rname, router) in enumerate(router_list.items(), 1):
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


def test_converge_protocols():
    "Wait for protocol convergence"

    tgen = get_topogen()
    # Don't run this test if we have any failure.
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r2 = tgen.gears["r2"]
    ref_file = "{}/{}/show_bgp_ipv6_summary.json".format(CWD, r2.name)
    expected = json.loads(open(ref_file).read())

    test_func = partial(
        topotest.router_json_cmp,
        r2,
        "show bgp view RS ipv6 summary json",
        expected,
    )
    _, res = topotest.run_and_expect(test_func, None, count=30, wait=1)
    assertmsg = "{}: BGP convergence failed".format(r2.name)
    assert res is None, assertmsg


def test_bgp_route_server_client_step1():
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    router_list = tgen.routers().values()
    for router in router_list:
        if router.name == "r2":
            # route-server
            cmd = "show bgp view RS ipv6 unicast json"
        else:
            cmd = "show bgp ipv6 unicast json"

        # router.cmd("vtysh -c 'sh bgp ipv6 json' >/tmp/show_bgp_ipv6_%s.json" % router.name)
        ref_file = "{}/{}/show_bgp_ipv6.json".format(CWD, router.name)
        expected = json.loads(open(ref_file).read())

        test_func = partial(
            topotest.router_json_cmp,
            router,
            cmd,
            expected,
        )
        _, res = topotest.run_and_expect(test_func, None, count=30, wait=1)
        assertmsg = "{}: BGP IPv6 table failure".format(router.name)
        assert res is None, assertmsg


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
