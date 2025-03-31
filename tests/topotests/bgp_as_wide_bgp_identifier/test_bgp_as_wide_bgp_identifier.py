#!/usr/bin/env python
# SPDX-License-Identifier: ISC

#
# test_bgp_as_wide_bgp_identifier.py
# Part of NetDEF Topology Tests
#
# Copyright (c) 2020 by
# Donatas Abraitis <donatas.abraitis@gmail.com>
#

"""
rfc6286: Autonomous-System-Wide Unique BGP Identifier for BGP-4
Test if 'Bad BGP Identifier' notification is sent only to
internal peers (autonomous-system-wide). eBGP peers are not
affected and should work.
"""

import os
import sys
import json
import pytest
import functools

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


def test_bgp_as_wide_bgp_identifier():
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    def _bgp_converge(router):
        output = json.loads(router.vtysh_cmd("show ip bgp neighbor 192.168.255.1 json"))
        expected = {"192.168.255.1": {"bgpState": "Established"}}
        return topotest.json_cmp(output, expected)

    def _bgp_failed(router):
        output = json.loads(router.vtysh_cmd("show ip bgp neighbor 192.168.255.1 json"))
        expected = {
            "192.168.255.1": {
                "lastNotificationReason": "OPEN Message Error/Bad BGP Identifier"
            }
        }
        return topotest.json_cmp(output, expected)

    test_func = functools.partial(_bgp_converge, tgen.gears["r1"])
    _, result = topotest.run_and_expect(test_func, None, count=260, wait=0.5)

    assert result is None, 'Failed to converge: "{}"'.format(tgen.gears["r1"])

    test_func = functools.partial(_bgp_failed, tgen.gears["r3"])
    _, result = topotest.run_and_expect(test_func, None, count=260, wait=0.5)

    assert result is None, 'Bad BGP Identifier notification not sent: "{}"'.format(
        tgen.gears["r3"]
    )


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
