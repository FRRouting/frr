#!/usr/bin/env python
# SPDX-License-Identifier: ISC

#
# Copyright (c) 2022 by
# Donatas Abraitis <donatas@opensourcerouting.org>
#

"""
Check if labeled-unicast works correctly with default-originate.
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
from lib.common_config import step

pytestmark = [pytest.mark.bgpd]


def build_topo(tgen):
    for routern in range(1, 3):
        tgen.add_router("r{}".format(routern))

    switch = tgen.add_switch("s1")
    switch.add_link(tgen.gears["r1"])
    switch.add_link(tgen.gears["r2"])


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


def test_bgp_labeled_unicast_default_originate():
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]
    r2 = tgen.gears["r2"]

    def _bgp_check_advertised_routes():
        output = json.loads(
            r1.vtysh_cmd(
                "show bgp ipv4 labeled-unicast neighbors 192.168.12.2 advertised-routes json"
            )
        )
        expected = {
            "bgpOriginatingDefaultNetwork": "0.0.0.0/0",
        }
        return topotest.json_cmp(output, expected)

    test_func = functools.partial(_bgp_check_advertised_routes)
    _, result = topotest.run_and_expect(test_func, None, count=60, wait=0.5)
    assert result is None, "Failed to advertise default route for labeled-unicast"

    def _bgp_check_received_ipv4_routes():
        output = json.loads(
            r2.vtysh_cmd("show bgp ipv4 labeled-unicast 0.0.0.0/0 json")
        )
        expected = {
            "paths": [
                {
                    "valid": True,
                    "metric": 666,
                    "community": {
                        "string": "65001:65001",
                    },
                    "remoteLabel": 0,
                }
            ]
        }
        return topotest.json_cmp(output, expected)

    test_func = functools.partial(_bgp_check_received_ipv4_routes)
    _, result = topotest.run_and_expect(test_func, None, count=60, wait=0.5)
    assert result is None, "Failed to receive IPv4 default route for labeled-unicast"

    def _bgp_check_received_ipv6_routes():
        output = json.loads(r2.vtysh_cmd("show bgp ipv6 labeled-unicast ::/0 json"))
        expected = {
            "paths": [
                {
                    "valid": True,
                    "metric": 666,
                    "community": {
                        "string": "65001:65001",
                    },
                    "remoteLabel": 2,
                }
            ]
        }
        return topotest.json_cmp(output, expected)

    test_func = functools.partial(_bgp_check_received_ipv6_routes)
    _, result = topotest.run_and_expect(test_func, None, count=60, wait=0.5)
    assert result is None, "Failed to receive IPv6 default route for labeled-unicast"


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
