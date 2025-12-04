#!/usr/bin/env python
# SPDX-License-Identifier: ISC

#
# Copyright (c) 2025, Palo Alto Networks, Inc.
# Enke Chen <enchen@paloaltonetworks.com>
#

"""
When a static route configured as backup (based-on the admin-distance) to an
EBGP route is redistributed to BGP, make sure the EBGP route is always favored
regardless whether the static route or the EBGP route is received first.

Case 1: static route first, and then EBGP route.
Case 2: EBGP route first, and then static route.
"""

import os
import sys
import time
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

    for _, (rname, router) in enumerate(router_list.items(), 1):
        router.load_frr_config(os.path.join(CWD, "{}/frr.conf".format(rname)))

    tgen.start_router()


def teardown_module(mod):
    tgen = get_topogen()
    tgen.stop_topology()


def test_bgp_redistribute_ebgp():
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]
    r2 = tgen.gears["r2"]

    def _bgp_check_neighbor(router, neighbor):
        output = json.loads(
            router.vtysh_cmd("show bgp neighbor {} json".format(neighbor))
        )
        expected = {
            neighbor:{
                "bgpState": "Established",
            }
        }
        return topotest.json_cmp(output, expected)

    def _bgp_check_route_sourced(router, prefix):
        output = json.loads(
            router.vtysh_cmd("show bgp ipv4 unicast {} json".format(prefix))
        )
        expected = {"paths": [{"valid": True, "sourced": True}]}
        return topotest.json_cmp(output, expected)

    def _bgp_check_route_bestpath(router, prefix, neighbor):
        output = json.loads(
            router.vtysh_cmd("show bgp ipv4 unicast {} json".format(prefix))
        )
        expected = {
            "paths":[
                {
                    "bestpath":{
                        "overall":True,
                    },
                    "peer":{
                        "peerId":neighbor,
                    }
                }
            ]
        }
        return topotest.json_cmp(output, expected)

    def _check_ip_route_selected(router, prefix):
        output = json.loads(
            router.vtysh_cmd("show ip route {} json".format(prefix))
        )
        expected = {
            prefix:[
                {
                    "prefix": prefix,
                    "protocol": "bgp",
                    "selected": True,
                    "distance": 20,
                },
                {
                    "prefix": prefix,
                    "protocol": "static",
                    "distance": 30,
                }
            ]
        }
        return topotest.json_cmp(output, expected)


    step("r1: configure the backup static route")
    r1.vtysh_cmd(
        """
    configure terminal
        ip route 10.0.50.0/24 Null0 30
    """
    )

    step("r1: check if the static route is redistributed to bgp")
    test_func = functools.partial(_bgp_check_route_sourced, r1, "10.0.50.0/24")
    _, result = topotest.run_and_expect(test_func, None, count=30, wait=1)
    assert result is None, "static route 10.0.50.0/24 not redistributed in bgp"

    step("r1: check BGP session is established with r2")
    test_func = functools.partial(_bgp_check_neighbor, r1, "192.168.12.2")
    _, result = topotest.run_and_expect(test_func, None, count=30, wait=1)
    assert result is None, "BGP neighbor 192.168.12.2 not established"

    step("r2: config the static route")
    r2.vtysh_cmd(
        """
    configure terminal
        ip route 10.0.50.0/24 Null0
    """
    )

    step("r1: verify the ebgp route is favored in BGP")
    test_func = functools.partial(_bgp_check_route_bestpath, r1, "10.0.50.0/24", "192.168.12.2")
    _, result = topotest.run_and_expect(test_func, None, count=30, wait=1)
    assert result is None, "Static route first and then EBGP, but EBGP route not favored in BGP"

    step("r1: verify the ebgp route is favored in RIB")
    test_func = functools.partial(_check_ip_route_selected, r1, "10.0.50.0/24")
    _, result = topotest.run_and_expect(test_func, None, count=30, wait=1)
    assert result is None, "static route first and then EBGP, but EBGP route not favored in RIB"

    step("r1: delete, and then add the backup static route")
    r1.vtysh_cmd(
        """
    configure terminal
        no ip route 10.0.50.0/24 Null0 30
    """
    )

    r1.vtysh_cmd(
        """
    configure terminal
        ip route 10.0.50.0/24 Null0 30
    """
    )

    step("r1: verify the ebgp route is still favored")
    test_func = functools.partial(_check_ip_route_selected, r1, "10.0.50.0/24")
    _, result = topotest.run_and_expect(test_func, None, count=30, wait=1)
    assert result is None, "EBGP first and then static route, but EBGP route not favored"


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
