#!/usr/bin/env python
# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright (c) 2026 6WIND

import os
import sys
import json
import pytest
import functools

CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

from lib import topotest
from lib.topogen import Topogen, TopoRouter, get_topogen
from lib.topolog import logger


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

def test_bgp_route_map_comm_list():
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r2 = tgen.gears["r2"]
    r1 = tgen.gears["r1"]

    def _bgp_converge():
        output = json.loads(r2.vtysh_cmd("show ip bgp neighbor 192.168.1.1 json"))

        expected = {
            "192.168.1.1": {
                "bgpState": "Established",
                "addressFamilyInfo": {
                    "ipv4Unicast": {
                        "acceptedPrefixCounter": 4,
                    }
                },
            }
        }
        return topotest.json_cmp(output, expected)

    # Function to verify BGP convergence and received communities
    def _verify_bgp_rib():
        output = json.loads(r2.vtysh_cmd("show bgp ipv4 unicast detail json"))

        # Case 1: test "set comm-list add" (10.1.1.0/24)
        expected = {
            "routes": {
                "10.1.1.0/24": [
                    {
                        "aspath": {"string": "65001"},
                        "community": {"list": ["65001:10", "65001:111"]},
                        "peer": {"peerId": "192.168.1.1", "hostname": "r1"},
                    }
                ]
            }
        }

        if topotest.json_cmp(output, expected) is not None:
            return "ADD case failed: expected communities no present for 10.1.1.0/24"

        # --- Case 2: test "set comm-list delete" (10.1.2.0/24) ---
        #  65001:99 must be removed and 65001:20 keep

        expected_1 = {
            "routes": {
                "10.1.2.0/24": [
                    {
                        "aspath": {"string": "65001"},
                        "community": {"list": ["65001:20"]},
                        "peer": {"peerId": "192.168.1.1", "hostname": "r1"},
                    }
                ]
            }
        }

        expected_2 = {
            "routes": {
                "10.1.2.0/24": [
                    {
                        "aspath": {"string": "65001"},
                        "community": {"list": ["65001:99"]},
                        "peer": {"peerId": "192.168.1.1", "hostname": "r1"},
                    }
                ]
            }
        }

        if (
            topotest.json_cmp(output, expected_1) is not None
            or topotest.json_cmp(output, expected_2) is None
        ):
            return "DELETE case failed: 65001:99 is not removed for 10.1.2.0/24"

        # --- Case 3: test "set comm-list replace" (10.1.3.0/24) ---
        #  65001:30 must be removed and only 65001:222 must be present

        expected_1 = {
            "routes": {
                "10.1.3.0/24": [
                    {
                        "aspath": {"string": "65001"},
                        "community": {"list": ["65001:222"]},
                        "peer": {"peerId": "192.168.1.1", "hostname": "r1"},
                    }
                ]
            }
        }

        expected_2 = {
            "routes": {
                "10.1.3.0/24": [
                    {
                        "aspath": {"string": "65001"},
                        "community": {"list": ["65001:30"]},
                        "peer": {"peerId": "192.168.1.1", "hostname": "r1"},
                    }
                ]
            }
        }

        # --- Case 4: test "set comm-list add + set comm-list del" (10.1.4.0/24) ---
        #  65001:99 must be removed and 65001:20 65001:30 65001:111 must be present

        expected_3 = {
            "routes": {
                "10.1.4.0/24": [
                    {
                        "aspath": {"string": "65001"},
                        "community": {"list": ["65001:20", "65001:30", "65001:111"]},
                        "peer": {"peerId": "192.168.1.1", "hostname": "r1"},
                    }
                ]
            }
        }

        expected_4 = {
            "routes": {
                "10.1.4.0/24": [
                    {
                        "aspath": {"string": "65001"},
                        "community": {"list": ["65001:99"]},
                        "peer": {"peerId": "192.168.1.1", "hostname": "r1"},
                    }
                ]
            }
        }

        if (
            topotest.json_cmp(output, expected_3) is not None
            or topotest.json_cmp(output, expected_4) is None
        ):
            return "ADD DEL case failed: 65001:30 is not replaced by 65001:222 for 10.1.3.0/24"

        return None

    test_func = functools.partial(_bgp_converge)
    _, result = topotest.run_and_expect(test_func, None, count=60, wait=0.5)
    assert result is None, "Can't converge initially"


    success, result = topotest.run_and_expect(_verify_bgp_rib, None, count=15, wait=1)
    assert  result is None, "Failed"

if __name__ == "__main__":
    sys.exit(pytest.main([__file__]))
