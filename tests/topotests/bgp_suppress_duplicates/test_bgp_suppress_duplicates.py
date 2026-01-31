#!/usr/bin/env python
# SPDX-License-Identifier: ISC

#
# Copyright (c) 2026, Palo Alto Networks, Inc.
# Enke Chen <enchen@paloaltonetworks.com>
#

"""
This is to verify "bgp suppress-duplicates" functionality. The route is
sourced by network command, and its attributes are set by route-map.

Note: this tests requires these two fixes: PR #20325 and PR #20533.

Note: The "route-map delay-timer" is 5 seconds as the default, and is
configured as 1 in this test. It's necessary to wait for more than the
delay-timer for the route-map to take effect.

TC 1: Attribute A --> Attribute A.

Change local-pref from 500 to 600.
No update should go out.

TC 2: Attribute A --> Attribute B --> Attribute A.

First change metric from 2000 --> 3000 to force update.

Then within MRAI: change metrics 3000 --> 2000 --> 3000.
No update should go out.

TC 3: Attribute A --> Attribute B --> Attribute B.

First change metric from 3000 --> 2000 to force update first.

Then within MRAI: metric 2000 --> 3000, and then change local-pref 600 --> 500.
Only one update (instead of two) should go out.

TC 4: Attribute A --> Withdraw --> Attribute A

First change metric from 3000 --> 2000 to force update first.

Then within MRAI: delete the route, and then add the route.
Route withdraw should be queued, and then cancelled.
No update should go out.
"""

import os
import sys
import time
import json
import pytest
import functools
from time import sleep

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

def test_bgp_suppress_duplicates():
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


    def _bgp_get_mrai_expire_secs(router, neighbor):
        output = json.loads(
            router.vtysh_cmd("show bgp neighbor {} json".format(neighbor))
        )
        expire_msecs = output[neighbor].get("mraiTimerExpireInMsecs")
        if expire_msecs is not None:
            expire_secs = 1 + (int(expire_msecs) / 1000)
        else:
            expire_secs = 0
        return expire_secs

    def _bgp_get_duplicate_count(router, neighbor):
        output = json.loads(
            router.vtysh_cmd("show bgp neighbors {} json".format(neighbor))
        )
        dup_count = []
        dup_count.append(output[neighbor]["addressFamilyInfo"]["ipv4Unicast"]["receivedPrefixDup"])
        return dup_count

    def _bgp_check_route_attributes(router, prefix, neighbor, local_pref, metric):
        output = json.loads(
            router.vtysh_cmd("show bgp ipv4 unicast {} json".format(prefix))
        )
        expected = {
            "prefix":prefix,
            "paths":[
                {
                    "metric":metric,
                    "locPrf":local_pref,
                    "peer":{
                        "peerId":neighbor,
                    }
                }
            ]
        }
        return topotest.json_cmp(output, expected)

    step("Check BGP session is established")
    test_func = functools.partial(_bgp_check_neighbor, r1, "192.168.12.2")
    _, result = topotest.run_and_expect(test_func, None, count=30, wait=1)
    assert result is None, "BGP neighbor 192.168.12.2 not established"

    dup_string = _bgp_get_duplicate_count(r2, "192.168.12.1")
    dup_before = int(dup_string[0])


    step("TC: Attribute A --> Attribute A")
    r1.vtysh_cmd(
        """
    configure terminal
        route-map rmap-network permit 10
         set local-preference 600
    """
    )

    # For route-map to take effect
    sleep(2)

    secs = _bgp_get_mrai_expire_secs(r1, "192.168.12.2");
    if secs > 0:
        sleep(secs)

    step("Check route after MRAI is expired")
    dup_string = _bgp_get_duplicate_count(r2, "192.168.12.1")
    dup_after = int(dup_string[0])
    assert dup_before == dup_after, "BGP dup count changed from {} to {}".format(
        dup_before, dup_after)

    result = _bgp_check_route_attributes(r2, "5.5.5.5/32", "192.168.12.1", 100, 2000)
    assert result is None, "BGP route attributes mismatch"


    step("TC: Attribute A --> Attribute B --> Attribute A")
    r1.vtysh_cmd(
        """
    configure terminal
        route-map rmap-network permit 10
         set metric 3000
    """
    )

    # For route-map to take effect
    sleep(2)

    step("Make sure MRAI is expired, and update is sent out")
    secs = _bgp_get_mrai_expire_secs(r1, "192.168.12.2");
    if secs > 0:
        sleep(secs)

    r1.vtysh_cmd(
        """
    configure terminal
        route-map rmap-network permit 10
         set metric 2000
    """
    )

    # For route-map to take effect
    sleep(2)

    r1.vtysh_cmd(
        """
    configure terminal
        route-map rmap-network permit 10
         set metric 3000
    """
    )

    # For route-map to take effect
    sleep(2)

    secs = _bgp_get_mrai_expire_secs(r1, "192.168.12.2");
    if secs > 0:
        sleep(secs)

    step("Check route after MRAI is expired")
    dup_string = _bgp_get_duplicate_count(r2, "192.168.12.1")
    dup_after = int(dup_string[0])
    assert dup_before == dup_after, "BGP dup count changed from {} to {}".format(
        dup_before, dup_after)

    result = _bgp_check_route_attributes(r2, "5.5.5.5/32", "192.168.12.1", 100, 3000)
    assert result is None, "BGP route attributes mismatch"


    step("TC: Attribute A --> Attribute B --> Attribute B")
    r1.vtysh_cmd(
        """
    configure terminal
        route-map rmap-network permit 10
         set metric 2000
    """
    )

    # For route-map to take effect
    sleep(2)

    step("Make sure MRAI is expired, and update is sent out")
    secs = _bgp_get_mrai_expire_secs(r1, "192.168.12.2");
    if secs > 0:
        sleep(secs)

    r1.vtysh_cmd(
        """
    configure terminal
        route-map rmap-network permit 10
         set metric 3000
    """
    )

    # For route-map to take effect
    sleep(2)

    r1.vtysh_cmd(
        """
    configure terminal
        route-map rmap-network permit 10
         set local-preference 500
    """
    )

    # For route-map to take effect
    sleep(2)

    secs = _bgp_get_mrai_expire_secs(r1, "192.168.12.2");
    if secs > 0:
        sleep(secs)

    step("Check route after MRAI is expired")
    dup_string = _bgp_get_duplicate_count(r2, "192.168.12.1")
    dup_after = int(dup_string[0])
    assert dup_before == dup_after, "BGP dup count changed from {} to {}".format(
        dup_before, dup_after)

    result = _bgp_check_route_attributes(r2, "5.5.5.5/32", "192.168.12.1", 100, 3000)
    assert result is None, "BGP route attributes mismatch"


    step("TC: Attribute A --> Withdraw --> Attribute A")
    r1.vtysh_cmd(
        """
    configure terminal
        route-map rmap-network permit 10
         set metric 2000
    """
    )

    # For route-map to take effect
    sleep(2)

    step("Make sure MRAI is expired, and update is sent out")
    secs = _bgp_get_mrai_expire_secs(r1, "192.168.12.2");
    if secs > 0:
        sleep(secs)

    r1.vtysh_cmd(
        """
    configure terminal
        router bgp
         address-family ipv4 unicast
          no network 5.5.5.5/32 route-map rmap-network
    """
    )

    # For route-map to take effect
    sleep(2)

    r1.vtysh_cmd(
        """
    configure terminal
        router bgp
         address-family ipv4 unicast
          network 5.5.5.5/32 route-map rmap-network
    """
    )

    # For route-map to take effect
    sleep(2)

    secs = _bgp_get_mrai_expire_secs(r1, "192.168.12.2");
    if secs > 0:
        sleep(secs)

    step("Check route after MRAI is expired")
    dup_string = _bgp_get_duplicate_count(r2, "192.168.12.1")
    dup_after = int(dup_string[0])
    assert dup_before == dup_after, "BGP dup count changed from {} to {}".format(
        dup_before, dup_after)

    result = _bgp_check_route_attributes(r2, "5.5.5.5/32", "192.168.12.1", 100, 2000)
    assert result is None, "BGP route is missing or attributes mismatch"


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
