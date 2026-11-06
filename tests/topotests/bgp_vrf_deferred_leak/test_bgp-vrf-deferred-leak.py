#!/usr/bin/env python
# SPDX-License-Identifier: ISC

#
# test_bgp-vrf-deferred-leak.py
#
# Copyright (c) 2026 VyOS, Inc; Kyrylo Yatsenko
#

"""
test_bgp-vrf-deferred-leak.py: Test vrf route leaking for deferred routes
"""

import os
import sys
from functools import partial
import pytest

CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

# pylint: disable=C0413
from lib import topotest
from lib.topogen import Topogen, get_topogen
from lib.topolog import logger

pytestmark = [pytest.mark.bgpd]


def build_topo(tgen):
    "Build function"
    tgen.add_router("r1")


def setup_module(mod):
    tgen = Topogen(build_topo, mod.__name__)
    tgen.start_topology()

    router_list = tgen.routers()

    for router in router_list.values():
        router.run("/bin/bash {}/setup_vrfs".format(CWD))
        router.load_frr_config()

    tgen.start_router()


def teardown_module(mod):
    tgen = get_topogen()
    tgen.stop_topology()


# Check deferred leaks after default bgp instance is created,
# see comment to vpn_leak_postchange_all
def test_vrf_deferred_route_leak():
    logger.info(
        "Ensure that deferred route leaks are processed properly (the ones exported before default bgp router is created)"
    )
    tgen = get_topogen()
    # Don't run this test if we have any failure.
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]

    # Wait for all preconditions:
    # * Wait for route to be known to bgp vrf instance
    # * Wait for all known conditions that can call `vpn_leak_postchange_all`
    #   asynchronously after default bgp instance creation so that we really
    #   check that deferred leaks are processed properly
    # * Recheck that default bgp instance is not created yet
    wait_data = [
        # route in NONNA is known to bgp
        {
            "cmd": "show bgp vrf NONNA ipv4 unicast json",
            "expect": {"routes": {"10.0.5.0/24": [{"valid": True}]}},
            "msg": "Initial route in BGP VRF didn't appear",
        },
        # call in `bgp_zebra_label_manager_connect`
        {
            "cmd": "show bgp labelpool summary json",
            "expect": {"reconnects": 1},
            "msg": "Wait for label manager connect failed",
        },
        # call in `bgp_ifp_up`
        {
            "cmd": "show interface NONNA json",
            "expect": {"NONNA": {"operationalStatus": "up"}},
            "msg": "Wait for NONNA vrf interface to come up failed",
        },
        # Ensure currently there is no default bgp instance
        {
            "cmd": "show bgp vrfs json",
            "expect": {"vrfs": {"default": None}},
            "msg": "bgp default instance is unexpectedly present before the test",
        },
    ]

    for data in wait_data:
        cmd = data["cmd"]
        expect = data["expect"]
        msg = data["msg"]

        test_func = partial(
            topotest.router_json_cmp, r1, cmd, expect
        )
        result, diff = topotest.run_and_expect(test_func, None, count=15, wait=1)
        assert result, f"{msg}:\n{diff}"

    # Now enable bgp router in default VRF
    r1.vtysh_cmd("configure terminal\nrouter bgp 65500")

    # Verify deferred route leak was processed properly
    expect = {
        "routes": {
            "routeDistinguishers": {
                "65500:100": {
                    "10.0.5.0/24": [{"valid": True}],
                },
            },
        }
    }
    test_func = partial(topotest.router_json_cmp, r1, "show bgp ipv4 vpn json", expect)
    result, diff = topotest.run_and_expect(test_func, None, count=15, wait=1)
    assert result, "BGP VRF deferred route leak check failed:\n{}".format(diff)


def test_memory_leak():
    "Run the memory leak test and report results."
    tgen = get_topogen()
    if not tgen.is_memleak_enabled():
        pytest.skip("Memory leak test/report is disabled")

    tgen.report_memory_leaks()


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
