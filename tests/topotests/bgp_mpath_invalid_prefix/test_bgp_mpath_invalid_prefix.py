#!/usr/bin/env python
# SPDX-License-Identifier: ISC

#
# test_bgp_mpath_invalid_prefix.py
# Part of NetDEF Topology Tests
#
# Test that when a BGP route becomes invalid (e.g. network statement
# no longer has a matching local interface), the path is NOT incorrectly
# marked with the multipath flag. See issue #21103.
#
# Scenario:
# - r1 has "network 200.1.12.0/24" but no interface in that subnet (invalid).
# - Add dummy interface with 200.1.12.1/24 on r1 -> route becomes valid.
# - Remove that address -> route becomes invalid again.
# - Assert the path for 200.1.12.0/24 does not show multipath: true when invalid.
#

import json
import os
import sys
import pytest

CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

# pylint: disable=C0413
from lib import topotest
from lib.topogen import Topogen, get_topogen
from lib.topolog import logger
from lib.common_config import create_interface_in_kernel, step

pytestmark = [pytest.mark.bgpd]

DUMMY_IF = "dum0"
NETWORK_PREFIX = "200.1.12.0/24"
NETWORK_IP = "200.1.12.1/24"


def build_topo(tgen):
    tgen.add_router("r1")
    tgen.add_router("r2")
    switch = tgen.add_switch("s1")
    switch.add_link(tgen.gears["r1"])
    switch.add_link(tgen.gears["r2"])


def setup_module(mod):
    tgen = Topogen(build_topo, mod.__name__)
    tgen.start_topology()

    router_list = tgen.routers()
    for rname, router in router_list.items():
        router.load_frr_config(os.path.join(CWD, "{}/frr.conf".format(rname)))

    tgen.start_router()


def teardown_module(mod):
    tgen = get_topogen()
    r1 = tgen.gears.get("r1")
    if r1:
        r1.run("ip link show {} >/dev/null 2>&1 && ip link del {}".format(DUMMY_IF, DUMMY_IF))
    tgen.stop_topology()


def _get_bgp_prefix_json(router, prefix):
    """Return parsed JSON for 'show bgp ipv4 unicast <prefix> json' or None."""
    try:
        out = router.vtysh_cmd("show bgp ipv4 unicast {} json".format(prefix), isjson=True)
        return out
    except (ValueError, TypeError):
        return None


def test_bgp_mpath_flag_not_set_when_route_invalid():
    """
    When the only path to a prefix becomes invalid (e.g. network statement
    no longer has a matching connected subnet), that path must not be
    marked as multipath. Regression test for #21103.
    """
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]

    step("Ensure 200.1.12.0/24 is in BGP but invalid (no matching interface)")
    # Initially r1 has network 200.1.12.0/24 but no interface in that subnet
    output = _get_bgp_prefix_json(r1, NETWORK_PREFIX)
    assert output is not None, "BGP should have entry for {}".format(NETWORK_PREFIX)
    paths = output.get("paths", [])
    assert len(paths) >= 1, "Expected at least one path (local)"

    step("Add dummy interface with 200.1.12.1/24 so the route becomes valid")
    create_interface_in_kernel(tgen, "r1", DUMMY_IF, NETWORK_IP)

    def _route_valid():
        out = _get_bgp_prefix_json(r1, NETWORK_PREFIX)
        if not out:
            return None
        for p in out.get("paths", []):
            if p.get("valid") and p.get("bestpath", {}).get("overall"):
                return True
        return None

    _, res = topotest.run_and_expect(_route_valid, True, count=30, wait=0.5)
    assert res is not None, "Route 200.1.12.0/24 should become valid after adding interface"

    step("Remove 200.1.12.1/24 from dummy so the route becomes invalid again")
    r1.run("ip addr del {} dev {}".format(NETWORK_IP, DUMMY_IF))

    def _route_has_no_best():
        out = _get_bgp_prefix_json(r1, NETWORK_PREFIX)
        if not out:
            return None
        has_best = any(
            p.get("bestpath", {}).get("overall") for p in out.get("paths", [])
        )
        return True if not has_best else None

    success, _ = topotest.run_and_expect(_route_has_no_best, True, count=30, wait=0.5)
    assert success, (
        "Route 200.1.12.0/24 should become invalid (no best path) after removing interface"
    )

    step("Verify no path has multipath set when route is invalid")
    out_after_invalid = _get_bgp_prefix_json(r1, NETWORK_PREFIX)
    assert out_after_invalid is not None, "BGP entry for {} should still exist".format(NETWORK_PREFIX)
    paths = out_after_invalid.get("paths", [])
    for i, p in enumerate(paths):
        multipath = p.get("multipath")
        assert multipath is not True, (
            "Path {} should not have multipath=True when route is invalid (no best path). "
            "Got multipath={}. Full path: {}".format(i, multipath, p)
        )
    logger.info("PASS: Invalid path(s) do not show multipath=True")
