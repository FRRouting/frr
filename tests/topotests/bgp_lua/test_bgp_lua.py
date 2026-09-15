#!/usr/bin/env python
# SPDX-License-Identifier: ISC
#
# test_bgp_lua.py
#
# Copyright (c) 2026 by NVIDIA Corporation
#                       Donald Sharp
#

"""
Test basic BGP Lua route-map match-script functionality.

Topology: r1 (AS 65001) -- r2 (AS 65002)

r2 originates six prefixes. r1 applies an inbound route-map whose only
match is ``match script route_match``, which loads
/etc/frr/scripts/route_match.lua.

  10.0.1.0/24  RM_MATCH (permit unchanged)
  10.0.2.0/24  RM_NOMATCH (filtered)
  10.0.3.0/24  RM_MATCH_AND_CHANGE (set MED 123)
  10.0.4.0/24  RM_MATCH_AND_CHANGE (set community, local-pref, weight)
  10.0.5.0/24  match incoming community 65002:99 (permit)
  10.0.6.0/24  no community 65002:99 (filtered)

The suite is skipped when ``vtysh -c "show ver"`` does not include
``--enable-scripting``.
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
from lib.topogen import Topogen, get_topogen
from lib.topolog import logger
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

    r1 = tgen.gears["r1"]
    script_src = os.path.join(CWD, "r1", "scripts", "route_match.lua")

    for router in tgen.routers().values():
        router.load_frr_config()

    r1.cmd_raises("mkdir -p /etc/frr/scripts")
    r1.cmd_raises("cp {} /etc/frr/scripts/route_match.lua".format(script_src))
    r1.cmd_raises("chown frr:frr /etc/frr/scripts /etc/frr/scripts/route_match.lua")
    r1.cmd_raises("chmod 755 /etc/frr/scripts")
    r1.cmd_raises("chmod 644 /etc/frr/scripts/route_match.lua")

    tgen.start_router()

    version = r1.vtysh_cmd("show ver")
    logger.info("show ver:\n%s", version)
    if "--enable-scripting" not in version:
        pytest.skip("FRR is not compiled with --enable-scripting")

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)


def teardown_module(mod):
    tgen = get_topogen()
    tgen.stop_topology()


def _bgp_check_neighbor_established(router, neighbor):
    output = json.loads(router.vtysh_cmd("show bgp neighbor {} json".format(neighbor)))
    expected = {
        neighbor: {
            "bgpState": "Established",
        }
    }
    return topotest.json_cmp(output, expected)


def _bgp_check_route(router, prefix, expected_path):
    output = json.loads(
        router.vtysh_cmd("show bgp ipv4 unicast {} json".format(prefix))
    )
    expected = {"paths": [expected_path]}
    return topotest.json_cmp(output, expected)


def _bgp_check_route_missing(router, prefix):
    output = json.loads(
        router.vtysh_cmd("show bgp ipv4 unicast {} json".format(prefix))
    )
    if output.get("paths"):
        return "Route {} should not exist".format(prefix)
    return None


def test_bgp_lua_converge():
    """Wait for the eBGP session and the RM_MATCH prefix to appear."""
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]

    step("Check BGP session is established")
    test_func = functools.partial(_bgp_check_neighbor_established, r1, "192.168.12.2")
    _, result = topotest.run_and_expect(test_func, None, count=30, wait=1)
    assert result is None, "BGP session not established"

    step("Verify 10.0.1.0/24 is accepted unchanged (RM_MATCH)")
    test_func = functools.partial(
        _bgp_check_route,
        r1,
        "10.0.1.0/24",
        {
            "valid": True,
            "aspath": {"string": "65002"},
            "community": None,
        },
    )
    _, result = topotest.run_and_expect(test_func, None, count=30, wait=1)
    assert result is None, "10.0.1.0/24 was not accepted unchanged"


def test_bgp_lua_nomatch_filtered():
    """RM_NOMATCH must drop the prefix via the implicit route-map deny."""
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]

    step("Wait for Lua policy to have been applied (10.0.1.0/24 present)")
    test_func = functools.partial(_bgp_check_route, r1, "10.0.1.0/24", {"valid": True})
    _, result = topotest.run_and_expect(test_func, None, count=30, wait=1)
    assert result is None, "10.0.1.0/24 did not appear; cannot trust filter checks"

    step("Verify 10.0.2.0/24 is filtered (RM_NOMATCH)")
    test_func = functools.partial(_bgp_check_route_missing, r1, "10.0.2.0/24")
    _, result = topotest.run_and_expect(test_func, None, count=15, wait=1)
    assert result is None, "10.0.2.0/24 should have been filtered by Lua"


def test_bgp_lua_match_and_change_metric():
    """RM_MATCH_AND_CHANGE must install the MED written by Lua."""
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]

    step("Verify 10.0.3.0/24 has MED 123 from Lua")
    test_func = functools.partial(
        _bgp_check_route,
        r1,
        "10.0.3.0/24",
        {
            "valid": True,
            "metric": 123,
        },
    )
    _, result = topotest.run_and_expect(test_func, None, count=30, wait=1)
    assert result is None, "10.0.3.0/24 did not get MED 123 from Lua"


def test_bgp_lua_match_and_change_attributes():
    """RM_MATCH_AND_CHANGE must install community, local-pref, and weight."""
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]

    step("Verify 10.0.4.0/24 has community, local-pref, and weight from Lua")
    test_func = functools.partial(
        _bgp_check_route,
        r1,
        "10.0.4.0/24",
        {
            "valid": True,
            "locPrf": 200,
            "weight": 400,
            "community": {"string": "65001:1"},
        },
    )
    _, result = topotest.run_and_expect(test_func, None, count=30, wait=1)
    assert result is None, "10.0.4.0/24 did not get Lua-set attributes"


def test_bgp_lua_match_incoming_community():
    """Lua must read attributes.community and filter on it."""
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]

    step("Verify 10.0.5.0/24 is accepted because it carries 65002:99")
    test_func = functools.partial(
        _bgp_check_route,
        r1,
        "10.0.5.0/24",
        {
            "valid": True,
            "community": {"string": "65002:99"},
        },
    )
    _, result = topotest.run_and_expect(test_func, None, count=30, wait=1)
    assert result is None, "10.0.5.0/24 with community 65002:99 was not accepted"

    step("Verify 10.0.6.0/24 is filtered (no 65002:99)")
    test_func = functools.partial(_bgp_check_route_missing, r1, "10.0.6.0/24")
    _, result = topotest.run_and_expect(test_func, None, count=15, wait=1)
    assert result is None, "10.0.6.0/24 should have been filtered by Lua"


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
