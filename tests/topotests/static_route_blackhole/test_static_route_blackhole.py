#!/usr/bin/env python
# SPDX-License-Identifier: ISC

# Copyright (c) 2025 by
# Donatas Abraitis <donatas@opensourcerouting.org>
#

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

pytestmark = [pytest.mark.staticd]


def setup_module(mod):
    topodef = {"s1": ("r1",)}
    tgen = Topogen(topodef, mod.__name__)
    tgen.start_topology()

    router_list = tgen.routers()

    for _, (rname, router) in enumerate(router_list.items(), 1):
        router.load_frr_config(os.path.join(CWD, "{}/frr.conf".format(rname)))
    tgen.start_router()


def teardown_module(mod):
    tgen = get_topogen()
    tgen.stop_topology()


def test_static_route_blackhole():
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]

    def _check_static_routes():
        output = json.loads(r1.vtysh_cmd("show ip route json"))
        expected = {
            "10.0.0.1/32": [
                {
                    "protocol": "static",
                    "nexthops": [
                        {
                            "blackhole": True,
                        }
                    ],
                }
            ],
            "10.0.0.2/32": [
                {
                    "protocol": "static",
                    "nexthops": [
                        {
                            "reject": True,
                        }
                    ],
                }
            ],
            "10.0.0.3/32": [
                {
                    "protocol": "static",
                    "nexthops": [
                        {
                            "blackhole": True,
                        }
                    ],
                }
            ],
        }
        return topotest.json_cmp(output, expected)

    test_func = functools.partial(
        _check_static_routes,
    )
    _, result = topotest.run_and_expect(test_func, None, count=30, wait=1)
    assert result is None, "Can't see expected static routes"

    # Try to delete blackhole static routes with a wrong blackhole types.
    # The routes should not be deleted.
    r1.vtysh_cmd(
        """
        configure terminal
        no ip route 10.0.0.1/32 reject
        no ip route 10.0.0.2/32 blackhole
        no ip route 10.0.0.3/32 reject
        """
    )

    test_func = functools.partial(
        _check_static_routes,
    )
    _, result = topotest.run_and_expect(test_func, None, count=30, wait=1)
    assert result is None, "Can't see expected static routes"


def test_show_ip_route_brief_json():
    """Check that 'show ip route brief json' returns valid JSON with expected brief fields."""
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]
    expected_prefixes = [
        "10.0.0.1/32",
        "10.0.0.2/32",
        "10.0.0.3/32",
        "192.168.1.0/24",
        "192.168.1.1/32",
    ]
    required_brief_fields = [
        "protocol",
        "selected",
        "destSelected",
        "distance",
        "metric",
        "installed",
        "nexthopGroupId",
        "uptime",
    ]
    prefixes_connected_or_local = ["192.168.1.0/24", "192.168.1.1/32"]

    def _check_brief_json():
        output = r1.vtysh_cmd("show ip route brief json", isjson=True)
        if not isinstance(output, dict):
            return "Output is not a dict: %s" % type(output)
        for prefix in expected_prefixes:
            if prefix not in output:
                return "Missing prefix %s in brief json" % prefix
            routes = output[prefix]
            if not isinstance(routes, list) or len(routes) == 0:
                return "Prefix %s has no route list" % prefix
            entry = routes[0]
            for field in required_brief_fields:
                if field not in entry:
                    return "Prefix %s route missing field '%s'" % (prefix, field)
            if prefix in prefixes_connected_or_local:
                if entry.get("protocol") not in ("connected", "local"):
                    return "Prefix %s expected protocol connected/local, got %s" % (
                        prefix,
                        entry.get("protocol"),
                    )
                if "offloaded" in entry and not isinstance(entry["offloaded"], bool):
                    return "Prefix %s offloaded must be bool if present" % prefix
            else:
                if entry.get("protocol") != "static":
                    return "Prefix %s expected protocol static, got %s" % (
                        prefix,
                        entry.get("protocol"),
                    )
        return None

    _, result = topotest.run_and_expect(_check_brief_json, None, count=30, wait=1)
    assert result is None, "show ip route brief json check failed: %s" % (result or "")


def test_show_ip_route_brief_json_vrf_consistency():
    """Check that brief json is consistent across no-vrf, vrf default, and vrf all."""
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]

    def _check_vrf_consistency():
        brief = r1.vtysh_cmd("show ip route brief json", isjson=True)
        default_brief = r1.vtysh_cmd(
            "show ip route vrf default brief json", isjson=True
        )
        all_brief = r1.vtysh_cmd("show ip route vrf all brief json", isjson=True)

        if not isinstance(brief, dict):
            return "show ip route brief json is not a dict"
        if not isinstance(default_brief, dict):
            return "show ip route vrf default brief json is not a dict"
        if not isinstance(all_brief, dict):
            return "show ip route vrf all brief json is not a dict"

        if set(brief.keys()) != set(default_brief.keys()):
            return "Prefix set differs: brief vs vrf default"

        if "default" not in all_brief:
            return "vrf all brief json missing 'default' key"

        if set(all_brief["default"].keys()) != set(brief.keys()):
            return "Prefix set in vrf all['default'] differs from default VRF"

        return None

    _, result = topotest.run_and_expect(_check_vrf_consistency, None, count=30, wait=1)
    assert result is None, "show ip route brief json VRF consistency failed: %s" % (
        result or ""
    )


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
