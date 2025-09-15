#!/usr/bin/env python
# SPDX-License-Identifier: ISC

# Copyright (c) 2024 by
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

pytestmark = [pytest.mark.bgpd]


def setup_module(mod):
    topodef = {"s1": ("r1", "r2")}
    tgen = Topogen(topodef, mod.__name__)
    tgen.start_topology()

    router_list = tgen.routers()

    for _, (rname, router) in enumerate(router_list.items(), 1):
        router.load_frr_config(os.path.join(CWD, "{}/frr.conf".format(rname)))

    tgen.start_router()


def teardown_module(mod):
    tgen = get_topogen()
    tgen.stop_topology()


def test_bgp_received_routes_with_soft_inbound():
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]

    def _bgp_converge():
        output = json.loads(r1.vtysh_cmd("show bgp ipv4 unicast json"))
        expected = {
            "routes": {
                "10.0.0.2/32": [
                    {
                        "valid": True,
                        "path": "65000 65000 65000 65002",
                        "nexthops": [
                            {
                                "ip": "192.168.1.2",
                            }
                        ],
                    }
                ]
            }
        }

        return topotest.json_cmp(output, expected)

    test_func = functools.partial(
        _bgp_converge,
    )
    _, result = topotest.run_and_expect(test_func, None, count=30, wait=1)
    assert result is None, "Can't converge"

    def _bgp_check_receveived_routes():
        output = json.loads(
            r1.vtysh_cmd(
                "show bgp ipv4 unicast neighbors 192.168.1.2 received-routes json"
            )
        )
        expected = {
            "receivedRoutes": {
                "10.0.0.2/32": {
                    "valid": True,
                    "path": "65002",
                    "nextHop": "192.168.1.2",
                }
            }
        }

        return topotest.json_cmp(output, expected)

    test_func = functools.partial(
        _bgp_check_receveived_routes,
    )
    _, result = topotest.run_and_expect(test_func, None, count=30, wait=1)
    assert result is None, "Can't converge"


def test_bgp_adj_routes_json_error_paths():
    """Test JSON formatting consistency for BGP adj-route error paths"""
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]

    # Disable soft-reconfiguration to trigger warning paths
    r1.vtysh_cmd(
        """
        configure terminal
        router bgp 65001
        address-family ipv4 unicast
        no neighbor 192.168.1.2 soft-reconfiguration inbound
        end
    """
    )

    def _check_adj_route_json_consistency():
        """Check that all adj-route JSON outputs are well-formed"""
        test_commands = [
            "show bgp ipv4 unicast neighbors 192.168.1.2 received-routes json",
            "show bgp ipv4 unicast neighbors 192.168.1.2 advertised-routes json",
            "show bgp ipv4 unicast neighbors 192.168.1.2 filtered-routes json",
        ]

        for cmd in test_commands:
            output = r1.vtysh_cmd(cmd)

            # Critical: JSON should ALWAYS be valid after our fix
            try:
                parsed = json.loads(output)
            except json.JSONDecodeError as e:
                pytest.fail(f"Malformed JSON in command '{cmd}': {e}\nOutput: {output}")

            # Test CONTENT for expected error messages
            if "received-routes" in cmd or "filtered-routes" in cmd:
                warning_msg = parsed.get("warning", "")
                expected = "Inbound soft reconfiguration not enabled"
                if warning_msg != expected:
                    return (
                        f"Expected soft reconfig warning in {cmd}, "
                        f"got: '{warning_msg}'"
                    )

            # Verify JSON structure is a single object, not double-nested
            if not isinstance(parsed, dict):
                return f"Expected dict object for {cmd}"

            # Critical: Should not have nested structure { { "warning": ... } }
            warning_value = parsed.get("warning", "")
            if isinstance(warning_value, dict):
                # This indicates our fix failed - fail test immediately
                pytest.fail(f"Warning should be string, not nested object in {cmd}")

        return None

    test_func = functools.partial(_check_adj_route_json_consistency)
    _, result = topotest.run_and_expect(test_func, None, count=5, wait=3)
    assert result is None, f"JSON consistency check failed: {result}"

    # Restore original configuration
    r1.vtysh_cmd(
        """
        configure terminal
        router bgp 65001
        address-family ipv4 unicast
        neighbor 192.168.1.2 soft-reconfiguration inbound
        end
    """
    )


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
