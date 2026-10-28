#!/usr/bin/env python
# SPDX-License-Identifier: ISC

# Copyright (c) 2024 by
# Donatas Abraitis <donatas@opensourcerouting.org>
#

"""
Test if Paths-Limit capability works as expected.
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

pytestmark = [pytest.mark.bgpd]


def build_topo(tgen):
    for routern in range(1, 8):
        tgen.add_router("r{}".format(routern))

    switch = tgen.add_switch("s1")
    switch.add_link(tgen.gears["r1"])
    switch.add_link(tgen.gears["r2"])

    switch = tgen.add_switch("s2")
    switch.add_link(tgen.gears["r2"])
    switch.add_link(tgen.gears["r3"])
    switch.add_link(tgen.gears["r4"])
    switch.add_link(tgen.gears["r5"])
    switch.add_link(tgen.gears["r6"])

    switch = tgen.add_switch("s3")
    switch.add_link(tgen.gears["r7"])
    switch.add_link(tgen.gears["r2"])


def setup_module(mod):
    tgen = Topogen(build_topo, mod.__name__)
    tgen.start_topology()

    router_list = tgen.routers()

    for router in router_list.values():
        router.load_frr_config()

    tgen.start_router()


def teardown_module(mod):
    tgen = get_topogen()
    tgen.stop_topology()


def test_bgp_addpath_paths_limit():
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]
    r2 = tgen.gears["r2"]
    r7 = tgen.gears["r7"]

    def _bgp_converge():
        output = json.loads(r2.vtysh_cmd("show bgp neighbor json"))
        expected = {
            "192.168.7.7": {
                "neighborCapabilities": {
                    "pathsLimit": {
                        "ipv4Unicast": {
                            "advertisedAndReceived": True,
                            "advertisedPathsLimit": 0,
                            "receivedPathsLimit": 3,
                        }
                    }
                }
            },
            "192.168.1.1": {
                "neighborCapabilities": {
                    "pathsLimit": {
                        "ipv4Unicast": {
                            "advertisedAndReceived": True,
                            "advertisedPathsLimit": 0,
                            "receivedPathsLimit": 2,
                        }
                    }
                }
            },
        }
        return topotest.json_cmp(output, expected)

    test_func = functools.partial(_bgp_converge)
    _, result = topotest.run_and_expect(test_func, None, count=30, wait=1)
    assert result is None, "Can't converge initially"

    def _bgp_check_advertised_routes(neighbor, total_prefixes, total_paths):
        output = json.loads(
            r2.vtysh_cmd(f"show ip bgp neighbors {neighbor} advertised-routes json")
        )
        expected = {
            "totalPrefixCounter": total_prefixes,
            "totalPathsCount": total_paths,
        }

        return topotest.json_cmp(output, expected)

    test_func = functools.partial(_bgp_check_advertised_routes, "192.168.7.7", 3, 12)
    _, result = topotest.run_and_expect(test_func, None, count=30, wait=1)
    assert result is None, "Advertised routes count for 192.168.7.7 is not as expected"

    test_func = functools.partial(_bgp_check_advertised_routes, "192.168.2.6", 2, 2)
    _, result = topotest.run_and_expect(test_func, None, count=30, wait=1)
    assert result is None, "Advertised routes count for 192.168.2.6 is not as expected"

    def _bgp_check_received_routes(router, expected):
        output = json.loads(
            router.vtysh_cmd("show bgp ipv4 unicast 172.16.16.254/32 json")
        )

        if "paths" not in output:
            return "No paths received"

        return topotest.json_cmp(len(output["paths"]), expected)

    test_func = functools.partial(_bgp_check_received_routes, r1, 2)
    _, result = topotest.run_and_expect(test_func, None, count=30, wait=1)
    assert result is None, "Received routes count is not as expected"

    test_func = functools.partial(_bgp_check_received_routes, r7, 3)
    _, result = topotest.run_and_expect(test_func, None, count=30, wait=1)
    assert result is None, "Received routes count is not as expected"


def test_bgp_pathcount_json():
    """
    Test to verify the pathCount key exists in BGP JSON output and has correct values
    """
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]
    r7 = tgen.gears["r7"]

    def _bgp_check_path_count(router, expected_count):
        output = json.loads(
            router.vtysh_cmd("show bgp ipv4 unicast 172.16.16.254/32 json")
        )

        if "pathCount" not in output:
            return "pathCount key not found in JSON output"

        return topotest.json_cmp(output["pathCount"], expected_count)

    # Check pathCount for r1 (should be 2)
    test_func = functools.partial(_bgp_check_path_count, r1, 2)
    _, result = topotest.run_and_expect(test_func, None, count=30, wait=1)
    assert (
        result is None
    ), "pathCount in JSON output doesn't match expected value for r1"

    # Check pathCount for r7 (should be 3)
    test_func = functools.partial(_bgp_check_path_count, r7, 3)
    _, result = topotest.run_and_expect(test_func, None, count=30, wait=1)
    assert (
        result is None
    ), "pathCount in JSON output doesn't match expected value for r7"


def _bgp_received_aspaths(router):
    output = json.loads(router.vtysh_cmd("show bgp ipv4 unicast 172.16.16.254/32 json"))

    return sorted(path["aspath"]["string"] for path in output.get("paths", []))


def _bgp_check_received_aspaths(router, expected):
    received = _bgp_received_aspaths(router)
    if received != sorted(expected):
        return "Expected {}, got {}".format(sorted(expected), received)

    return None


def test_bgp_addpath_paths_limit_filtered_paths():
    """
    Filtered paths must not be counted against Paths-Limit.
    """
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]
    r2 = tgen.gears["r2"]

    r2.vtysh_cmd(
        """
    configure terminal
     bgp as-path access-list r1-out seq 5 deny ^6500[56]$
     bgp as-path access-list r1-out seq 10 permit .*
     router bgp 65002
      address-family ipv4 unicast
       neighbor 192.168.1.1 filter-list r1-out out
    """
    )

    test_func = functools.partial(
        _bgp_check_received_aspaths, r1, ["65002 65004", "65002 65003"]
    )
    _, result = topotest.run_and_expect(test_func, None, count=30, wait=1)
    assert result is None, "Filtered paths are counted against Paths-Limit: {}".format(
        result
    )

    r2.vtysh_cmd(
        """
    configure terminal
     router bgp 65002
      address-family ipv4 unicast
       no neighbor 192.168.1.1 filter-list r1-out out
     no bgp as-path access-list r1-out
    """
    )

    test_func = functools.partial(
        _bgp_check_received_aspaths, r1, ["65002 65006", "65002 65005"]
    )
    _, result = topotest.run_and_expect(test_func, None, count=30, wait=1)
    assert result is None, "r1 did not receive the two best paths: {}".format(result)


def test_bgp_addpath_paths_limit_best_selected():
    """
    Bestpath must be included into Paths-Limit with addpath-tx-best-selected.
    """
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r2 = tgen.gears["r2"]
    r7 = tgen.gears["r7"]

    r2.vtysh_cmd(
        """
    configure terminal
     router bgp 65002
      address-family ipv4 unicast
       neighbor 192.168.7.7 addpath-tx-best-selected 3
    """
    )

    test_func = functools.partial(
        _bgp_check_received_aspaths,
        r7,
        ["65002 65006", "65002 65005", "65002 65004"],
    )
    _, result = topotest.run_and_expect(test_func, None, count=30, wait=1)
    assert result is None, "Bestpath is not included into Paths-Limit: {}".format(
        result
    )

    r2.vtysh_cmd(
        """
    configure terminal
     router bgp 65002
      address-family ipv4 unicast
       neighbor 192.168.7.7 addpath-tx-all-paths
    """
    )

    test_func = functools.partial(
        _bgp_check_received_aspaths,
        r7,
        ["65002 65006", "65002 65005", "65002 65004"],
    )
    _, result = topotest.run_and_expect(test_func, None, count=30, wait=1)
    assert result is None, "r7 did not receive the three best paths: {}".format(result)


def test_bgp_addpath_paths_limit_best_selected_filtered():
    """
    Filtered candidate must not consume Paths-Limit with addpath-tx-best-selected.
    """
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]
    r2 = tgen.gears["r2"]

    r2.vtysh_cmd(
        """
    configure terminal
     bgp as-path access-list r1-out seq 5 deny ^65005$
     bgp as-path access-list r1-out seq 10 permit .*
     router bgp 65002
      address-family ipv4 unicast
       neighbor 192.168.1.1 addpath-tx-best-selected 3
       neighbor 192.168.1.1 filter-list r1-out out
    """
    )

    test_func = functools.partial(
        _bgp_check_received_aspaths, r1, ["65002 65006", "65002 65004"]
    )
    _, result = topotest.run_and_expect(test_func, None, count=30, wait=1)
    assert result is None, "Filtered candidate consumed Paths-Limit: {}".format(result)

    r2.vtysh_cmd(
        """
    configure terminal
     router bgp 65002
      address-family ipv4 unicast
       no neighbor 192.168.1.1 filter-list r1-out out
       neighbor 192.168.1.1 addpath-tx-all-paths
     no bgp as-path access-list r1-out
    """
    )

    test_func = functools.partial(
        _bgp_check_received_aspaths, r1, ["65002 65006", "65002 65005"]
    )
    _, result = topotest.run_and_expect(test_func, None, count=30, wait=1)
    assert result is None, "r1 did not receive the two best paths: {}".format(result)


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
