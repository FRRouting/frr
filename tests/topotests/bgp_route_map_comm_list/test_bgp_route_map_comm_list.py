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
                        "acceptedPrefixCounter": 12,
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
    assert result is None, "Failed"


def test_bgp_route_map_extcomm_list():
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r2 = tgen.gears["r2"]

    def _check_extcommunity(prefix, extcommunity):
        output = json.loads(
            r2.vtysh_cmd("show bgp ipv4 unicast {} json".format(prefix))
        )
        expected = {
            "paths": [
                {
                    "extendedCommunity": {"string": extcommunity},
                    "peer": {"peerId": "192.168.1.1"},
                }
            ]
        }
        return topotest.json_cmp(output, expected)

    # r1 sends both prefixes with RT:65001:10.
    # "set extended-comm-list add ECL_ADD" appends RT:65001:111, and
    # "set extended-comm-list replace ECL_REP" replaces RT:65001:10 with
    # RT:65001:222. The string comparison is exact.
    for prefix, extcommunity, case in (
        ("10.1.5.0/24", "RT:65001:10 RT:65001:111", "ADD"),
        ("10.1.6.0/24", "RT:65001:222", "REPLACE"),
    ):
        test_func = functools.partial(_check_extcommunity, prefix, extcommunity)
        _, result = topotest.run_and_expect(test_func, None, count=30, wait=1)
        assert (
            result is None
        ), "{} case failed: {} extended communities are not {}".format(
            case, prefix, extcommunity
        )

    # the new commands are displayed back in the configuration
    output = r2.vtysh_cmd("show running-config")
    for line in (
        " set extended-comm-list add ECL_ADD",
        " set extended-comm-list replace ECL_REP",
    ):
        assert line in output.splitlines(), "'{}' missing from r2 configuration".format(
            line
        )


def test_bgp_route_map_lcomm_list():
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r2 = tgen.gears["r2"]

    def _check_lcommunity(prefix, lcommunity):
        output = json.loads(
            r2.vtysh_cmd("show bgp ipv4 unicast {} json".format(prefix))
        )
        expected = {
            "paths": [
                {
                    "largeCommunity": {"string": lcommunity},
                    "peer": {"peerId": "192.168.1.1"},
                }
            ]
        }
        return topotest.json_cmp(output, expected)

    # r1 sends both prefixes with 65001:1:10.
    # "set large-comm-list add LCL_ADD" appends 65001:1:111, and
    # "set large-comm-list replace LCL_REP" replaces 65001:1:10 with
    # 65001:1:222. The string comparison is exact.
    for prefix, lcommunity, case in (
        ("10.1.7.0/24", "65001:1:10 65001:1:111", "ADD"),
        ("10.1.8.0/24", "65001:1:222", "REPLACE"),
    ):
        test_func = functools.partial(_check_lcommunity, prefix, lcommunity)
        _, result = topotest.run_and_expect(test_func, None, count=30, wait=1)
        assert result is None, "{} case failed: {} large communities are not {}".format(
            case, prefix, lcommunity
        )

    # the new commands are displayed back in the configuration
    output = r2.vtysh_cmd("show running-config")
    for line in (
        " set large-comm-list add LCL_ADD",
        " set large-comm-list replace LCL_REP",
    ):
        assert line in output.splitlines(), "'{}' missing from r2 configuration".format(
            line
        )


def test_bgp_route_map_comm_list_replace_expanded():
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r2 = tgen.gears["r2"]

    # An expanded list defines no value to set: "replace" must leave the
    # attribute received from r1 unchanged instead of removing it.
    r2.vtysh_cmd(
        """
        configure terminal
         route-map RM_IN permit 46
          set extended-comm-list replace ECL_EXP
         exit
         route-map RM_IN permit 48
          set large-comm-list replace LCL_EXP
         exit
        end
        clear bgp ipv4 unicast 192.168.1.1 soft in
        """
    )

    def _check_communities(prefix, key, value):
        output = json.loads(
            r2.vtysh_cmd("show bgp ipv4 unicast {} json".format(prefix))
        )
        expected = {
            "paths": [
                {
                    key: {"string": value},
                    "peer": {"peerId": "192.168.1.1"},
                }
            ]
        }
        return topotest.json_cmp(output, expected)

    for prefix, key, value in (
        ("10.1.6.0/24", "extendedCommunity", "RT:65001:10"),
        ("10.1.8.0/24", "largeCommunity", "65001:1:10"),
    ):
        test_func = functools.partial(_check_communities, prefix, key, value)
        _, result = topotest.run_and_expect(test_func, None, count=30, wait=1)
        assert (
            result is None
        ), "{} {} is not {} after replace with an expanded list".format(
            prefix, key, value
        )


def test_bgp_route_map_comm_list_delete():
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r2 = tgen.gears["r2"]

    # TODO: drop this block when the deprecated
    # "set extended-comm-list <COMM_LIST> delete" and
    # "set large-comm-list <COMM_LIST> delete" commands are removed
    # (CONFDATE 20270527, see bgpd/bgp_routemap.c).
    # The deprecated format is configured on 10.1.10.0/24 and 10.1.12.0/24,
    # the new format "set extended-comm-list delete <COMM_LIST>" on
    # 10.1.9.0/24 and 10.1.11.0/24 (r2/frr.conf). Both must give the same
    # result.
    r2.vtysh_cmd(
        """
        configure terminal
         ip prefix-list PL_EXT_DEL_OLD permit 10.1.10.0/24
         ip prefix-list PL_LARGE_DEL_OLD permit 10.1.12.0/24
         route-map RM_IN permit 42
          match ip address prefix-list PL_EXT_DEL_OLD
          set extended-comm-list ECL_DEL delete
         exit
         route-map RM_IN permit 44
          match ip address prefix-list PL_LARGE_DEL_OLD
          set large-comm-list LCL_DEL delete
         exit
        end
        clear bgp ipv4 unicast 192.168.1.1 soft in
        """
    )

    def _check_communities(prefix, key, value):
        output = json.loads(
            r2.vtysh_cmd("show bgp ipv4 unicast {} json".format(prefix))
        )
        expected = {
            "paths": [
                {
                    key: {"string": value},
                    "peer": {"peerId": "192.168.1.1"},
                }
            ]
        }
        return topotest.json_cmp(output, expected)

    # r1 sends RT:65001:10 RT:65001:99 and 65001:1:10 65001:1:99, the
    # delete lists remove the ":99" values.
    for prefix, key, value, case in (
        ("10.1.9.0/24", "extendedCommunity", "RT:65001:10", "new format"),
        ("10.1.10.0/24", "extendedCommunity", "RT:65001:10", "deprecated format"),
        ("10.1.11.0/24", "largeCommunity", "65001:1:10", "new format"),
        ("10.1.12.0/24", "largeCommunity", "65001:1:10", "deprecated format"),
    ):
        test_func = functools.partial(_check_communities, prefix, key, value)
        _, result = topotest.run_and_expect(test_func, None, count=30, wait=1)
        assert result is None, "delete with the {}: {} {} is not {}".format(
            case, prefix, key, value
        )

    # TODO: drop with the block above. The deprecated format sets the same
    # leaf as the new one, so it is displayed back with the new format.
    def _route_map_entry(output, seq):
        lines = output.splitlines()
        start = lines.index("route-map RM_IN permit {}".format(seq))
        entry = []
        for line in lines[start + 1 :]:
            if not line.startswith(" "):
                break
            entry.append(line)
        return entry

    output = r2.vtysh_cmd("show running-config")
    for seq, line in (
        (42, " set extended-comm-list delete ECL_DEL"),
        (44, " set large-comm-list delete LCL_DEL"),
    ):
        assert line in _route_map_entry(
            output, seq
        ), "'{}' missing from r2 route-map RM_IN permit {}".format(line, seq)


if __name__ == "__main__":
    sys.exit(pytest.main([__file__]))
