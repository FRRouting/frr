#!/usr/bin/env python
# SPDX-License-Identifier: ISC

# Copyright (c) 2026 by wangdan1323
#
# Test BGP confederation identifier behavior:
# 1. Initial confederation ID shows correctly
# 2. Changing confederation ID to ASDOT notation (same numeric value) does not reset BGP session
# 3. Deleting confederation ID multiple times does not reset session repeatedly
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

    for rname in router_list:
        router = tgen.gears[rname]
        router.load_frr_config(os.path.join(CWD, "{}/frr.conf".format(rname)))

    tgen.start_router()


def teardown_module(mod):
    tgen = get_topogen()
    tgen.stop_topology()


def get_bgp_confederation_id(router):
    """Get confederation identifier from router"""
    output = router.vtysh_cmd(
        "show running-config | include bgp confederation identifier"
    )
    if "bgp confederation identifier" in output:
        parts = output.strip().split()
        return parts[-1]
    return ""


def get_bgp_peer_uptime(router, peer_ip="192.168.0.2"):
    """Get BGP peer establishment timestamp"""
    output = json.loads(router.vtysh_cmd("show bgp summary json"))
    for afi_key, afi_data in output.items():
        if not isinstance(afi_data, dict):
            continue
        peers = afi_data.get("peers", {})
        for peer, info in peers.items():
            if peer_ip in peer:
                return info.get("peerUptimeEstablishedEpoch", 0)
    return 0


def get_bgp_peer_state(router, peer_ip="192.168.0.2"):
    """Get BGP peer state"""
    output = json.loads(router.vtysh_cmd("show bgp summary json"))
    for afi_key, afi_data in output.items():
        if not isinstance(afi_data, dict):
            continue
        peers = afi_data.get("peers", {})
        for peer, info in peers.items():
            if peer_ip in peer:
                return info.get("state", "")
    return ""


def test_bgp_confederation_id_unchanged():
    """
    Test that BGP session is not reset when confederation ID is:
    1. Initially configured correctly
    2. Changed to ASDOT notation (1.0 equals 65536, same numeric value) - session uptime continues
    3. Deleted multiple times - session uptime continues
    """
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]

    # Test point 1: Initial confederation ID shows correctly
    def _check_initial_confed_id():
        confed_id = get_bgp_confederation_id(r1)
        return confed_id == "65536"

    success, result = topotest.run_and_expect(_check_initial_confed_id, True, count=30, wait=1)
    assert success, "Initial confederation ID should be 65536, got: {}".format(result)

    # Wait for BGP to establish
    def _bgp_established():
        state = get_bgp_peer_state(r1)
        return state == "Established"

    success, _ = topotest.run_and_expect(_bgp_established, True, count=30, wait=1)
    assert success, "BGP session not established on r1"

    # Record initial uptime
    initial_uptime = get_bgp_peer_uptime(r1)
    assert initial_uptime > 0, "Initial uptime should be > 0, got: {}".format(initial_uptime)

    # Test point 2: Change confederation ID to 1.0 (ASDOT notation, same numeric value)
    r1.vtysh_cmd(
        """
        configure terminal
        router bgp 64512
        bgp confederation identifier 1.0
        end
    """
    )

    # Check confederation ID changed to 1.0
    def _check_changed_confed_id():
        confed_id = get_bgp_confederation_id(r1)
        return confed_id == "1.0"

    success, result = topotest.run_and_expect(_check_changed_confed_id, True, count=30, wait=1)
    assert success, "Confederation ID should be 1.0, got: {}".format(result)

    # Check session is still established
    def _bgp_still_established():
        state = get_bgp_peer_state(r1)
        return state == "Established"

    success, _ = topotest.run_and_expect(_bgp_still_established, True, count=30, wait=1)
    assert success, "BGP session should be established"

    # Check uptime continued (not reset) - allow 1 second difference
    new_uptime = get_bgp_peer_uptime(r1)
    assert abs(new_uptime - initial_uptime) <= 1, (
        "Session uptime reset! initial={}, new={}".format(initial_uptime, new_uptime)
    )

    # Test point 3: Delete confederation ID on r1 only
    r1.vtysh_cmd(
        """
        configure terminal
        router bgp 64512
        no bgp confederation identifier
        end
    """
    )

    # Check confederation ID is gone on r1
    def _check_confed_id_deleted():
        output = r1.vtysh_cmd(
            "show running-config | include bgp confederation identifier"
        )
        return "bgp confederation identifier" not in output

    success, _ = topotest.run_and_expect(_check_confed_id_deleted, True, count=30, wait=1)
    assert success, "Confederation ID should be deleted from r1"

    # Wait for convergence and check session is established
    def _bgp_established_after_delete():
        state = get_bgp_peer_state(r1)
        return state == "Established"

    success, _ = topotest.run_and_expect(_bgp_established_after_delete, True, count=30, wait=1)
    assert success, "Session should be established after delete"

    # Record uptime after first delete
    uptime_after_first_delete = get_bgp_peer_uptime(r1)

    # Delete again on r1 only (should not reset session)
    r1.vtysh_cmd(
        """
        configure terminal
        router bgp 64512
        no bgp confederation identifier
        end
    """
    )

    # Check session still established
    success, _ = topotest.run_and_expect(_bgp_still_established, True, count=30, wait=1)
    assert success, "Session should still be established"

    # Check uptime unchanged after second delete - allow 1 second difference
    uptime_after_second_delete = get_bgp_peer_uptime(r1)
    assert abs(uptime_after_second_delete - uptime_after_first_delete) <= 1, (
        "Second delete caused session reset! "
        "uptime before second delete={}, after={}".format(
            uptime_after_first_delete, uptime_after_second_delete
        )
    )


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))