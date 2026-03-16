#!/usr/bin/env python
# SPDX-License-Identifier: ISC

#
# test_zebra_tracker.py
#
# Copyright (c) 2026 by
# Nvidia Corporation
# Donald Sharp
#

"""
test_zebra_tracker.py: Testing five routers with BGP and RIP peering.

Topology:

              10.0.1.0/24
        .1 +------------+ .2
    +------+ r1-eth0     r2-eth0 [r2]
    |      +------------+
    |
    |      10.0.2.0/24
    |  .1 +------------+ .3
    + r1--+ r1-eth1     r3-eth0 [r3]
    |     +------------+
    |
    |      10.0.3.0/24
    |  .1 +------------+ .4
    +-----+ r1-eth2     r4-eth0 [r4]
    |     +------------+
    |
    |      10.0.4.0/24
    |  .1 +------------+ .5
    +-----+ r1-eth3     r5-eth0 [r5]
          +------------+
"""

import os
import re
import sys
import json
import pytest
import functools

pytestmark = [pytest.mark.bgpd, pytest.mark.ripd, pytest.mark.sharpd]

CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

from lib import topotest
from lib.topogen import Topogen, TopoRouter, get_topogen
from lib.topolog import logger


def build_topo(tgen):
    for rname in ["r1", "r2", "r3", "r4", "r5"]:
        tgen.add_router(rname)

    r1 = tgen.gears["r1"]

    # r1-eth0 <-> r2-eth0 via sw1
    sw1 = tgen.add_switch("sw1")
    sw1.add_link(r1)
    sw1.add_link(tgen.gears["r2"])

    # r1-eth1 <-> r3-eth0 via sw2
    sw2 = tgen.add_switch("sw2")
    sw2.add_link(r1)
    sw2.add_link(tgen.gears["r3"])

    # r1-eth2 <-> r4-eth0 via sw3
    sw3 = tgen.add_switch("sw3")
    sw3.add_link(r1)
    sw3.add_link(tgen.gears["r4"])

    # r1-eth3 <-> r5-eth0 via sw4
    sw4 = tgen.add_switch("sw4")
    sw4.add_link(r1)
    sw4.add_link(tgen.gears["r5"])


def setup_module(module):
    tgen = Topogen(build_topo, module.__name__)
    tgen.start_topology()

    router_list = tgen.routers()
    for rname, router in router_list.items():
        router.load_frr_config(
            os.path.join(CWD, "{}/frr.conf".format(rname)),
            [
                (TopoRouter.RD_ZEBRA, None),
                (TopoRouter.RD_BGP, None),
                (TopoRouter.RD_RIP, None),
                (TopoRouter.RD_SHARP, None),
            ],
        )

    tgen.start_router()


def teardown_module(_mod):
    tgen = get_topogen()
    tgen.stop_topology()


def test_bgp_convergence():
    "Verify that all BGP sessions reach Established state"
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    logger.info("Checking that all 4 EBGP sessions on r1 reach Established state")

    r1 = tgen.gears["r1"]

    expected_peers = {
        "10.0.1.2": {"state": "Established"},
        "10.0.2.3": {"state": "Established"},
        "10.0.3.4": {"state": "Established"},
        "10.0.4.5": {"state": "Established"},
    }

    def check_bgp_peers():
        output = json.loads(r1.vtysh_cmd("show bgp ipv4 unicast summary json"))
        peers = output.get("peers", {})
        for peer_addr, expected in expected_peers.items():
            if peer_addr not in peers:
                return "peer {} not found".format(peer_addr)
            if peers[peer_addr].get("state") != expected["state"]:
                return "peer {} state is {} expected {}".format(
                    peer_addr,
                    peers[peer_addr].get("state"),
                    expected["state"],
                )
        return None

    _, result = topotest.run_and_expect(check_bgp_peers, None, count=30, wait=1)
    assert result is None, "BGP convergence failed: {}".format(result)


def test_rip_convergence():
    "Verify that RIP routes are learned on all routers"
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    logger.info("Checking that r2-r5 each learn remote networks via RIP")

    # r2 should learn routes to 10.0.2.0/24, 10.0.3.0/24, 10.0.4.0/24 via RIP
    # (it already knows 10.0.1.0/24 as directly connected)
    rip_expected = {
        "r2": ["10.0.2.0/24", "10.0.3.0/24", "10.0.4.0/24"],
        "r3": ["10.0.1.0/24", "10.0.3.0/24", "10.0.4.0/24"],
        "r4": ["10.0.1.0/24", "10.0.2.0/24", "10.0.4.0/24"],
        "r5": ["10.0.1.0/24", "10.0.2.0/24", "10.0.3.0/24"],
    }

    def check_rip_routes(rname, expected_routes):
        router = tgen.gears[rname]
        output = json.loads(router.vtysh_cmd("show ip route rip json"))
        for route in expected_routes:
            if route not in output:
                return "{}: RIP route {} not found".format(rname, route)
        return None

    for rname, expected_routes in rip_expected.items():
        _, result = topotest.run_and_expect(
            functools.partial(check_rip_routes, rname, expected_routes),
            None,
            count=30,
            wait=2,
        )
        assert result is None, "RIP convergence failed: {}".format(result)


@pytest.mark.skip
def test_nhg_tracker_show_run():
    "Verify that zebra nexthop-group tracker 20 appears in show running-config on r1"
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    logger.info(
        "Verifying 'zebra nexthop-group tracker 20' is present in r1 show running-config"
    )

    r1 = tgen.gears["r1"]

    def check_tracker_present():
        output = r1.vtysh_cmd("show running-config")
        if "zebra nexthop-group tracker 20" not in output:
            return "zebra nexthop-group tracker 20 not found in show run"
        return None

    _, result = topotest.run_and_expect(check_tracker_present, None, count=20, wait=1)
    assert result is None, "NHG tracker show run failed: {}".format(result)

    logger.info(
        "Verifying 'show zebra' on r1 reports NHG Tracker Timeout as 20 seconds"
    )

    def check_show_zebra_tracker_20():
        output = r1.vtysh_cmd("show zebra")
        if not re.search(r"NHG Tracker Timeout\s+20 seconds", output):
            return "NHG Tracker Timeout 20 seconds not found in show zebra"
        return None

    _, result = topotest.run_and_expect(
        check_show_zebra_tracker_20, None, count=20, wait=1
    )
    assert result is None, "show zebra tracker timeout check failed: {}".format(result)


@pytest.mark.skip
def test_nhg_tracker_no_form():
    "Verify that 'no zebra nexthop-group tracker' removes the config from show run"
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    logger.info(
        "Issuing 'no zebra nexthop-group tracker' and verifying it is removed from r1 show running-config"
    )

    r1 = tgen.gears["r1"]
    r1.vtysh_cmd("configure terminal\nno zebra nexthop-group tracker\nend")

    def check_tracker_absent():
        output = r1.vtysh_cmd("show running-config")
        if "zebra nexthop-group tracker" in output:
            return "zebra nexthop-group tracker still found in show run"
        return None

    _, result = topotest.run_and_expect(check_tracker_absent, None, count=20, wait=1)
    assert result is None, "NHG tracker negation failed: {}".format(result)

    logger.info(
        "Verifying 'show zebra' on r1 reports NHG Tracker Timeout back to default 60 seconds"
    )

    def check_show_zebra_tracker_default():
        output = r1.vtysh_cmd("show zebra")
        if not re.search(r"NHG Tracker Timeout\s+60 seconds", output):
            return "NHG Tracker Timeout 60 seconds not found in show zebra"
        return None

    _, result = topotest.run_and_expect(
        check_show_zebra_tracker_default, None, count=20, wait=1
    )
    assert result is None, "show zebra tracker default timeout check failed: {}".format(
        result
    )


def test_nhg_tracker_sharp_routes_parking():
    """
    Verify tracker creation and RE parking: install sharp routes with 4-way ECMP,
    trigger link down (eth0), send 3-way updates and check routes are
    parked in the correct tracker matched/unmatched tables. Repeat for eth1 down.
    """
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]
    # Store last "show nexthop-group rib" output for printing on assert failure
    last_rib_output = [None]

    # Set tracker timer to 600 seconds so trackers do not expire during the test
    r1.vtysh_cmd("configure terminal\nzebra nexthop-group tracker 600\nend")

    # Step 1: Install 8 routes with 4-way ECMP (nexthops = peer IPs on r1's links)
    logger.info("Step 1: Install 8 sharp routes with 4-way ECMP")
    r1.vtysh_cmd(
        "sharp install routes 45.1.1.1 nexthops 10.0.1.2,10.0.2.3,10.0.3.4,10.0.4.5 8"
    )

    def check_route_installed():
        out = r1.vtysh_cmd("show ip route 45.1.1.1 json")
        try:
            data = json.loads(out)
        except json.JSONDecodeError:
            return "show ip route 45.1.1.1 json failed or invalid"
        key = "45.1.1.1/32"
        if key not in data or not data[key]:
            return "route 45.1.1.1/32 not found"
        entry = data[key][0]
        if not entry.get("installed", False):
            return "route 45.1.1.1/32 not installed"
        return None

    _, result = topotest.run_and_expect(check_route_installed, None, count=30, wait=1)
    assert result is None, "Route 45.1.1.1 not installed: {}".format(result)

    out = r1.vtysh_cmd("show ip route 45.1.1.1 json")
    data = json.loads(out)
    installed_nhg_id = data["45.1.1.1/32"][0].get("installedNexthopGroupId")
    assert installed_nhg_id is not None, "installedNexthopGroupId not found"
    logger.info("installedNexthopGroupId = %s", installed_nhg_id)

    # Step 2: Link r1-eth0 down -> tracker T1 created
    logger.info("Step 2: Shut r1-eth0 to create tracker T1")
    r1.vtysh_cmd("configure terminal\ninterface r1-eth0\nshutdown\nend")

    def check_t1_created():
        out = r1.vtysh_cmd(
            "show nexthop-group rib {} json".format(installed_nhg_id)
        )
        last_rib_output[0] = out
        try:
            data = json.loads(out)
        except json.JSONDecodeError:
            return "show nexthop-group rib json failed"
        nhe = data.get(str(installed_nhg_id))
        if not nhe or "trackers" not in nhe:
            return "no trackers on NHG"
        trackers = nhe["trackers"]
        if len(trackers) < 1:
            return "expected at least 1 tracker"
        t1 = trackers[0]
        if t1.get("event") != "DOWN":
            return "T1 event expected DOWN, got {}".format(t1.get("event"))
        if t1.get("expectedReCount") != 8:
            return "T1 expectedReCount expected 8, got {}".format(
                t1.get("expectedReCount")
            )
        # ifindex 2 = r1-eth0
        if t1.get("ifindex") != 2:
            return "T1 ifindex expected 2 (r1-eth0), got {}".format(t1.get("ifindex"))
        # Snapshot: first NH (eth0) should not have "active":true; others should
        snap = t1.get("snapshotNexthops", [])
        if len(snap) < 4:
            return "T1 snapshot expected 4 nexthops, got {}".format(len(snap))
        if snap[0].get("active", False):
            return "T1 snapshot NH0 (eth0) should be inactive"
        for i in range(1, 4):
            if not snap[i].get("active", False):
                return "T1 snapshot NH{} should be active".format(i)
        return None

    _, result = topotest.run_and_expect(check_t1_created, None, count=20, wait=1)
    assert result is None, (
        "T1 creation check failed: {}\nshow nexthop-group rib {} json:\n{}"
    ).format(result, installed_nhg_id, last_rib_output[0] or "")

    # Send 3 routes with 3-way ECMP (match T1 snapshot: eth0 down, eth1-3 up)
    logger.info("Send 3 sharp routes with 3-way ECMP (match T1)")
    r1.vtysh_cmd(
        "sharp install routes 45.1.1.1 nexthops 10.0.2.3,10.0.3.4,10.0.4.5 3"
    )

    # Step 3: Link r1-eth1 down -> tracker T2 created
    logger.info("Step 3: Shut r1-eth1 to create tracker T2")
    r1.vtysh_cmd("configure terminal\ninterface r1-eth1\nshutdown\nend")

    # Send 2 sharp routes with 2-way ECMP (match T2 snapshot: eth0+eth1 down, eth2+eth3 up)
    # Routes 45.1.1.4, 45.1.1.5 -> should be parked in T2 matched table
    logger.info("Send 2 sharp routes (45.1.1.4, 45.1.1.5) with 2-way ECMP to match T2")
    r1.vtysh_cmd(
        "sharp install routes 45.1.1.4 nexthops 10.0.3.4,10.0.4.5 2"
    )

    def check_trackers_state():
        out = r1.vtysh_cmd(
            "show nexthop-group rib {} json".format(installed_nhg_id)
        )
        last_rib_output[0] = out
        try:
            data = json.loads(out)
        except json.JSONDecodeError:
            return "show nexthop-group rib json failed"
        # NHE holds tracker chain in creation order (newest first): [T2, T1]
        nhe = data.get(str(installed_nhg_id))
        if not nhe:
            return "NHE id {} not found in output".format(installed_nhg_id)
        trackers = nhe.get("trackers", [])
        if len(trackers) != 2:
            return "expected 2 trackers on NHE, got {}".format(len(trackers))

        # Verify trackers states
        if trackers[0].get("ifindex") != 3 or trackers[0].get("trackerId") != 2:
            return "trackers[0] expected T2 (ifindex 3, trackerId 2), got ifindex {} trackerId {}".format(
                trackers[0].get("ifindex"), trackers[0].get("trackerId")
            )
        if trackers[1].get("ifindex") != 2 or trackers[1].get("trackerId") != 1:
            return "trackers[1] expected T1 (ifindex 2, trackerId 1), got ifindex {} trackerId {}".format(
                trackers[1].get("ifindex"), trackers[1].get("trackerId")
            )

        t1 = trackers[1]  # T1 = first link down (r1-eth0, ifindex 2)
        t2 = trackers[0]  # T2 = second link down (r1-eth1, ifindex 3)

        for t in (t1, t2):
            if t.get("event") != "DOWN":
                return "tracker ifindex {} event expected DOWN".format(t.get("ifindex"))
            if t.get("expectedReCount") != 8:
                return "tracker ifindex {} expectedReCount expected 8".format(
                    t.get("ifindex")
                )

        # T2 snapshot: eth0 and eth1 inactive, eth2/eth3 active
        snap2 = t2.get("snapshotNexthops", [])
        if len(snap2) < 4:
            return "T2 snapshot expected 4 nexthops"
        if snap2[0].get("active", False) or snap2[1].get("active", False):
            return "T2 snapshot NH0/NH1 (eth0/eth1) should be inactive"
        if not snap2[2].get("active", False) or not snap2[3].get("active", False):
            return "T2 snapshot NH2/NH3 should be active"

        # T1 snapshot: eth0 inactive, eth1/2/3 active
        snap1 = t1.get("snapshotNexthops", [])
        if snap1[0].get("active", False):
            return "T1 snapshot NH0 (eth0) should be inactive"
        for i in range(1, 4):
            if not snap1[i].get("active", False):
                return "T1 snapshot NH{} should be active".format(i)

        # Expected counts: T1 matched 3, unmatched 0; T2 matched 2, unmatched 0
        if t1.get("matchedRoutes") != 3:
            return "T1 matchedRoutes expected 3, got {}".format(
                t1.get("matchedRoutes")
            )
        if t1.get("unmatchedRoutes") != 0:
            return "T1 unmatchedRoutes expected 0, got {}".format(
                t1.get("unmatchedRoutes")
            )
        if t2.get("matchedRoutes") != 2:
            return "T2 matchedRoutes expected 2, got {}".format(
                t2.get("matchedRoutes")
            )
        if t2.get("unmatchedRoutes") != 0:
            return "T2 unmatchedRoutes expected 0, got {}".format(
                t2.get("unmatchedRoutes")
            )

        return None

    _, result = topotest.run_and_expect(check_trackers_state, None, count=30, wait=1)
    assert result is None, (
        "Two-tracker state check failed: {}\nshow nexthop-group rib {} json:\n{}"
    ).format(result, installed_nhg_id, last_rib_output[0] or "")


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
