#!/usr/bin/env python
# SPDX-License-Identifier: ISC
#
# test_pim_no_path_to_rp.py
#
# Copyright (c) 2026 Nvidia Inc.
#               Donald Sharp
#

"""
test_pim_no_path_to_rp.py: PIM without RP reachability

Network diagram:

    rp (.3) -------- r1 (.1) -------- r2 (.2)
      |
      +-- lo: 10.255.0.3/32 (RP address)
"""

import json
import os
import sys
import pytest
from functools import partial

pytestmark = [pytest.mark.pimd]

# Save the Current Working Directory to find configuration files.
CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

# pylint: disable=C0413
# Import topogen and topotest helpers
from lib import topotest
from lib.topogen import Topogen, TopoRouter, get_topogen
from lib.topolog import logger


#####################################################
##
##   Network Topology Definition
##
#####################################################


def build_topo(tgen):
    """
    Topology:

        rp (.3) -------- r1 (.1) -------- r2 (.2)
          |
          +-- lo: 10.255.0.3/32 (RP address)
    """

    tgen.add_router("rp")
    tgen.add_router("r1")
    tgen.add_router("r2")

    switch = tgen.add_switch("s1")
    switch.add_link(tgen.gears["rp"])
    switch.add_link(tgen.gears["r1"])

    switch = tgen.add_switch("s2")
    switch.add_link(tgen.gears["r1"])
    switch.add_link(tgen.gears["r2"])


#####################################################
##
##   Tests starting
##
#####################################################


def setup_module(module):
    "Setup topology"
    tgen = Topogen(build_topo, module.__name__)
    tgen.start_topology()

    router_list = tgen.routers()
    for rname, router in router_list.items():
        router.load_frr_config(
            os.path.join(CWD, "{}/frr.conf".format(rname)),
            [
                (TopoRouter.RD_ZEBRA, None),
                (TopoRouter.RD_PIM, None),
            ],
        )

    tgen.start_router()


def teardown_module(_mod):
    "Teardown the pytest environment"
    tgen = get_topogen()
    tgen.stop_topology()


def test_no_route_to_rp_loopback():
    "Verify r1 has no route to RP loopback"
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]

    def _no_route():
        output = r1.vtysh_cmd("show ip route 10.255.0.3/32")
        if "Network not in table" in output:
            return None
        return output

    logger.info("Checking r1 has no route to RP loopback 10.255.0.3/32")
    _, result = topotest.run_and_expect(_no_route, None, count=20, wait=1)
    assertmsg = "r1: route to RP loopback 10.255.0.3/32 should not exist"
    assert result is None, assertmsg


def test_pim_neighbors():
    "Verify PIM neighbors are formed between rp and r1"
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    logger.info("Checking PIM neighbor adjacencies")

    rp = tgen.gears["rp"]
    expected = {
        "rp-eth0": {},
    }
    test_func = partial(
        topotest.router_json_cmp, rp, "show ip pim neighbor json", expected
    )
    logger.info("Checking rp has PIM neighbor on rp-eth0")
    _, result = topotest.run_and_expect(test_func, None, count=60, wait=1)
    assertmsg = "rp: PIM neighbor with r1 did not converge"
    assert result is None, assertmsg

    r1 = tgen.gears["r1"]
    expected = {
        "r1-eth0": {},
    }
    test_func = partial(
        topotest.router_json_cmp, r1, "show ip pim neighbor json", expected
    )
    logger.info("Checking r1 has PIM neighbor on r1-eth0")
    _, result = topotest.run_and_expect(test_func, None, count=60, wait=1)
    assertmsg = "r1: PIM neighbor with rp did not converge"
    assert result is None, assertmsg

    logger.info("rp and r1 PIM neighbors converged successfully")


def test_mcast_stream_from_r2():
    "Send a multicast stream from r2 towards r1"
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]
    r2 = tgen.gears["r2"]

    group = "229.1.1.1"
    source = "10.0.2.2"

    mcast_tester = os.path.join(CWD, "../lib/mcast-tester.py")
    cmd_rx = [mcast_tester, group, "r1-eth1"]
    p_rx = r1.popen(cmd_rx)

    mcast_tx = os.path.join(CWD, "../pim_basic/mcast-tx.py")
    cmd_tx = [
        mcast_tx,
        "--ttl",
        "10",
        "--count",
        "1000000000",
        "--interval",
        "5000",
        group,
        "r2-eth0",
    ]
    p_tx = r2.popen(cmd_tx)

    def _mroute_present():
        output = r1.vtysh_cmd("show ip mroute json")
        try:
            data = json.loads(output)
        except json.JSONDecodeError:
            return output
        if group in data and source in data[group]:
            return None
        return data

    logger.info("Checking r1 has mroute for (%s,%s)", source, group)
    _, result = topotest.run_and_expect(_mroute_present, None, count=30, wait=1)
    assertmsg = f"r1: mroute for ({source},{group}) not present after traffic"
    assert result is None, assertmsg

    def _igmp_group_present():
        output = r1.vtysh_cmd("show ip igmp group json")
        try:
            data = json.loads(output)
        except json.JSONDecodeError:
            return output
        if "r1-eth1" not in data:
            return data
        groups = data["r1-eth1"].get("groups", [])
        for entry in groups:
            if entry.get("group") == group:
                return None
        return data

    logger.info("Checking r1 has IGMP group %s on r1-eth1", group)
    _, result = topotest.run_and_expect(_igmp_group_present, None, count=30, wait=1)
    assertmsg = f"r1: IGMP group {group} not present on r1-eth1"
    assert result is None, assertmsg

    logger.info("Adding routes to/from the RP")
    rp = tgen.gears["rp"]
    rp.vtysh_cmd("configure terminal\nip route 10.0.2.0/24 10.0.1.1")
    r1.vtysh_cmd("configure terminal\nip route 10.255.0.3/32 10.0.1.3")

    def _rp_loopback_reachable():
        output = r1.vtysh_cmd("show ip route 10.255.0.3/32")
        if "10.0.1.3, via r1-eth0" in output:
            return None
        return output

    logger.info("Checking r1 has route to RP loopback via r1-eth0")
    _, result = topotest.run_and_expect(_rp_loopback_reachable, None, count=20, wait=1)
    assertmsg = "r1: route to RP loopback 10.255.0.3/32 not installed"
    assert result is None, assertmsg

    def _r1_source_reachable():
        output = rp.vtysh_cmd("show ip route 10.0.2.2")
        if "10.0.1.1, via rp-eth0" in output:
            return None
        return output

    logger.info("Checking rp has route to source 10.0.2.2 via rp-eth0")
    _, result = topotest.run_and_expect(_r1_source_reachable, None, count=20, wait=1)
    assertmsg = "rp: route to source 10.0.2.2/32 not installed"
    assert result is None, assertmsg

    def _r1_rp_info_reachable():
        output = r1.vtysh_cmd("show ip pim rp-info json")
        try:
            data = json.loads(output)
        except json.JSONDecodeError:
            return output
        rp_info = data.get("10.255.0.3", [])
        for entry in rp_info:
            if entry.get("outboundInterface") == "r1-eth0":
                return None
        return data

    logger.info("Checking r1 rp-info shows RP via r1-eth0")
    _, result = topotest.run_and_expect(_r1_rp_info_reachable, None, count=20, wait=1)
    assertmsg = "r1: RP info for 10.255.0.3 not reachable via r1-eth0"
    assert result is None, assertmsg

    def _r1_upstream_state():
        output = r1.vtysh_cmd("show ip pim upstream 10.0.2.2 229.1.1.1 json")
        try:
            data = json.loads(output)
        except json.JSONDecodeError:
            return output
        upstream = data.get("229.1.1.1", {}).get("10.0.2.2", {})
        if not upstream:
            return "NO UPSTREAM for 10.0.2.2,229.1.1.1"
        if upstream.get("inboundInterface") != "r1-eth1":
            return "Upstream not on r1-eth1"
        if upstream.get("rpfAddress") != "10.255.0.3":
            return "rpfAddress is not 10.255.0.3"
        if upstream.get("state") != "J,RegP":
            return "State is not NotJ,RegP"
        if upstream.get("regState") != "RegPrune":
            return "regstate is not RegPrune"
        return None

    logger.info("Checking r1 upstream 10.0.2.2/229.1.1.1 is RegPrune")
    _, result = topotest.run_and_expect(_r1_upstream_state, None, count=30, wait=1)
    assertmsg = "r1: upstream 10.0.2.2/229.1.1.1 not in expected RegPrune state"
    assert result is None, assertmsg

    def _rp_upstream_state():
        output = rp.vtysh_cmd("show ip pim upstream 10.0.2.2 229.1.1.1 json")
        try:
            data = json.loads(output)
        except json.JSONDecodeError:
            return output
        upstream = data.get("229.1.1.1", {}).get("10.0.2.2", {})
        if not upstream:
            return "No UPSTREAM for 10.0.2.2, 229.1.1.1"
        if upstream.get("inboundInterface") != "rp-eth0":
            return "Upstream not on rp-eth0"
        if upstream.get("rpfAddress") != "10.0.2.2":
            return "rpfAddress is not 10.0.2.2"
        if upstream.get("state") != "NotJ":
            return "State is not Joined"
        if upstream.get("regState") != "RegNoInfo":
            return "regstate is not RegNoInfo"
        return None

    logger.info("Checking rp upstream 10.0.2.2/229.1.1.1 is RegNoInfo")
    _, result = topotest.run_and_expect(_rp_upstream_state, None, count=30, wait=1)
    assertmsg = "rp: upstream 10.0.2.2/229.1.1.1 not in expected RegNoInfo state"
    assert result is None, assertmsg

    if p_tx:
        p_tx.terminate()
        p_tx.wait()
    if p_rx:
        p_rx.terminate()
        p_rx.wait()


def test_memory_leak():
    "Run the memory leak test and report results."
    tgen = get_topogen()
    if not tgen.is_memleak_enabled():
        pytest.skip("Memory leak test/report is disabled")

    tgen.report_memory_leaks()


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
