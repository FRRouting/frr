#!/usr/bin/env python
# SPDX-License-Identifier: ISC

#
# test_pim_cand_rp_bsr.py
#
# Copyright (c) 2024 ATCorp
# Jafar Al-Gharaibeh
#

import os
import sys
import pytest
import json
from functools import partial

# pylint: disable=C0413
# Import topogen and topotest helpers
from lib import topotest
from lib.topogen import Topogen, get_topogen
from lib.topolog import logger
from lib.pim import verify_pim_rp_info
from lib.common_config import step, write_test_header, retry

from time import sleep

"""
test_pim_cand_rp_bsr.py: Test candidate RP/BSR functionality
"""

TOPOLOGY = """
    Candidate RP/BSR functionality

    +---+---+                      +---+---+
    | C-BSR |     10.0.0.0/24      | C-BSR |
    +  R1   + <--------+---------> +  R2   |
    |elected| .1       |        .2 |       |
    +---+---+          |           +---+---+
     .1 |              |  10.0.2.0/24  | .2
        | 10.0.1.0/24  |               |
     .3 |              +-----|  .4     | .4
    +---+---+                |---->+---+---+
    | C-RP  |    10.0.3.0/24       | C-RP  |
    +  R3   + <--------+---------> +  R4   |
    | prio  | .3       |        .4 |       |
    +---+---+          |           +---+---+
     .3 |              |              | .4
        |10.0.4.0/24   |   10.0.5.0/24|
     .5 |              |         .6   | .6
    +---+---+          +---------->+---+---+
    |       |                      |       |
    +  R5   + <------------------> +  R6   |
    |       | .5                .6 |       |
    +---+---+     10.0.6.0/24      +---+---+
"""

# Save the Current Working Directory to find configuration files.
CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

# Required to instantiate the topology builder class.
pytestmark = [
    pytest.mark.pimd,
    pytest.mark.pim6d,
    pytest.mark.ospfd,
    pytest.mark.ospf6d,
]


def build_topo(tgen):
    "Build function"

    # Create 6 routers
    for rn in range(1, 7):
        tgen.add_router("r{}".format(rn))

    # Create 7 switches and connect routers
    sw1 = tgen.add_switch("s1")
    sw1.add_link(tgen.gears["r1"])
    sw1.add_link(tgen.gears["r2"])

    sw = tgen.add_switch("s2")
    sw.add_link(tgen.gears["r1"])
    sw.add_link(tgen.gears["r3"])

    sw = tgen.add_switch("s3")
    sw.add_link(tgen.gears["r2"])
    sw.add_link(tgen.gears["r4"])

    sw3 = tgen.add_switch("s4")
    sw3.add_link(tgen.gears["r3"])
    sw3.add_link(tgen.gears["r4"])

    sw = tgen.add_switch("s5")
    sw.add_link(tgen.gears["r3"])
    sw.add_link(tgen.gears["r5"])

    sw = tgen.add_switch("s6")
    sw.add_link(tgen.gears["r4"])
    sw.add_link(tgen.gears["r6"])

    sw = tgen.add_switch("s7")
    sw.add_link(tgen.gears["r5"])
    sw.add_link(tgen.gears["r6"])

    # make the diagnoal connections
    sw1.add_link(tgen.gears["r4"])
    sw3.add_link(tgen.gears["r6"])


def setup_module(mod):
    logger.info("PIM Candidate RP/BSR:\n {}".format(TOPOLOGY))

    tgen = Topogen(build_topo, mod.__name__)
    tgen.start_topology()

    router_list = tgen.routers()
    for rname, router in router_list.items():
        logger.info("Loading router %s" % rname)
        router.load_frr_config(os.path.join(CWD, "{}/frr.conf".format(rname)))

    # Initialize all routers.
    tgen.start_router()
    for router in router_list.values():
        if router.has_version("<", "4.0"):
            tgen.set_error("unsupported version")


def teardown_module(mod):
    "Teardown the pytest environment"
    tgen = get_topogen()
    tgen.stop_topology()


def test_pim_bsr_election_r1(request):
    "Test PIM BSR Election"
    tgen = get_topogen()
    tc_name = request.node.name
    write_test_header(tc_name)

    if tgen.routers_have_failure():
        pytest.skip("skipped because of router(s) failure")

    r2 = tgen.gears["r2"]
    # r1 should be the BSR winner because it has higher priority
    expected = {
        "bsr": "10.0.0.1",
        "priority": 200,
        "state": "ACCEPT_PREFERRED",
    }

    test_func = partial(topotest.router_json_cmp, r2, "show ip pim bsr json", expected)
    _, result = topotest.run_and_expect(test_func, None, count=60, wait=1)

    assertmsg = "r2: r1 was not elected, bsr election mismatch"
    assert result is None, assertmsg


def test_pim_bsr_cand_bsr_r1(request):
    "Test PIM BSR candidate BSR"
    tgen = get_topogen()
    tc_name = request.node.name
    write_test_header(tc_name)

    if tgen.routers_have_failure():
        pytest.skip("skipped because of router(s) failure")

    r2 = tgen.gears["r2"]

    # r2 is a candidate bsr with low priority: elected = False
    expected = {"address": "10.0.0.2", "priority": 100, "elected": False}
    test_func = partial(
        topotest.router_json_cmp, r2, "show ip pim bsr candidate-bsr json", expected
    )
    _, result = topotest.run_and_expect(test_func, None, count=60, wait=1)

    assertmsg = "r2: candidate bsr mismatch "
    assert result is None, assertmsg


def test_pim_bsr_cand_rp(request):
    "Test PIM BSR candidate RP"
    tgen = get_topogen()
    tc_name = request.node.name
    write_test_header(tc_name)

    if tgen.routers_have_failure():
        pytest.skip("skipped because of router(s) failure")

    r3 = tgen.gears["r3"]

    # r3 is a candidate rp
    expected = {"address": "10.0.3.3", "priority": 10}
    test_func = partial(
        topotest.router_json_cmp, r3, "show ip pim bsr candidate-rp json", expected
    )
    _, result = topotest.run_and_expect(test_func, None, count=60, wait=1)

    assertmsg = "r3: bsr candidate rp mismatch"
    assert result is None, assertmsg


def test_pim_bsr_rp_info(request):
    "Test RP info state"
    tgen = get_topogen()
    tc_name = request.node.name
    write_test_header(tc_name)

    if tgen.routers_have_failure():
        pytest.skip("skipped because of router(s) failure")

    # At this point, all nodes, including r5 should have synced the RP state
    step("Verify rp-info on r5 from BSR")
    result = verify_pim_rp_info(
        tgen,
        None,
        "r5",
        "239.0.0.0/16",
        None,
        "10.0.3.3",
        "BSR",
        False,
        "ipv4",
        True,
        retry_timeout=90,
    )
    assert result is True, "Testcase {} :Failed \n Error: {}".format(tc_name, result)

    result = verify_pim_rp_info(
        tgen,
        None,
        "r5",
        "239.0.0.0/8",
        None,
        "10.0.3.4",
        "BSR",
        False,
        "ipv4",
        True,
        retry_timeout=30,
    )
    assert result is True, "Testcase {} :Failed \n Error: {}".format(tc_name, result)

    result = verify_pim_rp_info(
        tgen,
        None,
        "r5",
        "239.0.0.0/24",
        None,
        "10.0.3.4",
        "BSR",
        False,
        "ipv4",
        True,
        retry_timeout=30,
    )
    assert result is True, "Testcase {} :Failed \n Error: {}".format(tc_name, result)

    step("Verify rp-info on the BSR node itself r1")
    result = verify_pim_rp_info(
        tgen,
        None,
        "r1",
        "239.0.0.0/16",
        None,
        "10.0.3.3",
        "BSR",
        False,
        "ipv4",
        True,
        retry_timeout=10,
    )
    assert result is True, "Testcase {} :Failed \n Error: {}".format(tc_name, result)

    result = verify_pim_rp_info(
        tgen,
        None,
        "r1",
        "239.0.0.0/8",
        None,
        "10.0.3.4",
        "BSR",
        False,
        "ipv4",
        True,
        retry_timeout=10,
    )
    assert result is True, "Testcase {} :Failed \n Error: {}".format(tc_name, result)

    result = verify_pim_rp_info(
        tgen,
        None,
        "r1",
        "239.0.0.0/24",
        None,
        "10.0.3.4",
        "BSR",
        False,
        "ipv4",
        True,
        retry_timeout=10,
    )
    assert result is True, "Testcase {} :Failed \n Error: {}".format(tc_name, result)


def test_pim_bsr_election_fallback_r2(request):
    "Test PIM BSR Election Backup"
    tgen = get_topogen()
    tc_name = request.node.name
    write_test_header(tc_name)

    if tgen.routers_have_failure():
        pytest.skip("skipped because of router(s) failure")

    step("Take r1 out from BSR candidates")
    r1 = tgen.gears["r1"]
    r1.vtysh_cmd(
        """
        configure
          router pim
            no bsr candidate-bsr priority 200 source address 10.0.0.1
        """
    )

    step("Verify r1 is no longer a BSR candidate")
    expected = {}

    test_func = partial(
        topotest.router_json_cmp, r1, "show ip pim bsr candidate-bsr json", expected
    )
    _, result = topotest.run_and_expect(test_func, None, count=10, wait=1)

    assertmsg = "r1: failed to remove bsr candidate configuration"
    assert result is None, assertmsg

    r2 = tgen.gears["r2"]
    # We should fall back to r2 as the BSR
    expected = {
        "bsr": "10.0.0.2",
        "priority": 100,
        "state": "BSR_ELECTED",
    }

    step("Verify that we fallback to r2 as the new BSR")

    test_func = partial(topotest.router_json_cmp, r2, "show ip pim bsr json", expected)
    _, result = topotest.run_and_expect(test_func, None, count=180, wait=1)

    assertmsg = "r2: failed to fallback to r2 as a BSR"
    assert result is None, assertmsg


def test_pim_bsr_rp_info_fallback(request):
    "Test RP info state on r5"
    tgen = get_topogen()
    tc_name = request.node.name
    write_test_header(tc_name)

    if tgen.routers_have_failure():
        pytest.skip("skipped because of router(s) failure")

    step("Take r3 out from RP candidates for group 239.0.0.0/16")
    r3 = tgen.gears["r3"]
    r3.vtysh_cmd(
        """
        configure
          router pim
            no bsr candidate-rp group 239.0.0.0/16
        """
    )

    step("Verify falling back to r4 as the new RP for 239.0.0.0/16")

    result = verify_pim_rp_info(
        tgen,
        None,
        "r5",
        "239.0.0.0/16",
        None,
        "10.0.3.4",
        "BSR",
        False,
        "ipv4",
        True,
        retry_timeout=30,
    )
    assert result is True, "Testcase {} :Failed \n Error: {}".format(tc_name, result)


def test_pimv6_bsr_election_r1(request):
    "Test PIMv6 BSR Election"
    tgen = get_topogen()
    tc_name = request.node.name
    write_test_header(tc_name)

    if tgen.routers_have_failure():
        pytest.skip("skipped because of router(s) failure")

    r2 = tgen.gears["r2"]
    # r1 should be the BSR winner because it has higher priority
    expected = {
        "bsr": "fd00::1",
        "priority": 200,
        "state": "ACCEPT_PREFERRED",
    }

    test_func = partial(
        topotest.router_json_cmp, r2, "show ipv6 pim bsr json", expected
    )
    _, result = topotest.run_and_expect(test_func, None, count=60, wait=1)

    assertmsg = "r2: r1 was not elected, IPv6 bsr election mismatch"
    assert result is None, assertmsg


def test_pimv6_bsr_cand_rp(request):
    "Test PIMv6 BSR candidate RP"
    tgen = get_topogen()
    tc_name = request.node.name
    write_test_header(tc_name)

    if tgen.routers_have_failure():
        pytest.skip("skipped because of router(s) failure")

    r3 = tgen.gears["r3"]

    # r3 is a candidate rp
    expected = {"address": "fd00:0:0:3::3", "priority": 10}
    test_func = partial(
        topotest.router_json_cmp, r3, "show ipv6 pim bsr candidate-rp json", expected
    )
    _, result = topotest.run_and_expect(test_func, None, count=60, wait=1)

    assertmsg = "r3: bsr candidate rp mismatch"
    assert result is None, assertmsg


def test_pimv6_bsr_rp_info(request):
    "Test IPv6 RP info state"
    tgen = get_topogen()
    tc_name = request.node.name
    write_test_header(tc_name)

    if tgen.routers_have_failure():
        pytest.skip("skipped because of router(s) failure")

    # At this point, all nodes, including r5 should have synced the RP state
    step("Verify rp-info on r5 from BSR")
    result = verify_pim_rp_info(
        tgen,
        None,
        "r5",
        "ffbb::0/64",
        None,
        "fd00:0:0:3::3",
        "BSR",
        False,
        "ipv6",
        True,
        retry_timeout=90,
    )
    assert result is True, "Testcase {} :Failed \n Error: {}".format(tc_name, result)

    result = verify_pim_rp_info(
        tgen,
        None,
        "r5",
        "ffbb::0/124",
        None,
        "fd00:0:0:3::4",
        "BSR",
        False,
        "ipv6",
        True,
        retry_timeout=30,
    )
    assert result is True, "Testcase {} :Failed \n Error: {}".format(tc_name, result)

    result = verify_pim_rp_info(
        tgen,
        None,
        "r5",
        "ffbb::0/108",
        None,
        "fd00:0:0:3::4",
        "BSR",
        False,
        "ipv6",
        True,
        retry_timeout=30,
    )
    assert result is True, "Testcase {} :Failed \n Error: {}".format(tc_name, result)


def test_memory_leak():
    "Run the memory leak test and report results."
    tgen = get_topogen()
    if not tgen.is_memleak_enabled():
        pytest.skip("Memory leak test/report is disabled")

    tgen.report_memory_leaks()


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
