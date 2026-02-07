#!/usr/bin/env python
# SPDX-License-Identifier: ISC

#
# test_bfd_static_vrf.py
# Part of NetDEF Topology Tests
#
# Copyright 2025 6WIND S.A.
#

"""
test_bfd_static_vrf.py: Test the FRR static routes with BFD tracking.
"""

import os
import sys
import json
import platform
import functools
import pytest

pytestmark = [pytest.mark.staticd, pytest.mark.bfdd]

# Save the Current Working Directory to find configuration files.
CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

# pylint: disable=C0413
# Import topogen and topotest helpers
from lib import topotest
from lib.topogen import Topogen, TopoRouter, get_topogen
from lib.topolog import logger


def build_topo(tgen):
    "Build function"

    # Create 3 routers
    for routern in range(1, 4):
        tgen.add_router("r{}".format(routern))

    switch = tgen.add_switch("s1")
    switch.add_link(tgen.gears["r1"])
    switch.add_link(tgen.gears["r2"])

    switch = tgen.add_switch("s2")
    switch.add_link(tgen.gears["r1"])
    switch.add_link(tgen.gears["r3"])


def setup_module(mod):
    "Sets up the pytest environment"

    tgen = Topogen(build_topo, mod.__name__)
    tgen.start_topology()

    router_list = tgen.routers()

    for rname, router in router_list.items():
        tgen.net[rname].cmd(
            f"""
ip link add cust1 type vrf table 10
ip link set dev cust1 up
ip link set dev {rname}-eth0 master cust1
sysctl net.ipv6.conf.{rname}-eth0.keep_addr_on_down=1
"""
        )

    tgen.net["r1"].cmd(
        """
ip link set dev r1-eth1 master cust1
sysctl net.ipv6.conf.r1-eth1.keep_addr_on_down=1
"""
    )

    for _, (rname, router) in enumerate(router_list.items(), 1):
        router.load_frr_config(
            os.path.join(CWD, "{}/frr.conf".format(rname)),
            [
                (TopoRouter.RD_ZEBRA, None),
                (TopoRouter.RD_MGMTD, None),
                (TopoRouter.RD_BFD, None),
                (TopoRouter.RD_STATIC, None),
            ],
        )

    # Initialize all routers.
    tgen.start_router()


def teardown_module(_mod):
    "Teardown the pytest environment"

    tgen = get_topogen()
    tgen.stop_topology()


def check_bfd_state(step=None):
    tgen = get_topogen()

    r1 = tgen.gears["r1"]

    step_suffix = f"_step{step}" if step else ""

    logger.info("Check BFD entries")
    reffile = os.path.join(CWD, f"r1/show_bfd_peers{step_suffix}.json")
    expected = json.loads(open(reffile).read())
    cmd = "show bfd peers json"
    test_func = functools.partial(topotest.router_json_cmp, r1, cmd, expected)
    _, res = topotest.run_and_expect(test_func, None, count=30, wait=1)
    assertmsg = f"BFD did not converge. Error on r1 {cmd}"
    assert res is None, assertmsg

    logger.info("Check IPv4 default route")
    reffile = os.path.join(CWD, f"r1/show_ip_route{step_suffix}.json")
    expected = json.loads(open(reffile).read())
    cmd = "show ip route vrf cust1 0.0.0.0/0 json"
    test_func = functools.partial(topotest.router_json_cmp, r1, cmd, expected)
    _, res = topotest.run_and_expect(test_func, None, count=30, wait=1)
    assertmsg = f"BFD did not converge. Error on r1 {cmd}"
    assert res is None, assertmsg

    logger.info("Check IPv6 default route")
    reffile = os.path.join(CWD, f"r1/show_ipv6_route{step_suffix}.json")
    expected = json.loads(open(reffile).read())
    cmd = "show ipv6 route vrf cust1 ::/0 json"
    test_func = functools.partial(topotest.router_json_cmp, r1, cmd, expected)
    _, res = topotest.run_and_expect(test_func, None, count=30, wait=1)
    assertmsg = f"BFD did not converge. Error on r1 {cmd}"
    assert res is None, assertmsg


def test_bfd_convergence():
    "Assert that the BFD peers can find themselves."

    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    check_bfd_state()


def test_bfd_static_vrf_step1():
    """
    Assert that BFD notices the link down after simulating network
    failure.
    """

    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    logger.info("Set r3-eth0 down")
    tgen.gears["r3"].link_enable("r3-eth0", enabled=False)

    check_bfd_state(step=1)


def test_bfd_static_vrf_step2():
    """
    Assert that BFD goes back to the nominal stater after links are back up.
    """

    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    logger.info("Set r3-eth0 up")
    tgen.gears["r3"].link_enable("r3-eth0", enabled=True)

    check_bfd_state()


def test_memory_leak():
    "Run the memory leak test and report results."
    tgen = get_topogen()
    if not tgen.is_memleak_enabled():
        pytest.skip("Memory leak test/report is disabled")

    tgen.report_memory_leaks()


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
