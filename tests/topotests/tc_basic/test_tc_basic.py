#!/usr/bin/python
# SPDX-License-Identifier: ISC

#
# test_tc_basic.py
#
# Copyright (c) 2022 by Shichu Yang
#
"""
test_tc_basic.py: Test basic TC filters, classes and qdiscs.
"""
import sys
import os
import functools
import pytest

# Save the Current Working Directory to find configuration files.
CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))
sys.path.append(os.path.join(CWD, "../lib/"))

from lib import topotest
from lib.topogen import Topogen, TopoRouter
from lib.topolog import logger

pytestmark = [pytest.mark.sharpd]


def build_topo(tgen):
    "Build function"

    r1 = tgen.add_router("r1")
    r2 = tgen.add_router("r2")

    # Create a p2p connection between r1 and r2
    tgen.add_link(r1, r2)

    # Create switches with each router connected to it to simulate a empty network.
    switch = tgen.add_switch("s1")
    switch.add_link(r1)

    switch = tgen.add_switch("s2")
    switch.add_link(r2)


# New form of setup/teardown using pytest fixture
@pytest.fixture(scope="module")
def tgen(request):
    "Setup/Teardown the environment and provide tgen argument to tests"

    # This function initiates the topology build with Topogen...
    tgen = Topogen(build_topo, request.module.__name__)

    # ... and here it calls initialization functions.
    tgen.start_topology()

    # Before zebra starts, pre-install two qdiscs on r1 to exercise the
    # dataplane-based RTNLGRP_TC startup dump (DPLANE_OP_TC_QDISC_READ):
    #
    #  - On r1-eth0 install an HTB qdisc with the "beef:" major handle
    #    (the value zebra uses for TC qdiscs it owns). Zebra's startup
    #    TC read path is supposed to discover this leftover qdisc and
    #    remove it.
    #  - On r1-eth1 install an HTB qdisc with the "1234:" major handle.
    #    Zebra does not own this handle and must leave it alone.
    r1 = tgen.gears["r1"]
    r1.cmd_raises("tc qdisc add dev r1-eth0 root handle beef: htb")
    r1.cmd_raises("tc qdisc add dev r1-eth1 root handle 1234: htb")

    # This is a sample of configuration loading.
    router_list = tgen.routers()

    # For all routers arrange for:
    # - starting zebra using config file from <rtrname>/zebra.conf
    # - starting ospfd using an empty config file.
    for _, router in router_list.items():
        router.load_config(TopoRouter.RD_ZEBRA)
        router.load_config(TopoRouter.RD_SHARP)

    # Start and configure the router daemons
    tgen.start_router()

    # Provide tgen as argument to each test function
    yield tgen

    # Teardown after last test runs
    tgen.stop_topology()


# Fixture that executes before each test
@pytest.fixture(autouse=True)
def skip_on_failure(tgen):
    if tgen.routers_have_failure():
        pytest.skip("skipped because of previous test failure")


def fetch_iproute2_tc_info(r, interface):
    qdisc = r.cmd("tc qdisc show dev %s" % interface)
    tclass = r.cmd("tc class show dev %s" % interface)
    tfilter = r.cmd("tc filter show dev %s" % interface)
    return qdisc, tclass, tfilter


# ===================
# The tests functions
# ===================


def test_tc_startup_removes_leftover_qdisc(tgen):
    """
    Verify that zebra's TC startup read path:
      - removes the leftover "beef:" HTB qdisc on r1-eth0 (zebra owns it)
      - leaves the "1234:" HTB qdisc on r1-eth1 alone (zebra does not
        own it)
    Both qdiscs were installed before start_router.
    """

    r1 = tgen.gears["r1"]

    def _beef_removed():
        qdisc = r1.cmd("tc qdisc show dev r1-eth0")
        if "beef:" in qdisc:
            return "beef: qdisc still present on r1-eth0: %s" % qdisc
        return None

    test_func = functools.partial(_beef_removed)
    result, out = topotest.run_and_expect(test_func, None, count=20, wait=1)
    assert result, (
        "zebra failed to remove the leftover beef: qdisc at startup: %s" % out
    )

    def _user_qdisc_present():
        qdisc = r1.cmd("tc qdisc show dev r1-eth1")
        if "1234:" not in qdisc:
            return "1234: qdisc missing on r1-eth1: %s" % qdisc
        return None

    test_func = functools.partial(_user_qdisc_present)
    result, out = topotest.run_and_expect(test_func, None, count=20, wait=1)
    assert result, (
        "zebra incorrectly removed the user-owned 1234: qdisc at startup: %s" % out
    )


def test_tc_basic(tgen):
    "Test installing one pair of filter & class by sharpd"

    r1 = tgen.gears["r1"]
    intf = "r1-eth0"
    r1.vtysh_cmd(
        "sharp tc dev %s source 192.168.100.0/24 destination 192.168.101.0/24 ip-protocol tcp src-port 8000 dst-port 8001 rate 20mbit"
        % intf
    )

    expected = [
        ("qdisc", "htb"),
        ("qdisc", "beef:"),
        ("class", "20Mbit"),
        ("filter", "tcp"),
        ("filter", "dst_ip 192.168.101.0/24"),
        ("filter", "src_ip 192.168.100.0/24"),
        ("filter", "dst_port 8001"),
        ("filter", "src_port 8000"),
    ]

    def _tc_installed():
        qdisc, tclass, tfilter = fetch_iproute2_tc_info(r1, intf)
        outputs = {"qdisc": qdisc, "class": tclass, "filter": tfilter}
        for where, needle in expected:
            if needle not in outputs[where]:
                return "expected %r in tc %s output, got: %s" % (
                    needle,
                    where,
                    outputs[where],
                )
        return None

    test_func = functools.partial(_tc_installed)
    result, out = topotest.run_and_expect(test_func, None, count=20, wait=1)
    assert result, (
        "sharpd-driven TC install did not fully propagate to the kernel: %s" % out
    )

    qdisc, tclass, tfilter = fetch_iproute2_tc_info(r1, intf)
    logger.info("tc qdisc on %s: %s", intf, qdisc)
    logger.info("tc class on %s: %s", intf, tclass)
    logger.info("tc filter on %s: %s", intf, tfilter)


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
