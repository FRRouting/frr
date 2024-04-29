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
import pytest
import time

# Save the Current Working Directory to find configuration files.
CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))
sys.path.append(os.path.join(CWD, "../lib/"))

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


def test_tc_basic(tgen):
    "Test installing one pair of filter & class by sharpd"

    r1 = tgen.gears["r1"]
    intf = "r1-eth0"
    r1.vtysh_cmd(
        "sharp tc dev %s source 192.168.100.0/24 destination 192.168.101.0/24 ip-protocol tcp src-port 8000 dst-port 8001 rate 20mbit"
        % intf
    )

    time.sleep(3)

    qdisc, tclass, tfilter = fetch_iproute2_tc_info(r1, intf)

    logger.info("tc qdisc on %s: %s", intf, qdisc)
    logger.info("tc class on %s: %s", intf, tclass)
    logger.info("tc filter on %s: %s", intf, tfilter)

    assert "htb" in qdisc
    assert "beef:" in qdisc

    assert "20Mbit" in tclass

    assert "tcp" in tfilter
    assert "dst_ip 192.168.101.0/24" in tfilter
    assert "src_ip 192.168.100.0/24" in tfilter
    assert "dst_port 8001" in tfilter
    assert "src_port 8000" in tfilter


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
