#!/usr/bin/env python
# SPDX-License-Identifier: ISC

#
# test_tshark.py
# Part of NetDEF Topology Tests
#
# Copyright (c) 2026 by
# Adriano Marto Reis <adrianomarto@gmail.com>
#

"""
test_tshark.py: Test Tshark packet capturing tool.
"""
import os
import sys
import pytest

# Save the Current Working Directory to find configuration files.
CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

# pylint: disable=C0413
# Import topogen and topotest helpers
from lib import topotest

# Required to instantiate the topology builder class.
from lib.topogen import Topogen, TopoRouter, get_topogen
from lib.topolog import logger

from lib.tshark import Tshark

pytestmark = []


def build_topo(tgen):
    "Build function"
    tgen.add_router("r1")
    tgen.add_router("r2")
    switch = tgen.add_switch("s1")
    switch.add_link(tgen.gears["r1"])
    switch.add_link(tgen.gears["r2"])


def setup_module(mod):
    "Sets up the pytest environment"

    tgen = Topogen(build_topo, mod.__name__)
    tgen.start_topology()

    router_list = tgen.routers()
    for rname, router in router_list.items():
        daemon_file = "{}/{}/zebra.conf".format(CWD, rname)
        if os.path.isfile(daemon_file):
            router.load_config(TopoRouter.RD_ZEBRA, daemon_file)

    tgen.start_router()


def teardown_module():
    "Teardown the pytest environment"
    tgen = get_topogen()
    tgen.stop_topology()


def test_tshark():
    """
    Demonstrates how to use Tshark to capture traffic between two routers.
    """
    PING_COUNT = 4

    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    # Start tshark on r1
    tshark = Tshark("r1", "r1-eth0", "icmp", 10.0)

    # Start ping on r2
    tgen.routers()["r2"].cmd_raises(f"ping -c {PING_COUNT} 192.168.122.1")

    # Capture the packets
    packets = tshark.get_packets()
    assert packets, "No packet was captured"

    # Check if there are ICMP echo requests
    icmp_echo_requests = [
        packet
        for packet in packets
        if packet["icmp.type"] == "8"
        and packet["ip.src"] == "192.168.122.2"
        and packet["ip.dst"] == "192.168.122.1"
    ]
    assert (
        len(icmp_echo_requests) == PING_COUNT
    ), "One or more ICMP echo request was not captured"

    # Check if there are ICMP echo replies
    icmp_echo_replies = [
        packet
        for packet in packets
        if packet["icmp.type"] == "0"
        and packet["ip.src"] == "192.168.122.1"
        and packet["ip.dst"] == "192.168.122.2"
    ]
    assert (
        len(icmp_echo_replies) == PING_COUNT
    ), "One or more ICMP echo reply was not captured"


def test_memory_leak():
    "Run the memory leak test and report results."
    tgen = get_topogen()
    if not tgen.is_memleak_enabled():
        pytest.skip("Memory leak test/report is disabled")
    tgen.report_memory_leaks()


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
