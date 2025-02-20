#!/usr/bin/env python
# SPDX-License-Identifier: ISC

#
# test_bfd_vrflite_topo1.py
# Part of NetDEF Topology Tests
#
# Copyright (c) 2018 by
# Network Device Education Foundation, Inc. ("NetDEF")
# Copyright (c) 2022 by 6WIND
#

"""
test_bfd_vrflite_topo1.py: Test the FRR BFD daemon.
"""

import os
import sys
import json
from functools import partial
import pytest

# Save the Current Working Directory to find configuration files.
CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

# pylint: disable=C0413
# Import topogen and topotest helpers
from lib import topotest
from lib.topogen import Topogen, TopoRouter, get_topogen
from lib.topolog import logger

# Required to instantiate the topology builder class.

pytestmark = [pytest.mark.bfdd, pytest.mark.bgpd]


def build_topo(tgen):
    # Create 2 routers
    for routern in range(1, 3):
        tgen.add_router("r{}".format(routern))

    switch = tgen.add_switch("s1")
    switch.add_link(tgen.gears["r1"])
    switch.add_link(tgen.gears["r2"])

    switch = tgen.add_switch("s2")
    switch.add_link(tgen.gears["r2"])

    switch = tgen.add_switch("s3")
    switch.add_link(tgen.gears["r1"])


def setup_module(mod):
    "Sets up the pytest environment"
    tgen = Topogen(build_topo, mod.__name__)
    tgen.start_topology()

    router_list = tgen.routers()

    logger.info("Testing with Linux VRF support and udp_l3mdev=0")
    if os.system("echo 0 > /proc/sys/net/ipv4/udp_l3mdev_accept") != 0:
        return pytest.skip(
            "Skipping BFD vrflite Topo1 Test. Linux VRF not available on System"
        )

    for rname, router in router_list.items():
        router.net.add_l3vrf("vrf1", 10)
        router.net.add_l3vrf("vrf2", 20)
        router.net.add_l3vrf("vrf3", 30)
        router.net.add_vlan(rname + "-eth0.100", rname + "-eth0", 100)
        router.net.add_vlan(rname + "-eth0.200", rname + "-eth0", 200)
        router.net.add_vlan(rname + "-eth0.300", rname + "-eth0", 300)
        router.net.attach_iface_to_l3vrf(rname + "-eth0.100", "vrf1")
        router.net.attach_iface_to_l3vrf(rname + "-eth0.200", "vrf2")
        router.net.add_loop(rname + "-loop1")
        router.net.add_loop(rname + "-loop2")
        router.net.attach_iface_to_l3vrf(rname + "-loop1", "vrf1")
        router.net.attach_iface_to_l3vrf(rname + "-loop2", "vrf2")
        router.net.attach_iface_to_l3vrf(rname + "-eth0", "vrf3")

    for rname, router in router_list.items():
        router.load_config(
            TopoRouter.RD_ZEBRA, os.path.join(CWD, "{}/zebra.conf".format(rname))
        )
        router.load_config(
            TopoRouter.RD_BFD, os.path.join(CWD, "{}/bfdd.conf".format(rname))
        )

    # Initialize all routers.
    tgen.start_router()


def teardown_module(_mod):
    "Teardown the pytest environment"
    tgen = get_topogen()

    # Move interfaces out of vrf namespace and delete the namespace
    router_list = tgen.routers()
    for rname, router in router_list.items():
        router.net.del_iface(rname + "-eth0.100")
        router.net.del_iface(rname + "-eth0.200")
        router.net.del_iface(rname + "-eth0.300")
        router.net.del_iface(rname + "-loop1")
        router.net.del_iface(rname + "-loop2")

    tgen.stop_topology()


def test_bfd_connection():
    "Assert that the BFD peers can find themselves."
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)
    logger.info("waiting for bfd peers to go up")
    router = tgen.gears["r1"]
    json_file = "{}/{}/bfd_peers_status.json".format(CWD, "r1")
    expected = json.loads(open(json_file).read())

    test_func = partial(
        topotest.router_json_cmp, router, "show bfd peers json", expected
    )
    _, result = topotest.run_and_expect(test_func, None, count=16, wait=1)
    assertmsg = '"{}" JSON output mismatches'.format(router.name)
    assert result is None, assertmsg


def test_memory_leak():
    "Run the memory leak test and report results."
    tgen = get_topogen()
    if not tgen.is_memleak_enabled():
        pytest.skip("Memory leak test/report is disabled")

    tgen.report_memory_leaks()


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
