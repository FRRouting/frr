#!/usr/bin/env python
# SPDX-License-Identifier: ISC

#
# test_ospf_unnumbered_point_to_multipoint.py
#
# Copyright (c) 2024 by
# Vincent Jardin
#

"""
test_ospf_unnumbered_point_to_multipoint.py: Test the OSPF unnumbered for routers with point to multipoint over Ethernet
"""

import os
import sys
from functools import partial
import pytest
import json

# Save the Current Working Directory to find configuration files.
CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

# pylint: disable=C0413
# Import topogen and topotest helpers
from lib import topotest
from lib.topogen import Topogen, TopoRouter, get_topogen
from lib.topolog import logger

# Required to instantiate the topology builder class.

pytestmark = [pytest.mark.ospfd]


CWD = os.path.dirname(os.path.realpath(__file__))


def build_topo(tgen):
    "Build function"

    # Create routers
    for routern in range(1, 4):
        tgen.add_router("r{}".format(routern))

    # Create a empty network for router 1
    switch = tgen.add_switch("s1")
    switch.add_link(tgen.gears["r1"])

    # Create a empty network for router 2
    switch = tgen.add_switch("s2")
    switch.add_link(tgen.gears["r2"])

    # Create a empty network for router 3
    switch = tgen.add_switch("s3")
    switch.add_link(tgen.gears["r3"])

    # Interconect router 1, 2 and r3 to a common switch 4
    switch = tgen.add_switch("s4")
    switch.add_link(tgen.gears["r1"])
    switch.add_link(tgen.gears["r2"])
    switch.add_link(tgen.gears["r3"])


def setup_module(mod):
    "Sets up the pytest environment"
    tgen = Topogen(build_topo, mod.__name__)
    tgen.start_topology()

    router_list = tgen.routers()
    for rname, router in router_list.items():
        router.load_config(
            TopoRouter.RD_ZEBRA, os.path.join(CWD, "{}/zebra.conf".format(rname))
        )
        router.load_config(
            TopoRouter.RD_OSPF, os.path.join(CWD, "{}/ospfd.conf".format(rname))
        )

        # The multicast packet delivery is somewhat controlled by
        # the rp_filter. Setting it to '0' allows the kernel to pass
        # up the mcast packet not destined for the local routers
        # network.
        topotest.sysctl_assure(tgen.net["r1"], "net.ipv4.conf.r1-eth1.rp_filter", 0)
        topotest.sysctl_assure(tgen.net["r1"], "net.ipv4.conf.all.rp_filter", 0)
        topotest.sysctl_assure(tgen.net["r2"], "net.ipv4.conf.r2-eth1.rp_filter", 0)
        topotest.sysctl_assure(tgen.net["r2"], "net.ipv4.conf.all.rp_filter", 0)
        topotest.sysctl_assure(tgen.net["r3"], "net.ipv4.conf.r3-eth1.rp_filter", 0)
        topotest.sysctl_assure(tgen.net["r3"], "net.ipv4.conf.all.rp_filter", 0)

    # Initialize all routers.
    tgen.start_router()
    # tgen.mininet_cli()


def teardown_module(mod):
    "Teardown the pytest environment"
    tgen = get_topogen()
    tgen.stop_topology()


def test_ospf_convergence():
    "Test OSPF daemon convergence and that we have received the ospf routes"
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip("skipped because of router(s) failure")

    for router, rnode in tgen.routers().items():
        logger.info('Waiting for router "%s" convergence', router)

        json_file = "{}/{}/ospf-route.json".format(CWD, router)
        expected = json.loads(open(json_file).read())

        test_func = partial(
            topotest.router_json_cmp, rnode, "show ip ospf route json", expected
        )
        _, result = topotest.run_and_expect(test_func, None, count=160, wait=0.5)
        assertmsg = '"{}" JSON output mismatches'.format(router)
        assert result is None, assertmsg
    # tgen.mininet_cli()


def test_ospf_kernel_route():
    "Test OSPF kernel route installation and we have the onlink success"
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip("skipped because of router(s) failure")

    rlist = tgen.routers().values()
    for router in rlist:
        logger.info('Checking OSPF IPv4 kernel routes in "%s"', router.name)

        json_file = "{}/{}/v4_route.json".format(CWD, router.name)
        expected = json.loads(open(json_file).read())

        test_func = partial(
            topotest.router_json_cmp, router, "show ip route json", expected
        )
        _, result = topotest.run_and_expect(test_func, None, count=10, wait=0.5)
        assertmsg = '"{}" JSON output mistmatches'.format(router)
        assert result is None, assertmsg
    # tgen.mininet_cli()


def test_memory_leak():
    "Run the memory leak test and report results."
    tgen = get_topogen()
    if not tgen.is_memleak_enabled():
        pytest.skip("Memory leak test/report is disabled")

    tgen.report_memory_leaks()


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
