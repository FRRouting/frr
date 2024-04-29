#!/usr/bin/env python
# SPDX-License-Identifier: ISC

#
# test_evpn-pim_topo1.py
#
# Copyright (c) 2017 by
# Cumulus Networks, Inc.
# Donald Sharp
#

"""
test_evpn_pim_topo1.py: Testing evpn-pim

"""

import os
import sys
import pytest
import json
from functools import partial

pytestmark = [pytest.mark.pimd, pytest.mark.bgpd]

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
    tgen.add_router("spine")
    tgen.add_router("leaf1")
    tgen.add_router("leaf2")
    tgen.add_router("host1")
    tgen.add_router("host2")

    # On main router
    # First switch is for a dummy interface (for local network)
    # spine-eth0 is connected to leaf1-eth0
    switch = tgen.add_switch("sw1")
    switch.add_link(tgen.gears["spine"])
    switch.add_link(tgen.gears["leaf1"])

    # spine-eth1 is connected to leaf2-eth0
    switch = tgen.add_switch("sw2")
    switch.add_link(tgen.gears["spine"])
    switch.add_link(tgen.gears["leaf2"])

    # leaf1-eth1 is connected to host1-eth0
    switch = tgen.add_switch("sw3")
    switch.add_link(tgen.gears["leaf1"])
    switch.add_link(tgen.gears["host1"])

    # leaf2-eth1 is connected to host2-eth0
    switch = tgen.add_switch("sw4")
    switch.add_link(tgen.gears["leaf2"])
    switch.add_link(tgen.gears["host2"])


#####################################################
##
##   Tests starting
##
#####################################################


def setup_module(module):
    "Setup topology"
    tgen = Topogen(build_topo, module.__name__)
    tgen.start_topology()

    leaf1 = tgen.gears["leaf1"]
    leaf2 = tgen.gears["leaf2"]

    leaf1.run("brctl addbr brleaf1")
    leaf2.run("brctl addbr brleaf2")
    leaf1.run("ip link set dev brleaf1 up")
    leaf2.run("ip link set dev brleaf2 up")
    leaf1.run(
        "ip link add vxlan0 type vxlan id 42 group 239.1.1.1 dev leaf1-eth1 dstport 4789"
    )
    leaf2.run(
        "ip link add vxlan0 type vxlan id 42 group 239.1.1.1 dev leaf2-eth1 dstport 4789"
    )
    leaf1.run("brctl addif brleaf1 vxlan0")
    leaf2.run("brctl addif brleaf2 vxlan0")
    leaf1.run("ip link set up dev vxlan0")
    leaf2.run("ip link set up dev vxlan0")
    # tgen.mininet_cli()
    # This is a sample of configuration loading.
    router_list = tgen.routers()
    for rname, router in router_list.items():
        router.load_config(
            TopoRouter.RD_ZEBRA, os.path.join(CWD, "{}/zebra.conf".format(rname))
        )
        router.load_config(
            TopoRouter.RD_BGP, os.path.join(CWD, "{}/bgpd.conf".format(rname))
        )
        router.load_config(
            TopoRouter.RD_PIM, os.path.join(CWD, "{}/pimd.conf".format(rname))
        )
    tgen.start_router()
    # tgen.mininet_cli()


def teardown_module(_mod):
    "Teardown the pytest environment"
    tgen = get_topogen()

    # This function tears down the whole topology.
    tgen.stop_topology()


def test_converge_protocols():
    "Wait for protocol convergence"

    tgen = get_topogen()
    # Don't run this test if we have any failure.
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    spine = tgen.gears["spine"]
    json_file = "{}/{}/bgp.summ.json".format(CWD, spine.name)
    expected = json.loads(open(json_file).read())

    test_func = partial(
        topotest.router_json_cmp, spine, "show bgp ipv4 uni summ json", expected
    )
    _, result = topotest.run_and_expect(test_func, None, count=125, wait=1)
    assertmsg = '"{}" JSON output mismatches'.format(spine.name)
    assert result is None, assertmsg
    # tgen.mininet_cli()


def test_multicast_groups_on_rp():
    "Ensure the multicast groups show up on the spine"
    # This test implicitly tests the auto mcast groups
    # of the created vlans and then the auto-joins that
    # pim will do to the RP( spine )

    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    spine = tgen.gears["spine"]
    json_file = "{}/{}/join-info.json".format(CWD, spine.name)
    expected = json.loads(open(json_file).read())

    test_func = partial(
        topotest.router_json_cmp, spine, "show ip pim join json", expected
    )
    _, result = topotest.run_and_expect(test_func, None, count=30, wait=1)
    assertmsg = '"{}" JSON output mismatches'.format(spine.name)
    assert result is None, assertmsg
    # tgen.mininet_cli()


def test_shutdown_check_stderr():
    if os.environ.get("TOPOTESTS_CHECK_STDERR") is None:
        pytest.skip("Skipping test for Stderr output and memory leaks")

    tgen = get_topogen()
    # Don't run this test if we have any failure.
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    logger.info("Verifying unexpected STDERR output from daemons")

    router_list = tgen.routers().values()
    for router in router_list:
        router.stop()

        log = tgen.net[router.name].getStdErr("pimd")
        if log:
            logger.error("PIMd StdErr Log:" + log)
        log = tgen.net[router.name].getStdErr("bgpd")
        if log:
            logger.error("BGPd StdErr Log:" + log)
        log = tgen.net[router.name].getStdErr("zebra")
        if log:
            logger.error("Zebra StdErr Log:" + log)


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
