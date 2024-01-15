#!/usr/bin/env python
# SPDX-License-Identifier: ISC

#
# test_bgp_vrf_netns_topo1.py
# Part of NetDEF Topology Tests
#
# Copyright (c) 2018 by 6WIND
#

"""
test_bgp_vrf_netns_topo1.py: Test BGP topology with EBGP on NETNS VRF
"""

import json
import os
import sys
import functools
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

pytestmark = [pytest.mark.bgpd]


total_ebgp_peers = 1
CustomizeVrfWithNetns = True

#####################################################
##
##   Network Topology Definition
##
#####################################################


def build_topo(tgen):
    tgen.add_router("r1")

    # Setup Switches
    switch = tgen.add_switch("s1")
    switch.add_link(tgen.gears["r1"])

    # Add eBGP ExaBGP neighbors
    peer_ip = "10.0.1.101"
    peer_route = "via 10.0.1.1"
    peer = tgen.add_exabgp_peer("peer1", ip=peer_ip, defaultRoute=peer_route)
    switch = tgen.gears["s1"]
    switch.add_link(peer)


#####################################################
##
##   Tests starting
##
#####################################################


def setup_module(module):
    tgen = Topogen(build_topo, module.__name__)
    tgen.start_topology()

    # Get r1 reference
    router = tgen.gears["r1"]

    # check for zebra capability
    if CustomizeVrfWithNetns == True:
        if router.check_capability(TopoRouter.RD_ZEBRA, "--vrfwnetns") == False:
            return pytest.skip(
                "Skipping BGP VRF NETNS Test. VRF NETNS backend not available on FRR"
            )
        if os.system("ip netns list") != 0:
            return pytest.skip(
                "Skipping BGP VRF NETNS Test. NETNS not available on System"
            )
    # retrieve VRF backend kind
    if CustomizeVrfWithNetns == True:
        logger.info("Testing with VRF Namespace support")

    # create VRF r1-bgp-cust1
    # move r1-eth0 to VRF r1-bgp-cust1

    ns = "{}-bgp-cust1".format("r1")
    router.net.add_netns(ns)
    router.net.set_intf_netns("r1-eth0", ns, up=True)

    # run daemons
    router.load_config(TopoRouter.RD_MGMTD, None, "--vrfwnetns")
    router.load_config(
        TopoRouter.RD_ZEBRA,
        os.path.join(CWD, "{}/zebra.conf".format("r1")),
        "--vrfwnetns",
    )
    router.load_config(
        TopoRouter.RD_BGP, os.path.join(CWD, "{}/bgpd.conf".format("r1"))
    )

    logger.info("Launching BGP and ZEBRA")
    # BGP and ZEBRA start without underlying VRF
    router.start()
    # Starting Hosts and init ExaBGP on each of them
    logger.info("starting exaBGP on peer1")
    peer_list = tgen.exabgp_peers()
    for pname, peer in peer_list.items():
        peer_dir = os.path.join(CWD, pname)
        env_file = os.path.join(CWD, "exabgp.env")
        logger.info("Running ExaBGP peer")
        peer.start(peer_dir, env_file)
        logger.info(pname)


def teardown_module(module):
    tgen = get_topogen()

    # Move interfaces out of vrf namespace and delete the namespace
    tgen.net["r1"].reset_intf_netns("r1-eth0")
    tgen.net["r1"].delete_netns("r1-bgp-cust1")

    tgen.stop_topology()


def test_bgp_vrf_learn():
    "Test daemon learnt VRF context"
    tgen = get_topogen()

    # Skip if previous fatal error condition is raised
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    # Expected result
    output = tgen.gears["r1"].vtysh_cmd("show vrf", isjson=False)
    logger.info("output is: {}".format(output))

    output = tgen.gears["r1"].vtysh_cmd("show bgp vrfs", isjson=False)
    logger.info("output is: {}".format(output))


def test_bgp_convergence():
    "Test for BGP topology convergence"
    tgen = get_topogen()

    # uncomment if you want to troubleshoot
    # tgen.mininet_cli()
    # Skip if previous fatal error condition is raised
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    logger.info("waiting for bgp convergence")

    # Expected result
    router = tgen.gears["r1"]
    if router.has_version("<", "3.0"):
        reffile = os.path.join(CWD, "r1/summary20.txt")
    else:
        reffile = os.path.join(CWD, "r1/summary.txt")

    expected = json.loads(open(reffile).read())

    test_func = functools.partial(
        topotest.router_json_cmp,
        router,
        "show bgp vrf r1-bgp-cust1 summary json",
        expected,
    )
    _, res = topotest.run_and_expect(test_func, None, count=90, wait=0.5)
    assertmsg = "BGP router network did not converge"
    assert res is None, assertmsg


def test_bgp_vrf_netns():
    tgen = get_topogen()

    # Skip if previous fatal error condition is raised
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    expect = {
        "routerId": "10.0.1.1",
        "routes": {},
    }

    for subnet in range(0, 10):
        netkey = "10.201.{}.0/24".format(subnet)
        expect["routes"][netkey] = []
        peer = {"valid": True}
        expect["routes"][netkey].append(peer)

    test_func = functools.partial(
        topotest.router_json_cmp,
        tgen.gears["r1"],
        "show ip bgp vrf r1-bgp-cust1 ipv4 json",
        expect,
    )
    _, res = topotest.run_and_expect(test_func, None, count=12, wait=0.5)
    assertmsg = 'expected routes in "show ip bgp vrf r1-bgp-cust1 ipv4" output'
    assert res is None, assertmsg


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    ret = pytest.main(args)

    sys.exit(ret)
