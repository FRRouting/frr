#!/usr/bin/env python
# SPDX-License-Identifier: ISC

#
# test_bgp_flowspec_topo.py
# Part of NetDEF Topology Tests
#
# Copyright (c) 2019 by 6WIND
#

"""
test_bgp_flowspec_topo.py: Test BGP topology with Flowspec EBGP peering


                          +------+------+
                          |    peer1    |
                          | BGP peer 1  |
                          |192.168.0.161|
                          |             |
                          +------+------+
                        .2       | r1-eth0
                                 |
                           ~~~~~~~~~ 
                      +---~~    s1   ~~------+
                          ~~         ~~
                            ~~~~~~~~~
                                | 10.0.1.1 r1-eth0
                                | 1001::1  r1-eth0
                       +--------+--------+
                       |    r1           |
                       |BGP 192.168.0.162|
                       |                 |
                       |                 |
                       |                 |
                       +-----------------+

"""

import json
import functools
import os
import sys
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


#####################################################
##
##   Network Topology Definition
##
#####################################################


def build_topo(tgen):
    tgen.add_router("r1")

    # Setup Control Path Switch 1. r1-eth0
    switch = tgen.add_switch("s1")
    switch.add_link(tgen.gears["r1"])

    ## Add eBGP ExaBGP neighbors
    peer_ip = "10.0.1.101"  ## peer
    peer_route = "via 10.0.1.1"  ## router
    peer = tgen.add_exabgp_peer("peer1", ip=peer_ip, defaultRoute=peer_route)
    switch.add_link(peer)


#####################################################
##
##   Tests starting
##
#####################################################


def setup_module(module):
    tgen = Topogen(build_topo, module.__name__)

    tgen.start_topology()
    # check for zebra capability
    router = tgen.gears["r1"]

    # Get r1 reference and run Daemons
    logger.info("Launching BGP and ZEBRA on r1")
    router = tgen.gears["r1"]
    router.load_config(
        TopoRouter.RD_ZEBRA, os.path.join(CWD, "{}/zebra.conf".format("r1"))
    )
    router.load_config(
        TopoRouter.RD_BGP, os.path.join(CWD, "{}/bgpd.conf".format("r1"))
    )
    router.start()

    peer_list = tgen.exabgp_peers()
    for pname, peer in peer_list.items():
        peer_dir = os.path.join(CWD, pname)
        env_file = os.path.join(CWD, "exabgp.env")
        peer.start(peer_dir, env_file)
        logger.info(pname)


def teardown_module(module):
    tgen = get_topogen()
    tgen.stop_topology()


def test_bgp_convergence():
    "Test for BGP topology convergence"
    tgen = get_topogen()

    # Skip if previous fatal error condition is raised

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    logger.info("waiting for bgp convergence")

    # Expected result
    router = tgen.gears["r1"]
    reffile = os.path.join(CWD, "r1/summary.txt")

    expected = json.loads(open(reffile).read())

    test_func = functools.partial(
        topotest.router_json_cmp, router, "show bgp summary json", expected
    )
    _, res = topotest.run_and_expect(test_func, None, count=210, wait=1)
    assertmsg = "BGP router network did not converge"
    assert res is None, assertmsg


def test_bgp_flowspec():
    tgen = get_topogen()

    # Skip if previous fatal error condition is raised
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    router = tgen.gears["r1"]

    logger.info("Check BGP FS entry for 3.3.3.3 with redirect IP")
    output = router.vtysh_cmd(
        "show bgp ipv4 flowspec 3.3.3.3", isjson=False, daemon="bgpd"
    )
    logger.info(output)
    if (
        "NH 50.0.0.2" not in output
        or "FS:redirect IP" not in output
        or "Packet Length < 200" not in output
    ):
        assertmsg = "traffic to 3.3.3.3 should have been detected as FS entry. NOK"
        assert 0, assertmsg
    else:
        logger.info("Check BGP FS entry for 3.3.3.3 with redirect IP OK")

    logger.info("Check BGP FS entry for 3::3 with redirect IP")
    output = router.vtysh_cmd(
        "show bgp ipv6 flowspec 3::3", isjson=False, daemon="bgpd"
    )
    logger.info(output)
    if (
        "NH 50::2" not in output
        or "FS:redirect IP" not in output
        or "Packet Length < 200" not in output
    ):
        assertmsg = "traffic to 3::3 should have been detected as FS entry. NOK"
        assert 0, assertmsg
    else:
        logger.info("Check BGP FS entry for 3::3 with redirect IP OK")


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    ret = pytest.main(args)

    sys.exit(ret)
