#!/usr/bin/env python
# SPDX-License-Identifier: ISC

#
# test_bgp_multiview_topo1.py
# Part of NetDEF Topology Tests
#
# Copyright (c) 2016 by
# Network Device Education Foundation, Inc. ("NetDEF")
#

r"""
test_bgp_multiview_topo1.py: Simple FRR Route-Server Test

+----------+ +----------+ +----------+ +----------+ +----------+
|  peer1   | |  peer2   | |  peer3   | |  peer4   | |  peer5   |
| AS 65001 | | AS 65002 | | AS 65003 | | AS 65004 | | AS 65005 |
+-----+----+ +-----+----+ +-----+----+ +-----+----+ +-----+----+
      | .1         | .2         | .3         | .4         | .5
      |     ______/            /            /   _________/
       \   /  ________________/            /   /
        | |  /   _________________________/   /     +----------+
        | | |  /   __________________________/   ___|  peer6   |
        | | | |  /  ____________________________/.6 | AS 65006 |
        | | | | |  /  _________________________     +----------+
        | | | | | |  /  __________________     \    +----------+
        | | | | | | |  /                  \     \___|  peer7   |
        | | | | | | | |                    \     .7 | AS 65007 |
     ~~~~~~~~~~~~~~~~~~~~~                  \       +----------+
   ~~         SW1         ~~                 \      +----------+
   ~~       Switch           ~~               \_____|  peer8   |
   ~~    172.16.1.0/24     ~~                    .8 | AS 65008 |
     ~~~~~~~~~~~~~~~~~~~~~                          +----------+
              |
              | .254
    +---------+---------+
    |      FRR R1       |
    |   BGP Multi-View  |
    | Peer 1-3 > View 1 |
    | Peer 4-5 > View 2 |
    | Peer 6-8 > View 3 |
    +---------+---------+
              | .1
              |
        ~~~~~~~~~~~~~        Stub Network is redistributed
      ~~     SW0     ~~      into each BGP view with different
    ~~   172.20.0.1/28  ~~   attributes (using route-map)
      ~~ Stub Switch ~~
        ~~~~~~~~~~~~~
"""

import json
import os
import sys
import pytest
import json
from time import sleep

from functools import partial

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from lib import topotest
from lib.topogen import get_topogen, Topogen
from lib.common_config import step


pytestmark = [pytest.mark.bgpd]


fatal_error = ""


#####################################################
##
##   Network Topology Definition
##
#####################################################


def build_topo(tgen):
    # Setup Routers
    router = tgen.add_router("r1")

    # Setup Provider BGP peers
    peer = {}
    for i in range(1, 9):
        peer[i] = tgen.add_exabgp_peer(
            "peer%s" % i, ip="172.16.1.%s/24" % i, defaultRoute="via 172.16.1.254"
        )

    # First switch is for a dummy interface (for local network)
    switch = tgen.add_switch("sw0")
    switch.add_link(router, nodeif="r1-stub")

    # Second switch is for connection to all peering routers
    switch = tgen.add_switch("sw1")
    switch.add_link(router, nodeif="r1-eth0")
    for j in range(1, 9):
        switch.add_link(peer[j], nodeif="peer%s-eth0" % j)


#####################################################
##
##   Tests starting
##
#####################################################


def setup_module(module):
    thisDir = os.path.dirname(os.path.realpath(__file__))
    tgen = Topogen(build_topo, module.__name__)
    tgen.start_topology()

    # Starting Routers
    router = tgen.net["r1"]
    router.loadConf("zebra", "%s/r1/zebra.conf" % thisDir)
    router.loadConf("bgpd", "%s/r1/bgpd.conf" % thisDir)
    tgen.gears["r1"].start()

    # Starting PE Hosts and init ExaBGP on each of them
    peer_list = tgen.exabgp_peers()
    for pname, peer in peer_list.items():
        peer_dir = os.path.join(thisDir, pname)
        env_file = os.path.join(thisDir, "exabgp.env")
        peer.start(peer_dir, env_file)


def teardown_module(module):
    tgen = get_topogen()
    tgen.stop_topology()


def test_router_running():
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)


def test_bgp_converge():
    "Check for BGP converged on all peers and BGP views"

    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    # Wait for BGP to converge  (All Neighbors in either Full or TwoWay State)
    step("Verify for BGP to converge")

    timeout = 125
    while timeout > 0:
        print("Timeout in %s: " % timeout),
        sys.stdout.flush()
        # Look for any node not yet converged
        for i in range(1, 2):
            for view in range(1, 4):
                notConverged = tgen.net["r%s" % i].cmd(
                    r'vtysh -c "show ip bgp view %s summary" 2> /dev/null | grep ^[0-9] | grep -vP " 11\s+(\d+)"'
                    % view
                )
                if notConverged:
                    print("Waiting for r%s, view %s" % (i, view))
                    sys.stdout.flush()
                    break
            if notConverged:
                break
        if notConverged:
            sleep(5)
            timeout -= 5
        else:
            print("Done")
            break
    else:
        # Bail out with error if a router fails to converge
        bgpStatus = tgen.net["r%s" % i].cmd(
            'vtysh -c "show ip bgp view %s summary"' % view
        )
        assert False, "BGP did not converge:\n%s" % bgpStatus

    tgen.routers_have_failure()


def test_bgp_routingTable():
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    thisDir = os.path.dirname(os.path.realpath(__file__))

    step("Verifying BGP Routing Tables")

    router = tgen.gears["r1"]
    for view in range(1, 4):
        json_file = "{}/{}/view_{}.json".format(thisDir, router.name, view)
        expected = json.loads(open(json_file).read())
        test_func = partial(
            topotest.router_json_cmp,
            router,
            "show ip bgp view {} json".format(view),
            expected,
        )
        _, result = topotest.run_and_expect(test_func, None, count=5, wait=1)
        assertmsg = "Routing Table verification failed for router {}, view {}".format(
            router.name, view
        )
        assert result is None, assertmsg

    tgen.routers_have_failure()


def test_shutdown_check_memleak():
    tgen = get_topogen()
    if not tgen.is_memleak_enabled():
        pytest.skip("Memory leak test/report is disabled")

    tgen.report_memory_leaks()


if __name__ == "__main__":
    # To suppress tracebacks, either use the following pytest call or add "--tb=no" to cli
    # retval = pytest.main(["-s", "--tb=no"])
    retval = pytest.main(["-s"])
    sys.exit(retval)
