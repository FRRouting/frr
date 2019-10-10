#!/usr/bin/env python

#
# test_bgp_rr_ibgp_topo1.py
#
# Copyright (c) 2019 by
# Cumulus Networks, Inc.
# Donald Sharp
#
# Permission to use, copy, modify, and/or distribute this software
# for any purpose with or without fee is hereby granted, provided
# that the above copyright notice and this permission notice appear
# in all copies.
#
# THE SOFTWARE IS PROVIDED "AS IS" AND NETDEF DISCLAIMS ALL WARRANTIES
# WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
# MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL NETDEF BE LIABLE FOR
# ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY
# DAMAGES WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS,
# WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS
# ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE
# OF THIS SOFTWARE.
#

"""
test_bgp_rr_ibgp_topo1.py: Testing IBGP with RR and no IGP


    In a leaf/spine topology with only IBGP connections, where
    the same network is being redistributed at multiple points
    in the network ( say a redistribute connected at both leaf and spines )
    we end up in a state where zebra gets very confused.

    eva# show ip route
    Codes: K - kernel route, C - connected, S - static, R - RIP,
           O - OSPF, I - IS-IS, B - BGP, E - EIGRP, N - NHRP,
           T - Table, v - VNC, V - VNC-Direct, A - Babel, D - SHARP,
           F - PBR, f - OpenFabric,
           > - selected route, * - FIB route, q - queued route, r - rejected route
    
    C>* 192.168.1.0/24 is directly connected, tor1-eth0, 00:00:30
    C>* 192.168.2.0/24 is directly connected, tor1-eth1, 00:00:30
    B   192.168.3.0/24 [200/0] via 192.168.4.2 inactive, 00:00:25
                               via 192.168.6.2 inactive, 00:00:25
    B>* 192.168.4.0/24 [200/0] via 192.168.2.3, tor1-eth1, 00:00:25
      *                        via 192.168.6.2 inactive, 00:00:25
    C>* 192.168.5.0/24 is directly connected, tor1-eth2, 00:00:30
    B>* 192.168.6.0/24 [200/0] via 192.168.4.2 inactive, 00:00:25
      *                        via 192.168.5.4, tor1-eth2, 00:00:25

    Effectively we have ibgp routes recursing through ibgp routes
    and there is no metric to discern whom to listen to.
    
    This draft:
    https://tools.ietf.org/html/draft-ietf-idr-bgp-optimal-route-reflection-19
    
    appears to address this issue.  From looking at both cisco and arista
    deployments they are handling this issue by having the route reflector
    prefer the localy learned routes over from their clients.
    
    Add this topology, in a broken state, so that when we do fix this issue
    it is a simple matter of touching this topology up and re-adding it
    to the normal daily builds.  I also wanted to add this topology
    since it is in a state of `doneness` and I wanted to move onto
    my normal day job without having to remember about this test.
    
    This topology is not configured to be run as part of the normal
    topotests.

"""

import os
import re
import sys
import pytest
import json

# Save the Current Working Directory to find configuration files.
CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, '../'))

# pylint: disable=C0413
# Import topogen and topotest helpers
from lib import topotest
from lib.topogen import Topogen, TopoRouter, get_topogen
from lib.topolog import logger

# Required to instantiate the topology builder class.
from mininet.topo import Topo

#####################################################
##
##   Network Topology Definition
##
#####################################################

class NetworkTopo(Topo):
    "BGP_RR_IBGP Topology 1"

    def build(self, **_opts):
        "Build function"

        tgen = get_topogen(self)

        tgen.add_router('tor1')
        tgen.add_router('tor2')
        tgen.add_router('spine1')
        tgen.add_router('spine2')

        # First switch is for a dummy interface (for local network)
        # on tor1
	# 192.168.1.0/24
        switch = tgen.add_switch('sw1')
        switch.add_link(tgen.gears['tor1'])

	# 192.168.2.0/24 - tor1 <-> spine1 connection
        switch = tgen.add_switch('sw2')
        switch.add_link(tgen.gears['tor1'])
        switch.add_link(tgen.gears['spine1'])

        # 3rd switch is for a dummy interface (for local netwokr)
	# 192.168.3.0/24 - tor2 
        switch = tgen.add_switch('sw3')
        switch.add_link(tgen.gears['tor2'])

	# 192.168.4.0/24 - tor2 <-> spine1 connection
        switch = tgen.add_switch('sw4')
        switch.add_link(tgen.gears['tor2'])
        switch.add_link(tgen.gears['spine1'])

	# 192.168.5.0/24 - tor1 <-> spine2 connection
        switch = tgen.add_switch('sw5')
        switch.add_link(tgen.gears['tor1'])
        switch.add_link(tgen.gears['spine2'])

	# 192.168.6.0/24 - tor2 <-> spine2 connection
        switch = tgen.add_switch('sw6')
        switch.add_link(tgen.gears['tor2'])
        switch.add_link(tgen.gears['spine2'])

#####################################################
##
##   Tests starting
##
#####################################################

def setup_module(module):
    "Setup topology"
    tgen = Topogen(NetworkTopo, module.__name__)
    tgen.start_topology()

    # This is a sample of configuration loading.
    router_list = tgen.routers()
    for rname, router in router_list.iteritems():
        router.load_config(
            TopoRouter.RD_ZEBRA,
            os.path.join(CWD, '{}/zebra.conf'.format(rname))
        )
        router.load_config(
            TopoRouter.RD_BGP,
            os.path.join(CWD, '{}/bgpd.conf'.format(rname))
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

    topotest.sleep(5, 'Waiting for BGP_RR_IBGP convergence')


def test_bgp_rr_ibgp_routes():
    "Test Route Reflection"

    tgen = get_topogen()
    # Don't run this test if we have any failure.
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    # Verify BGP_RR_IBGP Status
    logger.info("Verifying BGP_RR_IBGP routes")

def test_zebra_ipv4_routingTable():
    "Test 'show ip route'"

    tgen = get_topogen()
    # Don't run this test if we have any failure.
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    failures = 0
    router_list = tgen.routers().values()
    for router in router_list:
        output = router.vtysh_cmd('show ip route json', isjson=True)
        refTableFile = '{}/{}/show_ip_route.json_ref'.format(CWD, router.name)
        expected = json.loads(open(refTableFile).read())

        assertmsg = 'Zebra IPv4 Routing Table verification failed for router {}'.format(router.name)
        assert topotest.json_cmp(output, expected) is None, assertmsg

def test_shutdown_check_stderr():
    if os.environ.get('TOPOTESTS_CHECK_STDERR') is None:
        pytest.skip('Skipping test for Stderr output and memory leaks')

    tgen = get_topogen()
    # Don't run this test if we have any failure.
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    logger.info("Verifying unexpected STDERR output from daemons")

    router_list = tgen.routers().values()
    for router in router_list:
        router.stop()

        log = tgen.net[router.name].getStdErr('bgpd')
        if log:
            logger.error('BGPd StdErr Log:' + log)
        log = tgen.net[router.name].getStdErr('zebra')
        if log:
            logger.error('Zebra StdErr Log:' + log)


if __name__ == '__main__':
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))

#
# Auxiliary Functions
#
