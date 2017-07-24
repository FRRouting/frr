#!/usr/bin/env python

#
# test_bgp_ecmp_topo1.py
# Part of NetDEF Topology Tests
#
# Copyright (c) 2017 by
# Network Device Education Foundation, Inc. ("NetDEF")
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
test_bgp_ecmp_topo1.py: Test BGP topology with ECMP (Equal Cost MultiPath).
"""

import json
import os
import sys
import pytest

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

total_ebgp_peers = 20

#####################################################
##
##   Network Topology Definition
##
#####################################################

class BGPECMPTopo1(Topo):
    "BGP ECMP Topology 1"

    def build(self, **_opts):
        tgen = get_topogen(self)

        # Create the BGP router
        router = tgen.add_router('r1')

        # Setup Switches - 1 switch per 5 peering routers
        for swNum in range(1, (total_ebgp_peers+4)/5 +1):
            switch = tgen.add_switch('s{}'.format(swNum))
            switch.add_link(router)

        # Add 'total_ebgp_peers' number of eBGP ExaBGP neighbors
        for peerNum in range(1, total_ebgp_peers+1):
            swNum = ((peerNum -1) / 5 + 1)

            peer_ip = '10.0.{}.{}'.format(swNum, peerNum + 100)
            peer_route = 'via 10.0.{}.1'.format(swNum)
            peer = tgen.add_exabgp_peer('peer{}'.format(peerNum),
                                        ip=peer_ip, defaultRoute=peer_route)

            switch = tgen.gears['s{}'.format(swNum)]
            switch.add_link(peer)


#####################################################
##
##   Tests starting
##
#####################################################

def setup_module(module):
    tgen = Topogen(BGPECMPTopo1, module.__name__)
    tgen.start_topology()

    # Starting Routers
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
        router.start()

    # Starting Hosts and init ExaBGP on each of them
    topotest.sleep(10, 'starting BGP on all {} peers'.format(total_ebgp_peers))
    peer_list = tgen.exabgp_peers()
    for pname, peer in peer_list.iteritems():
        peer_dir = os.path.join(CWD, pname)
        env_file = os.path.join(CWD, 'exabgp.env')
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

    topotest.sleep(20, 'waiting for bgp convergence')

    # Expected result
    router = tgen.gears['r1']
    if router.has_version('<', '3'):
        reffile = os.path.join(CWD, 'r1/summary20.txt')
    else:
        reffile = os.path.join(CWD, 'r1/summary.txt')

    expected = json.loads(open(reffile).read())

    # Define test function and call it
    def _convergence_test():
        output = router.vtysh_cmd('show ip bgp summary json', isjson=True)
        return topotest.json_cmp(output, expected)

    _, res = topotest.run_and_expect(_convergence_test, None, count=10, wait=1)
    assertmsg = 'BGP router network did not converge'
    assert res is None, assertmsg

def test_bgp_ecmp():
    tgen = get_topogen()

    # Skip if previous fatal error condition is raised
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    expect = {
        'routerId': '10.0.255.1',
        'routes': {
        },
    }

    for net in range(1, 5):
        for subnet in range(0, 10):
            netkey = '10.20{}.{}.0/24'.format(net, subnet)
            expect['routes'][netkey] = []
            for _ in range(0, 10):
                peer = {'multipath': True, 'valid': True}
                expect['routes'][netkey].append(peer)

    def _output_cmp():
        output = tgen.gears['r1'].vtysh_cmd('show ip bgp json', isjson=True)
        return topotest.json_cmp(output, expect)

    _, res = topotest.run_and_expect(_output_cmp, None, count=20, wait=3)
    assertmsg = 'expected multipath routes in "show ip bgp" output'
    assert res is None, assertmsg

if __name__ == '__main__':
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
