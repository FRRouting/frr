#!/usr/bin/env python

#
# test_bgp_vrf_netns_topo1.py
# Part of NetDEF Topology Tests
#
# Copyright (c) 2018 by 6WIND
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
test_bgp_vrf_netns_topo1.py: Test BGP topology with EBGP on NETNS VRF
"""

import json
import os
import sys
import functools
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

total_ebgp_peers = 1
CustomizeVrfWithNetns = True

#####################################################
##
##   Network Topology Definition
##
#####################################################

class BGPVRFNETNSTopo1(Topo):
    "BGP EBGP VRF NETNS Topology 1"

    def build(self, **_opts):
        tgen = get_topogen(self)

        # Setup Routers
        tgen.add_router('r1')

        # Setup Switches
        switch = tgen.add_switch('s1')
        switch.add_link(tgen.gears['r1'])

        # Add eBGP ExaBGP neighbors
        peer_ip = '10.0.1.101'
        peer_route = 'via 10.0.1.1'
        peer = tgen.add_exabgp_peer('peer1',
                                    ip=peer_ip, defaultRoute=peer_route)
        switch = tgen.gears['s1']
        switch.add_link(peer)


#####################################################
##
##   Tests starting
##
#####################################################

def setup_module(module):
    tgen = Topogen(BGPVRFNETNSTopo1, module.__name__)
    tgen.start_topology()

    # Get r1 reference
    router = tgen.gears['r1']

    # check for zebra capability
    if CustomizeVrfWithNetns == True:
        if router.check_capability(
                TopoRouter.RD_ZEBRA,
                '--vrfwnetns'
                ) == False:
            return  pytest.skip('Skipping BGP VRF NETNS Test. VRF NETNS backend not available on FRR')
        if os.system('ip netns list') != 0:
            return  pytest.skip('Skipping BGP VRF NETNS Test. NETNS not available on System')
    # retrieve VRF backend kind
    if CustomizeVrfWithNetns == True:
        logger.info('Testing with VRF Namespace support')

    # create VRF r1-cust1
    # move r1-eth0 to VRF r1-cust1
    cmds = ['if [ -e /var/run/netns/{0}-cust1 ] ; then ip netns del {0}-cust1 ; fi',
            'ip netns add {0}-cust1',
            'ip link set dev {0}-eth0 netns {0}-cust1',
            'ip netns exec {0}-cust1 ifconfig {0}-eth0 up']
    for cmd in cmds:
        cmd = cmd.format('r1')
        logger.info('cmd: '+cmd);
        output = router.run(cmd.format('r1'))
        if output != None and len(output) > 0:
            logger.info('Aborting due to unexpected output: cmd="{}" output=\n{}'.format(cmd, output))
            return pytest.skip('Skipping BGP VRF NETNS Test. Unexpected output to command: '+cmd)
    #run daemons
    router.load_config(
        TopoRouter.RD_ZEBRA,
        os.path.join(CWD, '{}/zebra.conf'.format('r1')),
        '--vrfwnetns'
    )
    router.load_config(
        TopoRouter.RD_BGP,
        os.path.join(CWD, '{}/bgpd.conf'.format('r1'))
    )

    logger.info('Launching BGP and ZEBRA')
    # BGP and ZEBRA start without underlying VRF
    router.start()
    # Starting Hosts and init ExaBGP on each of them
    logger.info('starting exaBGP on peer1')
    peer_list = tgen.exabgp_peers()
    for pname, peer in peer_list.iteritems():
        peer_dir = os.path.join(CWD, pname)
        env_file = os.path.join(CWD, 'exabgp.env')
        logger.info('Running ExaBGP peer')
        peer.start(peer_dir, env_file)
        logger.info(pname)

def teardown_module(module):
    tgen = get_topogen()
    # move back r1-eth0 to default VRF
    # delete VRF r1-cust1
    cmds = ['ip netns exec {0}-cust1 ip link set {0}-eth0 netns 1',
            'ip netns delete {0}-cust1']
    for cmd in cmds:
        tgen.net['r1'].cmd(cmd.format('r1'))

    tgen.stop_topology()

def test_bgp_vrf_learn():
    "Test daemon learnt VRF context"
    tgen = get_topogen()

    # Skip if previous fatal error condition is raised
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    # Expected result
    output = tgen.gears['r1'].vtysh_cmd("show vrf", isjson=False)
    logger.info('output is: {}'.format(output))

    output = tgen.gears['r1'].vtysh_cmd("show bgp vrfs", isjson=False)
    logger.info('output is: {}'.format(output))


def test_bgp_convergence():
    "Test for BGP topology convergence"
    tgen = get_topogen()

    # uncomment if you want to troubleshoot
    # tgen.mininet_cli()
    # Skip if previous fatal error condition is raised
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    logger.info('waiting for bgp convergence')

    # Expected result
    router = tgen.gears['r1']
    if router.has_version('<', '3.0'):
        reffile = os.path.join(CWD, 'r1/summary20.txt')
    else:
        reffile = os.path.join(CWD, 'r1/summary.txt')

    expected = json.loads(open(reffile).read())

    test_func = functools.partial(topotest.router_json_cmp,
        router, 'show bgp vrf r1-cust1 summary json', expected)
    _, res = topotest.run_and_expect(test_func, None, count=90, wait=0.5)
    assertmsg = 'BGP router network did not converge'
    assert res is None, assertmsg

def test_bgp_vrf_netns():
    tgen = get_topogen()

    # Skip if previous fatal error condition is raised
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    expect = {
        'routerId': '10.0.1.1',
        'routes': {
        },
    }

    for subnet in range(0, 10):
        netkey = '10.201.{}.0/24'.format(subnet)
        expect['routes'][netkey] = []
        peer = {'valid': True}
        expect['routes'][netkey].append(peer)

    test_func = functools.partial(topotest.router_json_cmp,
        tgen.gears['r1'], 'show ip bgp vrf r1-cust1 ipv4 json', expect)
    _, res = topotest.run_and_expect(test_func, None, count=12, wait=0.5)
    assertmsg = 'expected routes in "show ip bgp vrf r1-cust1 ipv4" output'
    assert res is None, assertmsg

if __name__ == '__main__':

    args = ["-s"] + sys.argv[1:]
    ret = pytest.main(args)

    sys.exit(ret)
