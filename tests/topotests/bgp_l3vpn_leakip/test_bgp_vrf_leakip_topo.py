#!/usr/bin/env python

#
# test_bgp_vrf_ipleak_topo.py
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
test_bgp_vrf_ipleak_topo.py: Test BGP topology with EBGP on NETNS VRF
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

class BGPVRFIPLEAKTopo(Topo):
    "BGP BGP VRF Leak Topology 1"

    def build(self, **_opts):
        tgen = get_topogen(self)

        # Setup Routers
        tgen.add_router('r1')

        # Setup Switches
        switch = tgen.add_switch('s1')
        switch.add_link(tgen.gears['r1'])

        # Add eBGP ExaBGP neighbors
        peer_ip = '1.1.1.2'
        peer_route = 'via 1.1.1.2'
        peer = tgen.add_exabgp_peer('peer1',
                                    ip=peer_ip, defaultRoute=peer_route)
        switch.add_link(peer)

        switch = tgen.add_switch('s2')
        switch.add_link(tgen.gears['r1'])

        peer_ip = '2.2.2.3'
        peer_route = 'via 2.2.2.3'
        peer = tgen.add_exabgp_peer('peer2',
                                    ip=peer_ip, defaultRoute=peer_route)
        switch.add_link(peer)

#####################################################
##
##   Tests starting
##
#####################################################

def setup_module(module):
    tgen = Topogen(BGPVRFIPLEAKTopo, module.__name__)
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

    # sanity check - del previous vrf if any
    cmds = ['ip netns del {0}-cust1',
            'ip netns del {0}-cust2']
    for cmd in cmds:
        cmd = cmd.format('r1')
        logger.info('cmd: '+cmd);
        router.run(cmd.format('r1'))

    # create r1-cust1 and r1-cust2
    cmds = ['ip netns add {0}-cust1',
            'ip link set dev {0}-eth0 netns {0}-cust1',
            'ip netns exec {0}-cust1 ifconfig {0}-eth0 up',
            'ip netns exec {0}-cust1 ip li set dev lo up',
            'ip netns add {0}-cust2',
            'ip link set dev {0}-eth1 netns {0}-cust2',
            'ip netns exec {0}-cust2 ifconfig {0}-eth1 up',
            'ip netns exec {0}-cust2 ip li set dev lo up']
    for cmd in cmds:
        cmd = cmd.format('r1')
        logger.info('cmd: '+cmd);
        output = router.run(cmd.format('r1'))
        if output != None and len(output) > 0:
            logger.info('Aborting due to unexpected output: cmd="{}" output=\n{}'.format(cmd, output))
            return pytest.skip('Skipping BGP VRF NETNS Test. Unexpected output to command: '+cmd)

    # create virtual ethernet interface across rx
    cmds = ['ip link add r1-cust1 type veth peer name r1-cust2',
            'ip link set r1-cust1 netns r1-cust1',
            'ip link set r1-cust2 netns r1-cust2',
            'ip netns exec r1-cust1 ip link set dev r1-cust1 up',
            'ip netns exec r1-cust2 ip link set dev r1-cust2 up']
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

def test_bgp_vrf_ipleak_learn():
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
    reffile = os.path.join(CWD, 'r1/summary_peer1.txt')

    expected = json.loads(open(reffile).read())

    test_func = functools.partial(topotest.router_json_cmp,
        router, 'show bgp vrf r1-cust1 summary json', expected)
    _, res = topotest.run_and_expect(test_func, None, count=10, wait=0.5)
    assertmsg = 'BGP router network for peer 1 did not converge'
    assert res is None, assertmsg

    router = tgen.gears['r1']
    reffile = os.path.join(CWD, 'r1/summary_peer2.txt')

    expected = json.loads(open(reffile).read())

    test_func = functools.partial(topotest.router_json_cmp,
        router, 'show bgp vrf r1-cust2 summary json', expected)
    _, res = topotest.run_and_expect(test_func, None, count=90, wait=0.5)
    assertmsg = 'BGP router network for peer 2 did not converge'

    assert res is None, assertmsg

def test_bgp_vrf_ipleak():
    tgen = get_topogen()

    # tgen.mininet_cli()
    # Skip if previous fatal error condition is raised
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    expect = {
        'routerId': '1.1.1.1',
        'routes': {
        },
    }

    list_values = {'0','1','2','3','4','5','6','7','8','9'}
    donna = tgen.gears['r1'].vtysh_cmd("show bgp vrf r1-cust1 ipv4 json", isjson=True)

    routes = donna['routes']
    for i in list_values:
        routeid = routes['10.201.{}.0/24'.format(i)]
        assert routeid is not None, "route 10.201.{}.0/24 not found".format(i)
        nexthopid = routeid[0]['nexthops']
        assert nexthopid is not None, "nexthop for 10.201.{}.0/24 not found".format(i)
        nh = nexthopid[0]['ip']
        assert nh == "169.254.128.2", "nexthop {} not expected".format(nh)

    donna = tgen.gears['r1'].vtysh_cmd("show bgp vrf r1-cust2 ipv4 json", isjson=True)

    routes = donna['routes']
    for i in list_values:
        routeid = routes['10.101.{}.0/24'.format(i)]
        assert routeid is not None, "route 10.101.{}.0/24 not found".format(i)
        nexthopid = routeid[0]['nexthops']
        assert nexthopid is not None, "nexthop for 10.101.{}.0/24 not found".format(i)
        nh = nexthopid[0]['ip']
        assert nh == "169.254.128.1", "nexthop {} not expected".format(nh)
    
    donna = tgen.gears['r1'].vtysh_cmd("show ip route vrf r1-cust1 json", isjson=True)
    for i in list_values:
        routeid = donna['10.201.{}.0/24'.format(i)]
        assert routeid is not None, "route 10.201.{}.0/24 not found".format(i)
        nexthopid = routeid[0]['nexthops']
        assert nexthopid is not None, "nexthop for 10.201.{}.0/24 not found".format(i)
        fib = nexthopid[0]['fib']
        nh = nexthopid[0]['ip']
        assert fib == True, "nexthop {} not added to FIB".format(nh)

    donna = tgen.gears['r1'].vtysh_cmd("show ip route vrf r1-cust2 json", isjson=True)
    for i in list_values:
        routeid = donna['10.101.{}.0/24'.format(i)]
        assert routeid is not None, "route 10.101.{}.0/24 not found".format(i)
        nexthopid = routeid[0]['nexthops']
        fib = nexthopid[0]['fib']
        nh = nexthopid[0]['ip']
        assert fib == True, "nexthop {} not added to FIB".format(nh)


if __name__ == '__main__':

    args = ["-s"] + sys.argv[1:]
    ret = pytest.main(args)

    sys.exit(ret)
