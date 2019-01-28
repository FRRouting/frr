#!/usr/bin/env python

#
# test_bgp_l3vpn_ldp_netns_leak.py
# Copyright 2018 6WIND S.A.
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
test_bgp_l3vpn_ldp_netns_leak.py: Test BGP topology with IBGP on NETNS VRF and LDP
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

CustomizeVrfWithNetns = True

#####################################################
##
##   Network Topology Definition
##
#####################################################

class BGPVRFNETNS_Topo(Topo):
    "BGP BGP VRF Leak Topology 1"

    def build(self, **_opts):
        tgen = get_topogen(self)

        # peer configuration on r1 side
        # Setup Routers r1
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

        # peer configuration on r2 side
        # Setup Routers r2 and peer
        tgen.add_router('r2')

        # Setup Switches
        switch = tgen.add_switch('s3')
        switch.add_link(tgen.gears['r2'])

        # Add eBGP ExaBGP neighbors
        peer_ip = '1.1.1.4'
        peer_route = 'via 1.1.1.4'
        peer = tgen.add_exabgp_peer('peer3',
                                    ip=peer_ip, defaultRoute=peer_route)
        switch.add_link(peer)

        switch = tgen.add_switch('s4')
        switch.add_link(tgen.gears['r2'])

        peer_ip = '2.2.2.5'
        peer_route = 'via 2.2.2.5'
        peer = tgen.add_exabgp_peer('peer4',
                                    ip=peer_ip, defaultRoute=peer_route)
        switch.add_link(peer)

        # Interco between r1 and r2
        # Setup Routers r3, r4
        tgen.add_router('r3')
        tgen.add_router('r4')

        # Setup Switches
        switch = tgen.add_switch('s5')
        switch.add_link(tgen.gears['r1'])
        switch.add_link(tgen.gears['r3'])

        switch = tgen.add_switch('s6')
        switch.add_link(tgen.gears['r2'])
        switch.add_link(tgen.gears['r4'])

        switch = tgen.add_switch('s7')
        switch.add_link(tgen.gears['r3'])
        switch.add_link(tgen.gears['r4'])
        
        # Setup Routers r5 and peer
        tgen.add_router('r5')
        # Setup Switches
        switch = tgen.add_switch('s8')
        switch.add_link(tgen.gears['r5'])
        # Add eBGP ExaBGP neighbors
        peer_ip = '1.1.1.21'
        peer_route = 'via 1.1.1.21'
        peer = tgen.add_exabgp_peer('peer5',
                                    ip=peer_ip, defaultRoute=peer_route)
        switch.add_link(peer)

        # provisioning for peer2
        switch = tgen.add_switch('s9')
        switch.add_link(tgen.gears['r5'])

        switch = tgen.add_switch('s10')
        switch.add_link(tgen.gears['r5'])
        switch.add_link(tgen.gears['r4'])

        
#####################################################
##
##   Tests starting
##
#####################################################

def setup_module(module):
    tgen = Topogen(BGPVRFNETNS_Topo, module.__name__)
    tgen.start_topology()

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

    router_list = ["r1","r2", "r5"]
    # sanity check - del previous vrf if any
    cmds = ['ip netns delete {0}-cust1',
            'ip netns delete {0}-cust2']
    for name in router_list:
        router = tgen.gears[name]
        for cmd in cmds:
            cmd = cmd.format(name)
            logger.info('cmd: '+cmd);
            output = router.run(cmd.format(name))
            logger.info('cmdresult: '+output);

    # create r1-cust1 and r1-cust2
    cmds = ['ip netns add {0}-cust1',
            'ip link set dev {0}-eth0 netns {0}-cust1',
            'ip netns exec {0}-cust1 ip li set dev {0}-eth0 up',
            'ip netns exec {0}-cust1 ip li set dev lo up',
            'ip netns add {0}-cust2',
            'ip link set dev {0}-eth1 netns {0}-cust2',
            'ip netns exec {0}-cust2 ip li set dev {0}-eth1 up',
            'ip netns exec {0}-cust2 ip li set dev lo up']
    for name in router_list:
        router = tgen.gears[name]
        for cmd in cmds:
            cmd = cmd.format(name)
            output = router.run(cmd.format(name))
            logger.info('cmd: '+cmd + 'result: ' +output);

    # create virtual ethernet interface across rx
    cmds = [# pair between {0}-cust1 and {0}-cust2
            'ip link set dev lo up',
            'ip link add {0}-cust1 type veth peer name {0}-cust2',
            'ip link set dev {0}-cust1 arp off',
            'ip link set dev {0}-cust2 arp off',
            'ip link set dev {0}-cust1 address 00:80:ed:01:01:03',
            'ip link set dev {0}-cust2 address 00:80:ed:01:01:03',
            'ip link set {0}-cust1 netns {0}-cust2',
            'ip link set {0}-cust2 netns {0}-cust1',
            'ip netns exec {0}-cust1 ip link set dev {0}-cust2 up',
            'ip netns exec {0}-cust2 ip link set dev {0}-cust1 up',
            # pair between vrf0 and {0}-cust1
            'ip link add {0}-cust1 type veth peer name vrf0',
            'ip link set dev {0}-cust1 arp off',
            'ip link set dev vrf0 arp off',
            'ip link set dev {0}-cust1 address 00:80:ed:01:01:01',
            'ip link set dev vrf0 address 00:80:ed:01:01:01',
            'ip link set vrf0 netns {0}-cust1',
            'ip netns exec {0}-cust1 ip link set dev vrf0 up',
            'ip link set dev {0}-cust1 up',
            # pair between vrf0 and {0}-cust2
            'ip link add {0}-cust2 type veth peer name vrf0',
            'ip link set dev {0}-cust2 arp off',
            'ip link set dev vrf0 arp off',
            'ip link set dev {0}-cust2 address 00:80:ed:01:01:02',
            'ip link set dev vrf0 address 00:80:ed:01:01:02',
            'ip link set vrf0 netns {0}-cust2',
            'ip netns exec {0}-cust2 ip link set dev vrf0 up',
            'ip link set dev {0}-cust2 up',
            # loopback interface config
            'ip link add {0}-loop1 type dummy',
            'ip link set {0}-loop1 netns {0}-cust1',
            'ip netns exec {0}-cust1 ip link set dev {0}-loop1 up',
            'ip link add {0}-loop2 type dummy',
            'ip link set {0}-loop2 netns {0}-cust2',
            'ip netns exec {0}-cust2 ip link set dev {0}-loop2 up']

    for name in router_list:
        router = tgen.gears[name]
        for cmd in cmds:
            cmd = cmd.format(name)
            logger.info('cmd: '+cmd);
            output = router.run(cmd.format(name))
            logger.info('cmd: '+cmd + 'result: ' +output);

    # MPLS configuration
    router_list = ["r3","r4"]
    cmds = [# config mpls for r3 and r4
        'ip link set dev lo up'
        ]
    for name in router_list:
        router = tgen.gears[name]
        for cmd in cmds:
            cmd = cmd.format(name)
            logger.info('cmd: '+cmd);
            output = router.run(cmd.format(name))
            logger.info('cmd: '+cmd + 'result: ' +output);

    #run daemons
    router_list = ["r1","r2","r3","r4","r5"]
    for name in router_list:
        router = tgen.gears[name]
        logger.info('running {0}/<file>.conf'.format(name))
        router.load_config(
            TopoRouter.RD_ZEBRA,
            os.path.join(CWD, '{}/zebra.conf'.format(name)),
            '--vrfwnetns -o vrf0'
        )
        router.load_config(
            TopoRouter.RD_LDP,
            os.path.join(CWD, '{}/ldpd.conf'.format(name))
        )
        router.load_config(
            TopoRouter.RD_OSPF,
            os.path.join(CWD, '{}/ospfd.conf'.format(name))
        )

    for name in router_list:
        router = tgen.gears[name]
        router.load_config(
            TopoRouter.RD_BGP,
            os.path.join(CWD, '{}/bgpd.conf'.format(name))
        )
        # BGP and ZEBRA and LDP start without underlying VRF

    logger.info('Launching BGP, OSPF, ZEBRA and LDP')
    router_list = ["r1","r2","r3","r4","r5"]
    for name in router_list:
        router = tgen.gears[name]
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
    # delete veth pairs
    router_list = ["r1","r2","r5"]
    cmds = ['ip link del {0}-cust1',
            'ip link del {0}-cust2',
            'ip link set netns exec {0}-cust1 ip link set dev {0}-cust2 netns 1',
            'ip link del {0}-cust2',
            # move back {0}-eth0 and {0}-eth1 to default vrf
            'ip link set netns exec {0}-cust1 ip link set dev {0}-eth0 netns 1',
            'ip link set netns exec {0}-cust2 ip link set dev {0}-eth1 netns 1',
            # move back loopx interfaces to default vrf
            'ip link set netns exec {0}-cust1 ip link set dev {0}-loop1 netns 1',
            'ip link set netns exec {0}-cust2 ip link set dev {0}-loop2 netns 1',
            'ip netns del {0}-cust1',
            'ip netns del {0}-cust2',
            'ip link del {0}-loop1',
            'ip link del {0}-loop2',
            'ip link del {0}-eth0',
            'ip link del {0}-eth1']
    for name in router_list:
        for cmd in cmds:
            tgen.net[name].cmd(cmd.format(name))

    tgen.stop_topology()

def test_bgp_vrf_ldp_netns_leak__learn():
    "Test daemon learnt VRF context"
    tgen = get_topogen()

    # Skip if previous fatal error condition is raised
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    router_list = ['r1','r2','r5']
    for name in router_list:
        # Expected result
        output = tgen.gears[name].vtysh_cmd("show vrf", isjson=False)
        logger.info('output is: {}'.format(output))

        output = tgen.gears[name].vtysh_cmd("show bgp vrfs", isjson=False)
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
    router_list = ["r1","r2"]
    for name in router_list:
        router = tgen.gears[name]

        reffile = os.path.join(CWD, '{0}/summary_peer1.txt'.format(name))

        expected = json.loads(open(reffile).read())

        test_func = functools.partial(topotest.router_json_cmp,
                                      router, 'show bgp vrf {0}-cust1 summary json'.format(name), expected)
        _, res = topotest.run_and_expect(test_func, None, count=20, wait=0.5)
        assertmsg = 'BGP router network for {0} peer 1 did not converge'.format(name)
        assert res is None, assertmsg

        reffile = os.path.join(CWD, '{0}/summary_peer2.txt'.format(name))

        expected = json.loads(open(reffile).read())

        test_func = functools.partial(topotest.router_json_cmp,
                                      router, 'show bgp vrf {0}-cust2 summary json'.format(name), expected)
        _, res = topotest.run_and_expect(test_func, None, count=20, wait=0.5)
        assertmsg = 'BGP router network for {0} peer 2 did not converge'.format(name)
        assert res is None, assertmsg

    router_list = ["r1","r2"]
    for name in router_list:
        router = tgen.gears[name]
        # peering with remote may take time, due to ospf adjacencies forming
        # and ldp establishment
        reffile = os.path.join(CWD, '{0}/summary_rx.txt'.format(name))

        expected = json.loads(open(reffile).read())

        test_func = functools.partial(topotest.router_json_cmp,
                                      router, 'show bgp ipv4 vpn summary json', expected)
        _, res = topotest.run_and_expect(test_func, None, count=25, wait=2)
        assertmsg = 'BGP router network for {0} L3VPN did not converge'.format(name)
        assert res is None, assertmsg
        logger.info('cmd: peering information with {}'.format(name));
        output = tgen.gears[name].vtysh_cmd('show bgp neighbors'.format(name), isjson=False)
        logger.info(output)
        output = tgen.gears[name].vtysh_cmd('show bgp ipv4 vpn'.format(name), isjson=False)
        logger.info(output)
        output = tgen.gears[name].vtysh_cmd('show bgp vrf {0}-cust1 ipv4'.format(name), isjson=False)
        logger.info(output)
        output = tgen.gears[name].vtysh_cmd('show bgp vrf {0}-cust2 ipv4'.format(name), isjson=False)
        logger.info(output)
        output = tgen.gears[name].vtysh_cmd('show ip route vrf {0}-cust1'.format(name), isjson=False)
        logger.info(output)
        output = tgen.gears[name].vtysh_cmd('show ip route vrf {0}-cust2'.format(name), isjson=False)
        logger.info(output)

def test_bgp_vrf_ldp_netns_leak():
    tgen = get_topogen()

    # tgen.mininet_cli()
    # Skip if previous fatal error condition is raised
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    list_values = {'0','1','2','3','4','5','6','7','8','9'}
    nh_values = {'r1-cust2' : '2.2.2.3','r1-cust1' : '1.1.1.2',
                 'r2-cust2' : '2.2.2.5','r2-cust1' : '1.1.1.4'}
    nh_values_remote = {'r1' : '9.9.9.9','r2' : '5.5.5.5'}

    router_list = ["r1","r2"]
    # check for VPN routes only
    # tgen.mininet_cli()
    for name in router_list:
        donna = tgen.gears[name].vtysh_cmd('show bgp vrf {0}-cust1 ipv4 json'.format(name), isjson=True)
        routes = donna['routes']
        for i in list_values:
            j = i
            if name == 'r1':
                j = int(i) + 11
            routeid = routes['10.201.{}.0/24'.format(j)]
            assert routeid is not None, "{0}, route 10.201.{1}.0/24 not found".format(name, j)
            nhVrfName = routeid[0]['nhVrfName']
            assertmsg = "{0}, unexpected nexthop vrf for 10.201.{1}.0/24: {2}".format(name, j, nhVrfName)
            assert nhVrfName == 'vrf0', assertmsg
            nexthopid = routeid[0]['nexthops']
            assert nexthopid is not None, "{0}, nexthop for 10.201.{1}.0/24 not found".format(name, j)
            nh = nexthopid[0]['ip']
            assert nh == nh_values_remote['{0}'.format(name)], "{0}, nexthop {1} not expected".format(name, nh)

        donna = tgen.gears[name].vtysh_cmd('show bgp vrf {0}-cust2 ipv4 json'.format(name), isjson=True)
        routes = donna['routes']
        for i in list_values:
            j = i
            if name == 'r1':
                j = int(i) + 11
            routeid = routes['10.101.{}.0/24'.format(j)]
            assert routeid is not None, "{0}, route 10.101.{1}.0/24 not found".format(name, j)
            nhVrfName = routeid[0]['nhVrfName']
            assertmsg = "{0}, unexpected nexthop vrf for 10.101.{1}.0/24: {2}".format(name, j, nhVrfName)
            assert nhVrfName == 'vrf0', assertmsg
            nexthopid = routeid[0]['nexthops']
            assert nexthopid is not None, "{0}, nexthop for 10.101.{1}.0/24 not found".format(name, j)
            nh = nexthopid[0]['ip']
            assert nh == nh_values_remote['{0}'.format(name)], "{0}, nexthop {1} not expected".format(name, nh)
    
        donna = tgen.gears[name].vtysh_cmd('show ip route vrf {0}-cust1 json'.format(name), isjson=True)
        for i in list_values:
            j = i
            if name == 'r1':
                j = int(i) + 11

            routeid = donna['10.201.{}.0/24'.format(j)]
            assert routeid is not None, "{0}, route 10.201.{1}.0/24 not found".format(name, j)
            nexthopid = routeid[0]['nexthops']
            assert nexthopid is not None, "{0}, nexthop for 10.201.{1}.0/24 not found".format(name, j)
            if 'fib' not in nexthopid[0].keys():
                assert 0, "{0}, FIB entry 10.201.{1}.0/24 not present".format(name, j)
            fib = nexthopid[0]['fib']
            ifacename = nexthopid[0]['interfaceName']
            assertmsg = "{0}, unexpected nh interface name vrf for 10.201.{1}.0/24: {2}".format(name, j, ifacename)
            assert ifacename == 'vrf0', assertmsg
            assert fib == True, "{0}, FIB entry 10.201.{}.0/24 not present".format(name, i)

        donna = tgen.gears[name].vtysh_cmd('show ip route vrf {0}-cust2 json'.format(name), isjson=True)
        for i in list_values:
            j = i
            if name == 'r1':
                j = int(i) + 11
            routeid = donna['10.101.{}.0/24'.format(j)]
            assert routeid is not None, "{0}, route 10.101.{1}.0/24 not found".format(name, j)
            nexthopid = routeid[0]['nexthops']
            if 'fib' not in nexthopid[0].keys():
                assert 0, "{0}, FIB entry 10.101.{}.0/24 not present".format(name, j)
            fib = nexthopid[0]['fib']
            ifacename = nexthopid[0]['interfaceName']
            assertmsg = "{0}, unexpected nh interface name vrf for 10.101.{1}.0/24: {2}".format(name, j, ifacename)
            assert ifacename == 'vrf0', assertmsg
            assert fib == True, "{0}, FIB entry 10.101.{}.0/24 not present".format(name, j)

    ## configure redistribute
    logger.info('Enabling redistribute connected in BGP VRF')
    cmd = 'vtysh -c \"configure terminal\" -c \"router bgp 100 vrf {0}-cust{1}\" -c \"address-family ipv4 unicast\" -c \"redistribute connected\" -c \"no redistribute connected\"  -c \"redistribute connected\"'
    tgen.net['r1'].cmd(cmd.format('r1','1','5.5.5.5'))
    tgen.net['r1'].cmd(cmd.format('r1','2','5.5.5.5'))
    tgen.net['r2'].cmd(cmd.format('r2','1','9.9.9.9'))
    tgen.net['r2'].cmd(cmd.format('r2','2','9.9.9.9'))

    topotest.sleep(2)
    output = tgen.net['r1'].cmd('ip netns exec r1-cust1 ping 10.101.51.3 -I 10.101.51.1 -f -c 1000')
    logger.info(output)
    if '1000 packets transmitted, 1000 received' not in output:
        assertmsg = 'expected ping from r1-cust1(10.101.51.1) to r2-cust1 (10.101.51.3) should be ok'
        assert 0, assertmsg
    else:
            logger.info('Check Ping from r1-cust1(10.101.51.1) to r2-cust1 (10.101.51.3) OK')

    output = tgen.net['r1'].cmd('ip netns exec r1-cust1 ping 10.201.52.4 -I 10.101.51.1 -f -c 1000')
    logger.info(output)
    if '1000 packets transmitted, 1000 received' not in output:
        assertmsg = 'expected ping from r1-cust1(10.101.51.1) to remote r2-cust2 (10.201.52.4) should be ok'
        assert 0, assertmsg
    else:
            logger.info('Check Ping from r1-cust1(10.101.51.1) to remote r2-cust2 (10.201.52.4) OK')

    logger.info('Disabling vrf0 interface on r1-cust1')
    output = tgen.net['r1'].cmd('ip netns exec r1-cust1 ip link set dev vrf0 down')
    logger.info(output)
    topotest.sleep(3)
    name = 'r1'
    donna = tgen.gears[name].vtysh_cmd('show ip route vrf {0}-cust1 json'.format(name), isjson=True)
    for i in list_values:
        j = int(i) + 11
        if '10.201.{}.0/24'.format(j) in donna.keys():
            assert 0, "{0}, route 10.201.{1}.0/24 found in RIB".format(name, j)

    #tgen.mininet_cli()
    donna = tgen.gears[name].vtysh_cmd('show bgp vrf {0}-cust1 ipv4 json'.format(name), isjson=True)
    routes = donna['routes']
    for i in list_values:
        j = int(i) + 11
        if '10.201.{}.0/24'.format(j) not in routes.keys():
            assert 0, "{0}, route 10.201.{1}.0/24 not found in BGP RIB".format(name, j)
        routeid = routes['10.101.{}.0/24'.format(j)]
        if 'valid' in routeid[0].keys():
            assert 0, "{0}, route 10.201.{1}.0/24 found in BGP RIB is valid".format(name, j)
        if 'bestpath' in routeid[0].keys():
            assert 0, "{0}, route 10.201.{1}.0/24 found in BGP RIB is bestpath".format(name, j)

    output = tgen.net['r1'].cmd('ip netns exec r1-cust1 ping 10.201.52.4 -I 10.101.51.1 -f -c 1000')
    logger.info(output)
    if '1000 packets transmitted, 0 received, 100% packet loss' in output:
        logger.info('Check Ping fail from r1-cust1(10.101.51.1) to r2-cust1 (10.101.51.3) OK')
    else:
        if 'connect: Network is unreachable' in output:
            logger.info('Check Ping fail from r1-cust1(10.101.51.1) to r2-cust1 (10.101.51.3) OK')
        else:
            assertmsg = 'expected ping from r1-cust1(10.101.51.1) to r2-cust1 (10.101.51.3) should fail'
            assert 0, assertmsg

    logger.info('Reenabling vrf0 interface on r1-cust1')
    output = tgen.net['r1'].cmd('ip netns exec r1-cust1 ip link set dev vrf0 up')
    logger.info(output)
    topotest.sleep(3)

    output = tgen.net['r1'].cmd('ip netns exec r1-cust1 ping 10.101.51.3 -I 10.101.51.1 -f -c 1000')
    logger.info(output)
    if '1000 packets transmitted, 1000 received' not in output:
        assertmsg = 'expected ping from r1-cust1(10.101.51.1) to r2-cust1 (10.101.51.3) should be ok'
        assert 0, assertmsg
    else:
            logger.info('Check Ping from r1-cust1(10.101.51.1) to r2-cust1 (10.101.51.3) OK')

    logger.info('r1 : peering with r5. Testing multipath')
    cmd = 'vtysh -c \"configure terminal\" -c \"router bgp 100\" -c \"neighbor 15.15.15.15\" -c \"neighbor 15.15.15.15 update-source 5.5.5.5\" -c \"address-family ipv4 vpn\" -c \"neighbor 15.15.15.15 activate\"'
    tgen.net['r1'].cmd(cmd)
    topotest.sleep(3)
    output = tgen.gears[name].vtysh_cmd('show bgp ipv4 vpn'.format(name), isjson=False)
    logger.info(output)
    output = tgen.gears[name].vtysh_cmd('show bgp vrf {0}-cust1 ipv4'.format(name), isjson=False)
    logger.info(output)
    # tgen.mininet_cli()

    # activate mpath , then peer with r5
    logger.info('r1 : peering with r5. Testing multipath')
    cmd = 'vtysh -c \"configure terminal\" -c \"router bgp 100 vrf r1-cust1\" -c \"address-family ipv4 unicast\" -c \"maximum-paths 4\" -c \"maximum-paths ibgp 4\"'
    name = 'r1'
    tgen.net[name].cmd(cmd)
    cmd = 'vtysh -c \"configure terminal\" -c \"router bgp 100\" -c \"neighbor 15.15.15.15 remote-as 100\" -c \"neighbor 15.15.15.15 update-source 5.5.5.5\" -c \"address-family ipv4 vpn\" -c \"neighbor 15.15.15.15 activate\"'
    tgen.net[name].cmd(cmd)
    topotest.sleep(3)
    output = tgen.gears[name].vtysh_cmd('show bgp ipv4 vpn'.format(name), isjson=False)
    logger.info(output)
    output = tgen.gears[name].vtysh_cmd('show bgp vrf {0}-cust1 ipv4'.format(name), isjson=False)
    logger.info(output)

    donna = tgen.gears[name].vtysh_cmd('show bgp vrf {0}-cust1 ipv4 json'.format(name), isjson=True)
    routes = donna['routes']
    ecmp_values = {'9.9.9.9','15.15.15.15'}
    ecmp_entries_values = {0,1}
    for i in list_values:
        j = int(i) + 11
        routeid = routes['10.101.{}.0/24'.format(j)]
        assert routeid is not None, "{0}, route 10.101.{1}.0/24 not found".format(name, j)
        val_to_check = 'multipath'
        for k in ecmp_entries_values:
            if val_to_check in routeid[k].keys():
                logger.info("{0}, route 10.101.{1}.0/24 mpath entry found".format(name, j))
                assert routeid[k][val_to_check] is True, "{0}, route 10.101.{1}.0/24 {2} not True".format(name, j, val_to_check)
            else:
                val_to_check = 'bestpath'
                if val_to_check in routeid[k].keys():
                    logger.info("{0}, route 10.101.{1}.0/24 bestpath entry found".format(name, j))
                    assert routeid[k][val_to_check] is True, "{0}, route 10.101.{1}.0/24 {2} not True".format(name, j, val_to_check)
            nexthopid = routeid[k]['nexthops']
            assert nexthopid is not None, "{0}, nexthop for 10.101.{1}.0/24 not found".format(name, j)
            nh = nexthopid[0]['ip']
            assert nh in ecmp_values, "{0}, nexthop {1} not expected".format(name, nh)

    donna = tgen.gears[name].vtysh_cmd('show ip route vrf {0}-cust1 json'.format(name), isjson=True)
    for i in list_values:
        j = int(i) + 11
        routeid = donna['10.101.{}.0/24'.format(j)]
        assert routeid is not None, "{0}, route 10.101.{1}.0/24 not found".format(name, j)
        nexthopid = routeid[0]['nexthops']
        assert nexthopid is not None, "{0}, nexthop for 10.101.{1}.0/24 not found".format(name, j)
        if 'fib' not in nexthopid[0].keys():
            assert 0, "{0}, First FIB entry 10.101.{1}.0/24 not present".format(name, j)
        if 'fib' not in nexthopid[3].keys():
            assert 0, "{0}, Second FIB entry 10.101.{1}.0/24 not present".format(name, j)

    #tgen.mininet_cli()

if __name__ == '__main__':

    args = ["-s"] + sys.argv[1:]
    ret = pytest.main(args)

    sys.exit(ret)
