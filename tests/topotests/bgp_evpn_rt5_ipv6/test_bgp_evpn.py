#!/usr/bin/env python

#
# test_bgp_evpn.py
# Part of NetDEF Topology Tests
#
# Copyright 2019 6WIND S.A.
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
 test_bgp_evpn.py: Test the FRR/Quagga BGP daemon with BGP IPv6 interface
 with route advertisements on a separate netns.
"""

import os
import sys
import json
from functools import partial
import pytest
import platform

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


vxlan_static_set = 0
CustomizeVrfWithNetns = True

class BGPEVPNTopo(Topo):
    "Test topology builder"
    def build(self, *_args, **_opts):
        "Build function"
        tgen = get_topogen(self)

        tgen.add_router('r1')
        tgen.add_router('r2')

        switch = tgen.add_switch('s1')
        switch.add_link(tgen.gears['r1'])
        switch.add_link(tgen.gears['r2'])

        switch = tgen.add_switch('s2')
        tgen.add_router('r3')
        switch.add_link(tgen.gears['r1'])
        switch.add_link(tgen.gears['r3'])

        switch = tgen.add_switch('s3')
        switch.add_link(tgen.gears['r2'])

        switch = tgen.add_switch('s4')
        tgen.add_router('r4')
        switch.add_link(tgen.gears['r1'])
        switch.add_link(tgen.gears['r4'])

        switch = tgen.add_switch('s5')
        tgen.add_router('r5')
        switch.add_link(tgen.gears['r2'])
        switch.add_link(tgen.gears['r5'])
        
        switch = tgen.add_switch('s6')
        tgen.add_router('r6')
        switch.add_link(tgen.gears['r1'])
        switch.add_link(tgen.gears['r6'])

        switch = tgen.add_switch('s7')
        tgen.add_router('r7')
        switch.add_link(tgen.gears['r2'])
        switch.add_link(tgen.gears['r7'])

def setup_module(mod):
    "Sets up the pytest environment"
    global CustomizeVrfWithNetns
    global vxlan_static_set

    tgen = Topogen(BGPEVPNTopo, mod.__name__)
    tgen.start_topology()

    CustomizeVrfWithNetns = True
    option_vrf_mode = os.getenv('VRF_MODE_PARAM', 'netns')
    if option_vrf_mode == 'vrf-lite':
        CustomizeVrfWithNetns = False

    router_list = tgen.routers()

    # check for zebra capability
    if CustomizeVrfWithNetns:
        if os.system('ip netns list') != 0:
            return  pytest.skip('Skipping BGP VRF NETNS Test. NETNS not available on System')

    krel = platform.release()
    l3mdev_accept = 0
    if topotest.version_cmp(krel, '4.15') >= 0 and \
       topotest.version_cmp(krel, '4.18') <= 0:
        l3mdev_accept = 1

    if topotest.version_cmp(krel, '5.0') >= 0:
        l3mdev_accept = 1

    # create VRF vrf-101 and vrf-105 on bng01
    # create loop101 and loop105
    if not CustomizeVrfWithNetns:
        logger.info('setting net.ipv4.tcp_l3mdev_accept={0}'.format(l3mdev_accept))
        cmds = ['sysctl -w net.ipv4.tcp_l3mdev_accept={0}'.format(l3mdev_accept),
                'ip link add {0}-vrf-101 type vrf table 101',
                'ip link add {0}-vrf-105 type vrf table 105',
                'ip ru add oif {0}-vrf-101 table 101',
                'ip ru add iif {0}-vrf-101 table 101',
                'ip ru add oif {0}-vrf-105 table 105',
                'ip ru add iif {0}-vrf-105 table 105',
                'ip link set dev {0}-vrf-101 up',
                'ip link set dev {0}-vrf-105 up',
                'ip link set dev {0}-eth2 master {0}-vrf-101',
                'ip link set dev {0}-eth3 master {0}-vrf-105']
    else:
        cmds = ['ip netns add {0}-vrf-101',
                'ip netns add {0}-vrf-105',
                'ip netns exec {0}-vrf-101 ip li set dev lo up',
                'ip netns exec {0}-vrf-105 ip li set dev lo up',
                'ip netns exec {0}-vrf-101 sysctl -w net.ipv6.conf.all.forwarding=1',
                'ip netns exec {0}-vrf-105 sysctl -w net.ipv6.conf.all.forwarding=1',
                'ip link set dev {0}-eth2 netns {0}-vrf-101',
                'ip netns exec {0}-vrf-101 ip link set dev {0}-eth2 up',
                'ip netns exec {0}-vrf-101 sysctl -w net.ipv6.conf.{0}-eth2.forwarding=1',
                'ip link set dev {0}-eth3 netns {0}-vrf-105',
                'ip netns exec {0}-vrf-105 ip link set dev {0}-eth3 up',
                'ip netns exec {0}-vrf-105 sysctl -w net.ipv6.conf.{0}-eth3.forwarding=1']

    router_list = ["r1","r2"]

    for name in router_list:
        router = tgen.gears[name]
        for cmd in cmds:
            cmd = cmd.format(name)
            logger.info('input:'+cmd)
            output = router.run(cmd)
            logger.info('result: '+output);

    if not CustomizeVrfWithNetns:
        cmds = [ # config routing 101
            'ip link add name bridge-{1} up type bridge stp_state 0',
            'ip link set bridge-{1} master {0}-vrf-{1}',
            'ip link set dev bridge-{1} up',
            'ip link add name vxlan-{1} type vxlan id {1} dstport 4789 dev {0}-eth0 local 192.168.100.{2}',
            'brctl addif bridge-{1} vxlan-{1}',
            'ip link set vxlan-{1} up type bridge_slave learning off flood off mcast_flood off']
    else:
        cmds = ['ip link add name vxlan-{1} type vxlan id {1} dstport 4789 dev {0}-eth0 local 192.168.100.{2}',
                'ip link set dev vxlan-{1} netns {0}-vrf-{1}',
                'ip netns exec {0}-vrf-{1} ip li set dev lo up',
                'ip netns exec {0}-vrf-{1} brctl addbr bridge-{1}',
                'ip netns exec {0}-vrf-{1} brctl addif bridge-{1} vxlan-{1}',
                'ip netns exec {0}-vrf-{1} ip link set bridge-{1} up',
                'ip netns exec {0}-vrf-{1} ip link set vxlan-{1} up']

    for name in router_list:
        ip = '41' if name == 'r2' else '21'
        router = tgen.gears[name]
        for cmd in cmds:
            cmd = cmd.format(name, '101', ip)
            logger.info('input:'+cmd)
            output = router.run(cmd)
            logger.info('result: '+output);

        for cmd in cmds:
            cmd = cmd.format(name, '105', ip)
            logger.info('input:'+cmd)
            output = router.run(cmd)
            logger.info('result: '+output);

    cmds = ['ip link add name vxlan-{1} type vxlan id {1} dstport 4789 dev {0}-eth0 local 192.168.100.{2}',
            'brctl addbr bridge-{1}',
            'brctl addif bridge-{1} vxlan-{1}',
            'ip link set bridge-{1} up',
            'ip link set vxlan-{1} up',
            'echo 1 > /proc/sys/net/ipv6/conf/all/forwarding',
            'echo 1 > /proc/sys/net/ipv6/conf/bridge-{1}/forwarding']

    for name in router_list:
        ip = '41' if name == 'r2' else '21'
        router = tgen.gears[name]
        for cmd in cmds:
            cmd = cmd.format(name, '107', ip)
            logger.info('input:'+cmd)
            output = router.run(cmd)
            logger.info('result: '+output);

    zebra_option = '--vrfwnetns' if CustomizeVrfWithNetns else ''
    router_list = tgen.routers()
    for name, router in router_list.iteritems():
        router.load_config(
            TopoRouter.RD_ZEBRA,
            os.path.join(CWD, '{}/zebra.conf'.format(name)),
            zebra_option
        )
        if name in ('r1', 'r2', 'r3'):
            router.load_config(
                TopoRouter.RD_BGP,
                os.path.join(CWD, '{}/bgpd.conf'.format(name))
            )

    # Initialize all routers.
    logger.info('Launching BGP, ZEBRA')
    for name, router in router_list.iteritems():
        router.start()

def teardown_module(_mod):
    "Teardown the pytest environment"
    global CustomizeVrfWithNetns

    tgen = get_topogen()
    if not CustomizeVrfWithNetns:
        cmds = ['ip link del {}-vrf-101',
                'ip link del {}-vrf-105']
    else:
        cmds = ['ip netns del {}-vrf-101',
                'ip netns del {}-vrf-105']
    
    router_list = ["r1","r2"]
    for name in router_list:
        router = tgen.gears[name]
        for cmd in cmds:
            cmd = cmd.format(name)
            output = router.run(cmd)

    tgen.stop_topology()


def test_protocols_convergence():
    """
    Assert that all protocols have converged
    statuses as they depend on it.
    """
    global CustomizeVrfWithNetns

    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    topotest.sleep(4, 'waiting 4 seconds for bgp convergence')
    # Check IPv4/IPv6 routing tables.
    output = tgen.gears['r1'].vtysh_cmd('show bgp l2vpn evpn', isjson=False)
    logger.info('==== result from show bgp l2vpn evpn')
    logger.info(output)
    output = tgen.gears['r1'].vtysh_cmd('show bgp l2vpn evpn route detail', isjson=False)
    logger.info('==== result from show bgp l2vpn evpn route detail')
    logger.info(output)
    output = tgen.gears['r1'].vtysh_cmd('show bgp vrf r1-vrf-101 ipv4', isjson=False)
    logger.info('==== result from show bgp vrf r1-vrf-101 ipv4')
    logger.info(output)
    output = tgen.gears['r1'].vtysh_cmd('show bgp vrf r1-vrf-101', isjson=False)
    logger.info('==== result from show bgp vrf r1-vrf-101 ')
    logger.info(output)
    output = tgen.gears['r1'].vtysh_cmd('show bgp vrf r1-vrf-105 ipv4', isjson=False)
    logger.info('==== result from show bgp vrf r1-vrf-105 ipv4')
    logger.info(output)
    output = tgen.gears['r1'].vtysh_cmd('show bgp vrf r1-vrf-105', isjson=False)
    logger.info('==== result from show bgp vrf r1-vrf-105')
    logger.info(output)
    output = tgen.gears['r1'].vtysh_cmd('show ip route vrf r1-vrf-101', isjson=False)
    logger.info('==== result from show ip route vrf r1-vrf-101')
    logger.info(output)
    output = tgen.gears['r1'].vtysh_cmd('show ipv6 route vrf r1-vrf-101', isjson=False)
    logger.info('==== result from show ipv6 route vrf r1-vrf-101')
    logger.info(output)
    output = tgen.gears['r1'].vtysh_cmd('show ipv6 route vrf r1-vrf-105', isjson=False)
    logger.info('==== result from show ip route vrf r1-vrf-105')
    logger.info(output)
    output = tgen.gears['r1'].vtysh_cmd('show ipv6 route vrf r1-vrf-105', isjson=False)
    logger.info('==== result from show ip route vrf r1-vrf-105')
    logger.info(output)
    output = tgen.gears['r1'].vtysh_cmd('show evpn vni detail', isjson=False)
    logger.info('==== result from show evpn vni detail')
    logger.info(output)
    output = tgen.gears['r1'].vtysh_cmd('show evpn next-hops vni all', isjson=False)
    logger.info('==== result from show evpn next-hops vni all')
    logger.info(output)
    output = tgen.gears['r1'].vtysh_cmd('show evpn rmac vni all', isjson=False)
    logger.info('==== result from show evpn next-hops vni all')
    logger.info(output)
    # Check IPv6 connectivity between r1 and r2 ( routing vxlan evpn)
    logger.info('Check Ping IPv6 from  R1(r1-vrf-101) to R2(r2-vrf-101 = 2001:101::41)')
    pingrouter = tgen.gears['r4']

    output = pingrouter.run('ping6 2001:101::41 -f -c 1000')
    logger.info(output)
    if '1000 packets transmitted, 1000 received' not in output:
        assertmsg = 'expected ping IPv6 from R1(r1-vrf-101) to R2(2001:101::41) should be ok'
        assert 0, assertmsg
    else:
        logger.info('Check Ping IPv6 from R1(r1-vrf-101) to R2(2001:101::41) OK')

    pingrouter = tgen.gears['r6']
    logger.info('Check Ping IPv6 from  R1(r1-vrf-105) to R2(r2-vrf-105 = 2001:105::41)')
    output = pingrouter.run('ping6 2001:105::41 -f -c 1000')
    logger.info(output)
    if '1000 packets transmitted, 1000 received' not in output:
        assertmsg = 'expected ping IPv6 from R1(r1-vrf-105) to R2(2001:105::41) should be ok'
        assert 0, assertmsg
    else:
        logger.info('Check Ping IPv6 from R1(r1-vrf-105) to R2(2001:105::41) OK')

    pingrouter = tgen.gears['r3']
    logger.info('Check Ping IPv6 from  R3(default) to R2(2001:107::41)')
    output = pingrouter.run('ping6 2001:107::41 -I 2001:108::31 -f -c 1000')
    logger.info(output)
    if '1000 packets transmitted, 1000 received' not in output:
        assertmsg = 'expected ping IPv6 from R3(default) to R2(2001:107::41) should be ok'
        assert 0, assertmsg
    else:
        logger.info('Check Ping IPv6 from R3(default) to R2(2001:107::41) OK')

def test_memory_leak():
    "Run the memory leak test and report results."
    tgen = get_topogen()
    if not tgen.is_memleak_enabled():
        pytest.skip('Memory leak test/report is disabled')

    tgen.report_memory_leaks()


if __name__ == '__main__':
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
