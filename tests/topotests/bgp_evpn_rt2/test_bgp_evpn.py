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
        tgen.add_router('r4')
        switch.add_link(tgen.gears['r4'])
        
def setup_module(mod):
    "Sets up the pytest environment"
    global CustomizeVrfWithNetns

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

    if topotest.version_cmp(krel, '5.0') < 0:
        logger.info('BGP EVPN RT2 NETNS tests will not run (have kernel "{}", but it requires 5.0)'.format(krel))
        return pytest.skip('Skipping BGP EVPN RT2 NETNS Test. Kernel not supported')

    l3mdev_accept = 1
    logger.info('setting net.ipv4.tcp_l3mdev_accept={}'.format(l3mdev_accept))

    if not CustomizeVrfWithNetns:
        cmds = ['sysctl -w net.ipv4.tcp_l3mdev_accept={}'.format(l3mdev_accept),
                'ip link add {}-vrf-101 type vrf table 101',
                'ip link add {}-vrf-105 type vrf table 105',
                'ip link add {}-vrf-107 type vrf table 107',
                'ip link add {}-vrf-109 type vrf table 109',
                'ip ru add oif {}-vrf-101 table 101',
                'ip ru add iif {}-vrf-101 table 101',
                'ip ru add oif {}-vrf-105 table 105',
                'ip ru add iif {}-vrf-105 table 105',
                'ip ru add oif {}-vrf-107 table 107',
                'ip ru add iif {}-vrf-107 table 107',
                'ip ru add oif {}-vrf-109 table 109',
                'ip ru add iif {}-vrf-109 table 109',
                'ip link set dev {}-vrf-101 up',
                'ip link set dev {}-vrf-105 up',
                'ip link set dev {}-vrf-107 up',
                'ip link set dev {}-vrf-109 up',
                'sysctl -w net.ipv4.tcp_l3mdev_accept={}'.format(l3mdev_accept)]
    else:
        cmds = ['ip netns add {}-vrf-101',
                'ip netns add {}-vrf-105',
                'ip netns add {}-vrf-107',
                'ip netns add {}-vrf-109',
                'ip link set dev {0}-eth1 netns {0}-vrf-107',
                'ip netns exec {0}-vrf-107 ip link set dev {0}-eth1 up',
                'ip netns exec {0}-vrf-101 ip link set dev lo up',
                'ip netns exec {0}-vrf-105 ip link set dev lo up',
                'ip netns exec {0}-vrf-107 ip link set dev lo up',
                'ip netns exec {0}-vrf-109 ip link set dev lo up']

    router_list = ["r1","r2"]

    for name in router_list:
        router = tgen.gears[name]
        for cmd in cmds:
            cmd = cmd.format(name)
            logger.info('input:'+cmd)
            output = router.run(cmd)
            logger.info('result: '+output);

    if not CustomizeVrfWithNetns:
        cmds = ['ip link add name bridge-{1} up type bridge stp_state 0',
                'ip link add link bridge-{1} name bridge-{1}.{1} type vlan id {1}',
                'ip link set bridge-{1}.{1} master {0}-vrf-{1}',
                'ip link set dev bridge-{1} up',
                'ip link set dev bridge-{1}.{1} up',
                'ip link add name vxlan-{1} type vxlan id {1} dstport 4789 dev {0}-eth0 local 192.168.100.{2}',
                'brctl addif bridge-{1} vxlan-{1}',
                'ip link set vxlan-{1} up type bridge_slave learning on mcast_flood on',
                'ip link set vxlan-{1} up',
                'ip link add name bridge-{3} up type bridge stp_state 0',
                'ip link add veth-{3} type veth peer name veth-{3}-peer',
                'brctl addif bridge-{3} veth-{3}',
                'ip netns add {0}-rx-{3}',
                'ip link set dev veth-{3}-peer netns {0}-rx-{3}',
                'ip link set veth-{3} master {0}-vrf-{3}',
                'ip link set dev bridge-{3} up',
                'ip link set dev veth-{3} up',
                'ip link set veth-{3} up type bridge_slave learning on mcast_flood on',
                'ip netns exec {0}-rx-{3} ip link set dev lo up',
                'ip netns exec {0}-rx-{3} ip link set dev veth-{3}-peer up',
                'ip netns exec {0}-rx-{3} ip a a 192.168.{3}.{2}/24 dev veth-{3}-peer',
                'ip netns exec {0}-rx-{3} ip -6 a a 2001:{3}::{2}/112 dev veth-{3}-peer',
                'ip link add name vxlan-{3} type vxlan id {3} dstport 4789 dev {0}-eth0 local 192.168.100.{2}',
                'ip link set vxlan-{3} master bridge-{3}',
                'ip link set veth-{3} master bridge-{3}',
                'ip link set vxlan-{3} up type bridge_slave learning on mcast_flood on',
                'ip link add name bridge-{4} up type bridge stp_state 0',
                'ip link set dev bridge-{4} up',
                'ip link add name vxlan-{4} type vxlan id {4} dstport 4789 dev {0}-eth0 local 192.168.100.{2}',
                'brctl addif bridge-{4} vxlan-107',
                'brctl addif bridge-{4} {0}-eth1',
                'ip link set bridge-{4} master {0}-vrf-{4}',
                'ip link set vxlan-{4} up type bridge_slave learning on mcast_flood on',
                'ip link set {0}-eth1 up type bridge_slave',
                'ip link set {0}-eth1 up type bridge_slave mcast_flood on',
                'ip link add name bridge-{5} up type bridge stp_state 0',
                'ip link add veth-{5} type veth peer name veth-{5}-peer',
                'brctl addif bridge-{5} veth-{5}',
                'ip link set veth-{5}-peer master {0}-vrf-{5}',
                'ip link set dev bridge-{5} up',
                'ip link set dev veth-{5} up',
                'ip link set dev veth-{5}-peer up',
                'ip link add name vxlan-{5} type vxlan id {5} dstport 4789 dev {0}-eth0 local 192.168.100.{2}',
                'ip link set vxlan-{5} master bridge-{5}',
                'ip link set veth-{5} master bridge-{5}',
                'ip link set vxlan-{5} up type bridge_slave learning on mcast_flood on']
    else:
        cmds = ['ip link add name vxlan-{1} type vxlan id {1} dstport 4789 dev {0}-eth0 local 192.168.100.{2}',
                'ip link set dev vxlan-{1} netns {0}-vrf-{1}',
                'ip netns exec {0}-vrf-{1} ip li set dev lo up',
                #                             'ip netns exec {0}-vrf-{1} ip link add name bridge-{1} up type bridge stp_state 0',
                'ip netns exec {0}-vrf-{1} brctl addbr bridge-{1}',
                'ip netns exec {0}-vrf-{1} brctl addif bridge-{1} vxlan-{1}',
                'ip netns exec {0}-vrf-{1} ip link set vxlan-{1} up type bridge_slave learning on mcast_flood on',
                'ip netns exec {0}-vrf-{1} ip link set bridge-{1} up',
                'ip netns exec {0}-vrf-{1} ip link set vxlan-{1} up',
                'ip netns exec {0}-vrf-{1} ip link add link bridge-{1} name bridge-{1}.{1} type vlan id {1}',
                'ip netns exec {0}-vrf-{1} ip link set bridge-{1}.{1} up',
                'ip link add name vxlan-{3} type vxlan id {3} dstport 4789 dev {0}-eth0 local 192.168.100.{2}',
                'ip link set dev vxlan-{3} netns {0}-vrf-{3}',
                'ip netns exec {0}-vrf-{3} ip li set dev lo up',
                #                             'ip netns exec {0}-vrf-{1} ip link add name bridge-{1} up type bridge stp_state 0',
                'ip netns exec {0}-vrf-{3} brctl addbr bridge-{3}',
                'ip netns exec {0}-vrf-{3} brctl addif bridge-{3} vxlan-{3}',
                'ip netns exec {0}-vrf-{3} ip link set vxlan-{3} up type bridge_slave learning on mcast_flood on',
                'ip netns exec {0}-vrf-{3} ip link set bridge-{3} up',
                'ip netns exec {0}-vrf-{3} ip link set vxlan-{3} up',
                'ip netns add {0}-rx-{3}',
                'ip netns exec {0}-rx-{3} ip link set dev lo up',
                'ip netns exec {0}-vrf-{3} ip link add veth-{3} type veth peer name veth-{3}-peer',
                'ip netns exec {0}-vrf-{3} brctl addif bridge-{3} veth-{3}',
                'ip netns exec {0}-vrf-{3} ip link set veth-{3} up type bridge_slave learning on flood on mcast_flood on',
                'ip netns exec {0}-vrf-{3} ip link set dev veth-{3} up',
                'ip netns exec {0}-vrf-{3} ip link set dev veth-{3}-peer netns {0}-rx-{3}',
                'ip netns exec {0}-rx-{3} ip link set dev veth-{3}-peer up',
                'ip netns exec {0}-rx-{3} ip a a 192.168.{3}.{2}/24 dev veth-{3}-peer',
                'ip netns exec {0}-rx-{3} ip -6 a a 2001:{3}::{2}/112 dev veth-{3}-peer',
                'ip netns exec {0}-vrf-{3} ip link set vxlan-{3} up',
                'ip link add name vxlan-{4} type vxlan id {4} dstport 4789 dev {0}-eth0 local 192.168.100.{2}',
                'ip link set dev vxlan-{4} netns {0}-vrf-{4}',
                'ip netns exec {0}-vrf-{4} ip li set dev lo up',
                #                             'ip netns exec {0}-vrf-{1} ip link add name bridge-{1} up type bridge stp_state 0',
                'ip netns exec {0}-vrf-{4} brctl addbr bridge-{4}',
                'ip netns exec {0}-vrf-{4} brctl addif bridge-{4} vxlan-{4}',
                'ip netns exec {0}-vrf-{4} ip link set vxlan-{4} up type bridge_slave learning on mcast_flood on',
                'ip netns exec {0}-vrf-{4} ip link set bridge-{4} up',
                'ip netns exec {0}-vrf-{4} ip link set vxlan-{4} up',
                'ip netns exec {0}-vrf-{4} brctl addif bridge-{4} {0}-eth1',
                'ip netns exec {0}-vrf-{4} ip link set {0}-eth1 up type bridge_slave',
                'ip link add name vxlan-{5} type vxlan id {5} dstport 4789 dev {0}-eth0 local 192.168.100.{2}',
                'brctl addbr bridge-{5}',
                'brctl addif bridge-{5} vxlan-{5}',
                'ip link set bridge-{5} up',
                'ip link set vxlan-{5} up',
                'ip link add veth-{5} type veth peer name veth-{5}-peer',
                'ip link set dev veth-{5}-peer netns {0}-vrf-{5}',
                'ip netns exec {0}-vrf-{5} ip link set dev veth-{5}-peer up',
                'brctl addif bridge-{5} veth-{5}',
                'ip link set dev veth-{5} up']

    for name in router_list:
        ip = '41' if name == 'r2' else '21'
        router = tgen.gears[name]
        for cmd in cmds:
            cmd = cmd.format(name, '101', ip, '105', '107', '109')
            logger.info('input:'+cmd)
            output = router.run(cmd)
            logger.info('result: '+output);

    router_list = tgen.routers()
    zebra_option = '--vrfwnetns' if CustomizeVrfWithNetns else ''
    for rname, router in router_list.iteritems():
        router.load_config(
            TopoRouter.RD_ZEBRA,
            os.path.join(CWD, '{}/zebra.conf'.format(rname)),
            zebra_option
        )
        if rname == 'r1' or rname == 'r2':
            router.load_config(
                TopoRouter.RD_BGP,
                os.path.join(CWD, '{}/bgpd.conf'.format(rname))
            )

    # Initialize all routers.
    tgen.start_router()

def teardown_module(_mod):
    "Teardown the pytest environment"
    global CustomizeVrfWithNetns

    tgen = get_topogen()
    if CustomizeVrfWithNetns:
        cmds = ['ip netns del {}-vrf-101',
                'ip netns del {}-vrf-105',
                'ip netns del {}-vrf-107',
                'ip netns del {}-vrf-109',
                'ip netns del {}-rx-105']
    else:
        cmds = ['ip netns del {}-rx-105']

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
    output = tgen.gears['r1'].vtysh_cmd('show evpn vni detail', isjson=False)
    logger.info('==== result from show evpn vni detail')
    logger.info(output)
    output = tgen.gears['r1'].vtysh_cmd('show evpn arp-cache vni all', isjson=False)
    logger.info('==== result from show evpn arp-cache vni all')
    logger.info(output)
    # Check IPv4 and IPv6 connectivity between r1 and r2 ( routing vxlan evpn)
    pingrouter = tgen.gears['r1']
    if CustomizeVrfWithNetns:
        logger.info('Check Ping IPv4 from  R1(r1-vrf-101) to R2(r2-vrf-101 = 192.168.101.41)')
        output = pingrouter.run('ip netns exec r1-vrf-101 ping 192.168.101.41 -f -c 1000')
        logger.info(output)
        if '1000 packets transmitted, 1000 received' not in output:
            assertmsg = 'expected ping IPv4 from R1(r1-vrf-101) to R2(192.168.101.41) should be ok'
            assert 0, assertmsg
        else:
            logger.info('Check Ping IPv4 from R1(r1-vrf-101) to R2(192.168.101.41) OK')

        logger.info('Check Ping IPv6 from  R1(r1-vrf-101) to R2(r2-vrf-101 = 2001:101::41)')
        output = pingrouter.run('ip netns exec r1-vrf-101 ping6 2001:101::41 -f -c 1000')
        logger.info(output)
        if '1000 packets transmitted, 1000 received' not in output:
            assertmsg = 'expected ping IPv6 from R1(r1-vrf-101) to R2(2001:101::41) should be ok'
            assert 0, assertmsg
        else:
            logger.info('Check Ping IPv6 from R1(r1-vrf-101) to R2(2001:101::41) OK')

    logger.info('Check Ping IPv4 from  R1(r1-rx-105) to R2(r2-rx-105 = 192.168.105.41)')

    output = pingrouter.run('ip netns exec r1-rx-105 ping 192.168.105.41 -f -c 1000')
    logger.info(output)
    if '1000 packets transmitted, 1000 received' not in output:
        assertmsg = 'expected ping IPv4 from R1(r1-rx-105) to R2(192.168.105.41) should be ok'
        assert 0, assertmsg
    else:
        logger.info('Check Ping IPv4 from R1(r1-rx-105) to R2(192.168.105.41) OK')

    logger.info('Check Ping IPv6 from  R1(r1-rx-105) to R2(r2-rx-105 = 2001:105::41)')
    output = pingrouter.run('ip netns exec r1-rx-105 ping6 2001:105::41 -f -c 1000')
    logger.info(output)
    if '1000 packets transmitted, 1000 received' not in output:
        assertmsg = 'expected ping IPv6 from R1(r1-rx-105) to R2(2001:105::41) should be ok'
        assert 0, assertmsg
    else:
        logger.info('Check Ping IPv6 from R1(r1-rx-105) to R2(2001:105::41) OK')

    pingrouter = tgen.gears['r3']
    logger.info('Check Ping IPv4 from  R3(default) to R2(192.168.107.41)')
    output = pingrouter.run('ping 192.168.107.41 -I 192.168.107.31 -f -c 1000')
    logger.info(output)
    if '1000 packets transmitted, 1000 received' not in output:
        assertmsg = 'expected ping IPv4 from R3(default) to R2(192.168.107.41) should be ok'
        assert 0, assertmsg
    else:
        logger.info('Check Ping IPv4 from R3(default) to R2(192.168.107.41) OK')

    logger.info('Check Ping IPv6 from  R3(default) to R2(2001:107::41)')
    output = pingrouter.run('ping6 2001:107::41 -I 2001:107::31 -f -c 1000')
    logger.info(output)
    if '1000 packets transmitted, 1000 received' not in output:
        assertmsg = 'expected ping IPv6 from R3(default) to R2(2001:107::41) should be ok'
        assert 0, assertmsg
    else:
        logger.info('Check Ping IPv6 from R3(default) to R2(2001:107::41) OK')

    if CustomizeVrfWithNetns:
        pingrouter = tgen.gears['r1']
        logger.info('Check Ping IPv4 from  R1(r1-vrf-109) to R2(r2-vrf-109 = 192.168.109.41)')
        output = pingrouter.run('ip netns exec r1-vrf-109 ping 192.168.109.41 -f -c 1000')
        logger.info(output)
        if '1000 packets transmitted, 1000 received' not in output:
            assertmsg = 'expected ping IPv4 from R1(r1-vrf-109) to R2(192.168.109.41) should be ok'
            assert 0, assertmsg
        else:
            logger.info('Check Ping IPv4 from R1(r1-vrf-109) to R2(192.168.109.41) OK')

        logger.info('Check Ping IPv6 from  R1(r1-vrf-109) to R2(r2-vrf-109 = 2001:109::41)')
        output = pingrouter.run('ip netns exec r1-vrf-109 ping6 2001:109::41 -f -c 1000')
        logger.info(output)
        if '1000 packets transmitted, 1000 received' not in output:
            assertmsg = 'expected ping IPv6 from R1(r1-vrf-109) to R2(2001:109::41) should be ok'
            assert 0, assertmsg
        else:
            logger.info('Check Ping IPv6 from R1(r1-vrf-109) to R2(2001:109::41) OK')

def test_memory_leak():
    "Run the memory leak test and report results."
    tgen = get_topogen()
    if not tgen.is_memleak_enabled():
        pytest.skip('Memory leak test/report is disabled')

    tgen.report_memory_leaks()


if __name__ == '__main__':
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
