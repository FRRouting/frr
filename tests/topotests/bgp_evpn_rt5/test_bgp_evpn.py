#!/usr/bin/env python

#
# test_bgp_evpn.py
# Part of NetDEF Topology Tests
#
# Copyright (c) 2019 by 6WIND
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

l3mdev_accept = 0
krel = ''

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
        switch.add_link(tgen.gears['r1'])

        switch = tgen.add_switch('s3')
        switch.add_link(tgen.gears['r2'])
        
def setup_module(mod):
    "Sets up the pytest environment"
    global l3mdev_accept
    global krel

    tgen = Topogen(BGPEVPNTopo, mod.__name__)
    tgen.start_topology()

    router_list = tgen.routers()

    krel = platform.release()
    if topotest.version_cmp(krel, '4.18') < 0:
        logger.info('BGP EVPN RT5 NETNS tests will not run (have kernel "{}", but it requires 4.18)'.format(krel))
        return pytest.skip('Skipping BGP EVPN RT5 NETNS Test. Kernel not supported')

    l3mdev_accept = 1
    logger.info('setting net.ipv4.tcp_l3mdev_accept={}'.format(l3mdev_accept))

    # create VRF vrf-101 on R1 and R2
    # create loop101
    cmds_vrflite = ['sysctl -w net.ipv4.tcp_l3mdev_accept={}'.format(l3mdev_accept),
                    'ip link add {}-vrf-101 type vrf table 101',
                    'ip ru add oif {}-vrf-101 table 101',
                    'ip ru add iif {}-vrf-101 table 101',
                    'ip link set dev {}-vrf-101 up',
                    'sysctl -w net.ipv4.tcp_l3mdev_accept={}'.format(l3mdev_accept),
                    'ip link add loop101 type dummy',
                    'ip link set dev loop101 master {}-vrf-101',
                    'ip link set dev loop101 up']
    cmds_netns = ['ip netns add {}-vrf-101',
                  'ip link add loop101 type dummy',
                  'ip link set dev loop101 netns {}-vrf-101',
                  'ip netns exec {}-vrf-101 ip link set dev loop101 up']

    cmds_r2 = [ # config routing 101
               'ip link add name bridge-101 up type bridge stp_state 0',
               'ip link set bridge-101 master {}-vrf-101',
               'ip link set dev bridge-101 up',
               'ip link add name vxlan-101 type vxlan id 101 dstport 4789 dev r2-eth0 local 192.168.100.41',
               'ip link set dev vxlan-101 master bridge-101',
               'ip link set vxlan-101 up type bridge_slave learning off flood off mcast_flood off']

    cmds_r1_netns_method3 = ['ip link add name vxlan-{1} type vxlan id {1} dstport 4789 dev {0}-eth0 local 192.168.100.21',
                             'ip link set dev vxlan-{1} netns {0}-vrf-{1}',
                             'ip netns exec {0}-vrf-{1} ip li set dev lo up',
                             'ip netns exec {0}-vrf-{1} ip link add name bridge-{1} up type bridge stp_state 0',
                             'ip netns exec {0}-vrf-{1} ip link set dev vxlan-{1} master bridge-{1}',
                             'ip netns exec {0}-vrf-{1} ip link set bridge-{1} up',
                             'ip netns exec {0}-vrf-{1} ip link set vxlan-{1} up']

    router = tgen.gears['r1']
    for cmd in cmds_netns:
        logger.info('cmd to r1: '+cmd);
        output = router.run(cmd.format('r1'))
        logger.info('result: '+output);

    router = tgen.gears['r2']
    for cmd in cmds_vrflite:
        logger.info('cmd to r2: '+cmd.format('r2'));
        output = router.run(cmd.format('r2'))
        logger.info('result: '+output);

    for cmd in cmds_r2:
        logger.info('cmd to r2: '+cmd.format('r2'));
        output = router.run(cmd.format('r2'))
        logger.info('result: '+output);

    router = tgen.gears['r1']
    bridge_id = '101'
    for cmd in cmds_r1_netns_method3:
        logger.info('cmd to r1: '+cmd.format('r1', bridge_id));
        output = router.run(cmd.format('r1', bridge_id))
        logger.info('result: '+output);
    router = tgen.gears['r1']

    for rname, router in router_list.iteritems():
        if rname == 'r1':
            router.load_config(
                TopoRouter.RD_ZEBRA,
                os.path.join(CWD, '{}/zebra.conf'.format(rname)),
                '--vrfwnetns -o vrf0'
            )
        else:
            router.load_config(
                TopoRouter.RD_ZEBRA,
                os.path.join(CWD, '{}/zebra.conf'.format(rname))
            )
        router.load_config(
            TopoRouter.RD_BGP,
            os.path.join(CWD, '{}/bgpd.conf'.format(rname))
        )

    # Initialize all routers.
    tgen.start_router()

def teardown_module(_mod):
    "Teardown the pytest environment"
    tgen = get_topogen()
    cmds_rx_netns = ['ip netns del {}-vrf-101']
    
    router = tgen.gears['r1']
    for cmd in cmds_rx_netns:
        logger.info('cmd to r1: '+cmd.format('r1'));
        output = router.run(cmd.format('r1'))
    tgen.stop_topology()


def test_protocols_convergence():
    """
    Assert that all protocols have converged
    statuses as they depend on it.
    """
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
    output = tgen.gears['r1'].vtysh_cmd('show ip route vrf r1-vrf-101', isjson=False)
    logger.info('==== result from show ip route vrf r1-vrf-101')
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
    # Check IPv4 and IPv6 connectivity between r1 and r2 ( routing vxlan evpn)
    pingrouter = tgen.gears['r1']
    logger.info('Check Ping IPv4 from  R1(r1-vrf-101) to R2(r2-vrf-101 = 192.168.101.41)')
    output = pingrouter.run('ip netns exec r1-vrf-101 ping 192.168.101.41 -f -c 1000')
    logger.info(output)
    if '1000 packets transmitted, 1000 received' not in output:
        assertmsg = 'expected ping IPv4 from R1(r1-vrf-101) to R2(192.168.101.41) should be ok'
        assert 0, assertmsg
    else:
        logger.info('Check Ping IPv4 from R1(r1-vrf-101) to R2(192.168.101.41) OK')

def test_memory_leak():
    "Run the memory leak test and report results."
    tgen = get_topogen()
    if not tgen.is_memleak_enabled():
        pytest.skip('Memory leak test/report is disabled')

    tgen.report_memory_leaks()


if __name__ == '__main__':
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
