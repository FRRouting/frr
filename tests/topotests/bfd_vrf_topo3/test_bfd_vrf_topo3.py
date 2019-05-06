#!/usr/bin/env python

#
# test_bfd_vrf_topo3.py
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
test_bfd_vrf_topo3.py: Test the FRR/Quagga BFD daemon.
"""

import os
import sys
import json
import platform
from functools import partial
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

class BFDTopo(Topo):
    "Test topology builder"
    def build(self, *_args, **_opts):
        "Build function"
        tgen = get_topogen(self)

        # Create 4 routers
        for routern in range(1, 4):
            tgen.add_router('r{}'.format(routern))

        switch = tgen.add_switch('s1')
        switch.add_link(tgen.gears['r1'])
        switch.add_link(tgen.gears['r2'])

        switch = tgen.add_switch('s2')
        switch.add_link(tgen.gears['r2'])
        switch.add_link(tgen.gears['r3'])

        switch = tgen.add_switch('s3')
        switch.add_link(tgen.gears['r3'])

        switch = tgen.add_switch('s4')
        switch.add_link(tgen.gears['r1'])


def setup_module(mod):
    "Sets up the pytest environment"
    global CustomizeVrfWithNetns

    tgen = Topogen(BFDTopo, mod.__name__)
    tgen.start_topology()

    CustomizeVrfWithNetns = True
    option_vrf_mode = os.getenv('VRF_MODE_PARAM', 'netns')
    if option_vrf_mode == 'vrf-lite':
        CustomizeVrfWithNetns = False

    router_list = tgen.routers()

    if CustomizeVrfWithNetns:
        if os.system('ip netns list') != 0:
            return  pytest.skip('Skipping BFD Topo3 VRF NETNS Test. NETNS not available on System')

    krel = platform.release()
    l3mdev_accept = 0
    if topotest.version_cmp(krel, '4.15') >= 0 and \
       topotest.version_cmp(krel, '4.18') <= 0:
        l3mdev_accept = 1

    if topotest.version_cmp(krel, '5.0') >= 0:
        l3mdev_accept = 1

    # in addition to move interfaces to appropriate netns
    # - ipv6 forwarding is enabled for each namespace
    # - ipv6 address are kept after link up / link down operations
    if CustomizeVrfWithNetns:
        logger.info('Testing with VRF Namespace support')
        cmds = ['if [ -e /var/run/netns/{0}-cust1 ] ; then ip netns del {0}-cust1 ; fi',
                'ip netns add {0}-cust1',
                'ip link set dev {0}-eth0 netns {0}-cust1',
                'ip netns exec {0}-cust1 ifconfig {0}-eth0 up',
                'ip link set dev {0}-eth1 netns {0}-cust1',
                'ip netns exec {0}-cust1 ifconfig {0}-eth1 up',
                'ip netns exec {0}-cust1 ip li set dev lo up',
                'ip netns exec {0}-cust1 sysctl net.ipv6.conf.all.forwarding=1',
                'ip netns exec {0}-cust1 sysctl net.ipv6.conf.{0}-eth0.keep_addr_on_down=1',
                'ip netns exec {0}-cust1 sysctl net.ipv6.conf.{0}-eth1.keep_addr_on_down=1']
    else:
        logger.info('setting net.ipv4.tcp_l3mdev_accept={}'.format(l3mdev_accept))
        logger.info('setting net.ipv4.udp_l3mdev_accept={}'.format(l3mdev_accept))
        cmds = ['sysctl -w net.ipv4.tcp_l3mdev_accept={}'.format(l3mdev_accept),
                'sysctl -w net.ipv4.udp_l3mdev_accept={}'.format(l3mdev_accept),
                'ip link add {0}-cust1 type vrf table 10',
                'ip link set dev {0}-cust1 up',
                'ip link set dev {0}-eth0 master {0}-cust1',
                'ip link set dev {0}-eth1 master {0}-cust1',
                'sysctl -w net.ipv6.conf.all.forwarding=1',
                'sysctl net.ipv6.conf.{0}-eth0.keep_addr_on_down=1',
                'sysctl net.ipv6.conf.{0}-eth1.keep_addr_on_down=1']

    for rname, router in router_list.iteritems():
        for cmd in cmds:
            cmd = cmd.format(rname)
            output = tgen.net[rname].cmd(cmd.format(rname))
            logger.info('output: '+output);

    zebra_option = '--vrfwnetns' if CustomizeVrfWithNetns else ''
    for rname, router in router_list.iteritems():
        router.load_config(
            TopoRouter.RD_ZEBRA,
            os.path.join(CWD, '{}/zebra.conf'.format(rname)),
            zebra_option
        )
        router.load_config(
            TopoRouter.RD_BFD,
            os.path.join(CWD, '{}/bfdd.conf'.format(rname))
        )

    # Initialize all routers.
    tgen.start_router()
    # Verify that we are using the proper version and that the BFD
    # daemon exists.
    for router in router_list.values():
        # Check for Version
        if router.has_version('<', '5.1'):
            tgen.set_error('Unsupported FRR version')
            break
    for router in tgen.routers().values():
        output = router.vtysh_cmd('show running-config')
        logger.info('==== {0} show running-config:'.format(router.name))
        logger.info(output)


def teardown_module(_mod):
    "Teardown the pytest environment"
    global CustomizeVrfWithNetns

    tgen = get_topogen()
    if CustomizeVrfWithNetns:
        cmds = ['ip netns exec {0}-cust1 ip link set {0}-eth1 netns 1',
                'ip netns exec {0}-cust1 ip link set {0}-eth0 netns 1',
                'ip netns delete {0}-cust1']
    else:
        cmds = ['ip link set dev {0}-eth1 nomaster',
                'ip link set dev {0}-eth0 nomaster',
                'ip link delete {0}-cust1']

    router_list = tgen.routers()
    for rname, router in router_list.iteritems():
        for cmd in cmds:
            tgen.net[rname].cmd(cmd.format(rname))

    tgen.stop_topology()


def test_bfd_connection():
    "Assert that the BFD peers can find themselves."
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    logger.info('waiting for bfd peers to go up')
    # compare show bfd peers json with expected
    # expected = all peers (4 = 2 IPv4 + 2 IPv6 ) are supposed to be up
    for router in tgen.routers().values():
        logger.info('==== {0} show bfd static route:'.format(router.name))
        output = router.vtysh_cmd('show bfd static route')
        logger.info(output)
        logger.info('==== {0} show bfd peers counters:'.format(router.name))
        output = router.vtysh_cmd('show bfd peers counter')
        logger.info(output)
        json_file = '{}/{}/peers.json'.format(CWD, router.name)
        expected = json.loads(open(json_file).read())

        test_func = partial(topotest.router_json_cmp,
            router, 'show bfd peers json', expected)
        _, result = topotest.run_and_expect(test_func, None, count=8, wait=0.5)
        assertmsg = '"{}" JSON output mismatches'.format(router.name)
        assert result is None, assertmsg

    # expected = static routes check on r1
    router = tgen.gears['r1']

    # expected = static routes ipv4 are present
    logger.info('check route entry ipv4 ok for r1')
    json_file = '{}/{}/show_ip_route.json'.format(CWD, router.name)
    if not os.path.isfile(json_file):
        logger.info('skipping file {}'.format(json_file))
        assert 0, "file {0} not found".format(json_file)
    expected = json.loads(open(json_file).read())
    test_func = partial(topotest.router_json_cmp,
                        router, 'show ip route vrf {0}-cust1 json'.format(router.name), expected)
    _, result = topotest.run_and_expect(test_func, None, count=160,
                                        wait=0.5)
    assertmsg = '"{}" JSON output mismatches'.format(router.name)
    assert result is None, assertmsg

    # expected = static routes ipv6 are present
    logger.info('check route entry ipv6 ok for r1')
    json_file = '{}/{}/show_ipv6_route.json'.format(CWD, router.name)
    if not os.path.isfile(json_file):
        logger.info('skipping file {}'.format(json_file))
        assert 0, "file {0} not found".format(json_file)
    expected = json.loads(open(json_file).read())
    test_func = partial(topotest.router_json_cmp,
                        router, 'show ipv6 route vrf {0}-cust1 json'.format(router.name), expected)
    _, result = topotest.run_and_expect(test_func, None, count=160,
                                        wait=0.5)
    assertmsg = '"{}" JSON output mismatches'.format(router.name)
    assert result is None, assertmsg

def test_bfd_fast_convergence():
    """
    Assert that BFD notices the link down after simulating network
    failure.
    """
    global CustomizeVrfWithNetns

    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    logger.info('waiting for bfd multihop peers to go down')
    # Disable r2-eth1 link.
    netns = 'r2-cust1' if CustomizeVrfWithNetns else None
    tgen.gears['r2'].link_enable('r2-eth1', enabled=False, netns=netns)
    topotest.sleep(5)
    # compare show bfd peers json with expected
    # expected =  2 multihop peers (2 = 1 IPv4 + 1 IPv6 ) are supposed to be down
    # expected =  'show ip route | show ipv6 route' shows the extra static route removed
    router = tgen.gears['r1']
    donna = router.vtysh_cmd('show bfd peers json', isjson=True)
    for peer in donna:
        if peer['peer'] == '192.168.1.1':
            control_expire = 'r1, bfd peer 192.168.1.1, diagnostic different from time expired'
            assert peer['status'] == 'down', "r1, bfd peer 192.168.1.1 not down"
            assert peer['diagnostic'] == 'control detection time expired', control_expire
        if peer['peer'] == '1001:1::1':
            control_expire = 'r1, bfd peer 1001:1::1, diagnostic different from time expired'
            assert peer['status'] == 'down', "r1, bfd peer 1001:1::1 not down"
            assert peer['diagnostic'] == 'control detection time expired', control_expire
    router = tgen.gears['r3']
    donna = router.vtysh_cmd('show bfd peers json', isjson=True)
    for peer in donna:
        control_expire = 'r3, bfd peer {0}, diagnostic different from time expired'.format(peer['peer'])
        assert peer['status'] == 'down', "r3, bfd peer {0} not down".format(peer['peer'])
        assert peer['diagnostic'] == 'control detection time expired', control_expire

    router = tgen.gears['r1']
    logger.info('checking that ipv4 route entry 192.168.3.0 is not present')
    donna = router.vtysh_cmd('show ip route vrf r1-cust1 json', isjson=True)
    if '192.168.3.0/24' in donna.keys():
        assert 0, "r1, route 192.168.3.0/24 present"

    logger.info('checking that ipv6 route entry 1003:1::/96 is not present')
    donna = router.vtysh_cmd('show ipv6 route vrf r1-cust1 json', isjson=True)
    if '1003:1::/96' in donna.keys():
        assert 0, "r1, route 1003:1::/96 present"

    logger.info('waiting for all bfd peers to go down')
    # Disable r2-eth0 link.
    tgen.gears['r2'].link_enable('r2-eth0', enabled=False, netns=netns)
    topotest.sleep(2)
    # compare show bfd peers json with expected
    # expected =  2 other peers (2 = 1 IPv4 + 1 IPv6 ) are supposed to be down
    router = tgen.gears['r1']
    donna = router.vtysh_cmd('show bfd peers json', isjson=True)
    for peer in donna:
        if peer['peer'] == '192.168.0.2':
            assert peer['status'] == 'down', "r1, bfd peer 192.168.0.2 not down"
        if peer['peer'] == '1000:1::2':
            assert peer['status'] == 'down', "r1, bfd peer 1000:1::2 not down"

    router = tgen.gears['r2']
    for peer in donna:
        control_expire = 'r2, bfd peer {0}, diagnostic different from time expired'.format(peer['peer'])
        assert peer['status'] == 'down', 'r2, bfd peer {0} not down'.format(peer['peer'])
        assert peer['diagnostic'] == 'control detection time expired', control_expire
                           
    router = tgen.gears['r3']
    for peer in donna:
        control_expire = 'r3, bfd peer {0}, diagnostic different from time expired'.format(peer['peer'])
        assert peer['status'] == 'down', 'r3, bfd peer {0} not down'.format(peer['peer'])
        assert peer['diagnostic'] == 'control detection time expired', control_expire

    for router in tgen.routers().values():
        logger.info('==== {0} show bfd static route:'.format(router.name))
        output = router.vtysh_cmd('show bfd static route')
        logger.info(output)
        logger.info('==== {0} show bfd peers:'.format(router.name))
        output = router.vtysh_cmd('show bfd peers')
        logger.info(output)
        logger.info('==== {0} show bfd peers counter:'.format(router.name))
        output = router.vtysh_cmd('show bfd peers counter')
        logger.info(output)
        
    logger.info('waiting for bfd singlehop peers to go up again')
    # Enable r2-eth0 link.
    # compare show bfd peers json with expected
    # expected =  2 singlehop peers (2 = 1 IPv4 + 1 IPv6 ) are supposed to be up
    # expected =  2 multihop peers (2 = 1 IPv4 + 1 IPv6 ) are supposed to be up
    # expected =  'show ip route | show ipv6 route' shows the extra static route
    tgen.gears['r2'].link_enable('r2-eth0', enabled=True, netns=netns)
    tgen.gears['r2'].link_enable('r2-eth1', enabled=True, netns=netns)
    topotest.sleep(5)
    test_bfd_connection()

def test_memory_leak():
    "Run the memory leak test and report results."
    tgen = get_topogen()
    if not tgen.is_memleak_enabled():
        pytest.skip('Memory leak test/report is disabled')

    tgen.report_memory_leaks()


if __name__ == '__main__':
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
