#!/usr/bin/env python

#
# test_bfd_vrf_topo2.py
# Part of NetDEF Topology Tests
#
# Copyright (c) 2019 by
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
test_bfd_vrf_topo2.py: Test the FRR/Quagga BFD daemon with multihop and BGP
unnumbered.
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

        # Create 4 routers.
        for routern in range(1, 5):
            tgen.add_router('r{}'.format(routern))

        switch = tgen.add_switch('s1')
        switch.add_link(tgen.gears['r1'])
        switch.add_link(tgen.gears['r2'])

        switch = tgen.add_switch('s2')
        switch.add_link(tgen.gears['r2'])
        switch.add_link(tgen.gears['r3'])

        switch = tgen.add_switch('s3')
        switch.add_link(tgen.gears['r2'])
        switch.add_link(tgen.gears['r4'])


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
            return  pytest.skip('Skipping BFD Topo2 VRF NETNS Test. NETNS not available on System')

    krel = platform.release()
    l3mdev_accept = 0
    if topotest.version_cmp(krel, '4.15') >= 0 and \
       topotest.version_cmp(krel, '4.18') <= 0:
        l3mdev_accept = 1

    if topotest.version_cmp(krel, '5.0') >= 0:
        l3mdev_accept = 1

    if CustomizeVrfWithNetns:
        logger.info('Testing with VRF Namespace support')
        cmds = ['if [ -e /var/run/netns/{0}-cust1 ] ; then ip netns del {0}-cust1 ; fi',
                'ip netns add {0}-cust1',
                'ip link set dev {0}-eth0 netns {0}-cust1',
                'ip netns exec {0}-cust1 ifconfig {0}-eth0 up',
                'ip netns exec {0}-cust1 ip link set dev lo up',
                'ip netns exec {0}-cust1 sysctl -w net.ipv6.conf.all.forwarding=1',
                'ip netns exec {0}-cust1 ip link add loop1 type dummy',
                'ip netns exec {0}-cust1 ip link set dev loop1 up']

        cmds2 = ['ip link set dev {0}-eth1 netns {0}-cust1',
                 'ip netns exec {0}-cust1 ifconfig {0}-eth1 up',
                 'ip link set dev {0}-eth2 netns {0}-cust1',
                 'ip netns exec {0}-cust1 ifconfig {0}-eth2 up']
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
                'sysctl net.ipv6.conf.{0}-eth1.keep_addr_on_down=1',
                'ip link add loop1 type dummy',
                'ip link set dev loop1 up',
                'ip link set dev loop1 master {0}-cust1']

        cmds2 = ['ip link set dev {0}-eth1 master {0}-cust1',
                 'ip link set dev {0}-eth2 master {0}-cust1']

    for rname, router in router_list.iteritems():
        # create VRF rx-cust1 and link rx-eth0 to rx-cust1
        for cmd in cmds:
            output = tgen.net[rname].cmd(cmd.format(rname))
        if rname == 'r2':
            for cmd in cmds2:
                output = tgen.net[rname].cmd(cmd.format(rname))

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
        router.load_config(
            TopoRouter.RD_BGP,
            os.path.join(CWD, '{}/bgpd.conf'.format(rname))
        )
        router.load_config(
            TopoRouter.RD_OSPF,
            os.path.join(CWD, '{}/ospfd.conf'.format(rname))
        )
        router.load_config(
            TopoRouter.RD_OSPF6,
            os.path.join(CWD, '{}/ospf6d.conf'.format(rname))
        )

    # Initialize all routers.
    tgen.start_router()


def teardown_module(_mod):
    "Teardown the pytest environment"
    global CustomizeVrfWithNetns

    tgen = get_topogen()

    if CustomizeVrfWithNetns:
        cmds = ['ip netns exec {0}-cust1 ip link set {0}-eth0 netns 1',
                'ip netns exec {0}-cust1 ip link set loop1 netns 1',
                'ip netns delete {0}-cust1']
        cmds2 = ['ip netns exec {0}-cust1 ip link set {0}-eth1 netns 1',
                 'ip netns exec {0}-cust2 ip link set {0}-eth1 netns 1']
    else:
        cmds = ['ip link set dev {0}-eth0 nomaster',
                'ip link set dev loop1 nomaster',
                'ip link delete {0}-cust1']
        cmds2 = ['ip link set {0}-eth1 nomaster',
                 'ip link set {0}-eth2 nomaster']

    router_list = tgen.routers()
    for rname, router in router_list.iteritems():
        if rname == 'r2':
            for cmd in cmds2:
                tgen.net[rname].cmd(cmd.format(rname))
        for cmd in cmds:
            tgen.net[rname].cmd(cmd.format(rname))
    tgen.stop_topology()


def test_protocols_convergence():
    """
    Assert that all protocols have converged before checking for the BFD
    statuses as they depend on it.
    """
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    # Check IPv4 routing tables.
    logger.info("Checking IPv4 routes for convergence")
    for router in tgen.routers().values():
        if router.name == 'r4':
            logger.info('skipping ipv4 check for {}'.format(router.name))
            continue
        json_file = '{}/{}/ipv4_routes.json'.format(CWD, router.name)
        if not os.path.isfile(json_file):
            logger.info('skipping file {}'.format(json_file))
            continue

        expected = json.loads(open(json_file).read())
        test_func = partial(topotest.router_json_cmp,
                            router, 'show ip route vrf {}-cust1 json'.format(router.name), expected)
        _, result = topotest.run_and_expect(test_func, None, count=40, wait=2)
        assertmsg = '"{}" JSON output mismatches'.format(router.name)
        assert result is None, assertmsg

    # Check IPv6 routing tables.
    logger.info("Checking IPv6 routes for convergence")
    for router in tgen.routers().values():
        json_file = '{}/{}/ipv6_routes.json'.format(CWD, router.name)
        if not os.path.isfile(json_file):
            logger.info('skipping file {}'.format(json_file))
            continue

        expected = json.loads(open(json_file).read())
        test_func = partial(topotest.router_json_cmp,
                            router, 'show ipv6 route vrf {}-cust1 json'.format(router.name), expected)
        _, result = topotest.run_and_expect(test_func, None, count=40, wait=2)
        assertmsg = '"{}" JSON output mismatches'.format(router.name)
        assert result is None, assertmsg


def test_bfd_connection():
    "Assert that the BFD peers can find themselves."
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    logger.info('waiting for bfd peers to go up')

    for router in tgen.routers().values():
        json_file = '{}/{}/peers.json'.format(CWD, router.name)
        expected = json.loads(open(json_file).read())

        test_func = partial(topotest.router_json_cmp,
                            router, 'show bfd peers json', expected)
        _, result = topotest.run_and_expect(test_func, None, count=8, wait=0.5)
        assertmsg = '"{}" JSON output mismatches'.format(router.name)
        assert result is None, assertmsg


def test_memory_leak():
    "Run the memory leak test and report results."
    tgen = get_topogen()
    if not tgen.is_memleak_enabled():
        pytest.skip('Memory leak test/report is disabled')

    tgen.report_memory_leaks()


if __name__ == '__main__':
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
