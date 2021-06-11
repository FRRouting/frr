#!/usr/bin/env python

#
# test_nhrp_topo.py
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
test_nhrp_topo.py: Test the FRR/Quagga NHRP daemon
"""

import os
import sys
import json
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


class NHRPTopo(Topo):
    "Test topology builder"
    def build(self, *_args, **_opts):
        "Build function"
        tgen = get_topogen(self)

        # Create 3 routers.
        for routern in range(1, 4):
            tgen.add_router('r{}'.format(routern))

        switch = tgen.add_switch('s1')
        switch.add_link(tgen.gears['r1'])
        switch.add_link(tgen.gears['r3'])
        switch = tgen.add_switch('s2')
        switch.add_link(tgen.gears['r2'])
        switch.add_link(tgen.gears['r3'])
        switch = tgen.add_switch('s3')
        switch.add_link(tgen.gears['r2'])
        switch = tgen.add_switch('s4')
        switch.add_link(tgen.gears['r1'])


def _populate_iface():
    tgen = get_topogen()
    cmds_tot_hub = ['ip tunnel add {0}-gre0 mode gre ttl 64 key 42 dev {0}-eth0 local 10.2.1.{1} remote 0.0.0.0',
                    'ip link set dev {0}-gre0 up',
                    'echo 0 > /proc/sys/net/ipv4/ip_forward_use_pmtu',
                    'echo 1 > /proc/sys/net/ipv6/conf/{0}-eth0/disable_ipv6',
                    'echo 1 > /proc/sys/net/ipv6/conf/{0}-gre0/disable_ipv6']

    cmds_tot = ['ip tunnel add {0}-gre0 mode gre ttl 64 key 42 dev {0}-eth0 local 10.1.1.{1} remote 0.0.0.0',
                'ip link set dev {0}-gre0 up',
                'echo 0 > /proc/sys/net/ipv4/ip_forward_use_pmtu',
                'echo 1 > /proc/sys/net/ipv6/conf/{0}-eth0/disable_ipv6',
                'echo 1 > /proc/sys/net/ipv6/conf/{0}-gre0/disable_ipv6']

    for cmd in cmds_tot_hub:
        input = cmd.format('r2', '2')
        logger.info('input: '+cmd)
        output = tgen.net['r2'].cmd(cmd.format('r2', '2'))
        logger.info('output: '+output);

    for cmd in cmds_tot:
        input = cmd.format('r1', '1')
        logger.info('input: '+cmd)
        output = tgen.net['r1'].cmd(cmd.format('r1', '1'))
        logger.info('output: '+output);


def setup_module(mod):
    "Sets up the pytest environment"
    tgen = Topogen(NHRPTopo, mod.__name__)
    tgen.start_topology()

    router_list = tgen.routers()
    _populate_iface()
        
    for rname, router in router_list.iteritems():
        router.load_config(
            TopoRouter.RD_ZEBRA,
            os.path.join(CWD, '{}/zebra.conf'.format(rname)),
        )
        if rname in ('r1', 'r2'):
            router.load_config(
                TopoRouter.RD_NHRP,
                os.path.join(CWD, '{}/nhrpd.conf'.format(rname))
            )

    # Initialize all routers.
    logger.info('Launching BGP, NHRP')
    for name in router_list:
        router = tgen.gears[name]
        router.start()


def teardown_module(_mod):
    "Teardown the pytest environment"
    tgen = get_topogen()
    tgen.stop_topology()


def test_protocols_convergence():
    """
    Assert that all protocols have converged before checking for the NHRP
    statuses as they depend on it.
    """
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    # Check IPv4 routing tables.
    logger.info("Checking NHRP cache and IPv4 routes for convergence")
    router_list = tgen.routers()

    for rname, router in router_list.iteritems():
        if rname == 'r3':
            continue

        json_file = '{}/{}/nhrp4_cache.json'.format(CWD, router.name)
        if not os.path.isfile(json_file):
            logger.info('skipping file {}'.format(json_file))
            continue

        expected = json.loads(open(json_file).read())
        test_func = partial(topotest.router_json_cmp,
                            router, 'show ip nhrp cache json', expected)
        _, result = topotest.run_and_expect(test_func, None, count=40,
                                            wait=0.5)

        output = router.vtysh_cmd('show ip nhrp cache')
        logger.info(output)

        assertmsg = '"{}" JSON output mismatches'.format(router.name)
        assert result is None, assertmsg

    for rname, router in router_list.iteritems():
        if rname == 'r3':
            continue

        json_file = '{}/{}/nhrp_route4.json'.format(CWD, router.name)
        if not os.path.isfile(json_file):
            logger.info('skipping file {}'.format(json_file))
            continue

        expected = json.loads(open(json_file).read())
        test_func = partial(topotest.router_json_cmp,
                            router, 'show ip route nhrp json', expected)
        _, result = topotest.run_and_expect(test_func, None, count=40,
                                            wait=0.5)

        output = router.vtysh_cmd('show ip route nhrp')
        logger.info(output)

        assertmsg = '"{}" JSON output mismatches'.format(router.name)
        assert result is None, assertmsg

    for rname, router in router_list.iteritems():
        if rname == 'r3':
            continue
        logger.info('Dump neighbor information on {}-gre0'.format(rname))
        output = router.run('ip neigh show')
        logger.info(output)


def test_nhrp_connection():
    "Assert that the NHRP peers can find themselves."
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    pingrouter = tgen.gears['r1']
    logger.info('Check Ping IPv4 from  R1 to R2 = 10.255.255.2)')
    output = pingrouter.run('ping 10.255.255.2 -f -c 1000')
    logger.info(output)
    if '1000 packets transmitted, 1000 received' not in output:
        assertmsg = 'expected ping IPv4 from R1 to R2 should be ok'
        assert 0, assertmsg
    else:
        logger.info('Check Ping IPv4 from R1 to R2 OK')


def test_memory_leak():
    "Run the memory leak test and report results."
    tgen = get_topogen()
    if not tgen.is_memleak_enabled():
        pytest.skip('Memory leak test/report is disabled')

    tgen.report_memory_leaks()


if __name__ == '__main__':
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
