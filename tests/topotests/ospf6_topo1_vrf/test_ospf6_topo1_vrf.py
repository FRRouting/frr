#!/usr/bin/env python

#
# test_ospf6_topo1_vrf.py
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
test_ospf6_topo1_vrf.py: Test the FRR/Quagga OSPF6 routing daemon.
"""

import os
import re
import sys
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

class OSPF6TopoVrf(Topo):
    "Test topology builder"
    def build(self, *_args, **_opts):
        "Build function"
        tgen = get_topogen(self)

        # Create 3 routers
        for routern in range(1, 4):
            tgen.add_router('r{}'.format(routern))

        # Create a empty network for router 1
        switch = tgen.add_switch('s1')
        switch.add_link(tgen.gears['r1'])

        # Create a empty network for router 2
        switch = tgen.add_switch('s2')
        switch.add_link(tgen.gears['r2'])

        # Interconect router 1, 2 and 3
        switch = tgen.add_switch('s3')
        switch.add_link(tgen.gears['r1'])
        switch.add_link(tgen.gears['r2'])
        switch.add_link(tgen.gears['r3'])

        # Create empty netowrk for router3
        switch = tgen.add_switch('s4')
        switch.add_link(tgen.gears['r3'])


def setup_module(mod):
    "Sets up the pytest environment"
    tgen = Topogen(OSPF6TopoVrf, mod.__name__)
    tgen.start_topology()

    router_list = tgen.routers()

    # check for zebra capability
    for rname, router in router_list.iteritems():
        if router.check_capability(
                TopoRouter.RD_ZEBRA,
                '--vrfwnetns'
        ) == False:
            return  pytest.skip('Skipping OSPF6 VRF NETNS feature. VRF NETNS backend not available on FRR')

    if os.system('ip netns list') != 0:
        return  pytest.skip('Skipping OSPF6 VRF NETNS Test. NETNS not available on System')

    logger.info('Testing with VRF Namespace support')

    cmds = ['if [ -e /var/run/netns/{0}-cust1 ] ; then ip netns del {0}-cust1 ; fi',
            'ip netns add {0}-cust1',
            'ip link set dev {0}-eth0 netns {0}-cust1',
            'ip netns exec {0}-cust1 ifconfig {0}-eth0 up',
            'ip link set dev {0}-eth1 netns {0}-cust1',
            'ip netns exec {0}-cust1 ifconfig {0}-eth1 up']

    for rname, router in router_list.iteritems():

        # create VRF rx-cust1 and link rx-eth0 to rx-cust1
        for cmd in cmds:
            output = tgen.net[rname].cmd(cmd.format(rname))

        router.load_config(
            TopoRouter.RD_ZEBRA,
            os.path.join(CWD, '{}/zebra.conf'.format(rname)),
            param = '--vrfwnetns'
        )
        router.load_config(
            TopoRouter.RD_OSPF6,
            os.path.join(CWD, '{}/ospf6d.conf'.format(rname)),
            param = None
        )

    # Initialize all routers.
    tgen.start_router()

def teardown_module(mod):
    "Teardown the pytest environment"
    tgen = get_topogen()

    # move back rx-eth0 to default VRF
    # delete rx-vrf
    cmds = ['ip netns exec {0}-cust1 ip link set {0}-eth0 netns 1',
            'ip netns exec {0}-cust1 ip link set {0}-eth1 netns 1',
            'ip netns delete {0}-cust1']
        
    router_list = tgen.routers()
    for rname, router in router_list.iteritems():
        for cmd in cmds:
            tgen.net[rname].cmd(cmd.format(rname))
    tgen.stop_topology()

# Shared test function to validate expected output.
def compare_show_ipv6_ospf6_vrf(rname, expected):
    """
    Calls 'show ipv6 ospf6 route' for router `rname` in vrf [rname]-cust1
    and compare the obtained result with the expected output.
    """
    tgen = get_topogen()
    if tgen.gears[rname].has_version('<', '4.0') == True:
        return
    current = tgen.gears[rname].vtysh_cmd('show ipv6 ospf6 vrf {}-cust1 route'.format(rname))
    current = re.sub(r" [0-2][0-9]:[0-5][0-9]:[0-5][0-9]", " XX:XX:XX", current)
    current = re.sub(r" fe80::[0-9a-f:]+", " fe80::XXXX:XXXX:XXXX:XXXX", current)
    current = topotest.normalize_text(current)
    ret = topotest.difflines(current, expected,
                              title1="Current output",
                              title2="Expected output")
    return ret

def remove_fe8064_line(output):
    outp = ''
    for i in output.splitlines():
        if 'fe80::/64' not in i:
            outp += i + '\n'
    return outp
    
def compare_show_ipv6_route_vrf(rname, expected):
    """
    Calls 'show ipv6 route vrf [rname]-cust1' for router `rname`
    and compare the obtained result with the expected output.
    """
    tgen = get_topogen()
    if tgen.gears[rname].has_version('<', '4.0') == True:
        return
    current = topotest.ip6_route_zebra(tgen.gears[rname], '{0}-cust1'.format(rname))
    current = remove_fe8064_line(current)
    current = topotest.normalize_text(current)
    ret = topotest.difflines(current, expected,
                             title1="Current output",
                             title2="Expected output")
    return ret

def test_ospf6_convergence():
    "Test OSPF6 daemon convergence"
    tgen = get_topogen()

    for rname, router in tgen.routers().iteritems():
        if tgen.gears[rname].has_version('<', '4.0') == True:
            return

    if tgen.routers_have_failure():
        pytest.skip('skipped because of router(s) failure')
    #comment out
    #tgen.mininet_cli()
    for rnum in range(1, 4):
        router = 'r{}'.format(rnum)

        logger.info('Waiting for router "%s" convergence', router)

        # Load expected results from the command
        reffile = os.path.join(CWD, '{}/ospf6route.txt'.format(router))
        expected = open(reffile).read()
        expected = topotest.normalize_text(expected)
        # Run test function until we get an result. Wait at most 60 seconds.
        test_func = partial(compare_show_ipv6_ospf6_vrf, router, expected)
        result, diff = topotest.run_and_expect(test_func, '',
                                               count=25, wait=3)
        assert result, 'OSPF6 did not converge on {}:\n{}'.format(router, diff)

def test_ospf6_kernel_route():
    "Test OSPF6 kernel route installation"
    tgen = get_topogen()
    for rname, router in tgen.routers().iteritems():
        if tgen.gears[rname].has_version('<', '4.0') == True:
            return
    if tgen.routers_have_failure():
        pytest.skip('skipped because of router(s) failure')

    rlist = tgen.routers().values()
    for router in rlist:
        logger.info('Checking OSPF6 IPv6 kernel routes in "%s"', router.name)
        str='{0}-cust1'.format(router.name)
        reffile = os.path.join(CWD, '{}/zebraroute.txt'.format(router.name))
        expected = open(reffile).read()
        expected = topotest.normalize_text(expected)
        # Run test function until we get an result. Wait at most 60 seconds.
        test_func = partial(compare_show_ipv6_route_vrf, router.name, expected)
        result, diff = topotest.run_and_expect(test_func, '',
                                               count=25, wait=3)
        assert result, 'OSPF IPv6 route mismatch in router "{}"'.format(router.name, diff)

def test_ospf6_link_down():
    "Test OSPF6 convergence after a link goes down"
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip('skipped because of router(s) failure')

    # Simulate a network down event on router3 switch3 interface.
    router3 = tgen.gears['r3']
    topotest.interface_set_status(router3, 'r3-eth0', ifaceaction=False, vrf_name='r3-cust1')
    #tgen.mininet_cli()
    # Expect convergence on all routers
    for rnum in range(1, 4):
        router = 'r{}'.format(rnum)
        logger.info('Waiting for router "%s" convergence after link failure', router)
        # Load expected results from the command
        reffile = os.path.join(CWD, '{}/ospf6route_down.txt'.format(router))
        expected = open(reffile).read()
        expected = topotest.normalize_text(expected)

        # Run test function until we get an result. Wait at most 60 seconds.
        test_func = partial(compare_show_ipv6_ospf6_vrf, router, expected)
        result, diff = topotest.run_and_expect(test_func, '',
                                               count=25, wait=3)
        assert result, 'OSPF6 did not converge on {}:\n{}'.format(router, diff)

def test_ospf6_link_down_kernel_route():
    "Test OSPF6 kernel route installation"
    tgen = get_topogen()
    for rname, router in tgen.routers().iteritems():
        if tgen.gears[rname].has_version('<', '4.0') == True:
            return
    if tgen.routers_have_failure():
        pytest.skip('skipped because of router(s) failure')

    rlist = tgen.routers().values()
    for router in rlist:
        logger.info('Checking OSPF6 IPv6 kernel routes in "%s" after link down', router.name)

        str='{0}-cust1'.format(router.name)
        reffile = os.path.join(CWD, '{}/zebraroutedown.txt'.format(router.name))
        expected = open(reffile).read()
        expected = topotest.normalize_text(expected)
        # Run test function until we get an result. Wait at most 60 seconds.
        test_func = partial(compare_show_ipv6_route_vrf, router.name, expected)
        result, diff = topotest.run_and_expect(test_func, '',
                                               count=25, wait=3)
        assert result, 'OSPF6 IPv6 route mismatch in router "{}" after link down'.format(router.name, diff)

def test_memory_leak():
    "Run the memory leak test and report results."
    tgen = get_topogen()
    if not tgen.is_memleak_enabled():
        pytest.skip('Memory leak test/report is disabled')

    tgen.report_memory_leaks()

if __name__ == '__main__':
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
