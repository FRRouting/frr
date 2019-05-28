#!/usr/bin/env python

#
# test_bfd_mpath_topo5.py
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
test_bfd_mpath_topo5.py: Test the FRR/Quagga BFD daemon.
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

class BFDTopo(Topo):
    "Test topology builder"
    def build(self, *_args, **_opts):
        "Build function"
        tgen = get_topogen(self)

        # Create 4 routers
        for routern in range(1, 5):
            tgen.add_router('r{}'.format(routern))

        switch = tgen.add_switch('s1')
        switch.add_link(tgen.gears['r1'])
        switch.add_link(tgen.gears['r2'])

        switch = tgen.add_switch('s2')
        switch.add_link(tgen.gears['r2'])
        switch.add_link(tgen.gears['r3'])
        switch.add_link(tgen.gears['r4'])

        switch = tgen.add_switch('s3')
        switch.add_link(tgen.gears['r3'])

        switch = tgen.add_switch('s4')
        switch.add_link(tgen.gears['r1'])

        switch = tgen.add_switch('s5')
        switch.add_link(tgen.gears['r1'])
        switch.add_link(tgen.gears['r4'])
        
def setup_module(mod):
    "Sets up the pytest environment"
    tgen = Topogen(BFDTopo, mod.__name__)
    tgen.start_topology()

    router_list = tgen.routers()

    # - ipv6 forwarding is enabled
    # - ipv6 address are kept after link up / link down operations
    cmds = ['sysctl net.ipv6.conf.all.forwarding=1',
            'sysctl net.ipv6.conf.{0}-eth0.keep_addr_on_down=1',
            'sysctl net.ipv6.conf.{0}-eth1.keep_addr_on_down=1']

    cmds2 = ['ifconfig {0}-eth2 up',
            'sysctl net.ipv6.conf.{0}-eth2.keep_addr_on_down=1']
    cmds3 = ['ip link add loop1 type dummy',
             'ifconfig loop1 up',
             'sysctl net.ipv6.conf.loop1.keep_addr_on_down=1',
             'ip link add loop2 type dummy',
             'ifconfig loop2 up',
             'sysctl net.ipv6.conf.loop2.keep_addr_on_down=1']
    for rname, router in router_list.iteritems():
        for cmd in cmds:
            cmd = cmd.format(rname)
            output = tgen.net[rname].cmd(cmd.format(rname))
            logger.info('output: '+output);
        if rname == 'r1':
            for cmd in cmds2:
                cmd = cmd.format(rname)
                output = tgen.net[rname].cmd(cmd.format(rname))
                logger.info('output: '+output);
        if rname == 'r3':
            for cmd in cmds3:
                cmd = cmd.format(rname)
                output = tgen.net[rname].cmd(cmd.format(rname))
                logger.info('output: '+output);

    for rname, router in router_list.iteritems():
        router.load_config(
            TopoRouter.RD_ZEBRA,
            os.path.join(CWD, '{}/zebra.conf'.format(rname))
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


def teardown_module(_mod):
    "Teardown the pytest environment"
    tgen = get_topogen()

    tgen.stop_topology()


def check_bfd_ipv6_nominal_state():
    tgen = get_topogen()

    # check bfd entries
    donna = tgen.gears['r1'].vtysh_cmd('show bfd peer 192.168.1.3 multihop json', isjson=True)
    assert donna['peer'] == '192.168.1.3', "r1, 192.168.1.3, bfd entry not present"
    assert donna['local'] == '192.168.5.1', "r1, 192.168.1.3, bfd local address not 192.168.5.1"
    assert donna['status'] == 'up', "r1, 192.168.1.3, bfd status not up"
    assert donna['diagnostic'] == 'ok', "r1, 192.168.1.3, bfd diagnostic not ok"
    donna = tgen.gears['r1'].vtysh_cmd('show bfd peer 1001:1::3 multihop json', isjson=True)
    assert donna['peer'] == '1001:1::3', "r1, 1001:1::3, bfd entry not present"
    assert donna['local'] == '1005:1::1', "r1, 1001:1::3, bfd local address not 1005:1::1"
    assert donna['status'] == 'up', "r1, 1001:1::3, bfd status not up"
    assert donna['diagnostic'] == 'ok', "r1, 1001:1::3, bfd diagnostic not ok"

    # check routing entries
    donna = tgen.gears['r1'].vtysh_cmd('show ip route 192.168.3.0/24 json', isjson=True)
    if '192.168.3.0/24' not in donna.keys():
        assert 0, "r1, route 192.168.3.0/24 not present"
    routeid = donna['192.168.3.0/24']
    if 'selected' not in routeid[0].keys():
        assert 0, "r1, route 192.168.3.0/24 found in BGP RIB is not selected"
    assert routeid[0]["selected"] == True, "r1, route 192.168.3.0/24 not set to true"
    if 'nexthops' not in routeid[0].keys():
        assert 0, "r1, route 192.168.3.0/24 does not have nexthops"
    nhop = routeid[0]["nexthops"]
    if nhop[1]['ip'] == "192.168.5.4":
        assert nhop[1]['interfaceName'] == "r1-eth2", "r1, nh 192.168.5.3 does not use r1-eth2"
    else:
        if nhop[0]['ip'] == "192.168.5.4":
            assert nhop[0]['interfaceName'] == "r1-eth2", "r1, nh 192.168.5.3 does not use r1-eth2"
        else:
            assert 0, "r1, route 192.168.3.0/24, no valid nexthop found"
    donna = tgen.gears['r1'].vtysh_cmd('show ipv6 route 1003:1::/96 json', isjson=True)
    if '1003:1::/96' not in donna.keys():
        assert 0, "r1, route 1003:1::/96 not present"
    routeid = donna['1003:1::/96']
    if 'selected' not in routeid[0].keys():
        assert 0, "r1, route 1003:1::/96 found in BGP RIB is not selected"
    assert routeid[0]["selected"] == True, "r1, route 1003:1::/96 not set to true"
    if 'nexthops' not in routeid[0].keys():
        assert 0, "r1, route 1003:1::/96 does not have nexthops"
    nhop = routeid[0]["nexthops"]
    if nhop[1]['ip'] == "1005:1::4":
        assert nhop[1]['interfaceName'] == "r1-eth2", "r1, nh 1003:1::/96 does not use r1-eth2"
    else:
        if nhop[0]['ip'] == "1005:1::4":
            assert nhop[0]['interfaceName'] == "r1-eth2", "r1, nh 1003:1::/96 does not use r1-eth2"
        else:
            assert 0, "r1, route 1003:1::/96, no valid nexthop found"
    
def test_bfd_connection():
    "Assert that the BFD peers can find themselves."
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    topotest.sleep(5, 'waiting that BFD initialises')
    output = tgen.gears['r1'].vtysh_cmd('show running-config', isjson=False)
    logger.info('==== result from show running-config')
    logger.info(output)
    output = tgen.gears['r1'].vtysh_cmd('show bfd peer 192.168.1.3 multihop', isjson=False)
    logger.info('==== result from show bfd peer 192.168.1.3')
    logger.info(output)
    output = tgen.gears['r1'].vtysh_cmd('show bfd peer 1001:1::3 multihop', isjson=False)
    logger.info('==== result from show bfd peer 1001:1::3 multihop')
    logger.info(output)
    logger.info('==== result from show ip route and show ipv6 route')
    output = tgen.gears['r1'].vtysh_cmd('show ip route', isjson=False)
    logger.info(output)
    output = tgen.gears['r1'].vtysh_cmd('show ipv6 route', isjson=False)
    logger.info(output)
    check_bfd_ipv6_nominal_state()

def test_bfd_fast_convergence():
    """
    Assert that BFD notices the link down after simulating network
    failure.
    """
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    logger.info('=========== disabling r4 device')
    logger.info('waiting for bfd multihop peers to go down')
    # 
    # Disable r4-eth0 and r4-eth1 link.
    tgen.gears['r4'].link_enable('r4-eth1', enabled=False)
    tgen.gears['r4'].link_enable('r4-eth0', enabled=False)
    topotest.sleep(5, 'waiting that BFD event propagates')
    output = tgen.gears['r1'].vtysh_cmd('show bfd peer 192.168.1.3 multihop', isjson=False)
    logger.info('==== result from show bfd peer 192.168.1.3 multihop')
    logger.info(output)
    output = tgen.gears['r1'].vtysh_cmd('show bfd peer 1001:1::3 multihop', isjson=False)
    logger.info('==== result from show bfd peer 1001:1::3 multihop')
    logger.info(output)
    logger.info('==== result from show ip route and show ipv6 route')
    output = tgen.gears['r1'].vtysh_cmd('show ip route', isjson=False)
    logger.info(output)
    output = tgen.gears['r1'].vtysh_cmd('show ipv6 route', isjson=False)
    logger.info(output)

    # check bfd entries
    donna = tgen.gears['r1'].vtysh_cmd('show bfd peer 192.168.1.3 multihop json', isjson=True)
    assert donna['peer'] == '192.168.1.3', "r1, 192.168.1.3, bfd entry not present"
    assert donna['local'] == '192.168.0.1', "r1, 192.168.1.3, bfd local address not 192.168.0.1"
    assert donna['status'] == 'up', "r1, 192.168.1.3, bfd status not up"
    assert donna['diagnostic'] == 'ok', "r1, 192.168.1.3, bfd diagnostic not ok"
    donna = tgen.gears['r1'].vtysh_cmd('show bfd peer 1001:1::3 multihop json', isjson=True)
    assert donna['peer'] == '1001:1::3', "r1, 1001:1::3, bfd entry not present"
    assert donna['local'] == '1000:1::1', "r1, 1000:1::1, bfd local address not 1000:1::1"
    assert donna['status'] == 'up', "r1, 1001:1::3, bfd status not up"
    assert donna['diagnostic'] == 'ok', "r1, 1001:1::3, bfd diagnostic not ok"

    # check routing entries
    donna = tgen.gears['r1'].vtysh_cmd('show ip route 192.168.3.0/24 json', isjson=True)
    if '192.168.3.0/24' not in donna.keys():
        assert 0, "r1, route 192.168.3.0/24 not present"
    routeid = donna['192.168.3.0/24']
    if 'selected' not in routeid[0].keys():
        assert 0, "r1, route 192.168.3.0/24 found in BGP RIB is not selected"
    assert routeid[0]["selected"] == True, "r1, route 192.168.3.0/24 not set to true"
    if 'nexthops' not in routeid[0].keys():
        assert 0, "r1, route 192.168.3.0/24 does not have nexthops"
    nhop = routeid[0]["nexthops"]
    if nhop[1]['ip'] == "192.168.0.2":
        assert nhop[1]['interfaceName'] == "r1-eth0", "r1, nh 192.168.0.2 does not use r1-eth0"
    else:
        if nhop[0]['ip'] == "192.168.0.2":
            assert nhop[0]['interfaceName'] == "r1-eth2", "r1, nh 192.168.0.2 does not use r1-eth0"
        else:
            assert 0, "r1, route 192.168.3.0/24, no valid nexthop found"
    donna = tgen.gears['r1'].vtysh_cmd('show ipv6 route 1003:1::/96 json', isjson=True)
    if '1003:1::/96' not in donna.keys():
        assert 0, "r1, route 1003:1::/96 not present"
    routeid = donna['1003:1::/96']
    if 'selected' not in routeid[0].keys():
        assert 0, "r1, route 1003:1::/96 found in BGP RIB is not selected"
    assert routeid[0]["selected"] == True, "r1, route 1003:1::/96 not set to true"
    if 'nexthops' not in routeid[0].keys():
        assert 0, "r1, route 1003:1::/96 does not have nexthops"
    nhop = routeid[0]["nexthops"]
    if nhop[1]['ip'] == "1000:1::2":
        assert nhop[1]['interfaceName'] == "r1-eth0", "r1, nh 1003:1::/96 does not use r1-eth0"
    else:
        if nhop[0]['ip'] == "1000:1::2":
            assert nhop[0]['interfaceName'] == "r1-eth0", "r1, nh 1003:1::/96 does not use r1-eth0"
        else:
            assert 0, "r1, route 1003:1::/96, no valid nexthop found"
    
    # expected = 2 mhop sessions should use 192.168.0.2 as gateway
    # as well as r1-eth0 interface
    logger.info('=========== enabling r4 device')
    logger.info('waiting for bfd multihop peers to go up again')
    tgen.gears['r4'].link_enable('r4-eth0', enabled=True)
    tgen.gears['r4'].link_enable('r4-eth1', enabled=True)
    topotest.sleep(5, 'waiting that BFD event propagates')
    output = tgen.gears['r1'].vtysh_cmd('show bfd peer 192.168.1.3 multihop', isjson=False)
    logger.info('==== result from show bfd peer 192.168.1.3 multihop')
    logger.info(output)
    output = tgen.gears['r1'].vtysh_cmd('show bfd peer 1001:1::3 multihop', isjson=False)
    logger.info('==== result from show bfd peer 1001:1::3 multihop')
    logger.info(output)
    logger.info('==== result from show ip route and show ipv6 route')
    output = tgen.gears['r1'].vtysh_cmd('show ip route', isjson=False)
    logger.info(output)
    output = tgen.gears['r1'].vtysh_cmd('show ipv6 route', isjson=False)
    logger.info(output)
    check_bfd_ipv6_nominal_state()

def test_memory_leak():
    "Run the memory leak test and report results."
    tgen = get_topogen()
    if not tgen.is_memleak_enabled():
        pytest.skip('Memory leak test/report is disabled')

    tgen.report_memory_leaks()


if __name__ == '__main__':
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
