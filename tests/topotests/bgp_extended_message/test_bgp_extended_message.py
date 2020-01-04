#!/usr/bin/env python

#
# test_bgp_extended_message.py
# Part of NetDEF Topology Tests
#
# Copyright (c) 2019 by
# Donatas Abraitis <donatas.abraitis@gmail.com>
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
Test if Extended Message Support for BGP is negotiated.
"""

import os
import sys
import json
import time
import pytest
import functools

CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, '../'))

# pylint: disable=C0413
from lib import topotest
from lib.topogen import Topogen, TopoRouter, get_topogen
from lib.topolog import logger
from mininet.topo import Topo

class TemplateTopo(Topo):
    def build(self, *_args, **_opts):
        tgen = get_topogen(self)

        for routern in range(1, 5):
            tgen.add_router('r{}'.format(routern))

        switch = tgen.add_switch('s1')
        switch.add_link(tgen.gears['r1'])
        switch.add_link(tgen.gears['r2'])

        switch = tgen.add_switch('s2')
        switch.add_link(tgen.gears['r3'])
        switch.add_link(tgen.gears['r4'])

def setup_module(mod):
    tgen = Topogen(TemplateTopo, mod.__name__)
    tgen.start_topology()

    router_list = tgen.routers()

    for i, (rname, router) in enumerate(router_list.iteritems(), 1):
        router.load_config(
            TopoRouter.RD_ZEBRA,
            os.path.join(CWD, '{}/zebra.conf'.format(rname))
        )
        router.load_config(
            TopoRouter.RD_SHARP,
            os.path.join(CWD, '{}/sharpd.conf'.format(rname))
        )
        router.load_config(
            TopoRouter.RD_BGP,
            os.path.join(CWD, '{}/bgpd.conf'.format(rname))
        )

    tgen.start_router()

def teardown_module(mod):
    tgen = get_topogen()
    tgen.stop_topology()

def test_bgp_extended_message_capability_adv():
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    def _install_sharp_routes(router):
        router.vtysh_cmd('sharp install routes 172.16.0.0 nexthop 192.168.255.2 5000')
        output = json.loads(router.vtysh_cmd('show ip route summary json'))
        expected = {
            'routes': [
                {
                    'fib': 1,
                    'rib': 1,
                    'type': 'connected'
                },
                {
                    'fib': 5000,
                    'rib': 5000,
                    'type': 'sharp'
                }
            ],
            'routesTotal': 5001
        }
        return topotest.json_cmp(output, expected)

    def _uninstall_sharp_routes(router):
        router.vtysh_cmd('sharp remove routes 172.16.0.0 5000')
        output = json.loads(router.vtysh_cmd('show ip route summary json'))
        expected = {
            'routes': [
                {
                    'fib': 1,
                    'rib': 1,
                    'type': 'connected'
                }
            ],
            'routesTotal': 1
        }
        return topotest.json_cmp(output, expected)

    def _bgp_converge(router):
        output = json.loads(router.vtysh_cmd('show ip bgp neighbor 192.168.255.2 json'))
        expected = {
            '192.168.255.2': {
                'bgpState': 'Established',
                'addressFamilyInfo': {
                    'ipv4Unicast': {
                        'acceptedPrefixCounter': 5000
                    }
                }
            }
        }
        return topotest.json_cmp(output, expected)

    def _bgp_extended_message_capability_received(router):
        output = json.loads(router.vtysh_cmd('show ip bgp neighbor 192.168.255.2 json'))
        expected = {
            '192.168.255.2': {
                'neighborCapabilities': {
                    'extendedMessage': 'received'
                }
            }
        }
        return topotest.json_cmp(output, expected)

    def _bgp_extended_message_capability_updates_received(router):
        output = json.loads(router.vtysh_cmd('show ip bgp neighbor 192.168.255.2 json'))
        return output['192.168.255.2']['messageStats']['updatesRecv']

    def _bgp_extended_message_capability_both(router):
        output = json.loads(router.vtysh_cmd('show ip bgp neighbor 192.168.255.2 json'))
        expected = {
            '192.168.255.2': {
                'neighborCapabilities': {
                    'extendedMessage': 'advertisedAndReceived'
                }
            }
        }
        return topotest.json_cmp(output, expected)

    # Test without BGP extended message capability
    test_func = functools.partial(_install_sharp_routes, tgen.gears['r1'])
    success, result = topotest.run_and_expect(test_func, None, count=60, wait=0.5)
    assert result is None, 'Failed installing sharp routes "{}"'.format(tgen.gears['r1'])

    test_func = functools.partial(_bgp_converge, tgen.gears['r2'])
    success, result = topotest.run_and_expect(test_func, None, count=60, wait=0.5)
    assert result is None, 'Failed bgp convergence in "{}"'.format(tgen.gears['r2'])

    test_func = functools.partial(_bgp_extended_message_capability_received, tgen.gears['r2'])
    success, result = topotest.run_and_expect(test_func, None, count=60, wait=0.5)
    assert result is None, 'Failed to see an extended message capability in "{}"'.format(tgen.gears['r2'])

    if success:
        assert _bgp_extended_message_capability_updates_received(tgen.gears['r2']) > 10

    test_func = functools.partial(_uninstall_sharp_routes, tgen.gears['r1'])
    success, result = topotest.run_and_expect(test_func, None, count=60, wait=0.5)
    assert result is None, 'Failed uninstalling sharp routes "{}"'.format(tgen.gears['r1'])

    # Test with BGP extended message capability
    test_func = functools.partial(_install_sharp_routes, tgen.gears['r3'])
    success, result = topotest.run_and_expect(test_func, None, count=60, wait=0.5)
    assert result is None, 'Failed installing sharp routes "{}"'.format(tgen.gears['r3'])

    test_func = functools.partial(_bgp_converge, tgen.gears['r4'])
    success, result = topotest.run_and_expect(test_func, None, count=60, wait=0.5)
    assert result is None, 'Failed bgp convergence in "{}"'.format(tgen.gears['r4'])

    test_func = functools.partial(_bgp_extended_message_capability_both, tgen.gears['r4'])
    success, result = topotest.run_and_expect(test_func, None, count=60, wait=0.5)
    assert result is None, 'Failed to see an extended message capability in "{}"'.format(tgen.gears['r4'])

    if success:
        assert _bgp_extended_message_capability_updates_received(tgen.gears['r4']) < 10

    test_func = functools.partial(_uninstall_sharp_routes, tgen.gears['r1'])
    success, result = topotest.run_and_expect(test_func, None, count=60, wait=0.5)
    assert result is None, 'Failed uninstalling sharp routes "{}"'.format(tgen.gears['r3'])

if __name__ == '__main__':
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
