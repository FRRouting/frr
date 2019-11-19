#!/usr/bin/env python

#
# bgp_distance_change.py
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
bgp_distance_change.py:

Test if works the following commands:
router bgp 65031
  address-family ipv4 unicast
    distance bgp 123 123 123

Changed distance should reflect to RIB after changes.
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

        for routern in range(1, 3):
            tgen.add_router('r{}'.format(routern))

        switch = tgen.add_switch('s1')
        switch.add_link(tgen.gears['r1'])
        switch.add_link(tgen.gears['r2'])

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
            TopoRouter.RD_BGP,
            os.path.join(CWD, '{}/bgpd.conf'.format(rname))
        )

    tgen.start_router()

def teardown_module(mod):
    tgen = get_topogen()
    tgen.stop_topology()

def test_bgp_maximum_prefix_invalid():
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    router = tgen.gears['r1']

    def _bgp_converge(router):
        output = json.loads(router.vtysh_cmd("show ip bgp neighbor 192.168.255.2 json"))
        expected = {
            '192.168.255.2': {
                'bgpState': 'Established',
                'addressFamilyInfo': {
                    'ipv4Unicast': {
                        'acceptedPrefixCounter': 2
                    }
                }
            }
        }
        return topotest.json_cmp(output, expected)

    def _bgp_distance_change(router):
        router.vtysh_cmd("""
          configure terminal
            router bgp 65000
              address-family ipv4 unicast
                distance bgp 123 123 123
        """)

    def _bgp_check_distance_change(router):
        output = json.loads(router.vtysh_cmd("show ip route 172.16.255.254/32 json"))
        expected = {
            '172.16.255.254/32': [
                {
                    'protocol': 'bgp',
                    'distance': 123
                }
            ]
        }
        return topotest.json_cmp(output, expected)

    test_func = functools.partial(_bgp_converge, router)
    success, result = topotest.run_and_expect(test_func, None, count=15, wait=0.5)

    assert result is None, 'Failed to see BGP convergence in "{}"'.format(router)

    _bgp_distance_change(router)

    test_func = functools.partial(_bgp_check_distance_change, router)
    success, result = topotest.run_and_expect(test_func, None, count=15, wait=0.5)

    assert result is None, 'Failed to see applied BGP distance in RIB "{}"'.format(router)

if __name__ == '__main__':
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
