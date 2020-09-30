#!/usr/bin/env python

#
# test_bgp_nht_peer.py
# Part of NetDEF Topology Tests
#
# Copyright (c) 2020 by 6WIND
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
Test if BGP nexthop tracking information is taken into account by BGP
peering, as the nht information is related to the nht peer IP itself.
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

        for routern in range(1, 4):
            tgen.add_router('r{}'.format(routern))

        switch = tgen.add_switch('s1')
        switch.add_link(tgen.gears['r1'])
        switch.add_link(tgen.gears['r2'])

        switch = tgen.add_switch('s2')
        switch.add_link(tgen.gears['r2'])
        switch.add_link(tgen.gears['r3'])

def setup_module(mod):
    tgen = Topogen(TemplateTopo, mod.__name__)
    tgen.start_topology()

    router_list = tgen.routers()

    cmds = ['ip link add name {0}-gre type gre dev {0}-eth0',
            'ip link set dev {0}-gre up']
    for rtr in ('r1', 'r3'):
        router = tgen.gears[rtr]
        for cmd in cmds:
            cmd = cmd.format(rtr)
            logger.info('cmd: '+cmd)
            output = router.run(cmd)
            logger.info('output: '+output);

    for i, (rname, router) in enumerate(router_list.iteritems(), 1):
        router.load_config(
            TopoRouter.RD_ZEBRA,
            os.path.join(CWD, '{}/zebra.conf'.format(rname))
        )
        if rname == 'r2':
            continue
        router.load_config(
            TopoRouter.RD_BGP,
            os.path.join(CWD, '{}/bgpd.conf'.format(rname))
        )

    tgen.start_router()

    cmds = ['ip a a 192.168.255.2/24 dev {}-eth0',
            'ip a a 10.255.255.3/32 dev {}-gre',
            'ip neigh add 10.255.255.1 lladdr 192.168.254.2 dev {0}-gre',
            'ip route add 10.255.255.1/32 dev {0}-gre',
            'ip route add 192.168.254.0/24 via 192.168.255.1']
    router = tgen.gears['r3']
    for cmd in cmds:
        cmd = cmd.format('r3')
        logger.info('cmd: '+cmd);
        output = router.run(cmd.format('r3'))
        logger.info('output: '+output);

    cmds = ['ip a a 192.168.254.2/24 dev {}-eth0',
            'ip a a 10.255.255.1/32 dev {}-gre',
            'ip neigh add 10.255.255.3 lladdr 192.168.255.2 dev {0}-gre',
            'ip route add 10.255.255.3/32 dev {0}-gre',
            'ip route add 192.168.255.0/24 via 192.168.254.1']
    router = tgen.gears['r1']
    for cmd in cmds:
        cmd = cmd.format('r1')
        logger.info('cmd: '+cmd);
        output = router.run(cmd.format('r1'))
        logger.info('output: '+output);


def teardown_module(mod):
    tgen = get_topogen()
    tgen.stop_topology()

def test_bgp_nht_peer():
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    router = tgen.gears['r1']

    def _bgp_converge(router):
        output = json.loads(router.vtysh_cmd("show ip bgp neighbor 10.255.255.3 json"))
        expected = {
            '10.255.255.3': {
                'bgpState': 'Established',
                'addressFamilyInfo': {
                    'ipv4Unicast': {
                        'acceptedPrefixCounter': 1
                    }
                }
            }
        }
        return topotest.json_cmp(output, expected)

    def _bgp_converge_active(router):
        output = json.loads(router.vtysh_cmd("show ip bgp neighbor 10.255.255.3 json"))
        expected = {
            '10.255.255.3': {
                'bgpState': 'Active'
            }
        }
        return topotest.json_cmp(output, expected)

    test_func = functools.partial(_bgp_converge, router)
    success, result = topotest.run_and_expect(test_func, None, count=60, wait=0.5)

    assert result is None, 'Failed bgp convergence in "{}"'.format(router)

    cmds = ['ip route del 10.255.255.3/32 dev {0}-gre',
            'ip neigh del 10.255.255.3 lladdr 192.168.255.2 dev {0}-gre']
    router = tgen.gears['r1']
    for cmd in cmds:
        cmd = cmd.format('r1')
        logger.info('cmd: '+cmd);
        output = router.run(cmd.format('r1'))
        logger.info('output: '+output);

    # should converge in few seconds
    test_func = functools.partial(_bgp_converge_active, router)
    success, result = topotest.run_and_expect(test_func, None, count=20, wait=0.5)

    assert result is None, 'Failed bgp convergence down in "{}"'.format(router)

    cmds = ['ip neigh replace 10.255.255.3 lladdr 192.168.255.2 dev {0}-gre',
            'ip route add 10.255.255.3/32 dev {0}-gre']
    router = tgen.gears['r1']
    for cmd in cmds:
        cmd = cmd.format('r1')
        logger.info('cmd: '+cmd);
        output = router.run(cmd.format('r1'))
        logger.info('output: '+output);
    test_func = functools.partial(_bgp_converge, router)
    success, result = topotest.run_and_expect(test_func, None, count=60, wait=0.5)

    assert result is None, 'Failed bgp convergence in "{}"'.format(router)
    

if __name__ == '__main__':
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
