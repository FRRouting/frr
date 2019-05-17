#!/usr/bin/env python

#
# bgp_ebgp_requires_policy.py
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
bgp_ebgp_requires_policy.py:

Test if eBGP sender without a filter applied to the peer is allowed
to send advertisements.
"""

import os
import sys
import json
import time
import pytest

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
            TopoRouter.RD_BGP,
            os.path.join(CWD, '{}/bgpd.conf'.format(rname))
        )

    tgen.start_router()

def teardown_module(mod):
    tgen = get_topogen()
    tgen.stop_topology()

def test_bgp_remove_private_as():
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    def _bgp_converge(router):
        while True:
            cmd = "show ip bgp neighbor 192.168.255.1 json"
            output = json.loads(tgen.gears[router].vtysh_cmd(cmd))
            if output['192.168.255.1']['bgpState'] == 'Established':
                time.sleep(3)
                return True

    def _bgp_ebgp_requires_policy(router):
        cmd = "show ip bgp 172.16.255.254/32 json"
        output = json.loads(tgen.gears[router].vtysh_cmd(cmd))
        if 'prefix' in output:
            return True
        return False

    if _bgp_converge('r2'):
        assert _bgp_ebgp_requires_policy('r2') == True

    if _bgp_converge('r4'):
        assert _bgp_ebgp_requires_policy('r4') == False

if __name__ == '__main__':
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
