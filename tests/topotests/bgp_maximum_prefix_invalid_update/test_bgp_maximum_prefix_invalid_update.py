#!/usr/bin/env python

#
# bgp_local_as_private_remove.py
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
bgp_maximum_prefix_invalid_update.py:
Test if unnecesarry UPDATE message like below:

[Error] Error parsing NLRI
%NOTIFICATION: sent to neighbor X.X.X.X 3/10 (UPDATE Message Error/Invalid Network Field) 0 bytes

is not sent if maximum-prefix count is overflow.
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

    def _bgp_converge(router):
        while True:
            output = json.loads(tgen.gears[router].vtysh_cmd("show ip bgp neighbor 192.168.255.1 json"))
            if output['192.168.255.1']['connectionsEstablished'] > 0:
                return True

    def _bgp_parsing_nlri(router):
        cmd_max_exceeded = 'grep "%MAXPFXEXCEED: No. of IPv4 Unicast prefix received" bgpd.log'
        cmdt_error_parsing_nlri = 'grep "Error parsing NLRI" bgpd.log'
        output_max_exceeded = tgen.gears[router].run(cmd_max_exceeded)
        output_error_parsing_nlri = tgen.gears[router].run(cmdt_error_parsing_nlri)

        if len(output_max_exceeded) > 0:
            if len(output_error_parsing_nlri) > 0:
                return False
        return True


    if _bgp_converge('r2'):
        assert _bgp_parsing_nlri('r2') == True

if __name__ == '__main__':
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
