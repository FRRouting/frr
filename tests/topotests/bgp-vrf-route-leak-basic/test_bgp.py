#!/usr/bin/env python

#
# test_bgp.py
#
# Copyright (c) 2018 Cumulus Networks, Inc.
#                    Donald Sharp
#
# Permission to use, copy, modify, and/or distribute this software
# for any purpose with or without fee is hereby granted, provided
# that the above copyright notice and this permission notice appear
# in all copies.
#
# THE SOFTWARE IS PROVIDED "AS IS" AND Cumulus Networks DISCLAIMS ALL WARRANTIES
# WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
# MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL NETDEF BE LIABLE FOR
# ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY
# DAMAGES WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS,
# WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS
# ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE
# OF THIS SOFTWARE.
#

"""
test_bgp.py: Test basic vrf route leaking
"""

import json
import os
import sys
import pytest

CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, '../'))

# pylint: disable=C0413
from lib import topotest
from lib.topogen import Topogen, TopoRouter, get_topogen
from lib.topolog import logger

from mininet.topo import Topo


class BGPVRFTopo(Topo):
    def build(self, *_args, **_opts):
        "Build function"
        tgen = get_topogen(self)

        for routern in range(1, 2):
            tgen.add_router('r{}'.format(routern))

def setup_module(mod):
    "Sets up the pytest environment"
    tgen = Topogen(BGPVRFTopo, mod.__name__)
    tgen.start_topology()

    # For all registered routers, load the zebra configuration file
    for rname, router in tgen.routers().iteritems():
        router.run("/bin/bash {}/setup_vrfs".format(CWD))
        router.load_config(
            TopoRouter.RD_ZEBRA,
            os.path.join(CWD, '{}/zebra.conf'.format(rname))
        )
        router.load_config(
            TopoRouter.RD_BGP,
            os.path.join(CWD, '{}/bgpd.conf'.format(rname))
        )

    # After loading the configurations, this function loads configured daemons.
    tgen.start_router()
    #tgen.mininet_cli()

def teardown_module(mod):
    "Teardown the pytest environment"
    tgen = get_topogen()

    # This function tears down the whole topology.
    tgen.stop_topology()

def test_vrf_route_leak():
    logger.info("Ensure that routes are leaked back and forth")
    tgen = get_topogen()
    # Don't run this test if we have any failure.
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears['r1']

    donna = r1.vtysh_cmd("show ip route vrf DONNA json", isjson=True)
    route0 = donna["10.0.0.0/24"][0]
    assert route0['protocol'] == "connected"
    route1 = donna["10.0.1.0/24"][0]
    assert route1['protocol'] == "bgp"
    assert route1['selected'] == True
    nhop = route1['nexthops'][0]
    assert nhop['fib'] == True
    route2 = donna["10.0.2.0/24"][0]
    assert route2['protocol'] == "connected"
    route3 = donna["10.0.3.0/24"][0]
    assert route3['protocol'] == "bgp"
    assert route3['selected'] == True
    nhop = route3['nexthops'][0]
    assert nhop['fib'] == True
    eva = r1.vtysh_cmd("show ip route vrf EVA json", isjson=True)
    route0 = eva["10.0.0.0/24"][0]
    assert route0['protocol'] == "bgp"
    assert route0['selected'] == True
    nhop = route0['nexthops'][0]
    assert nhop['fib'] == True
    route1 = eva["10.0.1.0/24"][0]
    assert route1['protocol'] == "connected"
    route2 = eva["10.0.2.0/24"][0]
    assert route2['protocol'] == "bgp"
    assert route2['selected'] == True
    nhop = route2['nexthops'][0]
    assert nhop['fib'] == True
    route3 = eva["10.0.3.0/24"][0]
    assert route3['protocol'] == "connected"
    #tgen.mininet_cli()

def test_memory_leak():
    "Run the memory leak test and report results."
    tgen = get_topogen()
    if not tgen.is_memleak_enabled():
        pytest.skip('Memory leak test/report is disabled')

    tgen.report_memory_leaks()


if __name__ == '__main__':
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
