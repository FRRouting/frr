#!/usr/bin/env python

#
# test_bgp_rr_ibgp_topo1.py
#
# Copyright (c) 2019 by
# Cumulus Networks, Inc.
# Donald Sharp
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
test_bgp_rr_ibgp_addpath.py: Testing IBGP with RR and no IGP


   Given 5 routers on the same segment:

   A       B       C
   |       |       |
   -----------------
      |        |
      D        E

   A specifies B is a route-reflector client
   A C D and E are in a mesh

   C D and E specify redistribute connected
   C and D have on their loopback 192.168.4.4/32

   After we come up and start testing B has the two paths
   via C and D because of the route-reflector status

   If we add to E's loopback a 192.168.4.4/32 address
   A is seeing the 3rd path and should send it to B as well.
   This will test that this is happening.
"""

import os
import re
import sys
import pytest
import json

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

#####################################################
##
##   Network Topology Definition
##
#####################################################

class NetworkTopo(Topo):
    "BGP_RR_IBGP addpath"

    def build(self, **_opts):
        "Build function"

        tgen = get_topogen(self)

        tgen.add_router('a')
        tgen.add_router('b')
        tgen.add_router('c')
        tgen.add_router('d')
        tgen.add_router('e')

        # First switch is for a dummy interface (for local network)
        # on tor1
	# 192.168.1.0/24
        switch = tgen.add_switch('sw1')
        switch.add_link(tgen.gears['a'])
        switch.add_link(tgen.gears['b'])
        switch.add_link(tgen.gears['c'])
        switch.add_link(tgen.gears['d'])
        switch.add_link(tgen.gears['e'])

#####################################################
##
##   Tests starting
##
#####################################################

def setup_module(module):
    "Setup topology"
    tgen = Topogen(NetworkTopo, module.__name__)
    tgen.start_topology()

    # This is a sample of configuration loading.
    router_list = tgen.routers()
    for rname, router in router_list.iteritems():
        router.load_config(
            TopoRouter.RD_ZEBRA,
            os.path.join(CWD, '{}/zebra.conf'.format(rname))
        )
        router.load_config(
            TopoRouter.RD_BGP,
            os.path.join(CWD, '{}/bgpd.conf'.format(rname))
        )

    tgen.start_router()


def test_converge_protocols():
    "Wait for protocol convergence"

    tgen = get_topogen()
    # Don't run this test if we have any failure.
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    topotest.sleep(5, 'Waiting for BGP_RR_IBGP convergence')
    router = tgen.gears['a']
    output = router.vtysh_cmd('show running-config')
    logger.info('==== {0} show running-config:'.format(router.name))
    logger.info(output)
    output = router.vtysh_cmd('show bgp ipv4 unicast')
    logger.info('==== {0} show bgp ipv4 unicast before:'.format(router.name))
    logger.info(output)

    router = tgen.gears['b']
    output = router.vtysh_cmd('show running-config')
    logger.info('==== {0} show running-config:'.format(router.name))
    logger.info(output)
    output = router.vtysh_cmd('show bgp ipv4 unicast')
    logger.info('==== {0} show bgp ipv4 unicast before:'.format(router.name))
    logger.info(output)

    logger.info('========== a configuration modification =======')
    router = tgen.gears['a']
    output = router.vtysh_cmd('configure terminal\nrouter bgp\nneighbor 192.168.2.5 remote-as internal')
    logger.info('==== {0} adding neighbor 192.168.2.5 as neighbor:'.format(router.name))
    logger.info(output)

    topotest.sleep(3, '...')
    output = router.vtysh_cmd('show bgp ipv4 unicast')
    logger.info('==== {0} show bgp ipv4 unicast after:'.format(router.name))
    logger.info(output)

    logger.info('========== b routing impact =======')
    router = tgen.gears['b']
    logger.info('==== {0} show bgp ipv4 unicast after:'.format(router.name))
    output = router.vtysh_cmd('show bgp ipv4 unicast')
    logger.info(output)
    output = router.vtysh_cmd('show bgp ipv4 unicast json', isjson=True)
    routes = output['routes']
    if not routes:
        assert 0, "{0}, no BGP route found".format(router.name)
    routeid = routes['192.168.4.4/32']
    val_mpath = 'multipath'
    val_bpath = 'bestpath'
    ecmp_entries_values = {0,1,2}
    for k in ecmp_entries_values:
        if val_mpath in routeid[k].keys():
            continue
        if val_bpath in routeid[k].keys():
            continue
        assert 0, "{0}, one of the entries for 192.168.4.4 is not best path or multipath".format(router.name)

    ## check 3 mpath entries should be found
   
def teardown_module(_mod):
    "Teardown the pytest environment"
    tgen = get_topogen()

    # This function tears down the whole topology.
    tgen.stop_topology()

if __name__ == '__main__':
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))

#
# Auxiliary Functions
#
