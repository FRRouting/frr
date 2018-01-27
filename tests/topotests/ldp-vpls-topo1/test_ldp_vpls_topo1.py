#!/usr/bin/env python

#
# test_ldp_vpls_topo1.py
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
test_ldp_vpls_topo1.py:

                   +---------+                +---------+
                   |         |                |         |
                   |   CE1   |                |   CE2   |
                   |         |                |         |
                   +---------+                +---------+
ce1-eth0 (172.16.1.1/24)|                          |ce2-eth0 (172.16.1.2/24)
                        |                          |
                        |                          |
                rt1-eth0|                          |rt2-eth0
                   +---------+  10.0.1.0/24   +---------+
                   |         |rt1-eth1        |         |
                   |   RT1   +----------------+   RT2   |
                   | 1.1.1.1 |        rt2-eth1| 2.2.2.2 |
                   |         |                |         |
                   +---------+                +---------+
                rt1-eth2|                          |rt2-eth2
                        |                          |
                        |                          |
             10.0.2.0/24|        +---------+       |10.0.3.0/24
                        |        |         |       |
                        |        |   RT3   |       |
                        +--------+ 3.3.3.3 +-------+
                         rt3-eth2|         |rt3-eth1
                                 +---------+
                                      |rt3-eth0
                                      |
                                      |
              ce3-eth0 (172.16.1.3/24)|
                                 +---------+
                                 |         |
                                 |   CE3   |
                                 |         |
                                 +---------+
"""

import os
import sys
import pytest
import json
from time import sleep
from functools import partial

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

class TemplateTopo(Topo):
    "Test topology builder"
    def build(self, *_args, **_opts):
        "Build function"
        tgen = get_topogen(self)

        #
        # Define FRR Routers
        #
        for router in ['ce1', 'ce2', 'ce3', 'r1', 'r2', 'r3']:
            tgen.add_router(router)

        #
        # Define connections
        #
        switch = tgen.add_switch('s1')
        switch.add_link(tgen.gears['ce1'])
        switch.add_link(tgen.gears['r1'])

        switch = tgen.add_switch('s2')
        switch.add_link(tgen.gears['ce2'])
        switch.add_link(tgen.gears['r2'])

        switch = tgen.add_switch('s3')
        switch.add_link(tgen.gears['ce3'])
        switch.add_link(tgen.gears['r3'])

        switch = tgen.add_switch('s4')
        switch.add_link(tgen.gears['r1'])
        switch.add_link(tgen.gears['r2'])

        switch = tgen.add_switch('s5')
        switch.add_link(tgen.gears['r1'])
        switch.add_link(tgen.gears['r3'])

        switch = tgen.add_switch('s6')
        switch.add_link(tgen.gears['r2'])
        switch.add_link(tgen.gears['r3'])

def setup_module(mod):
    "Sets up the pytest environment"
    tgen = Topogen(TemplateTopo, mod.__name__)
    tgen.start_topology()

    router_list = tgen.routers()

    # For all registered routers, load the zebra configuration file
    for rname, router in router_list.iteritems():
        router.load_config(
            TopoRouter.RD_ZEBRA,
            os.path.join(CWD, '{}/zebra.conf'.format(rname))
        )
        # Don't start ospfd and ldpd in the CE nodes
        if router.name[0] == 'r':
            router.load_config(
                TopoRouter.RD_OSPF,
                os.path.join(CWD, '{}/ospfd.conf'.format(rname))
            )
            router.load_config(
                TopoRouter.RD_LDP,
                os.path.join(CWD, '{}/ldpd.conf'.format(rname))
            )

    tgen.start_router()
    for router in router_list.values():
        if router.has_version('<', '3'):
            tgen.set_error('unsupported version')

def teardown_module(mod):
    "Teardown the pytest environment"
    tgen = get_topogen()

    # This function tears down the whole topology.
    tgen.stop_topology()

def router_compare_json_output_cb(rname, command, reference):
    tgen = get_topogen()
    router = tgen.gears[rname]
    output = router.vtysh_cmd(command, isjson=True)
    refTableFile = '{}/{}/{}'.format(CWD, router.name, reference)
    expected = json.loads(open(refTableFile).read())
    return topotest.json_cmp(output, expected)

def router_compare_json_output(rname, command, reference):
    logger.info('Comparing router "%s" "%s" output', rname, command)

    # Run test function until we get an result. Wait at most 60 seconds.
    test_func = partial(router_compare_json_output_cb, rname, command, reference)
    _, diff = topotest.run_and_expect(test_func, None, count=20, wait=3)
    assertmsg = '"{}" JSON output mismatches the expected result'.format(rname)
    assert diff is None, assertmsg

def test_ospf_convergence():
    logger.info("Test: check OSPF adjacencies")
    tgen = get_topogen()

    # Skip if previous fatal error condition is raised
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    # Old output (before FRR PR1383) didn't show a list of neighbors.
    # Check for dict object and compare to old output if this is the case
    tgen = get_topogen()
    router = tgen.gears['r1']
    output = router.vtysh_cmd("show ip ospf neighbor json", isjson=True)

    # We could have either old format (without "neighbors" and direct list
    # of IP's or new format from PR1659 with "neighbors".
    # Trying old formats first and fall back to new format
    try:
        if isinstance(output["2.2.2.2"], dict):
            reffile = "show_ip_ospf_neighbor.ref-old-nolist"
        else:
            reffile = "show_ip_ospf_neighbor.ref-no-neigh"
    except:
        reffile = "show_ip_ospf_neighbor.ref"

    for rname in ['r1', 'r2', 'r3']:
        router_compare_json_output(rname, "show ip ospf neighbor json", reffile)

def test_rib():
    logger.info("Test: verify RIB")
    tgen = get_topogen()

    # Skip if previous fatal error condition is raised
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    for rname in ['r1', 'r2', 'r3']:
        router_compare_json_output(rname, "show ip route json", "show_ip_route.ref")

def test_ldp_adjacencies():
    logger.info("Test: verify LDP adjacencies")
    tgen = get_topogen()

    # Skip if previous fatal error condition is raised
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    for rname in ['r1', 'r2', 'r3']:
        router_compare_json_output(rname, "show mpls ldp discovery json", "show_ldp_discovery.ref")

def test_ldp_neighbors():
    logger.info("Test: verify LDP neighbors")
    tgen = get_topogen()

    # Skip if previous fatal error condition is raised
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    for rname in ['r1', 'r2', 'r3']:
        router_compare_json_output(rname, "show mpls ldp neighbor json", "show_ldp_neighbor.ref")

def test_ldp_bindings():
    logger.info("Test: verify LDP bindings")
    tgen = get_topogen()

    # Skip if previous fatal error condition is raised
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    for rname in ['r1', 'r2', 'r3']:
        router_compare_json_output(rname, "show mpls ldp binding json", "show_ldp_binding.ref")

def test_ldp_pwid_bindings():
    logger.info("Test: verify LDP PW-ID bindings")
    tgen = get_topogen()

    # Skip if previous fatal error condition is raised
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    for rname in ['r1', 'r2', 'r3']:
        router_compare_json_output(rname, "show l2vpn atom binding json", "show_l2vpn_binding.ref")

def test_ldp_pseudowires():
    logger.info("Test: verify LDP pseudowires")
    tgen = get_topogen()

    # Skip if previous fatal error condition is raised
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    for rname in ['r1', 'r2', 'r3']:
        router_compare_json_output(rname, "show l2vpn atom vc json", "show_l2vpn_vc.ref")

def test_ldp_pseudowires_after_link_down():
    logger.info("Test: verify LDP pseudowires after r1-r2 link goes down")
    tgen = get_topogen()

    # Skip if previous fatal error condition is raised
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    # Shut down r1-r2 link */
    tgen = get_topogen()
    tgen.gears['r1'].peer_link_enable('r1-eth1', False)

    # Wait 15 seconds for the r1-r2 LDP link adjacencies to time out
    sleep(15)

    # check if the pseudowire is still up (using an alternate path for nexthop resolution)
    for rname in ['r1', 'r2', 'r3']:
        router_compare_json_output(rname, "show l2vpn atom vc json", "show_l2vpn_vc.ref")

# Memory leak test template
def test_memory_leak():
    "Run the memory leak test and report results."
    tgen = get_topogen()
    if not tgen.is_memleak_enabled():
        pytest.skip('Memory leak test/report is disabled')

    tgen.report_memory_leaks()

if __name__ == '__main__':
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
