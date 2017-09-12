#!/usr/bin/env python

#
# test_eigrp_topo1.py
#
# Copyright (c) 2017 by
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
test_eigrp_topo1.py: Testing EIGRP

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
    "EIGRP Topology 1"

    def build(self, **_opts):
        "Build function"

        tgen = get_topogen(self)

        for routern in range(1, 4):
            tgen.add_router('r{}'.format(routern))

        # On main router
        # First switch is for a dummy interface (for local network)
        switch = tgen.add_switch('sw1')
        switch.add_link(tgen.gears['r1'])

        # Switches for EIGRP
        # switch 2 switch is for connection to EIGRP router
        switch = tgen.add_switch('sw2')
        switch.add_link(tgen.gears['r1'])
        switch.add_link(tgen.gears['r2'])

        # switch 4 is stub on remote EIGRP router
        switch = tgen.add_switch('sw4')
        switch.add_link(tgen.gears['r3'])

        # switch 3 is between EIGRP routers
        switch = tgen.add_switch('sw3')
        switch.add_link(tgen.gears['r2'])
        switch.add_link(tgen.gears['r3'])


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
            TopoRouter.RD_EIGRP,
            os.path.join(CWD, '{}/eigrpd.conf'.format(rname))
        )

    tgen.start_router()


def teardown_module(_mod):
    "Teardown the pytest environment"
    tgen = get_topogen()

    # This function tears down the whole topology.
    tgen.stop_topology()


def test_converge_protocols():
    "Wait for protocol convergence"

    tgen = get_topogen()
    # Don't run this test if we have any failure.
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    topotest.sleep(5, 'Waiting for EIGRP convergence')


def test_eigrp_routes():
    "Test EIGRP 'show ip eigrp'"

    tgen = get_topogen()
    # Don't run this test if we have any failure.
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    # Verify EIGRP Status
    logger.info("Verifying EIGRP routes")

    failures = 0
    router_list = tgen.routers().values()
    for router in router_list:
        refTableFile = '{}/{}/show_ip_eigrp.ref'.format(CWD, router.name)

        # Read expected result from file
        expected = open(refTableFile).read().rstrip()

        # Actual output from router
        actual = router.vtysh_cmd('show ip eigrp topo').rstrip()
        # Drop Time
        actual = re.sub(r"[0-9][0-9]:[0-5][0-9]", "XX:XX", actual)

        # Generate Diff
        diff = topotest.difflines(actual, expected,
                                  title1="actual SHOW IP EIGRP",
                                  title2="expected SHOW IP EIGRP")

        # Empty string if it matches, otherwise diff contains unified diff
        if diff:
            failures += 1
        else:
            logger.info('{} ok'.format(router.name))

        assert failures == 0, 'SHOW IP EIGRP failed for router {}:\n{}'.format(router.name, diff)


# def test_zebra_ipv4_routingTable():
#     "Test 'show ip route'"

#     tgen = get_topogen()
#     # Don't run this test if we have any failure.
#     if tgen.routers_have_failure():
#         pytest.skip(tgen.errors)

#     # Verify OSPFv2 Routing Table
#     logger.info("Verifying Zebra IPv4 Routing Table")

#     failures = 0
#     router_list = tgen.routers().values()
#     for router in router_list:
#         refTableFile = '{}/{}/show_ip_route.ref'.format(CWD, router.name)

#         # Read expected result from file
#         expected = open(refTableFile).read().rstrip()

#         # Actual output from router
#         actual = router.vtysh_cmd('show ip route').rstrip()

#         # Generate Diff
#         diff = topotest.difflines(actual, expected,
#                                   title1="actual Zebra IPv4 routing table",
#                                   title2="expected Zebra IPv4 routing table")

#         # Empty string if it matches, otherwise diff contains unified diff
#         if diff:
#             failures += 1
#         else:
#             logger.info('{} ok'.format(router.name))

#         assert failures == 0, 'Zebra IPv4 Routing Table verification failed for router {}:\n{}'.format(router.name, diff)


def test_zebra_ipv4_routingTable():
    "Test 'show ip route'"

    tgen = get_topogen()
    # Don't run this test if we have any failure.
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    failures = 0
    router_list = tgen.routers().values()
    for router in router_list:
        output = router.vtysh_cmd('show ip route json', isjson=True)
        refTableFile = '{}/{}/show_ip_route.json_ref'.format(CWD, router.name)
        expected = json.loads(open(refTableFile).read())

        # diff = topotest.json_cmp(output, expected)

        assertmsg = 'Zebra IPv4 Routing Table verification failed for router {}'.format(router.name)
        assert topotest.json_cmp(output, expected) is None, assertmsg

        # # Empty string if it matches, otherwise diff contains unified diff
        # if diff:
        #     logger.info('{} NOT ok'.format(router.name))
        #     print("diff = %s" % str(diff))
        #     failures += 1
        # else:
        #     logger.info('{} ok'.format(router.name))

        # assert failures == 0, 'Zebra IPv4 Routing Table verification failed for router {}:\n{}'.format(router.name, diff)


def test_shutdown_check_stderr():
    if os.environ.get('TOPOTESTS_CHECK_STDERR') is None:
        pytest.skip('Skipping test for Stderr output and memory leaks')

    tgen = get_topogen()
    # Don't run this test if we have any failure.
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    logger.info("Verifying unexpected STDERR output from daemons")

    router_list = tgen.routers().values()
    for router in router_list:
        router.stop()

        log = tgen.net[router.name].getStdErr('eigrpd')
        if log:
            logger.error('EIGRPd StdErr Log:' + log)
        log = tgen.net[router.name].getStdErr('zebra')
        if log:
            logger.error('Zebra StdErr Log:' + log)


if __name__ == '__main__':
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
