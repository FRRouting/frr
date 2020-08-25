#!/usr/bin/env python

#
# test_bgp_features.py
# Part of NetDEF Topology Tests
#
# Copyright (c) 2020 by
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
test_bgp_features.py: Test various BGP features.
"""

import json
import functools
import os
import sys
import pytest
import re

# Save the Current Working Directory to find configuration files.
CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

# pylint: disable=C0413
# Import topogen and topotest helpers
from lib import topotest
from lib.topogen import Topogen, TopoRouter, get_topogen
from lib.topolog import logger

# Required to instantiate the topology builder class.
from mininet.topo import Topo

#####################################################
#
#   Network Topology Definition
#
#####################################################


class BGPFeaturesTopo1(Topo):
    "BGP Features Topology 1"

    def build(self, **_opts):
        tgen = get_topogen(self)

        # Create the routers
        for rtrNum in range(1, 6):
            tgen.add_router("r{}".format(rtrNum))

        # Setup Switches and connections
        for swNum in range(1, 11):
            tgen.add_switch("sw{}".format(swNum))

        # Add connections to stub switches
        tgen.gears["r1"].add_link(tgen.gears["sw6"])
        tgen.gears["r2"].add_link(tgen.gears["sw7"])
        tgen.gears["r3"].add_link(tgen.gears["sw8"])
        tgen.gears["r4"].add_link(tgen.gears["sw9"])
        tgen.gears["r5"].add_link(tgen.gears["sw10"])

        # Add connections to R1-R2-R3 core
        tgen.gears["r1"].add_link(tgen.gears["sw1"])
        tgen.gears["r1"].add_link(tgen.gears["sw3"])
        tgen.gears["r2"].add_link(tgen.gears["sw1"])
        tgen.gears["r2"].add_link(tgen.gears["sw2"])
        tgen.gears["r3"].add_link(tgen.gears["sw2"])
        tgen.gears["r3"].add_link(tgen.gears["sw3"])

        # Add connections to external R4/R5 Routers
        tgen.gears["r1"].add_link(tgen.gears["sw4"])
        tgen.gears["r4"].add_link(tgen.gears["sw4"])
        tgen.gears["r2"].add_link(tgen.gears["sw5"])
        tgen.gears["r5"].add_link(tgen.gears["sw5"])


#####################################################
#
#   Tests starting
#
#####################################################


def setup_module(module):
    tgen = Topogen(BGPFeaturesTopo1, module.__name__)
    tgen.start_topology()

    # Starting Routers
    router_list = tgen.routers()
    for rname, router in router_list.iteritems():
        router.load_config(
            TopoRouter.RD_ZEBRA, os.path.join(CWD, "{}/zebra.conf".format(rname))
        )
        if os.path.exists(os.path.join(CWD, "{}/bgpd.conf".format(rname))):
            logger.info("{} uses BGPd".format(rname))
            router.load_config(
                TopoRouter.RD_BGP, os.path.join(CWD, "{}/bgpd.conf".format(rname))
            )
        if os.path.exists(os.path.join(CWD, "{}/ospfd.conf".format(rname))):
            logger.info("{} uses OSPFd".format(rname))
            router.load_config(
                TopoRouter.RD_OSPF, os.path.join(CWD, "{}/ospfd.conf".format(rname))
            )
        if os.path.exists(os.path.join(CWD, "{}/ospf6d.conf".format(rname))):
            logger.info("{} uses OSPF6d".format(rname))
            router.load_config(
                TopoRouter.RD_OSPF6, os.path.join(CWD, "{}/ospf6d.conf".format(rname))
            )
        router.start()


def teardown_module(module):
    tgen = get_topogen()
    tgen.stop_topology()


def test_ospf_convergence():
    "Test for OSPFv2 topology convergence"
    tgen = get_topogen()

    # Skip if previous fatal error condition is raised
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    # Check Router r1, r2 & r3 OSPF
    for rtrNum in range(1, 4):
        logger.info("Checking OSPFv2 convergence on router r{}".format(rtrNum))

        router = tgen.gears["r{}".format(rtrNum)]
        reffile = os.path.join(CWD, "r{}/ospf_neighbor.json".format(rtrNum))
        expected = json.loads(open(reffile).read())

        test_func = functools.partial(
            topotest.router_json_cmp, router, "show ip ospf neighbor json", expected
        )
        _, res = topotest.run_and_expect(test_func, None, count=60, wait=2)
        assertmsg = "OSPF router R{} did not converge".format(rtrNum)
        assert res is None, assertmsg


def test_bgp_convergence():
    "Test for BGP topology convergence"
    tgen = get_topogen()

    # Skip if previous fatal error condition is raised
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    # Check Router r1 & r2 BGP
    for rtrNum in [1, 2, 4, 5]:
        logger.info("Checking BGP IPv4 convergence on router r{}".format(rtrNum))

        router = tgen.gears["r{}".format(rtrNum)]
        reffile = os.path.join(CWD, "r{}/bgp_summary.json".format(rtrNum))
        expected = json.loads(open(reffile).read())

        test_func = functools.partial(
            topotest.router_json_cmp, router, "show ip bgp summary json", expected
        )
        _, res = topotest.run_and_expect(test_func, None, count=60, wait=2)
        assertmsg = "BGP router R{} did not converge".format(rtrNum)
        assert res is None, assertmsg

    # tgen.mininet_cli()


def test_bgp_shutdown():
    "Test BGP instance shutdown"

    tgen = get_topogen()

    # Skip if previous fatal error condition is raised
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    tgen.net['r1'].cmd('vtysh -c \"conf t\" -c \"router bgp 65000\" -c \"bgp shutdown message ABCDabcd\"')

    # Check BGP Summary on local and remote routers
    for rtrNum in [1, 2, 4]:
        logger.info("Checking BGP Summary after shutdown of R1 BGP on router r{}".format(rtrNum))

        router = tgen.gears["r{}".format(rtrNum)]
        reffile = os.path.join(CWD, "r{}/bgp_shutdown_summary.json".format(rtrNum))
        expected = json.loads(open(reffile).read())

        test_func = functools.partial(
            topotest.router_json_cmp, router, "show ip bgp summary json", expected
        )
        _, res = topotest.run_and_expect(test_func, None, count=60, wait=2)
        assertmsg = "BGP sessions on router R{} are in incorrect state (not down as expected?)".format(rtrNum)
        assert res is None, assertmsg


def test_bgp_shutdown_message():
    "Test BGP Peer Shutdown Message"

    tgen = get_topogen()

    # Skip if previous fatal error condition is raised
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    for rtrNum in [2, 4]:
        logger.info("Checking BGP shutdown received on router r{}".format(rtrNum))

        shut_message = tgen.net['r{}'.format(rtrNum)].cmd(
            'tail bgpd.log | grep "NOTIFICATION.*Cease/Administratively Shutdown"')
        assertmsg = "BGP shutdown message not received on router R{}".format(rtrNum)
        assert shut_message != '', assertmsg

        m = re.search('.*([0-9]+ bytes[ 0-9a-fA-F]+)', shut_message)
        if m:
            found = m.group(1)
        else:
            found = ''
        assertmsg = "Incorrect BGP shutdown message received on router R{}".format(rtrNum)
        assert found == '8 bytes 41 42 43 44 61 62 63 64', assertmsg

    # tgen.mininet_cli()


def test_bgp_no_shutdown():
    "Test BGP instance no shutdown"

    tgen = get_topogen()

    # Skip if previous fatal error condition is raised
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    tgen.net['r1'].cmd('vtysh -c \"conf t\" -c \"router bgp 65000\" -c \"no bgp shutdown\"')

    # Check BGP Summary on local and remote routers
    for rtrNum in [1, 2, 4]:
        logger.info("Checking BGP Summary after removing bgp shutdown on router r1 on router r{}".format(rtrNum))

        router = tgen.gears["r{}".format(rtrNum)]
        reffile = os.path.join(CWD, "r{}/bgp_summary.json".format(rtrNum))
        expected = json.loads(open(reffile).read())

        test_func = functools.partial(
            topotest.router_json_cmp, router, "show ip bgp summary json", expected
        )
        _, res = topotest.run_and_expect(test_func, None, count=60, wait=2)
        assertmsg = "BGP sessions on router R{} are in incorrect state (not down as expected?)".format(rtrNum)
        assert res is None, assertmsg



if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
