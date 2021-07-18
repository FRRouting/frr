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
import time
from time import sleep

# Save the Current Working Directory to find configuration files.
CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

# pylint: disable=C0413
# Import topogen and topotest helpers
from lib import topotest
from lib.topogen import Topogen, TopoRouter, get_topogen
from lib.topolog import logger

# Required to instantiate the topology builder class.
from lib.micronet_compat import Topo

pytestmark = [pytest.mark.bgpd, pytest.mark.ospfd]

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

        # create ExaBGP peers
        for peer_num in range(1, 5):
            tgen.add_exabgp_peer(
                "peer{}".format(peer_num),
                ip="192.168.101.{}".format(peer_num + 2),
                defaultRoute="via 192.168.101.1",
            )

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

        # Add ExaBGP peers to sw4
        tgen.gears["peer1"].add_link(tgen.gears["sw4"])
        tgen.gears["peer2"].add_link(tgen.gears["sw4"])
        tgen.gears["peer3"].add_link(tgen.gears["sw4"])
        tgen.gears["peer4"].add_link(tgen.gears["sw4"])


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
    for rname, router in router_list.items():
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

    tgen.net["r1"].cmd(
        'vtysh -c "conf t" -c "router bgp 65000" -c "bgp shutdown message ABCDabcd"'
    )

    # Check BGP Summary on local and remote routers
    for rtrNum in [1, 2, 4]:
        logger.info(
            "Checking BGP Summary after shutdown of R1 BGP on router r{}".format(rtrNum)
        )

        router = tgen.gears["r{}".format(rtrNum)]
        reffile = os.path.join(CWD, "r{}/bgp_shutdown_summary.json".format(rtrNum))
        expected = json.loads(open(reffile).read())

        test_func = functools.partial(
            topotest.router_json_cmp, router, "show ip bgp summary json", expected
        )
        _, res = topotest.run_and_expect(test_func, None, count=60, wait=2)
        assertmsg = "BGP sessions on router R{} are in incorrect state (not down as expected?)".format(
            rtrNum
        )
        assert res is None, assertmsg


def test_bgp_shutdown_message():
    "Test BGP Peer Shutdown Message"

    tgen = get_topogen()

    # Skip if previous fatal error condition is raised
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    for rtrNum in [2, 4]:
        logger.info("Checking BGP shutdown received on router r{}".format(rtrNum))

        shut_message = tgen.net["r{}".format(rtrNum)].cmd(
            'tail bgpd.log | grep "NOTIFICATION.*Cease/Administratively Shutdown"'
        )
        assertmsg = "BGP shutdown message not received on router R{}".format(rtrNum)
        assert shut_message != "", assertmsg

        m = re.search(".*([0-9]+ bytes[ 0-9a-fA-F]+)", shut_message)
        if m:
            found = m.group(1)
        else:
            found = ""
        assertmsg = "Incorrect BGP shutdown message received on router R{}".format(
            rtrNum
        )
        assert found == "8 bytes 41 42 43 44 61 62 63 64", assertmsg

    # tgen.mininet_cli()


def test_bgp_no_shutdown():
    "Test BGP instance no shutdown"

    tgen = get_topogen()

    # Skip if previous fatal error condition is raised
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    tgen.net["r1"].cmd('vtysh -c "conf t" -c "router bgp 65000" -c "no bgp shutdown"')

    # Check BGP Summary on local and remote routers
    for rtrNum in [1, 2, 4]:
        logger.info(
            "Checking BGP Summary after removing bgp shutdown on router r1 on router r{}".format(
                rtrNum
            )
        )

        router = tgen.gears["r{}".format(rtrNum)]
        reffile = os.path.join(CWD, "r{}/bgp_summary.json".format(rtrNum))
        expected = json.loads(open(reffile).read())

        test_func = functools.partial(
            topotest.router_json_cmp, router, "show ip bgp summary json", expected
        )
        _, res = topotest.run_and_expect(test_func, None, count=60, wait=2)
        assertmsg = "BGP sessions on router R{} are in incorrect state (not down as expected?)".format(
            rtrNum
        )
        assert res is None, assertmsg


def test_bgp_metric_config():
    "Test BGP Changing metric values in route-maps"

    tgen = get_topogen()

    # Skip if previous fatal error condition is raised
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    logger.info("Configuring bgp route-maps on router r1 and r2 to update metric")

    # # Adding the following configuration to r1:
    # router bgp 65000
    #  address-family ipv4 unicast
    #   neighbor 192.168.0.2 route-map addmetric-in in
    #   neighbor 192.168.0.2 route-map addmetric-out out
    #   neighbor 192.168.101.2 route-map setmetric-in in
    #   neighbor 192.168.101.2 route-map setmetric-out out
    #  exit-address-family
    # !
    # ip prefix-list net1 seq 10 permit 192.168.101.0/24
    # ip prefix-list net2 seq 20 permit 192.168.1.0/24
    # !
    # route-map setmetric-in permit 10
    #  match ip address prefix-list net1
    #  set metric 111
    # !
    # route-map setmetric-in permit 20
    # !
    # route-map setmetric-out permit 10
    #  match ip address prefix-list net2
    #  set metric 1011
    # !
    # route-map setmetric-out permit 20
    # !
    # route-map addmetric-in permit 10
    #  set metric +11
    # !
    # route-map addmetric-out permit 10
    #  set metric +12
    # !

    tgen.net["r1"].cmd(
        'vtysh -c "conf t" -c "router bgp 65000" '
        + '-c "address-family ipv4 unicast" '
        + '-c "neighbor 192.168.0.2 route-map addmetric-in in" '
        + '-c "neighbor 192.168.0.2 route-map addmetric-out out" '
        + '-c "neighbor 192.168.101.2 route-map setmetric-in in" '
        + '-c "neighbor 192.168.101.2 route-map setmetric-out out" '
    )
    tgen.net["r1"].cmd(
        'vtysh -c "conf t" '
        + '-c "ip prefix-list net1 seq 10 permit 192.168.101.0/24" '
        + '-c "ip prefix-list net2 seq 20 permit 192.168.1.0/24"'
    )
    tgen.net["r1"].cmd(
        'vtysh -c "conf t" '
        + '-c "route-map setmetric-in permit 10" '
        + '-c "match ip address prefix-list net1" '
        + '-c "set metric 111" '
        + '-c "route-map setmetric-in permit 20"'
    )
    tgen.net["r1"].cmd(
        'vtysh -c "conf t" '
        + '-c "route-map setmetric-out permit 10" '
        + '-c "match ip address prefix-list net2" '
        + '-c "set metric 1011" '
        + '-c "route-map setmetric-out permit 20"'
    )
    tgen.net["r1"].cmd(
        'vtysh -c "conf t" '
        + '-c "route-map addmetric-in permit 10" '
        + '-c "set metric +11"'
    )
    tgen.net["r1"].cmd(
        'vtysh -c "conf t" '
        + '-c "route-map addmetric-out permit 10" '
        + '-c "set metric +12"'
    )

    # # Adding the following configuration to r2:
    # router bgp 65000
    #  address-family ipv4 unicast
    # neighbor 192.168.0.1 route-map subtractmetric-in in
    # neighbor 192.168.0.1 route-map subtractmetric-out out
    # neighbor 192.168.201.2 route-map setmetric-in in
    # neighbor 192.168.201.2 route-map setmetric-out out
    #  exit-address-family
    # !
    # ip prefix-list net1 seq 10 permit 192.168.201.0/24
    # ip prefix-list net2 seq 20 permit 192.168.2.0/24
    # !
    # route-map setmetric-in permit 10
    #  match ip address prefix-list net1
    #  set metric 222
    # !
    # route-map setmetric-in permit 20
    # !
    # route-map setmetric-out permit 10
    #  match ip address prefix-list net2
    #  set metric 2022
    # !
    # route-map setmetric-out permit 20
    # !
    # route-map subtractmetric-in permit 10
    #  set metric -22
    # !
    # route-map subtractmetric-out permit 10
    #  set metric -23
    # !

    tgen.net["r2"].cmd(
        'vtysh -c "conf t" -c "router bgp 65000" '
        + '-c "address-family ipv4 unicast" '
        + '-c "neighbor 192.168.0.1 route-map subtractmetric-in in" '
        + '-c "neighbor 192.168.0.1 route-map subtractmetric-out out" '
        + '-c "neighbor 192.168.201.2 route-map setmetric-in in" '
        + '-c "neighbor 192.168.201.2 route-map setmetric-out out" '
    )
    tgen.net["r2"].cmd(
        'vtysh -c "conf t" '
        + '-c "ip prefix-list net1 seq 10 permit 192.168.201.0/24" '
        + '-c "ip prefix-list net2 seq 20 permit 192.168.2.0/24" '
    )
    tgen.net["r2"].cmd(
        'vtysh -c "conf t" '
        + '-c "route-map setmetric-in permit 10" '
        + '-c "match ip address prefix-list net1" '
        + '-c "set metric 222" '
        + '-c "route-map setmetric-in permit 20"'
    )
    tgen.net["r2"].cmd(
        'vtysh -c "conf t" '
        + '-c "route-map setmetric-out permit 10" '
        + '-c "match ip address prefix-list net2" '
        + '-c "set metric 2022" '
        + '-c "route-map setmetric-out permit 20"'
    )
    tgen.net["r2"].cmd(
        'vtysh -c "conf t" '
        + '-c "route-map subtractmetric-in permit 10" '
        + '-c "set metric -22"'
    )
    tgen.net["r2"].cmd(
        'vtysh -c "conf t" '
        + '-c "route-map subtractmetric-out permit 10" '
        + '-c "set metric -23"'
    )

    # Clear IN the bgp neighbors to make sure the route-maps are applied
    tgen.net["r1"].cmd(
        'vtysh -c "clear ip bgp 192.168.0.2 in" ' + '-c "clear ip bgp 192.168.101.2 in"'
    )
    tgen.net["r2"].cmd(
        'vtysh -c "clear ip bgp 192.168.0.1 in" ' + '-c "clear ip bgp 192.168.201.2 in"'
    )

    # tgen.mininet_cli()

    # Checking BGP config - should show the bgp metric settings in the route-maps
    logger.info("Checking BGP configuration for correct 'set metric' values")

    setmetric111 = (
        tgen.net["r1"].cmd('vtysh -c "show running" | grep "^ set metric 111"').rstrip()
    )
    assertmsg = (
        "'set metric 111' configuration applied to R1, but not visible in configuration"
    )
    assert setmetric111 == " set metric 111", assertmsg

    setmetric222 = (
        tgen.net["r2"].cmd('vtysh -c "show running" | grep "^ set metric 222"').rstrip()
    )
    assertmsg = (
        "'set metric 222' configuration applied to R2, but not visible in configuration"
    )
    assert setmetric222 == " set metric 222", assertmsg


def test_bgp_metric_add_config():
    "Test BGP Changing metric values in route-maps"

    tgen = get_topogen()

    # Skip if previous fatal error condition is raised
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    logger.info("Checking BGP configuration for correct 'set metric' ADD value")

    setmetricP11 = (
        tgen.net["r1"].cmd('vtysh -c "show running" | grep "^ set metric +11"').rstrip()
    )
    assertmsg = (
        "'set metric +11' configuration applied to R1, but not visible in configuration"
    )
    assert setmetricP11 == " set metric +11", assertmsg


def test_bgp_metric_subtract_config():
    "Test BGP Changing metric values in route-maps"

    tgen = get_topogen()

    # Skip if previous fatal error condition is raised
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    logger.info("Checking BGP configuration for correct 'set metric' SUBTRACT value")

    setmetricM22 = (
        tgen.net["r2"].cmd('vtysh -c "show running" | grep "^ set metric -22"').rstrip()
    )
    assertmsg = (
        "'set metric -22' configuration applied to R2, but not visible in configuration"
    )
    assert setmetricM22 == " set metric -22", assertmsg


def test_bgp_set_metric():
    "Test setting metrics"

    tgen = get_topogen()

    # Skip if previous fatal error condition is raised
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    logger.info("Test absolute metric")

    # Check BGP Summary on local and remote routers
    for rtrNum in [1, 2, 4, 5]:
        logger.info("Checking metrics of BGP router on r{}".format(rtrNum))

        router = tgen.gears["r{}".format(rtrNum)]
        reffile = os.path.join(CWD, "r{}/show_bgp_metric_test.json".format(rtrNum))
        expected = json.loads(open(reffile).read())

        test_func = functools.partial(
            topotest.router_json_cmp, router, "show ip bgp json", expected
        )
        _, res = topotest.run_and_expect(test_func, None, count=60, wait=2)
        assertmsg = "BGP metrics on router r{} wrong".format(rtrNum)
        assert res is None, assertmsg


def test_bgp_remove_metric_rmaps():
    "Test removing route-maps with metric changes again"

    tgen = get_topogen()

    # Skip if previous fatal error condition is raised
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    logger.info("Test absolute metric")

    # Remove metric route-maps and relevant comfiguration

    tgen.net["r1"].cmd(
        'vtysh -c "conf t" -c "router bgp 65000" '
        + '-c "address-family ipv4 unicast" '
        + '-c "no neighbor 192.168.0.2 route-map addmetric-in in" '
        + '-c "no neighbor 192.168.0.2 route-map addmetric-out out" '
        + '-c "no neighbor 192.168.101.2 route-map setmetric-in in" '
        + '-c "no neighbor 192.168.101.2 route-map setmetric-out out" '
    )
    tgen.net["r1"].cmd(
        'vtysh -c "conf t" '
        + '-c "no ip prefix-list net1" '
        + '-c "no ip prefix-list net2"'
    )
    tgen.net["r1"].cmd('vtysh -c "conf t" ' + '-c "no route-map setmetric-in" ')
    tgen.net["r1"].cmd('vtysh -c "conf t" ' + '-c "no route-map setmetric-out" ')
    tgen.net["r1"].cmd('vtysh -c "conf t" ' + '-c "no route-map addmetric-in" ')
    tgen.net["r1"].cmd('vtysh -c "conf t" ' + '-c "no route-map addmetric-out" ')

    tgen.net["r2"].cmd(
        'vtysh -c "conf t" -c "router bgp 65000" '
        + '-c "address-family ipv4 unicast" '
        + '-c "no neighbor 192.168.0.1 route-map subtractmetric-in in" '
        + '-c "no neighbor 192.168.0.1 route-map subtractmetric-out out" '
        + '-c "no neighbor 192.168.201.2 route-map setmetric-in in" '
        + '-c "no neighbor 192.168.201.2 route-map setmetric-out out" '
    )
    tgen.net["r2"].cmd(
        'vtysh -c "conf t" '
        + '-c "no ip prefix-list net1" '
        + '-c "no ip prefix-list net2" '
    )
    tgen.net["r2"].cmd('vtysh -c "conf t" ' + '-c "no route-map setmetric-in" ')
    tgen.net["r2"].cmd('vtysh -c "conf t" ' + '-c "no route-map setmetric-out" ')
    tgen.net["r2"].cmd('vtysh -c "conf t" ' + '-c "no route-map addmetric-in" ')
    tgen.net["r2"].cmd('vtysh -c "conf t" ' + '-c "no route-map addmetric-out" ')

    # Clear IN the bgp neighbors to make sure the route-maps are applied
    tgen.net["r1"].cmd(
        'vtysh -c "clear ip bgp 192.168.0.2 in" ' + '-c "clear ip bgp 192.168.101.2 in"'
    )
    tgen.net["r2"].cmd(
        'vtysh -c "clear ip bgp 192.168.0.1 in" ' + '-c "clear ip bgp 192.168.201.2 in"'
    )

    # tgen.mininet_cli()

    # Check BGP Summary on local and remote routers
    for rtrNum in [1, 2]:
        logger.info("Checking metrics of BGP router on r{}".format(rtrNum))

        router = tgen.gears["r{}".format(rtrNum)]
        reffile = os.path.join(CWD, "r{}/show_bgp.json".format(rtrNum))
        expected = json.loads(open(reffile).read())

        test_func = functools.partial(
            topotest.router_json_cmp, router, "show ip bgp json", expected
        )
        _, res = topotest.run_and_expect(test_func, None, count=60, wait=2)
        assertmsg = "BGP routes on router r{} are wrong after removing metric route-maps".format(
            rtrNum
        )
        assert res is None, assertmsg


def test_bgp_norib():
    "Test BGP disable RIB (Zebra) Route Install"

    tgen = get_topogen()

    # Skip if previous fatal error condition is raised
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    logger.info("Configuring 'bgp no-rib' on router r1")

    tgen.net["r1"].cmd('vtysh -c "conf t" -c "bgp no-rib"')

    # Checking BGP config - should show the "bgp no-rib" under the router bgp section
    logger.info("Checking BGP configuration for 'bgp no-rib'")

    norib_cfg = (
        tgen.net["r1"].cmd('vtysh -c "show running bgpd" | grep "^bgp no-rib"').rstrip()
    )

    assertmsg = "'bgp no-rib' configuration applied, but not visible in configuration"
    assert norib_cfg == "bgp no-rib", assertmsg


def test_bgp_norib_routes():
    "Test Routes in Zebra and BGP with the 'bgp-norib' configuration"

    tgen = get_topogen()

    # Skip if previous fatal error condition is raised
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    # Checking local BGP routes - they need to be gone from Zebra
    logger.info("Checking Zebra routes after removing bgp shutdown on router r1")

    router = tgen.gears["r1"]
    reffile = os.path.join(CWD, "r1/ip_route_norib.json")
    expected = json.loads(open(reffile).read())

    test_func = functools.partial(
        topotest.router_json_cmp, router, "show ip route json", expected
    )
    _, res = topotest.run_and_expect(test_func, None, count=30, wait=2)
    assertmsg = "Zebra IPv4 Routes after configuring 'bgp no-rib' (There should be no BGP routes in Zebra anymore)"
    assert res is None, assertmsg

    # Check BGP Summary on local and remote routers
    for rtrNum in [1, 2, 4]:
        logger.info(
            "Checking BGP Summary after 'bgp no-rib' on router r1 on router r{}".format(
                rtrNum
            )
        )

        router = tgen.gears["r{}".format(rtrNum)]
        reffile = os.path.join(CWD, "r{}/bgp_summary.json".format(rtrNum))
        expected = json.loads(open(reffile).read())

        test_func = functools.partial(
            topotest.router_json_cmp, router, "show ip bgp summary json", expected
        )
        _, res = topotest.run_and_expect(test_func, None, count=30, wait=2)
        assertmsg = "BGP sessions on router R{} has incorrect routes after adding 'bgp no-rib on r1'".format(
            rtrNum
        )
        assert res is None, assertmsg

    # tgen.mininet_cli()


def test_bgp_disable_norib():
    "Test BGP disabling the no-RIB (Zebra) Route Install"

    tgen = get_topogen()

    # Skip if previous fatal error condition is raised
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    logger.info("Configuring 'no bgp no-rib' on router r1")

    tgen.net["r1"].cmd('vtysh -c "conf t" -c "no bgp no-rib"')

    # Checking BGP config - should show the "bgp no-rib" under the router bgp section
    logger.info("Checking BGP configuration for 'bgp no-rib'")

    norib_cfg = (
        tgen.net["r1"]
        .cmd('vtysh -c "show running bgpd" | grep "^ bgp no-rib"')
        .rstrip()
    )

    assertmsg = (
        "'no bgp no-rib'configuration applied, but still visible in configuration"
    )
    assert norib_cfg == "", assertmsg


def test_bgp_disable_norib_routes():
    "Test Routes in Zebra and BGP with the 'bgp-norib' configuration"

    tgen = get_topogen()

    # Skip if previous fatal error condition is raised
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    # Checking local BGP routes - they need to be gone from Zebra
    logger.info("Checking Zebra routes after removing bgp shutdown on router r1")

    router = tgen.gears["r1"]
    reffile = os.path.join(CWD, "r1/ip_route.json")
    expected = json.loads(open(reffile).read())

    test_func = functools.partial(
        topotest.router_json_cmp, router, "show ip route json", expected
    )
    _, res = topotest.run_and_expect(test_func, None, count=30, wait=2)
    assertmsg = "Zebra IPv4 Routes wrong after removing the 'bgp no-rib'"
    assert res is None, assertmsg

    # Check BGP Summary on local and remote routers
    for rtrNum in [1, 2, 4]:
        logger.info(
            "Checking BGP Summary after removing the 'bgp no-rib' on router r1 on router r{}".format(
                rtrNum
            )
        )

        router = tgen.gears["r{}".format(rtrNum)]
        reffile = os.path.join(CWD, "r{}/bgp_summary.json".format(rtrNum))
        expected = json.loads(open(reffile).read())

        test_func = functools.partial(
            topotest.router_json_cmp, router, "show ip bgp summary json", expected
        )
        _, res = topotest.run_and_expect(test_func, None, count=30, wait=2)
        assertmsg = "BGP sessions on router R{} has incorrect routes after removing 'bgp no-rib on r1'".format(
            rtrNum
        )
        assert res is None, assertmsg

    # tgen.mininet_cli()


def test_bgp_delayopen_without():
    "Optional test of BGP functionality and behaviour without DelayOpenTimer enabled to establish a reference for following tests"
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    # part 1: no delay r1 <=> no delay r4
    logger.info(
        "Starting optional test of BGP functionality without DelayOpenTimer enabled to establish a reference for following tests"
    )

    # 1.1 enable peering shutdown
    logger.info("Enable shutdown of peering between r1 and r4")
    tgen.net["r1"].cmd(
        'vtysh -c "conf t" -c "router bgp 65000" -c "neighbor 192.168.101.2 shutdown"'
    )
    tgen.net["r4"].cmd(
        'vtysh -c "conf t" -c "router bgp 65100" -c "neighbor 192.168.101.1 shutdown"'
    )

    # 1.2 wait for peers to shut down (poll output)
    for router_num in [1, 4]:
        logger.info(
            "Checking BGP summary after enabling shutdown of peering on r{}".format(
                router_num
            )
        )
        router = tgen.gears["r{}".format(router_num)]
        reffile = os.path.join(
            CWD, "r{}/bgp_delayopen_summary_shutdown.json".format(router_num)
        )
        expected = json.loads(open(reffile).read())
        test_func = functools.partial(
            topotest.router_json_cmp, router, "show ip bgp summary json", expected
        )
        _, res = topotest.run_and_expect(test_func, None, count=3, wait=1)
        assertmsg = "BGP session on r{} did not shut down peer".format(router_num)
        assert res is None, assertmsg

    # 1.3 disable peering shutdown
    logger.info("Disable shutdown of peering between r1 and r4")
    tgen.net["r1"].cmd(
        'vtysh -c "conf t" -c "router bgp 65000" -c "no neighbor 192.168.101.2 shutdown"'
    )
    tgen.net["r4"].cmd(
        'vtysh -c "conf t" -c "router bgp 65100" -c "no neighbor 192.168.101.1 shutdown"'
    )

    # 1.4 wait for peers to establish connection (poll output)
    for router_num in [1, 4]:
        logger.info(
            "Checking BGP summary after disabling shutdown of peering on r{}".format(
                router_num
            )
        )
        router = tgen.gears["r{}".format(router_num)]
        reffile = os.path.join(
            CWD, "r{}/bgp_delayopen_summary_established.json".format(router_num)
        )
        expected = json.loads(open(reffile).read())
        test_func = functools.partial(
            topotest.router_json_cmp, router, "show ip bgp summary json", expected
        )
        _, res = topotest.run_and_expect(test_func, None, count=5, wait=1)
        assertmsg = (
            "BGP session on r{} did not establish a connection with peer".format(
                router_num
            )
        )
        assert res is None, assertmsg

    # tgen.mininet_cli()

    # end test_bgp_delayopen_without


def test_bgp_delayopen_singular():
    "Test of BGP functionality and behaviour with DelayOpenTimer enabled on one side of the peering"

    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    # part 2: delay 240s r1 <=> no delay r4
    logger.info(
        "Starting test of BGP functionality and behaviour with DelayOpenTimer enabled on one side of the peering"
    )

    # 2.1 enable peering shutdown
    logger.info("Enable shutdown of peering between r1 and r4")
    tgen.net["r1"].cmd(
        'vtysh -c "conf t" -c "router bgp 65000" -c "neighbor 192.168.101.2 shutdown"'
    )
    tgen.net["r4"].cmd(
        'vtysh -c "conf t" -c "router bgp 65100" -c "neighbor 192.168.101.1 shutdown"'
    )

    # 2.2 wait for peers to shut down (poll output)
    for router_num in [1, 4]:
        logger.info(
            "Checking BGP summary after disabling shutdown of peering on r{}".format(
                router_num
            )
        )
        router = tgen.gears["r{}".format(router_num)]
        reffile = os.path.join(
            CWD, "r{}/bgp_delayopen_summary_shutdown.json".format(router_num)
        )
        expected = json.loads(open(reffile).read())
        test_func = functools.partial(
            topotest.router_json_cmp, router, "show ip bgp summary json", expected
        )
        _, res = topotest.run_and_expect(test_func, None, count=3, wait=1)
        assertmsg = "BGP session on r{} did not shut down peer".format(router_num)
        assert res is None, assertmsg

    # 2.3 set delayopen on R1 to 240
    logger.info("Setting DelayOpenTime for neighbor r4 to 240 seconds on r1")
    tgen.net["r1"].cmd(
        'vtysh -c "conf t" -c "router bgp 65000" -c "neighbor 192.168.101.2 timers delayopen 240"'
    )

    # 2.4 check config (poll output)
    logger.info("Checking BGP neighbor configuration after setting DelayOpenTime on r1")
    router = tgen.gears["r1"]
    reffile = os.path.join(CWD, "r1/bgp_delayopen_neighbor.json")
    expected = json.loads(open(reffile).read())
    test_func = functools.partial(
        topotest.router_json_cmp, router, "show bgp neighbors json", expected
    )
    _, res = topotest.run_and_expect(test_func, None, count=3, wait=1)
    assertmsg = "BGP session on r1 failed to set DelayOpenTime for r4"
    assert res is None, assertmsg

    # 2.5 disable peering shutdown
    logger.info("Disable shutdown of peering between r1 and r4")
    tgen.net["r1"].cmd(
        'vtysh -c "conf t" -c "router bgp 65000" -c "no neighbor 192.168.101.2 shutdown"'
    )
    tgen.net["r4"].cmd(
        'vtysh -c "conf t" -c "router bgp 65100" -c "no neighbor 192.168.101.1 shutdown"'
    )

    # 2.6 wait for peers to establish connection (poll output)
    for router_num in [1, 4]:
        logger.info(
            "Checking BGP summary after disabling shutdown of peering on r{}".format(
                router_num
            )
        )
        router = tgen.gears["r{}".format(router_num)]
        reffile = os.path.join(
            CWD, "r{}/bgp_delayopen_summary_established.json".format(router_num)
        )
        expected = json.loads(open(reffile).read())
        test_func = functools.partial(
            topotest.router_json_cmp, router, "show ip bgp summary json", expected
        )
        _, res = topotest.run_and_expect(test_func, None, count=5, wait=1)
        assertmsg = (
            "BGP session on r{} did not establish a connection with peer".format(
                router_num
            )
        )
        assert res is None, assertmsg

    # 2.7 unset delayopen on R1
    logger.info("Disabling DelayOpenTimer for neighbor r4 on r1")
    tgen.net["r1"].cmd(
        'vtysh -c "conf t" -c "router bgp 65000" -c "no neighbor 192.168.101.2 timers delayopen"'
    )

    # 2.8 check config (poll output)
    logger.info(
        "Checking BGP neighbor configuration after disabling DelayOpenTimer on r1"
    )
    delayopen_cfg = (
        tgen.net["r1"]
        .cmd('vtysh -c "show bgp neighbors json" | grep "DelayOpenTimeMsecs"')
        .rstrip()
    )
    assertmsg = "BGP session on r1 failed disable DelayOpenTimer for peer r4"
    assert delayopen_cfg == "", assertmsg

    # tgen.mininet_cli()

    # end test_bgp_delayopen_singular


def test_bgp_delayopen_dual():
    "Test of BGP functionality and behaviour with DelayOpenTimer enabled on both sides of the peering with different timer intervals"
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    # part 3: delay 60s R2 <=> delay 30s R5
    logger.info(
        "Starting test of BGP functionality and behaviour with DelayOpenTimer enabled on both sides of the peering with different timer intervals"
    )

    # 3.1 enable peering shutdown
    logger.info("Enable shutdown of peering between r2 and r5")
    tgen.net["r2"].cmd(
        'vtysh -c "conf t" -c "router bgp 65000" -c "neighbor 192.168.201.2 shutdown"'
    )
    tgen.net["r5"].cmd(
        'vtysh -c "conf t" -c "router bgp 65200" -c "neighbor 192.168.201.1 shutdown"'
    )

    # 3.2 wait for peers to shut down (pool output)
    for router_num in [2, 5]:
        logger.info(
            "Checking BGP summary after disabling shutdown of peering on r{}".format(
                router_num
            )
        )
        router = tgen.gears["r{}".format(router_num)]
        reffile = os.path.join(
            CWD, "r{}/bgp_delayopen_summary_shutdown.json".format(router_num)
        )
        expected = json.loads(open(reffile).read())
        test_func = functools.partial(
            topotest.router_json_cmp, router, "show ip bgp summary json", expected
        )
        _, res = topotest.run_and_expect(test_func, None, count=3, wait=1)
        assertmsg = "BGP session on r{} did not shut down peer".format(router_num)
        assert res is None, assertmsg

    # 3.3 set delayopen on R2 to 60s and on R5 to 30s
    logger.info("Setting DelayOpenTime for neighbor r5 to 60 seconds on r2")
    tgen.net["r2"].cmd(
        'vtysh -c "conf t" -c "router bgp 65000" -c "neighbor 192.168.201.2 timers delayopen 60"'
    )
    logger.info("Setting DelayOpenTime for neighbor r2 to 30 seconds on r5")
    tgen.net["r5"].cmd(
        'vtysh -c "conf t" -c "router bgp 65200" -c "neighbor 192.168.201.1 timers delayopen 30"'
    )

    # 3.4 check config (poll output)
    for router_num in [2, 5]:
        logger.info(
            "Checking BGP neighbor configuration after setting DelayOpenTime on r{}i".format(
                router_num
            )
        )
        router = tgen.gears["r{}".format(router_num)]
        reffile = os.path.join(
            CWD, "r{}/bgp_delayopen_neighbor.json".format(router_num)
        )
        expected = json.loads(open(reffile).read())
        test_func = functools.partial(
            topotest.router_json_cmp, router, "show bgp neighbors json", expected
        )
        _, res = topotest.run_and_expect(test_func, None, count=3, wait=1)
        assertmsg = "BGP session on r{} failed to set DelayOpenTime".format(router_num)
        assert res is None, assertmsg

    ## 3.5 disable peering shutdown
    logger.info("Disable shutdown of peering between r2 and r5")
    tgen.net["r2"].cmd(
        'vtysh -c "conf t" -c "router bgp 65000" -c "no neighbor 192.168.201.2 shutdown"'
    )
    tgen.net["r5"].cmd(
        'vtysh -c "conf t" -c "router bgp 65200" -c "no neighbor 192.168.201.1 shutdown"'
    )

    ## 3.6 wait for peers to reach connect or active state (poll output)
    delay_start = int(time.time())
    for router_num in [2, 5]:
        logger.info(
            "Checking BGP summary after disabling shutdown of peering on r{}".format(
                router_num
            )
        )
        router = tgen.gears["r{}".format(router_num)]
        reffile = os.path.join(
            CWD, "r{}/bgp_delayopen_summary_connect.json".format(router_num)
        )
        expected = json.loads(open(reffile).read())
        test_func = functools.partial(
            topotest.router_json_cmp, router, "show ip bgp summary json", expected
        )
        _, res = topotest.run_and_expect(test_func, None, count=3, wait=1)
        assertmsg = "BGP session on r{} did not enter Connect state with peer".format(
            router_num
        )
        assert res is None, assertmsg

    ## 3.7 wait for peers to establish connection (poll output)
    for router_num in [2, 5]:
        logger.info(
            "Checking BGP summary after disabling shutdown of peering on r{}".format(
                router_num
            )
        )
        router = tgen.gears["r{}".format(router_num)]
        reffile = os.path.join(
            CWD, "r{}/bgp_delayopen_summary_established.json".format(router_num)
        )
        expected = json.loads(open(reffile).read())
        test_func = functools.partial(
            topotest.router_json_cmp, router, "show ip bgp summary json", expected
        )
        _, res = topotest.run_and_expect(test_func, None, count=35, wait=1)
        assertmsg = (
            "BGP session on r{} did not establish a connection with peer".format(
                router_num
            )
        )
        assert res is None, assertmsg

    delay_stop = int(time.time())
    assertmsg = "BGP peering between r2 and r5 was established before DelayOpenTimer (30sec) on r2 could expire"
    assert (delay_stop - delay_start) > 30, assertmsg

    # 3.8 unset delayopen on R2 and R5
    logger.info("Disabling DelayOpenTimer for neighbor r5 on r2")
    tgen.net["r2"].cmd(
        'vtysh -c "conf t" -c "router bgp 65000" -c "no neighbor 192.168.201.2 timers delayopen"'
    )
    logger.info("Disabling DelayOpenTimer for neighbor r2 on r5")
    tgen.net["r5"].cmd(
        'vtysh -c "conf t" -c "router bgp 65200" -c "no neighbor 192.168.201.1 timers delayopen"'
    )

    # 3.9 check config (poll output)
    for router_num in [2, 5]:
        logger.info(
            "Checking BGP neighbor configuration after disabling DelayOpenTimer on r{}".format(
                router_num
            )
        )
        delayopen_cfg = (
            tgen.net["r{}".format(router_num)]
            .cmd('vtysh -c "show bgp neighbors json" | grep "DelayOpenTimeMsecs"')
            .rstrip()
        )
        assertmsg = "BGP session on r{} failed disable DelayOpenTimer".format(
            router_num
        )
        assert delayopen_cfg == "", assertmsg

    # tgen.mininet_cli()

    # end test_bgp_delayopen_dual


def test_bgp_dampening_setup():
    "BGP route-flap dampening test setup"

    # This test starts four ExaBGP peers, adds them as neighbors to the
    # configuration of router r1 and checks if connections get established.

    tgen = get_topogen()

    # Skip if previous fatal error condition is raised
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    logger.info("Starting BGP route-flap dampening test setup")

    # Start ExaBGP peers connected to r1 via switch 4
    logger.info("Starting ExaBGP peers")
    for peer_num in range(1, 5):
        logger.info("Creating named pipe for ExaBGP peer peer{}".format(peer_num))
        fifo_in = "/var/run/exabgp_peer{}.in".format(peer_num)
        if os.path.exists(fifo_in):
            os.remove(fifo_in)
        os.mkfifo(fifo_in, 0o777)
        logger.info("Starting ExaBGP on peer peer{}".format(peer_num))
        peer = tgen.gears["peer{}".format(peer_num)]
        peer_dir = os.path.join(CWD, "peer{}".format(peer_num))
        env_file = os.path.join(CWD, "exabgp.env")
        peer.start(peer_dir, env_file)

    # Add ExaBGP peers to configuration of router r2
    logger.info("Adding ExaBGP peers as neighbors to configuration of router r2")
    tgen.net["r1"].cmd(
        'vtysh -c "conf t" -c "router bgp 65000" -c "neighbor 192.168.101.3 remote-as 65403"'
    )
    tgen.net["r1"].cmd(
        'vtysh -c "conf t" -c "router bgp 65000" -c "address-family ipv4 unicast" -c "neighbor 192.168.101.3 route-map testmap-in"'
    )
    tgen.net["r1"].cmd(
        'vtysh -c "conf t" -c "router bgp 65000" -c "address-family ipv4 unicast" -c "neighbor 192.168.101.3 route-map testmap-out"'
    )
    tgen.net["r1"].cmd(
        'vtysh -c "conf t" -c "router bgp 65000" -c "neighbor 192.168.101.4 remote-as 65404"'
    )
    tgen.net["r1"].cmd(
        'vtysh -c "conf t" -c "router bgp 65000" -c "address-family ipv4 unicast" -c "neighbor 192.168.101.4 route-map testmap-in"'
    )
    tgen.net["r1"].cmd(
        'vtysh -c "conf t" -c "router bgp 65000" -c "address-family ipv4 unicast" -c "neighbor 192.168.101.4 route-map testmap-out"'
    )
    tgen.net["r1"].cmd(
        'vtysh -c "conf t" -c "router bgp 65000" -c "neighbor 192.168.101.5 remote-as 65405"'
    )
    tgen.net["r1"].cmd(
        'vtysh -c "conf t" -c "router bgp 65000" -c "address-family ipv4 unicast" -c "neighbor 192.168.101.5 route-map testmap-in"'
    )
    tgen.net["r1"].cmd(
        'vtysh -c "conf t" -c "router bgp 65000" -c "address-family ipv4 unicast" -c "neighbor 192.168.101.5 route-map testmap-out"'
    )
    tgen.net["r1"].cmd(
        'vtysh -c "conf t" -c "router bgp 65000" -c "neighbor 192.168.101.6 remote-as 65406"'
    )
    tgen.net["r1"].cmd(
        'vtysh -c "conf t" -c "router bgp 65000" -c "address-family ipv4 unicast" -c "neighbor 192.168.101.6 route-map testmap-in"'
    )
    tgen.net["r1"].cmd(
        'vtysh -c "conf t" -c "router bgp 65000" -c "address-family ipv4 unicast" -c "neighbor 192.168.101.6 route-map testmap-out"'
    )

    # Check if exabgp peers are up and running
    logger.info("Checking for established connections to ExaBGP peers on router r1")
    router = tgen.gears["r1"]
    reffile = os.path.join(CWD, "r1/bgp_damp_setup.json")
    expected = json.loads(open(reffile).read())
    test_func = functools.partial(
        topotest.router_json_cmp, router, "show ip bgp summary json", expected
    )
    _, res = topotest.run_and_expect(test_func, None, count=10, wait=1)
    assertmsg = (
        "BGP session on r1 did not establish connections with one ore more ExaBGP peers"
    )
    assert res is None, assertmsg

    # end test_bgp_dampening_setup


def test_bgp_dampening_route_announce():
    "Test of BGP route-flap dampening route announcement"

    # This test checks if the four ExaBGP peers can announce routes to router
    # r1 and if these routes get forwarded to router r2.

    tgen = get_topogen()

    # Skip if previous fatal error condition is raised
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    logger.info("Starting test of BGP route-flap dampening route announcement")

    # Announce routes on exabgp peers to r2
    logger.info("Announcing routes on ExaBGP peers to r1")
    for prefix_iter in range(1, 5):
        for peer_num in range(1, 5):
            pipe = open("/run/exabgp_peer{}.in".format(peer_num), "w")
            with pipe:
                pipe.write(
                    "announce route 192.168.{}{}.0/24 next-hop 192.168.101.{}\n".format(
                        (peer_num + 2), prefix_iter, (peer_num + 2)
                    )
                )
                pipe.close()
                sleep(0.1)  # ExaBGP API command processing delay

    # Check if routes announced by ExaBGP peers are present in RIB of router r1
    logger.info(
        "Checking if routes announced by ExaBGP peers are present in RIB of router r1"
    )
    router = tgen.gears["r1"]
    reffile = os.path.join(CWD, "r1/bgp_damp_announced.json")
    expected = json.loads(open(reffile).read())
    test_func = functools.partial(
        topotest.router_json_cmp, router, "show ip bgp json", expected
    )
    _, res = topotest.run_and_expect(test_func, None, count=10, wait=1)
    assertmsg = (
        "BGP session on router r1 did not receive routes announced by ExaBGP peers"
    )
    assert res is None, assertmsg

    # Check if routes announced by ExaBGP peers to router r1 have been forwarded
    # and are now present in RIB of router r2
    logger.info(
        "Checking if forwarded routes announced by ExaBGP peers are present in RIB of router r2"
    )
    router = tgen.gears["r2"]
    reffile = os.path.join(CWD, "r2/bgp_damp_announced.json")
    expected = json.loads(open(reffile).read())
    test_func = functools.partial(
        topotest.router_json_cmp, router, "show ip bgp json", expected
    )
    _, res = topotest.run_and_expect(test_func, None, count=10, wait=1)
    assertmsg = "BGP session on router r2 did not receive routes announced by ExaBGP peers forwarded by router r1"
    assert res is None, assertmsg

    # end test_bgp_dampening_route_announce


def test_bgp_dampening_disabled():
    "Test of BGP route-flapping with dampening disabled"

    # This test verifies that flapped routes do not get withdrawn from the RIB
    # of router r1 if dampening is disabled.

    tgen = get_topogen()

    # Skip if previous fatal error condition is raised
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    logger.info("Starting test of BGP route-flapping with dampening disabled")

    # Flapping routes on ExaBGP peer peer1
    logger.info(
        "Flapping routes on ExaBGP peer peer1 with route-flap dampening disabled"
    )
    for _ in range(1, 5):
        for prefix_iter in range(1, 5):
            pipe = open("/run/exabgp_peer1.in", "w")
            with pipe:
                pipe.write(
                    "withdraw route 192.168.3{}.0/24 next-hop 192.168.101.3\n".format(
                        prefix_iter
                    )
                )
                pipe.close()
                sleep(0.1)  # ExaBGP API command processing delay
        sleep(1)  # Give the BGP session on router r1 time to process routes
        for prefix_iter in range(1, 5):
            pipe = open("/run/exabgp_peer1.in", "w")
            with pipe:
                pipe.write(
                    "announce route 192.168.3{}.0/24 next-hop 192.168.101.3\n".format(
                        prefix_iter
                    )
                )
                pipe.close()
                sleep(0.1)  # ExaBGP API command processing delay

    # Verify flapped routes are still present in RIB of router r1
    logger.info(
        "Verifying that the flapped routes are still present in RIB of router r1"
    )
    router = tgen.gears["r1"]
    reffile = os.path.join(CWD, "r1/bgp_damp_announced.json")
    expected = json.loads(open(reffile).read())
    test_func = functools.partial(
        topotest.router_json_cmp, router, "show ip bgp json", expected
    )
    _, res = topotest.run_and_expect(test_func, None, count=10, wait=1)
    assertmsg = "BGP session on router r1 removed flapped routes despite route-flap dampening being disabled"
    assert res is None, assertmsg

    # end test_bgp_dampening_disabled


def test_bgp_dampening_config():
    "Test of BGP route-flap dampening configuration"

    # This test adds peer-group group1 with peers peer1 and peer2 to the
    # configuration of router r1, sets up dampening configurations with
    # different profiles and verifies the configured dampening parameters.

    tgen = get_topogen()
    r_1 = tgen.net["r1"]

    # Skip if previous fatal error condition is raised
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    logger.info("Starting test of BGP route-flap dampening configuration")

    # Add peer-group group1 with peers peer1 and peer2
    logger.info(
        "Creating peer-group group1 and adding ExaBGP peers peer1 and peer2 to it"
    )
    r_1.cmd('vtysh -c "conf t" -c "router bgp 65000" -c "neighbor group1 peer-group"')
    r_1.cmd(
        'vtysh -c "conf t" -c "router bgp 65000" -c "neighbor 192.168.101.3 peer-group group1"'
    )  # peer1
    r_1.cmd(
        'vtysh -c "conf t" -c "router bgp 65000" -c "neighbor 192.168.101.4 peer-group group1"'
    )  # peer2

    # Enable different dampening profiles for peer1, peer3, group1 and global
    # configuration
    logger.info(
        "Enabling different dampening profiles for peer1, peer3, group1 and global configuration"
    )
    r_1.cmd(
        'vtysh -c "conf t" -c "router bgp 65000" -c "address-family ipv4 unicast" -c "bgp dampening 30 300 900 90"'
    )
    r_1.cmd(
        'vtysh -c "conf t" -c "router bgp 65000" -c "address-family ipv4 unicast" -c "neighbor group1 dampening 20 200 600 60"'
    )
    r_1.cmd(
        'vtysh -c "conf t" -c "router bgp 65000" -c "address-family ipv4 unicast" -c "neighbor 192.168.101.3 dampening 10 100 300 30"'
    )  # peer1
    r_1.cmd(
        'vtysh -c "conf t" -c "router bgp 65000" -c "address-family ipv4 unicast" -c "neighbor 192.168.101.5 dampening 10 100 300 30"'
    )  # peer3

    # Verify route-flap dampening configuration
    logger.info("Verifying route-flap dampening configuration on router r1")
    vtyout = r_1.cmd('vtysh -c "show running-config"')
    assertmsg = "BGP Session on r1 does not show enabled global route-flap dampening in running configuration"
    assert re.search("bgp dampening 30 300 900 90", vtyout), assertmsg
    assertmsg = "BGP Session on r1 does not show route-flap dampening enabled for peer-group group1 in running configuration"
    assert re.search("neighbor group1 dampening 20 200 600 60", vtyout), assertmsg
    assertmsg = "BGP Session on r1 does not show route-flap dampening enabled for peer peer1 in running configuration"
    assert re.search(
        "neighbor 192.168.101.3 dampening 10 100 300 30", vtyout
    ), assertmsg
    assertmsg = "BGP Session on r1 does not show route-flap dampening enabled for peer peer3 in running configuration"
    assert re.search(
        "neighbor 192.168.101.5 dampening 10 100 300 30", vtyout
    ), assertmsg

    # end test_bgp_dampening_config


def test_bgp_dampening_profile_peer_over_group():
    "Test of BGP route-flap dampening profile preferences: peer over group"

    # This test verifies that the dampening profile of a peer takes precedence
    # over the dampening profile of its peer-group by flapping the peers routes
    # until dampened and comparing the reuse times to the one specified in the
    # dampening configuration.

    tgen = get_topogen()
    r_1 = tgen.net["r1"]

    # Skip if previous fatal error condition is raised
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    logger.info(
        "Starting test of BGP route-flap dampening profile preferences: peer over group"
    )

    # Flapping routes on ExaBGP peer peer1
    logger.info(
        "Flapping routes on ExaBGP peer peer1 with route-flap dampening enabled"
    )
    for _ in range(1, 5):
        for prefix_iter in range(1, 5):
            pipe = open("/run/exabgp_peer1.in", "w")
            with pipe:
                pipe.write(
                    "withdraw route 192.168.3{}.0/24 next-hop 192.168.101.3\n".format(
                        prefix_iter
                    )
                )
                pipe.close()
                sleep(0.1)  # ExaBGP API command processing delay
        sleep(1)  # Give the BGP session on router r1 time to process routes
        for prefix_iter in range(1, 5):
            pipe = open("/run/exabgp_peer1.in", "w")
            with pipe:
                pipe.write(
                    "announce route 192.168.3{}.0/24 next-hop 192.168.101.3\n".format(
                        prefix_iter
                    )
                )
                pipe.close()
                sleep(0.1)  # ExaBGP API command processing delay

    # Check damped paths on r1 for routes of peer1 witn peer profile
    logger.info(
        "Checking if router r1 used the correct dampening profile on routes flapped by ExaBGP peer peer1"
    )
    sleep(5)  # Wait 5 seconds for paths to show up in dampened-paths list
    vtyout = r_1.cmd('vtysh -c "show ip bgp dampening dampened-paths"')
    routes = re.findall(r"\*d 192\.168\.3\d\.0\/24.*", vtyout)
    assertmsg = (
        "BGP session on router r1 did not dampen routes flapped by ExaBGP peer peer1"
    )
    assert len(routes) == 4, assertmsg
    assertmsg = "BGP session on router r1 used wrong dampening profile for a route flapped by ExaBGP peer peer1"
    for route in routes:
        assert (int(route.split()[3].split(":")[0]) == 0) and (  # hours of reuse time
            35 > int(route.split()[3].split(":")[1]) > 25
        ), assertmsg  # minutes of reuse time

    # end test_bgp_dampening_profile_peer_over_group


def test_bgp_dampening_profile_group_over_global():
    "Test of BGP route-flap dampening profile preferences: group over global"

    # This test verifies that the dampening profile of a peer-group takes
    # precedence over the global dampening profile by flapping the routes of a
    # peer-group member until dampened and comparing the reuse times to the one
    # specified in the dampening configuration.

    tgen = get_topogen()
    r_1 = tgen.net["r1"]

    # Skip if previous fatal error condition is raised
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    logger.info(
        "Starting test of BGP route-flap dampening profile preferences: group over global"
    )

    # Flapping routes on ExaBGP peer peer2
    logger.info(
        "Flapping routes on ExaBGP peer peer2 with route-flap dampening enabled"
    )
    for _ in range(1, 5):
        for prefix_iter in range(1, 5):
            pipe = open("/run/exabgp_peer2.in", "w")
            with pipe:
                pipe.write(
                    "withdraw route 192.168.4{}.0/24 next-hop 192.168.101.4\n".format(
                        prefix_iter
                    )
                )
                pipe.close()
                sleep(0.1)  # ExaBGP API command processing delay
        sleep(1)  # Give the BGP session on router r1 time to process routes
        for prefix_iter in range(1, 5):
            pipe = open("/run/exabgp_peer2.in", "w")
            with pipe:
                pipe.write(
                    "announce route 192.168.4{}.0/24 next-hop 192.168.101.4\n".format(
                        prefix_iter
                    )
                )
                pipe.close()
                sleep(0.1)  # ExaBGP API command processing delay

    # Check damped paths on r1 for routes of peer2 witn group profile
    logger.info(
        "Checking if router r1 used the correct dampening profile on routes flapped by ExaBGP peer peer2"
    )
    sleep(5)  # wait 5 seconds for paths to shop up in damp list
    vtyout = r_1.cmd('vtysh -c "show ip bgp dampening dampened-paths"')
    routes = re.findall(r"\*d 192\.168\.4\d\.0\/24.*", vtyout)
    assertmsg = (
        "BGP session on router r1 did not dampen routes flapped by ExaBGP peer peer2"
    )
    assert len(routes) == 4, assertmsg
    assertmsg = "BGP session on router r1 used wrong dampening profile for a route flapped by ExaBGP peer peer2"
    for route in routes:
        assert (int(route.split()[3].split(":")[0]) == 0) and (  # hours of reuse time
            65 > int(route.split()[3].split(":")[1]) > 55
        ), assertmsg  # minutes of reuse time

    # end test_bgp_dampening_profile_group_over_global


def test_bgp_dampening_profile_peer_over_global():
    "Test of BGP route-flap dampening profile preferences: peer over global"

    # This test verifies that the dampening profile of a peer takes precedence
    # over the global dampening profile by flapping the routes of the peer until
    # dampened and comparing the reuse times to the one specified in the
    # dampening configuration.

    tgen = get_topogen()
    r_1 = tgen.net["r1"]

    # Skip if previous fatal error condition is raised
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    logger.info(
        "Starting test of BGP route-flap dampening profile preferences: peer over global"
    )

    # Flapping routes on ExaBGP peer peer3
    logger.info(
        "Flapping routes on ExaBGP peer peer3 with route-flap dampening enabled"
    )
    for _ in range(1, 5):
        for prefix_iter in range(1, 5):
            pipe = open("/run/exabgp_peer3.in", "w")
            with pipe:
                pipe.write(
                    "withdraw route 192.168.5{}.0/24 next-hop 192.168.101.5\n".format(
                        prefix_iter
                    )
                )
                pipe.close()
                sleep(0.1)  # ExaBGP API command processing delay
        sleep(1)  # Give the BGP session on router r1 time to process routes
        for prefix_iter in range(1, 5):
            pipe = open("/run/exabgp_peer3.in", "w")
            with pipe:
                pipe.write(
                    "announce route 192.168.5{}.0/24 next-hop 192.168.101.5\n".format(
                        prefix_iter
                    )
                )
                pipe.close()
                sleep(0.1)  # ExaBGP API command processing delay

    # Check damped paths on r1 for routes of peer3 witn peer profile
    logger.info(
        "Checking if router r1 used the correct dampening profile on routes flapped by ExaBGP peer peer3"
    )
    sleep(5)  # wait 5 seconds for paths to shop up in damp list
    vtyout = r_1.cmd('vtysh -c "show ip bgp dampening dampened-paths"')
    routes = re.findall(r"\*d 192\.168\.5\d\.0\/24.*", vtyout)
    assertmsg = (
        "BGP session on router r1 did not dampen routes flapped by ExaBGP peer peer3"
    )
    assert len(routes) == 4, assertmsg
    assertmsg = "BGP session on router r1 used wrong dampening profile for a route flapped by ExaBGP peer peer3"
    for route in routes:
        assert (int(route.split()[3].split(":")[0]) == 0) and (  # hours of reuse time
            35 > int(route.split()[3].split(":")[1]) > 25
        ), assertmsg  # minutes of reuse time

    # end test_bgp_dampening_profile_peer_over_global


def test_bgp_dampening_profile_global():
    "Test of BGP route-flap dampening global profile"

    # This test verifies the application of the global dampening profile by
    # flapping the routes of a peer until dampened and comparing the reuse times
    # to the one specified in the dampening configuration.

    tgen = get_topogen()
    r_1 = tgen.net["r1"]

    # Skip if previous fatal error condition is raised
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    logger.info("Starting test of BGP route-flap dampening global profile")

    # Flapping routes on ExaBGP peer peer4
    logger.info(
        "Flapping routes on ExaBGP peer peer4 with route-flap dampening enabled"
    )
    for _ in range(1, 5):
        for prefix_iter in range(1, 5):
            pipe = open("/run/exabgp_peer4.in", "w")
            with pipe:
                pipe.write(
                    "withdraw route 192.168.6{}.0/24 next-hop 192.168.101.6\n".format(
                        prefix_iter
                    )
                )
                pipe.close()
                sleep(0.1)  # ExaBGP API command processing delay
        sleep(1)  # Give the BGP session on router r1 time to process routes
        for prefix_iter in range(1, 5):
            pipe = open("/run/exabgp_peer4.in", "w")
            with pipe:
                pipe.write(
                    "announce route 192.168.6{}.0/24 next-hop 192.168.101.6\n".format(
                        prefix_iter
                    )
                )
                pipe.close()
                sleep(0.1)  # ExaBGP API command processing delay

    # Check damped paths on r1 for routes of peer4 witn global profile
    logger.info(
        "Checking if router r1 used the global dampening profile on routes flapped by ExaBGP peer peer4"
    )
    sleep(5)  # wait 5 seconds for paths to shop up in damp list
    vtyout = r_1.cmd('vtysh -c "show ip bgp dampening dampened-paths"')
    routes = re.findall(r"\*d 192\.168\.6\d\.0\/24.*", vtyout)
    assertmsg = (
        "BGP session on router r1 did not dampen routes flapped by ExaBGP peer peer4"
    )
    assert len(routes) == 4, assertmsg
    assertmsg = "BGP session on router r1 did not use the global dampening profile for a route flapped by ExaBGP peer peer4"
    for route in routes:
        assert (int(route.split()[3].split(":")[0]) == 1) and (  # hours of reuse time
            35 > int(route.split()[3].split(":")[1]) > 25
        ), assertmsg  # minutes of reuse time

    # end test_bgp_dampening_profile_global


def test_bgp_dampening_withdaw():
    "Test BGP route-flap dampening route withdraw"

    # This test verifies that the withrawl of dampened routes from the RIB of
    # router r1 was propagated to router r2.

    tgen = get_topogen()

    # Skip if previous fatal error condition is raised
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    logger.info("Starting test of BGP route-flap dampening route withdraw")

    # Check if routes dampened on router r1 have been withdrawn from the RIB on
    # router r2
    logger.info(
        "Checking if routes dampened on router r1 have been withdrawn of RIB on router r2"
    )
    reffile = os.path.join(CWD, "r2/bgp_damp_withdrawn.json")
    expected = json.loads(open(reffile).read())
    test_func = functools.partial(
        topotest.router_json_cmp, tgen.gears["r2"], "show ip bgp json", expected
    )
    _, res = topotest.run_and_expect(test_func, None, count=5, wait=1)
    assertmsg = "BGP session on router r2 did not receive withdraw of routes dampened on router r1"
    assert res is None, assertmsg

    # end test_bgp_dampening_withdaw


def test_bgp_dampening_cleanup():
    "BGP route-flap dampening test cleanup"

    # This test cleans up after other tests associated with route-flap dampening
    # by disabling all dampening configurations, removing added peers and
    # peer-groups from the configuration on router r1, and shutting down ExaBGP
    # peers peer1, peer2 and peer3.

    tgen = get_topogen()
    r_1 = tgen.net["r1"]

    # Skip if previous fatal error condition is raised
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    logger.info("Starting BGP route-flap dampening test cleanup")

    # Disable all dampening configurations
    logger.info("Disabling all dampening configurations")
    r_1.cmd(
        'vtysh -c "conf t" -c "router bgp 65000" -c "address-family ipv4 unicast" -c "no bgp dampening"'
    )
    r_1.cmd(
        'vtysh -c "conf t" -c "router bgp 65000" -c "address-family ipv4 unicast" -c "no neighbor group1 dampening"'
    )
    r_1.cmd(
        'vtysh -c "conf t" -c "router bgp 65000" -c "address-family ipv4 unicast" -c "no neighbor 192.168.101.3 dampening"'
    )
    r_1.cmd(
        'vtysh -c "conf t" -c "router bgp 65000" -c "address-family ipv4 unicast" -c "no neighbor 192.168.101.5 dampening"'
    )

    # Remove ExaBGP peers from configuration of router r1
    logger.info("Removing ExaBGP peers from configuration of router r1")
    for router_num in range(3, 7):
        r_1.cmd(
            'vtysh -c "conf t" -c "router bgp 65000" -c "no neighbor 192.168.101.{}"'.format(
                router_num
            )
        )

    # Remove peer-group group1 from configuration of router r1
    logger.info("Removing peer-group group1 peers from configuration of router r1")
    r_1.cmd(
        'vtysh -c "conf t" -c "router bgp 65000" -c "no neighbor group1 peer-group"'
    )

    # Stop ExaBGP peers and remove associated named pipes
    logger.info("Stopping ExaBGP peers and removing associated named pipes")
    for peer_num in range(1, 5):
        logger.info("Terminating ExaBGP on peer peer{}".format(peer_num))
        peer = tgen.gears["peer{}".format(peer_num)]
        logger.info("Removing named pipe of ExaBGP peer peer{}".format(peer_num))
        fifo_in = "/var/run/exabgp_peer{}.in".format(peer_num)
        peer.stop()
        if os.path.exists(fifo_in):
            os.remove(fifo_in)

    # end test_bgp_dampening_cleanup


def test_bgp_dampening_aftermath():
    "BGP route-flap dampening aftermath test"

    # This test verifies routers r1 and r2 not being affected by the route-flap
    # dampening test series.

    tgen = get_topogen()

    # Skip if previous fatal error condition is raised
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    # Check BGP Summary on routers r1 and r2
    for rtr_num in [1, 2]:
        logger.info(
            "Checking if BGP router on r{} remains unaffected by route-flap dampening tests".format(
                rtr_num
            )
        )
        router = tgen.gears["r{}".format(rtr_num)]
        reffile = os.path.join(CWD, "r{}/show_bgp.json".format(rtr_num))
        expected = json.loads(open(reffile).read())
        test_func = functools.partial(
            topotest.router_json_cmp, router, "show ip bgp json", expected
        )
        _, res = topotest.run_and_expect(test_func, None, count=10, wait=2)
        assertmsg = "BGP routes on router r{} are wrong after route-flap dampening tests".format(
            rtr_num
        )
        assert res is None, assertmsg

    # end test_bgp_dampening_aftermath


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
