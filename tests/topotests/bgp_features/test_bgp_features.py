#!/usr/bin/env python
# SPDX-License-Identifier: ISC

#
# test_bgp_features.py
# Part of NetDEF Topology Tests
#
# Copyright (c) 2020 by
# Network Device Education Foundation, Inc. ("NetDEF")
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

# Save the Current Working Directory to find configuration files.
CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

# pylint: disable=C0413
# Import topogen and topotest helpers
from lib import topotest
from lib.topogen import Topogen, TopoRouter, get_topogen
from lib.topolog import logger

# Required to instantiate the topology builder class.

pytestmark = [pytest.mark.bgpd, pytest.mark.ospfd]

#####################################################
#
#   Network Topology Definition
#
#####################################################


def build_topo(tgen):
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
    tgen = Topogen(build_topo, module.__name__)
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


def get_shut_msg_count(tgen):
    shuts = {}
    for rtrNum in [2, 4]:
        shutmsg = tgen.net["r{}".format(rtrNum)].cmd_nostatus(
            'grep -c "NOTIFICATION.*Cease/Administrative Shutdown" bgpd.log', warn=False
        )
        try:
            shuts[rtrNum] = int(shutmsg.strip())
        except ValueError:
            shuts[rtrNum] = 0
    return shuts


def test_bgp_shutdown():
    "Test BGP instance shutdown"

    tgen = get_topogen()

    # Skip if previous fatal error condition is raised
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    shuts_before = get_shut_msg_count(tgen)

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

    shuts_after = get_shut_msg_count(tgen)

    for k in shuts_before:
        assert shuts_before[k] + 1 == shuts_after[k]


def test_bgp_shutdown_message():
    "Test BGP Peer Shutdown Message"

    tgen = get_topogen()

    # Skip if previous fatal error condition is raised
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    for rtrNum in [2, 4]:
        logger.info("Checking BGP shutdown received on router r{}".format(rtrNum))

        shut_message = tgen.net["r{}".format(rtrNum)].cmd(
            'grep -e "NOTIFICATION.*Cease/Administrative Shutdown.*ABCDabcd" bgpd.log'
        )
        assertmsg = "BGP shutdown message not received on router R{}".format(rtrNum)
        assert shut_message != "", assertmsg


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
        _, res = topotest.run_and_expect(test_func, None, count=5, wait=1)
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
        _, res = topotest.run_and_expect(test_func, None, count=5, wait=1)
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
    _, res = topotest.run_and_expect(test_func, None, count=5, wait=1)
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
        _, res = topotest.run_and_expect(test_func, None, count=5, wait=1)
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
        _, res = topotest.run_and_expect(test_func, None, count=5, wait=1)
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
        _, res = topotest.run_and_expect(test_func, None, count=5, wait=1)
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
    assert (delay_stop - delay_start) >= 30, assertmsg

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


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
