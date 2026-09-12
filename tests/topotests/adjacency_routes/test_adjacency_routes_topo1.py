#!/usr/bin/env python
# SPDX-License-Identifier: ISC

#
# test_adjacency_routes
#
# Copyright (c) 2024 by
# Cisco Systems, Inc.
# Mark Stapp
#

"""
test_adjacency_routes_topo1.py: Testing ADJACENCY route type for local hosts

"""

import os
import sys
import subprocess
from functools import partial

import pytest
import json
import platform

pytestmark = [pytest.mark.bgpd]

# Save the Current Working Directory to find configuration files.
CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

# pylint: disable=C0413
# Import topogen and topotest helpers
from lib import topotest

# Required to instantiate the topology builder class.
from lib.topogen import Topogen, TopoRouter, get_topogen
from lib.topolog import logger

#####################################################
##
##   Network Topology Definition
##
## See topology picture at evpn-mh-topo-tests.pdf
#####################################################


def build_topo(tgen):
    """
    Base Topology -
    1. Two level CLOS
    2. Two spine switches - spine1, spine2
    3. Two racks with two Top-of-Rack switches per rack - tormx1, tormx2
    4. two hosts per-rack - hostd11, hostd12, hostd21, hostd22
    5. vanilla ipv4 addressing
    """

    tgen.add_router("spine1")
    tgen.add_router("spine2")
    tgen.add_router("torm11")
    tgen.add_router("torm12")
    tgen.add_router("torm21")
    tgen.add_router("torm22")
    tgen.add_router("hostd11")
    tgen.add_router("hostd12")
    tgen.add_router("hostd21")
    tgen.add_router("hostd22")

    # On main router
    # First switch is for a dummy interface (for local network)

    ##################### spine1 ########################
    # spine1-eth0 is connected to torm11-eth0
    switch = tgen.add_switch("sw1")
    switch.add_link(tgen.gears["spine1"])
    switch.add_link(tgen.gears["torm11"])

    # spine1-eth1 is connected to torm12-eth0
    switch = tgen.add_switch("sw2")
    switch.add_link(tgen.gears["spine1"])
    switch.add_link(tgen.gears["torm12"])

    # spine1-eth2 is connected to torm21-eth0
    switch = tgen.add_switch("sw3")
    switch.add_link(tgen.gears["spine1"])
    switch.add_link(tgen.gears["torm21"])

    # spine1-eth3 is connected to torm22-eth0
    switch = tgen.add_switch("sw4")
    switch.add_link(tgen.gears["spine1"])
    switch.add_link(tgen.gears["torm22"])

    ##################### spine2 ########################
    # spine2-eth0 is connected to torm11-eth1
    switch = tgen.add_switch("sw5")
    switch.add_link(tgen.gears["spine2"])
    switch.add_link(tgen.gears["torm11"])

    # spine2-eth1 is connected to torm12-eth1
    switch = tgen.add_switch("sw6")
    switch.add_link(tgen.gears["spine2"])
    switch.add_link(tgen.gears["torm12"])

    # spine2-eth2 is connected to torm21-eth1
    switch = tgen.add_switch("sw7")
    switch.add_link(tgen.gears["spine2"])
    switch.add_link(tgen.gears["torm21"])

    # spine2-eth3 is connected to torm22-eth1
    switch = tgen.add_switch("sw8")
    switch.add_link(tgen.gears["spine2"])
    switch.add_link(tgen.gears["torm22"])

    ##################### torm11 ########################
    # torm11-eth2 is connected to hostd11-eth0
    switch = tgen.add_switch("sw9")
    switch.add_link(tgen.gears["torm11"])
    switch.add_link(tgen.gears["hostd11"])

    ##################### torm12 ########################
    # torm12-eth3 is connected to hostd12-eth1
    switch = tgen.add_switch("sw12")
    switch.add_link(tgen.gears["torm12"])
    switch.add_link(tgen.gears["hostd12"])

    ##################### torm21 ########################
    # torm21-eth2 is connected to hostd21-eth0
    switch = tgen.add_switch("sw13")
    switch.add_link(tgen.gears["torm21"])
    switch.add_link(tgen.gears["hostd21"])

    ##################### torm22 ########################
    # torm22-eth3 is connected to hostd22-eth1
    switch = tgen.add_switch("sw16")
    switch.add_link(tgen.gears["torm22"])
    switch.add_link(tgen.gears["hostd22"])


#####################################################
##
##   Tests starting
##
#####################################################

tor_ips = {
    "torm11": "192.168.100.15",
    "torm12": "192.168.100.16",
    "torm21": "192.168.100.17",
    "torm22": "192.168.100.18",
}

# distributed anycast gateway
svi_ips = { 
    "torm11": "45.0.0.2",
    "torm12": "45.0.0.3",
    "torm21": "20.0.0.20",
    "torm22": "20.0.0.23",
}

tor_ips_rack_1 = {"torm11": "192.168.100.15", "torm12": "192.168.100.16"}

tor_ips_rack_2 = {"torm21": "192.168.100.17", "torm22": "192.168.100.18"}


def config_bond(node, bond_name, bond_members, bond_ad_sys_mac):
    """
    Used to setup bonds on the TORs and hosts 
    """
    node.run("ip link add dev %s type bond mode 802.3ad" % bond_name)
    node.run("ip link set dev %s type bond lacp_rate 1" % bond_name)
    node.run("ip link set dev %s type bond miimon 100" % bond_name)
    node.run("ip link set dev %s type bond xmit_hash_policy layer3+4" % bond_name)
    node.run("ip link set dev %s type bond min_links 1" % bond_name)
    node.run(
        "ip link set dev %s type bond ad_actor_system %s" % (bond_name, bond_ad_sys_mac)
    )

    for bond_member in bond_members:
        node.run("ip link set dev %s down" % bond_member)
        node.run("ip link set dev %s master %s" % (bond_member, bond_name))
        node.run("ip link set dev %s up" % bond_member)

    node.run("ip link set dev %s up" % bond_name)


def config_tor(tor_name, tor, tor_ip, svi_pip):
    """
    Create the bond on the TOR which acts as EPN-PE
    """

    # create hostbonds
    if "torm11" in tor_name:
        sys_mac = "44:38:39:ff:ff:01"
    elif "torm12" in tor_name:
        sys_mac = "44:38:39:ff:ff:02"
    elif "torm21" in tor_name:
        sys_mac = "44:38:39:ff:ff:21"
    else:
        sys_mac = "44:38:39:ff:ff:22"


    bond_member = tor_name + "-eth2"
    config_bond(tor, "hostbond1", [bond_member], sys_mac)
    tor.run("ip addr add 45.0.0.2/24 dev hostbond1")


def config_tors(tgen, tors):
    for tor_name in tors:
        tor = tgen.gears[tor_name]
        config_tor(tor_name, tor, tor_ips.get(tor_name), svi_ips.get(tor_name))


def compute_host_ip_mac(host_name):
    host_id = host_name.split("hostd")[1]
    if host_name == "hostd2":
        host_ip = "20.0.0." + host_id + "/24"
    else:
        host_ip = "45.0.0." + host_id + "/24"
    host_mac = "00:00:00:00:00:" + host_id
    return host_ip, host_mac


def config_host(host_name, host):
    """
    Create the single-attached bond on host nodes for HH
    """
    bond_members = []
    bond_members.append(host_name + "-eth0")
    bond_name = "torbond"
    config_bond(host, bond_name, bond_members, "00:00:00:00:00:00")

    host_ip, host_mac = compute_host_ip_mac(host_name)
    host.run("ip addr add %s dev %s" % (host_ip, bond_name))
    host.run("ip link set dev %s address %s" % (bond_name, host_mac))


def config_hosts(tgen, hosts):
    for host_name in hosts:
        host = tgen.gears[host_name]
        config_host(host_name, host)


def setup_module(module):
    "Setup topology"
    tgen = Topogen(build_topo, module.__name__)
    tgen.start_topology()

    krel = platform.release()
    if topotest.version_cmp(krel, "4.19") < 0:
        tgen.errors = "kernel 4.19 needed for fabric tests"
        pytest.skip(tgen.errors)

    tors = []
    tors.append("torm11")
    tors.append("torm12")
    tors.append("torm21")
    tors.append("torm22")
    config_tors(tgen, tors)

    hosts = []
    hosts.append("hostd11")
    hosts.append("hostd12")
    hosts.append("hostd21")
    hosts.append("hostd22")
    config_hosts(tgen, hosts)

    # This is configuration loading.
    router_list = tgen.routers()
    for rname, router in router_list.items():
        router.load_frr_config()

    tgen.start_router()


def teardown_module(_mod):
    "Teardown the pytest environment"
    tgen = get_topogen()

    # This function tears down the whole topology.
    tgen.stop_topology()


#
# Helper for ping command
#
def check_ping4(name, dest_addr, expected, ifname=None):
    def _check(name, dest_addr, ifname, match):
        tgen = get_topogen()

        if ifname is None:
            output = tgen.gears[name].run("ping {} -c 1 -w 1".format(dest_addr))
        else:
            output = tgen.gears[name].run(
                "ping {} -I {} -c 1 -w 1".format(dest_addr, ifname)
            )

        logger.debug(output)
        if match not in output:
            return "ping fail"

    match = ", {} packet loss".format("0%" if expected else "100%")
    logger.info("[+] check {} {} {} {}".format(name, dest_addr, ifname, match))

    func = partial(_check, name, dest_addr, ifname, match)
    success, result = topotest.run_and_expect(func, None, count=10, wait=3)
    assert result is None, "Failed"


#
# Helper to check ADJ route info from ip route output
#
def check_route(router, addr_str):

    # show route on 'router'
    logger.info(
        "Check {} zebra route: {}".format(router.name, addr_str)
    )

    output = router.vtysh_cmd("show ip route {} json".format(addr_str))

    js = json.loads(output)

    ip_key = addr_str + "/32"

    try:
        entry = js[ip_key]
    except KeyError:
        return "{}: route {} not found".format(router.name, addr_str)

    return None


#
# Helper to check route info from bgp route output
#
def check_bgp_route(router, addr_str):

    # show route on 'router'
    logger.info(
        "Check {} bgp route: {}".format(router.name, addr_str)
    )

    ip_key = addr_str + "/32"

    output = router.vtysh_cmd("show bgp ipv4 unicast {} json".format(ip_key))

    js = json.loads(output)

    try:
        entry = js["prefix"]
    except KeyError:
        return "{}: route {} not found".format(router.name, addr_str)

    return None

#
#
#
def test_adj_routes():
    """
    Ping to create a neighbor entry; verify that the host route info is distributed
    across the topology via BGP.
    """

    tgen = get_topogen()

    local_tor = tgen.gears["torm11"]
    remote_tor = tgen.gears["torm21"]

    local_addr = "45.0.0.11"

    # ping neighbor
    logger.info("Ping local host {}".format(local_addr))

    check_ping4("torm11", local_addr, True, "hostbond1")

    # Check route data on local TOR
    logger.info(
        "Check local {} zebra route: {}".format(local_tor.name, local_addr)
    )

    test_fn = partial(check_route, local_tor, local_addr)

    _, result = topotest.run_and_expect(test_fn, None, count=10, wait=3)
    assertmsg = "{}: local route data incorrect".format(local_tor.name)
    assert result == None, assertmsg

    # Test route data on remote TOR
    logger.info(
        "Check remote {} zebra route: {}".format(remote_tor.name, local_addr)
    )

    test_fn = partial(check_route, remote_tor, local_addr)

    _, result = topotest.run_and_expect(test_fn, None, count=10, wait=3)
    assertmsg = "{}: remote adj route data incorrect".format(remote_tor.name)
    assert result == None, assertmsg

    # Test BGP data on local TOR
    logger.info(
        "Check local {} BGP route: {}".format(local_tor.name, local_addr)
    )

    test_fn = partial(check_bgp_route, local_tor, local_addr)

    _, result = topotest.run_and_expect(test_fn, None, count=10, wait=3)
    assertmsg = "{}: local BGP route data incorrect".format(local_tor.name)
    assert result == None, assertmsg

    # Test BGP data on remote TOR
    logger.info(
        "Check remote {} BGP route: {}".format(remote_tor.name, local_addr)
    )

    test_fn = partial(check_bgp_route, remote_tor, local_addr)

    _, result = topotest.run_and_expect(test_fn, None, count=10, wait=3)
    assertmsg = "{}: remote BGP route data incorrect".format(remote_tor.name)
    assert result == None, assertmsg

    #
    # TODO
    #

    # Test ipv6 host
