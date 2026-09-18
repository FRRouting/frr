#!/usr/bin/env python
# SPDX-License-Identifier: ISC

#
# test_evpn_anycast_macvlan.py
#
# Copyright (c) 2026 by
# VyOS, Inc.
# Kyrylo Yatsenko
#

"""
test_evpn_anycast_macvlan.py: Testing EVPN anycast with macvlan devices

"""

import json
import os
import pytest
import sys

from functools import partial
from lib.checkping import check_ping

pytestmark = [pytest.mark.bgpd]

# Save the Current Working Directory to find configuration files.
CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

# pylint: disable=C0413
# Import topogen and topotest helpers
from lib import topotest

# Required to instantiate the topology builder class.
from lib.topogen import Topogen, get_topogen
from lib.topolog import logger

#####################################################
##
##   Network Topology Definition
##
## See topology picture at test_evpn_anycast_macvlan.png
#####################################################


host_ips = {
    "host11": "192.168.1.10",
    "host12": "192.168.2.10",
    "host21": "192.168.1.20",
    "host22": "192.168.2.20",
}

host_mac_map = {
    "host11": "00:50:79:66:68:11",
    "host12": "00:50:79:66:68:12",
    "host21": "00:50:79:66:68:21",
    "host22": "00:50:79:66:68:22",
}

hosts = list(host_mac_map.keys())
routers = ["r1", "r2"]


def build_topo(tgen):
    """
    EVPN Anycast Topology -
    1. Two gateways: r1, r2
    2. Four hosts: host11, host12, host21, host22
        Hosts host1* are connected to r1, hosts host2* - to r2
        Hosts host*1 are in 192.168.1.0/24 network
        Hosts host*2 are in 192.168.2.0/24 network
    """

    tgen.add_router("r1")
    tgen.add_router("r2")
    tgen.add_router("host11")
    tgen.add_router("host12")
    tgen.add_router("host21")
    tgen.add_router("host22")

    # Create switches
    switch = tgen.add_switch("sr1r2")
    switch.add_link(tgen.gears["r1"])
    switch.add_link(tgen.gears["r2"])

    switch = tgen.add_switch("s11")
    switch.add_link(tgen.gears["r1"])
    switch.add_link(tgen.gears["host11"])

    switch = tgen.add_switch("s12")
    switch.add_link(tgen.gears["r1"])
    switch.add_link(tgen.gears["host12"])

    switch = tgen.add_switch("s21")
    switch.add_link(tgen.gears["r2"])
    switch.add_link(tgen.gears["host21"])

    switch = tgen.add_switch("s22")
    switch.add_link(tgen.gears["r2"])
    switch.add_link(tgen.gears["host22"])


def router_compare_json_output(rname, command, reference, count=130, wait=1):
    "Compare router JSON output"

    logger.info(f'Comparing router "{rname}" "{command}" output')

    tgen = get_topogen()
    filename = f"{CWD}/{rname}/{reference}"
    with open(filename) as f:
        expected = json.loads(f.read())

    # Run test function until we get an result.
    test_func = partial(topotest.router_json_cmp, tgen.gears[rname], command, expected)
    _, diff = topotest.run_and_expect(test_func, None, count=count, wait=wait)
    assertmsg = f'"{rname}" JSON output mismatches the expected result'
    assert diff is None, assertmsg


#####################################################
##
##   Tests starting
##
#####################################################


def config_vrf(node):
    """
    Create VRF on node
    """
    node.cmd_raises("ip link add RED type vrf table 111")
    node.cmd_raises("ip link set dev RED up")


def config_bridge(node):
    """
    Create a VLAN aware bridge
    """
    node.cmd_raises("ip link add dev br0 type bridge")
    node.cmd_raises("ip link set dev br0 type bridge vlan_filtering 1")
    node.cmd_raises("/sbin/bridge vlan add dev br0 vid 100 self")
    node.cmd_raises("/sbin/bridge vlan add dev br0 vid 200 self")
    node.cmd_raises("/sbin/bridge vlan add dev br0 vid 1000 self")
    node.cmd_raises("ip link set dev br0 up")
    node.cmd_raises("/sbin/bridge fdb add 00:aa:aa:aa:aa:aa dev br0 self local")


def config_interface_vid(node, ifname, vid):
    node.cmd_raises(f"ip link set dev {ifname} master br0")
    node.cmd_raises(f"/sbin/bridge link set dev {ifname} isolated off")
    node.cmd_raises(f"/sbin/bridge vlan del dev {ifname} vid 1 master")
    node.cmd_raises(
        f"/sbin/bridge vlan add dev {ifname} vid {vid} pvid untagged master"
    )


def config_vxlan(node, lo_addr):
    node.cmd_raises(
        f"ip link add vxlan0 type vxlan dstport 4789 external df unset tos inherit ttl 64 nolearning local {lo_addr} dev lo"
    )
    node.cmd_raises("ip link set dev vxlan0 mtu 1500")
    node.cmd_raises("ip link set dev vxlan0 master br0")
    node.cmd_raises("/sbin/bridge vlan del dev vxlan0 vid 1 master")
    node.cmd_raises("ip link set dev vxlan0 up")
    node.cmd_raises("/sbin/bridge link set dev vxlan0 vlan_tunnel on")
    node.cmd_raises("/sbin/bridge link set dev vxlan0 neigh_suppress on learning off")
    node.cmd_raises("ip link set vxlan0 type bridge_slave learning off")


def config_vlan(node, vid):
    node.cmd_raises(f"ip link add link br0 name br0.{vid} type vlan id {vid}")
    node.cmd_raises(f"ip link set dev br0.{vid} master RED")
    node.cmd_raises(f"ip link set dev br0.{vid} up")
    node.cmd_raises(f"/sbin/bridge vlan add dev vxlan0 vid {vid}")
    node.cmd_raises(f"/sbin/bridge vlan add dev vxlan0 vid {vid} tunnel_info id {vid}")


def config_macvlan(node, vid, addr):
    node.cmd_raises(
        f"ip link add macvlan{vid} link br0.{vid} type macvlan mode private"
    )
    node.cmd_raises(f"ip link set dev macvlan{vid} address 00:aa:aa:aa:aa:aa")
    node.cmd_raises(f"ip link set dev macvlan{vid} master RED")
    node.cmd_raises(f"ip addr add {addr}/24 dev macvlan{vid} brd +")
    node.cmd_raises(f"ip link set dev macvlan{vid} up")
    node.cmd_raises(f"/sbin/sysctl -w net.ipv4.conf.macvlan{vid}.arp_accept=1")


def config_lo(node, lo_addr):
    node.cmd_raises(f"ip addr add {lo_addr}/32 dev lo brd +")
    node.cmd_raises("ip link set dev lo up")


def config_router(node, name, lo_addr):
    config_vrf(node)
    config_bridge(node)
    config_interface_vid(node, f"{name}-eth1", 100)
    config_interface_vid(node, f"{name}-eth2", 200)
    config_vxlan(node, lo_addr)
    config_vlan(node, 100)
    config_vlan(node, 200)
    config_vlan(node, 1000)
    config_macvlan(node, 100, "192.168.1.1")
    config_macvlan(node, 200, "192.168.2.1")
    config_lo(node, lo_addr)


def config_host(host_name, host):
    """
    Setup host with hard-coded MAC/IP
    """
    ifname = host_name + "-eth0"
    host_ip = host_ips[host_name]
    host_mac = host_mac_map[host_name]
    host.run(f"ip addr add {host_ip}/24 dev {ifname}")
    host.run(f"ip link set dev {ifname} address {host_mac}")


def config_hosts(tgen):
    for host_name in hosts:
        host = tgen.gears[host_name]
        config_host(host_name, host)


def setup_module(module):
    "Setup topology"
    tgen = Topogen(build_topo, module.__name__)
    tgen.start_topology()

    router_list = tgen.routers()
    for rname, router in router_list.items():
        router.load_frr_config(os.path.join(CWD, f"{rname}/frr.conf"))

    # Putting these below start_router still work, but significantly slower
    config_router(tgen.gears["r1"], "r1", "1.1.1.1")
    config_router(tgen.gears["r2"], "r2", "1.1.1.2")

    tgen.start_router()

    # Putting this above start_router ruins all addresses/routes
    config_hosts(tgen)


def teardown_module(_mod):
    "Teardown the pytest environment"
    tgen = get_topogen()

    # This function tears down the whole topology.
    tgen.stop_topology()


def test_ping_all_hosts(tgen):
    # check ping of all hosts to hosts
    for host1_name in hosts:
        for host2_name in hosts:
            if host1_name == host2_name:
                continue
            check_ping(host1_name, host_ips[host2_name], True, 130, 1)


def test_evpn_arp_cache(tgen):
    # Fill in arp-cache by ping
    check_ping("host11", host_ips["host22"], True, 130, 1)
    check_ping("host12", host_ips["host21"], True, 30, 1)
    # Check
    for router in routers:
        router_compare_json_output(
            router,
            "show evpn arp-cache vni all json",
            "show_evpn_arp_cache_vni_all.ref",
        )


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
