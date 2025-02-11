#!/usr/bin/env python

#
# test_bgp_rtc.py
#
# Copyright (c) 2025 by
# Cisco Systems, Inc.
# Mark Stapp
#
# Permission to use, copy, modify, and/or distribute this software
# for any purpose with or without fee is hereby granted, provided
# that the above copyright notice and this permission notice appear
# in all copies.
#
# THE SOFTWARE IS PROVIDED "AS IS" AND CISCO DISCLAIMS ALL WARRANTIES
# WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
# MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL NETDEF BE LIABLE FOR
# ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY
# DAMAGES WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS,
# WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS
# ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE
# OF THIS SOFTWARE.
#

"""
test_bgp_rtc.py: Testing BGP RTC with L2VNI, L3VNI, and MPLSVPN

"""

import os
import sys
import subprocess
from functools import partial

import pytest
import json
import platform
from functools import partial

pytestmark = [pytest.mark.bgpd]

# Save the Current Working Directory to find configuration files.
CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

# pylint: disable=C0413
# Import topogen and topotest helpers
from lib import topotest

# Required to instantiate the topology builder class.
from lib.topogen import Topogen, TopoRouter, get_topogen

pytestmark = [pytest.mark.bgpd, pytest.mark.pimd]

#####################################################
##
##   Network Topology Definition
##
## See topology picture at bgp_rtc.pdf
#####################################################


def build_topo(tgen):
    """
    EVPN Multihoming Topology -
    1. Two level CLOS
    2. Two spine switches - spine1, spine2
    3. Two racks with Top-of-Rack switches per rack - tormx1, tormx2
    4. Dual attached hosts per-rack - hostd12, hostd21, hostd22
    5. Single attached host - hostd11 to torm11
    6. hostd22 is in a different subnet then hostd1x and hostd21
    7. L2VNI with L3VNI setup on each leaf with SVI as IP gateway
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

    # torm11-eth3 is connected to hostd12-eth0
    switch = tgen.add_switch("sw10")
    switch.add_link(tgen.gears["torm11"])
    switch.add_link(tgen.gears["hostd12"])

    ##################### torm12 ########################
    # keeping the hostd11 single-homed
    # torm12-eth2 is connected to hostd11-eth1
    # switch = tgen.add_switch("sw11")
    # switch.add_link(tgen.gears["torm12"])
    # switch.add_link(tgen.gears["hostd11"])

    # torm12-eth3 is connected to hostd12-eth1
    switch = tgen.add_switch("sw12")
    switch.add_link(tgen.gears["torm12"])
    switch.add_link(tgen.gears["hostd12"])

    ##################### torm21 ########################
    # torm21-eth2 is connected to hostd21-eth0
    switch = tgen.add_switch("sw13")
    switch.add_link(tgen.gears["torm21"])
    switch.add_link(tgen.gears["hostd21"])

    # torm21-eth3 is connected to hostd22-eth0
    switch = tgen.add_switch("sw14")
    switch.add_link(tgen.gears["torm21"])
    switch.add_link(tgen.gears["hostd22"])

    ##################### torm22 ########################
    # torm22-eth2 is connected to hostd21-eth1
    switch = tgen.add_switch("sw15")
    switch.add_link(tgen.gears["torm22"])
    switch.add_link(tgen.gears["hostd21"])

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

svi_ips = {
    "torm11": "45.0.0.2",
    "torm12": "45.0.0.3",
    "torm21": "45.0.0.4",
    "torm22": "45.0.0.5",
}

tor_ips_rack_1 = {"torm11": "192.168.100.15", "torm12": "192.168.100.16"}

tor_ips_rack_2 = {"torm21": "192.168.100.17", "torm22": "192.168.100.18"}

host_es_map = {
    "hostd12": "03:44:38:39:ff:ff:01:00:00:02",
    "hostd21": "03:44:38:39:ff:ff:02:00:00:01",
    "hostd22": "03:44:38:39:ff:ff:02:00:00:02",
}


def config_bond(node, bond_name, bond_members, bond_ad_sys_mac, br):
    """
    Used to setup bonds on the TORs and hosts for MH
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

    # if bridge is specified add the bond as a bridge member
    if br:
        node.run(" ip link set dev %s master %s" % (bond_name, br))
        node.run("/sbin/bridge link set dev %s priority 8" % bond_name)
        node.run("/sbin/bridge vlan del vid 1 dev %s" % bond_name)
        node.run("/sbin/bridge vlan del vid 1 untagged pvid dev %s" % bond_name)
        node.run("/sbin/bridge vlan add vid 1000 dev %s" % bond_name)
        node.run("/sbin/bridge vlan add vid 1000 untagged pvid dev %s" % bond_name)


def config_l3vni(tor_name, node, vtep_ip):
    """
    Create an L3VNI and its ip-vrf vrf500
    """
    node.run("ip link add vrf500 type vrf table 500")
    node.run("ip link set vrf500 up")

    node.run("ip link add br500 type bridge")
    node.run("ip link set br500 master vrf500 addrgenmode none")
    if "torm11" in tor_name:
        node.run("ip link set br500 addr aa:bb:cc:00:00:11")
    elif "torm12" in tor_name:
        node.run("ip link set br500 addr aa:bb:cc:00:00:12")
    elif "torm21" in tor_name:
        node.run("ip link set br500 addr aa:bb:cc:00:00:21")
    else:
        node.run("ip link set br500 addr aa:bb:cc:00:00:22")

    node.run(
        "ip link add vni500 type vxlan local %s dstport 4789 id 500 nolearning"
        % vtep_ip
    )
    node.run("ip link set vni500 master br500 addrgenmode none")
    node.run("/sbin/bridge link set dev vni500 learning off")
    node.run("ip link set vni500 up")
    node.run("ip link set br500 up")


def config_l2vni(tor_name, node, svi_ip, vtep_ip):
    """
    On torm1x amd torm21,
    Create a VxLAN device for VNI 1000 and add it to the bridge.
    VLAN-1000 is mapped to VNI-1000.

    On torm22, do the same + add another bridge and l2vni to create a different subnet
    """

    # on torm2x, there are 2 subnets. This required to different bridge domain, svi_ip and l2vni.
    # subnets are connected to same vrf. Therefore, same L3VNI can be used
    node.run("ip link add br1000 type bridge")
    node.run("ip link set br1000 master vrf500")
    node.run("ip addr add %s/24 dev br1000" % svi_ip)
    node.run("/sbin/sysctl net.ipv4.conf.br1000.arp_accept=1")

    node.run(
        "ip link add vni1000 type vxlan local %s dstport 4789 id 1000 nolearning"
        % vtep_ip
    )
    node.run("ip link set vni1000 master br1000 addrgenmode none")
    node.run("/sbin/bridge link set dev vni1000 learning off")
    node.run("ip link set vni1000 up")
    node.run("ip link set br1000 up")

    node.run("/sbin/bridge vlan del vid 1 dev vni1000")
    node.run("/sbin/bridge vlan del vid 1 untagged pvid dev vni1000")
    node.run("/sbin/bridge vlan add vid 1000 dev vni1000")
    node.run("/sbin/bridge vlan add vid 1000 untagged pvid dev vni1000")

    if "torm2" in tor_name:
        node.run("ip link add br2000 type bridge")
        node.run("ip link set br2000 master vrf500")
        node.run("ip addr add 20.0.0.20/24 dev br2000")
        node.run("/sbin/sysctl net.ipv4.conf.br2000.arp_accept=1")
        node.run(
            "ip link add vni2000 type vxlan local %s dstport 4789 id 2000 nolearning"
            % vtep_ip
        )
        node.run("ip link set vni2000 master br2000 addrgenmode none")
        node.run("/sbin/bridge link set dev vni2000 learning off")
        node.run("ip link set vni2000 up")
        node.run("ip link set br2000 up")
        node.run("/sbin/bridge vlan del vid 1 dev vni2000")
        node.run("/sbin/bridge vlan del vid 1 untagged pvid dev vni2000")
        node.run("/sbin/bridge vlan add vid 1000 dev vni2000")
        node.run("/sbin/bridge vlan add vid 1000 untagged pvid dev vni2000")


def config_tor(tor_name, tor, tor_ip, svi_pip):
    """
    Create the bond/vxlan-bridge on the TOR which acts as VTEP and EPN-PE
    """

    # create l3vni along with l3vni bridge
    config_l3vni(tor_name, tor, tor_ip)

    # create l2vni, bridge and associated SVI
    config_l2vni(tor_name, tor, svi_pip, tor_ip)

    # create hostbonds and add them to the bridge
    if "torm1" in tor_name:
        sys_mac = "44:38:39:ff:ff:01"
    else:
        sys_mac = "44:38:39:ff:ff:02"

    # torm11 has 2 connections on the same subnet: hostbond1 and hostbond2
    if "torm11" in tor_name:
        bond_member = tor_name + "-eth2"
        config_bond(tor, "hostbond1", [bond_member], sys_mac, "br1000")
        bond_member = tor_name + "-eth3"
        config_bond(tor, "hostbond2", [bond_member], sys_mac, "br1000")
    # torm12 has only 1 connection with hostbond2
    elif "torm12" in tor_name:
        bond_member = tor_name + "-eth2"
        config_bond(tor, "hostbond2", [bond_member], sys_mac, "br1000")
    # torm2x has 2 connections but on different subnets
    else:
        bond_member = tor_name + "-eth2"
        config_bond(tor, "hostbond1", [bond_member], sys_mac, "br1000")
        bond_member = tor_name + "-eth3"
        config_bond(tor, "hostbond2", [bond_member], sys_mac, "br2000")


def config_tors(tgen, tors):
    for tor_name in tors:
        tor = tgen.gears[tor_name]
        config_tor(tor_name, tor, tor_ips.get(tor_name), svi_ips.get(tor_name))


def compute_host_ip_mac(host_name):
    host_id = host_name.split("hostd")[1]
    if host_name == "hostd22":
        host_ip = "20.0.0." + host_id + "/24"
    else:
        host_ip = "45.0.0." + host_id + "/24"
    host_mac = "00:00:00:00:00:" + host_id
    return host_ip, host_mac


def config_host(host_name, host):
    """
    Create the dual-attached bond on host nodes for MH
    """
    bond_members = []
    bond_members.append(host_name + "-eth0")
    # Check for single-homed host
    if "hostd11" not in host_name:
        bond_members.append(host_name + "-eth1")

    bond_name = "torbond"
    config_bond(host, bond_name, bond_members, "00:00:00:00:00:00", None)

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
        tgen.errors = "kernel 4.19 needed for multihoming tests"
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

    # tgen.mininet_cli()
    # This is a sample of configuration loading.
    router_list = tgen.routers()
    for rname, router in router_list.items():
        router.load_config(
            TopoRouter.RD_ZEBRA, os.path.join(CWD, "{}/zebra.conf".format(rname))
        )
        router.load_config(
            TopoRouter.RD_BGP, os.path.join(CWD, "{}/evpn.conf".format(rname))
        )
    tgen.start_router()

    # TODO -- debugging
    #tgen.cli()


def teardown_module(_mod):
    "Teardown the pytest environment"
    tgen = get_topogen()

    # This function tears down the whole topology.
    tgen.stop_topology()


def check_local_es(esi, vtep_ips, dut_name, down_vteps):
    """
    Check if ES peers are setup correctly on local ESs
    """
    peer_ips = []
    if "torm1" in dut_name:
        tor_ips_rack = tor_ips_rack_1
    else:
        tor_ips_rack = tor_ips_rack_2

    for tor_name, tor_ip in tor_ips_rack.items():
        if dut_name not in tor_name:
            peer_ips.append(tor_ip)

    # remove down VTEPs from the peer check list
    peer_set = set(peer_ips)
    down_vtep_set = set(down_vteps)
    peer_set = peer_set - down_vtep_set

    vtep_set = set(vtep_ips)
    diff = peer_set.symmetric_difference(vtep_set)

    return (esi, diff) if diff else None


def check_remote_es(esi, vtep_ips, dut_name, down_vteps):
    """
    Verify list of PEs associated with a remote ES
    """
    remote_ips = []

    if "torm1" in dut_name:
        tor_ips_rack = tor_ips_rack_2
    else:
        tor_ips_rack = tor_ips_rack_1

    for tor_name, tor_ip in tor_ips_rack.items():
        remote_ips.append(tor_ip)

    # remove down VTEPs from the remote check list
    remote_set = set(remote_ips)
    down_vtep_set = set(down_vteps)
    remote_set = remote_set - down_vtep_set

    vtep_set = set(vtep_ips)
    diff = remote_set.symmetric_difference(vtep_set)

    return (esi, diff) if diff else None


def check_es(dut):
    """
    Verify list of PEs associated all ESs, local and remote
    """
    bgp_es = dut.vtysh_cmd("show bgp l2vp evpn es json")
    bgp_es_json = json.loads(bgp_es)

    result = None

    expected_es_set = set([v for k, v in host_es_map.items()])
    curr_es_set = []

    # check is ES content is correct
    for es in bgp_es_json:
        esi = es["esi"]
        curr_es_set.append(esi)
        types = es["type"]
        vtep_ips = []
        for vtep in es.get("vteps", []):
            vtep_ips.append(vtep["vtep_ip"])

        if "local" in types:
            result = check_local_es(esi, vtep_ips, dut.name, [])
        else:
            result = check_remote_es(esi, vtep_ips, dut.name, [])

        if result:
            return result

    # check if all ESs are present
    curr_es_set = set(curr_es_set)
    result = curr_es_set.symmetric_difference(expected_es_set)

    return result if result else None


def check_one_es(dut, esi, down_vteps):
    """
    Verify list of PEs associated all ESs, local and remote
    """
    bgp_es = dut.vtysh_cmd("show bgp l2vp evpn es %s json" % esi)
    es = json.loads(bgp_es)

    if not es:
        return "esi %s not found" % esi

    esi = es["esi"]
    types = es["type"]
    vtep_ips = []
    for vtep in es.get("vteps", []):
        vtep_ips.append(vtep["vtep_ip"])

    if "local" in types:
        result = check_local_es(esi, vtep_ips, dut.name, down_vteps)
    else:
        result = check_remote_es(esi, vtep_ips, dut.name, down_vteps)

    return result


def test_evpn_es():
    """
    One ES is setup on torm1x
    Two ES are setup on torm2x. This test checks if -
    1. ES peer has been added to the local ES (via Type-1/EAD route)
    2. The remote ESs are setup with the right list of PEs (via Type-1)
    """

    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    # Debugging
    #tgen.cli()

    dut_name = "torm11"
    dut = tgen.gears[dut_name]


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
