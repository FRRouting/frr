#!/usr/bin/env python
# SPDX-License-Identifier: ISC

#
# test_evpn_mh.py
#
# Copyright (c) 2020 by
# Cumulus Networks, Inc.
# Anuradha Karuppiah
#

"""
test_evpn_mh.py: Testing EVPN multihoming

"""

import os
import sys
import subprocess
from functools import partial

import pytest
import json
import platform
from functools import partial

pytestmark = [pytest.mark.bgpd, pytest.mark.pimd]

# Save the Current Working Directory to find configuration files.
CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

# pylint: disable=C0413
# Import topogen and topotest helpers
from lib import topotest

# Required to instantiate the topology builder class.
from lib.topogen import Topogen, TopoRouter, get_topogen

#####################################################
##
##   Network Topology Definition
##
## See topology picture at evpn-mh-topo-tests.pdf
#####################################################


def build_topo(tgen):
    """
    EVPN Multihoming Topology -
    1. Two level CLOS
    2. Two spine switches - spine1, spine2
    3. Two racks with Top-of-Rack switches per rack - tormx1, tormx2
    4. Two dual attached hosts per-rack - hostdx1, hostdx2
    """

    tgen.add_router("spine1")
    tgen.add_router("spine2")
    tgen.add_router("leaf1")
    tgen.add_router("leaf2")
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
    # spine1-eth0 is connected to leaf1-eth0
    switch = tgen.add_switch("sw1")
    switch.add_link(tgen.gears["spine1"])
    switch.add_link(tgen.gears["leaf1"])

    # spine1-eth1 is connected to leaf2-eth0
    switch = tgen.add_switch("sw2")
    switch.add_link(tgen.gears["spine1"])
    switch.add_link(tgen.gears["leaf2"])

    # spine2-eth0 is connected to leaf1-eth1
    switch = tgen.add_switch("sw3")
    switch.add_link(tgen.gears["spine2"])
    switch.add_link(tgen.gears["leaf1"])

    # spine2-eth1 is connected to leaf2-eth1
    switch = tgen.add_switch("sw4")
    switch.add_link(tgen.gears["spine2"])
    switch.add_link(tgen.gears["leaf2"])

    ################## leaf1 ##########################
    # leaf1-eth2 is connected to torm11-eth0
    switch = tgen.add_switch("sw5")
    switch.add_link(tgen.gears["leaf1"])
    switch.add_link(tgen.gears["torm11"])

    # leaf1-eth3 is connected to torm12-eth0
    switch = tgen.add_switch("sw6")
    switch.add_link(tgen.gears["leaf1"])
    switch.add_link(tgen.gears["torm12"])

    # leaf1-eth4 is connected to torm21-eth0
    switch = tgen.add_switch("sw7")
    switch.add_link(tgen.gears["leaf1"])
    switch.add_link(tgen.gears["torm21"])

    # leaf1-eth5 is connected to torm22-eth0
    switch = tgen.add_switch("sw8")
    switch.add_link(tgen.gears["leaf1"])
    switch.add_link(tgen.gears["torm22"])

    ##################### leaf2 ########################
    # leaf2-eth2 is connected to torm11-eth1
    switch = tgen.add_switch("sw9")
    switch.add_link(tgen.gears["leaf2"])
    switch.add_link(tgen.gears["torm11"])

    # leaf2-eth3 is connected to torm12-eth1
    switch = tgen.add_switch("sw10")
    switch.add_link(tgen.gears["leaf2"])
    switch.add_link(tgen.gears["torm12"])

    # leaf2-eth4 is connected to torm21-eth1
    switch = tgen.add_switch("sw11")
    switch.add_link(tgen.gears["leaf2"])
    switch.add_link(tgen.gears["torm21"])

    # leaf2-eth5 is connected to torm22-eth1
    switch = tgen.add_switch("sw12")
    switch.add_link(tgen.gears["leaf2"])
    switch.add_link(tgen.gears["torm22"])

    ##################### torm11 ########################
    # torm11-eth2 is connected to hostd11-eth0
    switch = tgen.add_switch("sw13")
    switch.add_link(tgen.gears["torm11"])
    switch.add_link(tgen.gears["hostd11"])

    # torm11-eth3 is connected to hostd12-eth0
    switch = tgen.add_switch("sw14")
    switch.add_link(tgen.gears["torm11"])
    switch.add_link(tgen.gears["hostd12"])

    ##################### torm12 ########################
    # torm12-eth2 is connected to hostd11-eth1
    switch = tgen.add_switch("sw15")
    switch.add_link(tgen.gears["torm12"])
    switch.add_link(tgen.gears["hostd11"])

    # torm12-eth3 is connected to hostd12-eth1
    switch = tgen.add_switch("sw16")
    switch.add_link(tgen.gears["torm12"])
    switch.add_link(tgen.gears["hostd12"])

    ##################### torm21 ########################
    # torm21-eth2 is connected to hostd21-eth0
    switch = tgen.add_switch("sw17")
    switch.add_link(tgen.gears["torm21"])
    switch.add_link(tgen.gears["hostd21"])

    # torm21-eth3 is connected to hostd22-eth0
    switch = tgen.add_switch("sw18")
    switch.add_link(tgen.gears["torm21"])
    switch.add_link(tgen.gears["hostd22"])

    ##################### torm22 ########################
    # torm22-eth2 is connected to hostd21-eth1
    switch = tgen.add_switch("sw19")
    switch.add_link(tgen.gears["torm22"])
    switch.add_link(tgen.gears["hostd21"])

    # torm22-eth3 is connected to hostd22-eth1
    switch = tgen.add_switch("sw20")
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
    "hostd11": "03:44:38:39:ff:ff:01:00:00:01",
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
        node.run(" ip link set dev %s master bridge" % bond_name)
        node.run("/sbin/bridge link set dev %s priority 8" % bond_name)
        node.run("/sbin/bridge vlan del vid 1 dev %s" % bond_name)
        node.run("/sbin/bridge vlan del vid 1 untagged pvid dev %s" % bond_name)
        node.run("/sbin/bridge vlan add vid 1000 dev %s" % bond_name)
        node.run("/sbin/bridge vlan add vid 1000 untagged pvid dev %s" % bond_name)


def config_mcast_tunnel_termination_device(node):
    """
    The kernel requires a device to terminate VxLAN multicast tunnels
    when EVPN-PIM is used for flooded traffic
    """
    node.run("ip link add dev ipmr-lo type dummy")
    node.run("ip link set dev ipmr-lo mtu 16000")
    node.run("ip link set dev ipmr-lo mode dormant")
    node.run("ip link set dev ipmr-lo up")


def config_bridge(node):
    """
    Create a VLAN aware bridge
    """
    node.run("ip link add dev bridge type bridge stp_state 0")
    node.run("ip link set dev bridge type bridge vlan_filtering 1")
    node.run("ip link set dev bridge mtu 9216")
    node.run("ip link set dev bridge type bridge ageing_time 1800")
    node.run("ip link set dev bridge type bridge mcast_snooping 0")
    node.run("ip link set dev bridge type bridge vlan_stats_enabled 1")
    node.run("ip link set dev bridge up")
    node.run("/sbin/bridge vlan add vid 1000 dev bridge self")


def config_vxlan(node, node_ip):
    """
    Create a VxLAN device for VNI 1000 and add it to the bridge.
    VLAN-1000 is mapped to VNI-1000.
    """
    node.run("ip link add dev vx-1000 type vxlan id 1000 dstport 4789")
    node.run("ip link set dev vx-1000 type vxlan nolearning")
    node.run("ip link set dev vx-1000 type vxlan local %s" % node_ip)
    node.run("ip link set dev vx-1000 type vxlan ttl 64")
    node.run("ip link set dev vx-1000 mtu 9152")
    node.run("ip link set dev vx-1000 type vxlan dev ipmr-lo group 239.1.1.100")
    node.run("ip link set dev vx-1000 up")

    # bridge attrs
    node.run("ip link set dev vx-1000 master bridge")
    node.run("/sbin/bridge link set dev vx-1000 neigh_suppress on")
    node.run("/sbin/bridge link set dev vx-1000 learning off")
    node.run("/sbin/bridge link set dev vx-1000 priority 8")
    node.run("/sbin/bridge vlan del vid 1 dev vx-1000")
    node.run("/sbin/bridge vlan del vid 1 untagged pvid dev vx-1000")
    node.run("/sbin/bridge vlan add vid 1000 dev vx-1000")
    node.run("/sbin/bridge vlan add vid 1000 untagged pvid dev vx-1000")


def config_svi(node, svi_pip):
    """
    Create an SVI for VLAN 1000
    """
    node.run("ip link add link bridge name vlan1000 type vlan id 1000 protocol 802.1q")
    node.run("ip addr add %s/24 dev vlan1000" % svi_pip)
    node.run("ip link set dev vlan1000 up")
    node.run("/sbin/sysctl net.ipv4.conf.vlan1000.arp_accept=1")
    node.run("ip link add link vlan1000 name vlan1000-v0 type macvlan mode private")
    node.run("/sbin/sysctl net.ipv6.conf.vlan1000-v0.accept_dad=0")
    node.run("/sbin/sysctl net.ipv6.conf.vlan1000-v0.dad_transmits")
    node.run("/sbin/sysctl net.ipv6.conf.vlan1000-v0.dad_transmits=0")
    node.run("ip link set dev vlan1000-v0 address 00:00:5e:00:01:01")
    node.run("ip link set dev vlan1000-v0 up")
    # metric 1024 is not working
    node.run("ip addr add 45.0.0.1/24 dev vlan1000-v0")


def config_tor(tor_name, tor, tor_ip, svi_pip):
    """
    Create the bond/vxlan-bridge on the TOR which acts as VTEP and EPN-PE
    """
    # create a device for terminating VxLAN multicast tunnels
    config_mcast_tunnel_termination_device(tor)

    # create a vlan aware bridge
    config_bridge(tor)

    # create vxlan device and add it to bridge
    config_vxlan(tor, tor_ip)

    # create hostbonds and add them to the bridge
    if "torm1" in tor_name:
        sys_mac = "44:38:39:ff:ff:01"
    else:
        sys_mac = "44:38:39:ff:ff:02"
    bond_member = tor_name + "-eth2"
    config_bond(tor, "hostbond1", [bond_member], sys_mac, "bridge")

    bond_member = tor_name + "-eth3"
    config_bond(tor, "hostbond2", [bond_member], sys_mac, "bridge")

    # create SVI
    config_svi(tor, svi_pip)


def config_tors(tgen, tors):
    for tor_name in tors:
        tor = tgen.gears[tor_name]
        config_tor(tor_name, tor, tor_ips.get(tor_name), svi_ips.get(tor_name))


def compute_host_ip_mac(host_name):
    host_id = host_name.split("hostd")[1]
    host_ip = "45.0.0." + host_id + "/24"
    host_mac = "00:00:00:00:00:" + host_id

    return host_ip, host_mac


def config_host(host_name, host):
    """
    Create the dual-attached bond on host nodes for MH
    """
    bond_members = []
    bond_members.append(host_name + "-eth0")
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

    # tgen.mininet_cli()
    # This is a sample of configuration loading.
    router_list = tgen.routers()
    for rname, router in router_list.items():
        router.load_config(
            TopoRouter.RD_ZEBRA, os.path.join(CWD, "{}/zebra.conf".format(rname))
        )
        router.load_config(
            TopoRouter.RD_PIM, os.path.join(CWD, "{}/pim.conf".format(rname))
        )
        router.load_config(
            TopoRouter.RD_BGP, os.path.join(CWD, "{}/evpn.conf".format(rname))
        )
    tgen.start_router()

    hosts = []
    hosts.append("hostd11")
    hosts.append("hostd12")
    hosts.append("hostd21")
    hosts.append("hostd22")
    config_hosts(tgen, hosts)
    # tgen.mininet_cli()


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

    for _, tor_ip in tor_ips_rack.items():
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
    Two ES are setup on each rack. This test checks if -
    1. ES peer has been added to the local ES (via Type-1/EAD route)
    2. The remote ESs are setup with the right list of PEs (via Type-1)
    """

    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    dut_name = "torm11"
    dut = tgen.gears[dut_name]
    test_fn = partial(check_es, dut)
    _, result = topotest.run_and_expect(test_fn, None, count=20, wait=3)

    assertmsg = '"{}" ES content incorrect'.format(dut_name)
    assert result is None, assertmsg
    # tgen.mininet_cli()


def test_evpn_ead_update():
    """
    Flap a host link one the remote rack and check if the EAD updates
    are sent/processed for the corresponding ESI
    """
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    # dut on rack1 and host link flap on rack2
    dut_name = "torm11"
    dut = tgen.gears[dut_name]

    remote_tor_name = "torm21"
    remote_tor = tgen.gears[remote_tor_name]

    host_name = "hostd21"
    host = tgen.gears[host_name]
    esi = host_es_map.get(host_name)

    # check if the VTEP list is right to start with
    down_vteps = []
    test_fn = partial(check_one_es, dut, esi, down_vteps)
    _, result = topotest.run_and_expect(test_fn, None, count=20, wait=3)
    assertmsg = '"{}" ES content incorrect'.format(dut_name)
    assert result is None, assertmsg

    # down a remote host link and check if the EAD withdraw is rxed
    # Note: LACP is not working as expected so I am temporarily shutting
    # down the link on the remote TOR instead of the remote host
    remote_tor.run("ip link set dev %s-%s down" % (remote_tor_name, "eth2"))
    down_vteps.append(tor_ips.get(remote_tor_name))
    _, result = topotest.run_and_expect(test_fn, None, count=20, wait=3)
    assertmsg = '"{}" ES incorrect after remote link down'.format(dut_name)
    assert result is None, assertmsg

    # bring up remote host link and check if the EAD update is rxed
    down_vteps.remove(tor_ips.get(remote_tor_name))
    remote_tor.run("ip link set dev %s-%s up" % (remote_tor_name, "eth2"))
    _, result = topotest.run_and_expect(test_fn, None, count=20, wait=3)
    assertmsg = '"{}" ES incorrect after remote link flap'.format(dut_name)
    assert result is None, assertmsg

    # tgen.mininet_cli()


def ping_anycast_gw(tgen):
    # ping the anycast gw from the local and remote hosts to populate
    # the mac address on the PEs
    python3_path = tgen.net.get_exec_path(["python3", "python"])
    script_path = os.path.abspath(os.path.join(CWD, "../lib/scapy_sendpkt.py"))
    intf = "torbond"
    ipaddr = "45.0.0.1"
    ping_cmd = [
        python3_path,
        script_path,
        "--imports=Ether,ARP",
        "--interface=" + intf,
        'Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst="{}")'.format(ipaddr),
    ]
    for name in ("hostd11", "hostd21", "hostd12", "hostd22"):
        host = tgen.net.hosts[name]
        _, stdout, _ = host.cmd_status(ping_cmd, warn=False, stderr=subprocess.STDOUT)
        stdout = stdout.strip()
        if stdout:
            host.logger.debug(
                "%s: arping on %s for %s returned: %s", name, intf, ipaddr, stdout
            )


def check_mac(dut, vni, mac, m_type, esi, intf, ping_gw=False, tgen=None):
    """
    checks if mac is present and if desination matches the one provided
    """

    if ping_gw:
        ping_anycast_gw(tgen)

    out = dut.vtysh_cmd("show evpn mac vni %d mac %s json" % (vni, mac))

    tmp_esi = None
    mac_js = json.loads(out)
    for mac, info in mac_js.items():
        tmp_esi = info.get("esi", "")
        tmp_m_type = info.get("type", "")
        tmp_intf = info.get("intf", "") if tmp_m_type == "local" else ""
        if tmp_esi == esi and tmp_m_type == m_type and intf == intf:
            return None

    return "invalid vni %d mac %s expected esi %s, %s m_type %s and intf %s out %s" % (
        vni,
        mac,
        tmp_esi,
        esi,
        m_type,
        intf,
        mac_js,
    )


def test_evpn_mac():
    """
    1. Add a MAC on hostd11 and check if the MAC is synced between
    torm11 and torm12. And installed as a local MAC.
    2. Add a MAC on hostd21 and check if the MAC is installed as a
    remote MAC on torm11 and torm12
    """

    tgen = get_topogen()

    local_host = tgen.gears["hostd11"]
    remote_host = tgen.gears["hostd21"]
    tors = []
    tors.append(tgen.gears["torm11"])
    tors.append(tgen.gears["torm12"])

    vni = 1000

    # check if the rack-1 host MAC is present on all rack-1 PEs
    # and points to local access port
    m_type = "local"
    _, mac = compute_host_ip_mac(local_host.name)
    esi = host_es_map.get(local_host.name)
    intf = "hostbond1"

    for tor in tors:
        test_fn = partial(check_mac, tor, vni, mac, m_type, esi, intf, True, tgen)
        _, result = topotest.run_and_expect(test_fn, None, count=20, wait=3)
        assertmsg = '"{}" local MAC content incorrect'.format(tor.name)
        assert result is None, assertmsg

    # check if the rack-2 host MAC is present on all rack-1 PEs
    # and points to the remote ES destination
    m_type = "remote"
    _, mac = compute_host_ip_mac(remote_host.name)
    esi = host_es_map.get(remote_host.name)
    intf = ""

    for tor in tors:
        test_fn = partial(check_mac, tor, vni, mac, m_type, esi, intf)
        _, result = topotest.run_and_expect(test_fn, None, count=20, wait=3)
        assertmsg = '"{}" remote MAC content incorrect'.format(tor.name)
        assert result is None, assertmsg


def check_df_role(dut, esi, role):
    """
    Return error string if the df role on the dut is different
    """
    es_json = dut.vtysh_cmd("show evpn es %s json" % esi)
    es = json.loads(es_json)

    if not es:
        return "esi %s not found" % esi

    flags = es.get("flags", [])
    curr_role = "nonDF" if "nonDF" in flags else "DF"

    if curr_role != role:
        return "%s is %s for %s" % (dut.name, curr_role, esi)

    return None


def test_evpn_df():
    """
    1. Check the DF role on all the PEs on rack-1.
    2. Increase the DF preference on the non-DF and check if it becomes
       the DF winner.
    """

    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    # We will run the tests on just one ES
    esi = host_es_map.get("hostd11")
    intf = "hostbond1"

    tors = []
    tors.append(tgen.gears["torm11"])
    tors.append(tgen.gears["torm12"])
    df_node = "torm11"

    # check roles on rack-1
    for tor in tors:
        role = "DF" if tor.name == df_node else "nonDF"
        test_fn = partial(check_df_role, tor, esi, role)
        _, result = topotest.run_and_expect(test_fn, None, count=20, wait=3)
        assertmsg = '"{}" DF role incorrect'.format(tor.name)
        assert result is None, assertmsg

    # change df preference on the nonDF to make it the df
    torm12 = tgen.gears["torm12"]
    torm12.vtysh_cmd("conf\ninterface %s\nevpn mh es-df-pref %d" % (intf, 60000))
    df_node = "torm12"

    # re-check roles on rack-1; we should have a new winner
    for tor in tors:
        role = "DF" if tor.name == df_node else "nonDF"
        test_fn = partial(check_df_role, tor, esi, role)
        _, result = topotest.run_and_expect(test_fn, None, count=20, wait=3)
        assertmsg = '"{}" DF role incorrect'.format(tor.name)
        assert result is None, assertmsg

    # tgen.mininet_cli()


def check_protodown_rc(dut, protodown_rc):
    """
    check if specified protodown reason code is set
    """

    out = dut.vtysh_cmd("show evpn json")

    evpn_js = json.loads(out)
    tmp_rc = evpn_js.get("protodownReasons", [])

    if protodown_rc:
        if protodown_rc not in tmp_rc:
            return "protodown %s missing in %s" % (protodown_rc, tmp_rc)
    else:
        if tmp_rc:
            return "unexpected protodown rc %s" % (tmp_rc)

    return None


def test_evpn_uplink_tracking():
    """
    1. Wait for access ports to come out of startup-delay
    2. disable uplinks and check if access ports have been protodowned
    3. enable uplinks and check if access ports have been moved out
       of protodown
    """

    tgen = get_topogen()

    dut_name = "torm11"
    dut = tgen.gears[dut_name]

    # wait for protodown rc to clear after startup
    test_fn = partial(check_protodown_rc, dut, None)
    _, result = topotest.run_and_expect(test_fn, None, count=20, wait=3)
    assertmsg = '"{}" protodown rc incorrect'.format(dut_name)
    assert result is None, assertmsg

    # disable the uplinks
    dut.run("ip link set %s-eth0 down" % dut_name)
    dut.run("ip link set %s-eth1 down" % dut_name)

    # check if the access ports have been protodowned
    test_fn = partial(check_protodown_rc, dut, "uplinkDown")
    _, result = topotest.run_and_expect(test_fn, None, count=20, wait=3)
    assertmsg = '"{}" protodown rc incorrect'.format(dut_name)
    assert result is None, assertmsg

    # enable the uplinks
    dut.run("ip link set %s-eth0 up" % dut_name)
    dut.run("ip link set %s-eth1 up" % dut_name)

    # check if the access ports have been moved out of protodown
    test_fn = partial(check_protodown_rc, dut, None)
    _, result = topotest.run_and_expect(test_fn, None, count=20, wait=3)
    assertmsg = '"{}" protodown rc incorrect'.format(dut_name)
    assert result is None, assertmsg


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
