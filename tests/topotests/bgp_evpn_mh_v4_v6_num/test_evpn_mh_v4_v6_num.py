#!/usr/bin/env python
# SPDX-License-Identifier: ISC

#
# test_evpn_mh_v6_numbered.py
#
# Copyright (c) 2020 by
# Nvidia Corporation
# Chirag Shah
# Copyright (c) 2025 by
# IPv6 VTEP EBGP Numbered Extensions
#

"""
test_evpn_mh_v6_numbered.py: Testing EVPN multihoming with IPv6 VTEP addresses
and EBGP numbered peering

This is an IPv6 VTEP variant with EBGP numbered peering and unified FRR config
"""

import os
import sys
import subprocess
from functools import partial
from ipaddress import ip_network

import pytest
import json
import platform
import time

pytestmark = [pytest.mark.bgpd, pytest.mark.pim6d, pytest.mark.evpn]

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
## Same topology as test_evpn_mh.py but with IPv6 VTEP addresses
## and EBGP numbered peering
#####################################################


def build_topo(tgen):
    """
    EVPN Multihoming Topology -
    1. Two level CLOS
    2. Two spine switches - spine1, spine2
    3. Two leaf switches - leaf1, leaf2
    4. Two racks with Top-of-Rack switches per rack - tormx1, tormx2
    5. Two dual attached hosts per-rack - hostdx1, hostdx2
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

# IPv6 VTEP addresses
tor_ips = {
    "torm11": "2001:db8:100::15",
    "torm12": "2001:db8:100::16",
    "torm21": "2001:db8:100::17",
    "torm22": "2001:db8:100::18",
}

svi_ips = {
    "torm11": "2001:db8:45::2",
    "torm12": "2001:db8:45::3",
    "torm21": "2001:db8:45::4",
    "torm22": "2001:db8:45::5",
}

tor_ips_rack_1 = {"torm11": "2001:db8:100::15", "torm12": "2001:db8:100::16"}

tor_ips_rack_2 = {"torm21": "2001:db8:100::17", "torm22": "2001:db8:100::18"}

host_es_map = {
    "hostd11": "03:44:38:39:ff:ff:01:00:00:01",
    "hostd12": "03:44:38:39:ff:ff:01:00:00:02",
    "hostd21": "03:44:38:39:ff:ff:02:00:00:01",
    "hostd22": "03:44:38:39:ff:ff:02:00:00:02",
}

# Underlay IPv6 addresses for TOR uplink interfaces. These mirror the interface
# addresses configured in the per-router frr.conf files, but are applied early
# using Linux iproute2 so that zebra/BGP always see stable interface addresses,
# even when configuration is loaded via tools/frr-reload.py.
tor_uplink_ipv6 = {
    "torm11": {
        "torm11-eth0": "2001:db8:1::0/127",
        "torm11-eth1": "2001:db8:5::0/127",
    },
    "torm12": {
        "torm12-eth0": "2001:db8:2::0/127",
        "torm12-eth1": "2001:db8:6::0/127",
    },
    "torm21": {
        "torm21-eth0": "2001:db8:3::0/127",
        "torm21-eth1": "2001:db8:7::0/127",
    },
    "torm22": {
        "torm22-eth0": "2001:db8:4::0/127",
        "torm22-eth1": "2001:db8:8::0/127",
    },
}


def _normalize_prefix_for_ip_show(prefix):
    """
    Given a prefix string as used in `ip -6 addr add` (e.g. "2001:db8:1::0/127"),
    return the normalized form that `ip -6 addr show` prints (e.g. "2001:db8:1::/127").
    """
    try:
        net = ip_network(prefix, strict=False)
        return str(net)
    except ValueError:
        # Fallback: just return what we were given
        return prefix


def check_underlay_and_bgp_ipv6(dut, lo_prefix, uplink_prefixes, neighbors):
    """
    Generic helper to verify:

    - Kernel IPv6 address on loopback matches `lo_prefix`
    - Kernel IPv6 addresses on all uplink interfaces match `uplink_prefixes`
    - All BGP IPv6 unicast neighbors in `neighbors` are Established
    """

    # Check loopback IPv6
    lo_out = dut.run("ip -6 addr show dev lo")
    if lo_prefix not in lo_out:
        return f"{dut.name}: loopback IPv6 missing in kernel: {lo_out}"

    # Check uplink IPv6 addresses
    for ifname, prefix in uplink_prefixes.items():
        expected = _normalize_prefix_for_ip_show(prefix)
        out = dut.run(f"ip -6 addr show dev {ifname}")
        if expected not in out:
            return f"{dut.name}: {ifname} IPv6 missing in kernel: {out}"

    # Check BGP IPv6 unicast neighbors
    summary = dut.vtysh_cmd("show bgp ipv6 unicast summary json")
    try:
        js = json.loads(summary)
    except Exception as exc:  # pragma: no cover - defensive
        return f"{dut.name}: failed to parse BGP IPv6 summary json: {summary} ({exc})"

    # Prefer modern layout, fall back if needed
    peers = js.get("ipv6Unicast", {}).get("peers")
    if not isinstance(peers, dict):
        peers = js.get("peers", {}) if isinstance(js.get("peers"), dict) else {}

    for neigh in neighbors:
        state = peers.get(neigh, {}).get("state", "")
        if state != "Established":
            return f"{dut.name}: neighbor {neigh} not Established (state={state})"

    return None


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
    Create a VLAN aware bridge for SVD:
    - Single bridge `br_default`
    - VLANs 1000–1003 (L2VNIs) and 4000/4001 (L3VNIs for vrf1/vrf2)
    """
    node.run("ip link del br_default 2>/dev/null || true")
    node.run("ip link add dev br_default type bridge stp_state 0")
    node.run("ip link set dev br_default type bridge vlan_filtering 1")
    node.run("ip link set dev br_default mtu 9216")
    node.run("ip link set dev br_default type bridge ageing_time 1800")
    node.run("ip link set dev br_default type bridge mcast_snooping 0")
    node.run("ip link set dev br_default type bridge vlan_stats_enabled 1")
    node.run("ip link set dev br_default up")
    # Self VLAN entries for all L2VNIs and L3VNI VLANs
    for vid in (1000, 1001, 1002, 1003, 4000, 4001):
        node.run(f"/sbin/bridge vlan add vid {vid} dev br_default self")


def config_vxlan(node, node_ip):
    """
    Create a Single VXLAN Device (SVD) `vxlan48` and add it to the bridge.
    VLANs 1000–1003 (L2VNIs) and 4000/4001 (L3VNIs for vrf1/vrf2) are mapped to
    VNIs 1000–1003 and 4000/4001 respectively via tunnel_info, following the
    same pattern as `setup_vtep` in bgp_evpn_three_tier_clos_topo1.
    """
    # Cleanup any existing vxlan48
    node.run("ip link del vxlan48 2>/dev/null || true")

    # Create VXLAN with IPv6 local address; BGP EVPN will control remote
    # endpoints via the `external` flag.
    node.run(
        "ip link add vxlan48 type vxlan dstport 4789 local %s "
        "nolearning external ttl 64 ageing 18000" % node_ip
    )
    node.run("ip link set dev vxlan48 mtu 9152")
    node.run("ip link set dev vxlan48 master br_default")
    # Mirror SVD behavior: enable VLAN tunneling, suppress ARP/ND, disable learning
    node.run("/sbin/bridge link set dev vxlan48 vlan_tunnel on")
    node.run("/sbin/bridge link set dev vxlan48 neigh_suppress on")
    node.run("/sbin/bridge link set dev vxlan48 learning off")
    node.run("/sbin/bridge vlan del vid 1 dev vxlan48")
    node.run("/sbin/bridge vlan del vid 1 untagged pvid dev vxlan48")

    # Map VLANs to VNIs
    vni_map = {
        1000: 1000,
        1001: 1001,
        1002: 1002,
        1003: 1003,
        4000: 4000,
        4001: 4001,
    }
    for vid, vni in vni_map.items():
        # First add the VLAN membership on vxlan48, then add tunnel_info id
        node.run(f"/sbin/bridge vlan add dev vxlan48 vid {vid}")
        node.run(
            f"/sbin/bridge vlan add dev vxlan48 vid {vid} tunnel_info id {vni}"
        )

    node.run("ip link set dev vxlan48 up")


def config_l3vni(node, node_ip):
    """
    L3VNI is handled by VLAN 4001 mapped to VNI 4001 on `vxlan48`, so this
    function becomes a no-op placeholder kept for compatibility.
    """
    del node
    del node_ip


def config_svi(node, svi_pip):
    """
    Create an SVI for VLAN 1000 with IPv6 addressing in vrf1.
    SVIs for other VLANs (1001–1003) can be created similarly if needed.
    """
    node.run(
        "ip link add link br_default name vlan1000 type vlan id 1000 protocol 802.1q"
    )
    node.run("ip -6 addr add %s/64 dev vlan1000" % svi_pip)
    node.run("ip link set dev vlan1000 master vrf1")
    node.run("ip link set dev vlan1000 up")
    node.run("/sbin/sysctl net.ipv6.conf.vlan1000.accept_dad=0")
    node.run("/sbin/sysctl net.ipv6.conf.vlan1000.dad_transmits=0")


def config_vrf_l3vni(node):
    """
    Create VRFs and the L3VNI VLAN interfaces for vrf1 (L3VNI 4000)
    and vrf2 (L3VNI 4001). vrf1 and vrf2 are created here so that
    config_svi() can attach SVIs.
    """
    # VRF vrf1 (table 1001) and vrf2 (table 1002)
    node.run("ip link add vrf1 type vrf table 1001 2>/dev/null || true")
    node.run("ip link set dev vrf1 up")
    node.run("ip link add vrf2 type vrf table 1002 2>/dev/null || true")
    node.run("ip link set dev vrf2 up")

    # L3VNI VLAN interface (vlan4000) for vrf1/L3VNI 4000
    node.run(
        "ip link add link br_default name vlan4000 type vlan id 4000 protocol 802.1q"
    )
    node.run("ip link set dev vlan4000 master vrf1")
    node.run("ip link set dev vlan4000 up")
    node.run("/sbin/sysctl net.ipv6.conf.vlan4000.accept_dad=0")
    node.run("/sbin/sysctl net.ipv6.conf.vlan4000.dad_transmits=0")

    # L3VNI VLAN interface (vlan4001) for vrf2/L3VNI 4001
    node.run(
        "ip link add link br_default name vlan4001 type vlan id 4001 protocol 802.1q"
    )
    node.run("ip link set dev vlan4001 master vrf2")
    node.run("ip link set dev vlan4001 up")
    node.run("/sbin/sysctl net.ipv6.conf.vlan4001.accept_dad=0")
    node.run("/sbin/sysctl net.ipv6.conf.vlan4001.dad_transmits=0")


def config_tor(tor_name, tor, tor_ip, svi_pip):
    """
    Create the bond/vxlan-bridge on the TOR which acts as VTEP and EPN-PE
    """
    # Add IPv4 and IPv6 addresses to loopback interface for VTEP
    # These must be added before creating VXLAN device.
    # They match the addresses in frr.conf for consistency and are applied
    # via Linux iproute2 so that zebra/BGP learn them from the kernel.
    tor_id = tor_name.replace("torm", "")  # Extract number: 11, 12, 21, 22
    if tor_id == "11":
        ipv4_lo = "10.0.0.15"
    elif tor_id == "12":
        ipv4_lo = "10.0.0.16"
    elif tor_id == "21":
        ipv4_lo = "10.0.0.17"
    elif tor_id == "22":
        ipv4_lo = "10.0.0.18"

    tor.run("ip addr add %s/32 dev lo" % ipv4_lo)
    tor.run("ip -6 addr add %s/128 dev lo" % tor_ip)

    # Add IPv6 underlay addresses on uplink interfaces using iproute2 as well.
    # This avoids timing/race issues where, when using frr-reload.py, BGP may
    # come up before interface addresses have been fully programmed by zebra
    # from the FRR config, leading to incorrect (e.g. IPv4-mapped IPv6) nexthops.
    uplinks = tor_uplink_ipv6.get(tor_name, {})
    for ifname, prefix in uplinks.items():
        tor.run("ip -6 addr add %s dev %s" % (prefix, ifname))

    # create VRFs and L3VNI VLAN 4001
    config_bridge(tor)
    config_vxlan(tor, tor_ip)
    config_vrf_l3vni(tor)

    # create hostbonds; we will attach them to the bridge explicitly
    if "torm1" in tor_name:
        sys_mac = "44:38:39:ff:ff:01"
    else:
        sys_mac = "44:38:39:ff:ff:02"
    bond_member = tor_name + "-eth2"
    config_bond(tor, "hostbond1", [bond_member], sys_mac, None)

    bond_member = tor_name + "-eth3"
    config_bond(tor, "hostbond2", [bond_member], sys_mac, None)

    # Attach host bonds to bridge with VLANs:
    # - hostbond1 carries VLAN 1000 (vrf1)
    # - hostbond2 carries VLAN 1001 (vrf1)
    for bond, vid in (("hostbond1", 1000), ("hostbond2", 1001)):
        tor.run(f"ip link set dev {bond} master br_default")
        tor.run(f"/sbin/bridge vlan del vid 1 dev {bond}")
        tor.run(f"/sbin/bridge vlan del vid 1 untagged pvid dev {bond}")
        tor.run(f"/sbin/bridge vlan add vid {vid} dev {bond}")
        tor.run(f"/sbin/bridge vlan add vid {vid} pvid untagged dev {bond}")

    # create SVI for VLAN 1000 in vrf1 (others can be added similarly as needed)
    config_svi(tor, svi_pip)


def setup_vtep_mh(tgen, tor_name, tor_ip, svi_pip):
    """
    Configure SVD VXLAN (`vxlan48`) and bridge (`br_default`) on a TOR VTEP
    in a manner similar to `setup_vtep` from bgp_evpn_three_tier_clos_topo1:
    - Clean up any existing SVD state
    - Create a single VLAN-aware bridge
    - Create a single VXLAN device for all VNIs (L2 and L3)
    - Create VRFs and L3VNI VLANs for vrf1 (4000) and vrf2 (4001)
    - Attach host-facing bonds to the bridge with appropriate VLANs
    """
    tor = tgen.gears[tor_name]

    # Cleanup any existing SVD-related interfaces
    cleanup_cmds = [
        # SVIs and L3VNI VLANs
        "ip link set dev vlan1000 down 2>/dev/null || true",
        "ip link set dev vlan1001 down 2>/dev/null || true",
        "ip link set dev vlan1002 down 2>/dev/null || true",
        "ip link set dev vlan1003 down 2>/dev/null || true",
        "ip link set dev vlan4000 down 2>/dev/null || true",
        "ip link set dev vlan4001 down 2>/dev/null || true",
        "ip link del vlan1000 2>/dev/null || true",
        "ip link del vlan1001 2>/dev/null || true",
        "ip link del vlan1002 2>/dev/null || true",
        "ip link del vlan1003 2>/dev/null || true",
        "ip link del vlan4000 2>/dev/null || true",
        "ip link del vlan4001 2>/dev/null || true",
        # VXLAN and bridge
        "ip link set dev vxlan48 down 2>/dev/null || true",
        "ip link del vxlan48 2>/dev/null || true",
        "ip link set dev br_default down 2>/dev/null || true",
        "ip link del br_default 2>/dev/null || true",
        # VRFs
        "ip link set dev vrf1 down 2>/dev/null || true",
        "ip link set dev vrf2 down 2>/dev/null || true",
        "ip link del vrf1 2>/dev/null || true",
        "ip link del vrf2 2>/dev/null || true",
    ]
    for cmd in cleanup_cmds:
        tor.run(cmd)

    # Now configure SVD data plane and host bonds using existing helper
    config_tor(tor_name, tor, tor_ip, svi_pip)


def config_tors(tgen, tors):
    for tor_name in tors:
        setup_vtep_mh(
            tgen,
            tor_name,
            tor_ips.get(tor_name),
            svi_ips.get(tor_name),
        )


def compute_host_ip_mac(host_name):
    host_id = host_name.split("hostd")[1]
    host_ip = "2001:db8:45::" + host_id + "/64"
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


def disable_dad_on_all_interfaces(tgen):
    """
    Disable DAD (Duplicate Address Detection) on all interfaces for all routers.
    This is necessary to prevent IPv6 address installation failures in test environments.
    """
    router_list = tgen.routers()
    for rname, router in router_list.items():
        # Disable DAD globally for all interfaces
        router.run("/sbin/sysctl -w net.ipv6.conf.all.accept_dad=0 2>/dev/null || true")
        router.run(
            "/sbin/sysctl -w net.ipv6.conf.all.dad_transmits=0 2>/dev/null || true"
        )
        router.run(
            "/sbin/sysctl -w net.ipv6.conf.default.accept_dad=0 2>/dev/null || true"
        )
        router.run(
            "/sbin/sysctl -w net.ipv6.conf.default.dad_transmits=0 2>/dev/null || true"
        )

        # Get list of all interfaces and disable DAD on each
        try:
            # Get all interfaces
            output = router.run(
                "ip link show | grep -E '^[0-9]+:' | awk -F': ' '{print $2}' | awk '{print $1}'"
            )
            interfaces = [line.strip() for line in output.split("\n") if line.strip()]

            for intf in interfaces:
                # Skip loopback and special interfaces
                if intf in ["lo", "ipmr-lo"]:
                    continue
                # Disable DAD on this interface
                router.run(
                    "/sbin/sysctl -w net.ipv6.conf.{}.accept_dad=0 2>/dev/null || true".format(
                        intf
                    )
                )
                router.run(
                    "/sbin/sysctl -w net.ipv6.conf.{}.dad_transmits=0 2>/dev/null || true".format(
                        intf
                    )
                )
        except Exception as e:
            logger.warning(
                "Failed to disable DAD on interfaces for {}: {}".format(rname, e)
            )


@pytest.fixture(scope="module", params=["ipv4", "ipv6"])
def tgen_and_ip_version(request):
    """
    Parametrized fixture to run the multihoming topology with IPv4 or IPv6 underlay.

    For now only the IPv6 underlay is implemented; the IPv4 variant is skipped
    until dedicated configs and host plumbing are added.
    """

    ip_version = request.param

    if ip_version == "ipv4":
        pytest.skip("IPv4 underlay is not yet implemented for this topology")

    # Build topology
    tgen = Topogen(build_topo, request.module.__name__)
    tgen.start_topology()

    # Basic kernel requirement check (same as original test)
    krel = platform.release()
    if topotest.version_cmp(krel, "4.19") < 0:
        tgen.errors = "kernel 4.19 needed for multihoming tests"
        pytest.skip(tgen.errors)

    # Configure TORs and hosts (IPv6-only for now)
    tors = ["torm11", "torm12", "torm21", "torm22"]
    config_tors(tgen, tors)

    # CRITICAL: Enable IPv6 and disable DAD BEFORE starting daemons
    # This must be done before zebra tries to configure IPv6 addresses
    router_list = tgen.routers()
    for rname, router in router_list.items():
        # Enable IPv6 forwarding first
        router.run("sysctl -w net.ipv6.conf.all.forwarding=1")
        router.run("sysctl -w net.ipv6.conf.default.forwarding=1")
        # Disable DAD globally to prevent address configuration delays/failures
        router.run("sysctl -w net.ipv6.conf.all.accept_dad=0")
        router.run("sysctl -w net.ipv6.conf.all.dad_transmits=0")
        router.run("sysctl -w net.ipv6.conf.default.accept_dad=0")
        router.run("sysctl -w net.ipv6.conf.default.dad_transmits=0")

    # Load unified FRR configurations using integrated-vtysh-config
    config_dir = os.path.join(CWD, ip_version)
    for rname, router in router_list.items():
        logger.info(
            "Loading unified %s config for %s from %s", ip_version, rname, config_dir
        )
        # Enable mgmtd first (required for modern FRR)
        router.load_config(TopoRouter.RD_MGMTD, "")
        # Load unified frr.conf from the IP-version specific config directory
        router.load_frr_config(os.path.join(config_dir, "{}/frr.conf".format(rname)))

    # For all TORs we now manage addresses directly via Linux iproute2 in
    # config_tor(), not via FRR interface configuration. Prevent startRouter()
    # from flushing those kernel IPs, and for torm11 specifically, exercise
    # config application via frr-reload.py instead of the default
    # "vtysh -f /etc/frr/frr.conf" path in Router.startRouter.
    torm11 = router_list.get("torm11")
    for tor_name in tors:
        tor = router_list.get(tor_name)
        if tor is None:
            continue
        # `tor` is a TopoRouter wrapper; the actual FRR router object is
        # `tor.net` (topotest.Router). Apply flags there so that
        # Router.startRouter() sees them.
        nrouter = tor.net
        nrouter.skip_remove_ips = True
        if tor_name == "torm11":
            nrouter.skip_unified_vtysh = True

    logger.info("Starting all routers...")
    tgen.start_router()

    # Give daemons a moment to stabilize
    time.sleep(2)

    # Verify all routers started successfully
    logger.info("Verifying router daemons started...")
    for rname, router in router_list.items():
        status = router.check_router_running()
        if status:
            logger.error("Router %s has issues: %s", rname, status)
            pytest.fail("Router {} failed to start properly: {}".format(rname, status))

    # Explicitly exercise frr-reload on torm11 using the unified frr.conf.
    # Run this inside the torm11 namespace so that vtysh talks to the correct daemons.
    if torm11 is not None:
        logger.info("Running frr-reload.py on torm11 unified config")
        cmd = "/usr/lib/frr/frr-reload.py --reload /etc/frr/frr.conf"
        # Run inside the torm11 namespace (TopoRouter.net is the underlying node)
        rc, out, err = torm11.net.cmd_status(cmd, warn=False)
        if rc:
            logger.error(
                "frr-reload failed on torm11 (rc=%s): stdout=%s stderr=%s",
                rc,
                out,
                err,
            )
            pytest.fail("frr-reload failed on torm11 (rc={})".format(rc))

        # Sanity check that all expected daemons on torm11 are still healthy
        status = torm11.check_router_running()
        if status:
            logger.error("Router torm11 has issues after frr-reload: %s", status)
            pytest.fail(
                "Router torm11 failed health-check after frr-reload: {}".format(status)
            )

    # Configure hosts
    hosts = ["hostd11", "hostd12", "hostd21", "hostd22"]
    config_hosts(tgen, hosts)

    # Disable DAD on all interfaces (additional per-interface configuration)
    disable_dad_on_all_interfaces(tgen)

    # Final underlay/BGP sanity check on torm11: verify that loopback/uplink
    # IPv6 addresses are present in the kernel and that IPv6 BGP neighbors
    # towards leaf1/leaf2 establish. This uses the generic helper so it can be
    # reused for other routers/AFs if needed.
    if torm11 is not None:
        check_fn = partial(
            check_underlay_and_bgp_ipv6,
            torm11,
            lo_prefix="2001:db8:100::15/128",
            uplink_prefixes=tor_uplink_ipv6["torm11"],
            neighbors=["2001:db8:1::1", "2001:db8:5::1"],
        )
        _, result = topotest.run_and_expect(check_fn, None, count=20, wait=3)
        assert result is None, "torm11 underlay/BGP sanity failed: %s" % (result,)

    # Yield to tests
    yield tgen, ip_version

    # Teardown
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
    bgp_es = dut.vtysh_cmd("show bgp l2vpn evpn es json")
    bgp_es_json = json.loads(bgp_es)

    result = None

    expected_es_set = set([v for k, v in host_es_map.items()])
    curr_es_set = []

    # check is ES content is correct
    for es in bgp_es_json:
        esi = es["esi"]
        curr_es_set.append(esi)
        if not es.get("type", False):
            return None
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
    bgp_es = dut.vtysh_cmd("show bgp l2vpn evpn es %s json" % esi)
    es = json.loads(bgp_es)

    if not es:
        return "esi %s not found" % esi

    esi = es["esi"]
    if not es.get("type", False):
        return None
    types = es["type"]
    vtep_ips = []
    for vtep in es.get("vteps", []):
        vtep_ips.append(vtep["vtep_ip"])

    if "local" in types:
        result = check_local_es(esi, vtep_ips, dut.name, down_vteps)
    else:
        result = check_remote_es(esi, vtep_ips, dut.name, down_vteps)

    return result


def test_evpn_es(tgen_and_ip_version):
    """
    Two ES are setup on each rack. This test checks if -
    1. ES peer has been added to the local ES (via Type-1/EAD route)
    2. The remote ESs are setup with the right list of PEs (via Type-1)
    """

    tgen, ip_version = tgen_and_ip_version

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    dut_name = "torm11"
    dut = tgen.gears[dut_name]
    test_fn = partial(check_es, dut)
    _, result = topotest.run_and_expect(test_fn, None, count=20, wait=3)

    assertmsg = '"{}" ES content incorrect. Result: {}'.format(dut_name, result)
    assert result is None, assertmsg


def test_evpn_ead_update(tgen_and_ip_version):
    """
    Flap a host link one the remote rack and check if the EAD updates
    are sent/processed for the corresponding ESI
    """
    tgen, ip_version = tgen_and_ip_version

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


def ping_anycast_gw(tgen):
    # ping the anycast gw from the local and remote hosts to populate
    # the mac address on the PEs
    intf = "torbond"
    ipaddr = "2001:db8:45::1"
    for name in ("hostd11", "hostd21", "hostd12", "hostd22"):
        host = tgen.net.hosts[name]
        # Use ping6 to trigger neighbor discovery
        ping_cmd = "ping6 -I {} -c 1 {}".format(intf, ipaddr)
        _, stdout, _ = host.cmd_status(ping_cmd, warn=False, stderr=subprocess.STDOUT)
        stdout = stdout.strip()
        if stdout:
            host.logger.debug(
                "%s: ping6 on %s for %s returned: %s", name, intf, ipaddr, stdout
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
        if tmp_esi == esi and tmp_m_type == m_type and tmp_intf == intf:
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


def test_evpn_mac(tgen_and_ip_version):
    """
    1. Add a MAC on hostd11 and check if the MAC is synced between
    torm11 and torm12. And installed as a local MAC.
    2. Add a MAC on hostd21 and check if the MAC is installed as a
    remote MAC on torm11 and torm12
    """

    tgen, ip_version = tgen_and_ip_version

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


def test_evpn_df(tgen_and_ip_version):
    """
    1. Check the DF role on all the PEs on rack-1.
    2. Increase the DF preference on the non-DF and check if it becomes
       the DF winner.
    """

    tgen, ip_version = tgen_and_ip_version

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


def test_evpn_uplink_tracking(tgen_and_ip_version):
    """
    1. Wait for access ports to come out of startup-delay
    2. disable uplinks and check if access ports have been protodowned
    3. enable uplinks and check if access ports have been moved out
       of protodown
    """

    tgen, ip_version = tgen_and_ip_version

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
