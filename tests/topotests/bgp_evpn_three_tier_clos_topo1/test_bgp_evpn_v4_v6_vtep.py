#!/usr/bin/env python
# SPDX-License-Identifier: ISC

#
# test_bgp_evpn_v4_v6_vtep.py
# Part of NetDEF Topology Tests
#
# Copyright (c) 2025 by Nvidia Corporation
#

"""
test_bgp_evpn_v4_v6_vtep.py: Test BGP EVPN with VXLAN using Single VXLAN Device (SVD)
configuration with IPv6 VTEPs and eBGP numbered underlay in 3-tier CLOS topology.

Commands Invoked During Test Execution
=======================================

VTYSH Commands:
---------------
1. show bgp summary json
2. show bgp l2vpn evpn route json
3. show bgp l2vpn evpn vni {vni} json
4. show evpn vni {vni} json
5. show evpn rmac vni {vni} json
6. show evpn next-hops vni {vni} json
7. show ip route vrf {vrf}
8. show ip route vrf {vrf} {route} json
9. show ipv6 route vrf {vrf} {route} json

Linux Commands:
---------------
10. bridge -j fdb show
11. ip -d -j link show {vxlan_device}
12. ip -j route show vrf {vrf} {route}
13. ip -j nexthop get id {nhid}
14. ping / ping6

Test Execution Order:
=====================
1. test_bgp_summary_neighbor_state      - Verify BGP neighbors established
2. test_evpn_routes_advertised          - Verify EVPN route advertisement
3. test_evpn_vni_remote_vtep_and_hrep   - Verify remote VTEPs and HREP entries
4. test_evpn_local_vtep_ip              - Verify local VTEP source IP
5. test_vni_state                       - Verify VNI state (L2 and L3)
6. test_l3vni_rmacs                     - Verify L3VNI RMACs
7. test_vrf_routes                      - Display VRF routes (informational)
8. test_evpn_vtep_nexthops              - Verify L3VNI next-hops
9. test_evpn_check_overlay_route        - Verify EVPN Type-5 overlay route in VRF RIB
10. test_host_to_host_ping              - Verify end-to-end connectivity
11. test_memory_leak                    - Memory leak detection
"""

import os
import sys
import json
from functools import partial
import pytest

# Save the Current Working Directory to find configuration files.
CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

# pylint: disable=C0413
# Import topogen and topotest helpers
from lib import topotest
from lib.topogen import Topogen, TopoRouter, get_topogen
from lib.topolog import logger
from lib.common_config import required_linux_kernel_version
from lib.evpn import (
    evpn_verify_vni_remote_vteps,
    evpn_verify_vni_vtep_src_ip,
    evpn_verify_vni_state,
    evpn_verify_route_advertisement,
    evpn_verify_bgp_vni_state,
    evpn_verify_l3vni_remote_rmacs,
    evpn_verify_l3vni_remote_nexthops,
    evpn_verify_vrf_rib_route,
    evpn_verify_overlay_route_in_kernel,
    evpn_trigger_arp_scapy,
    evpn_verify_ping_connectivity,
)

# Required to instantiate the topology builder class.

pytestmark = [pytest.mark.evpn]

# VTEP source IP addresses by underlay version
VTEP_IPS = {
    "ipv6": {
        "bordertor-11": "fd00:0:20::1",
        "bordertor-12": "fd00:0:20::2",
        "tor-21": "fd00:0:20::30",
        "tor-22": "fd00:0:20::31",
    },
    "ipv4": {
        "bordertor-11": "10.0.0.1",
        "bordertor-12": "10.0.0.2",
        "tor-21": "10.0.0.30",
        "tor-22": "10.0.0.31",
    },
}


@pytest.fixture(scope="module", params=["ipv4", "ipv6"])
def tgen_and_ip_version(request):
    """
    Fixture to setup topology with parametrized IPv4/IPv6 underlay

    Returns:
        tuple: (tgen, ip_version)
    """
    ip_version = request.param

    # Check kernel version
    result = required_linux_kernel_version("5.15")
    if result is not True:
        pytest.skip("Kernel requirements are not met, kernel version should be >= 5.15")

    # This function initiates the topology build with Topogen
    tgen = Topogen(build_topo, request.module.__name__)

    # ... and here it calls Mininet initialization functions.
    tgen.start_topology()

    # Determine config directory based on IP version
    config_dir = os.path.join(CWD, ip_version)
    logger.info(
        f"Running test with {ip_version} underlay configuration from {config_dir}"
    )

    # Get VTEP IPs for this IP version
    vtep_ips = VTEP_IPS[ip_version]

    # Configure SVD on all 4 VTEPs using appropriate VTEP source IPs
    # Border ToRs
    setup_vtep(tgen, "bordertor-11", vtep_ips["bordertor-11"], is_bordertor=True)
    setup_vtep(tgen, "bordertor-12", vtep_ips["bordertor-12"], is_bordertor=True)

    # ToRs
    setup_vtep(tgen, "tor-21", vtep_ips["tor-21"], is_bordertor=False)
    setup_vtep(tgen, "tor-22", vtep_ips["tor-22"], is_bordertor=False)

    # Configure BorderToR to external router connectivity
    setup_bordertor_ext_connectivity(tgen, ip_version)

    # Configure external router
    setup_ext1(tgen, ip_version)

    # Load FRR configuration for all routers from IP-version-specific directory
    router_list = tgen.routers()

    for rname, router in router_list.items():
        conf_file = os.path.join(config_dir, rname, "frr.conf")
        if os.path.exists(conf_file):
            logger.info(f"Loading {ip_version} configuration for {rname}")
            router.load_frr_config(conf_file)
        else:
            logger.warning(f"Config file not found: {conf_file}")

    # Start all routers
    tgen.start_router()

    # Trigger ARP/NDP to populate MAC tables
    logger.info("Triggering ARP/NDP for MAC learning")

    # Define VLAN interfaces and their host-gateway mappings
    vlan_host_gateways = {
        "swp1": {  # VLAN 111 (VRF2) - 192.168.11.0/24
            "host-111": "192.168.11.11",
            "host-121": "192.168.11.12",
            "host-211": "192.168.11.21",
            "host-221": "192.168.11.22",
        },
        "swp2": {  # VLAN 112 (VRF1) - 192.168.12.0/24
            "host-211": "192.168.12.21",
            "host-221": "192.168.12.22",
        },
    }

    # Trigger ARP for each VLAN interface
    for interface, host_gateways in vlan_host_gateways.items():
        logger.info(f"Triggering ARP on {interface} for {len(host_gateways)} hosts")
        evpn_trigger_arp_scapy(tgen, host_gateways, interface=interface)

    # Yield control to tests
    yield tgen, ip_version

    # Teardown - Cleanup VXLAN interfaces and bridges on all VTEPs before stopping
    logger.info("Cleaning up VXLAN interfaces on all VTEPs")
    for rname in ["bordertor-11", "bordertor-12", "tor-21", "tor-22"]:
        if rname in tgen.gears:
            router = tgen.gears[rname]
            logger.info(f"Cleaning up interfaces on {rname}")

            # Bring interfaces down first
            router.run("ip link set dev vlan111 down 2>/dev/null || true")
            router.run("ip link set dev vlan112 down 2>/dev/null || true")
            router.run("ip link set dev vlan4001 down 2>/dev/null || true")
            router.run("ip link set dev vlan4002 down 2>/dev/null || true")
            router.run("ip link set dev vxlan48 down 2>/dev/null || true")
            router.run("ip link set dev vxlan99 down 2>/dev/null || true")
            router.run("ip link set dev br_default down 2>/dev/null || true")
            router.run("ip link set dev br_l3vni down 2>/dev/null || true")

            # Delete in dependency order
            router.run("ip link del vlan111 2>/dev/null || true")
            router.run("ip link del vlan112 2>/dev/null || true")
            router.run("ip link del vlan4001 2>/dev/null || true")
            router.run("ip link del vlan4002 2>/dev/null || true")
            router.run("ip link del vxlan48 2>/dev/null || true")
            router.run("ip link del vxlan99 2>/dev/null || true")
            router.run("ip link del br_default 2>/dev/null || true")
            router.run("ip link del br_l3vni 2>/dev/null || true")
            router.run("ip link del vrf1 2>/dev/null || true")
            router.run("ip link del vrf2 2>/dev/null || true")

    tgen.stop_topology()


def build_topo(tgen):
    """
    Build 3-tier CLOS topology with 16 nodes:
    - 2 spines (spine-1, spine-2)
    - 4 leafs (leaf-11, leaf-12, leaf-21, leaf-22)
    - 2 border ToRs (bordertor-11, bordertor-12) - EVPN VTEPs
    - 2 ToRs (tor-21, tor-22) - EVPN VTEPs
    - 1 external router (ext-1)
    - 5 hosts (host-111, host-121, host-211, host-221, host-1)
    """

    # Create routers
    tgen.add_router("spine-1")
    tgen.add_router("spine-2")
    tgen.add_router("leaf-11")
    tgen.add_router("leaf-12")
    tgen.add_router("leaf-21")
    tgen.add_router("leaf-22")
    tgen.add_router("bordertor-11")
    tgen.add_router("bordertor-12")
    tgen.add_router("tor-21")
    tgen.add_router("tor-22")
    tgen.add_router("ext-1")
    tgen.add_router("host-111")
    tgen.add_router("host-121")
    tgen.add_router("host-211")
    tgen.add_router("host-221")
    tgen.add_router("host-1")

    # Spine-1 to Leafs
    switch = tgen.add_switch("s1")
    switch.add_link(tgen.gears["spine-1"], nodeif="swp1")
    switch.add_link(tgen.gears["leaf-11"], nodeif="swp1")

    switch = tgen.add_switch("s2")
    switch.add_link(tgen.gears["spine-1"], nodeif="swp2")
    switch.add_link(tgen.gears["leaf-12"], nodeif="swp1")

    switch = tgen.add_switch("s3")
    switch.add_link(tgen.gears["spine-1"], nodeif="swp3")
    switch.add_link(tgen.gears["leaf-21"], nodeif="swp1")

    switch = tgen.add_switch("s4")
    switch.add_link(tgen.gears["spine-1"], nodeif="swp4")
    switch.add_link(tgen.gears["leaf-22"], nodeif="swp1")

    # Spine-2 to Leafs
    switch = tgen.add_switch("s5")
    switch.add_link(tgen.gears["spine-2"], nodeif="swp1")
    switch.add_link(tgen.gears["leaf-11"], nodeif="swp2")

    switch = tgen.add_switch("s6")
    switch.add_link(tgen.gears["spine-2"], nodeif="swp2")
    switch.add_link(tgen.gears["leaf-12"], nodeif="swp2")

    switch = tgen.add_switch("s7")
    switch.add_link(tgen.gears["spine-2"], nodeif="swp3")
    switch.add_link(tgen.gears["leaf-21"], nodeif="swp2")

    switch = tgen.add_switch("s8")
    switch.add_link(tgen.gears["spine-2"], nodeif="swp4")
    switch.add_link(tgen.gears["leaf-22"], nodeif="swp2")

    # Leaf-11 to BorderToRs
    switch = tgen.add_switch("s9")
    switch.add_link(tgen.gears["leaf-11"], nodeif="swp3")
    switch.add_link(tgen.gears["bordertor-11"], nodeif="swp1")

    switch = tgen.add_switch("s10")
    switch.add_link(tgen.gears["leaf-11"], nodeif="swp4")
    switch.add_link(tgen.gears["bordertor-12"], nodeif="swp1")

    # Leaf-12 to BorderToRs
    switch = tgen.add_switch("s11")
    switch.add_link(tgen.gears["leaf-12"], nodeif="swp3")
    switch.add_link(tgen.gears["bordertor-11"], nodeif="swp2")

    switch = tgen.add_switch("s12")
    switch.add_link(tgen.gears["leaf-12"], nodeif="swp4")
    switch.add_link(tgen.gears["bordertor-12"], nodeif="swp2")

    # Leaf-21 to ToRs
    switch = tgen.add_switch("s13")
    switch.add_link(tgen.gears["leaf-21"], nodeif="swp3")
    switch.add_link(tgen.gears["tor-21"], nodeif="swp1")

    switch = tgen.add_switch("s14")
    switch.add_link(tgen.gears["leaf-21"], nodeif="swp4")
    switch.add_link(tgen.gears["tor-22"], nodeif="swp1")

    # Leaf-22 to ToRs
    switch = tgen.add_switch("s15")
    switch.add_link(tgen.gears["leaf-22"], nodeif="swp3")
    switch.add_link(tgen.gears["tor-21"], nodeif="swp2")

    switch = tgen.add_switch("s16")
    switch.add_link(tgen.gears["leaf-22"], nodeif="swp4")
    switch.add_link(tgen.gears["tor-22"], nodeif="swp2")

    # BorderToR-11 to External Router
    switch = tgen.add_switch("s17")
    switch.add_link(tgen.gears["bordertor-11"], nodeif="swp3")
    switch.add_link(tgen.gears["ext-1"], nodeif="swp1")

    # BorderToR-12 to External Router
    switch = tgen.add_switch("s18")
    switch.add_link(tgen.gears["bordertor-12"], nodeif="swp3")
    switch.add_link(tgen.gears["ext-1"], nodeif="swp2")

    # BorderToR-11 to Host (VLAN 111 only)
    switch = tgen.add_switch("s19")
    switch.add_link(tgen.gears["bordertor-11"], nodeif="swp4")
    switch.add_link(tgen.gears["host-111"], nodeif="swp1")

    # BorderToR-12 to Host (VLAN 111 only)
    switch = tgen.add_switch("s20")
    switch.add_link(tgen.gears["bordertor-12"], nodeif="swp4")
    switch.add_link(tgen.gears["host-121"], nodeif="swp1")

    # ToR-21 to Host host-211 (VLAN 111 on swp3, VLAN 112 on swp4)
    switch = tgen.add_switch("s21")
    switch.add_link(tgen.gears["tor-21"], nodeif="swp3")
    switch.add_link(tgen.gears["host-211"], nodeif="swp1")

    switch = tgen.add_switch("s27")
    switch.add_link(tgen.gears["tor-21"], nodeif="swp4")
    switch.add_link(tgen.gears["host-211"], nodeif="swp2")

    # ToR-22 to Host host-221 (VLAN 111 on swp3, VLAN 112 on swp4)
    switch = tgen.add_switch("s22")
    switch.add_link(tgen.gears["tor-22"], nodeif="swp3")
    switch.add_link(tgen.gears["host-221"], nodeif="swp1")

    switch = tgen.add_switch("s28")
    switch.add_link(tgen.gears["tor-22"], nodeif="swp4")
    switch.add_link(tgen.gears["host-221"], nodeif="swp2")

    # External router to host-1 (4 links)
    switch = tgen.add_switch("s23")
    switch.add_link(tgen.gears["ext-1"], nodeif="swp3")
    switch.add_link(tgen.gears["host-1"], nodeif="swp1")

    switch = tgen.add_switch("s24")
    switch.add_link(tgen.gears["ext-1"], nodeif="swp4")
    switch.add_link(tgen.gears["host-1"], nodeif="swp2")

    switch = tgen.add_switch("s25")
    switch.add_link(tgen.gears["ext-1"], nodeif="swp5")
    switch.add_link(tgen.gears["host-1"], nodeif="swp3")

    switch = tgen.add_switch("s26")
    switch.add_link(tgen.gears["ext-1"], nodeif="swp6")
    switch.add_link(tgen.gears["host-1"], nodeif="swp4")


def setup_vtep(tgen, rname, local_ip, is_bordertor=True):
    """
    Configure TRUE Single VXLAN Device (SVD) on VTEPs (border ToRs and ToRs)
    Uses ONE vxlan device (vxlan48) for ALL VNIs (both L2 and L3)
    Uses a single VLAN-aware bridge with all VLANs mapped to their VNIs
    """
    router = tgen.gears[rname]

    logger.info(f"Configuring TRUE SVD on {rname} with VTEP {local_ip}")

    # Cleanup any existing interfaces from previous runs
    logger.info(f"Cleaning up existing interfaces on {rname}")
    # First bring interfaces down, then delete them
    router.run("ip link set dev vlan111 down 2>/dev/null || true")
    router.run("ip link set dev vlan112 down 2>/dev/null || true")
    router.run("ip link set dev vlan4001 down 2>/dev/null || true")
    router.run("ip link set dev vlan4002 down 2>/dev/null || true")
    router.run("ip link set dev vxlan48 down 2>/dev/null || true")
    router.run("ip link set dev vxlan99 down 2>/dev/null || true")
    router.run("ip link set dev br_default down 2>/dev/null || true")
    router.run("ip link set dev br_l3vni down 2>/dev/null || true")

    # Delete VLAN interfaces first (they depend on bridges)
    router.run("ip link del vlan111 2>/dev/null || true")
    router.run("ip link del vlan112 2>/dev/null || true")
    router.run("ip link del vlan4001 2>/dev/null || true")
    router.run("ip link del vlan4002 2>/dev/null || true")

    # Delete VXLAN interfaces (they depend on bridges)
    router.run("ip link del vxlan48 2>/dev/null || true")
    router.run("ip link del vxlan99 2>/dev/null || true")

    # Delete bridges
    router.run("ip link del br_default 2>/dev/null || true")
    router.run("ip link del br_l3vni 2>/dev/null || true")

    # Delete VRF interfaces last
    router.run("ip link del vrf1 2>/dev/null || true")
    router.run("ip link del vrf2 2>/dev/null || true")

    # Small delay to ensure kernel processes deletions
    import time

    time.sleep(0.5)

    # Create ONE VLAN-aware bridge for ALL VNIs (L2 and L3)
    router.run("ip link add name br_default type bridge stp_state 0")
    router.run("ip link set dev br_default type bridge vlan_filtering 1")
    router.run("ip link set dev br_default type bridge ageing_time 18000")
    router.run("ip link set dev br_default up")

    # Add all VLANs to the bridge (L2VNIs: 111, 112 and L3VNIs: 4001, 4002)
    router.run("bridge vlan add vid 111 dev br_default self")
    router.run("bridge vlan add vid 112 dev br_default self")
    router.run("bridge vlan add vid 4001 dev br_default self")
    router.run("bridge vlan add vid 4002 dev br_default self")

    # Create ONE Single VXLAN Device for ALL VNIs (both L2 and L3)
    router.run(
        f"ip link add vxlan48 type vxlan dstport 4789 local {local_ip} nolearning external ttl 64 ageing 18000"
    )
    router.run("ip link set dev vxlan48 master br_default")
    router.run("bridge link set dev vxlan48 vlan_tunnel on")
    router.run("bridge link set dev vxlan48 neigh_suppress on")
    router.run("bridge link set dev vxlan48 learning off")

    # Map ALL VLANs to their respective VNIs on the single VXLAN device
    # L2VNIs
    router.run("bridge vlan add dev vxlan48 vid 111")
    router.run("bridge vlan add dev vxlan48 vid 111 tunnel_info id 1000111")
    router.run("bridge vlan add dev vxlan48 vid 112")
    router.run("bridge vlan add dev vxlan48 vid 112 tunnel_info id 1000112")

    # L3VNIs
    router.run("bridge vlan add dev vxlan48 vid 4001")
    router.run("bridge vlan add dev vxlan48 vid 4001 tunnel_info id 104001")
    router.run("bridge vlan add dev vxlan48 vid 4002")
    router.run("bridge vlan add dev vxlan48 vid 4002 tunnel_info id 104002")

    router.run("ip link set up dev vxlan48")

    # Create VRFs
    router.run("ip link add vrf1 type vrf table 1001")
    router.run("ip link set dev vrf1 up")
    router.run("ip link add vrf2 type vrf table 1002")
    router.run("ip link set dev vrf2 up")

    # Create SVI for VLAN 111 (VRF2) from br_default
    router.run(
        "ip link add link br_default name vlan111 type vlan id 111 protocol 802.1q"
    )
    router.run("ip link set dev vlan111 master vrf2")

    # Configure SVI IPs based on router
    if rname == "bordertor-11":
        router.run("ip addr add 192.168.11.11/24 dev vlan111")
        router.run("ip addr add fd00:60:1:1::11/64 dev vlan111")
    elif rname == "bordertor-12":
        router.run("ip addr add 192.168.11.12/24 dev vlan111")
        router.run("ip addr add fd00:60:1:1::12/64 dev vlan111")
    elif rname == "tor-21":
        router.run("ip addr add 192.168.11.21/24 dev vlan111")
        router.run("ip addr add fd00:60:1:1::21/64 dev vlan111")
    elif rname == "tor-22":
        router.run("ip addr add 192.168.11.22/24 dev vlan111")
        router.run("ip addr add fd00:60:1:1::22/64 dev vlan111")

    router.run("ip link set dev vlan111 up")
    router.run("/sbin/sysctl net.ipv4.conf.vlan111.arp_accept=1")

    # Create SVI for VLAN 112 (VRF1) from br_default
    router.run(
        "ip link add link br_default name vlan112 type vlan id 112 protocol 802.1q"
    )
    router.run("ip link set dev vlan112 master vrf1")

    if rname == "bordertor-11":
        router.run("ip addr add 192.168.12.11/24 dev vlan112")
        router.run("ip addr add fd00:50:1:1::11/64 dev vlan112")
    elif rname == "bordertor-12":
        router.run("ip addr add 192.168.12.12/24 dev vlan112")
        router.run("ip addr add fd00:50:1:1::12/64 dev vlan112")
    elif rname == "tor-21":
        router.run("ip addr add 192.168.12.21/24 dev vlan112")
        router.run("ip addr add fd00:50:1:1::21/64 dev vlan112")
    elif rname == "tor-22":
        router.run("ip addr add 192.168.12.22/24 dev vlan112")
        router.run("ip addr add fd00:50:1:1::22/64 dev vlan112")

    router.run("ip link set dev vlan112 up")
    router.run("/sbin/sysctl net.ipv4.conf.vlan112.arp_accept=1")

    # Create L3VNI interfaces from br_default (same bridge as L2VNIs)
    router.run(
        "ip link add link br_default name vlan4001 type vlan id 4001 protocol 802.1q"
    )
    router.run("ip link set dev vlan4001 master vrf1")
    router.run("ip link set dev vlan4001 up")

    router.run(
        "ip link add link br_default name vlan4002 type vlan id 4002 protocol 802.1q"
    )
    router.run("ip link set dev vlan4002 master vrf2")
    router.run("ip link set dev vlan4002 up")

    # Add host interfaces to br_default bridge
    # Border ToRs: swp4 for hosts (VLAN 111 only)
    # Regular ToRs: swp3 for hosts (VLAN 111), swp4 for hosts (VLAN 112)
    if is_bordertor:
        # bordertor-11/12: swp4 only (VLAN 111)
        intf = "swp4"
        router.run(f"ip link set dev {intf} master br_default")
        router.run(f"bridge vlan del vid 1 dev {intf}")
        router.run(f"bridge vlan del vid 1 untagged pvid dev {intf}")
        # Add host to VLAN 111 (host-111 or host-121)
        router.run(f"bridge vlan add vid 111 dev {intf}")
        router.run(f"bridge vlan add vid 111 pvid untagged dev {intf}")
    else:
        # tor-21/22: swp3 (VLAN 111), swp4 (VLAN 112)
        # swp3: VLAN 111 (host-211/221 swp1)
        intf = "swp3"
        router.run(f"ip link set dev {intf} master br_default")
        router.run(f"bridge vlan del vid 1 dev {intf}")
        router.run(f"bridge vlan del vid 1 untagged pvid dev {intf}")
        router.run(f"bridge vlan add vid 111 dev {intf}")
        router.run(f"bridge vlan add vid 111 pvid untagged dev {intf}")

        # swp4: VLAN 112 (host-211/221 swp2)
        intf = "swp4"
        router.run(f"ip link set dev {intf} master br_default")
        router.run(f"bridge vlan del vid 1 dev {intf}")
        router.run(f"bridge vlan del vid 1 untagged pvid dev {intf}")
        router.run(f"bridge vlan add vid 112 dev {intf}")
        router.run(f"bridge vlan add vid 112 pvid untagged dev {intf}")


def setup_bordertor_ext_connectivity(tgen, ip_version):
    """
    Configure BorderToR interfaces for external router connectivity

    Args:
        tgen: Topogen instance
        ip_version: IP version for underlay ("ipv4" or "ipv6")
    """
    # Configure bordertor-11
    router = tgen.gears["bordertor-11"]
    logger.info("Configuring bordertor-11 external connectivity interfaces")

    # Configure VLAN sub-interfaces on swp3 for L3VNI connectivity to ext-1
    # swp3.4001 for VRF1 L3VNI
    router.run("ip link add link swp3 name swp3.4001 type vlan id 4001")
    router.run("ip link set dev swp3.4001 master vrf1")
    router.run("ip addr add 192.0.2.2/30 dev swp3.4001")
    if ip_version == "ipv6":
        router.run("ip addr add 2001:db8:144:1::2/64 dev swp3.4001")
    router.run("ip link set dev swp3.4001 up")

    # swp3.4002 for VRF2 L3VNI
    router.run("ip link add link swp3 name swp3.4002 type vlan id 4002")
    router.run("ip link set dev swp3.4002 master vrf2")
    router.run("ip addr add 192.0.2.6/30 dev swp3.4002")
    if ip_version == "ipv6":
        router.run("ip addr add 2001:db8:144:2::6/64 dev swp3.4002")
    router.run("ip link set dev swp3.4002 up")

    # Configure bordertor-12
    router = tgen.gears["bordertor-12"]
    logger.info("Configuring bordertor-12 external connectivity interfaces")

    # Configure VLAN sub-interfaces on swp3 for L3VNI connectivity to ext-1
    # swp3.4001 for VRF1 L3VNI
    router.run("ip link add link swp3 name swp3.4001 type vlan id 4001")
    router.run("ip link set dev swp3.4001 master vrf1")
    router.run("ip addr add 192.0.2.10/30 dev swp3.4001")
    if ip_version == "ipv6":
        router.run("ip addr add 2001:db8:144:11::2/64 dev swp3.4001")
    router.run("ip link set dev swp3.4001 up")

    # swp3.4002 for VRF2 L3VNI
    router.run("ip link add link swp3 name swp3.4002 type vlan id 4002")
    router.run("ip link set dev swp3.4002 master vrf2")
    router.run("ip addr add 192.0.2.14/30 dev swp3.4002")
    if ip_version == "ipv6":
        router.run("ip addr add 2001:db8:144:12::6/64 dev swp3.4002")
    router.run("ip link set dev swp3.4002 up")


def setup_ext1(tgen, ip_version):
    """
    Configure external router ext-1 interfaces

    Args:
        tgen: Topogen instance
        ip_version: IP version for underlay ("ipv4" or "ipv6")
    """
    router = tgen.gears["ext-1"]

    logger.info(f"Configuring ext-1 interfaces for {ip_version} underlay")

    # Configure swp1 - Connected to bordertor-11
    router.run("ip link set dev swp1 up")
    if ip_version == "ipv6":
        router.run("ip addr add fd00:10:254::2:0:2/126 dev swp1")
    else:  # ipv4
        router.run("ip addr add 10.254.0.10/30 dev swp1")

    # Configure swp2 - Connected to bordertor-12
    router.run("ip link set dev swp2 up")
    if ip_version == "ipv6":
        router.run("ip addr add fd00:10:254::9:0:2/126 dev swp2")
    else:  # ipv4
        router.run("ip addr add 10.254.0.38/30 dev swp2")

    # Configure VLAN sub-interfaces on swp1 for bordertor-11
    # swp1.4001 for VRF1 L3VNI connectivity - always configure both IPv4 and IPv6
    router.run("ip link add link swp1 name swp1.4001 type vlan id 4001")
    router.run("ip addr add 192.0.2.1/30 dev swp1.4001")
    router.run("ip addr add 2001:db8:144:1::1/64 dev swp1.4001")
    router.run("ip link set dev swp1.4001 up")

    # swp1.4002 for VRF2 L3VNI connectivity - always configure both IPv4 and IPv6
    router.run("ip link add link swp1 name swp1.4002 type vlan id 4002")
    router.run("ip addr add 192.0.2.5/30 dev swp1.4002")
    router.run("ip addr add 2001:db8:144:2::5/64 dev swp1.4002")
    router.run("ip link set dev swp1.4002 up")

    # Configure VLAN sub-interfaces on swp2 for bordertor-12
    # swp2.4001 for VRF1 L3VNI connectivity - always configure both IPv4 and IPv6
    router.run("ip link add link swp2 name swp2.4001 type vlan id 4001")
    router.run("ip addr add 192.0.2.9/30 dev swp2.4001")
    router.run("ip addr add 2001:db8:144:11::1/64 dev swp2.4001")
    router.run("ip link set dev swp2.4001 up")

    # swp2.4002 for VRF2 L3VNI connectivity - always configure both IPv4 and IPv6
    router.run("ip link add link swp2 name swp2.4002 type vlan id 4002")
    router.run("ip addr add 192.0.2.13/30 dev swp2.4002")
    router.run("ip addr add 2001:db8:144:12::5/64 dev swp2.4002")
    router.run("ip link set dev swp2.4002 up")

    # Configure swp3-6 for connection to host-1 (4 links)
    # Using separate /24 networks from 198.51.100-103.0/24 TEST-NET-2 space
    # This matches the original design where each link has its own /24 network
    link_networks = [
        (100, 1),
        (101, 2),
        (102, 3),
        (103, 4),
    ]  # (IPv4 3rd octet, IPv6 net)
    for i, (ipv4_net, ipv6_net) in enumerate(link_networks, start=3):
        intf = f"swp{i}"
        # Check if interface exists by examining command output
        output = router.run(f"ip link show {intf} 2>&1")
        if "does not exist" not in output and "Cannot find device" not in output:
            router.run(f"ip link set dev {intf} up")
            router.run(f"ip addr add 198.51.{ipv4_net}.1/24 dev {intf}")
            router.run(f"ip addr add 2001:db8:81:{ipv6_net}::1/64 dev {intf}")
            logger.info(f"Configured {intf} on ext-1 (connected to host-1 swp{i-2})")
        else:
            logger.info(f"Interface {intf} does not exist on ext-1, skipping")


def test_bgp_summary_neighbor_state(tgen_and_ip_version):
    """
    Verify BGP neighbor states are Established based on underlay IP version

    Verifies BGP session state for the appropriate address family:
    - IPv4 underlay: checks ipv4Unicast peers
    - IPv6 underlay: checks ipv6Unicast peers
    """
    tgen, ip_version = tgen_and_ip_version
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    # Map IP version to BGP address family key
    af_key = "ipv4Unicast" if ip_version == "ipv4" else "ipv6Unicast"

    logger.info(
        f"Checking BGP convergence on all routers ({af_key} for {ip_version} underlay)"
    )

    # Check BGP convergence on key routers
    for rname in ["bordertor-11", "bordertor-12", "leaf-11", "spine-1"]:
        router = tgen.gears[rname]

        # Wait for BGP to converge
        def check_bgp_summary(router, address_family):
            output = router.vtysh_cmd("show bgp summary json", isjson=True)
            if not output:
                return "No BGP summary output"

            # Check if we have neighbors in the appropriate address family
            if address_family not in output:
                return f"No {address_family} address family in BGP summary"

            if "peers" not in output[address_family]:
                return f"No peers in {address_family} address family"

            peers = output[address_family]["peers"]
            if not peers:
                return f"No peers found in {address_family}"

            # Check each peer state
            for peer, peer_data in peers.items():
                state = peer_data.get("state", "")
                if state != "Established":
                    return f"Peer {peer} not established: {state}"

            return None

        test_func = partial(check_bgp_summary, router, af_key)
        _, result = topotest.run_and_expect(test_func, None, count=60, wait=1)
        assert result is None, f"{rname} BGP did not converge: {result}"


def test_evpn_routes_advertised(tgen_and_ip_version):
    """
    Check that EVPN routes are advertised on all VTEPs
    """
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    logger.info("Checking EVPN routes on all 4 VTEPs")

    for rname in ["bordertor-11", "bordertor-12", "tor-21", "tor-22"]:
        router = tgen.gears[rname]

        logger.info(f"Verifying EVPN route advertisement on {rname}")

        # Check that at least Type-3 (IMET) routes are present
        # VTEPs always advertise Type-3 routes for their VNIs
        test_func = partial(
            evpn_verify_route_advertisement,
            router,
            min_type3=1,  # At least 1 Type-3 (IMET) route should be present
        )
        # Increase timeout to 40 seconds to allow for BGP convergence
        _, result = topotest.run_and_expect(test_func, None, count=40, wait=1)
        assert (
            result is None
        ), f"{rname} EVPN route advertisement check failed: {result}"


def test_evpn_vni_remote_vtep_and_hrep(tgen_and_ip_version):
    """
    Verify remote VTEPs and HREP (Head-end Replication) entries for each VNI on all VTEPs

    This test validates that each VTEP has correctly learned remote VTEPs for all L2VNIs
    through the EVPN control plane and that the corresponding HREP entries are populated
    in the bridge FDB for VXLAN head-end replication.
    """
    tgen, ip_version = tgen_and_ip_version
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    logger.info(
        f"Checking remote VTEPs for each VNI on all 4 VTEPs ({ip_version} underlay)"
    )

    # Get VTEP IPs for the current IP version from module-level VTEP_IPS dictionary
    vtep_ips = VTEP_IPS[ip_version]

    # L2VNIs to check
    vni_list = ["1000111", "1000112"]

    for rname in ["bordertor-11", "bordertor-12", "tor-21", "tor-22"]:
        router = tgen.gears[rname]

        # Build expected remote VTEPs list (all VTEPs except itself)
        local_vtep_ip = vtep_ips[rname]
        expected_remote_vteps = [ip for ip in vtep_ips.values() if ip != local_vtep_ip]

        logger.info(
            f"Checking {rname} (local VTEP: {local_vtep_ip}) expects remote VTEPs: {expected_remote_vteps}"
        )

        # Use library function to check remote VTEPs for each VNI
        test_func = partial(
            evpn_verify_vni_remote_vteps, router, vni_list, expected_remote_vteps
        )
        _, result = topotest.run_and_expect(test_func, None, count=30, wait=1)
        assert result is None, f"{rname} remote VTEP verification failed: {result}"


def test_evpn_local_vtep_ip(tgen_and_ip_version):
    """
    Verify local VTEP IP is correctly configured in kernel and FRR for all VNIs on all VTEPs

    This test validates that the local VTEP source IP address is properly configured
    for both L2 and L3 VNIs in the VXLAN device and advertised via EVPN.
    """
    tgen, ip_version = tgen_and_ip_version
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    logger.info(
        f"Checking VTEP source IP configuration on all 4 VTEPs ({ip_version} underlay)"
    )

    # Get VTEP IPs for the current IP version from module-level VTEP_IPS dictionary
    vtep_ips = VTEP_IPS[ip_version]

    # L2 VNIs to verify
    l2vni_list = ["1000111", "1000112"]

    # L3 VNIs to verify
    l3vni_list = ["104001", "104002"]

    for rname in ["bordertor-11", "bordertor-12", "tor-21", "tor-22"]:
        router = tgen.gears[rname]
        vtep_ip = vtep_ips[rname]

        logger.info(f"Verifying L2 VNI VTEP source IP on {rname} (expected: {vtep_ip})")

        # Check L2 VNIs - In SVD configuration, vxlan48 handles both L2 and L3 VNIs
        test_func = partial(
            evpn_verify_vni_vtep_src_ip,
            router,
            vtep_ip,
            l2vni_list,
            vni_type="L2",
            vxlan_device="vxlan48",
        )
        _, result = topotest.run_and_expect(test_func, None, count=30, wait=1)
        assert (
            result is None
        ), f"{rname} L2 VNI VTEP source IP verification failed: {result}"

        logger.info(f"Verifying L3 VNI VTEP source IP on {rname} (expected: {vtep_ip})")

        # Check L3 VNIs - In SVD, same vxlan48 device is used for L3 VNIs too
        # But we skip kernel check here since we already verified the device above
        test_func = partial(
            evpn_verify_vni_vtep_src_ip,
            router,
            vtep_ip,
            l3vni_list,
            vni_type="L3",
            vxlan_device=None,  # Skip kernel check for L3 VNIs in SVD
        )
        _, result = topotest.run_and_expect(test_func, None, count=30, wait=1)
        assert (
            result is None
        ), f"{rname} L3 VNI VTEP source IP verification failed: {result}"


def test_vni_state(tgen_and_ip_version):
    """
    Verify VNI state on all VTEPs (both L2 and L3 VNIs)
    """
    tgen, ip_version = tgen_and_ip_version
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    logger.info("Checking VNI state on all 4 VTEPs")

    # L2 VNIs to verify
    l2vni_list = ["1000111", "1000112"]

    # L3 VNIs to verify
    l3vni_list = ["104001", "104002"]

    for rname in ["bordertor-11", "bordertor-12", "tor-21", "tor-22"]:
        router = tgen.gears[rname]

        logger.info(f"Verifying L2 VNI state on {rname}")

        # Check L2 VNIs - verifies remoteVteps and numRemoteVteps
        test_func = partial(evpn_verify_vni_state, router, l2vni_list, vni_type="L2")
        _, result = topotest.run_and_expect(test_func, None, count=30, wait=1)
        assert result is None, f"{rname} L2 VNI state verification failed: {result}"

        logger.info(f"Verifying L3 VNI state on {rname}")

        # Check L3 VNIs - verifies VRF association and router MAC
        test_func = partial(evpn_verify_vni_state, router, l3vni_list, vni_type="L3")
        _, result = topotest.run_and_expect(test_func, None, count=30, wait=1)
        assert result is None, f"{rname} L3 VNI state verification failed: {result}"


def test_static_route_advertisement(tgen_and_ip_version):
    """
    Verify that TORs are advertising their static routes as Type-5 routes.

    This test validates that:
    1. Static routes are installed in VRF routing tables
    2. Static routes are being advertised as EVPN Type-5 routes
    3. Each TOR has unique routes (no conflicts)
    4. Remote VTEPs receive these Type-5 routes
    """
    tgen, ip_version = tgen_and_ip_version
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    logger.info(
        f"Validating static route advertisement from TORs ({ip_version} underlay)"
    )

    # Expected static routes per TOR and VRF based on IP version
    if ip_version == "ipv4":
        expected_routes = {
            "tor-21": {
                "vrf1": "203.0.113.0/24",
                "vrf2": "203.0.115.0/24",
            },
            "tor-22": {
                "vrf1": "203.0.114.0/24",
                "vrf2": "203.0.116.0/24",
            },
        }
        route_cmd_prefix = "show ip route vrf"
        route_type = "IPv4"
    else:  # ipv6
        expected_routes = {
            "tor-21": {
                "vrf1": "2001:db8:72:21::/64",
                "vrf2": "2001:db8:73:21::/64",
            },
            "tor-22": {
                "vrf1": "2001:db8:72:22::/64",
                "vrf2": "2001:db8:73:22::/64",
            },
        }
        route_cmd_prefix = "show ipv6 route vrf"
        route_type = "IPv6"

    # Validate static routes
    logger.info(f"Validating {route_type} static routes")
    for tor, vrfs in expected_routes.items():
        router = tgen.gears[tor]

        for vrf, route in vrfs.items():
            # Check if static route is in VRF routing table
            output = router.vtysh_cmd(f"{route_cmd_prefix} {vrf} {route}", isjson=False)
            logger.info(f"{tor} {vrf}: {route_type} route table for {route}:\n{output}")

            # Verify route exists and is a static blackhole route
            if "blackhole" not in output.lower():
                pytest.fail(
                    f"{tor} {vrf}: {route_type} static route {route} not found or not blackhole"
                )

            logger.info(f"{tor} {vrf}: {route_type} static route {route} is installed")

    # Verify Type-5 routes are advertised
    logger.info(
        f"Checking Type-5 route advertisement for {route_type} routes (self-originated)"
    )

    for tor in ["tor-21", "tor-22"]:
        router = tgen.gears[tor]
        output = router.vtysh_cmd(
            "show bgp l2vpn evpn route self-originate", isjson=False
        )
        logger.info(f"{tor} self-originated EVPN routes:\n{output}")

        # Count Type-5 routes
        type5_count = output.count("[5]:")
        if type5_count == 0:
            pytest.fail(f"{tor}: No Type-5 routes being advertised!")

        logger.info(f"{tor}: Advertising {type5_count} Type-5 route(s)")

        # Verify specific routes are advertised (case-insensitive for IPv6)
        for vrf, route in expected_routes[tor].items():
            route_base = route.split('/')[0].lower()  # Get network address (lowercase for comparison)
            if route_base not in output.lower():
                pytest.fail(
                    f"{tor} {vrf}: {route_type} route {route} not found in Type-5 advertisements"
                )

            logger.info(
                f"{tor} {vrf}: {route_type} route {route} is being advertised as Type-5"
            )

    # Verify remote VTEPs receive these Type-5 routes
    logger.info(
        f"Checking Type-5 route reception on remote VTEPs ({ip_version} underlay)"
    )

    # Determine VTEP IPs based on IP version
    if ip_version == "ipv4":
        tor21_vtep = "10.0.0.30"
        tor22_vtep = "10.0.0.31"
    else:  # ipv6
        tor21_vtep = "fd00:0:20::30"
        tor22_vtep = "fd00:0:20::31"

    # tor-21 should receive routes from tor-22
    router = tgen.gears["tor-21"]
    output = router.vtysh_cmd(
        f"show bgp l2vpn evpn route type prefix | grep {tor22_vtep}", isjson=False
    )
    if not output or len(output.strip()) == 0:
        pytest.fail(f"tor-21: Not receiving Type-5 routes from tor-22 ({tor22_vtep})")
    logger.info(f"tor-21: Receiving Type-5 routes from tor-22 ({tor22_vtep})")

    # tor-22 should receive routes from tor-21
    router = tgen.gears["tor-22"]
    output = router.vtysh_cmd(
        f"show bgp l2vpn evpn route type prefix | grep {tor21_vtep}", isjson=False
    )
    if not output or len(output.strip()) == 0:
        pytest.fail(f"tor-22: Not receiving Type-5 routes from tor-21 ({tor21_vtep})")
    logger.info(f"tor-22: Receiving Type-5 routes from tor-21 ({tor21_vtep})")

    logger.info(
        f"Static route advertisement validation completed successfully ({ip_version})"
    )


def test_l3vni_rmacs(tgen_and_ip_version):
    """
    Verify L3VNI Router MACs (RMACs) from remote VTEPs on all VTEPs.

    This test is IP version agnostic - it works with both IPv4 and IPv6 VTEPs.
    VTEP addresses are dynamically discovered from vxlan48 device configuration.
    """
    tgen, ip_version = tgen_and_ip_version
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    logger.info(f"Checking L3VNI RMACs on all VTEPs ({ip_version} underlay)")

    # Define VTEPs and L3VNIs to verify
    vtep_routers = ["bordertor-11", "bordertor-12", "tor-21", "tor-22"]
    l3vni_list = ["104001", "104002"]

    # Use library function to discover VTEP IPs and verify L3VNI remote RMACs
    evpn_verify_l3vni_remote_rmacs(tgen, vtep_routers, l3vni_list)


def test_vrf_routes(tgen_and_ip_version):
    """
    Verify routes in VRF1 and VRF2
    """
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    logger.info("Checking VRF routes on all 4 VTEPs")

    for rname in ["bordertor-11", "bordertor-12", "tor-21", "tor-22"]:
        router = tgen.gears[rname]

        # Check VRF1 routes
        output = router.vtysh_cmd("show ip route vrf vrf1", isjson=False)
        logger.info(f"VRF1 routes on {rname}:\n{output}")

        # Check VRF2 routes
        output = router.vtysh_cmd("show ip route vrf vrf2", isjson=False)
        logger.info(f"VRF2 routes on {rname}:\n{output}")


def test_evpn_vtep_nexthops(tgen_and_ip_version):
    """
    Verify EVPN L3VNI next-hops are learned from remote VTEPs

    This test validates that EVPN L3VNI next-hops are correctly learned via
    the EVPN control plane. It uses the evpn_verify_l3vni_remote_nexthops
    library function which:
    - Auto-discovers VTEP IPs from the VXLAN device (IPv4/IPv6 agnostic)
    - Verifies each VTEP has learned next-hops from all remote VTEPs
    - Checks both L3VNIs (104001 for VRF1, 104002 for VRF2)

    Test scenario:
    - Verifies tor-21 has learned next-hops from: bordertor-11, bordertor-12, tor-22
    - L3VNIs tested: 104001 (VRF1), 104002 (VRF2)
    - Works with both IPv4 and IPv6 underlay
    """
    tgen, ip_version = tgen_and_ip_version
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    logger.info(f"Verifying EVPN L3VNI next-hops ({ip_version} underlay)")

    # Define VTEPs to test - focus on tor-21 learning from remote VTEPs
    # tor-21 should learn next-hops from: bordertor-11, bordertor-12, tor-22
    vtep_routers = ["bordertor-11", "bordertor-12", "tor-21", "tor-22"]

    # L3VNIs to verify
    l3vni_list = ["104001", "104002"]

    # Use library function to verify L3VNI next-hops
    # This will automatically:
    # - Discover VTEP IPs from vxlan48 device
    # - For each VTEP, verify it has next-hops from all other VTEPs
    # - Use retry logic with topotest.run_and_expect
    evpn_verify_l3vni_remote_nexthops(tgen, vtep_routers, l3vni_list)

    logger.info("EVPN L3VNI next-hop verification completed successfully")


def test_evpn_check_overlay_route(tgen_and_ip_version):
    """
    Verify EVPN Type-5 overlay route in FRR RIB and Linux kernel

    This test validates that EVPN Type-5 routes advertised from external
    router (ext-1) are properly received and installed in both:
    1. FRR routing table (show ip route vrf)
    2. Linux kernel routing table (ip route show vrf)

    Verification includes:
    - Route 198.51.100.0/24 exists in vrf1
    - Protocol is BGP
    - Route is selected and installed
    - Multiple ECMP next-hops via EVPN L3VNI (vlan4001)
    - Kernel nexthop groups are correctly configured
    - Each nexthop has 'onlink' flag set

    Test scenario:
    - Router: tor-21
    - VRF: vrf1
    - Route: 198.51.100.0/24 (IPv4 overlay route advertised from ext-1)
    - Expected next-hops:
      * IPv4 underlay: bordertor-11 (10.0.0.1), bordertor-12 (10.0.0.2)
      * IPv6 underlay: bordertor-11 (fd00:0:0::1), bordertor-12 (fd00:0:0::2)
    - Interface: vlan4001 (L3VNI interface)

    Note: This tests RFC 5549 behavior - IPv4 routes with IPv6 next-hops when
    using IPv6 underlay. Verifies both control plane (FRR) and data plane (kernel).
    """
    tgen, ip_version = tgen_and_ip_version
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    logger.info(
        f"Verifying EVPN Type-5 overlay route 198.51.100.0/24 in vrf1 on tor-21 "
        f"({ip_version} underlay)"
    )

    router = tgen.gears["tor-21"]

    # Load expected JSON from version-specific directory
    # IPv4 underlay: IPv4 next-hops (10.0.0.1, 10.0.0.2)
    # IPv6 underlay: IPv6 next-hops (fd00:0:0::1, fd00:0:0::2)
    config_dir = os.path.join(CWD, ip_version)
    expected_file = os.path.join(config_dir, "tor-21", "type5_prefix1.json")
    with open(expected_file, "r") as f:
        expected = json.load(f)

    logger.info(
        f"Loaded expected route data from {expected_file} "
        f"(testing IPv4 route with {ip_version} next-hops)"
    )

    # Verify route in FRR RIB with retry logic
    test_func = partial(
        evpn_verify_vrf_rib_route,
        router,
        vrf="vrf1",
        route="198.51.100.0/24",
        expected_json=expected,
    )
    _, result = topotest.run_and_expect(test_func, None, count=30, wait=1)
    assert (
        result is None
    ), f"EVPN Type-5 overlay route verification (RIB) failed: {result}"

    logger.info(f"FRR RIB verification successful for route 198.51.100.0/24")

    # Verify route in Linux kernel with nexthop groups
    # Extract expected nexthops from JSON (the 'ip' field from each nexthop)
    kernel_expected_nexthops = []
    for nh in expected["198.51.100.0/24"][0]["nexthops"]:
        if "ip" in nh and "duplicate" not in nh:
            # Only add unique nexthops (skip duplicates)
            if nh["ip"] not in kernel_expected_nexthops:
                kernel_expected_nexthops.append(nh["ip"])

    logger.info(
        f"Verifying kernel route 198.51.100.0/24 with nexthops: {kernel_expected_nexthops}"
    )

    test_func = partial(
        evpn_verify_overlay_route_in_kernel,
        router,
        vrf="vrf1",
        route="198.51.100.0/24",
        expected_nexthops=kernel_expected_nexthops,
        expected_dev="vlan4001",
    )
    _, result = topotest.run_and_expect(test_func, None, count=30, wait=1)
    assert (
        result is None
    ), f"EVPN Type-5 overlay route verification (kernel) failed: {result}"

    logger.info(
        f"EVPN Type-5 overlay route verification completed successfully "
        f"(RIB + kernel, {ip_version} underlay)"
    )


def test_host_to_host_ping(tgen_and_ip_version):
    """
    Test ping connectivity between hosts across EVPN fabric

    Demonstrates the use of evpn_verify_ping_connectivity library function to verify
    end-to-end connectivity across VXLAN overlay between hosts in different pods.
    Uses topotest.run_and_expect for automatic retry logic.

    Test scenario:
    - Source: host-211 (connected to tor-21 on VLAN 111, VRF2)
      - IPv4: 192.168.11.211/24
      - IPv6: fd00:60:1:1::211/64
    - Destination: host-111 (connected to bordertor-11 on VLAN 111, VRF2)
      - IPv4: 192.168.11.111/24
      - IPv6: fd00:60:1:1::111/64

    This tests VXLAN overlay connectivity (L2VNI 1000111) between:
    - tor-21 VTEP (different pod)
    - bordertor-11 VTEP (border pod)

    Both hosts are on the same VLAN 111 and VRF2, so traffic should be routed
    via the EVPN fabric through the VXLAN tunnel.
    """
    tgen, ip_version = tgen_and_ip_version
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    logger.info(
        f"Testing host-to-host connectivity across EVPN VXLAN fabric ({ip_version} underlay)"
    )

    # Test IPv4 connectivity only when running with IPv4 underlay
    if ip_version == "ipv4":
        logger.info(
            "Testing IPv4: host-211 (192.168.11.211) -> host-111 (192.168.11.111)"
        )
        test_func = partial(
            evpn_verify_ping_connectivity,
            tgen=tgen,
            source_host="host-211",
            dest_ip="192.168.11.111",
            source_ip="192.168.11.211",
            count=4,
        )
        _, result = topotest.run_and_expect(test_func, None, count=10, wait=1)
        assert result is None, f"IPv4 connectivity test failed: {result}"
    else:
        logger.info("Skipping IPv4 connectivity test (not running with IPv4 underlay)")

    # Test IPv6 connectivity only when running with IPv6 underlay
    if ip_version == "ipv6":
        logger.info(
            "Testing IPv6: host-211 (fd00:60:1:1::211) -> host-111 (fd00:60:1:1::111)"
        )
        test_func = partial(
            evpn_verify_ping_connectivity,
            tgen=tgen,
            source_host="host-211",
            dest_ip="fd00:60:1:1::111",
            source_ip="fd00:60:1:1::211",
            count=4,
        )
        _, result = topotest.run_and_expect(test_func, None, count=15, wait=1)
        assert result is None, f"IPv6 connectivity test failed: {result}"
    else:
        logger.info("Skipping IPv6 connectivity test (not running with IPv6 underlay)")

    logger.info("Host-to-host connectivity test completed successfully")


def test_memory_leak(tgen_and_ip_version):
    """Run the memory leak test and report results."""
    tgen = get_topogen()
    if not tgen.is_memleak_enabled():
        pytest.skip("Memory leak test/report is disabled")

    tgen.report_memory_leaks()


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
