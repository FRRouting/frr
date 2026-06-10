#!/bin/bash
# Linux plumbing for dut's two L3VNIs.
#
# Same shape as bgp_evpn_l3vni_modify/PE1/setup.sh (VLAN-aware bridge +
# VXLAN device + VLAN SVI enslaved to a VRF), repeated once per tenant VRF:
#
#   vrf1  <- vlan101 (SVI) <- br4001 (vlan_filtering) <- vxlan4001 (VNI 4001)
#   vrf2  <- vlan102 (SVI) <- br4002 (vlan_filtering) <- vxlan4002 (VNI 4002)
#
# The SVI is what makes the overlay next-hop its own kernel object: bgpd
# hands an imported Type-5 route to zebra as NEXTHOP_TYPE_IPV4_IFINDEX with
# ZAPI_NEXTHOP_FLAG_ONLINK and ifindex = this SVI (bgpd/bgp_zebra.c,
# update_ipv4nh_for_route_install), and nexthop_active() returns early for
# an ONLINK nexthop (zebra/zebra_nhg.c).  So the overlay group never
# resolves recursively onto the underlay ECMP group and never collapses
# into it -- which is why an underlay member change cannot alter its
# kernel-visible contents, and why re-sending it is pure redundancy.
#
# `local` must be dut's VXLAN/loopback address, because that is the tunnel
# source the remote VTEPs' Type-5 next-hops are matched against.

# ---- L3VNI 4001 -> vrf1 ----------------------------------------------------
ip link add vrf1 type vrf table 1001
ip link set vrf1 up

ip link add name br4001 type bridge stp_state 0 vlan_filtering 1
ip link set dev br4001 up

ip link add vxlan4001 type vxlan id 4001 dstport 4789 local 10.10.10.1 nolearning
ip link set dev vxlan4001 master br4001
ip link set up dev vxlan4001

bridge vlan add vid 101 dev br4001 self
bridge vlan del vid 1 dev vxlan4001
bridge vlan add vid 101 dev vxlan4001 pvid untagged

ip link add link br4001 name vlan101 type vlan id 101
ip link set dev vlan101 master vrf1
ip addr add 10.201.0.1/24 dev vlan101
ip link set dev vlan101 up

# ---- L3VNI 4002 -> vrf2 ----------------------------------------------------
ip link add vrf2 type vrf table 1002
ip link set vrf2 up

ip link add name br4002 type bridge stp_state 0 vlan_filtering 1
ip link set dev br4002 up

ip link add vxlan4002 type vxlan id 4002 dstport 4789 local 10.10.10.1 nolearning
ip link set dev vxlan4002 master br4002
ip link set up dev vxlan4002

bridge vlan add vid 102 dev br4002 self
bridge vlan del vid 1 dev vxlan4002
bridge vlan add vid 102 dev vxlan4002 pvid untagged

ip link add link br4002 name vlan102 type vlan id 102
ip link set dev vlan102 master vrf2
ip addr add 10.202.0.1/24 dev vlan102
ip link set dev vlan102 up
