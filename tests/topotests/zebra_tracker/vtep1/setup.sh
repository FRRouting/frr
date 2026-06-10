#!/bin/bash
# Linux plumbing for vtep1's two L3VNIs -- same shape as dut/setup.sh, with
# this VTEP's own tunnel source (its loopback, 10.121.0.1) and its own SVI
# addresses.  The VNIs and the SVI VLAN ids must match dut's for symmetric
# L3VNI routing to come up.

# ---- L3VNI 4001 -> vrf1 ----------------------------------------------------
ip link add vrf1 type vrf table 1001
ip link set vrf1 up

ip link add name br4001 type bridge stp_state 0 vlan_filtering 1
ip link set dev br4001 up

ip link add vxlan4001 type vxlan id 4001 dstport 4789 local 10.121.0.1 nolearning
ip link set dev vxlan4001 master br4001
ip link set up dev vxlan4001

bridge vlan add vid 101 dev br4001 self
bridge vlan del vid 1 dev vxlan4001
bridge vlan add vid 101 dev vxlan4001 pvid untagged

ip link add link br4001 name vlan101 type vlan id 101
ip link set dev vlan101 master vrf1
ip addr add 10.201.0.11/24 dev vlan101
ip link set dev vlan101 up

# ---- L3VNI 4002 -> vrf2 ----------------------------------------------------
ip link add vrf2 type vrf table 1002
ip link set vrf2 up

ip link add name br4002 type bridge stp_state 0 vlan_filtering 1
ip link set dev br4002 up

ip link add vxlan4002 type vxlan id 4002 dstport 4789 local 10.121.0.1 nolearning
ip link set dev vxlan4002 master br4002
ip link set up dev vxlan4002

bridge vlan add vid 102 dev br4002 self
bridge vlan del vid 1 dev vxlan4002
bridge vlan add vid 102 dev vxlan4002 pvid untagged

ip link add link br4002 name vlan102 type vlan id 102
ip link set dev vlan102 master vrf2
ip addr add 10.202.0.11/24 dev vlan102
ip link set dev vlan102 up
