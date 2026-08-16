#!/bin/bash
# VLAN-aware bridge with an L2VNI. VLAN 3745 maps to VNI 5000; VLAN 12 does
# not map to anything. r1-eth0 carries VLAN 3745, r1-eth1 carries VLAN 12, so
# a MAC can be learned on each and attribution can be compared.
#
# NOTE: no `vrf ... vni 5000`. That would make 5000 an L3VNI, and
# zebra_evpn_map_vlan() resolves the L2 EVPN table -- `show evpn mac vni 5000`
# would answer "VNI does not exist" and the test would prove nothing.

ip link add name bridge type bridge stp_state 0 vlan_filtering 1
ip link set bridge type bridge vlan_default_pvid 0
ip link set dev bridge up

ip link add vxlan5000 type vxlan id 5000 dstport 4789 local 10.10.10.10 nolearning
ip link set dev vxlan5000 master bridge
ip link set up dev vxlan5000

# VLAN 3745 <-> VNI 5000
bridge vlan add vid 3745 dev bridge self
bridge vlan del vid 1 dev vxlan5000
bridge vlan add vid 3745 dev vxlan5000 pvid untagged
ip link add link bridge name Vlan3745 type vlan id 3745
ip addr add 10.37.0.1/24 dev Vlan3745
ip link set dev Vlan3745 up

# VLAN 12 -- no VNI mapping
bridge vlan add vid 12 dev bridge self
ip link add link bridge name Vlan12 type vlan id 12
ip addr add 10.12.0.1/24 dev Vlan12
ip link set dev Vlan12 up

# Bridge ports: eth0 on the mapped VLAN, eth1 on the unmapped one.
ip addr flush dev r1-eth0 2>/dev/null
ip link set dev r1-eth0 master bridge
bridge vlan del vid 1 dev r1-eth0
bridge vlan add vid 3745 dev r1-eth0 pvid untagged
ip link set dev r1-eth0 up

ip addr flush dev r1-eth1 2>/dev/null
ip link set dev r1-eth1 master bridge
bridge vlan del vid 1 dev r1-eth1
bridge vlan add vid 12 dev r1-eth1 pvid untagged
ip link set dev r1-eth1 up
