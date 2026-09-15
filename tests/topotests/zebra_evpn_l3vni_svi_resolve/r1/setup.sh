#!/bin/bash
# VLAN-aware bridge. VLAN 3745 maps to VNI 5000; VLAN 12 maps to NOTHING.
# Both SVIs live in the same VRF, which is what lets a bug in SVI resolution
# bind the L3VNI to the wrong one.

ip link add vrf-red type vrf table 1000
ip link set vrf-red up

ip link add name bridge type bridge stp_state 0 vlan_filtering 1
ip link set bridge type bridge vlan_default_pvid 0
ip link set dev bridge up

ip link add vxlan5000 type vxlan id 5000 dstport 4789 local 10.10.10.10 nolearning
ip link set dev vxlan5000 master bridge
ip link set up dev vxlan5000

# VLAN 12 -- present on the bridge, in the same VRF, but has NO VNI mapping.
#
# Order matters: resolution is "last SVI up wins", so Vlan12 is brought up
# FIRST and Vlan3745 second. That gives a correct baseline, which is what
# lets the flap test below isolate the regression instead of tripping over
# an already-wrong initial state.
bridge vlan add vid 12 dev bridge self
ip link add link bridge name Vlan12 type vlan id 12
ip link set dev Vlan12 master vrf-red
ip addr add 1.12.1.100/16 dev Vlan12
ip link set dev Vlan12 up

# VLAN 3745 <-> VNI 5000  (the correct L3VNI SVI)
bridge vlan add vid 3745 dev bridge self
bridge vlan del vid 1 dev vxlan5000
bridge vlan add vid 3745 dev vxlan5000 pvid untagged
ip link add link bridge name Vlan3745 type vlan id 3745
ip link set dev Vlan3745 master vrf-red
ip link set dev Vlan3745 up
