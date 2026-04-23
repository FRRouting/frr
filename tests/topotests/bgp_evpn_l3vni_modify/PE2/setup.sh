#!/bin/bash
# Create Linux VRF, VXLAN, bridge, and VLAN SVI for L3VNI 3109 on PE2

ip link add vrf-blue type vrf table 1000
ip link set vrf-blue up

ip link add name br3109 type bridge stp_state 0 vlan_filtering 1
ip link set dev br3109 up

ip link add vxlan3109 type vxlan id 3109 dstport 4789 local 10.30.30.30 nolearning
ip link set dev vxlan3109 master br3109
ip link set up dev vxlan3109

bridge vlan add vid 60 dev br3109 self
bridge vlan del vid 1 dev vxlan3109
bridge vlan add vid 60 dev vxlan3109 pvid untagged

ip link add link br3109 name vlan60 type vlan id 60
ip link set dev vlan60 master vrf-blue
ip addr add 10.99.99.3/24 dev vlan60
ip link set dev vlan60 up
