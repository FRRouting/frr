#!/bin/bash

for vni in 10 20 30; do
    bridge=br$vni
    vxlanid=$vni
    vxlandev=vxlan$vni

    ip link add name "$bridge" \
        address 00:00:5e:00:01:00 \
        type bridge \
        forward_delay 0 \
        stp_state 0 \
        mcast_snooping 0
    ip link set dev "$bridge" up

    ip link add name "$vxlandev" \
        master "$bridge" \
        type vxlan \
        id "$vxlanid" \
        dstport 4789 \
        nolearning \
        local 192.168.1.1
    ip link set "$vxlandev" addrgenmode none
    ip link set "$vxlandev" type bridge_slave learning off neigh_suppress on
    ip link set dev "$vxlandev" up
done

# VNI 40 in vrf-red, which has L3VNI 1000
ip link add vrf-red type vrf table 10
ip link set dev vrf-red up
for vni in 40 1000; do
    ip link add name "br$vni" type bridge forward_delay 0 stp_state 0 mcast_snooping 0
    ip link set dev "br$vni" master vrf-red
    ip link set dev "br$vni" up
    ip link add name "vxlan$vni" master "br$vni" type vxlan id "$vni" \
        dstport 4789 nolearning local 192.168.1.1
    ip link set "vxlan$vni" addrgenmode none
    ip link set "vxlan$vni" type bridge_slave learning off neigh_suppress on
    ip link set dev "vxlan$vni" up
done
