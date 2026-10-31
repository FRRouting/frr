#!/bin/bash
# SPDX-License-Identifier: ISC

set -e

ip addr add 10.0.0.1/32 dev lo

ip link add vrf-red type vrf table 1000
ip link set vrf-red up

for vni in 100 200; do
	ip link add br$vni type bridge
	ip link set br$vni up
	ip link add vxlan$vni type vxlan id $vni local 10.0.0.1 dstport 4789 nolearning
	ip link set vxlan$vni master br$vni
	ip link set vxlan$vni up
done

ip link set br100 master vrf-red
