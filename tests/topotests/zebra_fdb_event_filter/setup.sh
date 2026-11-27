#!/bin/bash
# SPDX-License-Identifier: ISC
#
# br100: L2-VNI 100 (vxlan100) with access port acc100.
# br200: plain bridge without VXLAN, access port acc200.

set -e

ip link add br100 type bridge stp_state 0
ip link set br100 up
ip link add vxlan100 type vxlan id 100 local 10.0.0.1 dstport 4789 nolearning
ip link set vxlan100 master br100
ip link set vxlan100 up
ip link add acc100 type dummy
ip link set acc100 master br100
ip link set acc100 up

ip link add br200 type bridge stp_state 0
ip addr add 192.0.2.1/24 dev br200
ip link set br200 up
ip link add acc200 type dummy
ip link set acc200 master br200
ip link set acc200 up
