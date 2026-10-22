#!/bin/bash
# SPDX-License-Identifier: ISC
#
# setup.sh <vtep-ip>: L2-VNI 100 bridged to a local access port.

set -e

vtep=$1

ip addr add "$vtep/32" dev lo

ip link add br100 type bridge stp_state 0
ip link set br100 up
ip link add vxlan100 type vxlan id 100 local "$vtep" dstport 4789 nolearning
ip link set vxlan100 master br100
ip link set vxlan100 up
ip link add acc100 type dummy
ip link set acc100 master br100
ip link set acc100 up
