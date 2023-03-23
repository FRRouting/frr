#!/bin/bash
# SPDX-License-Identifier: MIT
#
# Copyright 2018 Network Device Education Foundation, Inc. ("NetDEF")

# Load shared functions
CDIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
. $CDIR/funcs.sh

#
# Script begin
#

log_info "Configuring OpenvSwitch...."

# Configure OpenvSwitch so we are able to run mininet
mkdir -p /var/run/openvswitch
ovsdb-tool create /etc/openvswitch/conf.db \
	/usr/share/openvswitch/vswitch.ovsschema
ovsdb-server /etc/openvswitch/conf.db \
	--remote=punix:/var/run/openvswitch/db.sock \
	--remote=ptcp:6640 --pidfile=ovsdb-server.pid >/dev/null 2>/dev/null & \
	disown
ovs-vswitchd >/dev/null 2>/dev/null & disown

sleep 2

ovs-vsctl --no-wait -- init
ovs_version=$(ovs-vsctl -V | grep ovs-vsctl | awk '{print $4}')
ovs_db_version=$(\
	ovsdb-tool schema-version /usr/share/openvswitch/vswitch.ovsschema)
ovs-vsctl --no-wait -- set Open_vSwitch . db-version="${ovs_db_version}"
ovs-vsctl --no-wait -- set Open_vSwitch . ovs-version="${ovs_version}"
ovs-vsctl --no-wait -- set Open_vSwitch . system-type="docker-ovs"
ovs-vsctl --no-wait -- set Open_vSwitch . system-version="0.1"
ovs-vsctl --no-wait -- \
	set Open_vSwitch . external-ids:system-id=`cat /proc/sys/kernel/random/uuid`
ovs-vsctl --no-wait -- set-manager ptcp:6640
ovs-appctl -t ovsdb-server \
	ovsdb-server/add-remote db:Open_vSwitch,Open_vSwitch,manager_options
