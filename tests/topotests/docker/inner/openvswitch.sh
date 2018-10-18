#!/bin/bash
#
# Copyright 2018 Network Device Education Foundation, Inc. ("NetDEF")
#
# Permission is hereby granted, free of charge, to any person obtaining
# a copy of this software and associated documentation files (the
# "Software"), to deal in the Software without restriction, including
# without limitation the rights to use, copy, modify, merge, publish,
# distribute, sublicense, and/or sell copies of the Software, and to
# permit persons to whom the Software is furnished to do so, subject to
# the following conditions:
#
# The above copyright notice and this permission notice shall be
# included in all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
# EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
# MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
# NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
# BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
# ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
# CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

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
