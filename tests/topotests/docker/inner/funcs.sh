#!/bin/bash
# SPDX-License-Identifier: MIT
#
# Copyright 2018 Network Device Education Foundation, Inc. ("NetDEF")

FRR_HOST_DIR=/root/host-frr
FRR_BUILD_DIR=/root/persist/frr-build

if [ ! -L "/root/frr" ]; then
	ln -s $FRR_BUILD_DIR /root/frr
fi

[ -z $TOPOTEST_CLEAN ] && TOPOTEST_CLEAN=0
[ -z $TOPOTEST_VERBOSE ] && TOPOTEST_VERBOSE=1
[ -z $TOPOTEST_DOC ] && TOPOTEST_DOC=0
[ -z $TOPOTEST_SANITIZER ] && TOPOTEST_SANITIZER=1

log_info() {
	local msg=$1

	echo -e "=> $msg"
}

log_error() {
	local msg=$1

	echo -e "E: $msg" 2>&1
}

log_warning() {
	local msg=$1

	echo -e "W: $msg" 2>&1
}

log_fatal() {
	local msg=$1

	echo -e "F: $msg" 2>&1

	exit 1
}

cpu_count() {
	local cpu_count

	cpu_count=$(cat /proc/cpuinfo	| grep -w processor | wc -l)
	if [ $? -eq 0 ]; then
		echo -n $cpu_count
	else
		echo -n 2
	fi
}
