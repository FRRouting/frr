#!/bin/bash
# SPDX-License-Identifier: MIT
#
# Copyright 2018 Network Device Education Foundation, Inc. ("NetDEF")

# Load shared functions
CDIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
. $CDIR/funcs.sh

set -e

#
# Script begin
#
"${CDIR}/compile_frr.sh"
"${CDIR}/openvswitch.sh"

cd "${FRR_BUILD_DIR}/tests/topotests"

log_info "Setting permissions on /tmp so we can generate logs"
chmod 1777 /tmp

# ExaBGP warns and stalls ~15s per peer when reverse DNS for peer hostnames
# is missing (e.g. bgp_peer_shut starts twenty ExaBGP peers).
if ! grep -qE '[[:space:]]peer1([[:space:]]|$)' /etc/hosts; then
	log_info "Adding ExaBGP peer hostnames to /etc/hosts for faster startup"
	peer_hosts=""
	for i in $(seq 1 20); do
		peer_hosts+=" peer${i}"
	done
	echo "127.0.0.1${peer_hosts}" >> /etc/hosts
fi

# This is a MUST, otherwise we have:
# AddressSanitizer:DEADLYSIGNAL
# Segmentation fault
sysctl -w vm.mmap_rnd_bits=28

if [ $# -eq 0 ] || ([[ "$1" != /* ]] && [[ "$1" != ./* ]]); then
	export TOPOTESTS_CHECK_MEMLEAK=/tmp/memleak_
	export TOPOTESTS_CHECK_STDERR=Yes
	set -- pytest \
		--junitxml /tmp/topotests.xml \
		"$@"
fi

exec "$@"
