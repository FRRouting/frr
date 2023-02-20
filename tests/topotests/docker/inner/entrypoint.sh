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

if [ $# -eq 0 ] || ([[ "$1" != /* ]] && [[ "$1" != ./* ]]); then
	export TOPOTESTS_CHECK_MEMLEAK=/tmp/memleak_
	export TOPOTESTS_CHECK_STDERR=Yes
	set -- pytest \
		--junitxml /tmp/topotests.xml \
		"$@"
fi

exec "$@"
