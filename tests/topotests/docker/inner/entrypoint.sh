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

# If compile_frr.sh exited early (e.g., TOPOTEST_SKIP_BUILD=1 with packages),
# FRR_BUILD_DIR might not exist or be empty. Use the host FRR source instead.
# Check if the directory exists AND has actual test files (not just conftest.py)
TOPTEST_DIR=""
# Check if build dir has test files (check for test_*.py files in subdirectories)
BUILD_HAS_TESTS=false
if [ -d "${FRR_BUILD_DIR}/tests/topotests" ] && [ -f "${FRR_BUILD_DIR}/tests/topotests/conftest.py" ]; then
	# Check if there are any test_*.py files in subdirectories
	if find "${FRR_BUILD_DIR}/tests/topotests" -mindepth 2 -name "test_*.py" -type f | head -1 | grep -q .; then
		BUILD_HAS_TESTS=true
	fi
fi

if [ "$BUILD_HAS_TESTS" = "true" ]; then
	TOPTEST_DIR="${FRR_BUILD_DIR}/tests/topotests"
	log_info "Using topotests from build directory: ${TOPTEST_DIR}"
elif [ -d "${FRR_HOST_DIR}/tests/topotests" ] && [ -f "${FRR_HOST_DIR}/tests/topotests/conftest.py" ]; then
	TOPTEST_DIR="${FRR_HOST_DIR}/tests/topotests"
	log_info "Using topotests from host directory: ${TOPTEST_DIR}"
else
	log_error "FRR_BUILD_DIR: ${FRR_BUILD_DIR}/tests/topotests (exists: $([ -d "${FRR_BUILD_DIR}/tests/topotests" ] && echo yes || echo no), has test files: $BUILD_HAS_TESTS)"
	log_error "FRR_HOST_DIR: ${FRR_HOST_DIR}/tests/topotests (exists: $([ -d "${FRR_HOST_DIR}/tests/topotests" ] && echo yes || echo no), has conftest: $([ -f "${FRR_HOST_DIR}/tests/topotests/conftest.py" ] && echo yes || echo no))"
	log_fatal "Could not find topotests directory with test files in ${FRR_BUILD_DIR} or ${FRR_HOST_DIR}"
fi

cd "${TOPTEST_DIR}" || log_fatal "Failed to change to directory: ${TOPTEST_DIR}"
log_info "Current directory: $(pwd)"

log_info "Setting permissions on /tmp so we can generate logs"
chmod 1777 /tmp

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
