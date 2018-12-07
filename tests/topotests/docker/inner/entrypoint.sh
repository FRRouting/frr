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
