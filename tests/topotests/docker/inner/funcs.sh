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

FRR_HOST_DIR=/root/host-frr
FRR_SYNC_DIR=/root/persist/frr-sync
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
