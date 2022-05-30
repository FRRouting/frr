#!/bin/sh

cd "`dirname $0`"

if [ \! -d "/etc/frr" ]; then
	echo /etc/frr does not exist or is not a directory.  Please create it. >&2
	exit 1
fi

if [ "$1" = "ns_inner" ]; then
	shift
	for I in `ls -1 etc`; do
		mount --bind "etc/$I" "/etc/$I"
	done
	mount -t tmpfs none /var/tmp
	mount -t tmpfs none /var/run

	ip link set lo up

	exec python3 -mpytest "$@"
else
	exec unshare -U -m -p -n -r -f --mount-proc tini -g "$0" -- ns_inner "$@"
fi
