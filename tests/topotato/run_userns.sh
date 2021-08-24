#!/bin/sh

cd "`dirname $0`"

if [ "$1" = "ns_inner" ]; then
	shift
	for I in `ls -1 etc`; do
		mount --bind "etc/$I" "/etc/$I"
	done
	mount -t tmpfs none /var/tmp
	mount -t tmpfs none /var/run
	exec pytest-3 --html=results.html "$@"
else
	exec unshare -U -m -p -n -r -f --mount-proc tini -g "$0" -- ns_inner "$@"
fi
