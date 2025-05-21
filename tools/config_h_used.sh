#!/bin/sh
# 2025 by David Lamparter, public domain
#
# get an overview of where definitions from config.h are actually used
#
# good ways to call this -- note '*.h' will be applied by git grep
#   tools/config_h_used.sh
#   tools/config_h_used.sh -A 3 '*.h'

args="-c"	# default: count number of occurences in file
l=false
[ "$1" = "-A" ] && { shift; args="-A $1"; shift; }	# -A 9  lines after
[ "$1" = "-C" ] && { shift; args="-C $1"; shift; }	# -C 9  lines context
[ "$1" = "-l" ] && { shift; args="-l"; l=true; }	# -l    list filenames

# put macro names on stderr when doing -l
$l && exec 4>&2
$l || exec 4>&1

perl -ne '/#(?:define|undef)\s+(.*?)\s+/ && printf "%s\n", $1;' < config.h | while read sym; do
	printf '\e[93m%s\e[m\n' "$sym" >&4
	git --no-pager grep $args -P "\\b$sym\\b" "$@"
done
