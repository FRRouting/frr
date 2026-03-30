#!/bin/sh
# SPDX-License-Identifier: MIT
## C header self-sufficiency check tool
##
## usage:  tools/headercheck.sh [-v] HEADERFILES...
##
## This retrieves the compile command from FRR's Makefile (i.e. you need to
## have run ./configure before) and uses it to check that the given headers
## don't produce compiler errors when used by themselves.
##
## Options:
##		-v, --verbose		turn on more (and colorful) output
##
## The exit code from this tool will indicate success only if all passed.

v_printf() { true; }

# -h if not parameters given (TBD: check some default set of headers)
case "${1:--h}" in
-h|--help)
	# just print the block above
	egrep '^##' "$0" | cut -c 4-
	exit 0
	;;
-v|--verbose)
	shift
	v_printf() { printf "$@"; }
	;;
esac

COMPILE="$(make var-COMPILE)"
COMPILE="${COMPILE#ccache }"
v_printf "compile command: %s\n" "$COMPILE"

unset fail

for target in "$@"; do
	v_printf "\033[107;30m checking: %s \033[K\033[m\n" "$target"

	# note config.h needs to be included, otherwise edge cases might get
	# strange errors (config.h is required to be included first in any
	# .c file, generally transitive via zebra.h)
	$COMPILE -include config.h -c -o /dev/null -xc "$target" || fail="$fail $target"
done

test "$fail" || exit 0
v_printf "\033[91mfailed:%s\033[m" "$fail"
exit 1
