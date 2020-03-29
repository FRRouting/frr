#!/bin/sh

pfiles=`git grep -lP 'PRI[udx]64'`

case "$1" in
prepare)
	sed -E -i \
		-e 's%"(\s*PRI[udx]64\s*)"%lldXxX\1YyY%g' \
		-e 's%"(\s*PRI[udx]64)%lldXxX\1ZzZ"%g' \
		$pfiles
	;;
runargs)
	shift
	spatch -I . -I lib --macro-file tools/cocci.h "$@" --use-gitgrep
	#-j16 --sp-file tools/coccinelle/printfrr.cocci --in-place --steps 64 --dir .
	;;
revert)
	sed -E -i \
		-e 's%lldXxX(\s*PRI[udx]64\s*)YyY%"\1"%g' \
		-e 's%lldXxX(\s*PRI[udx]64\s*)ZzZ"%"\1%g' \
		$pfiles
	;;
esac
