#!/bin/bash
# This script converts nonstandard fixed-width integer types found in FRR to
# C99 standard types.
USAGE="./$(basename "$0")"
USAGE+=$' <src-path> -- convert nonstandard fixed-width integer types found in FRR to C99 standard types\n'
USAGE+=$'<src-path> - a directory containing C source, or a C source file\n'
if [ $# -eq 0 ]; then
    printf "%s" "$USAGE"
    exit 1
fi

FRRTREE=$1

if [[ -d $FRRTREE ]]; then
	SOURCES=$(find $FRRTREE -type f -name '*.[ch]')
elif [[ -f $FRRTREE ]]; then
	SOURCES="$FRRTREE"
	SOURCES+=$'\n'
else
	printf "%s" "$USAGE"
	exit 1
fi

printf "%s" "$SOURCES" | while read line ; do
    printf "Processing $line "
    sed -i -e 's/u_int\([0-9]\{1,3\}\)_t/uint\1_t/g' $line
    printf "."
    sed -i -e 's/\([^a-z_]\)u_char\([^a-z_]\|$\)/\1uint8_t\2/g' $line
    printf "."
    sed -i -e 's/\([^a-z_]\)u_short\([^a-z_]\|$\)/\1unsigned short\2/g' $line
    printf "."
    sed -i -e 's/\([^a-z_]\)u_int\([^a-z_]\|$\)/\1unsigned int\2/g' $line
    printf "."
    sed -i -e 's/\([^a-z_]\)u_long\([^a-z_]\|$\)/\1unsigned long\2/g' $line
    printf "."
    sed -i -e 's/^u_char /uint8_t /g' $line
    printf "."
    sed -i -e 's/^u_short /unsigned short /g' $line
    printf "."
    sed -i -e 's/^u_int /unsigned int /g' $line
    printf "."
    sed -i -e 's/^u_long /unsigned long /g' $line
    printf ".\n"
done
