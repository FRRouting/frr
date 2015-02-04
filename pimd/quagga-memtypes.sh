#! /bin/bash
#
# Check lib/memtypes.h from Quagga
#
# Run from quagga's top dir as:
# ./pimd/quagga-memtypes.sh
#
# $QuaggaId: $Format:%an, %ai, %h$ $

me=`basename $0`
msg () {
	echo >&2 $me: $*
}

memtypes_h=lib/memtypes.h
if [ -e $memtypes_h ]; then
	memtypes_h_size=`ls -s $memtypes_h | cut -d' ' -f1`
	if [ "$memtypes_h_size" -lt 1 ]; then
		msg WARNING: removing empty file: $memtypes_h -- awk failed?
		rm $memtypes_h	
	fi
fi
