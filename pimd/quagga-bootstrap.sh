#! /bin/bash
#
# Bootstrap Quagga autotools for pimd.
#
# Run from quagga's top dir as:
# ./pimd/quagga-bootstrap.sh
#
# $QuaggaId: $Format:%an, %ai, %h$ $

me=`basename $0`
msg () {
	echo >&2 $me: $*
}

if [ -f ./bootstrap.sh ]; then
	msg found ./bootstrap.sh from quagga
	./bootstrap.sh
else
	msg missing ./bootstrap.sh from quagga
	#autoreconf -i --force
	#bootstrap from tarball prefers autoreconf -i
	autoreconf -i
fi
