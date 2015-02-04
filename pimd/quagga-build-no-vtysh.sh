#! /bin/bash
#
# Build minimum Quagga needed for pimd.
#
# Run from quagga's top dir as:
# ./pimd/quagga-build-no-vtysh.sh
#
# $QuaggaId: $Format:%an, %ai, %h$ $

./pimd/quagga-memtypes.sh && ./pimd/quagga-bootstrap.sh && ./pimd/quagga-configure-no-vtysh.sh && make
