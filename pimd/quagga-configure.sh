#! /bin/bash
#
# Configure for minimum Quagga build needed for pimd.
#
# Run from quagga's top dir as:
# . pimd/quagga-configure.sh
#
# $QuaggaId: $Format:%an, %ai, %h$ $

tail -1 ./pimd/quagga-configure-no-vtysh.sh --enable-vtysh
