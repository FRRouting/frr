#! /bin/bash
#
# Add to git new files created by qpimd patch
#
# Run from quagga's top dir as:
# ./pimd/quagga-git-add.sh
#
# $QuaggaId: $Format:%an, %ai, %h$ $

chmod a+rx pimd/*.sh
git add doc/pimd.8
git add pimd
