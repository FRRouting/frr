#!/usr/bin/env python
# SPDX-License-Identifier: ISC

#
# test_bgp_vpnv4_gretap.py
# Part of NetDEF Topology Tests
#
# Copyright (c) 2025 by 6WIND
#

"""
test_bgp_vpnv4_gretap.py: Test the FRR BGP daemon with BGP IPv6 interface
with route advertisements on a separate netns.
"""

import os
import sys

CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

from bgp_vpnv4_gre.test_bgp_vpnv4_gre import *

if __name__ == "__main__":
    # run test_bgp_vpnv4_gre.py test but with different parameters
    # the name of the file controls the name of the global variable TUNNEL_TYPE
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
