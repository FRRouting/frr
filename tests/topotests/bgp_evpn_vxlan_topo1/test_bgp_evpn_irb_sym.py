#!/usr/bin/env python
# SPDX-License-Identifier: ISC

#
# test_bgp_evpn_irb_sym.py
# Part of NetDEF Topology Tests
#
# Copyright 2025 6WIND S.A.
#

"""
Test the RFC 9135 Integrated Routing and Bridging in Ethernet VPN (EVPN) feature
Symmetric mode.
"""

import os
import sys

CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

from bgp_evpn_vxlan_topo1.test_bgp_evpn_vxlan import *

if __name__ == "__main__":
    # run test_bgp_evpn_vxlan.py test but with different parameters
    # the name of the file controls the name of the global variable VRF_OVERLAY and L3VNI
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
