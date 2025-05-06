#!/usr/bin/env python
# SPDX-License-Identifier: ISC

#
# test_bgp_evpn_vrf_underlay.py
# Part of NetDEF Topology Tests
#
# Copyright (c) 2025 by 6WIND
#

"""
bgp_evpn_vrf_underlay.py: run test_bgp_evpn tests by using r2 evpn backbone in a L3VRF.
"""
import os
import sys

CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

from bgp_evpn_rt5.test_bgp_evpn import *

if __name__ == "__main__":
    # run test_bgp_evpn_rt5.py test but with different parameters
    # the name of the file controls the name of the global variable R2_VRF_UNDERLAY
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
