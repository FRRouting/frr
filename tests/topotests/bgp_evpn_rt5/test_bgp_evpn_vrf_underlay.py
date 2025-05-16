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

os.environ["VRF_UNDERLAY"] = "vrf-evpn"

if __name__ == "__main__":
    # test_bgp_evpn is executed with different behavior controlled by the VRF_UNDERLAY environment variable
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
