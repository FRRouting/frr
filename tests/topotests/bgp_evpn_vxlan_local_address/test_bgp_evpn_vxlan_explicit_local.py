#!/usr/bin/env python
# SPDX-License-Identifier: ISC

"""
Same as test_bgp_evpn_vxlan_implicit_local.py but
the VXLAN interface has explicit local
address, meaning the command to create the interface
"ip link add <ifname> type vxlan id <vni> dstport 4789 dev <output-iface> "local <ip>""
has "local <ip>"to force the source address of the VXLAN traffic.

The test verifies that explicit and implicit local configurations behave consistently.
"""

import os
import sys

CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

from bgp_evpn_vxlan_local_address.test_bgp_evpn_vxlan_implicit_local import *

if __name__ == "__main__":
    # run test_bgp_evpn_vxlan.py test but with different parameters
    # the name of the file controls the presence of local param in "ip add <ifname> type vxlan..."
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
