#!/usr/bin/env python
# SPDX-License-Identifier: ISC

#
# Copyright (c) 2023 by Carmine Scarpitta <cscarpit@cisco.com>
#

"""
test_srv6_sid_manager.py:

                         +---------+
                         |         |
                         |   RT1   |
                         | 1.1.1.1 |
                         |         |
                         +---------+
                              |eth-sw1
                              |
                              |
                              |
         +---------+          |          +---------+
         |         |          |          |         |
         |   RT2   |eth-sw1   |   eth-sw1|   RT3   |
         | 2.2.2.2 +----------+----------+ 3.3.3.3 |
         |         |     10.0.1.0/24     |         |
         +---------+                     +---------+
    eth-rt4-1|  |eth-rt4-2          eth-rt5-1|  |eth-rt5-2
             |  |                            |  |
  10.0.2.0/24|  |10.0.3.0/24      10.0.4.0/24|  |10.0.5.0/24
             |  |                            |  |
    eth-rt2-1|  |eth-rt2-2          eth-rt3-1|  |eth-rt3-2
         +---------+                     +---------+
         |         |                     |         |
         |   RT4   |     10.0.6.0/24     |   RT5   |
         | 4.4.4.4 +---------------------+ 5.5.5.5 |
         |         |eth-rt5       eth-rt4|         |
         +---------+                     +---------+
       eth-rt6|                                |eth-rt6
              |                                |
   10.0.7.0/24|                                |10.0.8.0/24
              |          +---------+           |
              |          |         |           |
              |          |   RT6   |           |
              +----------+ 6.6.6.6 +-----------+
                  eth-rt4|         |eth-rt5
                         +---------+
                              |eth-dst (.1)
                              |
                              |10.0.10.0/24
                              |
                              |eth-rt6 (.2)
                         +---------+
                         |         |
                         |   DST   |
                         | 9.9.9.2 |
                         |         |
                         +---------+

"""

import os
import re
import sys
import json
import functools
import pytest

CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

# pylint: disable=C0413
# Import topogen and topotest helpers
from lib import topotest
from lib.topogen import Topogen, TopoRouter, get_topogen
from lib.topolog import logger
from lib.common_config import (
    required_linux_kernel_version,
    create_interface_in_kernel,
)
from lib.checkping import check_ping

pytestmark = [pytest.mark.isisd, pytest.mark.sharpd]


def build_topo(tgen):
    """Build function"""

    # Define FRR Routers
    tgen.add_router("rt1")
    tgen.add_router("rt2")
    tgen.add_router("rt3")
    tgen.add_router("rt4")
    tgen.add_router("rt5")
    tgen.add_router("rt6")
    tgen.add_router("dst")
    tgen.add_router("ce1")
    tgen.add_router("ce2")
    tgen.add_router("ce3")
    tgen.add_router("ce4")
    tgen.add_router("ce5")
    tgen.add_router("ce6")

    # Define connections
    switch = tgen.add_switch("s1")
    switch.add_link(tgen.gears["rt1"], nodeif="eth-sw1")
    switch.add_link(tgen.gears["rt2"], nodeif="eth-sw1")
    switch.add_link(tgen.gears["rt3"], nodeif="eth-sw1")

    switch = tgen.add_switch("s2")
    switch.add_link(tgen.gears["rt2"], nodeif="eth-rt4-1")
    switch.add_link(tgen.gears["rt4"], nodeif="eth-rt2-1")

    switch = tgen.add_switch("s3")
    switch.add_link(tgen.gears["rt2"], nodeif="eth-rt4-2")
    switch.add_link(tgen.gears["rt4"], nodeif="eth-rt2-2")

    switch = tgen.add_switch("s4")
    switch.add_link(tgen.gears["rt3"], nodeif="eth-rt5-1")
    switch.add_link(tgen.gears["rt5"], nodeif="eth-rt3-1")

    switch = tgen.add_switch("s5")
    switch.add_link(tgen.gears["rt3"], nodeif="eth-rt5-2")
    switch.add_link(tgen.gears["rt5"], nodeif="eth-rt3-2")

    switch = tgen.add_switch("s6")
    switch.add_link(tgen.gears["rt4"], nodeif="eth-rt5")
    switch.add_link(tgen.gears["rt5"], nodeif="eth-rt4")

    switch = tgen.add_switch("s7")
    switch.add_link(tgen.gears["rt4"], nodeif="eth-rt6")
    switch.add_link(tgen.gears["rt6"], nodeif="eth-rt4")

    switch = tgen.add_switch("s8")
    switch.add_link(tgen.gears["rt5"], nodeif="eth-rt6")
    switch.add_link(tgen.gears["rt6"], nodeif="eth-rt5")

    switch = tgen.add_switch("s9")
    switch.add_link(tgen.gears["rt6"], nodeif="eth-dst")
    switch.add_link(tgen.gears["dst"], nodeif="eth-rt6")

    tgen.add_link(tgen.gears["ce1"], tgen.gears["rt1"], "eth-rt1", "eth-ce1")
    tgen.add_link(tgen.gears["ce2"], tgen.gears["rt6"], "eth-rt6", "eth-ce2")
    tgen.add_link(tgen.gears["ce3"], tgen.gears["rt1"], "eth-rt1", "eth-ce3")
    tgen.add_link(tgen.gears["ce4"], tgen.gears["rt6"], "eth-rt6", "eth-ce4")
    tgen.add_link(tgen.gears["ce5"], tgen.gears["rt1"], "eth-rt1", "eth-ce5")
    tgen.add_link(tgen.gears["ce6"], tgen.gears["rt6"], "eth-rt6", "eth-ce6")

    tgen.gears["rt1"].run("ip link add vrf10 type vrf table 10")
    tgen.gears["rt1"].run("ip link set vrf10 up")
    tgen.gears["rt1"].run("ip link add vrf20 type vrf table 20")
    tgen.gears["rt1"].run("ip link set vrf20 up")
    tgen.gears["rt1"].run("ip link set eth-ce1 master vrf10")
    tgen.gears["rt1"].run("ip link set eth-ce3 master vrf10")
    tgen.gears["rt1"].run("ip link set eth-ce5 master vrf20")

    tgen.gears["rt6"].run("ip link add vrf10 type vrf table 10")
    tgen.gears["rt6"].run("ip link set vrf10 up")
    tgen.gears["rt6"].run("ip link add vrf20 type vrf table 20")
    tgen.gears["rt6"].run("ip link set vrf20 up")
    tgen.gears["rt6"].run("ip link set eth-ce2 master vrf10")
    tgen.gears["rt6"].run("ip link set eth-ce4 master vrf20")
    tgen.gears["rt6"].run("ip link set eth-ce6 master vrf20")

    # Add dummy interface for SRv6
    create_interface_in_kernel(
        tgen,
        "rt1",
        "sr0",
        "2001:db8::1",
        netmask="128",
        create=True,
    )
    create_interface_in_kernel(
        tgen,
        "rt2",
        "sr0",
        "2001:db8::2",
        netmask="128",
        create=True,
    )
    create_interface_in_kernel(
        tgen,
        "rt3",
        "sr0",
        "2001:db8::3",
        netmask="128",
        create=True,
    )
    create_interface_in_kernel(
        tgen,
        "rt4",
        "sr0",
        "2001:db8::4",
        netmask="128",
        create=True,
    )
    create_interface_in_kernel(
        tgen,
        "rt5",
        "sr0",
        "2001:db8::5",
        netmask="128",
        create=True,
    )
    create_interface_in_kernel(
        tgen,
        "rt6",
        "sr0",
        "2001:db8::6",
        netmask="128",
        create=True,
    )


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
