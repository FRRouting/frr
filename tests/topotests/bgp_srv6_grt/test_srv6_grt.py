#!/usr/bin/env python
# SPDX-License-Identifier: ISC

import os
import re
import sys
import json
import pytest
import functools

CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

from lib import topotest
from lib.topogen import Topogen, get_topogen, TopoRouter

pytestmark = [pytest.mark.bgpd]
"""
                        +-------+
                        |       |
                        |   R4  |
                        |       |
                        +---+---+
                            |
                            |
                            |
    +------+            +---+---+              +------+
    |      |            |       |              |      |
    |  R2  |------------|   R1  |--------------|  R3  |
    |      |            |       |              |      |
    +------+            +-------+              +------+
"""

def setup_module(mod):
    topodef = {"s1": ("r1", "r2"), "s2": ("r1", "r3"), "s3":("r1", "r4")}
    tgen = Topogen(topodef, mod.__name__)
    tgen.start_topology()

    router_list = tgen.routers()

    for _, (rname, router) in enumerate(router_list.items()):
        router.load_frr_config(
            os.path.join(CWD, "{}/frr.conf".format(rname)),
            [(TopoRouter.RD_ZEBRA, None), (TopoRouter.RD_BGP, "-M bmp")],
        )

    tgen.net["r1"].cmd(
        """
        sysctl -w net.vrf.strict_mode=1
        """
    )
    #tgen.net["r1"].cmd(
    #    """
    #    ip link add vrf1 type vrf table 10
    #    ip link set up dev vrf1
    #    ip link set dev r1-eth0 master vrf1
    #    ip link set dev r1-eth1 master vrf1
    #    ip link set dev r1-eth2 master vrf1
    #    """
    #)
    tgen.start_router()


def teardown_module(mod):
    tgen = get_topogen()
    tgen.stop_topology()


def test_bgp_srv6():
    tgen = get_topogen()


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
