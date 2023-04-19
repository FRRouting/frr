#!/usr/bin/env python

#
# Part of NetDEF Topology Tests
#
# Copyright (c) 2017 by
# Network Device Education Foundation, Inc. ("NetDEF")
#
# Permission to use, copy, modify, and/or distribute this software
# for any purpose with or without fee is hereby granted, provided
# that the above copyright notice and this permission notice appear
# in all copies.
#
# THE SOFTWARE IS PROVIDED "AS IS" AND NETDEF DISCLAIMS ALL WARRANTIES
# WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
# MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL NETDEF BE LIABLE FOR
# ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY
# DAMAGES WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS,
# WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS
# ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE
# OF THIS SOFTWARE.
#

"""
customize.py: Simple FRR SRV6 TE-POLICY test topology

    +-----+-----+         +-----+-----+                                      +-----+-----+                        
    |   peer1   |         |    ce1    |                                      |    ce3    |
    |100.0.1.101|---------| 99.0.0.1  |             ~~~~~~~~~~~~~            | 99.0.0.3  |  CE Routers   
    +-----+-----+         +-----+-----+           ~~     sw1     ~~          +-----+-----+    
                                |                 ~~ 10.0.2.0/24 ~~                |        
                               .2\                  ~~~~~~~~~~~~~                 /         .2
                      192.168.1.1 \r1.eth3    _________/    \_________    r2.eth3/ 192.168.3.1
                            +-----+-----+    /                        \    +-----+-----+
                            |    r1     |___/r1.eth0            r2.eth0\___|    r2     |
                            |  1.1.1.1  |___                            ___|  2.2.2.2  |     PE Routers
                            +-----+-----+   \r1.eth1            r2.eth1/   +-----+-----+
                      192.168.2.1 /r1.eth4   \_________      _________/    r2.eth4\ 192.168.4.1
                               .2/                      \   /                      \         .2
                                |                   ~~~~~~~~~~~~~                   |
    +-----+-----+         +-----+-----+           ~~     sw2     ~~           +-----+-----+
    |   peer2   |---------|    ce2    |           ~~ 10.0.2.0/24 ~~           |    ce4    |
    |100.0.2.102|         | 99.0.0.2  |             ~~~~~~~~~~~~~             | 99.0.0.4  |   CE Routers
    +-----+-----+         +-----+-----+                                       +-----+-----+
"""
import os
import re
import pytest
import platform

# pylint: disable=C0413
# Import topogen and topotest helpers
from lib import topotest
from lib.topogen import Topogen, TopoRouter, get_topogen
from lib.topolog import logger
from lib.ltemplate import ltemplateRtrCmd
from lib.common_config import (
    step,
    verify_rib,
    start_topology,
    write_test_header,
    check_address_types,
    write_test_footer,
    reset_config_on_routers,
    create_route_maps,
    create_static_routes,
    create_prefix_lists,
    create_interface_in_kernel,
    create_bgp_community_lists,
    check_router_status,
    apply_raw_config,
    required_linux_kernel_version,
)
# Required to instantiate the topology builder class.
from mininet.topo import Topo

import shutil

CWD = os.path.dirname(os.path.realpath(__file__))
# test name based on directory
TEST = os.path.basename(CWD)

LOOPBACK_1 = {
    "ipv4": "10.10.10.10/32",
    "ipv6": "1000::1000/128",
    "ipv4_mask": "255.255.255.255",
    "ipv6_mask": None,
}
LOOPBACK_2 = {
    "ipv4": "20.20.20.20/32",
    "ipv6": "2000::2000/128",
    "ipv4_mask": "255.255.255.255",
    "ipv6_mask": None,
}

class ThisTestTopo(Topo):
    "Test topology builder"

    def build(self, *_args, **_opts):
        "Build function"
        tgen = get_topogen(self)

        # This function only purpose is to define allocation and relationship
        # between routers, switches and hosts.
        #
        # Create P/PE routers
        for routern in range(1, 3):
            tgen.add_router("r{}".format(routern))
        # Create CE routers
        for routern in range(1, 5):
            tgen.add_router("ce{}".format(routern))

        # CE/PE links
        tgen.add_link(tgen.gears["ce1"], tgen.gears["r1"], "ce1-eth0", "r1-eth3")
        tgen.add_link(tgen.gears["ce2"], tgen.gears["r1"], "ce2-eth0", "r1-eth4")
        tgen.add_link(tgen.gears["ce3"], tgen.gears["r2"], "ce3-eth0", "r2-eth3")
        tgen.add_link(tgen.gears["ce4"], tgen.gears["r2"], "ce4-eth0", "r2-eth4")

        # Create a switch with just one router connected to it to simulate a
        # empty network.
        switch = {}
        switch[0] = tgen.add_switch("sw0")
        switch[0].add_link(tgen.gears["r1"], nodeif="r1-eth0")
        switch[0].add_link(tgen.gears["r2"], nodeif="r2-eth0")

        switch[1] = tgen.add_switch("sw1")
        switch[1].add_link(tgen.gears["r1"], nodeif="r1-eth1")
        switch[1].add_link(tgen.gears["r2"], nodeif="r2-eth1")

        switch[2] = tgen.add_switch("sw2")
        peer1 = tgen.add_exabgp_peer(
            "peer1", ip="100.0.1.101", defaultRoute="via 100.0.1.1"
        )
        switch[2].add_link(peer1)
        switch[2].add_link(tgen.gears["ce1"], nodeif="ce1-eth1")
        switch[3] = tgen.add_switch("sw3")
        peer2 = tgen.add_exabgp_peer(
            "peer2", ip="100.0.2.102", defaultRoute="via 100.0.2.1"
        )
        switch[3].add_link(peer2)
        switch[3].add_link(tgen.gears["ce2"], nodeif="ce2-eth1")

def ltemplatePreRouterStartHook():
    cc = ltemplateRtrCmd()
    krel = platform.release()
    tgen = get_topogen()
    logger.info("pre router-start hook, kernel=" + krel)

    # check for normal init
    if len(tgen.net) == 1:
        logger.info("Topology not configured, skipping setup")
        return False
    # trace errors/unexpected output
    cc.resetCounts()
    # configure cust1 VRFs 
    rtrs = ["r1", "r2"]
    cmds = [
        "ip link add {0}-cust1 type vrf table 10",
        "ip ru add oif {0}-cust1 table 10",
        "ip ru add iif {0}-cust1 table 10",
        "ip link set dev {0}-cust1 up",
    ]
    for rtr in rtrs:
        for cmd in cmds:
            cc.doCmd(tgen, rtr, cmd.format(rtr))
        cc.doCmd(tgen, rtr, "ip link set dev {0}-eth3 master {0}-cust1".format(rtr))

    cmds = [
        "ip link add {0}-cust2 type vrf table 20",
        "ip ru add oif {0}-cust2 table 20",
        "ip ru add iif {0}-cust2 table 20",
        "ip link set dev {0}-cust2 up",
    ]
    for rtr in rtrs:
        for cmd in cmds:
            cc.doCmd(tgen, rtr, cmd.format(rtr))
        cc.doCmd(tgen, rtr, "ip link set dev {0}-eth4 master {0}-cust2".format(rtr))

    global ADDR_TYPES
    ADDR_TYPES = check_address_types()
    for addr_type in ADDR_TYPES:
        create_interface_in_kernel(
            tgen,
            "r1",
            "loopback1",
            LOOPBACK_1[addr_type],
            "None",
            LOOPBACK_1["{}_mask".format(addr_type)],
        )

        create_interface_in_kernel(
            tgen,
            "r2",
            "loopback1",
            LOOPBACK_2[addr_type],
            "None",
            LOOPBACK_2["{}_mask".format(addr_type)],
        )

    if cc.getOutput() != 0:
        InitSuccess = False
        logger.info(
            "Unexpected output seen ({} times, tests will be skipped".format(
                cc.getOutput()
            )
        )
    else:
        InitSuccess = True
        logger.info("VRF config successful!")
    return InitSuccess


def ltemplatePostRouterStartHook():
    logger.info("post router-start hook")
    tgen = get_topogen()
    logger.info("starting exaBGP on peer1")
    peer_list = tgen.exabgp_peers()
    for pname, peer in peer_list.items():
        peer_dir = os.path.join(CWD, pname)
        env_file = os.path.join(CWD, "exabgp.env")
        logger.info("Running ExaBGP peer")
        peer.start(peer_dir, env_file)
        logger.info(pname)

    return True
