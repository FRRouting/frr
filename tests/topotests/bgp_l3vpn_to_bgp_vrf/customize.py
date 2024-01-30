#!/usr/bin/env python
# SPDX-License-Identifier: ISC

#
# Part of NetDEF Topology Tests
#
# Copyright (c) 2017 by
# Network Device Education Foundation, Inc. ("NetDEF")
#

r"""
customize.py: Simple FRR MPLS L3VPN test topology

                  |
             +----+----+
             |   ce1   |
             | 99.0.0.1|                              CE Router
             +----+----+
       192.168.1. | .2  ce1-eth0
                  | .1  r1-eth4
             +---------+
             |    r1   |
             | 1.1.1.1 |                              PE Router
             +----+----+
                  | .1  r1-eth0
                  |
            ~~~~~~~~~~~~~
          ~~     sw0     ~~
          ~~ 10.0.1.0/24 ~~
            ~~~~~~~~~~~~~
                  |10.0.1.0/24
                  |
                  | .2  r2-eth0
             +----+----+
             |    r2   |
             | 2.2.2.2 |                              P router
             +--+---+--+
    r2-eth2  .2 |   | .2  r2-eth1
         ______/     \______
        /                   \
  ~~~~~~~~~~~~~        ~~~~~~~~~~~~~
~~     sw2     ~~    ~~     sw1     ~~
~~ 10.0.3.0/24 ~~    ~~ 10.0.2.0/24 ~~
  ~~~~~~~~~~~~~        ~~~~~~~~~~~~~
        |                 /    |
         \      _________/     |
          \    /                \
r3-eth1 .3 |  | .3  r3-eth0      | .4 r4-eth0
      +----+--+---+         +----+----+
      |     r3    |         |    r4   | r4-eth5
      |  3.3.3.3  |         | 4.4.4.4 |-------+       PE Routers
      +-----------+         +---------+       |
192.168.1.1 |r3.eth4 192.168.1.1 | r4-eth4    |192.168.2.1
         .2 |       ceX-eth0  .2 |            |         .2
      +-----+-----+         +----+-----+ +----+-----+
      |    ce2    |         |   ce3    | |   ce4    |
      | 99.0.0.2  |         | 99.0.0.3 | | 99.0.0.4 | CE Routers
      +-----+-----+         +----+-----+ +----+-----+
            |                    |            |

"""

import os
import platform

# pylint: disable=C0413
# Import topogen and topotest helpers
from lib import topotest
from lib.topogen import get_topogen
from lib.topolog import logger
from lib.ltemplate import ltemplateRtrCmd

# Required to instantiate the topology builder class.


CWD = os.path.dirname(os.path.realpath(__file__))
# test name based on directory
TEST = os.path.basename(CWD)


def build_topo(tgen):
    "Build function"

    # This function only purpose is to define allocation and relationship
    # between routers, switches and hosts.
    #
    # Create P/PE routers
    # check for mpls
    tgen.add_router("r1")
    if tgen.hasmpls != True:
        logger.info("MPLS not available, tests will be skipped")
        return
    mach = platform.machine()
    krel = platform.release()
    if mach[:1] == "a" and topotest.version_cmp(krel, "4.11") < 0:
        logger.info("Need Kernel version 4.11 to run on arm processor")
        return
    for routern in range(2, 5):
        tgen.add_router("r{}".format(routern))
    # Create CE routers
    for routern in range(1, 5):
        tgen.add_router("ce{}".format(routern))

    # CE/PE links
    tgen.add_link(tgen.gears["ce1"], tgen.gears["r1"], "ce1-eth0", "r1-eth4")
    tgen.add_link(tgen.gears["ce2"], tgen.gears["r3"], "ce2-eth0", "r3-eth4")
    tgen.add_link(tgen.gears["ce3"], tgen.gears["r4"], "ce3-eth0", "r4-eth4")
    tgen.add_link(tgen.gears["ce4"], tgen.gears["r4"], "ce4-eth0", "r4-eth5")

    # Create a switch with just one router connected to it to simulate a
    # empty network.
    switch = {}
    switch[0] = tgen.add_switch("sw0")
    switch[0].add_link(tgen.gears["r1"], nodeif="r1-eth0")
    switch[0].add_link(tgen.gears["r2"], nodeif="r2-eth0")

    switch[1] = tgen.add_switch("sw1")
    switch[1].add_link(tgen.gears["r2"], nodeif="r2-eth1")
    switch[1].add_link(tgen.gears["r3"], nodeif="r3-eth0")
    switch[1].add_link(tgen.gears["r4"], nodeif="r4-eth0")

    switch[1] = tgen.add_switch("sw2")
    switch[1].add_link(tgen.gears["r2"], nodeif="r2-eth2")
    switch[1].add_link(tgen.gears["r3"], nodeif="r3-eth1")


def ltemplatePreRouterStartHook():
    cc = ltemplateRtrCmd()
    krel = platform.release()
    tgen = get_topogen()
    logger.info("pre router-start hook, kernel=" + krel)

    # check for mpls
    if tgen.hasmpls != True:
        logger.info("MPLS not available, skipping setup")
        return False
    # trace errors/unexpected output
    cc.resetCounts()
    # configure r2 mpls interfaces
    intfs = ["lo", "r2-eth0", "r2-eth1", "r2-eth2"]
    for intf in intfs:
        cc.doCmd(tgen, "r2", "echo 1 > /proc/sys/net/mpls/conf/{}/input".format(intf))

    # configure cust1 VRFs & MPLS
    rtrs = ["r1", "r3", "r4"]
    cmds = [
        "ip link add {0}-cust1 type vrf table 10",
        "ip ru add oif {0}-cust1 table 10",
        "ip ru add iif {0}-cust1 table 10",
        "ip link set dev {0}-cust1 up",
    ]
    for rtr in rtrs:
        for cmd in cmds:
            cc.doCmd(tgen, rtr, cmd.format(rtr))
        cc.doCmd(tgen, rtr, "ip link set dev {0}-eth4 master {0}-cust1".format(rtr))
        intfs = [rtr + "-cust1", "lo", rtr + "-eth0", rtr + "-eth4"]
        for intf in intfs:
            cc.doCmd(
                tgen, rtr, "echo 1 > /proc/sys/net/mpls/conf/{}/input".format(intf)
            )
        logger.info(
            "setup {0} vrf {0}-cust1, {0}-eth4. enabled mpls input.".format(rtr)
        )
    # configure cust4 VRFs & MPLS
    cmds = [
        "ip link add {0}-cust4 type vrf table 30",
        "ip link set dev {0}-cust4 up",
        "ip link add {0}-cust5 type vrf table 40",
        "ip link set dev {0}-cust5 up",
    ]
    rtr = "r1"
    for cmd in cmds:
        cc.doCmd(tgen, rtr, cmd.format(rtr))
    logger.info("setup {0} vrf {0}-cust3 and{0}-cust4.".format(rtr))
    # configure cust2 VRFs & MPLS
    rtrs = ["r4"]
    cmds = [
        "ip link add {0}-cust2 type vrf table 20",
        "ip ru add oif {0}-cust2 table 20",
        "ip ru add iif {0}-cust2 table 20",
        "ip link set dev {0}-cust2 up",
    ]
    for rtr in rtrs:
        for cmd in cmds:
            cc.doCmd(tgen, rtr, cmd.format(rtr))
        cc.doCmd(tgen, rtr, "ip link set dev {0}-eth5 master {0}-cust2".format(rtr))
        intfs = [rtr + "-cust2", rtr + "-eth5"]
        for intf in intfs:
            cc.doCmd(
                tgen, rtr, "echo 1 > /proc/sys/net/mpls/conf/{}/input".format(intf)
            )
        logger.info(
            "setup {0} vrf {0}-cust2, {0}-eth5. enabled mpls input.".format(rtr)
        )
    # put ce4-eth0 into a VRF (no default instance!)
    rtrs = ["ce4"]
    cmds = [
        "ip link add {0}-cust2 type vrf table 20",
        "ip ru add oif {0}-cust2 table 20",
        "ip ru add iif {0}-cust2 table 20",
        "ip link set dev {0}-cust2 up",
    ]
    for rtr in rtrs:
        for cmd in cmds:
            cc.doCmd(tgen, rtr, cmd.format(rtr))
        cc.doCmd(tgen, rtr, "ip link set dev {0}-eth0 master {0}-cust2".format(rtr))
    if cc.getOutput() != 0:
        InitSuccess = False
        logger.info(
            "Unexpected output seen ({} times, tests will be skipped".format(
                cc.getOutput()
            )
        )
    else:
        rtrs = ["r1", "r3", "r4", "ce4"]
        for rtr in rtrs:
            logger.info("{} configured".format(rtr))
            cc.doCmd(tgen, rtr, "ip -d link show type vrf")
            cc.doCmd(tgen, rtr, "ip link show")
        InitSuccess = True
        logger.info("VRF config successful!")
    return InitSuccess


def ltemplatePostRouterStartHook():
    logger.info("post router-start hook")
    return True
