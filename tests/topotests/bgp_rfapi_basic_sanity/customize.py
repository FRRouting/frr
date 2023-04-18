#!/usr/bin/env python
# SPDX-License-Identifier: ISC

#
# Part of NetDEF Topology Tests
#
# Copyright (c) 2017-2018 by
# Network Device Education Foundation, Inc. ("NetDEF")
# Modified by LabN Consulting, L.L.C.
#

r"""
customize.py: Simple FRR MPLS L3VPN test topology

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
      |     r3    |         |    r4   |
      |  3.3.3.3  |         | 4.4.4.4 |               PE Routers
      +-----------+         +---------+
 
"""

import os

# pylint: disable=C0413
# Import topogen and topotest helpers
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
    tgen.add_router("r1")
    for routern in range(2, 5):
        tgen.add_router("r{}".format(routern))
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

    switch[2] = tgen.add_switch("sw2")
    switch[2].add_link(tgen.gears["r2"], nodeif="r2-eth2")
    switch[2].add_link(tgen.gears["r3"], nodeif="r3-eth1")


def ltemplatePreRouterStartHook():
    cc = ltemplateRtrCmd()
    tgen = get_topogen()
    logger.info("pre router-start hook")
    return True


def ltemplatePostRouterStartHook():
    logger.info("post router-start hook")
    return True
