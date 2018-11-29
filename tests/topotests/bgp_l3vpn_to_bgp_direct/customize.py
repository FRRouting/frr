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
customize.py: Simple FRR/Quagga MPLS L3VPN test topology

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
      |     r3    |         |    r4   |
      |  3.3.3.3  |         | 4.4.4.4 |               PE Routers
      +-----------+         +---------+
 192.168.1. | .1     192.168.1.  | .1    rX-eth4
            | .2                 | .2    ceX-eth0
      +-----+-----+         +----+-----+
      |    ce2    |         |   ce3    |
      | 99.0.0.2  |         | 99.0.0.3 |              CE Routers
      +-----+-----+         +----+-----+
            |                    |

"""

import os
import re
import pytest

# pylint: disable=C0413
# Import topogen and topotest helpers
from lib import topotest
from lib.topogen import Topogen, TopoRouter, get_topogen
from lib.topolog import logger
from lib.ltemplate import ltemplateRtrCmd

# Required to instantiate the topology builder class.
from mininet.topo import Topo

import shutil
CWD = os.path.dirname(os.path.realpath(__file__))
# test name based on directory
TEST = os.path.basename(CWD)

class ThisTestTopo(Topo):
    "Test topology builder"
    def build(self, *_args, **_opts):
        "Build function"
        tgen = get_topogen(self)

        # This function only purpose is to define allocation and relationship
        # between routers, switches and hosts.
        #
        # Create P/PE routers
        tgen.add_router('r1')
        #check for mpls
        if tgen.hasmpls != True:
            logger.info('MPLS not available, tests will be skipped')
            return
        for routern in range(2, 5):
            tgen.add_router('r{}'.format(routern))
        # Create CE routers
        for routern in range(1, 4):
            tgen.add_router('ce{}'.format(routern))

        #CE/PE links
        tgen.add_link(tgen.gears['ce1'], tgen.gears['r1'], 'ce1-eth0', 'r1-eth4')
        tgen.add_link(tgen.gears['ce2'], tgen.gears['r3'], 'ce2-eth0', 'r3-eth4')
        tgen.add_link(tgen.gears['ce3'], tgen.gears['r4'], 'ce3-eth0', 'r4-eth4')

        # Create a switch with just one router connected to it to simulate a
        # empty network.
        switch = {}
        switch[0] = tgen.add_switch('sw0')
        switch[0].add_link(tgen.gears['r1'], nodeif='r1-eth0')
        switch[0].add_link(tgen.gears['r2'], nodeif='r2-eth0')

        switch[1] = tgen.add_switch('sw1')
        switch[1].add_link(tgen.gears['r2'], nodeif='r2-eth1')
        switch[1].add_link(tgen.gears['r3'], nodeif='r3-eth0')
        switch[1].add_link(tgen.gears['r4'], nodeif='r4-eth0')

        switch[1] = tgen.add_switch('sw2')
        switch[1].add_link(tgen.gears['r2'], nodeif='r2-eth2')
        switch[1].add_link(tgen.gears['r3'], nodeif='r3-eth1')

def ltemplatePreRouterStartHook():
    cc = ltemplateRtrCmd()
    tgen = get_topogen()
    logger.info('pre router-start hook')
    #check for mpls
    if tgen.hasmpls != True:
        logger.info('MPLS not available, skipping setup')
        return False
    #check for normal init
    if len(tgen.net) == 1:
        logger.info('Topology not configured, skipping setup')
        return False
    #configure r2 mpls interfaces
    intfs = ['lo', 'r2-eth0', 'r2-eth1', 'r2-eth2']
    for intf in intfs:
        cc.doCmd(tgen, 'r2', 'echo 1 > /proc/sys/net/mpls/conf/{}/input'.format(intf))
    #configure MPLS
    rtrs = ['r1', 'r3', 'r4']
    cmds = ['echo 1 > /proc/sys/net/mpls/conf/lo/input']
    for rtr in rtrs:
        router = tgen.gears[rtr]
        for cmd in cmds:
            cc.doCmd(tgen, rtr, cmd)
        intfs = ['lo', rtr+'-eth0', rtr+'-eth4']
        for intf in intfs:
            cc.doCmd(tgen, rtr, 'echo 1 > /proc/sys/net/mpls/conf/{}/input'.format(intf))
    logger.info('setup mpls input')
    return True

def ltemplatePostRouterStartHook():
    logger.info('post router-start hook')
    return True

