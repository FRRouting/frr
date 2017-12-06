#!/usr/bin/env python

#
# test_isis_topo1.py
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
test_isis_topo1.py: Test ISIS topology.
"""

import os
import sys
import pytest

CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, '../'))

# pylint: disable=C0413
from lib import topotest
from lib.topogen import Topogen, TopoRouter, get_topogen
from lib.topolog import logger

from mininet.topo import Topo


class ISISTopo1(Topo):
    "Simple two layer ISIS topology"
    def build(self, *_args, **_opts):
        "Build function"
        tgen = get_topogen(self)

        # Add ISIS routers:
        # r1      r2
        #  | sw1  | sw2
        # r3     r4
        #  |      |
        # sw3    sw4
        #   \    /
        #     r5
        for routern in range(1, 6):
            tgen.add_router('r{}'.format(routern))

        # r1 <- sw1 -> r3
        sw = tgen.add_switch('sw1')
        sw.add_link(tgen.gears['r1'])
        sw.add_link(tgen.gears['r3'])

        # r2 <- sw2 -> r4
        sw = tgen.add_switch('sw2')
        sw.add_link(tgen.gears['r2'])
        sw.add_link(tgen.gears['r4'])

        # r3 <- sw3 -> r5
        sw = tgen.add_switch('sw3')
        sw.add_link(tgen.gears['r3'])
        sw.add_link(tgen.gears['r5'])

        # r4 <- sw4 -> r5
        sw = tgen.add_switch('sw4')
        sw.add_link(tgen.gears['r4'])
        sw.add_link(tgen.gears['r5'])


def setup_module(mod):
    "Sets up the pytest environment"
    tgen = Topogen(ISISTopo1, mod.__name__)
    tgen.start_topology()

    # For all registered routers, load the zebra configuration file
    for rname, router in tgen.routers().iteritems():
        router.load_config(
            TopoRouter.RD_ZEBRA,
            os.path.join(CWD, '{}/zebra.conf'.format(rname))
        )
        router.load_config(
            TopoRouter.RD_ISIS,
            os.path.join(CWD, '{}/isisd.conf'.format(rname))
        )

    # After loading the configurations, this function loads configured daemons.
    tgen.start_router()


def teardown_module(mod):
    "Teardown the pytest environment"
    tgen = get_topogen()

    # This function tears down the whole topology.
    tgen.stop_topology()


def test_isis_convergence():
    "Wait for the protocol to converge before starting to test"
    tgen = get_topogen()
    # Don't run this test if we have any failure.
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    topotest.sleep(10, "waiting for ISIS protocol to converge")


def test_memory_leak():
    "Run the memory leak test and report results."
    tgen = get_topogen()
    if not tgen.is_memleak_enabled():
        pytest.skip('Memory leak test/report is disabled')

    tgen.report_memory_leaks()


if __name__ == '__main__':
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
