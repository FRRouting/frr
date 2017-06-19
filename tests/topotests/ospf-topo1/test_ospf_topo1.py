#!/usr/bin/env python

#
# test_ospf_topo1.py
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
test_ospf_topo1.py: Test the FRR/Quagga OSPF routing daemon.
"""

import os
import sys
from functools import partial
import pytest

# Save the Current Working Directory to find configuration files.
CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, '../'))

# pylint: disable=C0413
# Import topogen and topotest helpers
from lib import topotest
from lib.topogen import Topogen, TopoRouter, get_topogen
from lib.topolog import logger

# Required to instantiate the topology builder class.
from mininet.topo import Topo

class OSPFTopo(Topo):
    "Test topology builder"
    def build(self, *_args, **_opts):
        "Build function"
        tgen = get_topogen(self)

        # Create 4 routers
        for routern in range(1, 5):
            tgen.add_router('r{}'.format(routern))

        # Create a empty network for router 1
        switch = tgen.add_switch('s1')
        switch.add_link(tgen.gears['r1'])

        # Create a empty network for router 2
        switch = tgen.add_switch('s2')
        switch.add_link(tgen.gears['r2'])

        # Interconect router 1, 2 and 3
        switch = tgen.add_switch('s3')
        switch.add_link(tgen.gears['r1'])
        switch.add_link(tgen.gears['r2'])
        switch.add_link(tgen.gears['r3'])

        # Create empty netowrk for router3
        switch = tgen.add_switch('s4')
        switch.add_link(tgen.gears['r3'])

        # Interconect router 3 and 4
        switch = tgen.add_switch('s5')
        switch.add_link(tgen.gears['r3'])
        switch.add_link(tgen.gears['r4'])

        # Create a empty network for router 4
        switch = tgen.add_switch('s6')
        switch.add_link(tgen.gears['r4'])

def setup_module(mod):
    "Sets up the pytest environment"
    tgen = Topogen(OSPFTopo, mod.__name__)
    tgen.start_topology()

    router_list = tgen.routers()
    for rname, router in router_list.iteritems():
        router.load_config(
            TopoRouter.RD_ZEBRA,
            os.path.join(CWD, '{}/zebra.conf'.format(rname))
        )
        router.load_config(
            TopoRouter.RD_OSPF,
            os.path.join(CWD, '{}/ospfd.conf'.format(rname))
        )

    # Initialize all routers.
    tgen.start_router()

def teardown_module(mod):
    "Teardown the pytest environment"
    tgen = get_topogen()
    tgen.stop_topology()

def test_ospf_convergence():
    "Test OSPF daemon convergence"
    tgen = get_topogen()

    # Define test function
    def compare_show_ip_ospf(rname, expected):
        """
        Calls 'show ip ospf route' for router `rname` and compare the obtained
        result with the expected output.
        """
        current = tgen.gears[rname].vtysh_cmd('show ip ospf route')
        return topotest.difflines(current, expected,
                                  title1="Current output",
                                  title2="Expected output")

    # Run the file comparison for all routers
    for rnum in range(1, 5):
        router = 'r{}'.format(rnum)

        # Load expected results from the command
        reffile = os.path.join(CWD, '{}/ospfroute.txt'.format(router))
        expected = open(reffile).read()

        # Run test function until we get an result. Wait at most 60 seconds.
        test_func = partial(compare_show_ip_ospf, router, expected)
        result, diff = topotest.run_and_expect(test_func, '',
                                               count=20, wait=3)
        assert result, 'OSPF did not converge on {}:\n{}'.format(router, diff)

if __name__ == '__main__':
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
