#!/usr/bin/env python

#
# test_route_scale.py
#
# Copyright (c) 2020 by
# Cumulus Networks, Inc.
# Donald Sharp
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
test_route_scale.py: Testing route scale

"""

import os
import re
import sys
import pytest
import json
from functools import partial

# Save the Current Working Directory to find configuration files.
CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

# pylint: disable=C0413
# Import topogen and topotest helpers
from lib import topotest
from lib.topogen import Topogen, TopoRouter, get_topogen
from lib.topolog import logger
from lib.common_config import shutdown_bringup_interface

# Required to instantiate the topology builder class.
from mininet.topo import Topo

#####################################################
##
##   Network Topology Definition
##
#####################################################


class NetworkTopo(Topo):
    "Route Scale Topology"

    def build(self, **_opts):
        "Build function"

        tgen = get_topogen(self)

        # Populate routers
        for routern in range(1, 2):
            tgen.add_router("r{}".format(routern))

        # Populate switches
        for switchn in range(1, 33):
            switch = tgen.add_switch("sw{}".format(switchn))
            switch.add_link(tgen.gears["r1"])


#####################################################
##
##   Tests starting
##
#####################################################


def setup_module(module):
    "Setup topology"
    tgen = Topogen(NetworkTopo, module.__name__)
    tgen.start_topology()

    router_list = tgen.routers()
    for rname, router in router_list.iteritems():
        router.load_config(
            TopoRouter.RD_ZEBRA, os.path.join(CWD, "{}/zebra.conf".format(rname))
        )
        router.load_config(
            TopoRouter.RD_SHARP, os.path.join(CWD, "{}/sharpd.conf".format(rname))
        )

    tgen.start_router()
    #tgen.mininet_cli()

def teardown_module(_mod):
    "Teardown the pytest environment"
    tgen = get_topogen()

    # This function tears down the whole topology.
    tgen.stop_topology()

def test_converge_protocols():
    "Wait for protocol convergence"

    tgen = get_topogen()
    # Don't run this test if we have any failure.
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

def run_one_setup(r1, s):
    "Run one ecmp config"

    # Extract params
    expected_installed = s['expect_in']
    expected_removed = s['expect_rem']

    count = s['count']
    wait = s['wait']

    logger.info("Testing 1 million routes X {} ecmp".format(s['ecmp']))

    r1.vtysh_cmd("sharp install route 1.0.0.0 \
                  nexthop-group {} 1000000".format(s['nhg']),
                 isjson=False)

    test_func = partial(topotest.router_json_cmp, r1, "show ip route summary json", expected_installed)
    success, result = topotest.run_and_expect(test_func, None, count, wait)
    assert success, "Route scale test install failed:\n{}".format(result)

    output = r1.vtysh_cmd("sharp data route", isjson=False)
    logger.info("1 million routes X {} ecmp installed".format(s['ecmp']))
    logger.info(output)
    r1.vtysh_cmd("sharp remove route 1.0.0.0 1000000", isjson=False)
    test_func = partial(topotest.router_json_cmp, r1, "show ip route summary json", expected_removed)
    success, result = topotest.run_and_expect(test_func, None, count, wait)
    assert success, "Route scale test remove failed:\n{}".format(result)

    output = r1.vtysh_cmd("sharp data route", isjson=False)
    logger.info("1 million routes x {} ecmp removed".format(
        s['ecmp']))
    logger.info(output)


def test_route_install():
    "Test route install for a variety of ecmp"

    tgen = get_topogen()
    # Don't run this test if we have any failure.
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    installed_file = "{}/r1/installed.routes.json".format(CWD)
    expected_installed = json.loads(open(installed_file).read())

    removed_file = "{}/r1/no.routes.json".format(CWD)
    expected_removed = json.loads(open(removed_file).read())

    # dict keys of params: ecmp number, corresponding nhg name, timeout,
    # number of times to wait
    scale_keys = ['ecmp', 'nhg', 'wait', 'count', 'expect_in', 'expect_rem']

    # Table of defaults, used for timeout values and 'expected' objects
    scale_defaults = dict(zip(scale_keys, [None, None, 7, 30,
                                           expected_installed,
                                           expected_removed]))

    # List of params for each step in the test; note extra time given
    # for the highest ecmp steps. Executing 'show' at scale can be costly
    # so we widen the interval there too.
    scale_steps = [
        [1, 'one'], [2, 'two'], [4, 'four'],
        [8, 'eight'], [16, 'sixteen', 10, 40], [32, 'thirtytwo', 10, 40]
    ]

    # Build up a list of dicts with params for each step of the test;
    # use defaults where the step doesn't supply a value
    scale_setups = []
    for s in scale_steps:
        d = dict(zip(scale_keys, s))
        for k in scale_keys:
            if k not in d:
                d[k] = scale_defaults[k]

        scale_setups.append(d)

    # Run each step using the dicts we've built
    r1 = tgen.gears["r1"]

    for s in scale_setups:
        run_one_setup(r1, s)

# Mem leak testcase
def test_memory_leak():
    "Run the memory leak test and report results."
    tgen = get_topogen()
    if not tgen.is_memleak_enabled():
        pytest.skip("Memory leak test/report is disabled")
    tgen.report_memory_leaks()

if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
