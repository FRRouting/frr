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

    r1 = tgen.gears["r1"]

    r1.vtysh_cmd("sharp install route 1.0.0.0 nexthop-group one 1000000", isjson=False)
    test_func = partial(topotest.router_json_cmp, r1, "show ip route summary json", expected_installed)
    _, result = topotest.run_and_expect(test_func, None, count=40, wait=5)
    output = r1.vtysh_cmd("sharp data route", isjson=False)
    logger.info("1 million routes X 1 ecmp installed")
    logger.info(output)
    r1.vtysh_cmd("sharp remove route 1.0.0.0 1000000", isjson=False)
    test_func = partial(topotest.router_json_cmp, r1, "show ip route summary json", expected_removed)
    _, result = topotest.run_and_expect(test_func, None, count=40, wait=5)
    output = r1.vtysh_cmd("sharp data route", isjson=False)
    logger.info("1 million routes x 1 ecmp removed")
    logger.info(output)

    r1.vtysh_cmd("sharp install route 1.0.0.0 nexthop-group two 1000000", isjson=False)
    test_func = partial(topotest.router_json_cmp, r1, "show ip route summary json", expected_installed)
    _, result = topotest.run_and_expect(test_func, None, count=40, wait=5)
    output = r1.vtysh_cmd("sharp data route", isjson=False)
    logger.info("1 million routes X 2 ecmp installed")
    logger.info(output)
    r1.vtysh_cmd("sharp remove route 1.0.0.0 1000000", isjson=False)
    test_func = partial(topotest.router_json_cmp, r1, "show ip route summary json", expected_removed)
    _, result = topotest.run_and_expect(test_func, None, count=40, wait=5)
    output = r1.vtysh_cmd("sharp data route", isjson=False)
    logger.info("1 million routes x 2 ecmp removed")
    logger.info(output)

    r1.vtysh_cmd("sharp install route 1.0.0.0 nexthop-group four 1000000", isjson=False)
    test_func = partial(topotest.router_json_cmp, r1, "show ip route summary json", expected_installed)
    _, result = topotest.run_and_expect(test_func, None, count=40, wait=5)
    output = r1.vtysh_cmd("sharp data route", isjson=False)
    logger.info("1 million routes X 4 ecmp installed")
    logger.info(output)
    r1.vtysh_cmd("sharp remove route 1.0.0.0 1000000", isjson=False)
    test_func = partial(topotest.router_json_cmp, r1, "show ip route summary json", expected_removed)
    _, result = topotest.run_and_expect(test_func, None, count=40, wait=5)
    output = r1.vtysh_cmd("sharp data route", isjson=False)
    logger.info("1 million routes x 4 ecmp removed")
    logger.info(output)

    r1.vtysh_cmd("sharp install route 1.0.0.0 nexthop-group eight 1000000", isjson=False)
    test_func = partial(topotest.router_json_cmp, r1, "show ip route summary json", expected_installed)
    _, result = topotest.run_and_expect(test_func, None, count=40, wait=5)
    output = r1.vtysh_cmd("sharp data route", isjson=False)
    logger.info("1 million routes X 8 ecmp installed")
    logger.info(output)
    r1.vtysh_cmd("sharp remove route 1.0.0.0 1000000", isjson=False)
    test_func = partial(topotest.router_json_cmp, r1, "show ip route summary json", expected_removed)
    _, result = topotest.run_and_expect(test_func, None, count=40, wait=5)
    output = r1.vtysh_cmd("sharp data route", isjson=False)
    logger.info("1 million routes x 8 ecmp removed")
    logger.info(output)

    r1.vtysh_cmd("sharp install route 1.0.0.0 nexthop-group sixteen 1000000", isjson=False)
    test_func = partial(topotest.router_json_cmp, r1, "show ip route summary json", expected_installed)
    _, result = topotest.run_and_expect(test_func, None, count=40, wait=5)
    output = r1.vtysh_cmd("sharp data route", isjson=False)
    logger.info("1 million routes X 16 ecmp installed")
    logger.info(output)
    r1.vtysh_cmd("sharp remove route 1.0.0.0 1000000", isjson=False)
    test_func = partial(topotest.router_json_cmp, r1, "show ip route summary json", expected_removed)
    _, result = topotest.run_and_expect(test_func, None, count=40, wait=5)
    output = r1.vtysh_cmd("sharp data route", isjson=False)
    logger.info("1 million routes x 16 ecmp removed")
    logger.info(output)

    r1.vtysh_cmd("sharp install route 1.0.0.0 nexthop-group thirtytwo 1000000", isjson=False)
    test_func = partial(topotest.router_json_cmp, r1, "show ip route summary json", expected_installed)
    _, result = topotest.run_and_expect(test_func, None, count=40, wait=5)
    output = r1.vtysh_cmd("sharp data route", isjson=False)
    logger.info("1 million routes X 32 ecmp installed")
    logger.info(output)
    r1.vtysh_cmd("sharp remove route 1.0.0.0 1000000", isjson=False)
    test_func = partial(topotest.router_json_cmp, r1, "show ip route summary json", expected_removed)
    _, result = topotest.run_and_expect(test_func, None, count=40, wait=5)
    output = r1.vtysh_cmd("sharp data route", isjson=False)
    logger.info("1 million routes x 32 ecmp removed")
    logger.info(output)

if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
