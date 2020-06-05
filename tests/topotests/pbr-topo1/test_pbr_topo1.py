#!/usr/bin/env python

#
# test_pbr_topo1.py
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
test_pbr_topo1.py: Testing PBR

"""

import os
import re
import sys
import pytest
import json

# Save the Current Working Directory to find configuration files.
CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

# pylint: disable=C0413
# Import topogen and topotest helpers
from lib import topotest
from lib.topogen import Topogen, TopoRouter, get_topogen
from lib.topolog import logger

# Required to instantiate the topology builder class.
from mininet.topo import Topo

#####################################################
##
##   Network Topology Definition
##
#####################################################


class NetworkTopo(Topo):
    "PBR Topology 1"

    def build(self, **_opts):
        "Build function"

        tgen = get_topogen(self)

        # Populate routers
        for routern in range(1, 2):
            tgen.add_router("r{}".format(routern))

        # Populate switches
        for switchn in range(1, 6):
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
            TopoRouter.RD_PBRD, os.path.join(CWD, "{}/pbrd.conf".format(rname))
        )

    tgen.start_router()


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

    topotest.sleep(5, "Waiting for PBR convergence")


def test_pbr_data():
    "Test PBR 'show ip eigrp'"

    tgen = get_topogen()
    # Don't run this test if we have any failure.
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    # Verify PBR Status
    logger.info("Verifying PBR routes")

    router_list = tgen.routers().values()
    for router in router_list:
        intf_file = "{}/{}/pbr-interface.json".format(CWD, router.name)
        logger.info(intf_file)

        # Read expected result from file
        expected = json.loads(open(intf_file).read())

        # Actual output from router
        actual = router.vtysh_cmd("show pbr interface json", isjson=True)
        assertmsg = '"show pbr interface" mismatches on {}'.format(router.name)
        assert topotest.json_cmp(actual, expected) is None, assertmsg

        map_file = "{}/{}/pbr-map.json".format(CWD, router.name)
        logger.info(map_file)

        # Read expected result from file
        expected = json.loads(open(map_file).read())

        # Actual output from router
        actual = router.vtysh_cmd("show pbr map json", isjson=True)

        assertmsg = '"show pbr map" mismatches on {}'.format(router.name)
        assert topotest.json_cmp(actual, expected) is None, assertmsg

        nexthop_file = "{}/{}/pbr-nexthop-groups.json".format(CWD, router.name)
        logger.info(nexthop_file)

        # Read expected result from file
        expected = json.loads(open(nexthop_file).read())

        # Actual output from router
        actual = router.vtysh_cmd("show pbr nexthop-groups json", isjson=True)

        assertmsg = '"show pbr nexthop-groups" mismatches on {}'.format(router.name)
        assert topotest.json_cmp(actual, expected) is None, assertmsg


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
