#!/usr/bin/env python

#
# test_zebra_netlink.py
#
# Copyright (c) 2020 by
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
test_zebra_netlink.py: Test some basic interactions with kernel using Netlink

"""

import os
import re
import sys
import pytest
import json
import platform
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


class ZebraTopo(Topo):
    "Test topology builder"

    def build(self, *_args, **_opts):
        "Build function"
        tgen = get_topogen(self)

        tgen.add_router("r1")

        # Create a empty network for router 1
        switch = tgen.add_switch("s1")
        switch.add_link(tgen.gears["r1"])


#####################################################
##
##   Tests starting
##
#####################################################


def setup_module(mod):
    "Sets up the pytest environment"
    tgen = Topogen(ZebraTopo, mod.__name__)
    tgen.start_topology()

    router_list = tgen.routers()
    for rname, router in router_list.items():
        router.load_config(
            TopoRouter.RD_ZEBRA, os.path.join(CWD, "{}/zebra.conf".format(rname))
        )

        router.load_config(
            TopoRouter.RD_SHARP, os.path.join(CWD, "{}/sharpd.conf".format(rname))
        )

    # Initialize all routers.
    tgen.start_router()


def teardown_module(_mod):
    "Teardown the pytest environment"
    tgen = get_topogen()

    # This function tears down the whole topology.
    tgen.stop_topology()


def test_zebra_netlink_batching():
    "Test the situation where dataplane fills netlink send buffer entirely."
    logger.info(
        "Test the situation where dataplane fills netlink send buffer entirely."
    )
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip("skipped because of previous test failure")
    r1 = tgen.gears["r1"]

    # Reduce the size of the buffer to hit the limit.
    r1.vtysh_cmd("conf t\nzebra kernel netlink batch-tx-buf 256 256")

    r1.vtysh_cmd("sharp install routes 2.1.3.7 nexthop 192.168.1.1 100")
    json_file = "{}/r1/v4_route.json".format(CWD)
    expected = json.loads(open(json_file).read())
    test_func = partial(
        topotest.router_json_cmp,
        r1,
        "show ip route json",
        expected,
    )
    _, result = topotest.run_and_expect(test_func, None, count=2, wait=0.5)
    assertmsg = '"r1" JSON output mismatches'
    assert result is None, assertmsg

    r1.vtysh_cmd("sharp remove routes 2.1.3.7 100")


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
