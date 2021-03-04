#!/usr/bin/env python
#
# test_zebra_rib.py
#
# Copyright (c) 2019 by
# Cumulus Networks, Inc
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
test_zebra_rib.py: Test some basic zebra <-> kernel interactions
"""

import os
import re
import sys
from functools import partial
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


class ZebraTopo(Topo):
    "Test topology builder"

    def build(self, *_args, **_opts):
        "Build function"
        tgen = get_topogen(self)

        tgen.add_router("r1")

        # Create a empty network for router 1
        switch = tgen.add_switch("s1")
        switch.add_link(tgen.gears["r1"])
        switch.add_link(tgen.gears["r1"])
        switch.add_link(tgen.gears["r1"])
        switch.add_link(tgen.gears["r1"])
        switch.add_link(tgen.gears["r1"])
        switch.add_link(tgen.gears["r1"])
        switch.add_link(tgen.gears["r1"])
        switch.add_link(tgen.gears["r1"])


def setup_module(mod):
    "Sets up the pytest environment"
    tgen = Topogen(ZebraTopo, mod.__name__)
    tgen.start_topology()

    router_list = tgen.routers()
    for rname, router in router_list.iteritems():
        router.load_config(
            TopoRouter.RD_ZEBRA, os.path.join(CWD, "{}/zebra.conf".format(rname))
        )

    # Initialize all routers.
    tgen.start_router()


def teardown_module(mod):
    "Teardown the pytest environment"
    tgen = get_topogen()
    tgen.stop_topology()


def test_zebra_kernel_admin_distance():
    "Test some basic kernel routes added that should be accepted"
    logger.info("Test some basic kernel routes that should be accepted")
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip("skipped because of router(s) failure")

    r1 = tgen.gears["r1"]

    # Route with 255/8192 metric
    r1.run("ip route add 4.5.1.0/24 via 192.168.210.2 dev r1-eth0 metric 4278198272")
    # Route with 1/1 metric
    r1.run("ip route add 4.5.2.0/24 via 192.168.211.2 dev r1-eth1 metric 16777217")
    # Route with 10/1 metric
    r1.run("ip route add 4.5.3.0/24 via 192.168.212.2 dev r1-eth2 metric 167772161")
    # Same route with a 160/1 metric
    r1.run("ip route add 4.5.3.0/24 via 192.168.213.2 dev r1-eth3 metric 2684354561")

    # Currently I believe we have a bug here with the same route and different
    # metric.  That needs to be properly resolved.  Making a note for
    # coming back around later and fixing this.
    # tgen.mininet_cli()
    for i in range(1, 2):
        json_file = "{}/r1/v4_route_{}.json".format(CWD, i)
        expected = json.loads(open(json_file).read())

        test_func = partial(
            topotest.router_json_cmp,
            r1,
            "show ip route 4.5.{}.0 json".format(i),
            expected,
        )
        _, result = topotest.run_and_expect(test_func, None, count=2, wait=0.5)
        assertmsg = '"r1" JSON output mismatches'
        assert result is None, assertmsg
    # tgen.mininet_cli()


def test_zebra_kernel_override():
    "Test that a FRR route with a lower admin distance takes over"
    logger.info("Test kernel override with a better admin distance")
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip("skipped because of previous test failure")

    r1 = tgen.gears["r1"]
    r1.vtysh_cmd("conf\nip route 4.5.1.0/24 192.168.216.3")
    json_file = "{}/r1/v4_route_1_static_override.json".format(CWD)
    expected = json.loads(open(json_file).read())

    test_func = partial(
        topotest.router_json_cmp, r1, "show ip route 4.5.1.0 json", expected
    )
    _, result = topotest.run_and_expect(test_func, None, count=2, wait=0.5)
    assert result is None, '"r1" JSON output mismatches'

    logger.info(
        "Test that the removal of the static route allows the kernel to take back over"
    )
    r1.vtysh_cmd("conf\nno ip route 4.5.1.0/24 192.168.216.3")
    json_file = "{}/r1/v4_route_1.json".format(CWD)
    expected = json.loads(open(json_file).read())

    test_func = partial(
        topotest.router_json_cmp, r1, "show ip route 4.5.1.0 json", expected
    )
    _, result = topotest.run_and_expect(test_func, None, count=2, wait=0.5)
    assert result is None, '"r1" JSON output mismatches'


def test_memory_leak():
    "Run the memory leak test and report results."
    tgen = get_topogen()
    if not tgen.is_memleak_enabled():
        pytest.skip("Memory leak test/report is disabled")

    tgen.report_memory_leaks()


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
