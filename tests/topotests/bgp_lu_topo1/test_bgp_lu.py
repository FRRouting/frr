#!/usr/bin/env python

#
# test_bgp_lu.py
# Part of NetDEF Topology Tests
#
# Copyright (c) 2020 by Volta Networks
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
test_bgp_lu.py: Test BGP LU label allocation
"""

import os
import sys
import json
from functools import partial
import pytest

# Save the Current Working Directory to find configuration files.
CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

# pylint: disable=C0413
# Import topogen and topotest helpers
from lib import topotest
from lib.topogen import Topogen, TopoRouter, get_topogen

# Required to instantiate the topology builder class.


pytestmark = [pytest.mark.bgpd]


# Basic scenario for BGP-LU. Nodes are directly connected.
# Node 3 is advertising many routes to 2, which advertises them
# as BGP-LU to 1; this way we get routes with actual labels, as
# opposed to implicit-null routes in the 2-node case.
#
#  AS1      BGP-LU        AS2         iBGP        AS2
# +-----+                +-----+                 +-----+
# |     |.1            .2|     |.2             .3|     |
# |  1  +----------------+  2  +-----------------+  3  |
# |     |   10.0.0.0/24  |     |   10.0.1.0/24   |     |
# +-----+                +-----+                 +-----+


def build_topo(tgen):
    "Build function"

    # This function only purpose is to define allocation and relationship
    # between routers, switches and hosts.
    #
    #
    # Create routers
    tgen.add_router("R1")
    tgen.add_router("R2")
    tgen.add_router("R3")

    # R1-R2
    switch = tgen.add_switch("s1")
    switch.add_link(tgen.gears["R1"])
    switch.add_link(tgen.gears["R2"])

    # R2-R3
    switch = tgen.add_switch("s2")
    switch.add_link(tgen.gears["R2"])
    switch.add_link(tgen.gears["R3"])


def setup_module(mod):
    "Sets up the pytest environment"
    # This function initiates the topology build with Topogen...
    tgen = Topogen(build_topo, mod.__name__)
    # ... and here it calls Mininet initialization functions.
    tgen.start_topology()

    # This is a sample of configuration loading.
    router_list = tgen.routers()

    # For all registered routers, load the zebra configuration file
    for rname, router in router_list.items():
        router.load_config(
            TopoRouter.RD_ZEBRA, os.path.join(CWD, "{}/zebra.conf".format(rname))
        )
        router.load_config(
            TopoRouter.RD_BGP, os.path.join(CWD, "{}/bgpd.conf".format(rname))
        )

    # After loading the configurations, this function loads configured daemons.
    tgen.start_router()


def teardown_module(mod):
    "Teardown the pytest environment"
    tgen = get_topogen()

    # This function tears down the whole topology.
    tgen.stop_topology()


def check_labelpool(router):
    json_file = "{}/{}/labelpool.summ.json".format(CWD, router.name)
    expected = json.loads(open(json_file).read())

    test_func = partial(
        topotest.router_json_cmp, router, "show bgp labelpool summary json", expected
    )
    _, result = topotest.run_and_expect(test_func, None, count=20, wait=1)
    assertmsg = '"{}" JSON output mismatches - Did not converge'.format(router.name)
    assert result is None, assertmsg


def test_converge_bgplu():
    "Wait for protocol convergence"

    tgen = get_topogen()
    # Don't run this test if we have any failure.
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    # tgen.mininet_cli();
    r1 = tgen.gears["R1"]
    r2 = tgen.gears["R2"]

    check_labelpool(r1)
    check_labelpool(r2)


def test_clear_bgplu():
    "Wait for protocol convergence"

    tgen = get_topogen()
    # Don't run this test if we have any failure.
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    # tgen.mininet_cli();
    r1 = tgen.gears["R1"]
    r2 = tgen.gears["R2"]

    r1.vtysh_cmd("clear bgp 10.0.0.2")
    check_labelpool(r1)
    check_labelpool(r2)

    r2.vtysh_cmd("clear bgp 10.0.1.3")
    check_labelpool(r1)
    check_labelpool(r2)

    r1.vtysh_cmd("clear bgp 10.0.0.2")
    r2.vtysh_cmd("clear bgp 10.0.1.3")
    check_labelpool(r1)
    check_labelpool(r2)


def test_memory_leak():
    "Run the memory leak test and report results."
    tgen = get_topogen()
    if not tgen.is_memleak_enabled():
        pytest.skip("Memory leak test/report is disabled")

    tgen.report_memory_leaks()


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
