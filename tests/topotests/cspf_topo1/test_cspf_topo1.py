#!/usr/bin/env python

#
# test_cspf_topo1.py
# Part of NetDEF Topology Tests
#
# Copyright (c) 2022 by Orange
# Author: Olivier Dugeon <olivier.dugeon@orange.com>
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
test_cspf_topo1.py: Test the FRR Constraint Shortest Path First algorithm.

           +------------+
           |            |
           |     R1     |
           | 10.0.225.1 |
           |            |
           +------------+
        r1-eth0|    |r1-eth1
               |    |
    10.0.0.0/24|    |10.0.1.0/24
               |    |2001:db8:1:/64
               |    |
        r2-eth0|    |r2-eth1
           +------------+                  +------------+
           |            |                  |            |
           |     R2     |r2-eth2    r3-eth0|     R3     |
           | 10.0.255.2 +------------------+ 10.0.255.3 |
           |            |     10.0.3.0/24  |            |
           +------------+  2001:db8:3:/64  +------+-----+
           r2-eth3|                        r3-eth1|
                  |                               |
       10.0.4.0/24|                               |
                  |                               |
                  |                               |
           r4-eth0|                 2001:db8:5:/64|
           +------------+                         |
           |            |                         |
           |     R4     |r4-eth1                  |
           | 10.0.255.4 +-------------------------+
           |            |
           +------------+

"""

import os
import sys
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

# and Finally pytest
import pytest

pytestmark = [pytest.mark.isisd]


def build_topo(tgen):
    "Build function"

    # Create 4 routers
    for routern in range(1, 5):
        tgen.add_router("r{}".format(routern))

    # Interconect router 1 and 2 with 2 links
    switch = tgen.add_switch("s1")
    switch.add_link(tgen.gears["r1"])
    switch.add_link(tgen.gears["r2"])
    switch = tgen.add_switch("s2")
    switch.add_link(tgen.gears["r1"])
    switch.add_link(tgen.gears["r2"])

    # Interconect router 3 and 2
    switch = tgen.add_switch("s3")
    switch.add_link(tgen.gears["r3"])
    switch.add_link(tgen.gears["r2"])

    # Interconect router 4 and 2
    switch = tgen.add_switch("s4")
    switch.add_link(tgen.gears["r4"])
    switch.add_link(tgen.gears["r2"])

    # Interconnect router 3 and 4
    switch = tgen.add_switch("s5")
    switch.add_link(tgen.gears["r3"])
    switch.add_link(tgen.gears["r4"])


def setup_module(mod):
    "Sets up the pytest environment"

    logger.info("\n\n---- Starting CSPF tests ----\n")

    tgen = Topogen(build_topo, mod.__name__)
    tgen.start_topology()

    router_list = tgen.routers()

    for rname, router in router_list.items():
        router.load_config(
            TopoRouter.RD_ZEBRA, os.path.join(CWD, "{}/zebra.conf".format(rname))
        )
        router.load_config(
            TopoRouter.RD_ISIS, os.path.join(CWD, "{}/isisd.conf".format(rname))
        )
        if rname == "r1":
            router.load_config(
                TopoRouter.RD_SHARP, os.path.join(CWD, "{}/sharpd.conf".format("r1"))
            )

    # Initialize all routers.
    tgen.start_router()


def teardown_module():
    "Teardown the pytest environment"

    tgen = get_topogen()
    tgen.stop_topology()

    logger.info("\n\n---- CSPF tests End ----\n")


def compare_ted_json_output(tgen, rname, fileref):
    "Compare TED JSON output"

    logger.info('Comparing router "%s" TED output', rname)

    filename = "{}/reference/{}".format(CWD, fileref)
    expected = json.loads(open(filename).read())
    command = "show sharp ted json"

    # Run test function until we get an result. Wait at most 60 seconds.
    test_func = partial(topotest.router_json_cmp, tgen.gears[rname], command, expected)
    _, diff = topotest.run_and_expect(test_func, None, count=60, wait=2)
    assertmsg = '"{}" TED JSON output mismatches the expected result'.format(rname)
    assert diff is None, assertmsg


def compare_cspf_output(tgen, rname, fileref, src, dst, cost, bw=""):
    "Compare CSPF output"

    logger.info('Comparing router "%s" CSPF output', rname)

    filename = "{}/reference/{}".format(CWD, fileref)
    expected = open(filename).read()
    command = "show sharp cspf source {} destination {} {} {}".format(
        src, dst, cost, bw
    )

    # Run test function until we get an result. Wait at most 60 seconds.
    test_func = partial(
        topotest.router_output_cmp, tgen.gears[rname], command, expected
    )
    result, diff = topotest.run_and_expect(test_func, "", count=5, wait=2)
    assert result, "CSPF output mismatches the expected result on {}:\n{}".format(
        rname, diff
    )


def setup_testcase(msg):
    "Setup test case"

    logger.info(msg)
    tgen = get_topogen()

    # Skip if previous fatal error condition is raised
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    return tgen


# Note that all routers must discover the same Network Topology, so the same TED.


def test_step1():
    "Step1: Check initial topology"

    tgen = setup_testcase("Step1: test initial IS-IS TE Data Base import")
    tgen.net["r1"].cmd('vtysh -c "sharp import-te"')

    compare_ted_json_output(tgen, "r1", "sharp-ted.json")


def test_step2():
    "Step2: Test CSPF from r1 to r4 for IPv4 with various metric"

    tgen = setup_testcase("Step2: CSPF(r1, r4, IPv4)")

    compare_cspf_output(
        tgen, "r1", "cspf-ipv4-metric.txt", "10.0.0.1", "10.0.255.4", "metric 50"
    )
    compare_cspf_output(
        tgen, "r1", "cspf-ipv4-te-metric.txt", "10.0.255.1", "10.0.4.4", "te-metric 50"
    )
    compare_cspf_output(
        tgen, "r1", "cspf-ipv4-delay.txt", "10.0.255.1", "10.0.255.4", "delay 50000"
    )
    compare_cspf_output(
        tgen,
        "r1",
        "cspf-ipv4-delay.txt",
        "10.0.255.1",
        "10.0.255.4",
        "delay 50000",
        "rsv 7 1000000",
    )


def test_step3():
    "Step3: Test CSPF from r1 to r4 for IPv6 with various metric"

    tgen = setup_testcase("Step2: CSPF(r1, r4, IPv6)")

    compare_cspf_output(
        tgen,
        "r1",
        "cspf-ipv6-metric.txt",
        "2001:db8:1::1:1",
        "2001:db8::4",
        "metric 50",
    )
    compare_cspf_output(
        tgen,
        "r1",
        "cspf-ipv6-te-metric.txt",
        "2001:db8::1",
        "2001:db8:5::3:4",
        "te-metric 80",
    )
    compare_cspf_output(
        tgen, "r1", "cspf-ipv6-delay.txt", "2001:db8::1", "2001:db8::4", "delay 80000"
    )
    compare_cspf_output(
        tgen,
        "r1",
        "cspf-ipv6-delay.txt",
        "2001:db8::1",
        "2001:db8::4",
        "delay 80000",
        "rsv 7 1000000",
    )


def test_step4():
    "Step4: Test CSPF from r1 to r4 with no possible path"

    tgen = setup_testcase("Step2: CSPF(r1, r4, failure)")

    compare_cspf_output(
        tgen, "r1", "cspf-failed.txt", "10.0.255.1", "10.0.255.4", "metric 10"
    )
    compare_cspf_output(
        tgen, "r1", "cspf-failed.txt", "2001:db8::1", "2001:db8::4", "te-metric 50"
    )
    compare_cspf_output(
        tgen, "r1", "cspf-failed.txt", "10.0.255.1", "10.0.255.4", "delay 5000"
    )
    compare_cspf_output(
        tgen,
        "r1",
        "cspf-failed.txt",
        "2001:db8::1",
        "2001:db8::4",
        "delay 80000",
        "rsv 7 10000000",
    )
    compare_cspf_output(
        tgen, "r1", "cspf-failed-src.txt", "10.0.0.3", "10.0.255.4", "metric 10"
    )
    compare_cspf_output(
        tgen, "r1", "cspf-failed-dst.txt", "10.0.0.1", "10.0.4.40", "metric 10"
    )
    compare_cspf_output(
        tgen, "r1", "cspf-failed-same.txt", "10.0.0.1", "10.0.0.1", "metric 10"
    )


def test_memory_leak():
    "Run the memory leak test and report results."

    tgen = get_topogen()
    if not tgen.is_memleak_enabled():
        pytest.skip("Memory leak test/report is disabled")

    tgen.report_memory_leaks()


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
