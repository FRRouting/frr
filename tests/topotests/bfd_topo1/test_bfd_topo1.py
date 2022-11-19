#!/usr/bin/env python

#
# test_bfd_topo1.py
# Part of NetDEF Topology Tests
#
# Copyright (c) 2018 by
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
test_bfd_topo1.py: Test the FRR BFD daemon.
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
from lib.topolog import logger

pytestmark = [pytest.mark.bfdd, pytest.mark.bgpd]


def setup_module(mod):
    "Sets up the pytest environment"
    topodef = {
        "s1": ("r1", "r2"),
        "s2": ("r2", "r3"),
        "s3": ("r2", "r4"),
    }
    tgen = Topogen(topodef, mod.__name__)
    tgen.start_topology()

    router_list = tgen.routers()
    for rname, router in router_list.items():
        router.load_config(
            TopoRouter.RD_ZEBRA, os.path.join(CWD, "{}/zebra.conf".format(rname))
        )
        router.load_config(
            TopoRouter.RD_BFD, os.path.join(CWD, "{}/bfdd.conf".format(rname))
        )
        router.load_config(
            TopoRouter.RD_BGP, os.path.join(CWD, "{}/bgpd.conf".format(rname))
        )

    # Initialize all routers.
    tgen.start_router()

    # Verify that we are using the proper version and that the BFD
    # daemon exists.
    for router in router_list.values():
        # Check for Version
        if router.has_version("<", "5.1"):
            tgen.set_error("Unsupported FRR version")
            break


def teardown_module(_mod):
    "Teardown the pytest environment"
    tgen = get_topogen()
    tgen.stop_topology()


def test_bfd_connection():
    "Assert that the BFD peers can find themselves."
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    logger.info("waiting for bfd peers to go up")

    for router in tgen.routers().values():
        json_file = "{}/{}/peers.json".format(CWD, router.name)
        expected = json.loads(open(json_file).read())

        test_func = partial(
            topotest.router_json_cmp, router, "show bfd peers json", expected
        )
        _, result = topotest.run_and_expect(test_func, None, count=30, wait=0.5)
        assertmsg = '"{}" JSON output mismatches'.format(router.name)
        assert result is None, assertmsg


def test_bgp_convergence():
    "Assert that BGP is converging."
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    logger.info("waiting for bgp peers to go up")

    for router in tgen.routers().values():
        ref_file = "{}/{}/bgp_summary.json".format(CWD, router.name)
        expected = json.loads(open(ref_file).read())
        test_func = partial(
            topotest.router_json_cmp, router, "show ip bgp summary json", expected
        )
        _, res = topotest.run_and_expect(test_func, None, count=125, wait=1.0)
        assertmsg = "{}: bgp did not converge".format(router.name)
        assert res is None, assertmsg


def test_bgp_fast_convergence():
    "Assert that BGP is converging before setting a link down."
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    logger.info("waiting for bgp peers converge")

    for router in tgen.routers().values():
        ref_file = "{}/{}/bgp_prefixes.json".format(CWD, router.name)
        expected = json.loads(open(ref_file).read())
        test_func = partial(
            topotest.router_json_cmp, router, "show ip bgp json", expected
        )
        _, res = topotest.run_and_expect(test_func, None, count=40, wait=0.5)
        assertmsg = "{}: bgp did not converge".format(router.name)
        assert res is None, assertmsg


def test_bfd_fast_convergence():
    """
    Assert that BFD notices the link down after simulating network
    failure.
    """
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    # Disable r1-eth0 link.
    tgen.gears["r1"].link_enable("r1-eth0", enabled=False)

    # Wait the minimum time we can before checking that BGP/BFD
    # converged.
    logger.info("waiting for BFD converge")

    # Check that BGP converged quickly.
    for router in tgen.routers().values():
        json_file = "{}/{}/peers.json".format(CWD, router.name)
        expected = json.loads(open(json_file).read())

        # Load the same file as previous test, but expect R1 to be down.
        if router.name == "r1":
            for peer in expected:
                if peer["peer"] == "192.168.0.2":
                    peer["status"] = "down"
        else:
            for peer in expected:
                if peer["peer"] == "192.168.0.1":
                    peer["status"] = "down"

        test_func = partial(
            topotest.router_json_cmp, router, "show bfd peers json", expected
        )
        _, res = topotest.run_and_expect(test_func, None, count=20, wait=0.5)
        assertmsg = '"{}" JSON output mismatches'.format(router.name)
        assert res is None, assertmsg


def test_bgp_fast_reconvergence():
    "Assert that BGP is converging after setting a link down."
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    logger.info("waiting for BGP re convergence")

    # Check that BGP converged quickly.
    for router in tgen.routers().values():
        ref_file = "{}/{}/bgp_prefixes.json".format(CWD, router.name)
        expected = json.loads(open(ref_file).read())

        # Load the same file as previous test, but set networks to None
        # to test absence.
        if router.name == "r1":
            expected["routes"]["10.254.254.2/32"] = None
            expected["routes"]["10.254.254.3/32"] = None
            expected["routes"]["10.254.254.4/32"] = None
        else:
            expected["routes"]["10.254.254.1/32"] = None

        test_func = partial(
            topotest.router_json_cmp, router, "show ip bgp json", expected
        )
        _, res = topotest.run_and_expect(test_func, None, count=5, wait=1)
        assertmsg = "{}: bgp did not converge".format(router.name)
        assert res is None, assertmsg


def test_memory_leak():
    "Run the memory leak test and report results."
    tgen = get_topogen()
    if not tgen.is_memleak_enabled():
        pytest.skip("Memory leak test/report is disabled")

    tgen.report_memory_leaks()


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
