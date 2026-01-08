#!/usr/bin/env python
# SPDX-License-Identifier: ISC
#
# test_isis_unnumbered.py
# Part of NetDEF Topology Tests
#
# Copyright (c) 2025 by
# Network Device Education Foundation, Inc. ("NetDEF")

"""
test_isis_unnumbered.py: Unnumbered ISIS topology.
"""
import time
import datetime
import functools
import json
import os
import re
import sys
import pytest

CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

# pylint: disable=C0413
from lib import topotest
from lib.common_config import start_router
from lib.topogen import Topogen, TopoRouter, get_topogen
from lib.topolog import logger

pytestmark = [pytest.mark.isisd]


def build_topo(tgen):
    "Build function"

    # Add ISIS routers:
    #      r1
    #    /   \
    #  r2 --- r3
    for routern in range(1, 4):
        tgen.add_router("r{}".format(routern))

    tgen.add_link(tgen.gears["r1"], tgen.gears["r2"], "r1-eth0", "r2-eth0")
    tgen.add_link(tgen.gears["r1"], tgen.gears["r3"], "r1-eth1", "r3-eth0")
    tgen.add_link(tgen.gears["r2"], tgen.gears["r3"], "r2-eth1", "r3-eth1")


def setup_module(mod):
    "Sets up the pytest environment"
    tgen = Topogen(build_topo, mod.__name__)
    tgen.start_topology()

    # For all registered routers, load the zebra configuration file
    for rname, router in tgen.routers().items():
        router.load_config(
            TopoRouter.RD_ZEBRA, os.path.join(CWD, "{}/zebra.conf".format(rname))
        )
        router.load_config(
            TopoRouter.RD_ISIS, os.path.join(CWD, "{}/isisd.conf".format(rname))
        )

    # After loading the configurations, this function loads configured daemons.
    tgen.start_router()


def teardown_module():
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

    logger.info("waiting for ISIS protocol to converge")
    for rname, router in tgen.routers().items():
        filename = "{0}/{1}/{1}_topology.json".format(CWD, rname)
        expected = json.loads(open(filename).read())

        def compare_isis_topology(router, expected):
            "Helper function to test ISIS topology convergence."
            actual = json.loads(router.vtysh_cmd("show isis topology json"))
            return topotest.json_cmp(actual, expected)

        test_func = functools.partial(compare_isis_topology, router, expected)
        (result, diff) = topotest.run_and_expect(test_func, None, wait=0.5, count=120)
        assert result, "ISIS did not converge on {}:\n{}".format(rname, diff)


def test_isis_route_installation():
    "Check whether all expected routes are present"
    tgen = get_topogen()
    # Don't run this test if we have any failure.
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    logger.info("Checking routers for installed ISIS routes")

    # Check for routes in 'show ip route json'
    for rname, router in tgen.routers().items():
        filename = "{0}/{1}/{1}_route.json".format(CWD, rname)
        expected = json.loads(open(filename, "r").read())

        def compare_isis_installed_routes(router, expected):
            "Helper function to test ISIS routes installed in rib."
            actual = router.vtysh_cmd("show ip route json", isjson=True)
            return topotest.json_cmp(actual, expected)

        test_func = functools.partial(compare_isis_installed_routes, router, expected)
        (result, diff) = topotest.run_and_expect(test_func, None, wait=1, count=10)
        assert result, "Router '{}' routes mismatch:\n{}".format(rname, diff)


def test_isis_linux_route_installation():
    "Check whether all expected routes are present and installed in the OS"
    tgen = get_topogen()
    # Don't run this test if we have any failure.
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    logger.info("Checking routers for installed ISIS routes in OS")

    # Check for routes in `ip route`
    for rname, router in tgen.routers().items():
        filename = "{0}/{1}/{1}_route_linux.json".format(CWD, rname)
        expected = json.loads(open(filename, "r").read())
        # use `ip route` directly and not `topotest.ip4_route(router)` so that
        # we can check the `onlink` flag.
        actual = json.loads(router.run("ip -json route"))

        assertmsg = "Router '{}' OS routes mismatch".format(rname)
        assert topotest.json_cmp(actual, expected) is None, assertmsg


def test_isis_summary_json():
    "Check json struct in show isis summary json"

    tgen = get_topogen()
    # Don't run this test if we have any failure.
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    logger.info("Checking 'show isis summary json'")
    for rname, _ in tgen.routers().items():
        logger.info("Checking router %s", rname)
        json_output = tgen.gears[rname].vtysh_cmd("show isis summary json", isjson=True)
        assertmsg = "Test isis summary json failed in '{}' data '{}'".format(
            rname, json_output
        )
        assert json_output["vrfs"][0]["vrf"] == "default", assertmsg
        assert json_output["vrfs"][0]["areas"][0]["area"] == "1", assertmsg
        assert json_output["vrfs"][0]["areas"][0]["levels"][0]["id"] != "3", assertmsg


def test_isis_interface_json():
    "Check json struct in show isis interface json"

    tgen = get_topogen()
    # Don't run this test if we have any failure.
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    logger.info("Checking 'show isis interface json'")
    for rname, _ in tgen.routers().items():
        logger.info("Checking router %s", rname)
        json_output = tgen.gears[rname].vtysh_cmd(
            "show isis interface json", isjson=True
        )
        assertmsg = "Test isis interface json failed in '{}' data '{}'".format(
            rname, json_output
        )
        assert (
            json_output["areas"][0]["circuits"][0]["interface"]["name"] == "lo"
        ), assertmsg
        assert (
            json_output["areas"][0]["circuits"][1]["interface"]["name"]
            == rname + "-eth0"
        ), assertmsg
        assert (
            json_output["areas"][0]["circuits"][2]["interface"]["name"]
            == rname + "-eth1"
        ), assertmsg

    for rname, router in tgen.routers().items():
        logger.info("Checking router %s", rname)
        json_output = tgen.gears[rname].vtysh_cmd(
            "show isis interface detail json", isjson=True
        )
        assertmsg = "Test isis interface json failed in '{}' data '{}'".format(
            rname, json_output
        )
        assert (
            json_output["areas"][0]["circuits"][0]["interface"]["name"] == "lo"
        ), assertmsg
        assert (
            json_output["areas"][0]["circuits"][1]["interface"]["name"]
            == rname + "-eth0"
        ), assertmsg
        assert (
            json_output["areas"][0]["circuits"][2]["interface"]["name"]
            == rname + "-eth1"
        ), assertmsg


def test_isis_neighbor_json():
    "Check json struct in show isis neighbor json"

    tgen = get_topogen()
    # Don't run this test if we have any failure.
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    # tgen.mininet_cli()
    logger.info("Checking 'show isis neighbor json'")
    for rname, _ in tgen.routers().items():
        logger.info("Checking router %s", rname)
        json_output = tgen.gears[rname].vtysh_cmd(
            "show isis neighbor json", isjson=True
        )
        assertmsg = "Test isis neighbor json failed in '{}' data '{}'".format(
            rname, json_output
        )
        assert (
            json_output["areas"][0]["circuits"][1]["interface"] == rname + "-eth0"
        ), assertmsg
        assert json_output["areas"][0]["circuits"][1]["state"] == "Up", assertmsg
        assert (
            json_output["areas"][0]["circuits"][2]["interface"] == rname + "-eth1"
        ), assertmsg
        assert json_output["areas"][0]["circuits"][2]["state"] == "Up", assertmsg

    for rname, router in tgen.routers().items():
        logger.info("Checking router %s", rname)
        json_output = tgen.gears[rname].vtysh_cmd(
            "show isis neighbor detail json", isjson=True
        )
        assertmsg = "Test isis neighbor json failed in '{}' data '{}'".format(
            rname, json_output
        )
        assert (
            json_output["areas"][0]["circuits"][1]["interface"]["name"]
            == rname + "-eth0"
        ), assertmsg
        assert (
            json_output["areas"][0]["circuits"][1]["interface"]["state"] == "Up"
        ), assertmsg
        assert (
            json_output["areas"][0]["circuits"][2]["interface"]["name"]
            == rname + "-eth1"
        ), assertmsg
        assert (
            json_output["areas"][0]["circuits"][2]["interface"]["state"] == "Up"
        ), assertmsg


def test_memory_leak():
    "Run the memory leak test and report results."
    tgen = get_topogen()
    if not tgen.is_memleak_enabled():
        pytest.skip("Memory leak test/report is disabled")

    tgen.report_memory_leaks()


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
