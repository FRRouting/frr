#!/usr/bin/env python
# SPDX-License-Identifier: ISC

#
# test_rip_topo1.py
# Part of NetDEF Topology Tests
#
# Copyright (c) 2017 by
# Network Device Education Foundation, Inc. ("NetDEF")
#

"""
test_rip_topo1.py: Testing RIPv2

"""

import os
import re
import sys
import pytest
from time import sleep
import functools


sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from lib import topotest
from lib.topogen import Topogen, get_topogen

fatal_error = ""

pytestmark = [pytest.mark.ripd]

#####################################################
##
##   Network Topology Definition
##
#####################################################


def build_topo(tgen):
    # Setup RIP Routers
    for i in range(1, 4):
        tgen.add_router("r%s" % i)

    #
    # On main router
    # First switch is for a dummy interface (for local network)
    switch = tgen.add_switch("sw1")
    switch.add_link(tgen.gears["r1"])
    #
    # Switches for RIP

    # switch 2 switch is for connection to RIP router
    switch = tgen.add_switch("sw2")
    switch.add_link(tgen.gears["r1"])
    switch.add_link(tgen.gears["r2"])

    # switch 3 is between RIP routers
    switch = tgen.add_switch("sw3")
    switch.add_link(tgen.gears["r2"])
    switch.add_link(tgen.gears["r3"], nodeif="r3-eth1")

    # switch 4 is stub on remote RIP router
    switch = tgen.add_switch("sw4")
    switch.add_link(tgen.gears["r3"], nodeif="r3-eth0")

    switch = tgen.add_switch("sw5")
    switch.add_link(tgen.gears["r1"])

    switch = tgen.add_switch("sw6")
    switch.add_link(tgen.gears["r1"])


#####################################################
##
##   Tests starting
##
#####################################################


def setup_module(module):
    print("\n\n** %s: Setup Topology" % module.__name__)
    print("******************************************\n")

    thisDir = os.path.dirname(os.path.realpath(__file__))
    tgen = Topogen(build_topo, module.__name__)
    tgen.start_topology()

    net = tgen.net

    # Starting Routers
    #
    for i in range(1, 4):
        net["r%s" % i].loadConf("zebra", "%s/r%s/zebra.conf" % (thisDir, i))
        net["r%s" % i].loadConf("ripd", "%s/r%s/ripd.conf" % (thisDir, i))
        tgen.gears["r%s" % i].start()

    # For debugging after starting FRR daemons, uncomment the next line
    # tgen.mininet_cli()


def teardown_module(module):
    print("\n\n** %s: Shutdown Topology" % module.__name__)
    print("******************************************\n")
    tgen = get_topogen()
    tgen.stop_topology()


def test_router_running():
    global fatal_error
    net = get_topogen().net

    # Skip if previous fatal error condition is raised
    if fatal_error != "":
        pytest.skip(fatal_error)

    print("\n\n** Check if FRR is running on each Router node")
    print("******************************************\n")

    # Make sure that all daemons are running
    for i in range(1, 4):
        fatal_error = net["r%s" % i].checkRouterRunning()
        assert fatal_error == "", fatal_error


def test_converge_protocols():
    global fatal_error
    net = get_topogen().net

    # Skip if previous fatal error condition is raised
    if fatal_error != "":
        pytest.skip(fatal_error)

    thisDir = os.path.dirname(os.path.realpath(__file__))

    print("\n\n** Waiting for protocols convergence")
    print("******************************************\n")

    # Not really implemented yet - just sleep 11 secs for now
    sleep(21)

    # Make sure that all daemons are still running
    for i in range(1, 4):
        fatal_error = net["r%s" % i].checkRouterRunning()
        assert fatal_error == "", fatal_error


def test_rip_status():
    global fatal_error
    net = get_topogen().net

    # Skip if previous fatal error condition is raised
    if fatal_error != "":
        pytest.skip(fatal_error)

    thisDir = os.path.dirname(os.path.realpath(__file__))

    # Verify RIP Status
    print("\n\n** Verifing RIP status")
    print("******************************************\n")
    failures = 0
    for i in range(1, 4):
        refTableFile = "%s/r%s/rip_status.ref" % (thisDir, i)
        if os.path.isfile(refTableFile):
            # Read expected result from file
            expected = open(refTableFile).read().rstrip()
            # Fix newlines (make them all the same)
            expected = ("\n".join(expected.splitlines()) + "\n").splitlines(1)

            # Actual output from router
            actual = (
                net["r%s" % i]
                .cmd('vtysh -c "show ip rip status" 2> /dev/null')
                .rstrip()
            )
            # Drop time in next due
            actual = re.sub(r"in [0-9]+ seconds", "in XX seconds", actual)
            # Drop time in last update
            actual = re.sub(r" [0-2][0-9]:[0-5][0-9]:[0-5][0-9]", " XX:XX:XX", actual)
            # Fix newlines (make them all the same)
            actual = ("\n".join(actual.splitlines()) + "\n").splitlines(1)

            # Generate Diff
            diff = topotest.get_textdiff(
                actual,
                expected,
                title1="actual IP RIP status",
                title2="expected IP RIP status",
            )

            # Empty string if it matches, otherwise diff contains unified diff
            if diff:
                sys.stderr.write("r%s failed IP RIP status check:\n%s\n" % (i, diff))
                failures += 1
            else:
                print("r%s ok" % i)

            assert failures == 0, "IP RIP status failed for router r%s:\n%s" % (i, diff)

    # Make sure that all daemons are still running
    for i in range(1, 4):
        fatal_error = net["r%s" % i].checkRouterRunning()
        assert fatal_error == "", fatal_error


def test_rip_routes():
    global fatal_error
    net = get_topogen().net

    # Skip if previous fatal error condition is raised
    if fatal_error != "":
        pytest.skip(fatal_error)

    thisDir = os.path.dirname(os.path.realpath(__file__))

    # Verify RIP Status
    print("\n\n** Verifing RIP routes")
    print("******************************************\n")
    failures = 0
    for i in range(1, 4):
        refTableFile = "%s/r%s/show_ip_rip.ref" % (thisDir, i)
        if os.path.isfile(refTableFile):
            # Read expected result from file
            expected = open(refTableFile).read().rstrip()
            # Fix newlines (make them all the same)
            expected = ("\n".join(expected.splitlines()) + "\n").splitlines(1)

            # Actual output from router
            actual = net["r%s" % i].cmd('vtysh -c "show ip rip" 2> /dev/null').rstrip()
            # Drop Time
            actual = re.sub(r"[0-9][0-9]:[0-5][0-9]", "XX:XX", actual)
            # Fix newlines (make them all the same)
            actual = ("\n".join(actual.splitlines()) + "\n").splitlines(1)

            # Generate Diff
            diff = topotest.get_textdiff(
                actual,
                expected,
                title1="actual SHOW IP RIP",
                title2="expected SHOW IP RIP",
            )

            # Empty string if it matches, otherwise diff contains unified diff
            if diff:
                sys.stderr.write("r%s failed SHOW IP RIP check:\n%s\n" % (i, diff))
                failures += 1
            else:
                print("r%s ok" % i)

            assert failures == 0, "SHOW IP RIP failed for router r%s:\n%s" % (i, diff)

    # Make sure that all daemons are still running
    for i in range(1, 4):
        fatal_error = net["r%s" % i].checkRouterRunning()
        assert fatal_error == "", fatal_error


def test_zebra_ipv4_routingTable():
    global fatal_error
    net = get_topogen().net

    def _verify_ip_route(expected):
        # Actual output from router
        actual = (
            net["r%s" % i]
            .cmd('vtysh -c "show ip route" 2> /dev/null | grep "^R"')
            .rstrip()
        )
        # Drop timers on end of line
        actual = re.sub(r", [0-2][0-9]:[0-5][0-9]:[0-5][0-9]", "", actual)
        # Fix newlines (make them all the same)
        actual = ("\n".join(actual.splitlines()) + "\n").splitlines(1)

        return topotest.get_textdiff(
            actual,
            expected,
            title1="actual Zebra IPv4 routing table",
            title2="expected Zebra IPv4 routing table",
        )

    # Skip if previous fatal error condition is raised
    if fatal_error != "":
        pytest.skip(fatal_error)

    thisDir = os.path.dirname(os.path.realpath(__file__))

    print("\n\n** Verifing Zebra IPv4 Routing Table")
    print("******************************************\n")
    for i in range(1, 4):
        refTableFile = "%s/r%s/show_ip_route.ref" % (thisDir, i)
        if os.path.isfile(refTableFile):
            expected = open(refTableFile).read().rstrip()
            # Fix newlines (make them all the same)
            expected = ("\n".join(expected.splitlines()) + "\n").splitlines(1)

            test_func = functools.partial(_verify_ip_route, expected)
            success, _ = topotest.run_and_expect(test_func, "", count=30, wait=1)
            assert success, "Failed verifying IPv4 routes for r{}".format(i)

    # Make sure that all daemons are still running
    for i in range(1, 4):
        fatal_error = net["r%s" % i].checkRouterRunning()
        assert fatal_error == "", fatal_error


def test_shutdown_check_stderr():
    global fatal_error
    net = get_topogen().net

    # Skip if previous fatal error condition is raised
    if fatal_error != "":
        pytest.skip(fatal_error)

    if os.environ.get("TOPOTESTS_CHECK_STDERR") is None:
        pytest.skip("Skipping test for Stderr output and memory leaks")

    thisDir = os.path.dirname(os.path.realpath(__file__))

    print("\n\n** Verifing unexpected STDERR output from daemons")
    print("******************************************\n")

    net["r1"].stopRouter()

    log = net["r1"].getStdErr("ripd")
    if log:
        print("\nRIPd StdErr Log:\n" + log)
    log = net["r1"].getStdErr("zebra")
    if log:
        print("\nZebra StdErr Log:\n" + log)


if __name__ == "__main__":
    # To suppress tracebacks, either use the following pytest call or add "--tb=no" to cli
    # retval = pytest.main(["-s", "--tb=no"])
    retval = pytest.main(["-s"])
    sys.exit(retval)
