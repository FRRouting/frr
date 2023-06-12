#!/usr/bin/env python
# SPDX-License-Identifier: ISC

#
# test_ripng_topo1.py
# Part of NetDEF Topology Tests
#
# Copyright (c) 2017 by
# Network Device Education Foundation, Inc. ("NetDEF")
#

"""
test_ripng_topo1.py: Test of RIPng Topology

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
    # Setup RIPng Routers
    for i in range(1, 4):
        tgen.add_router("r%s" % i)

    #
    # On main router
    # First switch is for a dummy interface (for local network)
    switch = tgen.add_switch("sw1")
    switch.add_link(tgen.gears["r1"])
    #
    # Switches for RIPng
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
        net["r%s" % i].loadConf("ripngd", "%s/r%s/ripngd.conf" % (thisDir, i))
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

    # Starting Routers
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
    sleep(11)

    # Make sure that all daemons are running
    for i in range(1, 4):
        fatal_error = net["r%s" % i].checkRouterRunning()
        assert fatal_error == "", fatal_error


def test_ripng_status():
    global fatal_error
    net = get_topogen().net

    # Skip if previous fatal error condition is raised
    if fatal_error != "":
        pytest.skip(fatal_error)

    thisDir = os.path.dirname(os.path.realpath(__file__))

    # Verify RIP Status
    print("\n\n** Verifying RIPng status")
    print("******************************************\n")
    failures = 0
    for i in range(1, 4):
        refTableFile = "%s/r%s/ripng_status.ref" % (thisDir, i)
        if os.path.isfile(refTableFile):
            # Read expected result from file
            expected = open(refTableFile).read().rstrip()
            # Fix newlines (make them all the same)
            expected = ("\n".join(expected.splitlines()) + "\n").splitlines(1)

            # Actual output from router
            actual = (
                net["r%s" % i]
                .cmd('vtysh -c "show ipv6 ripng status" 2> /dev/null')
                .rstrip()
            )
            # Mask out Link-Local mac address portion. They are random...
            actual = re.sub(r" fe80::[0-9a-f:]+", " fe80::XXXX:XXXX:XXXX:XXXX", actual)
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
                title1="actual IPv6 RIPng status",
                title2="expected IPv6 RIPng status",
            )

            # Empty string if it matches, otherwise diff contains unified diff
            if diff:
                sys.stderr.write(
                    "r%s failed IPv6 RIPng status check:\n%s\n" % (i, diff)
                )
                failures += 1
            else:
                print("r%s ok" % i)

            assert failures == 0, "IPv6 RIPng status failed for router r%s:\n%s" % (
                i,
                diff,
            )

    # Make sure that all daemons are running
    for i in range(1, 4):
        fatal_error = net["r%s" % i].checkRouterRunning()
        assert fatal_error == "", fatal_error


def test_ripng_routes():
    global fatal_error
    net = get_topogen().net

    # Skip if previous fatal error condition is raised
    if fatal_error != "":
        pytest.skip(fatal_error)

    thisDir = os.path.dirname(os.path.realpath(__file__))

    # Verify RIPng Status
    print("\n\n** Verifying RIPng routes")
    print("******************************************\n")
    failures = 0
    for i in range(1, 4):
        refTableFile = "%s/r%s/show_ipv6_ripng.ref" % (thisDir, i)
        if os.path.isfile(refTableFile):
            # Read expected result from file
            expected = open(refTableFile).read().rstrip()
            # Fix newlines (make them all the same)
            expected = ("\n".join(expected.splitlines()) + "\n").splitlines(1)

            # Actual output from router
            actual = (
                net["r%s" % i].cmd('vtysh -c "show ipv6 ripng" 2> /dev/null').rstrip()
            )
            # Drop Time
            actual = re.sub(r" [0-9][0-9]:[0-5][0-9]", " XX:XX", actual)
            # Mask out Link-Local mac address portion. They are random...
            actual = re.sub(
                r" fe80::[0-9a-f: ]+", " fe80::XXXX:XXXX:XXXX:XXXX   ", actual
            )
            # Remove trailing spaces on all lines
            actual = "\n".join([line.rstrip() for line in actual.splitlines()])

            # Fix newlines (make them all the same)
            actual = ("\n".join(actual.splitlines()) + "\n").splitlines(1)

            # Generate Diff
            diff = topotest.get_textdiff(
                actual,
                expected,
                title1="actual SHOW IPv6 RIPng",
                title2="expected SHOW IPv6 RIPng",
            )

            # Empty string if it matches, otherwise diff contains unified diff
            if diff:
                sys.stderr.write("r%s failed SHOW IPv6 RIPng check:\n%s\n" % (i, diff))
                failures += 1
            else:
                print("r%s ok" % i)

            assert failures == 0, "SHOW IPv6 RIPng failed for router r%s:\n%s" % (
                i,
                diff,
            )

    # Make sure that all daemons are running
    for i in range(1, 4):
        fatal_error = net["r%s" % i].checkRouterRunning()
        assert fatal_error == "", fatal_error


def test_zebra_ipv6_routingTable():
    global fatal_error
    net = get_topogen().net

    def _verify_ip_route(expected):
        # Actual output from router
        actual = (
            net["r%s" % i]
            .cmd('vtysh -c "show ipv6 route" 2> /dev/null | grep "^R"')
            .rstrip()
        )
        # Mask out Link-Local mac address portion. They are random...
        actual = re.sub(r" fe80::[0-9a-f:]+", " fe80::XXXX:XXXX:XXXX:XXXX", actual)
        # Drop timers on end of line
        actual = re.sub(r", [0-2][0-9]:[0-5][0-9]:[0-5][0-9]", "", actual)
        # Fix newlines (make them all the same)
        actual = ("\n".join(actual.splitlines()) + "\n").splitlines(1)

        return topotest.get_textdiff(
            actual,
            expected,
            title1="actual Zebra IPv6 routing table",
            title2="expected Zebra IPv6 routing table",
        )

    # Skip if previous fatal error condition is raised
    if fatal_error != "":
        pytest.skip(fatal_error)

    thisDir = os.path.dirname(os.path.realpath(__file__))

    # Verify OSPFv3 Routing Table
    print("\n\n** Verifying Zebra IPv6 Routing Table")
    print("******************************************\n")
    failures = 0
    for i in range(1, 4):
        refTableFile = "%s/r%s/show_ipv6_route.ref" % (thisDir, i)
        if os.path.isfile(refTableFile):
            # Read expected result from file
            expected = open(refTableFile).read().rstrip()
            # Fix newlines (make them all the same)
            expected = ("\n".join(expected.splitlines()) + "\n").splitlines(1)

            test_func = functools.partial(_verify_ip_route, expected)
            success, _ = topotest.run_and_expect(test_func, "", count=30, wait=1)
            assert success, "Failed verifying IPv6 routes for r{}".format(i)

    # Make sure that all daemons are running
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
        print(
            "SKIPPED final check on StdErr output: Disabled (TOPOTESTS_CHECK_STDERR undefined)\n"
        )
        pytest.skip("Skipping test for Stderr output")

    thisDir = os.path.dirname(os.path.realpath(__file__))

    print("\n\n** Verifying unexpected STDERR output from daemons")
    print("******************************************\n")

    net["r1"].stopRouter()

    log = net["r1"].getStdErr("ripngd")
    if log:
        print("\nRIPngd StdErr Log:\n" + log)
    log = net["r1"].getStdErr("zebra")
    if log:
        print("\nZebra StdErr Log:\n" + log)


def test_shutdown_check_memleak():
    global fatal_error
    net = get_topogen().net

    # Skip if previous fatal error condition is raised
    if fatal_error != "":
        pytest.skip(fatal_error)

    if os.environ.get("TOPOTESTS_CHECK_MEMLEAK") is None:
        print(
            "SKIPPED final check on Memory leaks: Disabled (TOPOTESTS_CHECK_MEMLEAK undefined)\n"
        )
        pytest.skip("Skipping test for memory leaks")

    thisDir = os.path.dirname(os.path.realpath(__file__))

    net["r1"].stopRouter()
    net["r1"].report_memory_leaks(
        os.environ.get("TOPOTESTS_CHECK_MEMLEAK"), os.path.basename(__file__)
    )


if __name__ == "__main__":
    # To suppress tracebacks, either use the following pytest call or add "--tb=no" to cli
    # retval = pytest.main(["-s", "--tb=no"])
    retval = pytest.main(["-s"])
    sys.exit(retval)
