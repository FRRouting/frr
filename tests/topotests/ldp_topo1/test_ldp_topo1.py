#!/usr/bin/env python

#
# test_bgp_multiview_topo1.py
# Part of NetDEF Topology Tests
#
# Copyright (c) 2016 by
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

r"""
test_ldp_topo1.py: Simple FRR LDP Test

             +---------+
             |    r1   |
             | 1.1.1.1 |
             +----+----+
                  | .1  r1-eth0
                  |
            ~~~~~~~~~~~~~
          ~~     sw0     ~~
          ~~ 10.0.1.0/24 ~~
            ~~~~~~~~~~~~~
                  |10.0.1.0/24
                  |
                  | .2  r2-eth0
             +----+----+
             |    r2   |
             | 2.2.2.2 |
             +--+---+--+
    r2-eth2  .2 |   | .2  r2-eth1
         ______/     \______
        /                   \
  ~~~~~~~~~~~~~        ~~~~~~~~~~~~~
~~     sw2     ~~    ~~     sw1     ~~
~~ 10.0.3.0/24 ~~    ~~ 10.0.2.0/24 ~~
  ~~~~~~~~~~~~~        ~~~~~~~~~~~~~
        |                 /    |
         \      _________/     |
          \    /                \
r3-eth1 .3 |  | .3  r3-eth0      | .4 r4-eth0
      +----+--+---+         +----+----+
      |     r3    |         |    r4   |
      |  3.3.3.3  |         | 4.4.4.4 |
      +-----------+         +---------+
"""

import os
import re
import sys
import pytest
import json
from functools import partial
from time import sleep
from lib.topolog import logger

# Save the Current Working Directory to find configuration files.
CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from lib import topotest
from lib.topogen import Topogen, get_topogen

fatal_error = ""

pytestmark = [pytest.mark.ldpd, pytest.mark.ospfd]

#####################################################
##
##   Network Topology Definition
##
#####################################################


def build_topo(tgen):

    # Setup Routers
    for i in range(1, 5):
        tgen.add_router("r%s" % i)

    # First switch
    switch = tgen.add_switch("sw0")
    switch.add_link(tgen.gears["r1"])
    switch.add_link(tgen.gears["r2"])
    # Second switch
    switch = tgen.add_switch("sw1")
    switch.add_link(tgen.gears["r2"])
    switch.add_link(tgen.gears["r3"])
    switch.add_link(tgen.gears["r4"])
    # Third switch
    switch = tgen.add_switch("sw2")
    switch.add_link(tgen.gears["r2"])
    switch.add_link(tgen.gears["r3"])


#####################################################
##
##   Helper functions
##
#####################################################


def router_compare_json_output(rname, command, reference, count=60, wait=1):
    "Compare router JSON output"

    logger.info('Comparing router "%s" "%s" output', rname, command)

    tgen = get_topogen()
    filename = "{}/{}/{}".format(CWD, rname, reference)
    expected = json.loads(open(filename).read())

    # Run test function until we get an result.
    test_func = partial(topotest.router_json_cmp, tgen.gears[rname], command, expected)
    _, diff = topotest.run_and_expect(test_func, None, count, wait)
    assertmsg = '"{}" JSON output mismatches the expected result'.format(rname)
    assert diff is None, assertmsg


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
    for i in range(1, 5):
        net["r%s" % i].loadConf("zebra", "%s/r%s/zebra.conf" % (thisDir, i))
        net["r%s" % i].loadConf("ospfd", "%s/r%s/ospfd.conf" % (thisDir, i))
        net["r%s" % i].loadConf("ldpd", "%s/r%s/ldpd.conf" % (thisDir, i))
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
    sleep(5)

    # Starting Routers
    for i in range(1, 5):
        fatal_error = net["r%s" % i].checkRouterRunning()
        assert fatal_error == "", fatal_error


def test_mpls_interfaces():
    global fatal_error
    net = get_topogen().net

    # Skip if previous fatal error condition is raised
    if fatal_error != "":
        pytest.skip(fatal_error)

    thisDir = os.path.dirname(os.path.realpath(__file__))

    # Verify MPLS Interfaces
    print("\n\n** Verifying MPLS Interfaces")
    print("******************************************\n")
    failures = 0
    for i in range(1, 5):
        refTableFile = "%s/r%s/show_mpls_ldp_interface.ref"
        if os.path.isfile(refTableFile):
            # Read expected result from file
            expected = open(refTableFile).read().rstrip()
            # Fix newlines (make them all the same)
            expected = ("\n".join(expected.splitlines()) + "\n").splitlines(1)

            # Actual output from router
            actual = (
                net["r%s" % i]
                .cmd('vtysh -c "show mpls ldp interface" 2> /dev/null')
                .rstrip()
            )
            # Mask out Timer in Uptime
            actual = re.sub(r" [0-9][0-9]:[0-9][0-9]:[0-9][0-9] ", " xx:xx:xx ", actual)
            # Fix newlines (make them all the same)
            actual = ("\n".join(actual.splitlines()) + "\n").splitlines(1)

            # Generate Diff
            diff = topotest.get_textdiff(
                actual,
                expected,
                title1="actual MPLS LDP interface status",
                title2="expected MPLS LDP interface status",
            )

            # Empty string if it matches, otherwise diff contains unified diff
            if diff:
                sys.stderr.write(
                    "r%s failed MPLS LDP Interface status Check:\n%s\n" % (i, diff)
                )
                failures += 1
            else:
                print("r%s ok" % i)

            if failures > 0:
                fatal_error = "MPLS LDP Interface status failed"

            assert (
                failures == 0
            ), "MPLS LDP Interface status failed for router r%s:\n%s" % (i, diff)

    # Make sure that all daemons are running
    for i in range(1, 5):
        fatal_error = net["r%s" % i].checkRouterRunning()
        assert fatal_error == "", fatal_error


def test_ospf_convergence():
    logger.info("Test: check OSPF adjacencies")

    # Skip if previous fatal error condition is raised
    if fatal_error != "":
        pytest.skip(fatal_error)

    for rname in ["r1", "r2", "r3", "r4"]:
        router_compare_json_output(
            rname, "show ip ospf neighbor json", "show_ip_ospf_neighbor.json"
        )


def test_mpls_ldp_neighbor_establish():
    global fatal_error
    net = get_topogen().net

    # Skip if previous fatal error condition is raised
    if fatal_error != "":
        pytest.skip(fatal_error)

    neighbors_operational = {
        1: 1,
        2: 3,
        3: 2,
        4: 2,
    }

    # Wait for MPLS LDP neighbors to establish.
    print("\n\n** Verify MPLS LDP neighbors to establish")
    print("******************************************\n")
    timeout = 90
    while timeout > 0:
        print("Timeout in %s: " % timeout),
        sys.stdout.flush()
        # Look for any node not yet converged
        for i in range(1, 5):
            established = (
                net["r%s" % i]
                .cmd('vtysh -c "show mpls ldp neighbor" 2> /dev/null')
                .rstrip()
            )

            # On current version, we need to make sure they all turn to OPERATIONAL on all lines
            #
            lines = ("\n".join(established.splitlines()) + "\n").splitlines(1)
            # Check all lines to be either table header (starting with ^AF or show OPERATIONAL)
            header = r"^AF.*"
            operational = r"^ip.*OPERATIONAL.*"
            found_operational = 0
            for j in range(1, len(lines)):
                if (not re.search(header, lines[j])) and (
                    not re.search(operational, lines[j])
                ):
                    established = ""  # Empty string shows NOT established
                if re.search(operational, lines[j]):
                    found_operational += 1

            logger.info("Found operational %d" % found_operational)
            if found_operational < 1:
                # Need at least one operational neighbor
                established = ""  # Empty string shows NOT established
            else:
                if found_operational != neighbors_operational[i]:
                    established = ""
            if not established:
                print("Waiting for r%s" % i)
                sys.stdout.flush()
                break
        if not established:
            sleep(5)
            timeout -= 5
        else:
            print("Done")
            break
    else:
        # Bail out with error if a router fails to converge
        fatal_error = "MPLS LDP neighbors did not establish"
        assert False, "MPLS LDP neighbors did not establish"

    print("MPLS LDP neighbors established.")

    if timeout < 60:
        # Only wait if we actually went through a convergence
        print("\nwaiting 15s for LDP sessions to establish")
        sleep(15)

    # Make sure that all daemons are running
    for i in range(1, 5):
        fatal_error = net["r%s" % i].checkRouterRunning()
        assert fatal_error == "", fatal_error


def test_mpls_ldp_discovery():
    global fatal_error
    net = get_topogen().net

    # Skip if previous fatal error condition is raised
    if fatal_error != "":
        pytest.skip(fatal_error)

    thisDir = os.path.dirname(os.path.realpath(__file__))

    # Verify MPLS LDP discovery
    print("\n\n** Verifying MPLS LDP discovery")
    print("******************************************\n")
    failures = 0
    for i in range(1, 5):
        refTableFile = "%s/r%s/show_mpls_ldp_discovery.ref" % (thisDir, i)
        if os.path.isfile(refTableFile):
            # Actual output from router
            actual = (
                net["r%s" % i]
                .cmd('vtysh -c "show mpls ldp discovery" 2> /dev/null')
                .rstrip()
            )

            # Read expected result from file
            expected = open(refTableFile).read().rstrip()
            # Fix newlines (make them all the same)
            expected = ("\n".join(expected.splitlines()) + "\n").splitlines(1)

            # Actual output from router
            actual = (
                net["r%s" % i]
                .cmd('vtysh -c "show mpls ldp discovery" 2> /dev/null')
                .rstrip()
            )

            # Fix newlines (make them all the same)
            actual = ("\n".join(actual.splitlines()) + "\n").splitlines(1)

            # Generate Diff
            diff = topotest.get_textdiff(
                actual,
                expected,
                title1="actual MPLS LDP discovery output",
                title2="expected MPLS LDP discovery output",
            )

            # Empty string if it matches, otherwise diff contains unified diff
            if diff:
                sys.stderr.write(
                    "r%s failed MPLS LDP discovery output Check:\n%s\n" % (i, diff)
                )
                failures += 1
            else:
                print("r%s ok" % i)

            assert (
                failures == 0
            ), "MPLS LDP Interface discovery output for router r%s:\n%s" % (i, diff)

    # Make sure that all daemons are running
    for i in range(1, 5):
        fatal_error = net["r%s" % i].checkRouterRunning()
        assert fatal_error == "", fatal_error


def test_mpls_ldp_neighbor():
    global fatal_error
    net = get_topogen().net

    # Skip if previous fatal error condition is raised
    if fatal_error != "":
        pytest.skip(fatal_error)

    thisDir = os.path.dirname(os.path.realpath(__file__))

    # Verify MPLS LDP neighbor
    print("\n\n** Verifying MPLS LDP neighbor")
    print("******************************************\n")
    failures = 0
    for i in range(1, 5):
        refTableFile = "%s/r%s/show_mpls_ldp_neighbor.ref" % (thisDir, i)
        if os.path.isfile(refTableFile):
            # Read expected result from file
            expected = open(refTableFile).read().rstrip()
            # Fix newlines (make them all the same)
            expected = ("\n".join(expected.splitlines()) + "\n").splitlines(1)

            # Actual output from router
            actual = (
                net["r%s" % i]
                .cmd('vtysh -c "show mpls ldp neighbor" 2> /dev/null')
                .rstrip()
            )

            # Mask out changing parts in output
            # Mask out Timer in Uptime
            actual = re.sub(
                r"(ipv4 [0-9\.]+ +OPERATIONAL [0-9\.]+ +)[0-9][0-9]:[0-9][0-9]:[0-9][0-9]",
                r"\1xx:xx:xx",
                actual,
            )

            # Fix newlines (make them all the same)
            actual = ("\n".join(actual.splitlines()) + "\n").splitlines(1)

            # Generate Diff
            diff = topotest.get_textdiff(
                actual,
                expected,
                title1="actual MPLS LDP neighbor output",
                title2="expected MPLS LDP neighbor output",
            )

            # Empty string if it matches, otherwise diff contains unified diff
            if diff:
                sys.stderr.write(
                    "r%s failed MPLS LDP neighbor output Check:\n%s\n" % (i, diff)
                )
                failures += 1
            else:
                print("r%s ok" % i)

            assert (
                failures == 0
            ), "MPLS LDP Interface neighbor output for router r%s:\n%s" % (i, diff)

    # Make sure that all daemons are running
    for i in range(1, 5):
        fatal_error = net["r%s" % i].checkRouterRunning()
        assert fatal_error == "", fatal_error


def test_mpls_ldp_binding():
    global fatal_error
    net = get_topogen().net

    # Skip this test for now until proper sorting of the output
    # is implemented
    # pytest.skip("Skipping test_mpls_ldp_binding")

    # Skip if previous fatal error condition is raised
    if fatal_error != "":
        pytest.skip(fatal_error)

    thisDir = os.path.dirname(os.path.realpath(__file__))

    # Verify MPLS LDP binding
    print("\n\n** Verifying MPLS LDP binding")
    print("******************************************\n")
    failures = 0
    for i in range(1, 5):
        refTableFile = "%s/r%s/show_mpls_ldp_binding.ref" % (thisDir, i)
        if os.path.isfile(refTableFile):
            # Read expected result from file
            expected = open(refTableFile).read().rstrip()
            # Fix newlines (make them all the same)
            expected = ("\n".join(expected.splitlines()) + "\n").splitlines(1)

            # Actual output from router
            actual = (
                net["r%s" % i]
                .cmd('vtysh -c "show mpls ldp binding" 2> /dev/null')
                .rstrip()
            )

            # Mask out changing parts in output
            # Mask out label
            actual = re.sub(
                r"(ipv4 [0-9\./]+ +[0-9\.]+ +)[0-9][0-9] (.*)", r"\1xxx\2", actual
            )
            actual = re.sub(
                r"(ipv4 [0-9\./]+ +[0-9\.]+ +[a-z\-]+ +)[0-9][0-9] (.*)",
                r"\1xxx\2",
                actual,
            )

            # Fix newlines (make them all the same)
            actual = ("\n".join(actual.splitlines()) + "\n").splitlines(1)

            # Sort lines which start with "xx via inet "
            pattern = r"^\s+[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+\s+"
            swapped = True
            while swapped:
                swapped = False
                for j in range(1, len(actual)):
                    if re.search(pattern, actual[j]) and re.search(
                        pattern, actual[j - 1]
                    ):
                        if actual[j - 1] > actual[j]:
                            temp = actual[j - 1]
                            actual[j - 1] = actual[j]
                            actual[j] = temp
                            swapped = True

            # Generate Diff
            diff = topotest.get_textdiff(
                actual,
                expected,
                title1="actual MPLS LDP binding output",
                title2="expected MPLS LDP binding output",
            )

            # Empty string if it matches, otherwise diff contains unified diff
            if diff:
                sys.stderr.write(
                    "r%s failed MPLS LDP binding output Check:\n%s\n" % (i, diff)
                )
                failures += 1
            else:
                print("r%s ok" % i)

            assert failures == 0, "MPLS LDP binding output for router r%s:\n%s" % (
                i,
                diff,
            )

    # Make sure that all daemons are running
    for i in range(1, 5):
        fatal_error = net["r%s" % i].checkRouterRunning()
        assert fatal_error == "", fatal_error


def test_zebra_ipv4_routingTable():
    global fatal_error
    net = get_topogen().net

    # Skip if previous fatal error condition is raised
    if fatal_error != "":
        pytest.skip(fatal_error)

    thisDir = os.path.dirname(os.path.realpath(__file__))

    # Verify Zebra IPv4 Routing Table
    print("\n\n** Verifying Zebra IPv4 Routing Table")
    print("******************************************\n")
    failures = 0
    for i in range(1, 5):
        refTableFile = "%s/r%s/show_ipv4_route.ref" % (thisDir, i)
        if os.path.isfile(refTableFile):
            # Read expected result from file
            expected = open(refTableFile).read().rstrip()

            # Actual output from router
            actual = (
                net["r%s" % i]
                .cmd('vtysh -c "show ip route" 2> /dev/null | grep "^O"')
                .rstrip()
            )
            # Drop timers on end of line
            actual = re.sub(r", [0-2][0-9]:[0-5][0-9]:[0-5][0-9]", "", actual)

            # Mask out label - all LDP labels should be >= 10 (2-digit)
            #   leaving the implicit labels unmasked
            actual = re.sub(r" label [0-9][0-9]+", " label xxx", actual)
            #   and translating remaining implicit (single-digit) labels to label implicit-null
            actual = re.sub(r" label [0-9]+", " label implicit-null", actual)
            # Check if we have implicit labels - if not, then remove them from reference
            if not re.search(r" label implicit-null", actual):
                expected = re.sub(r", label implicit-null", "", expected)

            # now fix newlines of expected (make them all the same)
            expected = ("\n".join(expected.splitlines()) + "\n").splitlines(1)

            # Fix newlines (make them all the same)
            actual = ("\n".join(actual.splitlines()) + "\n").splitlines(1)

            # Generate Diff
            diff = topotest.get_textdiff(
                actual,
                expected,
                title1="actual IPv4 zebra routing table",
                title2="expected IPv4 zebra routing table",
            )

            # Empty string if it matches, otherwise diff contains unified diff
            if diff:
                sys.stderr.write(
                    "r%s failed IPv4 Zebra Routing Table Check:\n%s\n" % (i, diff)
                )
                failures += 1
            else:
                print("r%s ok" % i)

            assert (
                failures == 0
            ), "IPv4 Zebra Routing Table verification failed for router r%s:\n%s" % (
                i,
                diff,
            )

    # Make sure that all daemons are running
    for i in range(1, 5):
        fatal_error = net["r%s" % i].checkRouterRunning()
        assert fatal_error == "", fatal_error


def test_mpls_table():
    global fatal_error
    net = get_topogen().net

    # Skip if previous fatal error condition is raised
    if fatal_error != "":
        pytest.skip(fatal_error)

    thisDir = os.path.dirname(os.path.realpath(__file__))

    # Verify MPLS table
    print("\n\n** Verifying MPLS table")
    print("******************************************\n")
    failures = 0

    for i in range(1, 5):
        refTableFile = "%s/r%s/show_mpls_table.ref" % (thisDir, i)
        if os.path.isfile(refTableFile):
            # Read expected result from file
            expected = open(refTableFile).read()
            # Fix newlines (make them all the same)
            expected = ("\n".join(expected.splitlines()) + "\n").splitlines(1)

            # Actual output from router
            actual = net["r%s" % i].cmd('vtysh -c "show mpls table" 2> /dev/null')

            # Fix inconsistent Label numbers at beginning of line
            actual = re.sub(r"(\s+)[0-9]+(\s+LDP)", r"\1XX\2", actual)
            # Fix inconsistent Label numbers at end of line
            actual = re.sub(
                r"(\s+[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+\s+)[0-9][0-9]", r"\1XX", actual
            )

            # Fix newlines (make them all the same)
            actual = ("\n".join(actual.splitlines()) + "\n").splitlines(1)

            # Sort lines which start with "      XX      LDP"
            pattern = r"^\s+[0-9X]+\s+LDP"
            swapped = True
            while swapped:
                swapped = False
                for j in range(1, len(actual)):
                    if re.search(pattern, actual[j]) and re.search(
                        pattern, actual[j - 1]
                    ):
                        if actual[j - 1] > actual[j]:
                            temp = actual[j - 1]
                            actual[j - 1] = actual[j]
                            actual[j] = temp
                            swapped = True

            # Generate Diff
            diff = topotest.get_textdiff(
                actual,
                expected,
                title1="actual MPLS table output",
                title2="expected MPLS table output",
            )

            # Empty string if it matches, otherwise diff contains unified diff
            if diff:
                sys.stderr.write(
                    "r%s failed MPLS table output Check:\n%s\n" % (i, diff)
                )
                failures += 1
            else:
                print("r%s ok" % i)

            assert failures == 0, "MPLS table output for router r%s:\n%s" % (i, diff)

    # Make sure that all daemons are running
    for i in range(1, 5):
        fatal_error = net["r%s" % i].checkRouterRunning()
        assert fatal_error == "", fatal_error


def test_linux_mpls_routes():
    global fatal_error
    net = get_topogen().net

    # Skip if previous fatal error condition is raised
    if fatal_error != "":
        pytest.skip(fatal_error)

    thisDir = os.path.dirname(os.path.realpath(__file__))

    # Verify Linux Kernel MPLS routes
    print("\n\n** Verifying Linux Kernel MPLS routes")
    print("******************************************\n")
    failures = 0
    for i in range(1, 5):
        refTableFile = "%s/r%s/ip_mpls_route.ref" % (thisDir, i)
        if os.path.isfile(refTableFile):
            # Read expected result from file
            expected = open(refTableFile).read().rstrip()
            # Fix newlines (make them all the same)
            expected = ("\n".join(expected.splitlines()) + "\n").splitlines(1)

            # Actual output from router
            actual = (
                net["r%s" % i].cmd("ip -o -family mpls route 2> /dev/null").rstrip()
            )

            # Mask out label and protocol
            actual = re.sub(r"[0-9][0-9] via inet ", "xx via inet ", actual)
            actual = re.sub(r"[0-9][0-9] +proto", "xx  proto", actual)
            actual = re.sub(r"[0-9][0-9] as to ", "xx as to ", actual)
            actual = re.sub(r"[ ]+proto \w+", "  proto xx", actual)

            # Sort nexthops
            nexthop_sorted = []
            for line in actual.splitlines():
                tokens = re.split(r"\\\t", line.strip())
                nexthop_sorted.append(
                    "{} {}".format(
                        tokens[0].strip(),
                        " ".join([token.strip() for token in sorted(tokens[1:])]),
                    ).strip()
                )

            # Sort lines and fixup differences between old and new iproute
            actual = "\n".join(sorted(nexthop_sorted))
            actual = re.sub(r"nexthop via", "nexthopvia", actual)
            actual = re.sub(r" nexthop as to xx via inet ", " nexthopvia inet ", actual)
            actual = re.sub(r" weight 1", "", actual)
            actual = re.sub(r" [ ]+", " ", actual)

            # put \n back at line ends
            actual = ("\n".join(actual.splitlines()) + "\n").splitlines(1)

            # Generate Diff
            diff = topotest.get_textdiff(
                actual,
                expected,
                title1="actual Linux Kernel MPLS route",
                title2="expected Linux Kernel MPLS route",
            )

            # Empty string if it matches, otherwise diff contains unified diff
            if diff:
                sys.stderr.write(
                    "r%s failed Linux Kernel MPLS route output Check:\n%s\n" % (i, diff)
                )
                failures += 1
            else:
                print("r%s ok" % i)

            assert (
                failures == 0
            ), "Linux Kernel MPLS route output for router r%s:\n%s" % (i, diff)

    # Make sure that all daemons are running
    for i in range(1, 5):
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

    for i in range(1, 5):
        net["r%s" % i].stopRouter()
        log = net["r%s" % i].getStdErr("ldpd")
        if log:
            print("\nRouter r%s LDPd StdErr Log:\n%s" % (i, log))
        log = net["r%s" % i].getStdErr("ospfd")
        if log:
            print("\nRouter r%s OSPFd StdErr Log:\n%s" % (i, log))
        log = net["r%s" % i].getStdErr("zebra")
        if log:
            print("\nRouter r%s Zebra StdErr Log:\n%s" % (i, log))


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

    for i in range(1, 5):
        net["r%s" % i].stopRouter()
        net["r%s" % i].report_memory_leaks(
            os.environ.get("TOPOTESTS_CHECK_MEMLEAK"), os.path.basename(__file__)
        )


if __name__ == "__main__":

    # To suppress tracebacks, either use the following pytest call or add "--tb=no" to cli
    # retval = pytest.main(["-s", "--tb=no"])
    retval = pytest.main(["-s"])
    sys.exit(retval)
