#!/usr/bin/env python
# SPDX-License-Identifier: ISC

#
# test_all_protocol_startup.py
# Part of NetDEF Topology Tests
#
# Copyright (c) 2017 by
# Network Device Education Foundation, Inc. ("NetDEF")
#

"""
test_all_protocol_startup.py: Test of all protocols at same time

"""

import os
import re
import sys
import pytest
import glob
from time import sleep

pytestmark = [
    pytest.mark.babeld,
    pytest.mark.bgpd,
    pytest.mark.isisd,
    pytest.mark.nhrpd,
    pytest.mark.ospfd,
    pytest.mark.pbrd,
    pytest.mark.ripd,
]

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from lib import topotest
from lib.topogen import Topogen, get_topogen
from lib.common_config import (
    required_linux_kernel_version,
)

import json
import functools

# Global that must be set on a failure to stop subsequent tests from being run
fatal_error = ""


#####################################################
##
##   Network Topology Definition
##
#####################################################


def build_topo(tgen):
    router = tgen.add_router("r1")
    for i in range(0, 10):
        tgen.add_switch("sw{}".format(i)).add_link(router)


#####################################################
##
##   Tests starting
##
#####################################################


def setup_module(module):
    global fatal_error

    print("\n\n** {}: Setup Topology".format(module.__name__))
    print("******************************************\n")

    thisDir = os.path.dirname(os.path.realpath(__file__))
    tgen = Topogen(build_topo, module.__name__)
    tgen.start_topology()

    net = tgen.net

    if net["r1"].get_routertype() != "frr":
        fatal_error = "Test is only implemented for FRR"
        sys.stderr.write("\n\nTest is only implemented for FRR - Skipping\n\n")
        pytest.skip(fatal_error)

    # Starting Routers
    #
    # Main router
    for i in range(1, 2):
        net["r{}".format(i)].loadConf("mgmtd", "{}/r{}/zebra.conf".format(thisDir, i))
        net["r{}".format(i)].loadConf("zebra", "{}/r{}/zebra.conf".format(thisDir, i))
        net["r{}".format(i)].loadConf("ripd", "{}/r{}/ripd.conf".format(thisDir, i))
        net["r{}".format(i)].loadConf("ripngd", "{}/r{}/ripngd.conf".format(thisDir, i))
        net["r{}".format(i)].loadConf("ospfd", "{}/r{}/ospfd.conf".format(thisDir, i))
        if net["r1"].checkRouterVersion("<", "4.0"):
            net["r{}".format(i)].loadConf(
                "ospf6d", "{}/r{}/ospf6d.conf-pre-v4".format(thisDir, i)
            )
        else:
            net["r{}".format(i)].loadConf(
                "ospf6d", "{}/r{}/ospf6d.conf".format(thisDir, i)
            )
        net["r{}".format(i)].loadConf("isisd", "{}/r{}/isisd.conf".format(thisDir, i))
        net["r{}".format(i)].loadConf("bgpd", "{}/r{}/bgpd.conf".format(thisDir, i))
        if net["r{}".format(i)].daemon_available("ldpd"):
            # Only test LDPd if it's installed and Kernel >= 4.5
            net["r{}".format(i)].loadConf("ldpd", "{}/r{}/ldpd.conf".format(thisDir, i))
        net["r{}".format(i)].loadConf("sharpd")
        net["r{}".format(i)].loadConf("nhrpd", "{}/r{}/nhrpd.conf".format(thisDir, i))
        net["r{}".format(i)].loadConf("babeld", "{}/r{}/babeld.conf".format(thisDir, i))
        net["r{}".format(i)].loadConf("pbrd", "{}/r{}/pbrd.conf".format(thisDir, i))
        tgen.gears["r{}".format(i)].start()

    # For debugging after starting FRR daemons, uncomment the next line
    # tgen.mininet_cli()


def teardown_module(module):
    print("\n\n** {}: Shutdown Topology".format(module.__name__))
    print("******************************************\n")
    tgen = get_topogen()
    tgen.stop_topology()


def test_router_running():
    global fatal_error
    tgen = get_topogen()
    net = tgen.net

    # Skip if previous fatal error condition is raised
    if fatal_error != "":
        pytest.skip(fatal_error)

    print("\n\n** Check if FRR is running on each Router node")
    print("******************************************\n")
    sleep(5)

    # Starting Routers
    for i in range(1, 2):
        fatal_error = net["r{}".format(i)].checkRouterRunning()
        assert fatal_error == "", fatal_error

    # For debugging after starting FRR daemons, uncomment the next line
    # tgen.mininet_cli()


def test_error_messages_vtysh():
    global fatal_error
    net = get_topogen().net

    # Skip if previous fatal error condition is raised
    if fatal_error != "":
        pytest.skip(fatal_error)

    print("\n\n** Check for error messages on VTYSH")
    print("******************************************\n")

    for i in range(1, 2):
        #
        # First checking Standard Output
        #

        # VTYSH output from router
        vtystdout = (
            net["r{}".format(i)].cmd('vtysh -c "show version" 2> /dev/null').rstrip()
        )

        # Fix newlines (make them all the same)
        vtystdout = ("\n".join(vtystdout.splitlines()) + "\n").rstrip()
        # Drop everything starting with "FRRouting X.xx" message
        vtystdout = re.sub(r"FRRouting [0-9]+.*", "", vtystdout, flags=re.DOTALL)

        if vtystdout == "":
            print("r{} StdOut ok".format(i))

        assert (
            vtystdout == ""
        ), "Vtysh StdOut Output check failed for router r{}".format(i)

        #
        # Second checking Standard Error
        #

        # VTYSH StdErr output from router
        vtystderr = (
            net["r{}".format(i)].cmd('vtysh -c "show version" > /dev/null').rstrip()
        )

        # Fix newlines (make them all the same)
        vtystderr = ("\n".join(vtystderr.splitlines()) + "\n").rstrip()
        # # Drop everything starting with "FRRouting X.xx" message
        # vtystderr = re.sub(r"FRRouting [0-9]+.*", "", vtystderr, flags=re.DOTALL)

        if vtystderr == "":
            print("r{} StdErr ok".format(i))

        assert (
            vtystderr == ""
        ), "Vtysh StdErr Output check failed for router r{}".format(i)

    # Make sure that all daemons are running
    for i in range(1, 2):
        fatal_error = net["r{}".format(i)].checkRouterRunning()
        assert fatal_error == "", fatal_error


def test_error_messages_daemons():
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

    print("\n\n** Check for error messages in daemons")
    print("******************************************\n")

    error_logs = ""

    for i in range(1, 2):
        log = net["r{}".format(i)].getStdErr("ripd")
        if log:
            error_logs += "r{} RIPd StdErr Output:\n".format(i)
            error_logs += log
        log = net["r{}".format(i)].getStdErr("ripngd")
        if log:
            error_logs += "r{} RIPngd StdErr Output:\n".format(i)
            error_logs += log
        log = net["r{}".format(i)].getStdErr("ospfd")
        if log:
            error_logs += "r{} OSPFd StdErr Output:\n".format(i)
            error_logs += log
        log = net["r{}".format(i)].getStdErr("ospf6d")
        if log:
            error_logs += "r{} OSPF6d StdErr Output:\n".format(i)
            error_logs += log
        log = net["r{}".format(i)].getStdErr("isisd")
        # ISIS shows debugging enabled status on StdErr
        # Remove these messages
        log = re.sub(r"^IS-IS .* debugging is on.*", "", log).rstrip()
        if log:
            error_logs += "r{} ISISd StdErr Output:\n".format(i)
            error_logs += log
        log = net["r{}".format(i)].getStdErr("bgpd")
        if log:
            error_logs += "r{} BGPd StdErr Output:\n".format(i)
            error_logs += log
        if net["r{}".format(i)].daemon_available("ldpd"):
            log = net["r{}".format(i)].getStdErr("ldpd")
            if log:
                error_logs += "r{} LDPd StdErr Output:\n".format(i)
                error_logs += log

        log = net["r1"].getStdErr("nhrpd")
        # NHRPD shows YANG model not embedded messages
        # Ignore these
        log = re.sub(r".*YANG model.*not embedded.*", "", log).rstrip()
        if log:
            error_logs += "r{} NHRPd StdErr Output:\n".format(i)
            error_logs += log

        log = net["r1"].getStdErr("babeld")
        if log:
            error_logs += "r{} BABELd StdErr Output:\n".format(i)
            error_logs += log

        log = net["r1"].getStdErr("pbrd")
        if log:
            error_logs += "r{} PBRd StdErr Output:\n".format(i)
            error_logs += log

        log = net["r{}".format(i)].getStdErr("zebra")
        if log:
            error_logs += "r{} Zebra StdErr Output:\n".format(i)
            error_logs += log

    if error_logs:
        sys.stderr.write(
            "Failed check for StdErr Output on daemons:\n{}\n".format(error_logs)
        )

    # Ignoring the issue if told to ignore (ie not yet fixed)
    if error_logs != "":
        if os.environ.get("bamboo_TOPOTESTS_ISSUE_349") == "IGNORE":
            sys.stderr.write(
                "Known issue - IGNORING. See https://github.com/FRRouting/frr/issues/349\n"
            )
            pytest.skip(
                "Known issue - IGNORING. See https://github.com/FRRouting/frr/issues/349"
            )

    assert error_logs == "", "Daemons report errors to StdErr"


def test_converge_protocols():
    global fatal_error
    net = get_topogen().net

    # Skip if previous fatal error condition is raised
    if fatal_error != "":
        pytest.skip(fatal_error)

    thisDir = os.path.dirname(os.path.realpath(__file__))

    # We need loopback to have a link local so it always is the
    # "selected" router for fe80::/64 when we static compare below.
    print("Adding link-local to loopback for stable results")
    cmd = (
        "mac=`cat /sys/class/net/lo/address`; echo lo: $mac;"
        " [ -z \"$mac\" ] && continue; IFS=':'; set $mac; unset IFS;"
        " ip address add dev lo scope link"
        " fe80::$(printf %02x $((0x$1 ^ 2)))$2:${3}ff:fe$4:$5$6/64"
    )
    net["r1"].cmd_raises(cmd)

    print("\n\n** Waiting for protocols convergence")
    print("******************************************\n")

    # Not really implemented yet - just sleep 60 secs for now
    sleep(5)

    # Make sure that all daemons are running
    failures = 0
    for i in range(1, 2):
        fatal_error = net["r{}".format(i)].checkRouterRunning()
        assert fatal_error == "", fatal_error

        print("Show that v4 routes are right\n")
        v4_routesFile = "{}/r{}/ipv4_routes.ref".format(thisDir, i)
        expected = (
            net["r{}".format(i)]
            .cmd("sort {} 2> /dev/null".format(v4_routesFile))
            .rstrip()
        )
        expected = ("\n".join(expected.splitlines()) + "\n").splitlines(1)

        actual = (
            net["r{}".format(i)]
            .cmd(
                "vtysh -c \"show ip route\" | sed -e '/^Codes: /,/^\\s*$/d' | sort 2> /dev/null"
            )
            .rstrip()
        )
        # Drop time in last update
        actual = re.sub(r" [0-2][0-9]:[0-5][0-9]:[0-5][0-9]", " XX:XX:XX", actual)
        actual = ("\n".join(actual.splitlines()) + "\n").splitlines(1)
        diff = topotest.get_textdiff(
            actual,
            expected,
            title1="Actual IP Routing Table",
            title2="Expected IP RoutingTable",
        )
        if diff:
            sys.stderr.write("r{} failed IP Routing table check:\n{}\n".format(i, diff))
            failures += 1
        else:
            print("r{} ok".format(i))

        assert failures == 0, "IP Routing table failed for r{}\n{}".format(i, diff)

        failures = 0

        print("Show that v6 routes are right\n")
        v6_routesFile = "{}/r{}/ipv6_routes.ref".format(thisDir, i)
        expected = (
            net["r{}".format(i)]
            .cmd("sort {} 2> /dev/null".format(v6_routesFile))
            .rstrip()
        )
        expected = ("\n".join(expected.splitlines()) + "\n").splitlines(1)

        actual = (
            net["r{}".format(i)]
            .cmd(
                "vtysh -c \"show ipv6 route\" | sed -e '/^Codes: /,/^\\s*$/d' | sort 2> /dev/null"
            )
            .rstrip()
        )
        # Drop time in last update
        actual = re.sub(r" [0-2][0-9]:[0-5][0-9]:[0-5][0-9]", " XX:XX:XX", actual)
        actual = ("\n".join(actual.splitlines()) + "\n").splitlines(1)
        diff = topotest.get_textdiff(
            actual,
            expected,
            title1="Actual IPv6 Routing Table",
            title2="Expected IPv6 RoutingTable",
        )
        if diff:
            sys.stderr.write(
                "r{} failed IPv6 Routing table check:\n{}\n".format(i, diff)
            )
            failures += 1
        else:
            print("r{} ok".format(i))

        assert failures == 0, "IPv6 Routing table failed for r{}\n{}".format(i, diff)


def route_get_nhg_id(route_str):
    global fatal_error

    def get_func(route_str):
        net = get_topogen().net
        output = net["r1"].cmd(
            'vtysh -c "show ip route {} nexthop-group"'.format(route_str)
        )
        match = re.search(r"Nexthop Group ID: (\d+)", output)
        if match is not None:
            nhg_id = int(match.group(1))
            return nhg_id
        else:
            return None

    test_func = functools.partial(get_func, route_str)
    _, nhg_id = topotest.run_and_expect_type(test_func, int, count=30, wait=1)
    if nhg_id == None:
        fatal_error = "Nexthop Group ID not found for route {}".format(route_str)
        assert nhg_id != None, fatal_error
    else:
        return nhg_id


def verify_nexthop_group(nhg_id, recursive=False, ecmp=0):
    net = get_topogen().net
    count = 0
    valid = None
    ecmpcount = None
    depends = None
    resolved_id = None
    installed = None
    found = False

    while not found and count < 10:
        count += 1
        # Verify NHG is valid/installed
        output = net["r1"].cmd('vtysh -c "show nexthop-group rib {}"'.format(nhg_id))
        valid = re.search(r"Valid", output)
        if valid is None:
            found = False
            sleep(1)
            continue

        if ecmp or recursive:
            ecmpcount = re.search(r"Depends:.*\n", output)
            if ecmpcount is None:
                found = False
                sleep(1)
                continue

            # list of IDs in group
            depends = re.findall(r"\((\d+)\)", ecmpcount.group(0))

            if ecmp:
                if len(depends) != ecmp:
                    found = False
                    sleep(1)
                    continue
            else:
                # If recursive, we need to look at its resolved group
                if len(depends) != 1:
                    found = False
                    sleep(1)
                    continue

                resolved_id = int(depends[0])
                verify_nexthop_group(resolved_id, False)
        else:
            installed = re.search(r"Installed", output)
            if installed is None:
                found = False
                sleep(1)
                continue
        found = True

    assert valid is not None, "Nexthop Group ID={} not marked Valid".format(nhg_id)
    if ecmp or recursive:
        assert ecmpcount is not None, "Nexthop Group ID={} has no depends".format(
            nhg_id
        )
        if ecmp:
            assert (
                len(depends) == ecmp
            ), "Nexthop Group ID={} doesn't match ecmp size".format(nhg_id)
        else:
            assert (
                len(depends) == 1
            ), "Nexthop Group ID={} should only have one recursive depend".format(
                nhg_id
            )
    else:
        assert installed is not None, "Nexthop Group ID={} not marked Installed".format(
            nhg_id
        )


def verify_route_nexthop_group(route_str, recursive=False, ecmp=0):
    global fatal_error

    # Verify route and that zebra created NHGs for and they are valid/installed

    nhg_id = route_get_nhg_id(route_str)

    verify_nexthop_group(nhg_id, recursive, ecmp)


def test_nexthop_groups():
    global fatal_error
    net = get_topogen().net

    # Skip if previous fatal error condition is raised
    if fatal_error != "":
        pytest.skip(fatal_error)

    print("\n\n** Verifying Nexthop Groups")
    print("******************************************\n")

    ### Nexthop Group Tests

    ## Basic test

    # Create a lib nexthop-group
    net["r1"].cmd(
        'vtysh -c "c t" -c "nexthop-group basic" -c "nexthop 1.1.1.1" -c "nexthop 1.1.1.2"'
    )

    # Create with sharpd using nexthop-group
    net["r1"].cmd('vtysh -c "sharp install routes 2.2.2.1 nexthop-group basic 1"')
    verify_route_nexthop_group("2.2.2.1/32")

    ## Connected

    net["r1"].cmd(
        'vtysh -c "c t" -c "nexthop-group connected" -c "nexthop r1-eth1" -c "nexthop r1-eth2"'
    )

    net["r1"].cmd('vtysh -c "sharp install routes 2.2.2.2 nexthop-group connected 1"')
    verify_route_nexthop_group("2.2.2.2/32")

    ## Recursive

    net["r1"].cmd(
        'vtysh -c "c t" -c "nexthop-group basic-recursive" -c "nexthop 2.2.2.1"'
    )

    net["r1"].cmd(
        'vtysh -c "sharp install routes 3.3.3.1 nexthop-group basic-recursive 1"'
    )

    verify_route_nexthop_group("3.3.3.1/32", True)

    ## Duplicate

    net["r1"].cmd(
        'vtysh -c "c t" -c "nexthop-group duplicate" -c "nexthop 2.2.2.1" -c "nexthop 1.1.1.1"'
    )

    net["r1"].cmd('vtysh -c "sharp install routes 3.3.3.2 nexthop-group duplicate 1"')

    verify_route_nexthop_group("3.3.3.2/32")

    ## Two 4-Way ECMP

    net["r1"].cmd(
        'vtysh -c "c t" -c "nexthop-group fourA" -c "nexthop 1.1.1.1" -c "nexthop 1.1.1.2" \
            -c "nexthop 1.1.1.3" -c "nexthop 1.1.1.4"'
    )

    net["r1"].cmd('vtysh -c "sharp install routes 4.4.4.1 nexthop-group fourA 1"')

    verify_route_nexthop_group("4.4.4.1/32")

    net["r1"].cmd(
        'vtysh -c "c t" -c "nexthop-group fourB" -c "nexthop 1.1.1.5" -c "nexthop 1.1.1.6" \
            -c "nexthop 1.1.1.7" -c "nexthop 1.1.1.8"'
    )

    net["r1"].cmd('vtysh -c "sharp install routes 4.4.4.2 nexthop-group fourB 1"')

    verify_route_nexthop_group("4.4.4.2/32")

    ## Recursive to 8-Way ECMP

    net["r1"].cmd(
        'vtysh -c "c t" -c "nexthop-group eight-recursive" -c "nexthop 4.4.4.1" -c "nexthop 4.4.4.2"'
    )

    net["r1"].cmd(
        'vtysh -c "sharp install routes 5.5.5.1 nexthop-group eight-recursive 1"'
    )

    verify_route_nexthop_group("5.5.5.1/32")

    ## 4-way ECMP Routes Pointing to Each Other

    # This is to check for a bug with NH resolution where
    # routes would infintely resolve to each other blowing
    # up the resolved-> nexthop pointer.

    net["r1"].cmd(
        'vtysh -c "c t" -c "nexthop-group infinite-recursive" -c "nexthop 6.6.6.1" -c "nexthop 6.6.6.2" \
            -c "nexthop 6.6.6.3" -c "nexthop 6.6.6.4"'
    )

    # static route nexthops can recurse to

    net["r1"].cmd('vtysh -c "c t" -c "ip route 6.6.6.0/24 1.1.1.1"')

    # Make routes that point to themselves in ecmp

    net["r1"].cmd(
        'vtysh -c "sharp install routes 6.6.6.4 nexthop-group infinite-recursive 1"'
    )
    sleep(5)

    net["r1"].cmd(
        'vtysh -c "sharp install routes 6.6.6.3 nexthop-group infinite-recursive 1"'
    )
    sleep(5)

    net["r1"].cmd(
        'vtysh -c "sharp install routes 6.6.6.2 nexthop-group infinite-recursive 1"'
    )
    sleep(5)

    net["r1"].cmd(
        'vtysh -c "sharp install routes 6.6.6.1 nexthop-group infinite-recursive 1"'
    )

    # Get routes and test if has too many (duplicate) nexthops
    count = 0
    dups = []
    nhg_id = route_get_nhg_id("6.6.6.1/32")
    while (len(dups) != 4) and count < 10:
        output = net["r1"].cmd('vtysh -c "show nexthop-group rib {}"'.format(nhg_id))

        dups = re.findall(r"(via 1\.1\.1\.1)", output)
        if len(dups) != 4:
            count += 1
            sleep(1)

    # Should find 3, itself is inactive
    assert (
        len(dups) == 4
    ), "Route 6.6.6.1/32 with Nexthop Group ID={} has wrong number of resolved nexthops".format(
        nhg_id
    )

    ## Remove all NHG routes

    net["r1"].cmd('vtysh -c "sharp remove routes 2.2.2.1 1"')
    net["r1"].cmd('vtysh -c "sharp remove routes 2.2.2.2 1"')
    net["r1"].cmd('vtysh -c "sharp remove routes 3.3.3.1 1"')
    net["r1"].cmd('vtysh -c "sharp remove routes 3.3.3.2 1"')
    net["r1"].cmd('vtysh -c "sharp remove routes 4.4.4.1 1"')
    net["r1"].cmd('vtysh -c "sharp remove routes 4.4.4.2 1"')
    net["r1"].cmd('vtysh -c "sharp remove routes 5.5.5.1 1"')
    net["r1"].cmd('vtysh -c "sharp remove routes 6.6.6.1 4"')
    net["r1"].cmd('vtysh -c "c t" -c "no ip route 6.6.6.0/24 1.1.1.1"')


def test_rip_status():
    global fatal_error
    net = get_topogen().net

    # Skip if previous fatal error condition is raised
    if fatal_error != "":
        pytest.skip(fatal_error)

    thisDir = os.path.dirname(os.path.realpath(__file__))

    print("\n\n** Verifying RIP status")
    print("******************************************\n")
    failures = 0
    for i in range(1, 2):
        refTableFile = "{}/r{}/rip_status.ref".format(thisDir, i)
        if os.path.isfile(refTableFile):
            # Read expected result from file
            expected = open(refTableFile).read().rstrip()
            # Fix newlines (make them all the same)
            expected = ("\n".join(expected.splitlines()) + "\n").splitlines(1)

            # Actual output from router
            actual = (
                net["r{}".format(i)]
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
                sys.stderr.write(
                    "r{} failed IP RIP status check:\n{}\n".format(i, diff)
                )
                failures += 1
            else:
                print("r{} ok".format(i))

            assert failures == 0, "IP RIP status failed for router r{}:\n{}".format(
                i, diff
            )

    # Make sure that all daemons are running
    for i in range(1, 2):
        fatal_error = net["r{}".format(i)].checkRouterRunning()
        assert fatal_error == "", fatal_error


def test_ripng_status():
    global fatal_error
    net = get_topogen().net

    # Skip if previous fatal error condition is raised
    if fatal_error != "":
        pytest.skip(fatal_error)

    thisDir = os.path.dirname(os.path.realpath(__file__))

    print("\n\n** Verifying RIPng status")
    print("******************************************\n")
    failures = 0
    for i in range(1, 2):
        refTableFile = "{}/r{}/ripng_status.ref".format(thisDir, i)
        if os.path.isfile(refTableFile):
            # Read expected result from file
            expected = open(refTableFile).read().rstrip()
            # Fix newlines (make them all the same)
            expected = ("\n".join(expected.splitlines()) + "\n").splitlines(1)

            # Actual output from router
            actual = (
                net["r{}".format(i)]
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
                    "r{} failed IPv6 RIPng status check:\n{}\n".format(i, diff)
                )
                failures += 1
            else:
                print("r{} ok".format(i))

            assert failures == 0, "IPv6 RIPng status failed for router r{}:\n{}".format(
                i, diff
            )

    # Make sure that all daemons are running
    for i in range(1, 2):
        fatal_error = net["r{}".format(i)].checkRouterRunning()
        assert fatal_error == "", fatal_error


def test_ospfv2_interfaces():
    global fatal_error
    net = get_topogen().net

    # Skip if previous fatal error condition is raised
    if fatal_error != "":
        pytest.skip(fatal_error)

    thisDir = os.path.dirname(os.path.realpath(__file__))

    print("\n\n** Verifying OSPFv2 interfaces")
    print("******************************************\n")
    failures = 0
    for i in range(1, 2):
        refTableFile = "{}/r{}/show_ip_ospf_interface.ref".format(thisDir, i)
        if os.path.isfile(refTableFile):
            # Read expected result from file
            expected = open(refTableFile).read().rstrip()
            # Fix newlines (make them all the same)
            expected = ("\n".join(expected.splitlines()) + "\n").splitlines(1)

            # Actual output from router
            actual = (
                net["r{}".format(i)]
                .cmd('vtysh -c "show ip ospf interface" 2> /dev/null')
                .rstrip()
            )
            # Mask out Bandwidth portion. They may change..
            actual = re.sub(r"BW [0-9]+ Mbit", "BW XX Mbit", actual)
            actual = re.sub(r"ifindex [0-9]+", "ifindex X", actual)

            # Drop time in next due
            actual = re.sub(r"Hello due in [0-9\.]+s", "Hello due in XX.XXXs", actual)
            actual = re.sub(
                r"Hello due in [0-9\.]+ usecs", "Hello due in XX.XXXs", actual
            )
            # Fix 'MTU mismatch detection: enabled' vs 'MTU mismatch detection:enabled' - accept both
            actual = re.sub(
                r"MTU mismatch detection:([a-z]+.*)",
                r"MTU mismatch detection: \1",
                actual,
            )
            # Fix newlines (make them all the same)
            actual = ("\n".join(actual.splitlines()) + "\n").splitlines(1)

            # Generate Diff
            diff = topotest.get_textdiff(
                actual,
                expected,
                title1="actual SHOW IP OSPF INTERFACE",
                title2="expected SHOW IP OSPF INTERFACE",
            )

            # Empty string if it matches, otherwise diff contains unified diff
            if diff:
                sys.stderr.write(
                    "r{} failed SHOW IP OSPF INTERFACE check:\n{}\n".format(i, diff)
                )
                failures += 1
            else:
                print("r{} ok".format(i))

            # Ignoring the issue if told to ignore (ie not yet fixed)
            if failures != 0:
                if os.environ.get("bamboo_TOPOTESTS_ISSUE_348") == "IGNORE":
                    sys.stderr.write(
                        "Known issue - IGNORING. See https://github.com/FRRouting/frr/issues/348\n"
                    )
                    pytest.skip(
                        "Known issue - IGNORING. See https://github.com/FRRouting/frr/issues/348"
                    )

            assert (
                failures == 0
            ), "SHOW IP OSPF INTERFACE failed for router r{}:\n{}".format(i, diff)

    # Make sure that all daemons are running
    for i in range(1, 2):
        fatal_error = net["r{}".format(i)].checkRouterRunning()
        assert fatal_error == "", fatal_error


def test_isis_interfaces():
    global fatal_error
    net = get_topogen().net

    # Skip if previous fatal error condition is raised
    if fatal_error != "":
        pytest.skip(fatal_error)

    thisDir = os.path.dirname(os.path.realpath(__file__))

    print("\n\n** Verifying ISIS interfaces")
    print("******************************************\n")
    failures = 0
    for i in range(1, 2):
        refTableFile = "{}/r{}/show_isis_interface_detail.ref".format(thisDir, i)
        if os.path.isfile(refTableFile):
            # Read expected result from file
            expected = open(refTableFile).read().rstrip()
            # Fix newlines (make them all the same)
            expected = ("\n".join(expected.splitlines()) + "\n").splitlines(1)

            # Actual output from router
            actual = (
                net["r{}".format(i)]
                .cmd('vtysh -c "show isis interface detail" 2> /dev/null')
                .rstrip()
            )
            # Mask out Link-Local mac address portion. They are random...
            actual = re.sub(r"fe80::[0-9a-f:]+", "fe80::XXXX:XXXX:XXXX:XXXX", actual)
            # Mask out SNPA mac address portion. They are random...
            actual = re.sub(r"SNPA: [0-9a-f\.]+", "SNPA: XXXX.XXXX.XXXX", actual)
            # Mask out Circuit ID number
            actual = re.sub(r"Circuit Id: 0x[0-9a-f]+", "Circuit Id: 0xXX", actual)
            # Fix newlines (make them all the same)
            actual = ("\n".join(actual.splitlines()) + "\n").splitlines(1)

            # Generate Diff
            diff = topotest.get_textdiff(
                actual,
                expected,
                title1="actual SHOW ISIS INTERFACE DETAIL",
                title2="expected SHOW ISIS OSPF6 INTERFACE DETAIL",
            )

            # Empty string if it matches, otherwise diff contains unified diff
            if diff:
                sys.stderr.write(
                    "r{} failed SHOW ISIS INTERFACE DETAIL check:\n{}\n".format(i, diff)
                )
                failures += 1
            else:
                print("r{} ok".format(i))

            assert (
                failures == 0
            ), "SHOW ISIS INTERFACE DETAIL failed for router r{}:\n{}".format(i, diff)

    # Make sure that all daemons are running
    for i in range(1, 2):
        fatal_error = net["r{}".format(i)].checkRouterRunning()
        assert fatal_error == "", fatal_error


def test_bgp_summary():
    global fatal_error
    net = get_topogen().net

    # Skip if previous fatal error condition is raised
    if fatal_error != "":
        pytest.skip(fatal_error)

    thisDir = os.path.dirname(os.path.realpath(__file__))

    print("\n\n** Verifying BGP Summary")
    print("******************************************\n")
    failures = 0
    for i in range(1, 2):
        refTableFile = "{}/r{}/show_ip_bgp_summary.ref".format(thisDir, i)
        if os.path.isfile(refTableFile):
            # Read expected result from file
            expected_original = open(refTableFile).read().rstrip()

            for arguments in [
                "",
                "remote-as internal",
                "remote-as external",
                "remote-as 100",
                "remote-as 123",
                "neighbor 192.168.7.10",
                "neighbor 192.168.7.10",
                "neighbor fc00:0:0:8::1000",
                "neighbor 10.0.0.1",
                "terse",
                "remote-as internal terse",
                "remote-as external terse",
                "remote-as 100 terse",
                "remote-as 123 terse",
                "neighbor 192.168.7.10 terse",
                "neighbor 192.168.7.10 terse",
                "neighbor fc00:0:0:8::1000 terse",
                "neighbor 10.0.0.1 terse",
            ]:
                # Actual output from router
                actual = (
                    net["r{}".format(i)]
                    .cmd(
                        'vtysh -c "show ip bgp summary ' + arguments + '" 2> /dev/null'
                    )
                    .rstrip()
                )

                # Mask out "using XXiXX bytes" portion. They are random...
                actual = re.sub(r"using [0-9]+ bytes", "using XXXX bytes", actual)
                # Mask out "using XiXXX KiB" portion. They are random...
                actual = re.sub(r"using [0-9]+ KiB", "using XXXX KiB", actual)

                # Remove extra summaries which exist with newer versions

                # Remove summary lines (changed recently)
                actual = re.sub(r"Total number.*", "", actual)
                actual = re.sub(r"Displayed.*", "", actual)
                # Remove IPv4 Unicast Summary (Title only)
                actual = re.sub(r"IPv4 Unicast Summary:", "", actual)
                # Remove IPv4 Multicast Summary (all of it)
                actual = re.sub(r"IPv4 Multicast Summary:", "", actual)
                actual = re.sub(r"No IPv4 Multicast neighbor is configured", "", actual)
                # Remove IPv4 VPN Summary (all of it)
                actual = re.sub(r"IPv4 VPN Summary:", "", actual)
                actual = re.sub(r"No IPv4 VPN neighbor is configured", "", actual)
                # Remove IPv4 Encap Summary (all of it)
                actual = re.sub(r"IPv4 Encap Summary:", "", actual)
                actual = re.sub(r"No IPv4 Encap neighbor is configured", "", actual)
                # Remove Unknown Summary (all of it)
                actual = re.sub(r"Unknown Summary:", "", actual)
                actual = re.sub(r"No Unknown neighbor is configured", "", actual)
                # Make Connect/Active/Idle the same (change them all to Active)
                actual = re.sub(r" Connect ", "  Active ", actual)
                actual = re.sub(r"    Idle ", "  Active ", actual)

                actual = re.sub(r"IPv4 labeled-unicast Summary:", "", actual)
                actual = re.sub(
                    r"No IPv4 labeled-unicast neighbor is configured", "", actual
                )

                expected = expected_original
                # apply argumentss on expected output
                if "internal" in arguments or "remote-as 100" in arguments:
                    expected = re.sub(r".+\s+200\s+.+", "", expected)
                elif "external" in arguments:
                    expected = re.sub(r".+\s+100\s+.+Active.+", "", expected)
                elif "remote-as 123" in arguments:
                    expected = re.sub(
                        r"(192.168.7.(1|2)0|fc00:0:0:8::(1|2)000).+Active.+",
                        "",
                        expected,
                    )
                    expected = re.sub(r"\nNeighbor.+Desc", "", expected)
                    expected = expected + "% No matching neighbor\n"
                elif "192.168.7.10" in arguments:
                    expected = re.sub(
                        r"(192.168.7.20|fc00:0:0:8::(1|2)000).+Active.+", "", expected
                    )
                elif "fc00:0:0:8::1000" in arguments:
                    expected = re.sub(
                        r"(192.168.7.(1|2)0|fc00:0:0:8::2000).+Active.+", "", expected
                    )
                elif "10.0.0.1" in arguments:
                    expected = "No such neighbor in this view/vrf"

                if "terse" in arguments:
                    expected = re.sub(r"BGP table version .+", "", expected)
                    expected = re.sub(r"RIB entries .+", "", expected)
                    expected = re.sub(r"Peers [0-9]+, using .+", "", expected)

                # Strip empty lines
                actual = actual.lstrip().rstrip()
                expected = expected.lstrip().rstrip()
                actual = re.sub(r"\n+", "\n", actual)
                expected = re.sub(r"\n+", "\n", expected)

                # reapply initial formatting
                if "terse" in arguments:
                    actual = re.sub(r" vrf-id 0\n", " vrf-id 0\n\n", actual)
                    expected = re.sub(r" vrf-id 0\n", " vrf-id 0\n\n", expected)
                else:
                    actual = re.sub(r"KiB of memory\n", "KiB of memory\n\n", actual)
                    expected = re.sub(r"KiB of memory\n", "KiB of memory\n\n", expected)

                # realign expected neighbor columns if needed
                try:
                    idx_actual = (
                        re.search(r"(Neighbor\s+V\s+)", actual).group(1).find("V")
                    )
                    idx_expected = (
                        re.search(r"(Neighbor\s+V\s+)", expected).group(1).find("V")
                    )
                    idx_diff = idx_expected - idx_actual
                    if idx_diff > 0:
                        # Neighbor        V         AS MsgRcvd MsgSent   TblVer  InQ OutQ  Up/Down State/PfxRcd
                        expected = re.sub(" " * idx_diff + "V ", "V ", expected)
                        # 192.168.7.10    4        100       0       0        0    0    0    never       Active
                        expected = re.sub(" " * idx_diff + "4 ", "4 ", expected)
                except AttributeError:
                    pass

                # Fix newlines (make them all the same)
                actual = ("\n".join(actual.splitlines()) + "\n").splitlines(1)
                expected = ("\n".join(expected.splitlines()) + "\n").splitlines(1)

                # Generate Diff
                diff = topotest.get_textdiff(
                    actual,
                    expected,
                    title1="actual SHOW IP BGP SUMMARY " + arguments.upper(),
                    title2="expected SHOW IP BGP SUMMARY " + arguments.upper(),
                )

                # Empty string if it matches, otherwise diff contains unified diff
                if diff:
                    sys.stderr.write(
                        "r{} failed SHOW IP BGP SUMMARY check:\n{}\n".format(i, diff)
                    )
                    failures += 1
                else:
                    print("r{} ok".format(i))

                assert (
                    failures == 0
                ), "SHOW IP BGP SUMMARY failed for router r{}:\n{}".format(i, diff)

    # Make sure that all daemons are running
    for i in range(1, 2):
        fatal_error = net["r{}".format(i)].checkRouterRunning()
        assert fatal_error == "", fatal_error


def test_bgp_ipv6_summary():
    global fatal_error
    net = get_topogen().net

    # Skip if previous fatal error condition is raised
    if fatal_error != "":
        pytest.skip(fatal_error)

    thisDir = os.path.dirname(os.path.realpath(__file__))

    print("\n\n** Verifying BGP IPv6 Summary")
    print("******************************************\n")
    failures = 0
    for i in range(1, 2):
        refTableFile = "{}/r{}/show_bgp_ipv6_summary.ref".format(thisDir, i)
        if os.path.isfile(refTableFile):
            # Read expected result from file
            expected = open(refTableFile).read().rstrip()
            # Fix newlines (make them all the same)
            expected = ("\n".join(expected.splitlines()) + "\n").splitlines(1)

            # Actual output from router
            actual = (
                net["r{}".format(i)]
                .cmd('vtysh -c "show bgp ipv6 summary" 2> /dev/null')
                .rstrip()
            )
            # Mask out "using XXiXX bytes" portion. They are random...
            actual = re.sub(r"using [0-9]+ bytes", "using XXXX bytes", actual)
            # Mask out "using XiXXX KiB" portion. They are random...
            actual = re.sub(r"using [0-9]+ KiB", "using XXXX KiB", actual)
            #
            # Remove extra summaries which exist with newer versions
            #
            # Remove summary lines (changed recently)
            actual = re.sub(r"Total number.*", "", actual)
            actual = re.sub(r"Displayed.*", "", actual)
            # Remove IPv4 Unicast Summary (Title only)
            actual = re.sub(r"IPv6 Unicast Summary:", "", actual)
            # Remove IPv4 Multicast Summary (all of it)
            actual = re.sub(r"IPv6 Multicast Summary:", "", actual)
            actual = re.sub(r"No IPv6 Multicast neighbor is configured", "", actual)
            # Remove IPv4 VPN Summary (all of it)
            actual = re.sub(r"IPv6 VPN Summary:", "", actual)
            actual = re.sub(r"No IPv6 VPN neighbor is configured", "", actual)
            # Remove IPv4 Encap Summary (all of it)
            actual = re.sub(r"IPv6 Encap Summary:", "", actual)
            actual = re.sub(r"No IPv6 Encap neighbor is configured", "", actual)
            # Remove Unknown Summary (all of it)
            actual = re.sub(r"Unknown Summary:", "", actual)
            actual = re.sub(r"No Unknown neighbor is configured", "", actual)
            # Make Connect/Active/Idle the same (change them all to Active)
            actual = re.sub(r" Connect ", "  Active ", actual)
            actual = re.sub(r"    Idle ", "  Active ", actual)

            # Remove Labeled Unicast Summary (all of it)
            actual = re.sub(r"IPv6 labeled-unicast Summary:", "", actual)
            actual = re.sub(
                r"No IPv6 labeled-unicast neighbor is configured", "", actual
            )

            # Strip empty lines
            actual = actual.lstrip()
            actual = actual.rstrip()
            #
            # Fix newlines (make them all the same)
            actual = ("\n".join(actual.splitlines()) + "\n").splitlines(1)

            # Generate Diff
            diff = topotest.get_textdiff(
                actual,
                expected,
                title1="actual SHOW BGP IPv6 SUMMARY",
                title2="expected SHOW BGP IPv6 SUMMARY",
            )

            # Empty string if it matches, otherwise diff contains unified diff
            if diff:
                sys.stderr.write(
                    "r{} failed SHOW BGP IPv6 SUMMARY check:\n{}\n".format(i, diff)
                )
                failures += 1
            else:
                print("r{} ok".format(i))

            assert (
                failures == 0
            ), "SHOW BGP IPv6 SUMMARY failed for router r{}:\n{}".format(i, diff)

    # Make sure that all daemons are running
    for i in range(1, 2):
        fatal_error = net["r{}".format(i)].checkRouterRunning()
        assert fatal_error == "", fatal_error


def test_nht():
    global fatal_error
    net = get_topogen().net

    # Skip if previous fatal error condition is raised
    if fatal_error != "":
        pytest.skip(fatal_error)

    print("\n\n**** Test that nexthop tracking is at least nominally working ****\n")

    thisDir = os.path.dirname(os.path.realpath(__file__))

    for i in range(1, 2):
        nhtFile = "{}/r{}/ip_nht.ref".format(thisDir, i)
        expected = open(nhtFile).read().rstrip()
        expected = ("\n".join(expected.splitlines()) + "\n").splitlines(1)

        actual = (
            net["r{}".format(i)].cmd('vtysh -c "show ip nht" 2> /dev/null').rstrip()
        )
        actual = re.sub(r"fd [0-9]+", "fd XX", actual)
        actual = ("\n".join(actual.splitlines()) + "\n").splitlines(1)

        diff = topotest.get_textdiff(
            actual,
            expected,
            title1="Actual `show ip nht`",
            title2="Expected `show ip nht`",
        )

        if diff:
            assert 0, "r{} failed ip nht check:\n{}\n".format(i, diff)
        else:
            print("show ip nht is ok\n")

        nhtFile = "{}/r{}/ipv6_nht.ref".format(thisDir, i)
        expected = open(nhtFile).read().rstrip()
        expected = ("\n".join(expected.splitlines()) + "\n").splitlines(1)

        actual = (
            net["r{}".format(i)].cmd('vtysh -c "show ipv6 nht" 2> /dev/null').rstrip()
        )
        actual = re.sub(r"fd [0-9]+", "fd XX", actual)
        actual = ("\n".join(actual.splitlines()) + "\n").splitlines(1)

        diff = topotest.get_textdiff(
            actual,
            expected,
            title1="Actual `show ip nht`",
            title2="Expected `show ip nht`",
        )

        if diff:
            assert 0, "r{} failed ipv6 nht check:\n{}\n".format(i, diff)
        else:
            print("show ipv6 nht is ok\n")


def test_bgp_ipv4():
    global fatal_error
    net = get_topogen().net

    # Skip if previous fatal error condition is raised
    if fatal_error != "":
        pytest.skip(fatal_error)

    thisDir = os.path.dirname(os.path.realpath(__file__))

    print("\n\n** Verifying BGP IPv4")
    print("******************************************\n")
    diffresult = {}
    for i in range(1, 2):
        success = 0
        for refTableFile in glob.glob("{}/r{}/show_bgp_ipv4*.ref".format(thisDir, i)):
            if os.path.isfile(refTableFile):
                # Read expected result from file
                expected = open(refTableFile).read().rstrip()
                # Fix newlines (make them all the same)
                expected = ("\n".join(expected.splitlines()) + "\n").splitlines(1)

                # Actual output from router
                actual = (
                    net["r{}".format(i)]
                    .cmd('vtysh -c "show bgp ipv4" 2> /dev/null')
                    .rstrip()
                )
                # Remove summary line (changed recently)
                actual = re.sub(r"Total number.*", "", actual)
                actual = re.sub(r"Displayed.*", "", actual)
                actual = actual.rstrip()
                # Fix newlines (make them all the same)
                actual = ("\n".join(actual.splitlines()) + "\n").splitlines(1)

                # Generate Diff
                diff = topotest.get_textdiff(
                    actual,
                    expected,
                    title1="actual SHOW BGP IPv4",
                    title2="expected SHOW BGP IPv4",
                )

                # Empty string if it matches, otherwise diff contains unified diff
                if diff:
                    diffresult[refTableFile] = diff
                else:
                    success = 1
                    print("template {} matched: r{} ok".format(refTableFile, i))
                    break

        if not success:
            resultstr = "No template matched.\n"
            for f in diffresult.keys():
                resultstr += (
                    "template {}: r{} failed SHOW BGP IPv4 check:\n{}\n".format(
                        f,
                        i,
                        diffresult[f],
                    )
                )
            raise AssertionError(
                "SHOW BGP IPv4 failed for router r{}:\n{}".format(i, resultstr)
            )

    # Make sure that all daemons are running
    for i in range(1, 2):
        fatal_error = net["r{}".format(i)].checkRouterRunning()
        assert fatal_error == "", fatal_error


def test_bgp_ipv6():
    global fatal_error
    net = get_topogen().net

    # Skip if previous fatal error condition is raised
    if fatal_error != "":
        pytest.skip(fatal_error)

    thisDir = os.path.dirname(os.path.realpath(__file__))

    print("\n\n** Verifying BGP IPv6")
    print("******************************************\n")
    diffresult = {}
    for i in range(1, 2):
        success = 0
        for refTableFile in glob.glob("{}/r{}/show_bgp_ipv6*.ref".format(thisDir, i)):
            if os.path.isfile(refTableFile):
                # Read expected result from file
                expected = open(refTableFile).read().rstrip()
                # Fix newlines (make them all the same)
                expected = ("\n".join(expected.splitlines()) + "\n").splitlines(1)

                # Actual output from router
                actual = (
                    net["r{}".format(i)]
                    .cmd('vtysh -c "show bgp ipv6" 2> /dev/null')
                    .rstrip()
                )
                # Remove summary line (changed recently)
                actual = re.sub(r"Total number.*", "", actual)
                actual = re.sub(r"Displayed.*", "", actual)
                actual = actual.rstrip()
                # Fix newlines (make them all the same)
                actual = ("\n".join(actual.splitlines()) + "\n").splitlines(1)

                # Generate Diff
                diff = topotest.get_textdiff(
                    actual,
                    expected,
                    title1="actual SHOW BGP IPv6",
                    title2="expected SHOW BGP IPv6",
                )

                # Empty string if it matches, otherwise diff contains unified diff
                if diff:
                    diffresult[refTableFile] = diff
                else:
                    success = 1
                    print("template {} matched: r{} ok".format(refTableFile, i))

        if not success:
            resultstr = "No template matched.\n"
            for f in diffresult.keys():
                resultstr += (
                    "template {}: r{} failed SHOW BGP IPv6 check:\n{}\n".format(
                        f,
                        i,
                        diffresult[f],
                    )
                )
            raise AssertionError(
                "SHOW BGP IPv6 failed for router r{}:\n{}".format(i, resultstr)
            )

    # Make sure that all daemons are running
    for i in range(1, 2):
        fatal_error = net["r{}".format(i)].checkRouterRunning()
        assert fatal_error == "", fatal_error


def test_route_map():
    global fatal_error
    net = get_topogen().net

    if fatal_error != "":
        pytest.skip(fatal_error)

    thisDir = os.path.dirname(os.path.realpath(__file__))

    print("\n\n** Verifying some basic routemap forward references\n")
    print("*******************************************************\n")
    failures = 0
    for i in range(1, 2):
        refroutemap = "{}/r{}/show_route_map.ref".format(thisDir, i)
        if os.path.isfile(refroutemap):
            expected = open(refroutemap).read().rstrip()
            expected = ("\n".join(expected.splitlines()) + "\n").splitlines(1)

            actual = (
                net["r{}".format(i)]
                .cmd('vtysh -c "show route-map" 2> /dev/null')
                .rstrip()
            )
            actual = ("\n".join(actual.splitlines()) + "\n").splitlines(1)

            diff = topotest.get_textdiff(
                actual,
                expected,
                title1="actual show route-map",
                title2="expected show route-map",
            )

            if diff:
                sys.stderr.write(
                    "r{} failed show route-map command Check:\n{}\n".format(i, diff)
                )
                failures += 1
            else:
                print("r{} ok".format(i))

            assert (
                failures == 0
            ), "Show route-map command failed for router r{}:\n{}".format(i, diff)


def test_nexthop_groups_with_route_maps():
    global fatal_error
    net = get_topogen().net

    # Skip if previous fatal error condition is raised
    if fatal_error != "":
        pytest.skip(fatal_error)

    print("\n\n** Verifying Nexthop Groups With Route-Maps")
    print("******************************************\n")

    ### Nexthop Group With Route-Map Tests

    # Create a lib nexthop-group
    net["r1"].cmd(
        'vtysh -c "c t" -c "nexthop-group test" -c "nexthop 1.1.1.1" -c "nexthop 1.1.1.2"'
    )

    ## Route-Map Proto Source

    route_str = "2.2.2.1"
    src_str = "192.168.0.1"

    net["r1"].cmd(
        'vtysh -c "c t" -c "route-map NH-SRC permit 111" -c "set src {}"'.format(
            src_str
        )
    )
    net["r1"].cmd('vtysh -c "c t" -c "ip protocol sharp route-map NH-SRC"')

    net["r1"].cmd(
        'vtysh -c "sharp install routes {} nexthop-group test 1"'.format(route_str)
    )

    verify_route_nexthop_group("{}/32".format(route_str))

    # Only a valid test on linux using nexthop objects
    if sys.platform.startswith("linux"):
        output = net["r1"].cmd("ip route show {}/32".format(route_str))
        match = re.search(r"src {}".format(src_str), output)
        assert match is not None, "Route {}/32 not installed with src {}".format(
            route_str,
            src_str,
        )

    # Remove NHG routes and route-map
    net["r1"].cmd('vtysh -c "sharp remove routes {} 1"'.format(route_str))
    net["r1"].cmd('vtysh -c "c t" -c "no ip protocol sharp route-map NH-SRC"')
    net["r1"].cmd(
        'vtysh -c "c t" -c "no route-map NH-SRC permit 111" # -c "set src {}"'.format(
            src_str
        )
    )
    net["r1"].cmd('vtysh -c "c t" -c "no route-map NH-SRC"')

    ## Route-Map Deny/Permit with same nexthop group

    permit_route_str = "3.3.3.1"
    deny_route_str = "3.3.3.2"

    net["r1"].cmd(
        'vtysh -c "c t" -c "ip prefix-list NOPE seq 5 permit {}/32"'.format(
            permit_route_str
        )
    )
    net["r1"].cmd(
        'vtysh -c "c t" -c "route-map NOPE permit 111" -c "match ip address prefix-list NOPE"'
    )
    net["r1"].cmd('vtysh -c "c t" -c "route-map NOPE deny 222"')
    net["r1"].cmd('vtysh -c "c t" -c "ip protocol sharp route-map NOPE"')

    # This route should be permitted
    net["r1"].cmd(
        'vtysh -c "sharp install routes {} nexthop-group test 1"'.format(
            permit_route_str
        )
    )

    verify_route_nexthop_group("{}/32".format(permit_route_str))

    # This route should be denied
    net["r1"].cmd(
        'vtysh -c "sharp install routes {} nexthop-group test 1"'.format(deny_route_str)
    )

    nhg_id = route_get_nhg_id(deny_route_str)
    output = net["r1"].cmd('vtysh -c "show nexthop-group rib {}"'.format(nhg_id))

    match = re.search(r"Valid", output)
    assert match is None, "Nexthop Group ID={} should not be marked Valid".format(
        nhg_id
    )

    match = re.search(r"Installed", output)
    assert match is None, "Nexthop Group ID={} should not be marked Installed".format(
        nhg_id
    )

    # Remove NHG routes and route-map
    net["r1"].cmd('vtysh -c "sharp remove routes {} 1"'.format(permit_route_str))
    net["r1"].cmd('vtysh -c "sharp remove routes {} 1"'.format(deny_route_str))
    net["r1"].cmd('vtysh -c "c t" -c "no ip protocol sharp route-map NOPE"')
    net["r1"].cmd('vtysh -c "c t" -c "no route-map NOPE permit 111"')
    net["r1"].cmd('vtysh -c "c t" -c "no route-map NOPE deny 222"')
    net["r1"].cmd('vtysh -c "c t" -c "no route-map NOPE"')
    net["r1"].cmd(
        'vtysh -c "c t" -c "no ip prefix-list NOPE seq 5 permit {}/32"'.format(
            permit_route_str
        )
    )


def test_nexthop_group_replace():
    global fatal_error
    net = get_topogen().net

    # Skip if previous fatal error condition is raised
    if fatal_error != "":
        pytest.skip(fatal_error)

    print("\n\n** Verifying Nexthop Groups")
    print("******************************************\n")

    ### Nexthop Group Tests

    ## 2-Way ECMP Directly Connected

    net["r1"].cmd(
        'vtysh -c "c t" -c "nexthop-group replace" -c "nexthop 1.1.1.1 r1-eth1 onlink" -c "nexthop 1.1.1.2 r1-eth2 onlink"'
    )

    # At the moment there is absolutely no real easy way to query sharpd
    # for the nexthop group actually installed.  If it is not installed
    # sharpd will just transmit the nexthops down instead of the nexthop
    # group id.  Leading to a situation where the replace is not actually
    # being tested.  So let's just wait some time here because this
    # is hard and this test fails all the time
    sleep(5)

    # Create with sharpd using nexthop-group
    net["r1"].cmd('vtysh -c "sharp install routes 3.3.3.1 nexthop-group replace 1"')

    verify_route_nexthop_group("3.3.3.1/32")

    # Change the nexthop group
    net["r1"].cmd(
        'vtysh -c "c t" -c "nexthop-group replace" -c "no nexthop 1.1.1.1 r1-eth1 onlink" -c "nexthop 1.1.1.3 r1-eth1 onlink" -c "nexthop 1.1.1.4 r1-eth4 onlink"'
    )

    # Verify it updated. We can just check install and ecmp count here.
    verify_route_nexthop_group("3.3.3.1/32", False, 3)


def test_mpls_interfaces():
    global fatal_error
    net = get_topogen().net

    # Skip if previous fatal error condition is raised
    if fatal_error != "":
        pytest.skip(fatal_error)

    # Skip if no LDP installed or old kernel
    if net["r1"].daemon_available("ldpd") == False:
        pytest.skip("No MPLS or kernel < 4.5")

    thisDir = os.path.dirname(os.path.realpath(__file__))

    print("\n\n** Verifying MPLS Interfaces")
    print("******************************************\n")
    failures = 0
    for i in range(1, 2):
        refTableFile = "{}/r{}/show_mpls_ldp_interface.ref".format(thisDir, i)
        if os.path.isfile(refTableFile):
            # Read expected result from file
            expected = open(refTableFile).read().rstrip()
            # Fix newlines (make them all the same)
            expected = ("\n".join(expected.splitlines()) + "\n").splitlines(1)

            # Actual output from router
            actual = (
                net["r{}".format(i)]
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
                    "r{} failed MPLS LDP Interface status Check:\n{}\n".format(i, diff)
                )
                failures += 1
            else:
                print("r{} ok".format(i))

            if failures > 0:
                fatal_error = "MPLS LDP Interface status failed"

            assert (
                failures == 0
            ), "MPLS LDP Interface status failed for router r{}:\n{}".format(i, diff)

    # Make sure that all daemons are running
    for i in range(1, 2):
        fatal_error = net["r{}".format(i)].checkRouterRunning()
        assert fatal_error == "", fatal_error


def test_resilient_nexthop_group():
    global fatal_error
    net = get_topogen().net

    # Skip if previous fatal error condition is raised
    if fatal_error != "":
        pytest.skip(fatal_error)

    result = required_linux_kernel_version("5.19")
    if result is not True:
        pytest.skip("Kernel requirements are not met, kernel version should be >= 5.19")

    net["r1"].cmd(
        'vtysh -c "conf" -c "nexthop-group resilience" -c "resilient buckets 64 idle-timer 128 unbalanced-timer 256" -c "nexthop 1.1.1.1 r1-eth1 onlink" -c "nexthop 1.1.1.2 r1-eth2 onlink"'
    )

    # Temporary helper function
    def _show_func():
        output = net["r1"].cmd('vtysh -c "show nexthop-group rib sharp"')
        buckets = re.findall(r"Buckets", output)

        return len(buckets)

    _, result = topotest.run_and_expect(_show_func, 1, count=30, wait=1)
    if result != 1:
        fatal_error = "Resilient NHG not created in zebra"

    assert result == 1, fatal_error

    output = net["r1"].cmd('vtysh -c "show nexthop-group rib sharp json"')

    joutput = json.loads(output)

    # Use the json output and collect the nhg id from it

    for nhgid in joutput:
        n = joutput[nhgid]
        if "buckets" in n:
            break

    if "buckets" not in n:
        fatal_error = "Resilient NHG not found in json output"
    assert "buckets" in n, fatal_error

    verify_nexthop_group(int(nhgid))

    # Remove NHG
    net["r1"].cmd('vtysh -c "conf" -c "no nexthop-group resilience"')


def test_shutdown_check_stderr():
    global fatal_error
    net = get_topogen().net

    # Skip if previous fatal error condition is raised
    if fatal_error != "":
        pytest.skip(fatal_error)

    print("\n\n** Verifying unexpected STDERR output from daemons")
    print("******************************************\n")

    if os.environ.get("TOPOTESTS_CHECK_STDERR") is None:
        print(
            "SKIPPED final check on StdErr output: Disabled (TOPOTESTS_CHECK_STDERR undefined)\n"
        )
        pytest.skip("Skipping test for Stderr output")

    thisDir = os.path.dirname(os.path.realpath(__file__))

    print("thisDir=" + thisDir)

    net["r1"].stopRouter()

    log = net["r1"].getStdErr("ripd")
    if log:
        print("\nRIPd StdErr Log:\n" + log)
    log = net["r1"].getStdErr("ripngd")
    if log:
        print("\nRIPngd StdErr Log:\n" + log)
    log = net["r1"].getStdErr("ospfd")
    if log:
        print("\nOSPFd StdErr Log:\n" + log)
    log = net["r1"].getStdErr("ospf6d")
    if log:
        print("\nOSPF6d StdErr Log:\n" + log)
    log = net["r1"].getStdErr("isisd")
    if log:
        print("\nISISd StdErr Log:\n" + log)
    log = net["r1"].getStdErr("bgpd")
    if log:
        print("\nBGPd StdErr Log:\n" + log)

    log = net["r1"].getStdErr("nhrpd")
    if log:
        print("\nNHRPd StdErr Log:\n" + log)

    log = net["r1"].getStdErr("pbrd")
    if log:
        print("\nPBRd StdErr Log:\n" + log)

    log = net["r1"].getStdErr("babeld")
    if log:
        print("\nBABELd StdErr Log:\n" + log)

    if net["r1"].daemon_available("ldpd"):
        log = net["r1"].getStdErr("ldpd")
        if log:
            print("\nLDPd StdErr Log:\n" + log)
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

    for i in range(1, 2):
        net["r{}".format(i)].stopRouter()
        net["r{}".format(i)].report_memory_leaks(
            os.environ.get("TOPOTESTS_CHECK_MEMLEAK"), os.path.basename(__file__)
        )


if __name__ == "__main__":
    # To suppress tracebacks, either use the following pytest call or add "--tb=no" to cli
    # retval = pytest.main(["-s", "--tb=no"])
    retval = pytest.main(["-s"])
    sys.exit(retval)
