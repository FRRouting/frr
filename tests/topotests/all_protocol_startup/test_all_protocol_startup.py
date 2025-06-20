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
from lib.topolog import logger

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
import subprocess

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
    if nhg_id is None:
        fatal_error = "Nexthop Group ID not found for route {}".format(route_str)
        assert nhg_id is not None, fatal_error
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

    ## TBD: This is a seperately tracked issue #18784
    tgen = get_topogen()
    router = tgen.gears["r1"]
    router.vtysh_cmd("configure\nno ip route 6.6.6.0/24 1.1.1.1")

    def _check_route_removed():
        output = router.cmd("ip route show 6.6.6.0/24")
        if "6.6.6.0/24" in output:
            return False
        return True

    _, result = topotest.run_and_expect(_check_route_removed, True, count=30, wait=1)
    if not result:
        output = router.cmd("ip route show 6.6.6.0/24")
        assert (
            False
        ), "Route 6.6.6.0/24 was not removed after unconfiguration. Current output:\n{}".format(
            output
        )

    # For interfaces r1-eth1 to r1-eth8,
    # DOWN - validate the NHG dependency nexthops are marked inactive
    # UP   - validate the NHG dependency nexthops are marked active
    router.vtysh_cmd("configure\nzebra nexthop-group keep 1")

    test_interfaces = ["r1-eth{}".format(i) for i in range(1, 9)]

    interface_addresses = {}
    for interface in test_interfaces:
        addr_output = router.cmd(
            "ip addr show {} | grep -E 'inet [0-9]+\.' | awk '{{print $2}}' | cut -d/ -f1".format(
                interface
            )
        )
        addresses = [addr.strip() for addr in addr_output.split("\n") if addr.strip()]
        if addresses:
            interface_addresses[interface] = addresses
            logger.info("Interface {} has addresses: {}".format(interface, addresses))

    for interface in test_interfaces:
        logger.info("=" * 80)
        logger.info(
            "*** Test {} down - validate nexthops using {} are marked inactive ***".format(
                interface, interface
            )
        )
        logger.info("=" * 80)

        router.cmd("ip link set {} down".format(interface))
        sleep(1)

        def _check_nhg_inactive_nexthops_for_interface():
            all_nhgs_output = router.vtysh_cmd("show nexthop-group rib")

            nhg_ids = re.findall(r"ID: (\d+)", all_nhgs_output)

            affected_nhgs = []
            validation_errors = []
            total_affected_nexthops = 0

            interface_ips = set()

            interface_addr_patterns = []
            if interface in interface_addresses:
                for addr in interface_addresses[interface]:
                    addr_parts = addr.split(".")
                    if len(addr_parts) == 4:
                        pattern_base = "\.".join(addr_parts[:3])  # e.g., "1\.1\.1"
                        interface_addr_patterns.append(pattern_base + r"\.[0-9]+")

            for nhg_id in nhg_ids:
                nhg_detail = router.vtysh_cmd(
                    "show nexthop-group rib {}".format(nhg_id)
                )

                if "Time to Deletion:" in nhg_detail:
                    continue

                # Parse NHG details
                lines = nhg_detail.split("\n")
                for line in lines:
                    if (
                        "via" in line
                        and line.strip().startswith("via")
                        and interface in line
                    ):
                        for pattern in interface_addr_patterns:
                            ip_match = re.search(
                                r"via ({})".format(pattern), line.strip()
                            )
                            if ip_match:
                                interface_ips.add(ip_match.group(1))

            logger.info(
                "Found interface IPs using {}: {}".format(
                    interface, sorted(list(interface_ips))
                )
            )

            for nhg_id in nhg_ids:
                nhg_detail = router.vtysh_cmd(
                    "show nexthop-group rib {}".format(nhg_id)
                )

                if "Time to Deletion:" in nhg_detail:
                    continue

                # Parse NHG details
                lines = nhg_detail.split("\n")
                dependents = []
                depends = []
                affected_nexthops = []
                all_nexthops = []
                nhg_valid = False

                for line in lines:
                    if "Dependents:" in line:
                        deps_match = re.findall(r"\((\d+)\)", line)
                        dependents = deps_match
                    elif "Depends:" in line:
                        deps_match = re.findall(r"\((\d+)\)", line)
                        depends = deps_match
                    elif "Valid" in line and "ID:" not in line:
                        nhg_valid = True
                    elif "via" in line and line.strip().startswith("via"):
                        all_nexthops.append(line.strip())

                        should_be_inactive = False

                        if interface in line:
                            should_be_inactive = True
                        else:
                            for pattern in interface_addr_patterns:
                                ip_match = re.search(
                                    r"via ({})".format(pattern), line.strip()
                                )
                                if ip_match and ip_match.group(1) in interface_ips:
                                    should_be_inactive = True
                                    break

                        if should_be_inactive:
                            affected_nexthops.append(line.strip())
                            total_affected_nexthops += 1
                            if interface in line:
                                if "inactive" not in line:
                                    validation_errors.append(
                                        "NHG {}: direct nexthop using DOWN interface {} should be inactive: {}".format(
                                            nhg_id, interface, line.strip()
                                        )
                                    )
                            else:
                                if "inactive" in line:
                                    validation_errors.append(
                                        "NHG {}: recursive nexthop affected by DOWN interface {} should NOT show inactive directly: {}".format(
                                            nhg_id, interface, line.strip()
                                        )
                                    )

                if affected_nexthops:
                    status = "Valid" if nhg_valid else "Invalid"
                    dep_str = ",".join(dependents) if dependents else "None"
                    depends_str = ",".join(depends) if depends else "None"
                    affected_nhgs.append(
                        {
                            "id": nhg_id,
                            "status": status,
                            "dependents": dep_str,
                            "depends": depends_str,
                            "affected_nexthops": affected_nexthops,
                            "all_nexthops": all_nexthops,
                        }
                    )

            # Log results
            if affected_nhgs:
                logger.info(
                    "Found {} NHGs with {} total nexthops affected by {}:".format(
                        len(affected_nhgs), total_affected_nexthops, interface
                    )
                )
                for nhg in affected_nhgs:
                    logger.info(
                        "  NHG {} ({}) - {} total nexthop(s), {} affected by {}, dependents: {} ({}), depends: {} ({})".format(
                            nhg["id"],
                            nhg["status"],
                            len(nhg["all_nexthops"]),
                            len(nhg["affected_nexthops"]),
                            interface,
                            nhg["dependents"],
                            len(nhg["dependents"].split(","))
                            if nhg["dependents"] != "None"
                            else 0,
                            nhg["depends"],
                            len(nhg["depends"].split(","))
                            if nhg["depends"] != "None"
                            else 0,
                        )
                    )
                    logger.info("    All nexthops:")
                    for nh in nhg["all_nexthops"]:
                        if nh in nhg["affected_nexthops"]:
                            state = (
                                "✓ INACTIVE"
                                if "inactive" in nh
                                else "✗ ACTIVE (ERROR!)"
                            )
                            logger.info(
                                "      {} {} [AFFECTED BY {}]".format(
                                    state, nh, interface.upper()
                                )
                            )
                        else:
                            state = "○ INACTIVE" if "inactive" in nh else "○ ACTIVE"
                            logger.info("      {} {}".format(state, nh))
            else:
                logger.info("No NHGs found affected by {}".format(interface))

            if validation_errors:
                logger.error("VALIDATION FAILURES when {} is DOWN:".format(interface))
                for error in validation_errors:
                    logger.error("  {}".format(error))
                return False

            logger.info(
                "✓ All nexthops affected by DOWN interface {} are correctly marked inactive".format(
                    interface
                )
            )
            return True

        _, result = topotest.run_and_expect(
            _check_nhg_inactive_nexthops_for_interface, True, count=30, wait=1
        )
        if not result:
            all_nhgs_output = router.vtysh_cmd("show nexthop-group rib")
            assert (
                False
            ), "Expected nexthops using {} to be marked inactive when interface is down. NHG output:\n{}".format(
                interface, all_nhgs_output
            )

        # Bring the interface back up for subsequent tests
        logger.info("=" * 80)
        logger.info(
            "*** Test {} UP - validate nexthops using {} are marked active ***".format(
                interface, interface
            )
        )
        logger.info("=" * 80)
        router.cmd("ip link set {} up".format(interface))
        sleep(1)

        def _check_nhg_active_nexthops_for_interface():
            all_nhgs_output = router.vtysh_cmd("show nexthop-group rib")

            nhg_ids = re.findall(r"ID: (\d+)", all_nhgs_output)
            affected_nhgs = []
            validation_errors = []
            total_affected_nexthops = 0

            interface_ips = set()

            interface_addr_patterns = []
            if interface in interface_addresses:
                for addr in interface_addresses[interface]:
                    addr_parts = addr.split(".")
                    if len(addr_parts) == 4:
                        pattern_base = "\.".join(addr_parts[:3])  # e.g., "1\.1\.1"
                        interface_addr_patterns.append(pattern_base + r"\.[0-9]+")

            for nhg_id in nhg_ids:
                nhg_detail = router.vtysh_cmd(
                    "show nexthop-group rib {}".format(nhg_id)
                )

                if "Time to Deletion:" in nhg_detail:
                    continue

                # Parse NHG details
                lines = nhg_detail.split("\n")
                for line in lines:
                    if (
                        "via" in line
                        and line.strip().startswith("via")
                        and interface in line
                    ):
                        for pattern in interface_addr_patterns:
                            ip_match = re.search(
                                r"via ({})".format(pattern), line.strip()
                            )
                            if ip_match:
                                interface_ips.add(ip_match.group(1))

            logger.info(
                "Found interface IPs using {}: {}".format(
                    interface, sorted(list(interface_ips))
                )
            )

            for nhg_id in nhg_ids:
                nhg_detail = router.vtysh_cmd(
                    "show nexthop-group rib {}".format(nhg_id)
                )

                if "Time to Deletion:" in nhg_detail:
                    continue

                # Parse NHG details
                lines = nhg_detail.split("\n")
                dependents = []
                depends = []
                affected_nexthops = []
                all_nexthops = []
                nhg_valid = False

                for line in lines:
                    if "Dependents:" in line:
                        deps_match = re.findall(r"\((\d+)\)", line)
                        dependents = deps_match
                    elif "Depends:" in line:
                        deps_match = re.findall(r"\((\d+)\)", line)
                        depends = deps_match
                    elif "Valid" in line and "ID:" not in line:
                        nhg_valid = True
                    elif "via" in line and line.strip().startswith("via"):
                        all_nexthops.append(line.strip())

                        should_be_active = False

                        if interface in line:
                            should_be_active = True
                        else:
                            for pattern in interface_addr_patterns:
                                ip_match = re.search(
                                    r"via ({})".format(pattern), line.strip()
                                )
                                if ip_match and ip_match.group(1) in interface_ips:
                                    should_be_active = True
                                    break

                        if should_be_active:
                            affected_nexthops.append(line.strip())
                            total_affected_nexthops += 1
                            if interface in line:
                                if "inactive" in line:
                                    validation_errors.append(
                                        "NHG {}: direct nexthop using UP interface {} should NOT be inactive: {}".format(
                                            nhg_id, interface, line.strip()
                                        )
                                    )
                            else:
                                if "inactive" in line:
                                    validation_errors.append(
                                        "NHG {}: recursive nexthop affected by UP interface {} should NOT show inactive directly: {}".format(
                                            nhg_id, interface, line.strip()
                                        )
                                    )

                if affected_nexthops:
                    status = "Valid" if nhg_valid else "Invalid"
                    dep_str = ",".join(dependents) if dependents else "None"
                    depends_str = ",".join(depends) if depends else "None"
                    affected_nhgs.append(
                        {
                            "id": nhg_id,
                            "status": status,
                            "dependents": dep_str,
                            "depends": depends_str,
                            "affected_nexthops": affected_nexthops,
                            "all_nexthops": all_nexthops,
                        }
                    )

            # Log results
            if affected_nhgs:
                logger.info(
                    "Found {} NHGs with {} total nexthops affected by {}:".format(
                        len(affected_nhgs), total_affected_nexthops, interface
                    )
                )
                for nhg in affected_nhgs:
                    logger.info(
                        "  NHG {} ({}) - {} total nexthop(s), {} affected by {}, dependents: {} ({}), depends: {} ({})".format(
                            nhg["id"],
                            nhg["status"],
                            len(nhg["all_nexthops"]),
                            len(nhg["affected_nexthops"]),
                            interface,
                            nhg["dependents"],
                            len(nhg["dependents"].split(","))
                            if nhg["dependents"] != "None"
                            else 0,
                            nhg["depends"],
                            len(nhg["depends"].split(","))
                            if nhg["depends"] != "None"
                            else 0,
                        )
                    )
                    logger.info("    All nexthops:")
                    for nh in nhg["all_nexthops"]:
                        if nh in nhg["affected_nexthops"]:
                            state = (
                                "✓ ACTIVE"
                                if "inactive" not in nh
                                else "✗ INACTIVE (ERROR!)"
                            )
                            logger.info(
                                "      {} {} [AFFECTED BY {}]".format(
                                    state, nh, interface.upper()
                                )
                            )
                        else:
                            state = "○ ACTIVE" if "inactive" not in nh else "○ INACTIVE"
                            logger.info("      {} {}".format(state, nh))
            else:
                logger.info("No NHGs found affected by {}".format(interface))

            if validation_errors:
                logger.error("VALIDATION FAILURES when {} is UP:".format(interface))
                for error in validation_errors:
                    logger.error("  {}".format(error))
                return False

            logger.info(
                "✓ All nexthops affected by UP interface {} are correctly marked active".format(
                    interface
                )
            )
            return True

        _, result = topotest.run_and_expect(
            _check_nhg_active_nexthops_for_interface, True, count=30, wait=1
        )
        if not result:
            all_nhgs_output = router.vtysh_cmd("show nexthop-group rib")
            assert (
                False
            ), "Expected nexthops using {} to be marked active when interface is up. NHG output:\n{}".format(
                interface, all_nhgs_output
            )

        logger.info("Test {} completed successfully".format(interface))

    # Multi-interface dependency testing
    logger.info("=" * 80)
    logger.info("*** Multi-Interface NHG Dependency Testing ***")
    logger.info("=" * 80)

    # Define interface pairs for iterative testing
    interface_pairs = [
        ("r1-eth1", "r1-eth2"),
        ("r1-eth3", "r1-eth4"),
        ("r1-eth5", "r1-eth6"),
        ("r1-eth7", "r1-eth8"),
    ]

    # Iter 1-4: Test interface pairs
    for i, (intf1, intf2) in enumerate(interface_pairs, 1):
        logger.info("=" * 80)
        logger.info(
            "*** Iter-{}: Testing interfaces {} and {} ***".format(i, intf1, intf2)
        )
        logger.info("=" * 80)

        # Bring interfaces down
        logger.info("=" * 80)
        logger.info("*** Testing DOWN: Interfaces {} and {} ***".format(intf1, intf2))
        logger.info("=" * 80)
        router.cmd("ip link set {} down".format(intf1))
        router.cmd("ip link set {} down".format(intf2))
        sleep(2)

        def _check_nhg_inactive_nexthops_for_pair():
            all_nhgs_output = router.vtysh_cmd("show nexthop-group rib")
            nhg_ids = re.findall(r"ID: (\d+)", all_nhgs_output)

            # Get all IPs on the interfaces
            intf1_ips = []
            intf2_ips = []

            # Get IPs for intf1
            intf1_output = router.cmd("ip addr show {}".format(intf1))
            for line in intf1_output.split("\n"):
                if "inet " in line and not "127.0.0.1" in line:
                    ip_match = re.search(r"inet (\d+\.\d+\.\d+\.\d+)", line)
                    if ip_match:
                        intf1_ips.append(ip_match.group(1))

            # Get IPs for intf2
            intf2_output = router.cmd("ip addr show {}".format(intf2))
            for line in intf2_output.split("\n"):
                if "inet " in line and not "127.0.0.1" in line:
                    ip_match = re.search(r"inet (\d+\.\d+\.\d+\.\d+)", line)
                    if ip_match:
                        intf2_ips.append(ip_match.group(1))

            all_target_ips = intf1_ips + intf2_ips
            logger.info(
                "Found interface IPs using {} and {}: {}".format(
                    intf1, intf2, sorted(all_target_ips)
                )
            )

            affected_nhgs = []
            validation_errors = []
            total_affected_nexthops = 0

            for nhg_id in nhg_ids:
                nhg_detail = router.vtysh_cmd(
                    "show nexthop-group rib {}".format(nhg_id)
                )

                if "Time to Deletion:" in nhg_detail:
                    continue

                # Parse NHG details
                lines = nhg_detail.split("\n")
                dependents = []
                depends = []
                affected_nexthops = []
                all_nexthops = []
                nhg_valid = False

                for line in lines:
                    if "Dependents:" in line:
                        deps_match = re.findall(r"\((\d+)\)", line)
                        dependents = deps_match
                    elif "Depends:" in line:
                        deps_match = re.findall(r"\((\d+)\)", line)
                        depends = deps_match
                    elif "Valid" in line and "ID:" not in line:
                        nhg_valid = True
                    elif "via" in line and line.strip().startswith("via"):
                        all_nexthops.append(line.strip())

                        should_be_inactive = False

                        # Check if nexthop uses either interface directly
                        if intf1 in line or intf2 in line:
                            should_be_inactive = True
                        else:
                            # Check if nexthop uses IPs on either interface (recursive)
                            for ip in all_target_ips:
                                if "via {}".format(ip) in line:
                                    should_be_inactive = True
                                    break

                        if should_be_inactive:
                            affected_nexthops.append(line.strip())
                            total_affected_nexthops += 1
                            if (
                                intf1 in line or intf2 in line
                            ) and "inactive" not in line:
                                validation_errors.append(
                                    "NHG {}: direct nexthop using DOWN interfaces {} or {} should be inactive: {}".format(
                                        nhg_id, intf1, intf2, line.strip()
                                    )
                                )

                if affected_nexthops:
                    status = "Valid" if nhg_valid else "Invalid"
                    dep_str = ",".join(dependents) if dependents else "None"
                    depends_str = ",".join(depends) if depends else "None"
                    affected_nhgs.append(
                        {
                            "id": nhg_id,
                            "status": status,
                            "dependents": dep_str,
                            "depends": depends_str,
                            "affected_nexthops": affected_nexthops,
                            "all_nexthops": all_nexthops,
                        }
                    )

            # Log results
            if affected_nhgs:
                logger.info(
                    "Found {} NHGs with {} total nexthops affected by {} and {}:".format(
                        len(affected_nhgs), total_affected_nexthops, intf1, intf2
                    )
                )
                for nhg in affected_nhgs:
                    logger.info(
                        "  NHG {} ({}) - {} total nexthop(s), {} affected by {} and {}, dependents: {} ({}), depends: {} ({})".format(
                            nhg["id"],
                            nhg["status"],
                            len(nhg["all_nexthops"]),
                            len(nhg["affected_nexthops"]),
                            intf1,
                            intf2,
                            nhg["dependents"],
                            len(nhg["dependents"].split(","))
                            if nhg["dependents"] != "None"
                            else 0,
                            nhg["depends"],
                            len(nhg["depends"].split(","))
                            if nhg["depends"] != "None"
                            else 0,
                        )
                    )
                    logger.info("    All nexthops:")
                    for nh in nhg["all_nexthops"]:
                        if nh in nhg["affected_nexthops"]:
                            state = (
                                "✓ INACTIVE"
                                if "inactive" in nh
                                else "✗ ACTIVE (ERROR!)"
                            )
                            logger.info(
                                "      {} {} [AFFECTED BY {} OR {}]".format(
                                    state, nh, intf1.upper(), intf2.upper()
                                )
                            )
                        else:
                            state = "○ INACTIVE" if "inactive" in nh else "○ ACTIVE"
                            logger.info("      {} {}".format(state, nh))
            else:
                logger.info("No NHGs found affected by {} and {}".format(intf1, intf2))

            if validation_errors:
                logger.error(
                    "VALIDATION FAILURES when {} and {} are DOWN:".format(intf1, intf2)
                )
                for error in validation_errors:
                    logger.error("  {}".format(error))
                return False

            logger.info(
                "✓ All nexthops affected by {} and {} DOWN are correctly marked inactive".format(
                    intf1, intf2
                )
            )
            return True

        _, result = topotest.run_and_expect(
            _check_nhg_inactive_nexthops_for_pair, True, count=30, wait=1
        )
        if not result:
            all_nhgs_output = router.vtysh_cmd("show nexthop-group rib")
            assert (
                False
            ), "Expected nexthops using {} and {} to be marked inactive when interfaces are down. NHG output:\n{}".format(
                intf1, intf2, all_nhgs_output
            )

        # Bring interfaces up
        logger.info("=" * 80)
        logger.info("*** Testing UP: Interfaces {} and {} ***".format(intf1, intf2))
        logger.info("=" * 80)
        router.cmd("ip link set {} up".format(intf1))
        router.cmd("ip link set {} up".format(intf2))
        sleep(3)

        def _check_nhg_active_nexthops_for_pair():
            all_nhgs_output = router.vtysh_cmd("show nexthop-group rib")
            nhg_ids = re.findall(r"ID: (\d+)", all_nhgs_output)

            # Get all IPs on the interfaces
            intf1_ips = []
            intf2_ips = []

            # Get IPs for intf1
            intf1_output = router.cmd("ip addr show {}".format(intf1))
            for line in intf1_output.split("\n"):
                if "inet " in line and not "127.0.0.1" in line:
                    ip_match = re.search(r"inet (\d+\.\d+\.\d+\.\d+)", line)
                    if ip_match:
                        intf1_ips.append(ip_match.group(1))

            # Get IPs for intf2
            intf2_output = router.cmd("ip addr show {}".format(intf2))
            for line in intf2_output.split("\n"):
                if "inet " in line and not "127.0.0.1" in line:
                    ip_match = re.search(r"inet (\d+\.\d+\.\d+\.\d+)", line)
                    if ip_match:
                        intf2_ips.append(ip_match.group(1))

            all_target_ips = intf1_ips + intf2_ips
            logger.info(
                "Found interface IPs using {} and {}: {}".format(
                    intf1, intf2, sorted(all_target_ips)
                )
            )

            affected_nhgs = []
            validation_errors = []
            total_affected_nexthops = 0

            for nhg_id in nhg_ids:
                nhg_detail = router.vtysh_cmd(
                    "show nexthop-group rib {}".format(nhg_id)
                )

                if "Time to Deletion:" in nhg_detail:
                    continue

                # Parse NHG details
                lines = nhg_detail.split("\n")
                dependents = []
                depends = []
                affected_nexthops = []
                all_nexthops = []
                nhg_valid = False

                for line in lines:
                    if "Dependents:" in line:
                        deps_match = re.findall(r"\((\d+)\)", line)
                        dependents = deps_match
                    elif "Depends:" in line:
                        deps_match = re.findall(r"\((\d+)\)", line)
                        depends = deps_match
                    elif "Valid" in line and "ID:" not in line:
                        nhg_valid = True
                    elif "via" in line and line.strip().startswith("via"):
                        all_nexthops.append(line.strip())

                        should_be_active = False

                        # Check if nexthop uses either interface directly
                        if intf1 in line or intf2 in line:
                            should_be_active = True
                        else:
                            # Check if nexthop uses IPs on either interface (recursive)
                            for ip in all_target_ips:
                                if "via {}".format(ip) in line:
                                    should_be_active = True
                                    break

                        if should_be_active:
                            affected_nexthops.append(line.strip())
                            total_affected_nexthops += 1
                            if (intf1 in line or intf2 in line) and "inactive" in line:
                                validation_errors.append(
                                    "NHG {}: direct nexthop using UP interfaces {} or {} should be active: {}".format(
                                        nhg_id, intf1, intf2, line.strip()
                                    )
                                )

                if affected_nexthops:
                    status = "Valid" if nhg_valid else "Invalid"
                    dep_str = ",".join(dependents) if dependents else "None"
                    depends_str = ",".join(depends) if depends else "None"
                    affected_nhgs.append(
                        {
                            "id": nhg_id,
                            "status": status,
                            "dependents": dep_str,
                            "depends": depends_str,
                            "affected_nexthops": affected_nexthops,
                            "all_nexthops": all_nexthops,
                        }
                    )

            # Log results
            if affected_nhgs:
                logger.info(
                    "Found {} NHGs with {} total nexthops affected by {} and {}:".format(
                        len(affected_nhgs), total_affected_nexthops, intf1, intf2
                    )
                )
                for nhg in affected_nhgs:
                    logger.info(
                        "  NHG {} ({}) - {} total nexthop(s), {} affected by {} and {}, dependents: {} ({}), depends: {} ({})".format(
                            nhg["id"],
                            nhg["status"],
                            len(nhg["all_nexthops"]),
                            len(nhg["affected_nexthops"]),
                            intf1,
                            intf2,
                            nhg["dependents"],
                            len(nhg["dependents"].split(","))
                            if nhg["dependents"] != "None"
                            else 0,
                            nhg["depends"],
                            len(nhg["depends"].split(","))
                            if nhg["depends"] != "None"
                            else 0,
                        )
                    )
                    logger.info("    All nexthops:")
                    for nh in nhg["all_nexthops"]:
                        if nh in nhg["affected_nexthops"]:
                            state = (
                                "✓ ACTIVE"
                                if "inactive" not in nh
                                else "✗ INACTIVE (ERROR!)"
                            )
                            logger.info(
                                "      {} {} [AFFECTED BY {} OR {}]".format(
                                    state, nh, intf1.upper(), intf2.upper()
                                )
                            )
                        else:
                            state = "○ INACTIVE" if "inactive" in nh else "○ ACTIVE"
                            logger.info("      {} {}".format(state, nh))
            else:
                logger.info("No NHGs found affected by {} and {}".format(intf1, intf2))

            if validation_errors:
                logger.error(
                    "VALIDATION FAILURES when {} and {} are UP:".format(intf1, intf2)
                )
                for error in validation_errors:
                    logger.error("  {}".format(error))
                return False

            logger.info(
                "✓ All nexthops affected by {} and {} UP are correctly marked active".format(
                    intf1, intf2
                )
            )
            return True

        _, result = topotest.run_and_expect(
            _check_nhg_active_nexthops_for_pair, True, count=30, wait=1
        )
        if not result:
            all_nhgs_output = router.vtysh_cmd("show nexthop-group rib")
            assert (
                False
            ), "Expected nexthops using {} and {} to be marked active when interfaces are up. NHG output:\n{}".format(
                intf1, intf2, all_nhgs_output
            )

        logger.info(
            "Iter-{}: {} and {} test completed successfully".format(i, intf1, intf2)
        )

    ## Validate NHG's installed in kernel has same nexthops with Interface flaps
    logger.info("=" * 80)
    logger.info(
        "*** NHG's installed in kernel has same nexthops with Interface flaps ***"
    )
    logger.info("=" * 80)
    pre_out = router.cmd('ip route show | grep "5.5.5.1"')
    pre_nhg = re.search(r"nhid\s+(\d+)", pre_out)
    pre_nh_show = router.cmd("ip next show id {}".format(pre_nhg.group(1)))
    pre_total_nhs = len((re.search(r"group ([\d/]+)", pre_nh_show)).group(1).split("/"))

    router.cmd(
        "ip link set r1-eth1 down;ip link set r1-eth2 down;ip link set r1-eth3 down;ip link set r1-eth4 down"
    )
    sleep(1)
    router.cmd(
        "ip link set r1-eth1 up;ip link set r1-eth2 up;ip link set r1-eth3 up;ip link set r1-eth4 up"
    )

    def _check_nexthops_stable():
        post_out = router.cmd('ip route show | grep "5.5.5.1"')
        if not post_out:
            return False
        post_nhg = re.search(r"nhid\s+(\d+)", post_out)
        if not post_nhg:
            return False
        post_nh_show = router.cmd("ip next show id {}".format(post_nhg.group(1)))
        post_total_nhs = len(
            (re.search(r"group ([\d/]+)", post_nh_show)).group(1).split("/")
        )
        return post_total_nhs == pre_total_nhs

    _, result = topotest.run_and_expect(_check_nexthops_stable, True, count=30, wait=1)
    if not result:
        post_out = router.cmd('ip route show | grep "5.5.5.1"')
        post_nhg = re.search(r"nhid\s+(\d+)", post_out)
        post_nh_show = router.cmd("ip next show id {}".format(post_nhg.group(1)))
        post_total_nhs = len(
            (re.search(r"group ([\d/]+)", post_nh_show)).group(1).split("/")
        )

        assert (
            False
        ), "Expected same nexthops(pre-{}: post-{}) in NHG (pre-{}:post-{}) after few Interface flaps".format(
            pre_total_nhs, post_total_nhs, pre_nhg.group(1), post_nhg.group(1)
        )

    ## Validate route re-install post nexthop delete an ID
    logger.info("=" * 80)
    logger.info("*** Validate route re-install post nexthop delete an ID ***")
    logger.info("=" * 80)
    nhg_id = route_get_nhg_id("6.6.6.1/32")
    pre_output = router.cmd(
        'vtysh -c "show nexthop-group rib {} routes"'.format(nhg_id)
    )
    post_out = router.cmd("ip nexthop del id {}".format(nhg_id))

    def _check_nhg_routes():
        post_output = router.cmd(
            'vtysh -c "show nexthop-group rib {} routes"'.format(nhg_id)
        )
        return post_output == pre_output

    _, result = topotest.run_and_expect(_check_nhg_routes, True, count=30, wait=1)
    if not result:
        post_output = router.cmd(
            'vtysh -c "show nexthop-group rib {} routes"'.format(nhg_id)
        )
        assert (
            False
        ), "Expected same pre and post routes after nhg {} delete from kernel\nPre:\n{}\nPost:\n{}".format(
            nhg_id, pre_output, post_output
        )

    # Iter 5: All interfaces down
    logger.info("=" * 80)
    logger.info("*** Iter-5: Testing ALL interfaces down ***")
    logger.info("=" * 80)
    all_interfaces = [
        "r1-eth1",
        "r1-eth2",
        "r1-eth3",
        "r1-eth4",
        "r1-eth5",
        "r1-eth6",
        "r1-eth7",
        "r1-eth8",
    ]

    # Bring all interfaces down
    for intf in all_interfaces:
        router.cmd("ip link set {} down".format(intf))
    sleep(2)

    def _check_nhg_inactive_nexthops_for_all_interfaces():
        all_nhgs_output = router.vtysh_cmd("show nexthop-group rib")
        nhg_ids = re.findall(r"ID: (\d+)", all_nhgs_output)

        # Get all IPs on all interfaces
        all_target_ips = []
        for intf in all_interfaces:
            intf_output = router.cmd("ip addr show {}".format(intf))
            for line in intf_output.split("\n"):
                if "inet " in line and not "127.0.0.1" in line:
                    ip_match = re.search(r"inet (\d+\.\d+\.\d+\.\d+)", line)
                    if ip_match:
                        all_target_ips.append(ip_match.group(1))

        logger.info(
            "Found interface IPs on ALL interfaces: {}".format(sorted(all_target_ips))
        )

        affected_nhgs = []
        validation_errors = []
        total_affected_nexthops = 0

        for nhg_id in nhg_ids:
            nhg_detail = router.vtysh_cmd("show nexthop-group rib {}".format(nhg_id))

            if "Time to Deletion:" in nhg_detail:
                continue

            # Parse NHG details
            lines = nhg_detail.split("\n")
            dependents = []
            depends = []
            affected_nexthops = []
            all_nexthops = []
            nhg_valid = False

            for line in lines:
                if "Dependents:" in line:
                    deps_match = re.findall(r"\((\d+)\)", line)
                    dependents = deps_match
                elif "Depends:" in line:
                    deps_match = re.findall(r"\((\d+)\)", line)
                    depends = deps_match
                elif "Valid" in line and "ID:" not in line:
                    nhg_valid = True
                elif "via" in line and line.strip().startswith("via"):
                    all_nexthops.append(line.strip())

                    should_be_inactive = False

                    # Check if nexthop uses any interface directly
                    for intf in all_interfaces:
                        if intf in line:
                            should_be_inactive = True
                            break

                    if not should_be_inactive:
                        # Check if nexthop uses IPs on any interface (recursive)
                        for ip in all_target_ips:
                            if "via {}".format(ip) in line:
                                should_be_inactive = True
                                break

                    if should_be_inactive:
                        affected_nexthops.append(line.strip())
                        total_affected_nexthops += 1
                        # Check if direct nexthop should be inactive
                        is_direct = any(intf in line for intf in all_interfaces)
                        if is_direct and "inactive" not in line:
                            validation_errors.append(
                                "NHG {}: direct nexthop using DOWN interfaces should be inactive: {}".format(
                                    nhg_id, line.strip()
                                )
                            )

            if affected_nexthops:
                status = "Valid" if nhg_valid else "Invalid"
                dep_str = ",".join(dependents) if dependents else "None"
                depends_str = ",".join(depends) if depends else "None"
                affected_nhgs.append(
                    {
                        "id": nhg_id,
                        "status": status,
                        "dependents": dep_str,
                        "depends": depends_str,
                        "affected_nexthops": affected_nexthops,
                        "all_nexthops": all_nexthops,
                    }
                )

        # Log results
        if affected_nhgs:
            logger.info(
                "Found {} NHGs with {} total nexthops affected by ALL DOWN interfaces:".format(
                    len(affected_nhgs), total_affected_nexthops
                )
            )
            for nhg in affected_nhgs:
                logger.info(
                    "  NHG {} ({}) - {} total nexthop(s), {} affected by ALL interfaces, dependents: {} ({}), depends: {} ({})".format(
                        nhg["id"],
                        nhg["status"],
                        len(nhg["all_nexthops"]),
                        len(nhg["affected_nexthops"]),
                        nhg["dependents"],
                        len(nhg["dependents"].split(","))
                        if nhg["dependents"] != "None"
                        else 0,
                        nhg["depends"],
                        len(nhg["depends"].split(","))
                        if nhg["depends"] != "None"
                        else 0,
                    )
                )
                logger.info("    All nexthops:")
                for nh in nhg["all_nexthops"]:
                    if nh in nhg["affected_nexthops"]:
                        state = (
                            "✓ INACTIVE" if "inactive" in nh else "✗ ACTIVE (ERROR!)"
                        )
                        logger.info(
                            "      {} {} [AFFECTED BY ALL INTERFACES]".format(state, nh)
                        )
                    else:
                        state = "○ INACTIVE" if "inactive" in nh else "○ ACTIVE"
                        logger.info("      {} {}".format(state, nh))
        else:
            logger.info("No NHGs found affected by ALL interfaces")

        if validation_errors:
            logger.error("VALIDATION FAILURES when ALL interfaces are DOWN:")
            for error in validation_errors:
                logger.error("  {}".format(error))
            return False

        logger.info(
            "✓ All nexthops affected by ALL DOWN interfaces are correctly marked inactive"
        )
        return True

    _, result = topotest.run_and_expect(
        _check_nhg_inactive_nexthops_for_all_interfaces, True, count=30, wait=1
    )
    if not result:
        all_nhgs_output = router.vtysh_cmd("show nexthop-group rib")
        assert (
            False
        ), "Expected all nexthops to be marked inactive when ALL interfaces are down. NHG output:\n{}".format(
            all_nhgs_output
        )

    # Bring all interfaces up
    for intf in all_interfaces:
        router.cmd("ip link set {} up".format(intf))
    sleep(2)

    def _check_nhg_active_nexthops_for_all_interfaces():
        all_nhgs_output = router.vtysh_cmd("show nexthop-group rib")
        nhg_ids = re.findall(r"ID: (\d+)", all_nhgs_output)

        # Get all IPs on all interfaces
        all_target_ips = []
        for intf in all_interfaces:
            intf_output = router.cmd("ip addr show {}".format(intf))
            for line in intf_output.split("\n"):
                if "inet " in line and not "127.0.0.1" in line:
                    ip_match = re.search(r"inet (\d+\.\d+\.\d+\.\d+)", line)
                    if ip_match:
                        all_target_ips.append(ip_match.group(1))

        logger.info(
            "Found interface IPs on ALL interfaces: {}".format(sorted(all_target_ips))
        )

        affected_nhgs = []
        validation_errors = []
        total_affected_nexthops = 0

        for nhg_id in nhg_ids:
            nhg_detail = router.vtysh_cmd("show nexthop-group rib {}".format(nhg_id))

            if "Time to Deletion:" in nhg_detail:
                continue

            # Parse NHG details
            lines = nhg_detail.split("\n")
            dependents = []
            depends = []
            affected_nexthops = []
            all_nexthops = []
            nhg_valid = False

            for line in lines:
                if "Dependents:" in line:
                    deps_match = re.findall(r"\((\d+)\)", line)
                    dependents = deps_match
                elif "Depends:" in line:
                    deps_match = re.findall(r"\((\d+)\)", line)
                    depends = deps_match
                elif "Valid" in line and "ID:" not in line:
                    nhg_valid = True
                elif "via" in line and line.strip().startswith("via"):
                    all_nexthops.append(line.strip())

                    should_be_active = False

                    # Check if nexthop uses any interface directly
                    for intf in all_interfaces:
                        if intf in line:
                            should_be_active = True
                            break

                    if not should_be_active:
                        # Check if nexthop uses IPs on any interface (recursive)
                        for ip in all_target_ips:
                            if "via {}".format(ip) in line:
                                should_be_active = True
                                break

                    if should_be_active:
                        affected_nexthops.append(line.strip())
                        total_affected_nexthops += 1
                        # Check if direct nexthop should be active
                        is_direct = any(intf in line for intf in all_interfaces)
                        if is_direct and "inactive" in line:
                            validation_errors.append(
                                "NHG {}: direct nexthop using UP interfaces should be active: {}".format(
                                    nhg_id, line.strip()
                                )
                            )

            if affected_nexthops:
                status = "Valid" if nhg_valid else "Invalid"
                dep_str = ",".join(dependents) if dependents else "None"
                depends_str = ",".join(depends) if depends else "None"
                affected_nhgs.append(
                    {
                        "id": nhg_id,
                        "status": status,
                        "dependents": dep_str,
                        "depends": depends_str,
                        "affected_nexthops": affected_nexthops,
                        "all_nexthops": all_nexthops,
                    }
                )

        # Log results
        if affected_nhgs:
            logger.info(
                "Found {} NHGs with {} total nexthops affected by ALL UP interfaces:".format(
                    len(affected_nhgs), total_affected_nexthops
                )
            )
            for nhg in affected_nhgs:
                logger.info(
                    "  NHG {} ({}) - {} total nexthop(s), {} affected by ALL interfaces, dependents: {} ({}), depends: {} ({})".format(
                        nhg["id"],
                        nhg["status"],
                        len(nhg["all_nexthops"]),
                        len(nhg["affected_nexthops"]),
                        nhg["dependents"],
                        len(nhg["dependents"].split(","))
                        if nhg["dependents"] != "None"
                        else 0,
                        nhg["depends"],
                        len(nhg["depends"].split(","))
                        if nhg["depends"] != "None"
                        else 0,
                    )
                )
                logger.info("    All nexthops:")
                for nh in nhg["all_nexthops"]:
                    if nh in nhg["affected_nexthops"]:
                        state = (
                            "✓ ACTIVE"
                            if "inactive" not in nh
                            else "✗ INACTIVE (ERROR!)"
                        )
                        logger.info(
                            "      {} {} [AFFECTED BY ALL INTERFACES]".format(state, nh)
                        )
                    else:
                        state = "○ INACTIVE" if "inactive" in nh else "○ ACTIVE"
                        logger.info("      {} {}".format(state, nh))
        else:
            logger.info("No NHGs found affected by ALL interfaces")

        if validation_errors:
            logger.error("VALIDATION FAILURES when ALL interfaces are UP:")
            for error in validation_errors:
                logger.error("  {}".format(error))
            return False

        logger.info(
            "✓ All nexthops affected by ALL UP interfaces are correctly marked active"
        )
        return True

    _, result = topotest.run_and_expect(
        _check_nhg_active_nexthops_for_all_interfaces, True, count=30, wait=1
    )
    if not result:
        all_nhgs_output = router.vtysh_cmd("show nexthop-group rib")
        assert (
            False
        ), "Expected all nexthops to be marked active when ALL interfaces are up. NHG output:\n{}".format(
            all_nhgs_output
        )

    logger.info("Iter-5: ALL interfaces test completed successfully")

    router.vtysh_cmd("configure\nno zebra nexthop-group keep 1")

    logger.info("Removing all sharp routes")
    ## Remove all NHG routes
    router.cmd('vtysh -c "sharp remove routes 2.2.2.1 1"')
    router.cmd('vtysh -c "sharp remove routes 2.2.2.2 1"')
    router.cmd('vtysh -c "sharp remove routes 3.3.3.1 1"')
    router.cmd('vtysh -c "sharp remove routes 3.3.3.2 1"')
    router.cmd('vtysh -c "sharp remove routes 4.4.4.1 1"')
    router.cmd('vtysh -c "sharp remove routes 4.4.4.2 1"')
    router.cmd('vtysh -c "sharp remove routes 5.5.5.1 1"')
    router.cmd('vtysh -c "sharp remove routes 6.6.6.1 4"')


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
            with open(refTableFile) as file:
                expected = file.read().rstrip()
            # Drop trailing whitespaces for each line
            expected = "\n".join(line.rstrip() for line in expected.splitlines())
            # Fix newlines (make them all the same)
            expected = ("\n".join(expected.splitlines()) + "\n").splitlines(1)

            def _check_rip_status():
                # Actual output from router
                actual = (
                    net["r{}".format(i)]
                    .cmd('vtysh -c "show ip rip status" 2> /dev/null')
                    .rstrip()
                )
                # Drop time in next due
                actual = re.sub(r"in [0-9]+ seconds", "in XX seconds", actual)
                # Drop time in last update
                actual = re.sub(
                    r" [0-2][0-9]:[0-5][0-9]:[0-5][0-9]", " XX:XX:XX", actual
                )
                # Drop trailing whitespaces for each line
                actual = "\n".join(line.rstrip() for line in actual.splitlines())
                # Fix newlines (make them all the same)
                actual = ("\n".join(actual.splitlines()) + "\n").splitlines(1)

                # Generate Diff
                diff = topotest.get_textdiff(
                    actual,
                    expected,
                    title1="actual IP RIP status",
                    title2="expected IP RIP status",
                )

                if diff:
                    return False
                return True

            # Try for 30 seconds with 1 second intervals
            _, result = topotest.run_and_expect(
                _check_rip_status, True, count=30, wait=1
            )
            if not result:
                actual = (
                    net["r{}".format(i)]
                    .cmd('vtysh -c "show ip rip status" 2> /dev/null')
                    .rstrip()
                )
                actual = re.sub(r"in [0-9]+ seconds", "in XX seconds", actual)
                actual = re.sub(
                    r" [0-2][0-9]:[0-5][0-9]:[0-5][0-9]", " XX:XX:XX", actual
                )
                actual = "\n".join(line.rstrip() for line in actual.splitlines())
                actual = ("\n".join(actual.splitlines()) + "\n").splitlines(1)
                diff = topotest.get_textdiff(
                    actual,
                    expected,
                    title1="actual IP RIP status",
                    title2="expected IP RIP status",
                )
                sys.stderr.write(
                    "r{} failed IP RIP status check after retries:\n{}\n".format(
                        i, diff
                    )
                )
                failures += 1
            else:
                print("r{} ok".format(i))

            assert (
                failures == 0
            ), "IP RIP status failed for router r{} after retries".format(i)

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
            with open(refTableFile) as file:
                expected = file.read().rstrip()
            # Drop trailing whitespaces for each line
            expected = "\n".join(line.rstrip() for line in expected.splitlines())
            # Fix newlines (make them all the same)
            expected = ("\n".join(expected.splitlines()) + "\n").splitlines(1)

            def _check_ripng_status():
                # Actual output from router
                actual = (
                    net["r{}".format(i)]
                    .cmd('vtysh -c "show ipv6 ripng status" 2> /dev/null')
                    .rstrip()
                )
                # Mask out Link-Local mac address portion. They are random...
                actual = re.sub(
                    r" fe80::[0-9a-f:]+", " fe80::XXXX:XXXX:XXXX:XXXX", actual
                )
                # Drop time in next due
                actual = re.sub(r"in [0-9]+ seconds", "in XX seconds", actual)
                # Drop time in last update
                actual = re.sub(
                    r" [0-2][0-9]:[0-5][0-9]:[0-5][0-9]", " XX:XX:XX", actual
                )
                # Drop trailing whitespaces for each line
                actual = "\n".join(line.rstrip() for line in actual.splitlines())
                # Fix newlines (make them all the same)
                actual = ("\n".join(actual.splitlines()) + "\n").splitlines(1)

                # Generate Diff
                diff = topotest.get_textdiff(
                    actual,
                    expected,
                    title1="actual IPv6 RIPng status",
                    title2="expected IPv6 RIPng status",
                )

                if diff:
                    return False
                return True

            # Try for 30 seconds with 1 second intervals
            _, result = topotest.run_and_expect(
                _check_ripng_status, True, count=30, wait=1
            )
            if not result:
                actual = (
                    net["r{}".format(i)]
                    .cmd('vtysh -c "show ipv6 ripng status" 2> /dev/null')
                    .rstrip()
                )
                actual = re.sub(
                    r" fe80::[0-9a-f:]+", " fe80::XXXX:XXXX:XXXX:XXXX", actual
                )
                actual = re.sub(r"in [0-9]+ seconds", "in XX seconds", actual)
                actual = re.sub(
                    r" [0-2][0-9]:[0-5][0-9]:[0-5][0-9]", " XX:XX:XX", actual
                )
                actual = "\n".join(line.rstrip() for line in actual.splitlines())
                actual = ("\n".join(actual.splitlines()) + "\n").splitlines(1)
                diff = topotest.get_textdiff(
                    actual,
                    expected,
                    title1="actual IPv6 RIPng status",
                    title2="expected IPv6 RIPng status",
                )
                sys.stderr.write(
                    "r{} failed IPv6 RIPng status check after retries:\n{}\n".format(
                        i, diff
                    )
                )
                failures += 1
            else:
                print("r{} ok".format(i))

            assert (
                failures == 0
            ), "IPv6 RIPng status failed for router r{} after retries".format(i)

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
            with open(refTableFile) as file:
                expected = file.read().rstrip()
            # Fix newlines (make them all the same)
            expected = ("\n".join(expected.splitlines()) + "\n").splitlines(1)

            def _check_ospf_interfaces():
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
                actual = re.sub(
                    r"Hello due in [0-9\.]+s", "Hello due in XX.XXXs", actual
                )
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

                if diff:
                    return False
                return True

            # Try for 30 seconds with 1 second intervals
            _, result = topotest.run_and_expect(
                _check_ospf_interfaces, True, count=30, wait=1
            )
            if not result:
                actual = (
                    net["r{}".format(i)]
                    .cmd('vtysh -c "show ip ospf interface" 2> /dev/null')
                    .rstrip()
                )
                actual = re.sub(r"BW [0-9]+ Mbit", "BW XX Mbit", actual)
                actual = re.sub(r"ifindex [0-9]+", "ifindex X", actual)
                actual = re.sub(
                    r"Hello due in [0-9\.]+s", "Hello due in XX.XXXs", actual
                )
                actual = re.sub(
                    r"Hello due in [0-9\.]+ usecs", "Hello due in XX.XXXs", actual
                )
                actual = re.sub(
                    r"MTU mismatch detection:([a-z]+.*)",
                    r"MTU mismatch detection: \1",
                    actual,
                )
                actual = ("\n".join(actual.splitlines()) + "\n").splitlines(1)
                diff = topotest.get_textdiff(
                    actual,
                    expected,
                    title1="actual SHOW IP OSPF INTERFACE",
                    title2="expected SHOW IP OSPF INTERFACE",
                )
                sys.stderr.write(
                    "r{} failed SHOW IP OSPF INTERFACE check after retries:\n{}\n".format(
                        i, diff
                    )
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
            ), "SHOW IP OSPF INTERFACE failed for router r{} after retries".format(i)

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
            with open(refTableFile) as file:
                expected = file.read().rstrip()
            # Fix newlines (make them all the same)
            expected = ("\n".join(expected.splitlines()) + "\n").splitlines(1)

            def _check_isis_interfaces():
                # Actual output from router
                actual = (
                    net["r{}".format(i)]
                    .cmd('vtysh -c "show isis interface detail" 2> /dev/null')
                    .rstrip()
                )
                # Mask out Link-Local mac address portion. They are random...
                actual = re.sub(
                    r"fe80::[0-9a-f:]+", "fe80::XXXX:XXXX:XXXX:XXXX", actual
                )
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

                if diff:
                    return False
                return True

            # Try for 30 seconds with 1 second intervals
            _, result = topotest.run_and_expect(
                _check_isis_interfaces, True, count=30, wait=1
            )
            if not result:
                actual = (
                    net["r{}".format(i)]
                    .cmd('vtysh -c "show isis interface detail" 2> /dev/null')
                    .rstrip()
                )
                actual = re.sub(
                    r"fe80::[0-9a-f:]+", "fe80::XXXX:XXXX:XXXX:XXXX", actual
                )
                actual = re.sub(r"SNPA: [0-9a-f\.]+", "SNPA: XXXX.XXXX.XXXX", actual)
                actual = re.sub(r"Circuit Id: 0x[0-9a-f]+", "Circuit Id: 0xXX", actual)
                actual = ("\n".join(actual.splitlines()) + "\n").splitlines(1)
                diff = topotest.get_textdiff(
                    actual,
                    expected,
                    title1="actual SHOW ISIS INTERFACE DETAIL",
                    title2="expected SHOW ISIS OSPF6 INTERFACE DETAIL",
                )
                sys.stderr.write(
                    "r{} failed SHOW ISIS INTERFACE DETAIL check after retries:\n{}\n".format(
                        i, diff
                    )
                )
                failures += 1
            else:
                print("r{} ok".format(i))

            assert (
                failures == 0
            ), "SHOW ISIS INTERFACE DETAIL failed for router r{} after retries".format(
                i
            )

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
            with open(refTableFile) as file:
                expected_original = file.read().rstrip()

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
            with open(refTableFile) as file:
                expected = file.read().rstrip()
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
        with open(nhtFile) as file:
            expected = file.read().rstrip()
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
        with open(nhtFile) as file:
            expected = file.read().rstrip()
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
                with open(refTableFile) as file:
                    expected = file.read().rstrip()
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
                with open(refTableFile) as file:
                    expected = file.read().rstrip()
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
            with open(refroutemap) as file:
                expected = file.read().rstrip()
            expected = ("\n".join(expected.splitlines()) + "\n").splitlines(1)

            actual = (
                net["r{}".format(i)]
                .cmd('vtysh -c "show route-map" 2> /dev/null')
                .rstrip()
            )
            actual = re.sub(r"\([0-9].* milli", "(X milli", actual)
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


def test_nexthop_flush_and_interface_flaps():
    global fatal_error
    net = get_topogen().net
    tgen = get_topogen()
    router = tgen.gears["r1"]

    # Skip if previous fatal error condition is raised
    if fatal_error != "":
        pytest.skip(fatal_error)

    logger.info("\n\n** Verifying Nexthop Flush and Interface Flaps")
    logger.info("******************************************\n")

    # Configure NHGs and routes for testing
    logger.info("=" * 80)
    logger.info("*** Configuring test routes with specific NHGs ***")
    logger.info("=" * 80)

    # Configure static routes with direct interface nexthops
    prefixes = [
        "20.1.1.0/24",
        "20.1.3.0/24",
        "20.1.5.0/24",
        "20.1.7.0/24",
        "20.1.9.0/24",
        "20.1.11.0/24",
        "20.1.13.0/24",
    ]
    interfaces = [
        "r1-eth1",
        "r1-eth2",
        "r1-eth3",
        "r1-eth4",
        "r1-eth5",
        "r1-eth6",
        "r1-eth7",
        "r1-eth8",
    ]

    # Configure routes - each prefix gets 2-8 interfaces based on pattern
    for i, prefix in enumerate(prefixes):
        if i < 4:  # First 4 prefixes (1,3,5,7) get 2 interfaces each
            router.cmd(
                f'vtysh -c "configure terminal" -c "ip route {prefix} {interfaces[i*2]}" -c "exit"'
            )
            router.cmd(
                f'vtysh -c "configure terminal" -c "ip route {prefix} {interfaces[i*2+1]}" -c "exit"'
            )
        elif i == 4:  # 20.1.9.0/24 gets 4 interfaces (eth1-4)
            for j in range(4):
                router.cmd(
                    f'vtysh -c "configure terminal" -c "ip route {prefix} {interfaces[j]}" -c "exit"'
                )
        elif i == 5:  # 20.1.11.0/24 gets 4 interfaces (eth5-8)
            for j in range(4, 8):
                router.cmd(
                    f'vtysh -c "configure terminal" -c "ip route {prefix} {interfaces[j]}" -c "exit"'
                )
        else:  # 20.1.13.0/24 gets all 8 interfaces
            for iface in interfaces:
                router.cmd(
                    f'vtysh -c "configure terminal" -c "ip route {prefix} {iface}" -c "exit"'
                )

    # Verify routes are installed
    def _verify_routes_installed():
        routes = router.cmd('vtysh -c "show ip route"')
        for prefix in prefixes:
            if prefix not in routes:
                return False
        return True

    _, result = topotest.run_and_expect(
        _verify_routes_installed, True, count=30, wait=1
    )
    assert result, "Failed to install test routes"

    ## Validate route re-install post ip nexthop flush
    logger.info("=" * 80)
    logger.info("*** Validate route re-install post ip nexthop flush ***")
    logger.info("=" * 80)
    pre_route = router.cmd("ip route show | wc -l")
    pre_route6 = router.cmd("ip -6 route show | wc -l")

    post_out = router.cmd("ip next flush")

    def _check_current_route_counts():
        post_route = router.cmd("ip route show | wc -l")
        post_route6 = router.cmd("ip -6 route show | wc -l")
        if post_route != pre_route or post_route6 != pre_route6:
            return False
        return True

    result_tuple = topotest.run_and_expect(
        _check_current_route_counts, True, count=30, wait=1
    )
    _, result = result_tuple
    if not result:
        post_route = router.cmd("ip route show | wc -l")
        post_route6 = router.cmd("ip -6 route show | wc -l")
        assert (
            False
        ), "Expected same ipv6 routes(pre-{}: post-{}) and ipv4 route count(pre-{}:post-{}) after nexthop flush".format(
            pre_route6, post_route6, pre_route, post_route
        )

    ## Validate route re-install after quick interface flaps of rt1-eth(1-8)
    logger.info("=" * 80)
    logger.info(
        "*** Validate route re-install after quick interface flaps of rt1-eth(1-8) ***"
    )
    logger.info("=" * 80)
    pre_route = router.cmd("ip route show | wc -l")
    pre_route6 = router.cmd("ip -6 route show | wc -l")

    interfaces = range(1, 9)
    cmds = [f"ip link set r1-eth{i} down; ip link set r1-eth{i} up" for i in interfaces]
    router.cmd(" ; ".join(cmds))

    def _check_current_route_counts_after_flap():
        post_route = router.cmd("ip route show | wc -l")
        post_route6 = router.cmd("ip -6 route show | wc -l")
        if post_route != pre_route or post_route6 != pre_route6:
            return False
        return True

    result_tuple = topotest.run_and_expect(
        _check_current_route_counts_after_flap, True, count=30, wait=1
    )
    _, result = result_tuple
    if not result:
        post_route = router.cmd("ip route show | wc -l")
        post_route6 = router.cmd("ip -6 route show | wc -l")
        assert (
            False
        ), "Expected same ipv6 routes(pre-{}: post-{}) and route count(pre-{}:post-{}) after quick interface flaps of rt1-eth(1-8)".format(
            pre_route6, post_route6, pre_route, post_route
        )

    # Clean up static routes - remove each route with its interfaces
    logger.info("*** Cleaning up test static routes ***")
    for i, prefix in enumerate(prefixes):
        if i < 4:  # First 4 prefixes (1,3,5,7) with 2 interfaces each
            router.cmd(
                f'vtysh -c "configure terminal" -c "no ip route {prefix} {interfaces[i*2]}" -c "exit"'
            )
            router.cmd(
                f'vtysh -c "configure terminal" -c "no ip route {prefix} {interfaces[i*2+1]}" -c "exit"'
            )
        elif i == 4:  # 20.1.9.0/24 with interfaces eth1-4
            for j in range(4):
                router.cmd(
                    f'vtysh -c "configure terminal" -c "no ip route {prefix} {interfaces[j]}" -c "exit"'
                )
        elif i == 5:  # 20.1.11.0/24 with interfaces eth5-8
            for j in range(4, 8):
                router.cmd(
                    f'vtysh -c "configure terminal" -c "no ip route {prefix} {interfaces[j]}" -c "exit"'
                )
        else:  # 20.1.13.0/24 with all 8 interfaces
            for iface in interfaces:
                router.cmd(
                    f'vtysh -c "configure terminal" -c "no ip route {prefix} {iface}" -c "exit"'
                )


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
            with open(refTableFile) as file:
                expected = file.read().rstrip()
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


def test_interface_stuff():
    global fatal_error
    net = get_topogen().net

    # Skip if previous fatal error condition is raised
    if fatal_error != "":
        pytest.skip(fatal_error)

    print("\n\n** Verifying some interface code")
    print("************************************\n")

    net["r1"].cmd('vtysh -c "conf" -c "interface r1-eth0" -c "multicast enable"')

    def _test_interface_multicast_on():
        output = json.loads(net["r1"].cmd('vtysh -c "show int r1-eth0 json"'))
        expected = {
            "r1-eth0": {
                "flags": "<UP,LOWER_UP,BROADCAST,RUNNING,MULTICAST>",
                "multicastConfig": "Enabled by CLI",
            }
        }
        return topotest.json_cmp(output, expected)

    test_func = functools.partial(_test_interface_multicast_on)
    _, result = topotest.run_and_expect(test_func, None, count=30, wait=1)
    assert result is None, "Multicast bit was not set on r1-eth0"

    net["r1"].cmd('vtysh -c "conf" -c "interface r1-eth0" -c "multicast disable"')

    def _test_interface_multicast_off():
        output = json.loads(
            net["r1"].cmd('vtysh -c "show int r1-eth0 vrf default json"')
        )
        expected = {
            "r1-eth0": {
                "flags": "<UP,LOWER_UP,BROADCAST,RUNNING>",
                "multicastConfig": "Disabled by CLI",
            }
        }
        return topotest.json_cmp(output, expected)

    test_func = functools.partial(_test_interface_multicast_off)
    _, result = topotest.run_and_expect(test_func, None, count=30, wait=1)
    assert result is None, "Multicast bit was not turned off on r1-eth0"

    net["r1"].cmd('vtysh -c "conf" -c "interface r1-eth0" -c "no multicast disable"')

    def _test_interface_multicast_disable():
        output = json.loads(net["r1"].cmd('vtysh -c "show int r1-eth0 json"'))
        expected = {
            "r1-eth0": {
                "flags": "<UP,LOWER_UP,BROADCAST,RUNNING>",
                "multicastConfig": "Not specified by CLI",
            }
        }
        return topotest.json_cmp(output, expected)

    test_func = functools.partial(_test_interface_multicast_disable)
    _, result = topotest.run_and_expect(test_func, None, count=30, wait=1)
    assert result is None, "Multicast bit was set on r1-eth0"

    logger.info("Ensure that these commands are still nominally working")
    rc, o, e = net["r1"].cmd_status('vtysh -c "show interface description vrf all"')
    logger.info(o)
    assert rc == 0

    rc, o, e = net["r1"].cmd_status('vtysh -c "show interface description vrf default"')
    logger.info(o)
    assert rc == 0


def test_pbr_table():
    global fatal_error
    net = get_topogen().net

    # Skip if previous fatal error condition is raised
    if fatal_error != "":
        pytest.skip(fatal_error)

    print("\n\n** Verifying PBR table default route")
    print("******************************************\n")

    # Get the route table output
    output = net["r1"].cmd('vtysh -c "show ip route table 10000 nexthop"').rstrip()

    # Check for default route (0.0.0.0/0)
    if "0.0.0.0/0" not in output:
        fatal_error = "Default route not found in PBR table 10000"
        assert False, fatal_error

    print("Default route found in PBR table 10000")


def test_vtysh_timeout():
    "Test vtysh idle session timeout feature."

    global fatal_error
    tgen = get_topogen()
    net = tgen.net

    # Skip if previous fatal error condition is raised
    if fatal_error != "":
        pytest.skip(fatal_error)
    r1 = tgen.gears["r1"]

    timeout = 20
    logger.info("Testing vtysh with idle timeout of {} seconds".format(timeout))

    p1 = None
    p1 = r1.popen(
        ["vtysh", "--exec-timeout", str(timeout)],
        encoding=None,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
    )

    # Wait for a while, with a bit of buffer time
    errmsg = None
    try:
        p1.wait(timeout + 10)
        retcode = p1.returncode
        if retcode == None:
            p1.terminate()
            errmsg = "Vtysh timeout failed after {} seconds".format(timeout + 10)
    except Exception as e:
        errmsg = "Vtysh timeout failed after {} seconds".format(timeout + 10)

    if errmsg != None:
        assert None, errmsg

    logger.info("Vtysh idle timeout test passed")


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
