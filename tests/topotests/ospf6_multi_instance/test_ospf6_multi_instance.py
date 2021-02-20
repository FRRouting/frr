#!/usr/bin/env python
# test_ospf6_multi_instance.py
# Based on test_ospf6_topo1.py
#
# Copyright (c) 2021 by Martin Buck, RUAG Schweiz AG
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

"""
test_ospf6_multi_instance.py:

+----------------+
| r1             |
| ID 0.0.0.1     |
| lo fc00::1/128 |
+----------------+
         |
         |
    ~~~~~~~~~~
  ~~          ~~
~~      sw1     ~~
  ~~          ~~
    ~~~~~~~~~~
         |
         |
+----------------+
|     ospf6 1    |
+----------------+
| r2             |
| ID 0.0.0.2     |
| ID 1.0.0.2     |
| lo fc00::2/128 |
+----------------+
|     ospf6 2    |
+----------------+
         |
         |
    ~~~~~~~~~~
  ~~          ~~
~~      sw2     ~~
  ~~          ~~
    ~~~~~~~~~~
         |
         |
+----------------+
| r3             |
| ID 0.0.0.3     |
| lo fc00::3/128 |
+----------------+
"""

import os
import re
import shutil
import sys
import pytest
from time import sleep

from functools import partial

from mininet.topo import Topo

# Save the Current Working Directory to find configuration files later.
CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

# pylint: disable=C0413
# Import topogen and topotest helpers
from lib import topotest
from lib.topogen import Topogen, TopoRouter, get_topogen
from lib.topolog import logger
import platform


pytestmark = [pytest.mark.ospf6d]

#####################################################
##
##   Network Topology Definition
##
#####################################################


class NetworkTopo(Topo):
    "OSPFv3 (IPv6) Multi Instance Test Topology"

    def build(self, **_opts):
        tgen = get_topogen(self)

        tgen.add_router("r1")
        tgen.add_router("r2")
        tgen.add_router("r3")
        tgen.add_switch("sw1")
        tgen.add_switch("sw2")
        tgen.gears["sw1"].add_link(tgen.gears["r1"], nodeif="r1-sw1")
        tgen.gears["sw1"].add_link(tgen.gears["r2"], nodeif="r2-sw1")
        tgen.gears["sw2"].add_link(tgen.gears["r2"], nodeif="r2-sw2")
        tgen.gears["sw2"].add_link(tgen.gears["r3"], nodeif="r3-sw2")


#####################################################
##
##   Tests starting
##
#####################################################


def setup_module(mod):
    "Sets up the pytest environment"

    tgen = Topogen(NetworkTopo, mod.__name__)
    tgen.start_topology()

    logger.info("** %s: Setup Topology" % mod.__name__)
    logger.info("******************************************")

    # For debugging after starting net, but before starting FRR
    if os.environ.get("TOPOTESTS_MININET_CLI") == "ospf6-multi-instance:pre_frr":
        tgen.mininet_cli()

    router_list = tgen.routers()
    for rname, router in router_list.items():
        for (rd, conf) in [(TopoRouter.RD_ZEBRA, "zebra.conf"),
                           (TopoRouter.RD_OSPF6, "ospf6d.conf"),
                           (TopoRouter.RD_OSPF6_1, "ospf6d-1.conf"),
                           (TopoRouter.RD_OSPF6_2, "ospf6d-2.conf"),
                          ]:
            confpath = os.path.join(CWD, rname, conf)
            if os.path.exists(confpath):
                router.load_config(rd, confpath)

    # Initialize all routers.
    tgen.start_router()

    # For debugging after starting FRR daemons
    if os.environ.get("TOPOTESTS_MININET_CLI") == "ospf6-multi-instance:post_frr":
        tgen.mininet_cli()


def teardown_module(mod):
    "Teardown the pytest environment"
    tgen = get_topogen()
    tgen.stop_topology()


def test_ospf6_converged():
    "Check whether all routers have converged"

    tgen = get_topogen()

    # For debugging, uncomment the next line
    # gen.mininet_cli()

    # Wait for OSPF6 to converge  (All Neighbors in either Full or TwoWay State)
    logger.info("Waiting for OSPF6 convergence")

    # Set up for regex
    pat1 = re.compile("^[0-9]")
    pat2 = re.compile("Full")
    pat3 = re.compile(r"[a-z0-9-]+\[[A-Z]+\]")

    resStr = "NONE"
    timeout = 60
    while timeout > 0:
        logger.info("Timeout in %s: " % timeout),
        sys.stdout.flush()

        # Look for any node not yet converged
        dr_bdr_states = []
        for router, rnode in tgen.routers().items():
            isConverged = False
            for daemon, started in sorted(rnode.net[router].daemons.items()):
                if not daemon.startswith("ospf6d") or not started:
                    continue

                (d, instance) = topotest.split_daemon_name_instance(daemon)
                if instance:
                    instance_arg = " {}".format(instance)
                else:
                    instance_arg = ""

                resStr = rnode.vtysh_cmd("show ipv6 ospf" + instance_arg + " neigh")

                isConverged = False

                for line in resStr.splitlines():
                    res1 = pat1.match(line)
                    if res1:
                        isConverged = True
                        res2 = pat2.search(line)

                        if res2 == None:
                            isConverged = False
                            break
                    
                        res3 = pat3.search(line)
                        if res3:
                            dr_bdr_states.append(res3.group())

                if not isConverged:
                    logger.info("Waiting for {}{}".format(router, instance_arg))
                    sys.stdout.flush()
                    break

            if not isConverged:
                break

        if isConverged:
            logger.info("Done")
            break
        else:
            sleep(5)
            timeout -= 5

    if timeout <= 0:
        # Bail out with error if a router fails to converge
        assert False, "OSPFv3 did not converge:\n{}".format(resStr)

    logger.info("OSPFv3 converged.")
    logger.info("DR/BDR summary: {}".format(" ".join(sorted(dr_bdr_states))))

    # For debugging after OSPFv3 convergence
    if os.environ.get("TOPOTESTS_MININET_CLI") == "ospf6-multi-instance:converged":
        tgen.mininet_cli()

    # Make sure that all daemons are still running
    if tgen.routers_have_failure():
        assert tgen.errors == "", tgen.errors


def compare_show_ipv6(rname, expected):
    """
    Calls 'show ipv6 route' for router `rname` and compare the obtained
    result with the expected output.
    """
    tgen = get_topogen()

    # Use the vtysh output, with some masking to make comparison easy
    current = topotest.ip6_route_zebra(tgen.gears[rname])

    # Use just the 'O'spf lines of the output
    linearr = []
    for line in current.splitlines():
        if re.match("^O", line):
            linearr.append(line)

    current = "\n".join(linearr)

    return topotest.difflines(
        topotest.normalize_text(current),
        topotest.normalize_text(expected),
        title1="Current output",
        title2="Expected output",
    )


def test_ospfv3_routingTable():

    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip("skipped because of router(s) failure")

    # For debugging, uncomment the next line
    # tgen.mininet_cli()

    # Verify OSPFv3 Routing Table
    for router, rnode in tgen.routers().items():
        logger.info('Verifying router "%s" OSPFv3 Routing Table', router)

        # Load expected results from the command
        reffile = os.path.join(CWD, "{}/show_ipv6_route.ref".format(router))
        expected = open(reffile).read()

        # Run test function until we get an result. Wait at most 60 seconds.
        test_func = partial(compare_show_ipv6, router, expected)
        result, diff = topotest.run_and_expect(test_func, "", count=120, wait=0.5)
        assert result, "OSPFv3 Routing Table verification failed for router {}:\n{}".format(router, diff)


def test_linux_ipv6_kernel_routingTable():

    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip("skipped because of router(s) failure")

    # Verify Linux Kernel Routing Table
    logger.info("Verifying Linux IPv6 Kernel Routing Table")

    failures = 0

    # Get a list of all current link-local addresses first as they change for
    # each run and we need to translate them
    linklocals = []
    for router, rnode in tgen.routers().items():
        linklocals += rnode.net[router].get_ipv6_linklocal()

    # Now compare the routing tables (after substituting link-local addresses)
    for router, rnode in tgen.routers().items():
        # Actual output from router
        actual = tgen.gears[router].run("ip -6 route").rstrip()
        if "nhid" in actual:
            refTableFile = os.path.join(CWD, "{}/ip_6_address.nhg.ref".format(router))
        else:
            refTableFile = os.path.join(CWD, "{}/ip_6_address.ref".format(router))

        if os.path.isfile(refTableFile):
            expected = open(refTableFile).read().rstrip()
            # Fix newlines (make them all the same)
            expected = ("\n".join(expected.splitlines())).splitlines(1)

            # Mask out Link-Local mac addresses
            for ll in linklocals:
                actual = actual.replace(ll[1], "fe80::__(%s)__" % ll[0])
            # Mask out protocol name or number
            actual = re.sub(r"[ ]+proto [0-9a-z]+ +", "  proto XXXX ", actual)
            actual = re.sub(r"[ ]+nhid [0-9]+ +", " nhid XXXX ", actual)
            # Remove ff00::/8 routes (seen on some kernels - not from FRR)
            actual = re.sub(r"ff00::/8.*", "", actual)
            # Convert "unreachable loopback" routes to normal ones by
            # stripping the unreachable and the error code. These only
            # occur with Linux kernels < 4.18 and they work just fine for
            # OSPF except for the different routing table output which
            # would cause spurious test failures.
            actual = re.sub(r"unreachable (.* dev lo .* )error -101 (.*)", r"\1\2", actual)

            # Strip empty lines
            actual = actual.lstrip()
            actual = actual.rstrip()
            actual = re.sub(r"  +", " ", actual)

            filtered_lines = []
            for line in sorted(actual.splitlines()):
                if line.startswith("fe80::/64 ") or line.startswith(
                    "unreachable fe80::/64 "
                ):
                    continue
                filtered_lines.append(line)
            actual = "\n".join(filtered_lines).splitlines(1)

            # Print Actual table
            # logger.info("Router %s table" % router)
            # for line in actual:
            #     logger.info(line.rstrip())

            # Generate Diff
            diff = topotest.get_textdiff(
                actual,
                expected,
                title1="actual OSPFv3 IPv6 routing table",
                title2="expected OSPFv3 IPv6 routing table",
            )

            # Empty string if it matches, otherwise diff contains unified diff
            if diff:
                sys.stderr.write(
                    "%s failed Linux IPv6 Kernel Routing Table Check:\n%s\n"
                    % (router, diff)
                )
                failures += 1
            else:
                logger.info("%s ok" % router)

            assert failures == 0, (
                "Linux Kernel IPv6 Routing Table verification failed for router %s:\n%s"
                % (router, diff)
            )


def test_shutdown_check_stderr():

    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip("skipped because of router(s) failure")

    if os.environ.get("TOPOTESTS_CHECK_STDERR") is None:
        logger.info(
            "SKIPPED final check on StdErr output: Disabled (TOPOTESTS_CHECK_STDERR undefined)\n"
        )
        pytest.skip("Skipping test for Stderr output")

    logger.info("\n\n** Verifying unexpected STDERR output from daemons")
    logger.info("******************************************")

    for router, rnode in tgen.routers().items():
        rnode.net[router].stopRouter()

        for daemon, started in sorted(rnode.net[router].daemons.items()):
            if not started:
                continue
            log = rnode.net[router].getStdErr(daemon)
            if log:
                logger.info("\nRouter %s %s StdErr Log:\n%s" % (router, daemon, log))


def test_shutdown_check_memleak():
    "Run the memory leak test and report results."

    if os.environ.get("TOPOTESTS_CHECK_MEMLEAK") is None:
        logger.info(
            "SKIPPED final check on Memory leaks: Disabled (TOPOTESTS_CHECK_MEMLEAK undefined)"
        )
        pytest.skip("Skipping test for memory leaks")

    tgen = get_topogen()

    for router, rnode in tgen.routers().items():
        rnode.net[router].stopRouter()
        rnode.net[router].report_memory_leaks(
            os.environ.get("TOPOTESTS_CHECK_MEMLEAK"), os.path.basename(__file__)
        )


if __name__ == "__main__":
    retval = pytest.main(["-s"])
    sys.exit(retval)
