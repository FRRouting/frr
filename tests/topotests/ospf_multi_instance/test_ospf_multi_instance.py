#!/usr/bin/env python
# test_ospf_multi_instance.py
# Based on test_ospf_topo1.py
#
# Copyright (c) 2021 by Martin Buck, RUAG Schweiz AG
# Copyright (c) 2017 by
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
test_ospf_multi_instance.py:

+----------------+
| r1             |
| ID 0.0.0.1     |
| lo 10.0.0.1/32 |
+----------------+
         | .1
         |
    ~~~~~~~~~~
  ~~          ~~
~~      sw1     ~~
~~ 10.255.0.0/24 ~~
  ~~          ~~
    ~~~~~~~~~~
         |
         | .2
+----------------+
|      ospf 1    |
+----------------+
| r2             |
| ID 0.0.0.2     |
| lo 10.0.0.2/32 |
+----------------+
|      ospf 2    |
+----------------+
         | .2
         |
    ~~~~~~~~~~
  ~~          ~~
~~      sw2     ~~
~~ 10.255.1.0/24 ~~
  ~~          ~~
    ~~~~~~~~~~
         |
         | .3
+----------------+
| r3             |
| ID 0.0.0.3     |
| lo 10.0.0.3/32 |
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


pytestmark = [pytest.mark.ospfd]

#####################################################
##
##   Network Topology Definition
##
#####################################################


class NetworkTopo(Topo):
    "OSPF Multi Instance Test Topology"

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
    if os.environ.get("TOPOTESTS_MININET_CLI") == "ospf-multi-instance:pre_frr":
        tgen.mininet_cli()

    router_list = tgen.routers()
    for rname, router in router_list.items():
        for (rd, conf) in [(TopoRouter.RD_ZEBRA, "zebra.conf"),
                           (TopoRouter.RD_OSPF, "ospfd.conf"),
                           (TopoRouter.RD_OSPF_1, "ospfd-1.conf"),
                           (TopoRouter.RD_OSPF_2, "ospfd-2.conf"),
                          ]:
            confpath = os.path.join(CWD, rname, conf)
            if os.path.exists(confpath):
                router.load_config(rd, confpath)

    # Initialize all routers.
    tgen.start_router()

    # For debugging after starting FRR daemons
    if os.environ.get("TOPOTESTS_MININET_CLI") == "ospf-multi-instance:post_frr":
        tgen.mininet_cli()


def teardown_module(mod):
    "Teardown the pytest environment"
    tgen = get_topogen()
    tgen.stop_topology()


def test_ospf_converged():
    "Check whether all routers have converged"

    tgen = get_topogen()

    # Wait for OSPF to converge  (All Neighbors in either Full or TwoWay State)
    logger.info("Waiting for OSPF convergence")

    # Set up for regex
    pat1 = re.compile("^[0-9]")
    pat2 = re.compile("Full")

    resStr = "NONE"
    timeout = 60
    while timeout > 0:
        logger.info("Timeout in %s: " % timeout),
        sys.stdout.flush()

        # Look for any node not yet converged
        for router, rnode in tgen.routers().items():
            isConverged = False
            for daemon, started in sorted(rnode.net[router].daemons.items()):
                if not daemon.startswith("ospfd") or not started:
                    continue

                (d, instance) = topotest.split_daemon_name_instance(daemon)
                if instance:
                    instance_arg = " {}".format(instance)
                else:
                    instance_arg = ""

                resStr = rnode.vtysh_cmd("show ip ospf" + instance_arg + " neigh")

                isConverged = False

                for line in resStr.splitlines():
                    res1 = pat1.match(line)
                    if res1:
                        isConverged = True
                        res2 = pat2.search(line)

                        if res2 == None:
                            isConverged = False
                            break

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
        assert False, "OSPF did not converge:\n{}".format(resStr)

    logger.info("OSPF converged.")

    # For debugging after OSPF convergence
    if os.environ.get("TOPOTESTS_MININET_CLI") == "ospf-multi-instance:converged":
        tgen.mininet_cli()

    # Make sure that all daemons are still running
    if tgen.routers_have_failure():
        assert tgen.errors == "", tgen.errors


def compare_show_ipv4(rnode, expected):
    """
    Calls 'show ip route' for router `rname` and compare the obtained
    result with the expected output.
    """

    # Use the vtysh output, with some masking to make comparison easy
    current = topotest.ip4_route_zebra(rnode)

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


def test_ospf_routingTable():
    "Test OSPF Routing Table"
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip("skipped because of router(s) failure")

    for router, rnode in tgen.routers().items():
        logger.info('Verifying router "{}" OSPF routing table'.format(router))

        # Load expected results from the command
        reffile = os.path.join(CWD, "{}/ospfroute.txt".format(router))
        expected = open(reffile).read()

        # Run test function until we get an result. Wait at most 80 seconds.
        test_func = partial(compare_show_ipv4, rnode, expected)
        result, diff = topotest.run_and_expect(test_func, "", count=160, wait=0.5)
        assert result, "OSPF Routing Table verification failed for router {}:\n{}".format(router, diff)


def test_ospf_kernel_route():
    "Test OSPF kernel route installation"
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip("skipped because of router(s) failure")

    rlist = tgen.routers().values()
    for router in rlist:
        logger.info('Checking OSPF IPv4 kernel routes in "%s"', router.name)

        routes = topotest.ip4_route(router)

        expected = {
            "r1": {
                "10.0.0.2": {},
                "10.0.0.3": {},
                "10.255.0.0/24": {},
            },
            "r2": {
                "10.0.0.1": {},
                "10.0.0.3": {},
                "10.255.0.0/24": {},
                "10.255.1.0/24": {},
            },
            "r3": {
                "10.255.1.0/24": {},
            },
        }
        assertmsg = 'OSPF IPv4 route mismatch in router "{}"'.format(router.name)
        assert topotest.json_cmp(routes, expected[router.name]) is None, assertmsg


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
