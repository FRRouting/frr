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

"""
test_bgp_multiview_topo1.py: Simple FRR Route-Server Test

+----------+ +----------+ +----------+ +----------+ +----------+
|  peer1   | |  peer2   | |  peer3   | |  peer4   | |  peer5   |
| AS 65001 | | AS 65002 | | AS 65003 | | AS 65004 | | AS 65005 |
+-----+----+ +-----+----+ +-----+----+ +-----+----+ +-----+----+
      | .1         | .2         | .3         | .4         | .5
      |     ______/            /            /   _________/
       \   /  ________________/            /   /
        | |  /   _________________________/   /     +----------+
        | | |  /   __________________________/   ___|  peer6   |
        | | | |  /  ____________________________/.6 | AS 65006 |
        | | | | |  /  _________________________     +----------+
        | | | | | |  /  __________________     \    +----------+
        | | | | | | |  /                  \     \___|  peer7   |
        | | | | | | | |                    \     .7 | AS 65007 |
     ~~~~~~~~~~~~~~~~~~~~~                  \       +----------+
   ~~         SW1         ~~                 \      +----------+
   ~~       Switch           ~~               \_____|  peer8   |
   ~~    172.16.1.0/24     ~~                    .8 | AS 65008 |
     ~~~~~~~~~~~~~~~~~~~~~                          +----------+
              |
              | .254
    +---------+---------+
    |      FRR R1       |
    |   BGP Multi-View  |
    | Peer 1-3 > View 1 |
    | Peer 4-5 > View 2 |
    | Peer 6-8 > View 3 |
    +---------+---------+
              | .1
              |
        ~~~~~~~~~~~~~        Stub Network is redistributed
      ~~     SW0     ~~      into each BGP view with different
    ~~   172.20.0.1/28  ~~   attributes (using route-map)
      ~~ Stub Switch ~~
        ~~~~~~~~~~~~~
"""

import os
import re
import sys
import glob
from time import sleep
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

from mininet.topo import Topo

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


#####################################################
##
##   Network Topology Definition
##
#####################################################


class NetworkTopo(Topo):
    "BGP Multiview Topology 1"

    def build(self, **_opts):
        tgen = get_topogen(self)

        # Setup Routers
        router = tgen.add_router('r1')

        # Setup Provider BGP peers
        peer = {}
        for i in range(1, 9):
            peer_ip = "172.16.1.{}".format(i)
            peer_route = "via 172.16.1.254"
            peer[i] = tgen.add_exabgp_peer(
                "peer{}".format(i), ip=peer_ip, defaultRoute=peer_route
            )

        # Setup Switches
        sw1 = tgen.add_switch('s1')
        sw1.add_link(router)

        sw2 = tgen.add_switch('s2')
        sw2.add_link(router)

        for i in range(1, 9):
            sw2.add_link(peer[i])


#####################################################
##
##   Tests starting
##
#####################################################


def setup_module(module):
    tgen = Topogen(NetworkTopo, module.__name__)
    tgen.start_topology()

    # Starting Routers
    router = tgen.gears['r1']
    router.load_config(
        TopoRouter.RD_ZEBRA, os.path.join(CWD, "r1/zebra.conf"))
    router.load_config(
        TopoRouter.RD_BGP, os.path.join(CWD, "r1/bgpd.conf"))
    router.start()

    # Starting PE Hosts and init ExaBGP on each of them
    for i in range(1, 9):
        pname = 'peer{}'.format(i)
        peer = tgen.gears[pname]
        peer_dir = os.path.join(CWD, pname)
        env_file = os.path.join(CWD, "exabgp.env")
        other_files = [os.path.join(CWD, 'exabgp-helper.py')]
        peer.start(peer_dir, env_file, other_files)


def teardown_module(module):
    tgen = get_topogen()
    tgen.stop_topology()


def test_bgp_converge():
    "Check for BGP converged on all peers and BGP views"
    tgen = get_topogen()

    # Skip if previous fatal error condition is raised
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    # Wait for BGP to converge  (All Neighbors in either Full or TwoWay State)
    logger.info("\n\n** Verify for BGP to converge")
    logger.info("******************************************\n")
    timeout = 125
    while timeout > 0:
        logger.info("Timeout in %s: " % timeout)
        # Look for any node not yet converged
        for i in range(1, 2):
            for view in range(1, 4):
                notConverged = tgen.net["r%s" % i].cmd(
                    'vtysh -c "show ip bgp view %s summary" 2> /dev/null | grep ^[0-9] | grep -vP " 11\s+(\d+)$"'
                    % view
                )
                if notConverged:
                    logger.info("Waiting for r%s, view %s" % (i, view))
                    break
            if notConverged:
                break
        if notConverged:
            sleep(5)
            timeout -= 5
        else:
            logger.info('Done')
            break
    else:
        # Bail out with error if a router fails to converge
        bgpStatus = tgen.net["r%s" % i].cmd('vtysh -c "show ip bgp view %s summary"' % view)
        assert False, "BGP did not converge:\n%s" % bgpStatus

    # Wait for an extra 5s to announce all routes
    logger.info("Waiting 5s for routes to be announced")
    topotest.sleep(5, 'waiting convergence')

    logger.info("BGP converged.")


def test_bgp_routingTable():
    tgen = get_topogen()

    # Skip if previous fatal error condition is raised
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    logger.info("\n\n** Verifying BGP Routing Tables")
    logger.info("******************************************\n")
    diffresult = {}
    for i in range(1, 2):
        for view in range(1, 4):
            success = 0
            # This glob pattern should work as long as number of views < 10
            for refTableFile in glob.glob(
                "%s/r%s/show_ip_bgp_view_%s*.ref" % (CWD, i, view)
            ):

                if os.path.isfile(refTableFile):
                    # Read expected result from file
                    expected = open(refTableFile).read().rstrip()
                    # Fix newlines (make them all the same)
                    expected = ("\n".join(expected.splitlines()) + "\n").splitlines(1)

                    # Actual output from router
                    actual = (
                        tgen.net["r%s" % i]
                        .cmd('vtysh -c "show ip bgp view %s" 2> /dev/null' % view)
                        .rstrip()
                    )

                    # Fix inconsitent spaces between 0.99.24 and newer versions
                    actual = re.sub("0             0", "0              0", actual)
                    actual = re.sub(
                        r"([0-9])         32768", r"\1          32768", actual
                    )
                    # Remove summary line (changed recently)
                    actual = re.sub(r"Total number.*", "", actual)
                    actual = re.sub(r"Displayed.*", "", actual)
                    actual = actual.rstrip()
                    # Fix table version (ignore it)
                    actual = re.sub(r"(BGP table version is )[0-9]+", r"\1XXX", actual)

                    # Fix newlines (make them all the same)
                    actual = ("\n".join(actual.splitlines()) + "\n").splitlines(1)

                # Generate Diff
                diff = topotest.get_textdiff(
                    actual,
                    expected,
                    title1="actual BGP routing table",
                    title2="expected BGP routing table",
                )

                if diff:
                    diffresult[refTableFile] = diff
                else:
                    success = 1
                    logger.info("template %s matched: r%s ok" % (refTableFile, i))
                    break

            if not success:
                resultstr = "No template matched.\n"
                for f in diffresult.iterkeys():
                    resultstr += (
                        "template %s: r%s failed Routing Table Check for view %s:\n%s\n"
                        % (f, i, view, diffresult[f])
                    )
                raise AssertionError(
                    "Routing Table verification failed for router r%s, view %s:\n%s"
                    % (i, view, resultstr)
                )


def test_shutdown_check_stderr():
    tgen = get_topogen()

    # Skip if previous fatal error condition is raised
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    if os.environ.get("TOPOTESTS_CHECK_STDERR") is None:
        logger.info(
            "SKIPPED final check on StdErr output: Disabled (TOPOTESTS_CHECK_STDERR undefined)\n"
        )
        pytest.skip("Skipping test for Stderr output")

    logger.info("\n\n** Verifying unexpected STDERR output from daemons")
    logger.info("******************************************\n")

    router = tgen.net['r1']
    router.stopRouter()

    log = router.getStdErr("bgpd")
    if log:
        logger.info("\nBGPd StdErr Log:\n" + log)
    log = router.getStdErr("zebra")
    if log:
        logger.info("\nZebra StdErr Log:\n" + log)


def test_shutdown_check_memleak():
    tgen = get_topogen()
    if not tgen.is_memleak_enabled():
        pytest.skip("Memory leak test/report is disabled")

    tgen.report_memory_leaks()


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(["-s"]))
