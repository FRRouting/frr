#!/usr/bin/env python
#
# test_ospf6_dr_no_netlsa_bug7030.py
# Try to reproduce #7030, based on test_ospf6_topo1.py
#
# Copyright (c) 2020 by Martin Buck, RUAG Schweiz AG
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
test_ospf6_dr_no_netlsa_bug7030.py:

Topotest to check for https://github.com/FRRouting/frr/issues/7030
(ospf6d: Sometimes DR doesn't originate Network LSA after reboot)

We repeatedly restart r2 to trigger the missing network LSA bug. Before the
restart, we disconnect r2 from r1 and r3. This way, r2's pre-restart network
LSAs will remain on r1/r3 and reappear on r2 after the restart. We disconnect
r2 by disabling the links between sw1/sw2 and sw3/sw4. This way, r2 doesn't
see "link down" and will become DR again on its links after the restart
(without being DR, it doesn't have to originate network LSAs so the bug
will not show up).

After reconnecting to r1 and r3, r2 will remain DR on the link to r1 due to
its higher router ID. If if fails to originate a network LSA for that link,
we will notice because r1/r2/r3's OSPF routes will not match (r1 will not
see routes to r2/r3 due to the missing network LSA).

Note: The bug is timing dependent, usually a few (10-50) iterations will be
required for it to show up.


Topology below. Links between routers use IPv6 link-local adressing, in
addition routers have one global address on their loopback interface (passive
interface in OSPF) which gets distributed:

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
    ~~~~~~~~~~
  ~~          ~~
~~      sw2     ~~
  ~~          ~~
    ~~~~~~~~~~
         |
         |
+----------------+
| r2             |
| ID 0.0.0.2     |
| lo fc00::2/128 |
+----------------+
         |
         |
    ~~~~~~~~~~
  ~~          ~~
~~      sw3     ~~
  ~~          ~~
    ~~~~~~~~~~
         |
         |
    ~~~~~~~~~~
  ~~          ~~
~~      sw4     ~~
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

# Long running test, only run on request (option --runall)
pytestmark = pytest.mark.skip_by_default


#####################################################
##
##   Network Topology Definition
##
#####################################################


class NetworkTopo(Topo):
    "OSPFv3 (IPv6) Test Topology to check for #7030"

    def build(self, **_opts):
        tgen = get_topogen(self)

        tgen.add_router("r1")
        tgen.add_router("r2")
        tgen.add_router("r3")
        
        tgen.add_switch("sw1")
        tgen.add_switch("sw2")
        tgen.add_switch("sw3")
        tgen.add_switch("sw4")
        tgen.gears["sw1"].add_link(tgen.gears["r1"], nodeif="r1-sw1")
        tgen.gears["sw1"].add_link(tgen.gears["sw2"], myif="sw1-sw2", nodeif="sw2-sw1")
        tgen.gears["sw2"].add_link(tgen.gears["r2"], nodeif="r2-sw2")
        tgen.gears["sw3"].add_link(tgen.gears["r2"], nodeif="r2-sw3")
        tgen.gears["sw3"].add_link(tgen.gears["sw4"], myif="sw3-sw4", nodeif="sw4-sw3")
        tgen.gears["sw4"].add_link(tgen.gears["r3"], nodeif="r3-sw4")


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

    # For debugging after starting net, but before starting FRR,
    # uncomment the next line
    # tgen.mininet_cli()

    router_list = tgen.routers()
    for rname, router in router_list.items():
        router.load_config(
            TopoRouter.RD_ZEBRA, os.path.join(CWD, "{}/zebra.conf".format(rname))
        )
        router.load_config(
            TopoRouter.RD_OSPF6, os.path.join(CWD, "{}/ospf6d.conf".format(rname))
        )

    # Initialize all routers.
    tgen.start_router()

    # For debugging after starting FRR daemons, uncomment the next line
    # tgen.mininet_cli()


def teardown_module(mod):
    "Teardown the pytest environment"
    tgen = get_topogen()
    tgen.stop_topology()


def _check_ospf6_converged():
    "Check whether all routers have converged"

    tgen = get_topogen()

    # For debugging, uncomment the next line
    # tgen.mininet_cli()

    # Wait for OSPF6 to converge  (All Neighbors in either Full or TwoWay State)
    logger.info("Waiting for OSPF6 convergence")

    # Set up for regex
    pat1 = re.compile("^[0-9]")
    pat2 = re.compile("Full")
    pat3 = re.compile(r"[a-z0-9-]+\[[A-Z]+\]")

    timeout = 60
    while timeout > 0:
        logger.info("Timeout in %s: " % timeout),
        sys.stdout.flush()

        # Look for any node not yet converged
        dr_bdr_states = []
        for router, rnode in tgen.routers().items():
            resStr = rnode.vtysh_cmd("show ipv6 ospf neigh")

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

            if isConverged == False:
                logger.info("Waiting for {}".format(router))
                sys.stdout.flush()
                break

        if isConverged:
            logger.info("Done")
            break
        else:
            sleep(5)
            timeout -= 5

    if timeout == 0:
        # Bail out with error if a router fails to converge
        ospfStatus = rnode.vtysh_cmd("show ipv6 ospf neigh")
        assert False, "OSPFv6 did not converge:\n{}".format(ospfStatus)

    logger.info("OSPFv3 converged.")
    logger.info("DR/BDR summary: {}".format(" ".join(sorted(dr_bdr_states))))

    # For debugging, uncomment the next line
    # tgen.mininet_cli()

    # Make sure that all daemons are still running
    if tgen.routers_have_failure():
        assert tgen.errors == "", tgen.errors


def test_dr_no_netlsa_bug7030():
    tgen = get_topogen()
    routers = tgen.routers()
    
    _check_ospf6_converged()
    for test_iter in xrange(100):
        logger.info("Iteration {}".format(test_iter))
        tgen.gears["sw1"].link_enable("sw1-sw2", enabled=False)
        tgen.gears["sw3"].link_enable("sw3-sw4", enabled=False)
        logger.info("Restarting r2 while disconnected")
        routers["r2"].stop()

        # Keep previous logs (they'd get overwritten when calling start() below)
        logname = "{}/{}/ospf6d.log".format(routers["r2"].logdir, routers["r2"].name)
        shutil.copyfile(logname, logname + ".prev")

        routers["r2"].start()
        logger.info("Waiting for r2 to become DR")
        sleep(40)
        tgen.gears["sw1"].link_enable("sw1-sw2")
        tgen.gears["sw3"].link_enable("sw3-sw4")
        _check_ospf6_converged()
        
        # Check whether all routers have the same number of OSPF routes
        logger.info("Checking number of OSPF6 routes")
        routes = {}
        for router, rnode in tgen.routers().items():
            res = rnode.vtysh_cmd("show ipv6 route ospf6")
            routes[router] = 0
            for line in res.splitlines():
                if line.startswith("O"):
                    routes[router] += 1
        logger.info("OSPF6 number of routes: {}".format(", ".join(["{}: {}".format(router, nroutes) for router, nroutes in  routes.items()])))
        if routes.values() != [len(routes)] * len(routes):
            for router, rnode in tgen.routers().items():
                dump = ["Error dump router {}:".format(router)]
                dump.extend(rnode.vtysh_cmd("show ipv6 ospf6 neighbor").splitlines())
                dump.extend(rnode.vtysh_cmd("show ipv6 route ospf6").splitlines())
                dump.extend(rnode.vtysh_cmd("show ipv6 ospf6 database network").splitlines())
                for l in dump:
                    logger.info(l)
            assert False, "OSPF6 routes differ on routers"


def test_memory_leak():
    "Run the memory leak test and report results."
    tgen = get_topogen()
    if not tgen.is_memleak_enabled():
        pytest.skip("Memory leak test/report is disabled")

    tgen.report_memory_leaks()


if __name__ == "__main__":
    retval = pytest.main(["-s"])
    sys.exit(retval)
