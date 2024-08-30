#!/usr/bin/env python
# SPDX-License-Identifier: ISC

#
# test_bfd_ospf_topo1.py
# Part of NetDEF Topology Tests
#
# Copyright (c) 2020 by
# Network Device Education Foundation, Inc. ("NetDEF")
#

"""
test_bfd_ospf_topo1.py:

                        +---------+
                        |         |
           eth-rt2 (.1) |   RT1   | eth-rt3 (.1)
             +----------+ 1.1.1.1 +----------+
             |          |         |          |
             |          +---------+          |
             |                               |
             |                   10.0.2.0/24 |
             |                               |
             |                       eth-rt1 | (.2)
             | 10.0.1.0/24              +----+----+
             |                          |         |
             |                          |   RT3   |
             |                          | 3.3.3.3 |
             |                          |         |
        (.2) | eth-rt1                  +----+----+
        +----+----+                  eth-rt4 | (.1)
        |         |                          |
        |   RT2   |                          |
        | 2.2.2.2 |              10.0.4.0/24 |
        |         |                          |
        +----+----+                          |
        (.1) | eth-rt5               eth-rt3 | (.2)
             |                          +----+----+
             |                          |         |
             |                          |   RT4   |
             |                          | 4.4.4.4 |
             |                          |         |
             |                          +----+----+
             | 10.0.3.0/24           eth-rt5 | (.1)
             |                               |
             |                               |
             |                   10.0.5.0/24 |
             |                               |
             |          +---------+          |
             |          |         |          |
             +----------+   RT5   +----------+
           eth-rt2 (.2) | 5.5.5.5 | eth-rt4 (.2)
                        |         |
                        +---------+

"""

import os
import sys
import pytest
import json
from functools import partial

# Save the Current Working Directory to find configuration files.
CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

# pylint: disable=C0413
# Import topogen and topotest helpers
from lib import topotest
from lib.topogen import Topogen, TopoRouter, get_topogen
from lib.topolog import logger

pytestmark = [pytest.mark.bfdd, pytest.mark.ospfd]


def setup_module(mod):
    "Sets up the pytest environment"
    topodef = {
        "s1": ("rt1:eth-rt2", "rt2:eth-rt1"),
        "s2": ("rt1:eth-rt3", "rt3:eth-rt1"),
        "s3": ("rt2:eth-rt5", "rt5:eth-rt2"),
        "s4": ("rt3:eth-rt4", "rt4:eth-rt3"),
        "s5": ("rt4:eth-rt5", "rt5:eth-rt4"),
    }
    tgen = Topogen(topodef, mod.__name__)
    tgen.start_topology()

    router_list = tgen.routers()

    # For all registered routers, load the zebra configuration file
    for rname, router in router_list.items():
        router.load_config(
            TopoRouter.RD_ZEBRA, os.path.join(CWD, "{}/zebra.conf".format(rname))
        )
        router.load_config(
            TopoRouter.RD_BFD, os.path.join(CWD, "{}/bfdd.conf".format(rname))
        )
        router.load_config(
            TopoRouter.RD_OSPF, os.path.join(CWD, "{}/ospfd.conf".format(rname))
        )
        router.load_config(
            TopoRouter.RD_OSPF6, os.path.join(CWD, "{}/ospf6d.conf".format(rname))
        )

    tgen.start_router()


def teardown_module(mod):
    "Teardown the pytest environment"
    tgen = get_topogen()

    # This function tears down the whole topology.
    tgen.stop_topology()


def print_cmd_result(rname, command):
    print(get_topogen().gears[rname].vtysh_cmd(command, isjson=False))


def router_compare_json_output(rname, command, reference, count=40, wait=2):
    "Compare router JSON output"

    logger.info('Comparing router "%s" "%s" output', rname, command)

    tgen = get_topogen()
    filename = "{}/{}/{}".format(CWD, rname, reference)
    expected = json.loads(open(filename).read())

    # Run test function until we get an result. Wait at most 80 seconds.
    test_func = partial(topotest.router_json_cmp, tgen.gears[rname], command, expected)
    _, diff = topotest.run_and_expect(test_func, None, count=count, wait=wait)
    assertmsg = '"{}" JSON output mismatches the expected result'.format(rname)
    assert diff is None, assertmsg


## TEST STEPS


def test_rib_ospf_step1():
    logger.info("Test (step 1): verify RIB for OSPF")
    tgen = get_topogen()

    # Skip if previous fatal error condition is raised
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    router_compare_json_output(
        "rt1", "show ip route ospf json", "step1/show_ip_route.ref"
    )
    router_compare_json_output(
        "rt1", "show ipv6 route ospf json", "step1/show_ipv6_route.ref"
    )


def test_bfd_ospf_sessions_step2():
    logger.info("Test (step 2): verify BFD peers for OSPF")
    tgen = get_topogen()

    # Skip if previous fatal error condition is raised
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    # BFD is just used on three routers
    for rt in ["rt1", "rt2", "rt3"]:
        router_compare_json_output(
            rt, "show bfd peers json", "step2/show_bfd_peers.ref"
        )


def test_bfd_ospf_interface_failure_rt2_step3():
    logger.info("Test (step 3): Check failover handling with RT2 down")
    tgen = get_topogen()

    # Skip if previous fatal error condition is raised
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    # Let's kill the interface on rt2 and see what happens with the RIB and BFD on rt1
    tgen.gears["rt2"].link_enable("eth-rt1", enabled=False)

    # By default BFD provides a recovery time of 900ms plus jitter, so let's wait
    # initial 2 seconds to let the CI not suffer.
    topotest.sleep(2, "Wait for BFD down notification")

    router_compare_json_output(
        "rt1", "show ip route ospf json", "step3/show_ip_route_rt2_down.ref", 10, 2
    )
    router_compare_json_output(
        "rt1", "show ipv6 route ospf json", "step3/show_ipv6_route_rt2_down.ref", 10, 2
    )
    router_compare_json_output(
        "rt1", "show bfd peers json", "step3/show_bfd_peers_rt2_down.ref", 10, 2
    )

    # Check recovery, this can take some time
    tgen.gears["rt2"].link_enable("eth-rt1", enabled=True)

    router_compare_json_output(
        "rt1", "show ip route ospf json", "step3/show_ip_route_healthy.ref"
    )
    router_compare_json_output(
        "rt1", "show ipv6 route ospf json", "step3/show_ipv6_route_healthy.ref"
    )
    router_compare_json_output(
        "rt1", "show bfd peers json", "step3/show_bfd_peers_healthy.ref"
    )


def test_bfd_ospf_interface_failure_rt3_step3():
    logger.info("Test (step 3): Check failover handling with RT3 down")
    tgen = get_topogen()

    # Skip if previous fatal error condition is raised
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    # Let's kill the interface on rt3 and see what happens with the RIB and BFD on rt1
    tgen.gears["rt3"].link_enable("eth-rt1", enabled=False)

    # By default BFD provides a recovery time of 900ms plus jitter, so let's wait
    # initial 2 seconds to let the CI not suffer.
    topotest.sleep(2, "Wait for BFD down notification")
    router_compare_json_output(
        "rt1", "show ip route ospf json", "step3/show_ip_route_rt3_down.ref", 10, 2
    )
    router_compare_json_output(
        "rt1", "show ipv6 route ospf json", "step3/show_ipv6_route_rt3_down.ref", 10, 2
    )
    router_compare_json_output(
        "rt1", "show bfd peers json", "step3/show_bfd_peers_rt3_down.ref", 10, 2
    )

    # Check recovery, this can take some time
    tgen.gears["rt3"].link_enable("eth-rt1", enabled=True)

    router_compare_json_output(
        "rt1", "show ip route ospf json", "step3/show_ip_route_healthy.ref"
    )
    router_compare_json_output(
        "rt1", "show ipv6 route ospf json", "step3/show_ipv6_route_healthy.ref"
    )
    router_compare_json_output(
        "rt1", "show bfd peers json", "step3/show_bfd_peers_healthy.ref"
    )


def test_memory_leak():
    "Run the memory leak test and report results."
    tgen = get_topogen()
    if not tgen.is_memleak_enabled():
        pytest.skip("Memory leak test/report is disabled")

    tgen.report_memory_leaks()


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
