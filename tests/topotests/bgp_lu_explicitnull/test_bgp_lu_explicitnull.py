#!/usr/bin/env python
# SPDX-License-Identifier: ISC
#
# test_bgp_explicitnull.py
#
# Part of NetDEF Topology Tests
#
# Copyright 2023 by 6WIND S.A.
#

"""
test_bgp_lu_explicitnull.py: Test BGP LU label allocation
"""

import os
import sys
import json
import functools
import pytest

# Save the Current Working Directory to find configuration files.
CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

# pylint: disable=C0413
# Import topogen and topotest helpers
from lib import topotest
from lib.topogen import Topogen, TopoRouter, get_topogen
from lib.topolog import logger


pytestmark = [pytest.mark.bgpd]


# Basic scenario for BGP-LU. Nodes are directly connected.
# The 192.168.2.2/32 prefix is advertised from r2 to r1
# The explicit-null label should be used
# The 192.168.2.1/32 prefix is advertised from r1 to r2
# The explicit-null label should be used
# Traffic from 192.168.2.1 to 192.168.2.2 should use explicit-null label
#
#  AS65500    BGP-LU        AS65501
# +-----+                +-----+
# |     |.1            .2|     |
# |  1  +----------------+  2  + 192.168.0.2/32
# |     |   192.0.2.0/24 |     |
# +-----+                +-----+


def build_topo(tgen):
    "Build function"

    # Create routers
    tgen.add_router("r1")
    tgen.add_router("r2")

    # r1-r2
    switch = tgen.add_switch("s1")
    switch.add_link(tgen.gears["r1"])
    switch.add_link(tgen.gears["r2"])

    # r1
    switch = tgen.add_switch("s2")
    switch.add_link(tgen.gears["r1"])

    # r2
    switch = tgen.add_switch("s3")
    switch.add_link(tgen.gears["r2"])


def setup_module(mod):
    "Sets up the pytest environment"
    # This function initiates the topology build with Topogen...
    tgen = Topogen(build_topo, mod.__name__)

    # Skip if no mpls support
    if not tgen.hasmpls:
        logger.info("MPLS is not available, skipping test")
        pytest.skip("MPLS is not available, skipping")
        return

    # ... and here it calls Mininet initialization functions.
    tgen.start_topology()

    # This is a sample of configuration loading.
    router_list = tgen.routers()

    # Enable mpls input for routers, so we can ping
    sval = "net.mpls.conf.{}.input"
    topotest.sysctl_assure(router_list["r2"], sval.format("r2-eth0"), 1)
    topotest.sysctl_assure(router_list["r1"], sval.format("r1-eth0"), 1)

    # For all registred routers, load the zebra configuration file
    for rname, router in router_list.items():
        router.load_config(
            TopoRouter.RD_ZEBRA, os.path.join(CWD, "{}/zebra.conf".format(rname))
        )
        router.load_config(
            TopoRouter.RD_BGP, os.path.join(CWD, "{}/bgpd.conf".format(rname))
        )

    # After loading the configurations, this function loads configured daemons.
    tgen.start_router()


def teardown_module(mod):
    "Teardown the pytest environment"
    tgen = get_topogen()

    # This function tears down the whole topology.
    tgen.stop_topology()


def check_show_ip_label_prefix_found(router, ipversion, prefix, label):
    output = json.loads(
        router.vtysh_cmd("show {} route {} json".format(ipversion, prefix))
    )
    expected = {
        prefix: [
            {"prefix": prefix, "nexthops": [{"fib": True, "labels": [int(label)]}]}
        ]
    }
    return topotest.json_cmp(output, expected)


def test_converge_bgplu():
    "Wait for protocol convergence"

    tgen = get_topogen()
    # Don't run this test if we have any failure.
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    # tgen.mininet_cli();
    r1 = tgen.gears["r1"]
    r2 = tgen.gears["r2"]
    # Check r1 gets prefix 192.168.2.2/32
    test_func = functools.partial(
        check_show_ip_label_prefix_found,
        tgen.gears["r1"],
        "ip",
        "192.168.2.2/32",
        "0",
    )
    success, _ = topotest.run_and_expect(test_func, None, count=10, wait=0.5)
    assert success, "r1, prefix 192.168.2.2/32 from r2 not present"

    # Check r2 gets prefix 192.168.2.1/32
    test_func = functools.partial(
        check_show_ip_label_prefix_found,
        tgen.gears["r2"],
        "ip",
        "192.168.2.1/32",
        "0",
    )
    success, _ = topotest.run_and_expect(test_func, None, count=10, wait=0.5)
    assert success, "r2, prefix 192.168.2.1/32 from r1 not present"


def test_traffic_connectivity():
    "Wait for protocol convergence"

    tgen = get_topogen()
    # Don't run this test if we have any failure.
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    def _check_ping(name, dest_addr, src_addr):
        tgen = get_topogen()
        output = tgen.gears[name].run(
            "ping {} -c 1 -w 1 -I {}".format(dest_addr, src_addr)
        )
        logger.info(output)
        if " 0% packet loss" not in output:
            return True

    logger.info("r1, check ping 192.168.2.2 from 192.168.2.1 is OK")
    tgen = get_topogen()
    func = functools.partial(_check_ping, "r1", "192.168.2.2", "192.168.2.1")
    # tgen.mininet_cli()
    _, result = topotest.run_and_expect(func, None, count=10, wait=0.5)
    assert result is None, "r1, ping to 192.168.2.2 from 192.168.2.1 fails"


def test_memory_leak():
    "Run the memory leak test and report results."
    tgen = get_topogen()
    if not tgen.is_memleak_enabled():
        pytest.skip("Memory leak test/report is disabled")

    tgen.report_memory_leaks()


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
