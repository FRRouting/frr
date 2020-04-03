#!/usr/bin/env python

#
# test_bgp_ipv6_rtadv.py
# Part of NetDEF Topology Tests
#
# Copyright (c) 2019 by 6WIND
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
 test_bgp_ipv6_rtadv.py: Test the FRR/Quagga BGP daemon with BGP IPv6 interface
 with route advertisements on a separate netns.
"""

import os
import sys
import json
from functools import partial
import pytest
import platform

# Save the Current Working Directory to find configuration files.
CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

# pylint: disable=C0413
# Import topogen and topotest helpers
from lib import topotest
from lib.topogen import Topogen, TopoRouter, get_topogen
from lib.topolog import logger

# Required to instantiate the topology builder class.
from mininet.topo import Topo


class BGPIPV6RTADVVRFTopo(Topo):
    "Test topology builder"

    def build(self, *_args, **_opts):
        "Build function"
        tgen = get_topogen(self)

        # Create 2 routers.
        tgen.add_router("r1")
        tgen.add_router("r2")

        switch = tgen.add_switch("s1")
        switch.add_link(tgen.gears["r1"])
        switch.add_link(tgen.gears["r2"])


def setup_module(mod):
    "Sets up the pytest environment"
    tgen = Topogen(BGPIPV6RTADVVRFTopo, mod.__name__)
    tgen.start_topology()

    router_list = tgen.routers()

    logger.info("Testing with VRF Lite support")
    krel = platform.release()

    # May need to adjust handling of vrf traffic depending on kernel version
    l3mdev_accept = 0
    if (
        topotest.version_cmp(krel, "4.15") >= 0
        and topotest.version_cmp(krel, "4.18") <= 0
    ):
        l3mdev_accept = 1

    if topotest.version_cmp(krel, "5.0") >= 0:
        l3mdev_accept = 1

    logger.info(
        "krel '{0}' setting net.ipv4.tcp_l3mdev_accept={1}".format(krel, l3mdev_accept)
    )

    cmds = [
        "ip link add {0}-cust1 type vrf table 1001",
        "ip link add loop1 type dummy",
        "ip link set loop1 master {0}-cust1",
        "ip link set {0}-eth0 master {0}-cust1",
    ]

    for rname, router in router_list.iteritems():
        for cmd in cmds:
            output = tgen.net[rname].cmd(cmd.format(rname))

        output = tgen.net[rname].cmd("sysctl -n net.ipv4.tcp_l3mdev_accept")
        logger.info(
            "router {0}: existing tcp_l3mdev_accept was {1}".format(rname, output)
        )

        if l3mdev_accept:
            output = tgen.net[rname].cmd(
                "sysctl -w net.ipv4.tcp_l3mdev_accept={}".format(l3mdev_accept)
            )

    for rname, router in router_list.iteritems():
        router.load_config(
            TopoRouter.RD_ZEBRA, os.path.join(CWD, "{}/zebra.conf".format(rname))
        )
        router.load_config(
            TopoRouter.RD_BGP, os.path.join(CWD, "{}/bgpd.conf".format(rname))
        )

    # Initialize all routers.
    tgen.start_router()


def teardown_module(_mod):
    "Teardown the pytest environment"
    tgen = get_topogen()

    tgen.stop_topology()


def test_protocols_convergence():
    """
    Assert that all protocols have converged
    statuses as they depend on it.
    """
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    # Check IPv4 routing tables.
    logger.info("Checking IPv4 routes for convergence")

    for router in tgen.routers().values():
        json_file = "{}/{}/ipv4_routes.json".format(CWD, router.name)
        if not os.path.isfile(json_file):
            logger.info("skipping file {}".format(json_file))
            continue

        expected = json.loads(open(json_file).read())
        test_func = partial(
            topotest.router_json_cmp,
            router,
            "show ip route vrf {}-cust1 json".format(router.name),
            expected,
        )
        _, result = topotest.run_and_expect(test_func, None, count=160, wait=0.5)
        assertmsg = '"{}" JSON output mismatches'.format(router.name)
        assert result is None, assertmsg

    # Check IPv6 routing tables.
    logger.info("Checking IPv6 routes for convergence")
    for router in tgen.routers().values():
        json_file = "{}/{}/ipv6_routes.json".format(CWD, router.name)
        if not os.path.isfile(json_file):
            logger.info("skipping file {}".format(json_file))
            continue

        expected = json.loads(open(json_file).read())
        test_func = partial(
            topotest.router_json_cmp,
            router,
            "show ipv6 route vrf {}-cust1 json".format(router.name),
            expected,
        )
        _, result = topotest.run_and_expect(test_func, None, count=160, wait=0.5)
        assertmsg = '"{}" JSON output mismatches'.format(router.name)
        assert result is None, assertmsg


def test_memory_leak():
    "Run the memory leak test and report results."
    tgen = get_topogen()
    if not tgen.is_memleak_enabled():
        pytest.skip("Memory leak test/report is disabled")

    tgen.report_memory_leaks()


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
