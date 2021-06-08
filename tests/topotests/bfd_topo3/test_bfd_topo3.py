#!/usr/bin/env python

#
# test_bfd_topo3.py
# Part of NetDEF Topology Tests
#
# Copyright (c) 2020 by
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
test_bfd_topo3.py: Test the FRR BFD daemon multi hop.
"""

import os
import sys
import json
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

# Required to instantiate the topology builder class.
from mininet.topo import Topo

pytestmark = [pytest.mark.bfdd, pytest.mark.bgpd]


class BFDTopo(Topo):
    "Test topology builder"

    def build(self, *_args, **_opts):
        "Build function"
        tgen = get_topogen(self)

        # Create 6 routers.
        for routern in range(1, 7):
            tgen.add_router("r{}".format(routern))

        switch = tgen.add_switch("s1")
        switch.add_link(tgen.gears["r1"])
        switch.add_link(tgen.gears["r2"])

        switch = tgen.add_switch("s2")
        switch.add_link(tgen.gears["r2"])
        switch.add_link(tgen.gears["r3"])

        switch = tgen.add_switch("s3")
        switch.add_link(tgen.gears["r3"])
        switch.add_link(tgen.gears["r4"])

        switch = tgen.add_switch("s4")
        switch.add_link(tgen.gears["r4"])
        switch.add_link(tgen.gears["r5"])
        switch.add_link(tgen.gears["r6"])


def setup_module(mod):
    "Sets up the pytest environment"
    tgen = Topogen(BFDTopo, mod.__name__)
    tgen.start_topology()

    router_list = tgen.routers()
    for rname, router in router_list.items():
        daemon_file = "{}/{}/bfdd.conf".format(CWD, rname)
        if os.path.isfile(daemon_file):
            router.load_config(TopoRouter.RD_BFD, daemon_file)

        daemon_file = "{}/{}/zebra.conf".format(CWD, rname)
        if os.path.isfile(daemon_file):
            router.load_config(TopoRouter.RD_ZEBRA, daemon_file)

        daemon_file = "{}/{}/bgpd.conf".format(CWD, rname)
        if os.path.isfile(daemon_file):
            router.load_config(TopoRouter.RD_BGP, daemon_file)

        daemon_file = "{}/{}/staticd.conf".format(CWD, rname)
        if os.path.isfile(daemon_file):
            router.load_config(TopoRouter.RD_STATIC, daemon_file)

    # Initialize all routers.
    tgen.start_router()


def test_wait_bgp_convergence():
    "Wait for BGP to converge"
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    logger.info("waiting for protocols to converge")

    def expect_loopback_route(router, iptype, route, proto):
        "Wait until route is present on RIB for protocol."
        logger.info("waiting route {} in {}".format(route, router))
        test_func = partial(
            topotest.router_json_cmp,
            tgen.gears[router],
            "show {} route json".format(iptype),
            {route: [{"protocol": proto}]},
        )
        _, result = topotest.run_and_expect(test_func, None, count=130, wait=1)
        assertmsg = '"{}" OSPF convergence failure'.format(router)
        assert result is None, assertmsg

    # Wait for R1 <-> R2 convergence.
    expect_loopback_route("r1", "ip", "10.254.254.2/32", "bgp")
    # Wait for R1 <-> R3 convergence.
    expect_loopback_route("r1", "ip", "10.254.254.3/32", "bgp")
    # Wait for R1 <-> R4 convergence.
    expect_loopback_route("r1", "ip", "10.254.254.4/32", "bgp")
    # Wait for R1 <-> R5 convergence.
    expect_loopback_route("r1", "ip", "10.254.254.5/32", "bgp")
    # Wait for R1 <-> R6 convergence.
    expect_loopback_route("r1", "ip", "10.254.254.6/32", "bgp")

    # Wait for R2 <-> R1 convergence.
    expect_loopback_route("r2", "ip", "10.254.254.1/32", "bgp")
    # Wait for R2 <-> R3 convergence.
    expect_loopback_route("r2", "ip", "10.254.254.3/32", "bgp")
    # Wait for R2 <-> R4 convergence.
    expect_loopback_route("r2", "ip", "10.254.254.4/32", "bgp")
    # Wait for R2 <-> R5 convergence.
    expect_loopback_route("r2", "ip", "10.254.254.5/32", "bgp")
    # Wait for R2 <-> R6 convergence.
    expect_loopback_route("r2", "ip", "10.254.254.6/32", "bgp")

    # Wait for R3 <-> R1 convergence.
    expect_loopback_route("r3", "ip", "10.254.254.1/32", "bgp")
    # Wait for R3 <-> R2 convergence.
    expect_loopback_route("r3", "ip", "10.254.254.2/32", "bgp")
    # Wait for R3 <-> R4 convergence.
    expect_loopback_route("r3", "ip", "10.254.254.4/32", "bgp")
    # Wait for R3 <-> R5 convergence.
    expect_loopback_route("r3", "ip", "10.254.254.5/32", "bgp")
    # Wait for R3 <-> R6 convergence.
    expect_loopback_route("r3", "ip", "10.254.254.6/32", "bgp")

    # Wait for R4 <-> R1 convergence.
    expect_loopback_route("r4", "ip", "10.254.254.1/32", "bgp")
    # Wait for R4 <-> R2 convergence.
    expect_loopback_route("r4", "ip", "10.254.254.2/32", "bgp")
    # Wait for R4 <-> R3 convergence.
    expect_loopback_route("r4", "ip", "10.254.254.3/32", "bgp")
    # Wait for R4 <-> R5 convergence.
    expect_loopback_route("r4", "ip", "10.254.254.5/32", "static")
    # Wait for R4 <-> R6 convergence.
    expect_loopback_route("r4", "ip", "10.254.254.6/32", "static")

    # Wait for R5 <-> R6 convergence.
    expect_loopback_route('r5', 'ipv6', '2001:db8:4::3/128', 'static')
    # Wait for R6 <-> R5 convergence.
    expect_loopback_route('r6', 'ipv6', '2001:db8:4::2/128', 'static')


def test_wait_bfd_convergence():
    "Wait for BFD to converge"
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    logger.info("test BFD configurations")

    def expect_bfd_configuration(router):
        "Load JSON file and compare with 'show bfd peer json'"
        logger.info("waiting BFD configuration on router {}".format(router))
        bfd_config = json.loads(open("{}/{}/bfd-peers.json".format(CWD, router)).read())
        test_func = partial(
            topotest.router_json_cmp,
            tgen.gears[router],
            "show bfd peers json",
            bfd_config,
        )
        _, result = topotest.run_and_expect(test_func, None, count=130, wait=1)
        assertmsg = '"{}" BFD configuration failure'.format(router)
        assert result is None, assertmsg

    expect_bfd_configuration("r1")
    expect_bfd_configuration("r2")
    expect_bfd_configuration("r3")
    expect_bfd_configuration("r4")
    expect_bfd_configuration("r5")
    expect_bfd_configuration("r6")


def test_static_route_monitoring():
    "Test static route monitoring output."
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    logger.info("test BFD static route status")

    def expect_static_bfd_output(router, filename):
        "Load JSON file and compare with 'show bfd peer json'"
        logger.info('waiting BFD configuration on router {}'.format(router))
        bfd_config = json.loads(open('{}/{}/{}.json'.format(CWD, router, filename)).read())
        test_func = partial(
            topotest.router_json_cmp,
            tgen.gears[router],
            'show bfd static route json',
            bfd_config
        )
        _, result = topotest.run_and_expect(test_func, None, count=20, wait=1)
        assertmsg = '"{}" BFD static route status failure'.format(router)
        assert result is None, assertmsg

    expect_static_bfd_output('r5', 'bfd-static')
    expect_static_bfd_output('r6', 'bfd-static')

    logger.info("Setting r5 link down ...")

    tgen.gears['r5'].link_enable('r5-eth0', False)

    expect_static_bfd_output('r5', 'bfd-static-down')
    expect_static_bfd_output('r6', 'bfd-static-down')


def test_expect_static_rib_removal():
    "Test that route got removed from RIB (staticd and bgpd)."

    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    def expect_route_missing(router, iptype, route):
        "Wait until route is present on RIB for protocol."
        logger.info('waiting route {} to disapear in {}'.format(route, router))
        test_func = partial(
            topotest.router_json_cmp,
            tgen.gears[router],
            'show {} route json'.format(iptype),
            { route: None }
        )
        rv, result = topotest.run_and_expect(test_func, None, count=20, wait=1)
        assertmsg = '"{}" convergence failure'.format(router)
        assert result is None, assertmsg

    expect_route_missing('r1', 'ip', '10.254.254.5/32')
    expect_route_missing('r2', 'ip', '10.254.254.5/32')
    expect_route_missing('r3', 'ip', '10.254.254.5/32')
    expect_route_missing('r4', 'ip', '10.254.254.5/32')
    expect_route_missing('r5', 'ip', '10.254.254.4/32')
    expect_route_missing('r5', 'ip', '2001:db8:4::3/128')
    expect_route_missing('r6', 'ipv6', '2001:db8:4::2/128')


def teardown_module(_mod):
    "Teardown the pytest environment"
    tgen = get_topogen()
    tgen.stop_topology()


def test_memory_leak():
    "Run the memory leak test and report results."
    tgen = get_topogen()
    if not tgen.is_memleak_enabled():
        pytest.skip("Memory leak test/report is disabled")

    tgen.report_memory_leaks()


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
