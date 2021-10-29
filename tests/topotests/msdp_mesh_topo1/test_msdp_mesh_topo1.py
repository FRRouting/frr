#!/usr/bin/env python
# SPDX-License-Identifier: ISC

#
# test_msdp_mesh_topo1.py
# Part of NetDEF Topology Tests
#
# Copyright (C) 2021 by
# Network Device Education Foundation, Inc. ("NetDEF")
#

"""
test_msdp_mesh_topo1.py: Test the FRR PIM MSDP mesh groups.
"""

import os
import sys
from functools import partial
import pytest

# Save the Current Working Directory to find configuration files.
CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

# pylint: disable=C0413
# Import topogen and topotest helpers
from lib import topotest

# Required to instantiate the topology builder class.
from lib.topogen import Topogen, TopoRouter, get_topogen
from lib.topolog import logger

from lib.pim import McastTesterHelper

pytestmark = [pytest.mark.bgpd, pytest.mark.ospfd, pytest.mark.pimd]

app_helper = McastTesterHelper()


def build_topo(tgen):
    "Build function"

    # Create 3 routers
    for routern in range(1, 4):
        tgen.add_router("r{}".format(routern))

    switch = tgen.add_switch("s1")
    switch.add_link(tgen.gears["r1"])
    switch.add_link(tgen.gears["r2"])

    switch = tgen.add_switch("s2")
    switch.add_link(tgen.gears["r2"])
    switch.add_link(tgen.gears["r3"])

    # Create stub networks for multicast traffic.
    tgen.add_host("h1", "192.168.10.2/24", "via 192.168.10.1")
    switch = tgen.add_switch("s3")
    switch.add_link(tgen.gears["r1"])
    switch.add_link(tgen.gears["h1"])

    tgen.add_host("h2", "192.168.30.2/24", "via 192.168.30.1")
    switch = tgen.add_switch("s4")
    switch.add_link(tgen.gears["r3"])
    switch.add_link(tgen.gears["h2"])


def setup_module(mod):
    "Sets up the pytest environment"
    tgen = Topogen(build_topo, mod.__name__)
    tgen.start_topology()

    router_list = tgen.routers()
    for rname, router in router_list.items():

        daemon_file = "{}/{}/mgmtd.conf".format(CWD, rname)
        if os.path.isfile(daemon_file):
            router.load_config(TopoRouter.RD_MGMTD, daemon_file)

        daemon_file = "{}/{}/zebra.conf".format(CWD, rname)
        if os.path.isfile(daemon_file):
            router.load_config(TopoRouter.RD_ZEBRA, daemon_file)

        daemon_file = "{}/{}/bgpd.conf".format(CWD, rname)
        if os.path.isfile(daemon_file):
            router.load_config(TopoRouter.RD_BGP, daemon_file)

        daemon_file = "{}/{}/ospfd.conf".format(CWD, rname)
        if os.path.isfile(daemon_file):
            router.load_config(TopoRouter.RD_OSPF, daemon_file)

        daemon_file = "{}/{}/pimd.conf".format(CWD, rname)
        if os.path.isfile(daemon_file):
            router.load_config(TopoRouter.RD_PIM, daemon_file)

    # Initialize all routers.
    tgen.start_router()

    app_helper.init(tgen)


def test_wait_ospf_convergence():
    "Wait for OSPF to converge"
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
        _, result = topotest.run_and_expect(test_func, None, count=40, wait=1)
        assertmsg = '"{}" OSPF convergence failure'.format(router)
        assert result is None, assertmsg

    # Wait for R1 <-> R2 convergence.
    expect_loopback_route("r1", "ip", "10.254.254.2/32", "ospf")
    # Wait for R1 <-> R3 convergence.
    expect_loopback_route("r1", "ip", "10.254.254.3/32", "ospf")

    # Wait for R2 <-> R1 convergence.
    expect_loopback_route("r2", "ip", "10.254.254.1/32", "ospf")
    # Wait for R2 <-> R3 convergence.
    expect_loopback_route("r2", "ip", "10.254.254.3/32", "ospf")

    # Wait for R3 <-> R1 convergence.
    expect_loopback_route("r3", "ip", "10.254.254.1/32", "ospf")
    # Wait for R3 <-> R2 convergence.
    expect_loopback_route("r3", "ip", "10.254.254.2/32", "ospf")


def test_wait_msdp_convergence():
    "Wait for MSDP to converge"
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    logger.info("test MSDP convergence")

    def expect_msdp_peer(router, peer, sa_count=0):
        "Expect MSDP peer connection to be established with SA amount."
        logger.info(
            "waiting MSDP connection from peer {} on router {}".format(peer, router)
        )
        test_func = partial(
            topotest.router_json_cmp,
            tgen.gears[router],
            "show ip msdp peer json",
            {peer: {"state": "established", "saCount": sa_count}},
        )
        _, result = topotest.run_and_expect(test_func, None, count=40, wait=2)
        assertmsg = '"{}" MSDP connection failure'.format(router)
        assert result is None, assertmsg

    mcastaddr = "229.0.1.10"
    logger.info("Starting helper1")
    app_helper.run("h1", ["--send=0.7", mcastaddr, "h1-eth0"])

    logger.info("Starting helper2")
    app_helper.run("h2", [mcastaddr, "h2-eth0"])

    # R1 peers.
    expect_msdp_peer("r1", "10.254.254.2")
    expect_msdp_peer("r1", "10.254.254.3")

    # R2 peers.
    expect_msdp_peer("r2", "10.254.254.1", 1)
    expect_msdp_peer("r2", "10.254.254.3")

    # R3 peers.
    expect_msdp_peer("r3", "10.254.254.1", 1)
    expect_msdp_peer("r3", "10.254.254.2")


def test_msdp_sa_configuration():
    "Expect the multicast traffic SA to be created"
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    logger.info("test MSDP SA")

    def expect_msdp_sa(router, source, group, local, rp, spt_setup):
        "Expect MSDP SA."
        logger.info("waiting MSDP SA on router {}".format(router))
        test_func = partial(
            topotest.router_json_cmp,
            tgen.gears[router],
            "show ip msdp sa json",
            {group: {source: {"local": local, "rp": rp, "sptSetup": spt_setup}}},
        )
        _, result = topotest.run_and_expect(test_func, None, count=30, wait=1)
        assertmsg = '"{}" MSDP SA failure'.format(router)
        assert result is None, assertmsg

    source = "192.168.10.2"
    group = "229.0.1.10"
    rp = "10.254.254.1"

    # R1 SA.
    expect_msdp_sa("r1", source, group, "yes", "-", "-")

    # R2 SA.
    expect_msdp_sa("r2", source, group, "no", rp, "no")

    # R3 peers.
    expect_msdp_sa("r3", source, group, "no", rp, "yes")


def teardown_module(_mod):
    "Teardown the pytest environment"
    tgen = get_topogen()
    app_helper.cleanup()
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
