#!/usr/bin/env python
# SPDX-License-Identifier: ISC

#
# test_pim_basic_topo2.py
# Part of NetDEF Topology Tests
#
# Copyright (c) 2021 by
# Network Device Education Foundation, Inc. ("NetDEF")
#

"""
test_pim_basic_topo2.py: Test the FRR PIM protocol convergence.
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
from lib.topogen import Topogen, TopoRouter, get_topogen
from lib.topolog import logger

# Required to instantiate the topology builder class.

pytestmark = [pytest.mark.bfdd, pytest.mark.pimd]


def build_topo(tgen):
    "Build function"

    # Create 4 routers
    for routern in range(1, 5):
        tgen.add_router("r{}".format(routern))

    switch = tgen.add_switch("s1")
    switch.add_link(tgen.gears["r1"])
    switch.add_link(tgen.gears["r2"])

    switch = tgen.add_switch("s2")
    switch.add_link(tgen.gears["r2"])
    switch.add_link(tgen.gears["r3"])

    switch = tgen.add_switch("s3")
    switch.add_link(tgen.gears["r2"])
    switch.add_link(tgen.gears["r4"])


def setup_module(mod):
    "Sets up the pytest environment"
    tgen = Topogen(build_topo, mod.__name__)
    tgen.start_topology()

    router_list = tgen.routers()
    for rname, router in router_list.items():
        daemon_file = "{}/{}/bfdd.conf".format(CWD, rname)
        if os.path.isfile(daemon_file):
            router.load_config(TopoRouter.RD_BFD, daemon_file)

        daemon_file = "{}/{}/pimd.conf".format(CWD, rname)
        if os.path.isfile(daemon_file):
            router.load_config(TopoRouter.RD_PIM, daemon_file)

        daemon_file = "{}/{}/zebra.conf".format(CWD, rname)
        if os.path.isfile(daemon_file):
            router.load_config(TopoRouter.RD_ZEBRA, daemon_file)

    # Initialize all routers.
    tgen.start_router()


def teardown_module(_mod):
    "Teardown the pytest environment"
    tgen = get_topogen()
    tgen.stop_topology()


def expect_neighbor(router, interface, peer):
    "Wait until peer is present on interface."
    logger.info("waiting peer {} in {}".format(peer, interface))
    tgen = get_topogen()
    test_func = partial(
        topotest.router_json_cmp,
        tgen.gears[router],
        "show ip pim neighbor json",
        {interface: {peer: {}}},
    )
    _, result = topotest.run_and_expect(test_func, None, count=130, wait=1)
    assertmsg = '"{}" PIM convergence failure'.format(router)
    assert result is None, assertmsg


def test_wait_pim_convergence():
    "Wait for PIM to converge"
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    logger.info("waiting for PIM to converge")

    expect_neighbor("r1", "r1-eth0", "192.168.1.2")
    expect_neighbor("r2", "r2-eth0", "192.168.1.1")

    expect_neighbor("r2", "r2-eth1", "192.168.2.3")
    expect_neighbor("r2", "r2-eth2", "192.168.3.4")

    expect_neighbor("r3", "r3-eth0", "192.168.2.1")
    expect_neighbor("r4", "r4-eth0", "192.168.3.1")


def test_bfd_peers():
    "Wait for BFD peers to show up."
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    logger.info("waiting for BFD to converge")

    def expect_bfd_peer(router, peer):
        "Wait until peer is present on interface."
        logger.info("waiting BFD peer {} in {}".format(peer, router))
        test_func = partial(
            topotest.router_json_cmp,
            tgen.gears[router],
            "show bfd peers json",
            [{"peer": peer, "status": "up"}],
        )
        _, result = topotest.run_and_expect(test_func, None, count=10, wait=1)
        assertmsg = '"{}" BFD convergence failure'.format(router)
        assert result is None, assertmsg

    expect_bfd_peer("r1", "192.168.1.2")
    expect_bfd_peer("r2", "192.168.1.1")
    expect_bfd_peer("r2", "192.168.2.3")
    expect_bfd_peer("r2", "192.168.3.4")
    expect_bfd_peer("r3", "192.168.2.1")
    expect_bfd_peer("r4", "192.168.3.1")


def test_pim_reconvergence():
    "Disconnect a peer and expect it to disconnect."
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    logger.info("waiting for disconnect convergence")
    tgen.gears["r4"].link_enable("r4-eth0", enabled=False)

    def expect_neighbor_down(router, interface, peer):
        "Wait until peer is present on interface."
        logger.info("waiting peer {} in {} to disappear".format(peer, interface))
        test_func = partial(
            topotest.router_json_cmp,
            tgen.gears[router],
            "show ip pim neighbor json",
            {interface: {peer: None}},
        )
        _, result = topotest.run_and_expect(test_func, None, count=5, wait=1)
        assertmsg = '"{}" PIM convergence failure'.format(router)
        assert result is None, assertmsg

    expect_neighbor_down("r2", "r2-eth2", "192.168.3.4")

    logger.info("waiting for reconvergence")
    tgen.gears["r4"].link_enable("r4-eth0", enabled=True)
    expect_neighbor("r2", "r2-eth2", "192.168.3.4")


def test_pim_bfd_profile():
    "Test that the BFD profile is properly applied in BFD."
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    def expect_bfd_peer_settings(router, settings):
        "Expect the following BFD configuration"
        logger.info("Verifying BFD peer {} in {}".format(settings["peer"], router))
        test_func = partial(
            topotest.router_json_cmp,
            tgen.gears[router],
            "show bfd peers json",
            [settings],
        )
        _, result = topotest.run_and_expect(test_func, None, count=5, wait=1)
        assertmsg = '"{}" BFD convergence failure'.format(router)
        assert result is None, assertmsg

    expect_bfd_peer_settings(
        "r1",
        {
            "peer": "192.168.1.2",
            "receive-interval": 250,
            "transmit-interval": 250,
        },
    )

    expect_bfd_peer_settings(
        "r2",
        {
            "peer": "192.168.1.1",
            "remote-receive-interval": 250,
            "remote-transmit-interval": 250,
        },
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
