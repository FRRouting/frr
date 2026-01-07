#!/usr/bin/env python
# SPDX-License-Identifier: ISC

#
# test_pim_slow_convergence.py
#
# Copyright (c) 2026 Nvidia Inc.
#                    Donald Sharp
#

"""
test_pim_slow_convergence.py: Testing PIM convergence with a diamond topology
                              This test shows that in certain situations S,G
                              state is not established on torc11 when it should
                              be.
"""

import os
import sys
import time
import pytest
from functools import partial

pytestmark = [pytest.mark.pimd, pytest.mark.ripd]

# Save the Current Working Directory to find configuration files.
CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

# pylint: disable=C0413
# Import topogen and topotest helpers
from lib import topotest
from lib.topogen import Topogen, TopoRouter, get_topogen
from lib.topolog import logger

# Required to instantiate the topology builder class.

#####################################################
##
##   Network Topology Definition
##
#####################################################


def build_topo(tgen):
    """
    Topology:
    
                    +----------+
                    |    rp    |
                    | 10.0.0.1 |
                    +----------+
                      /        \
                     /          \*,G
                    /            \
          +----------+          +----------+
          |  spine1  |          |  spine2  |
          | 10.0.0.2 |          | 10.0.0.7 |
          +----------+          +----------+
                    \            /  \
                     \       *,G/    \*,G
                      \        /      \
                    +----------+   +----------+
                    |  torc11  |   |  torc21  |
                    | 10.0.0.3 |   | 10.0.0.4 |
                    +----------+   +----------+
                         / \             |
                   src  /   \  rcv       | rcv *,G
                       /     \  *,G      | 
                    +----------+   +----------+
                    |  host11  |   |  host21  |
                    | 10.0.0.5 |   | 10.0.0.6 |
                    +----------+   +----------+
  
    All nodes use consistent final octets:
    .1=rp, .2=spine1, .3=torc11, .4=torc21, .5=host11, .6=host21, .7=spine2

    rip is used with some metrics to cause the path from the rp towards the
    S to alwys go through spine1.  Additionally pathing for the G is influenced
    such that torc11 always uses spine2 for the * pim joins.
    """

    # Add routers
    tgen.add_router("rp")
    tgen.add_router("spine1")
    tgen.add_router("spine2")
    tgen.add_router("torc11")
    tgen.add_router("torc21")
    tgen.add_router("host11")

    tgen.add_host("host21", "10.0.15.6/24", "via 10.0.15.4")

    # Add switches and links
    # rp to spine1
    switch = tgen.add_switch("s1")
    switch.add_link(tgen.gears["rp"])
    switch.add_link(tgen.gears["spine1"])

    # rp to spine2
    switch = tgen.add_switch("s2")
    switch.add_link(tgen.gears["rp"])
    switch.add_link(tgen.gears["spine2"])

    # spine1 to torc11
    switch = tgen.add_switch("s3")
    switch.add_link(tgen.gears["spine1"])
    switch.add_link(tgen.gears["torc11"])

    # torc11 to host11 (src)
    switch = tgen.add_switch("s4")
    switch.add_link(tgen.gears["torc11"])
    switch.add_link(tgen.gears["host11"])

    # torc11 to host11 (rcvr)
    switch = tgen.add_switch("s5")
    switch.add_link(tgen.gears["torc11"])
    switch.add_link(tgen.gears["host11"])

    # torc21 to host21
    switch = tgen.add_switch("s6")
    switch.add_link(tgen.gears["torc21"])
    switch.add_link(tgen.gears["host21"])

    # spine2 to torc11
    switch = tgen.add_switch("s7")
    switch.add_link(tgen.gears["spine2"])
    switch.add_link(tgen.gears["torc11"])

    # spine2 to torc21
    switch = tgen.add_switch("s8")
    switch.add_link(tgen.gears["spine2"])
    switch.add_link(tgen.gears["torc21"])


#####################################################
##
##   Tests starting
##
#####################################################


def setup_module(module):
    "Setup topology"
    tgen = Topogen(build_topo, module.__name__)
    tgen.start_topology()

    # Configure routers
    router_list = tgen.routers()
    for rname, router in router_list.items():
        router.load_frr_config(
            os.path.join(CWD, "{}/frr.conf".format(rname)),
            [
                (TopoRouter.RD_ZEBRA, None),
                (TopoRouter.RD_RIP, None),
                (TopoRouter.RD_PIM, None),
            ],
        )

    tgen.start_router()


def teardown_module(_mod):
    "Teardown the pytest environment"
    tgen = get_topogen()

    # This function tears down the whole topology.
    tgen.stop_topology()


def test_pim_convergence():
    "Basic test to verify topology is up and PIM neighbors are formed"
    tgen = get_topogen()
    # Don't run this test if we have any failure.
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    logger.info("Test PIM slow convergence topology is operational")

    # Test PIM neighbors on rp
    logger.info("Checking PIM neighbors on rp")
    rp = tgen.gears["rp"]
    expected = {
        "rp-eth0": {"10.0.10.2": {}},  # spine1
        "rp-eth1": {"10.0.11.7": {}},  # spine2
    }
    test_func = partial(
        topotest.router_json_cmp, rp, "show ip pim neighbor json", expected
    )
    _, result = topotest.run_and_expect(test_func, None, count=60, wait=1)
    assertmsg = "rp: PIM neighbors did not converge"
    assert result is None, assertmsg

    # Test PIM neighbors on spine1
    logger.info("Checking PIM neighbors on spine1")
    spine1 = tgen.gears["spine1"]
    expected = {
        "spine1-eth0": {"10.0.10.1": {}},  # rp
        "spine1-eth1": {"10.0.12.3": {}},  # torc11
    }
    test_func = partial(
        topotest.router_json_cmp, spine1, "show ip pim neighbor json", expected
    )
    _, result = topotest.run_and_expect(test_func, None, count=60, wait=1)
    assertmsg = "spine1: PIM neighbors did not converge"
    assert result is None, assertmsg

    # Test PIM neighbors on spine2
    logger.info("Checking PIM neighbors on spine2")
    spine2 = tgen.gears["spine2"]
    expected = {
        "spine2-eth0": {"10.0.11.1": {}},  # rp
        "spine2-eth1": {"10.0.16.3": {}},  # torc11
        "spine2-eth2": {"10.0.17.4": {}},  # torc21
    }
    test_func = partial(
        topotest.router_json_cmp, spine2, "show ip pim neighbor json", expected
    )
    _, result = topotest.run_and_expect(test_func, None, count=60, wait=1)
    assertmsg = "spine2: PIM neighbors did not converge"
    assert result is None, assertmsg

    # Test PIM neighbors on torc11
    logger.info("Checking PIM neighbors on torc11")
    torc11 = tgen.gears["torc11"]
    expected = {
        "torc11-eth0": {"10.0.12.2": {}},  # spine1
        "torc11-eth3": {"10.0.16.7": {}},  # spine2
    }
    test_func = partial(
        topotest.router_json_cmp, torc11, "show ip pim neighbor json", expected
    )
    _, result = topotest.run_and_expect(test_func, None, count=60, wait=1)
    assertmsg = "torc11: PIM neighbors did not converge"
    assert result is None, assertmsg

    # Test PIM neighbors on torc21
    logger.info("Checking PIM neighbors on torc21")
    torc21 = tgen.gears["torc21"]
    expected = {
        "torc21-eth1": {"10.0.17.7": {}},  # spine2
    }
    test_func = partial(
        topotest.router_json_cmp, torc21, "show ip pim neighbor json", expected
    )
    _, result = topotest.run_and_expect(test_func, None, count=60, wait=1)
    assertmsg = "torc21: PIM neighbors did not converge"
    assert result is None, assertmsg

    logger.info("All PIM neighbors converged successfully")


def test_multicast_receiver():
    "Test multicast receiver on host21 listening to 225.1.1.1"
    logger.info("Starting multicast receiver on host21 for group 225.1.1.1")

    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    host21 = tgen.gears["host21"]
    torc21 = tgen.gears["torc21"]

    # Start multicast receiver on host21 using mcast-tester.py
    mcast_tester = os.path.join(CWD, "../lib/mcast-tester.py")
    cmd = [mcast_tester, "225.1.1.1", "host21-eth0"]
    p = host21.popen(cmd)

    # Start multicast receiver on host11 (on second interface)
    host11 = tgen.gears["host11"]
    cmd_rx_host11 = [mcast_tester, "225.1.1.1", "host11-eth1"]
    p_rx_host11 = host11.popen(cmd_rx_host11)

    mcast_tx = os.path.join(CWD, "../pim_basic/mcast-tx.py")
    cmd_tx = [
        mcast_tx,
        "--ttl",
        "10",
        "--count",
        "100",
        "--interval",
        "100000",
        "225.1.1.1",
        "host11-eth0",
    ]
    p_tx = host11.popen(cmd_tx)

    # Wait for S,G join to be received on torc11 from spine1
    logger.info("Checking for S,G join on torc11 from spine1")
    torc11 = tgen.gears["torc11"]
    expected = {
        "torc11-eth0": {
            "225.1.1.1": {
                "10.0.14.5": {
                    "source": "10.0.14.5",
                    "group": "225.1.1.1",
                    "channelJoinName": "JOIN",
                }
            }
        }
    }
    test_func = partial(
        topotest.router_json_cmp, torc11, "show ip pim join json", expected
    )
    _, result = topotest.run_and_expect(test_func, None, count=20, wait=1)
    assertmsg = "torc11: S,G join not received from spine1"
    assert result is None, assertmsg

    logger.info("S,G join successfully received on torc11 on torc11-eth0")

    if p:
        p.terminate()
        p.wait()
    if p_rx_host11:
        p_rx_host11.terminate()
        p_rx_host11.wait()
    if p_tx:
        p_tx.terminate()
        p_tx.wait()


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
