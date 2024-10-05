#!/usr/bin/env python
# SPDX-License-Identifier: ISC

#
# test_ospf_metric_propagation.py
#
# Copyright (c) 2023 ATCorp
# Jafar Al-Gharaibeh
#

import os
import sys
import json
from functools import partial
import pytest

# pylint: disable=C0413
# Import topogen and topotest helpers
from lib import topotest
from lib.topogen import Topogen, get_topogen
from lib.topolog import logger


"""
test_ospf_metric_propagation.py: Test OSPF/BGP metric propagation
"""

TOPOLOGY = """
                                      +-----+                           +-----+
                                 eth1 |     |           eth0            |     | eth2
                        +-------------+ rA  +---------------------------+ rB  +---------------+
                        |          .5 |     | .5                     .6 |     | .6            |
                        |             +--+--+     10.0.50.0/24          +--+--+ .6            |
                        |                |.5                               |.6                |
                        |            eth2|                             eth1|                  |
                 10.0.10.0/24            |                                 |                  |
                        |            10.0.20.0/24                   10.0.30.0/24          10.0.40.0/24
                        |blue            |blue                             |blue              |blue
                        |                |                                 |                  |
                    eth1|.1          eth1|.2                           eth1|.3            eth1|.4
    +-----+          +--+--+          +--+--+           +-----+          +-+---+            +-+---+         +------+
    |     |eth0  eth2|     |   eth0   |     |eth2   eth1|     |eth2  eth3|     |   eth0     |     |eth2 eth0|      |
    | h1  +----------+ R1  +----------+ R2  +-----------+ rC  +----------+ R3  +------------+ R4  +---------+ h2   |
    |     |          |     |          |     |           |     |          |     |            |     |         |      |
    +-----+.2     .1 +-----+.1      .2+-----+.2      .7 +-----+.7      .3+-----+.3        .4+-----+.4     .2+------+
                  green                    green                      green                       green

       10.0.91.0/24        10.0.1.0/24      10.0.70.0/24      10.0.80.0/24     10.0.3.0/24        10.0.94.0/24
"""

# Save the Current Working Directory to find configuration files.
CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

# Required to instantiate the topology builder class.

pytestmark = [pytest.mark.ospfd, pytest.mark.bgpd]


def build_topo(tgen):
    "Build function"

    # Create 4 routers
    for routern in range(1, 5):
        tgen.add_router("r{}".format(routern))

    tgen.add_router("ra")
    tgen.add_router("rb")
    tgen.add_router("rc")
    tgen.add_router("h1")
    tgen.add_router("h2")

    # Interconect router 1, 2
    switch = tgen.add_switch("s1-2")
    switch.add_link(tgen.gears["r1"])
    switch.add_link(tgen.gears["r2"])

    # Interconect router 3, 4
    switch = tgen.add_switch("s3-4")
    switch.add_link(tgen.gears["r3"])
    switch.add_link(tgen.gears["r4"])

    # Interconect router a, b
    switch = tgen.add_switch("sa-b")
    switch.add_link(tgen.gears["ra"])
    switch.add_link(tgen.gears["rb"])

    # Interconect router 1, a
    switch = tgen.add_switch("s1-a")
    switch.add_link(tgen.gears["r1"])
    switch.add_link(tgen.gears["ra"])

    # Interconect router 2, a
    switch = tgen.add_switch("s2-a")
    switch.add_link(tgen.gears["r2"])
    switch.add_link(tgen.gears["ra"])

    # Interconect router 3, b
    switch = tgen.add_switch("s3-b")
    switch.add_link(tgen.gears["r3"])
    switch.add_link(tgen.gears["rb"])

    # Interconect router 4, b
    switch = tgen.add_switch("s4-b")
    switch.add_link(tgen.gears["r4"])
    switch.add_link(tgen.gears["rb"])

    # Interconect router 1, h1
    switch = tgen.add_switch("s1-h1")
    switch.add_link(tgen.gears["r1"])
    switch.add_link(tgen.gears["h1"])

    # Interconect router 4, h2
    switch = tgen.add_switch("s4-h2")
    switch.add_link(tgen.gears["r4"])
    switch.add_link(tgen.gears["h2"])

    # Interconect router 2, c
    switch = tgen.add_switch("s2-c")
    switch.add_link(tgen.gears["r2"])
    switch.add_link(tgen.gears["rc"])

    # Interconect router 3, c
    switch = tgen.add_switch("s3-c")
    switch.add_link(tgen.gears["r3"])
    switch.add_link(tgen.gears["rc"])


def setup_module(mod):
    logger.info("OSPF Metric Propagation:\n {}".format(TOPOLOGY))

    tgen = Topogen(build_topo, mod.__name__)
    tgen.start_topology()

    vrf_setup_cmds = [
        "ip link add name blue type vrf table 11",
        "ip link set dev blue up",
        "ip link add name green type vrf table 12",
        "ip link set dev green up",
    ]

    # Starting Routers
    router_list = tgen.routers()

    # Create VRFs and bind to interfaces
    for routern in range(1, 5):
        for cmd in vrf_setup_cmds:
            tgen.net["r{}".format(routern)].cmd(cmd)
    for routern in range(1, 5):
        tgen.net["r{}".format(routern)].cmd(
            "ip link set dev r{}-eth1 vrf blue up".format(routern)
        )
        tgen.net["r{}".format(routern)].cmd(
            "ip link set dev r{}-eth2 vrf green up".format(routern)
        )

    for rname, router in router_list.items():
        logger.info("Loading router %s" % rname)
        router.load_frr_config(os.path.join(CWD, "{}/frr.conf".format(rname)))

    # Initialize all routers.
    tgen.start_router()
    for router in router_list.values():
        if router.has_version("<", "4.20"):
            tgen.set_error("unsupported version")


def teardown_module():
    "Teardown the pytest environment"
    tgen = get_topogen()
    tgen.stop_topology()


def test_all_links_up():
    "Test path R1 -> Ra -> Rb -> R4"
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip("skipped because of router(s) failure")

    r1 = tgen.gears["r1"]
    json_file = "{}/r1/show_ip_route-1.json".format(CWD)
    expected = json.loads(open(json_file).read())
    test_func = partial(
        topotest.router_json_cmp, r1, "show ip route vrf green 10.0.94.2 json", expected
    )
    _, result = topotest.run_and_expect(test_func, None, count=60, wait=1)

    assertmsg = "r1 JSON output mismatches"
    assert result is None, assertmsg


def test_link_1_down():
    "Test path R1 -> R2 -> Ra -> Rb -> R4"
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip("skipped because of router(s) failure")

    tgen.net["r1"].cmd("ip link set dev r1-eth1 down")
    r1 = tgen.gears["r1"]

    json_file = "{}/r1/show_ip_route-2.json".format(CWD)
    expected = json.loads(open(json_file).read())
    test_func = partial(
        topotest.router_json_cmp, r1, "show ip route vrf green 10.0.94.2 json", expected
    )
    _, result = topotest.run_and_expect(test_func, None, count=60, wait=1)

    assertmsg = "r1 JSON output mismatches"
    assert result is None, assertmsg


def test_link_1_2_down():
    "Test path R1 -> R2 -> Rc -> R3 -> Rb -> R4"
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip("skipped because of router(s) failure")

    tgen.net["r2"].cmd("ip link set dev r2-eth1 down")
    tgen.net["r1"].cmd("ip link set dev r1-eth0 down")
    tgen.net["r2"].cmd("ip link set dev r2-eth2 down")
    tgen.net["r2"].cmd("ip link set dev r2-eth2 up")
    tgen.net["r1"].cmd("ip link set dev r1-eth0 up")
    r1 = tgen.gears["r1"]

    json_file = "{}/r1/show_ip_route-3.json".format(CWD)
    expected = json.loads(open(json_file).read())
    test_func = partial(
        topotest.router_json_cmp, r1, "show ip route vrf green 10.0.94.2 json", expected
    )
    _, result = topotest.run_and_expect(test_func, None, count=60, wait=1)

    assertmsg = "r1 JSON output mismatches"
    assert result is None, assertmsg


def test_link_1_2_3_down():
    "Test path R1 -> R2 -> Rc -> R3  -> R4"
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip("skipped because of router(s) failure")

    tgen.net["r3"].cmd("ip link set dev r3-eth1 down")
    tgen.net["r1"].cmd("ip link set dev r1-eth0 down")
    tgen.net["r3"].cmd("ip link set dev r3-eth0 down")
    tgen.net["r3"].cmd("ip link set dev r3-eth0 up")
    tgen.net["r1"].cmd("ip link set dev r1-eth0 up")
    r1 = tgen.gears["r1"]

    json_file = "{}/r1/show_ip_route-4.json".format(CWD)
    expected = json.loads(open(json_file).read())
    test_func = partial(
        topotest.router_json_cmp, r1, "show ip route vrf green 10.0.94.2 json", expected
    )
    _, result = topotest.run_and_expect(test_func, None, count=60, wait=1)

    assertmsg = "r1 JSON output mismatches"
    assert result is None, assertmsg


def test_link_1_2_3_4_down():
    "Test path R1 -> R2 -> Rc -> R3  -> R4"
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip("skipped because of router(s) failure")

    tgen.net["r4"].cmd("ip link set dev r4-eth1 down")
    r1 = tgen.gears["r1"]

    json_file = "{}/r1/show_ip_route-4.json".format(CWD)
    expected = json.loads(open(json_file).read())
    test_func = partial(
        topotest.router_json_cmp, r1, "show ip route vrf green 10.0.94.2 json", expected
    )
    _, result = topotest.run_and_expect(test_func, None, count=60, wait=1)

    assertmsg = "r1 JSON output mismatches"
    assert result is None, assertmsg


def test_link_1_2_4_down_3_up():
    "Test path R1 -> R2 -> Rc -> R3  -> R4"
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip("skipped because of router(s) failure")

    # bring link 3 back up
    tgen.net["r3"].cmd("ip link set dev r3-eth1 up")
    r1 = tgen.gears["r1"]

    json_file = "{}/r1/show_ip_route-4.json".format(CWD)
    expected = json.loads(open(json_file).read())
    test_func = partial(
        topotest.router_json_cmp, r1, "show ip route vrf green 10.0.94.2 json", expected
    )
    _, result = topotest.run_and_expect(test_func, None, count=60, wait=1)

    assertmsg = "r1 JSON output mismatches"
    assert result is None, assertmsg


def test_link_1_4_down_2_up():
    "Test path R1 -> R2 -> Ra -> Rb -> R3  -> R4"
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip("skipped because of router(s) failure")

    # bring back link 2 up
    tgen.net["r2"].cmd("ip link set dev r2-eth1 up")
    r1 = tgen.gears["r1"]

    json_file = "{}/r1/show_ip_route-5.json".format(CWD)
    expected = json.loads(open(json_file).read())
    test_func = partial(
        topotest.router_json_cmp, r1, "show ip route vrf green 10.0.94.2 json", expected
    )
    _, result = topotest.run_and_expect(test_func, None, count=120, wait=2)

    assertmsg = "r1 JSON output mismatches"
    assert result is None, assertmsg


def test_link_4_down_1_up():
    "Test path R1 -> Ra -> Rb -> R3  -> R4"
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip("skipped because of router(s) failure")

    # bring back link 1 up
    tgen.net["r1"].cmd("ip link set dev r1-eth1 up")
    r1 = tgen.gears["r1"]

    json_file = "{}/r1/show_ip_route-6.json".format(CWD)
    expected = json.loads(open(json_file).read())
    test_func = partial(
        topotest.router_json_cmp, r1, "show ip route vrf green 10.0.94.2 json", expected
    )
    _, result = topotest.run_and_expect(test_func, None, count=120, wait=2)

    assertmsg = "r1 JSON output mismatches"
    assert result is None, assertmsg


def test_link_1_2_3_4_up():
    "Test path R1 -> Ra -> Rb -> R4"
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip("skipped because of router(s) failure")

    # bring back link 4 up
    tgen.net["r4"].cmd("ip link set dev r4-eth1 up")
    r1 = tgen.gears["r1"]

    json_file = "{}/r1/show_ip_route-1.json".format(CWD)
    expected = json.loads(open(json_file).read())
    test_func = partial(
        topotest.router_json_cmp, r1, "show ip route vrf green 10.0.94.2 json", expected
    )
    _, result = topotest.run_and_expect(test_func, None, count=120, wait=2)

    assertmsg = "r1 JSON output mismatches"
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
