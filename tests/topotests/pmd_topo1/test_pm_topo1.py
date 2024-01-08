#!/usr/bin/env python

#
# Copyright 2024 6WIND S.A.
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
test_pm_topo1.py: Test the FRR PM daemon.
"""

import os
import sys
import json
import platform
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


def build_topo(tgen):
    "Build function"
    tgen = get_topogen()

    # Create 4 routers
    for routern in range(1, 4):
        tgen.add_router("r{}".format(routern))

    switch = tgen.add_switch("s1")
    switch.add_link(tgen.gears["r1"])
    switch.add_link(tgen.gears["r2"])

    switch = tgen.add_switch("s2")
    switch.add_link(tgen.gears["r2"])
    switch.add_link(tgen.gears["r3"])

    switch = tgen.add_switch("s3")
    switch.add_link(tgen.gears["r3"])

    switch = tgen.add_switch("s4")
    switch.add_link(tgen.gears["r1"])


def setup_module(mod):
    "Sets up the pytest environment"

    tgen = Topogen(build_topo, mod.__name__)
    tgen.start_topology()

    router_list = tgen.routers()

    krel = platform.release()
    l3mdev_accept = 0
    if (
        topotest.version_cmp(krel, "4.15") >= 0
        and topotest.version_cmp(krel, "4.18") <= 0
    ):
        l3mdev_accept = 1

    if topotest.version_cmp(krel, "5.0") >= 0:
        l3mdev_accept = 1

    # in addition to move interfaces to appropriate netns
    # - ipv6 forwarding is enabled for each namespace
    # - ipv6 address are kept after link up / link down operations
    logger.info("setting net.ipv4.tcp_l3mdev_accept={}".format(l3mdev_accept))
    cmds = [
        "sysctl -w net.ipv4.tcp_l3mdev_accept={}".format(l3mdev_accept),
        "sysctl net.ipv6.conf.all.forwarding=1",
        "sysctl net.ipv6.conf.{0}-eth0.keep_addr_on_down=1",
        "sysctl net.ipv6.conf.{0}-eth1.keep_addr_on_down=1",
    ]

    for rname, router in router_list.items():
        for cmd in cmds:
            cmd = cmd.format(rname)
            output = tgen.net[rname].cmd(cmd.format(rname))
            logger.info("output: {}".format(output))

    for rname, router in router_list.items():
        router.load_config(
            TopoRouter.RD_ZEBRA,
            os.path.join(CWD, "{}/zebra.conf".format(rname)),
        )
        router.load_config(
            TopoRouter.RD_PM,
            os.path.join(CWD, "{}/pmd.conf".format(rname)),
            "-M pm_tracking",
        )

    # Initialize all routers.
    tgen.start_router()

    # Verify that we are using the proper version and that the PM
    # daemon exists.
    for router in router_list.values():
        # Check for Version
        if router.has_version("<", "5.1"):
            tgen.set_error("Unsupported FRR version")
            break
    for router in tgen.routers().values():
        output = router.vtysh_cmd("show running-config")
        logger.info("==== {0} show running-config:".format(router.name))
        logger.info(output)


def teardown_module(_mod):
    "Teardown the pytest environment"

    tgen = get_topogen()

    tgen.stop_topology()


def router_pmd_sessions_json_cmp(router, data):
    current = router.vtysh_cmd("show pm sessions json", isjson=True)
    for peer in current:
        # ignore "id"
        if "id" in peer.keys():
            peer["id"] = 0
        # ignore "uptime" if present
        if "uptime" in peer.keys():
            peer["uptime"] = 0
        # ignore "downtime" if present
        if "downtime" in peer.keys():
            peer["downtime"] = 0
    return topotest.json_cmp(current, data)


def check_routing_table(router, version, expected_file):
    if version == 4:
        cmd = "show ip route json"
    else:
        cmd = "show ipv6 route json"

    expected = json.loads(open(expected_file).read())
    test_func = partial(
        topotest.router_json_cmp,
        router,
        cmd,
        expected,
    )
    _, result = topotest.run_and_expect(test_func, None, count=30, wait=0.5)
    assertmsg = '"{}" JSON output mismatches'.format(router.name)
    assert result is None, assertmsg


def test_pm_convergence():
    "Check that PM sessions are UP."

    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    logger.info("waiting for pm sessions to go up")

    for router in tgen.routers().values():
        json_file = "{}/{}/sessions.json".format(CWD, router.name)
        expected = json.loads(open(json_file).read())

        test_func = partial(router_pmd_sessions_json_cmp, router, expected)
        _, result = topotest.run_and_expect(test_func, None, count=20, wait=0.5)
        assertmsg = '"{}" JSON output mismatches'.format(router.name)
        assert result is None, assertmsg

    # expected = static routes check on r1
    r1 = tgen.gears["r1"]

    check_routing_table(r1, 4, "{}/{}/show_ip_route.json".format(CWD, "r1"))
    check_routing_table(r1, 6, "{}/{}/show_ipv6_route.json".format(CWD, "r1"))


def test_pm_step1():
    """
    Check that PM notices the link down after simulating network
    failure.
    """

    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    logger.info("waiting for pm sessions to go down")
    # Disable r2-eth1 link.
    tgen.gears["r2"].link_enable("r2-eth1", enabled=False)
    topotest.sleep(10)
    # compare show pm sessions json with expected
    # expected =  2 non connected sessions (2 = 1 IPv4 + 1 IPv6 ) are supposed to be down
    # expected =  'show ip route | show ipv6 route' shows the extra static route removed
    router = tgen.gears["r1"]
    donna = router.vtysh_cmd("show pm sessions json", isjson=True)
    for peer in donna:
        if peer["peer"] == "192.168.1.1":
            control_expire = (
                "r1, pm session 192.168.1.1, diagnostic different from expected"
            )
            assert peer["status"] == "down", "r1, pm session 192.168.1.1 not down"
            assert peer["diagnostic"] == "echo timeout", control_expire
        if peer["peer"] == "1001:1::1":
            control_expire = (
                "r1, pm session 1001:1::1, diagnostic different from expected"
            )
            assert peer["status"] == "down", "r1, pm session 1001:1::1 not down"
            assert peer["diagnostic"] == "echo timeout", control_expire
    router = tgen.gears["r3"]
    donna = router.vtysh_cmd("show pm sessions json", isjson=True)
    for peer in donna:
        control_expire = (
            "r3, pm session {0}, diagnostic different from expected".format(
                peer["peer"]
            )
        )
        assert peer["status"] == "down", "r3, pm session {0} not down".format(
            peer["peer"]
        )
        assert peer["diagnostic"] == "echo timeout", control_expire

    router = tgen.gears["r1"]
    logger.info("checking that ipv4 route entry 192.168.3.0 is not present")
    donna = router.vtysh_cmd("show ip route json", isjson=True)
    if "192.168.3.0/24" in donna.keys():
        assert 0, "r1, route 192.168.3.0/24 present"

    logger.info("checking that ipv6 route entry 1003:1::/96 is not present")
    donna = router.vtysh_cmd("show ipv6 route json", isjson=True)
    if "1003:1::/96" in donna.keys():
        assert 0, "r1, route 1003:1::/96 present"


def test_pm_step2():
    """
    Check that PM notices the link down after simulating a second network
    failure.
    """

    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    logger.info("waiting for all pm sessions to go down")
    # Disable r2-eth0 link.
    tgen.gears["r2"].link_enable("r2-eth0", enabled=False)
    topotest.sleep(10)
    # compare show pm sessions json with expected
    # expected =  2 other sessions (2 = 1 IPv4 + 1 IPv6 ) are supposed to be down
    router = tgen.gears["r1"]
    donna = router.vtysh_cmd("show pm sessions json", isjson=True)
    for peer in donna:
        control_expire = (
            "r1, pm session {0}, diagnostic different from expected".format(
                peer["peer"]
            )
        )
        if peer["peer"] == "192.168.1.1":
            assert peer["status"] == "down", "r1, pm session 192.168.1.1 not down"
            assert peer["diagnostic"] == "echo unreachable", control_expire
        if peer["peer"] == "1001:1::1":
            assert peer["status"] == "down", "r1, pm session 1001:1::1 not down"
            assert peer["diagnostic"] == "echo unreachable", control_expire
        if peer["peer"] == "192.168.0.2":
            assert peer["status"] == "down", "r1, pm session 192.168.0.2 not down"
            assert peer["diagnostic"] == "echo timeout", control_expire
        if peer["peer"] == "1000:1::2":
            assert peer["status"] == "down", "r1, pm session 1000:1::2 not down"
            assert peer["diagnostic"] == "echo timeout", control_expire

    router = tgen.gears["r2"]
    for peer in donna:
        control_expire = (
            "r2, pm session {0}, diagnostic different from expected".format(
                peer["peer"]
            )
        )
        assert peer["status"] == "down", "r2, pm session {0} not down".format(
            peer["peer"]
        )

    router = tgen.gears["r3"]
    for peer in donna:
        control_expire = (
            "r3, pm session {0}, diagnostic different from expected".format(
                peer["peer"]
            )
        )
        assert peer["status"] == "down", "r3, pm session {0} not down".format(
            peer["peer"]
        )

    for router in tgen.routers().values():
        logger.info("==== {0} show static routing pm:".format(router.name))
        output = router.vtysh_cmd("show static routing pm")
        logger.info(output)
        logger.info("==== {0} show pm sessions:".format(router.name))
        output = router.vtysh_cmd("show pm sessions")
        logger.info(output)
        logger.info("==== {0} show pm sessions operational:".format(router.name))
        output = router.vtysh_cmd("show pm sessions operational")
        logger.info(output)


def test_pm_step3():
    "Re-enable the links on R2 and check that sessions are UP"

    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    logger.info("waiting for pm connected sessions to go up again")
    # Enable r2-eth0 link.
    # compare show pm sessions json with expected
    # expected =  2 connected sessions (2 = 1 IPv4 + 1 IPv6 ) are supposed to be up
    # expected =  2 non connected sessions (2 = 1 IPv4 + 1 IPv6 ) are supposed to be up
    # expected =  'show ip route | show ipv6 route' shows the extra static route
    tgen.gears["r2"].link_enable("r2-eth0", enabled=True)
    tgen.gears["r2"].link_enable("r2-eth1", enabled=True)

    for router in tgen.routers().values():
        json_file = "{}/{}/sessions.json".format(CWD, router.name)
        expected = json.loads(open(json_file).read())

        test_func = partial(router_pmd_sessions_json_cmp, router, expected)
        _, result = topotest.run_and_expect(test_func, None, count=20, wait=0.5)
        assertmsg = '"{}" JSON output mismatches'.format(router.name)
        assert result is None, assertmsg

    # expected = static routes check on r1
    r1 = tgen.gears["r1"]

    check_routing_table(r1, 4, "{}/{}/show_ip_route.json".format(CWD, "r1"))
    check_routing_table(r1, 6, "{}/{}/show_ipv6_route.json".format(CWD, "r1"))


def test_memory_leak():
    "Run the memory leak test and report results."
    tgen = get_topogen()
    if not tgen.is_memleak_enabled():
        pytest.skip("Memory leak test/report is disabled")

    tgen.report_memory_leaks()


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
