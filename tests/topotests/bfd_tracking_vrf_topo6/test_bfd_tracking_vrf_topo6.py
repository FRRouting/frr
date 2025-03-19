#!/usr/bin/env python

#
# test_bfd_tracking_vrf_topo6.py
#
# Copyright 2019 6WIND S.A.
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
test_bfd_tracking_vrf_topo6.py: Test the FRR BFD Tracking.
"""

import os
import sys
import json
import platform
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
    switch.add_link(tgen.gears["r4"])
    switch.add_link(tgen.gears["r3"])

    switch = tgen.add_switch("s4")
    switch.add_link(tgen.gears["r3"])

    switch = tgen.add_switch("s5")
    switch.add_link(tgen.gears["r1"])

    switch = tgen.add_switch("s6")
    switch.add_link(tgen.gears["r1"])
    switch.add_link(tgen.gears["r4"])


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

    # - ipv6 address are kept after link up / link down operations
    cmds_rm = [
        "rm /tmp/ipv4eth0_status.txt -rf",
        "rm /tmp/ipv6eth0_status.txt -rf",
        "rm /tmp/ipv4eth2_status.txt -rf",
        "rm /tmp/ipv6eth2_status.txt -rf",
    ]
    for cmd in cmds_rm:
        logger.info("suppressing {0}".format(cmd))
        output = tgen.net["r1"].cmd(cmd)
        logger.info("output: " + output)

    logger.info("setting net.ipv4.tcp_l3mdev_accept={}".format(l3mdev_accept))
    logger.info("setting net.ipv4.udp_l3mdev_accept={}".format(l3mdev_accept))
    cmds = [
        "sysctl -w net.ipv4.tcp_l3mdev_accept={}".format(l3mdev_accept),
        "sysctl -w net.ipv4.udp_l3mdev_accept={}".format(l3mdev_accept),
        "ip link add {0}-cust1 type vrf table 10",
        "ip link set dev {0}-cust1 up",
        "ip link set dev {0}-eth0 master {0}-cust1",
        "ip link set dev {0}-eth1 master {0}-cust1",
        "sysctl -w net.ipv6.conf.all.forwarding=1",
        "sysctl net.ipv6.conf.{0}-eth0.keep_addr_on_down=1",
        "sysctl net.ipv6.conf.{0}-eth1.keep_addr_on_down=1",
    ]

    cmds2 = [
        "ip link set dev {0}-eth2 master {0}-cust1",
        "sysctl net.ipv6.conf.{0}-eth2.keep_addr_on_down=1",
    ]

    cmds3 = [
        "ip link add loop11 type dummy",
        "ip link set dev loop11 master {0}-cust1",
        "sysctl net.ipv6.conf.loop11.keep_addr_on_down=1",
        "ip link add loop21 type dummy",
        "ip link set dev loop21 master {0}-cust1",
        "sysctl net.ipv6.conf.loop21.keep_addr_on_down=1",
        "ip link add loop12 type dummy",
        "ip link set dev loop12 master {0}-cust1",
        "sysctl net.ipv6.conf.loop12.keep_addr_on_down=1",
        "ip link add loop22 type dummy",
        "ip link set dev loop22 master {0}-cust1",
        "sysctl net.ipv6.conf.loop22.keep_addr_on_down=1",
    ]

    for rname, router in router_list.items():
        for cmd in cmds:
            cmd = cmd.format(rname)
            output = tgen.net[rname].cmd(cmd.format(rname))
            logger.info("output: " + output)
        if rname == "r1":
            for cmd in cmds2:
                cmd = cmd.format(rname)
                output = tgen.net[rname].cmd(cmd.format(rname))
                logger.info("output: " + output)
        if rname == "r3":
            for cmd in cmds3:
                cmd = cmd.format(rname)
                output = tgen.net[rname].cmd(cmd.format(rname))
                logger.info("output: " + output)

    for rname, router in router_list.items():
        router.load_config(
            TopoRouter.RD_ZEBRA,
            os.path.join(CWD, "{}/zebra.conf".format(rname)),
        )
        router.load_config(
            TopoRouter.RD_BFD,
            os.path.join(CWD, "{}/bfdd.conf".format(rname)),
            "-M bfd_tracking",
        )

    # Initialize all routers.
    tgen.start_router()


def teardown_module(_mod):
    "Teardown the pytest environment"

    tgen = get_topogen()

    cmds2 = ["ip link set {0}-eth2 nomaster"]
    cmds = [
        "ip link set dev {0}-eth1 nomaster",
        "ip link set dev {0}-eth0 nomaster",
        "ip link delete {0}-cust1",
    ]

    router_list = tgen.routers()
    for rname, router in router_list.items():
        if rname == "r1":
            for cmd in cmds2:
                tgen.net[rname].cmd(cmd.format(rname))
        for cmd in cmds:
            tgen.net[rname].cmd(cmd.format(rname))

    tgen.stop_topology()


def check_bfd_state(step=None):
    tgen = get_topogen()

    r1 = tgen.gears["r1"]

    step_suffix = f"_step{step}" if step else ""

    logger.info("Check BFD entries")
    reffile = os.path.join(CWD, f"r1/show_bfd_peers{step_suffix}.json")
    expected = json.loads(open(reffile).read())
    cmd = "show bfd peers json"
    test_func = functools.partial(topotest.router_json_cmp, r1, cmd, expected)
    _, res = topotest.run_and_expect(test_func, None, count=30, wait=1)
    assertmsg = f"BFD did not converge. Error on r1 {cmd}"
    assert res is None, assertmsg

    logger.info("Check IPv4 default route")
    reffile = os.path.join(CWD, f"r1/show_ip_route{step_suffix}.json")
    expected = json.loads(open(reffile).read())
    cmd = "show ip route vrf r1-cust1 0.0.0.0/0 json"
    test_func = functools.partial(topotest.router_json_cmp, r1, cmd, expected)
    _, res = topotest.run_and_expect(test_func, None, count=30, wait=1)
    assertmsg = f"BFD did not converge. Error on r1 {cmd}"
    assert res is None, assertmsg

    logger.info("Check IPv6 default route")
    reffile = os.path.join(CWD, f"r1/show_ipv6_route{step_suffix}.json")
    expected = json.loads(open(reffile).read())
    cmd = "show ipv6 route vrf r1-cust1 ::/0 json"
    test_func = functools.partial(topotest.router_json_cmp, r1, cmd, expected)
    _, res = topotest.run_and_expect(test_func, None, count=30, wait=1)
    assertmsg = f"BFD did not converge. Error on r1 {cmd}"
    assert res is None, assertmsg

    logger.info("Check tracker file")

    files = [
        "/tmp/ipv4eth0_status.txt",
        "/tmp/ipv6eth0_status.txt",
        "/tmp/ipv4eth2_status.txt",
        "/tmp/ipv6eth2_status.txt",
    ]

    for file in files:
        output = tgen.net["r1"].cmd(f"cat {file}")
        expected = "0" if not step or "eth0" in file else "1"
        assert (
            output == expected
        ), "r1, tracker files {file} contains {output}. Expected {expected}"


def test_bfd_convergence():
    "Assert that the BFD peers can find themselves."

    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    check_bfd_state()


def test_bfd_tracking_step1():
    """
    Assert that BFD notices the link down after simulating network
    failure.
    """

    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    logger.info("Set r4-eth0 and r4-eth1 down")
    tgen.gears["r4"].link_enable("r4-eth0", enabled=False)
    tgen.gears["r4"].link_enable("r4-eth1", enabled=False)

    check_bfd_state(step=1)


def test_bfd_tracking_step2():
    """
    Assert that BFD goes back to the nominal stater after links are back up.
    """

    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    logger.info("Set r4-eth0 and r4-eth1 up")
    tgen.gears["r4"].link_enable("r4-eth0", enabled=True)
    tgen.gears["r4"].link_enable("r4-eth1", enabled=True)

    check_bfd_state()


def test_memory_leak():
    "Run the memory leak test and report results."
    tgen = get_topogen()
    if not tgen.is_memleak_enabled():
        pytest.skip("Memory leak test/report is disabled")

    tgen.report_memory_leaks()


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
