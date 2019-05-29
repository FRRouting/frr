#!/usr/bin/env python

#
# test_pmd_tracking_vrf_topo6.py
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
test_pmd_tracking_vrf_topo6.py: Test the FRR/Quagga PM daemon.
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

    # in addition to move interfaces to appropriate netns
    # - ipv6 forwarding is enabled for each namespace
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
    cmds = [
        "sysctl -w net.ipv4.tcp_l3mdev_accept={}".format(l3mdev_accept),
        "ip link add {0}-cust1 type vrf table 10",
        "ip link set dev {0}-cust1 up",
        "ip link set dev {0}-eth0 master {0}-cust1",
        "ip link set dev {0}-eth1 master {0}-cust1",
        "sysctl net.ipv6.conf.all.forwarding=1",
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
        commands = cmds
        if rname == "r1":
            commands += cmds2
        if rname == "r3":
            commands += cmds3

        for cmd in commands:
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


def teardown_module(_mod):
    "Teardown the pytest environment"

    tgen = get_topogen()

    cmds2 = ["ip link set {0}-eth2 nomaster"]
    cmds = [
        "ip link set {0}-eth1 nomaster",
        "ip link set {0}-eth0 nomaster",
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


def check_pm_ip_nominal_state():
    tgen = get_topogen()
    # check pm entries
    donna = tgen.gears["r1"].vtysh_cmd(
        "show pm vrf r1-cust1 session 192.168.5.4 json", isjson=True
    )
    assert donna[0]["peer"] == "192.168.5.4", "r1, 192.168.5.4, pm entry not present"
    assert (
        donna[0]["dst-ip"] == "192.168.7.3"
    ), "r1, 192.168.5.4, pm alternate ip not correct"
    assert (
        donna[0]["local"] == "192.168.5.1"
    ), "r1, 192.168.5.4, pm local address not 192.168.5.1"
    assert donna[0]["status"] == "up", "r1, 192.168.5.4, pm status not up"
    assert donna[0]["diagnostic"] == "echo ok", "r1, 192.168.5.4, pm diagnostic not ok"
    assert donna[0]["label"] == "other_session", "r1, 192.168.5.4, label value not ok"
    donna = tgen.gears["r1"].vtysh_cmd(
        "show pm vrf r1-cust1 session 1005:1::4 json", isjson=True
    )
    assert donna[0]["peer"] == "1005:1::4", "r1, 1005:1::4, pm entry not present"
    assert (
        donna[0]["dst-ip"] == "1007:1::3"
    ), "r1, 1005:1::4, pm alternate ip not correct"
    assert (
        donna[0]["local"] == "1005:1::1"
    ), "r1, 1005:1::4, pm local address not 1005:1::1"
    assert donna[0]["status"] == "up", "r1, 1005:1::4, pm status not up"
    assert donna[0]["diagnostic"] == "echo ok", "r1, 1005:1::4, pm diagnostic not ok"
    assert donna[0]["label"] == "keyword_other", "r1, 1005:1::4, label value not ok"
    donna = tgen.gears["r1"].vtysh_cmd(
        "show pm vrf r1-cust1 session 192.168.0.2 json", isjson=True
    )
    assert donna[0]["peer"] == "192.168.0.2", "r1, 192.168.0.2, pm entry not present"
    assert (
        donna[0]["dst-ip"] == "192.168.6.3"
    ), "r1, 192.168.0.2, pm alternate ip not correct"
    assert (
        donna[0]["local"] == "192.168.0.1"
    ), "r1, 192.168.0.2, pm local address not 192.168.0.1"
    assert donna[0]["status"] == "up", "r1, 192.168.0.2, pm status not up"
    assert donna[0]["diagnostic"] == "echo ok", "r1, 192.168.0.2, pm diagnostic not ok"
    assert donna[0]["label"] == "index_standard", "r1, 192.168.0.2, label value not ok"
    donna = tgen.gears["r1"].vtysh_cmd(
        "show pm vrf r1-cust1 session 1000:1::2 json", isjson=True
    )
    assert donna[0]["peer"] == "1000:1::2", "r1, 1000:1::2, pm entry not present"
    assert (
        donna[0]["dst-ip"] == "1006:1::3"
    ), "r1, 1000:1::2, pm alternate ip not correct"
    assert (
        donna[0]["local"] == "1000:1::1"
    ), "r1, 1000:1::2, pm local address not 1000:1::1"
    assert donna[0]["status"] == "up", "r1, 1000:1::2, pm status not up"
    assert donna[0]["diagnostic"] == "echo ok", "r1, 1000:1::2, pm diagnostic not ok"
    assert donna[0]["label"] == "keyword_special", "r1, 1000:1::2, label value not ok"

    # check routing entries
    donna = tgen.gears["r1"].vtysh_cmd(
        "show ip route vrf r1-cust1 0.0.0.0/0 json", isjson=True
    )
    if "0.0.0.0/0" not in donna.keys():
        assert 0, "r1, route 0.0.0.0/0 not present"
    routeid = donna["0.0.0.0/0"]
    if "selected" not in routeid[0].keys():
        assert 0, "r1, route 0.0.0.0/0 found in BGP RIB is not selected"
    assert routeid[0]["selected"] == True, "r1, route 0.0.0.0/0 not set to true"
    if "nexthops" not in routeid[0].keys():
        assert 0, "r1, route 0.0.0.0/0 does not have nexthops"
    nhop = routeid[0]["nexthops"]
    if nhop[0]["ip"] == "192.168.5.4":
        assert (
            nhop[0]["interfaceName"] == "r1-eth2"
        ), "r1, nh 192.168.5.3 does not use r1-eth2"
    donna = tgen.gears["r1"].vtysh_cmd(
        "show ipv6 route vrf r1-cust1 ::/0 json", isjson=True
    )
    if "::/0" not in donna.keys():
        assert 0, "r1, route ::/0 not present"
    routeid = donna["::/0"]
    idx = 0
    if "selected" not in routeid[0].keys():
        if "selected" not in routeid[1].keys():
            assert 0, "r1, route ::/0 found in BGP RIB is not selected"
        else:
            idx = 1
    assert routeid[idx]["selected"] == True, "r1, route ::/0 not set to true"
    if "nexthops" not in routeid[0].keys():
        assert 0, "r1, route ::/0 does not have nexthops"
    nhop = routeid[idx]["nexthops"]
    if nhop[0]["ip"] == "1005:1::4":
        assert (
            nhop[0]["interfaceName"] == "r1-eth2"
        ), "r1, nh 1005:1::4 does not use r1-eth2"

    cmds_check_file = [
        "cat /tmp/ipv4eth0_status.txt",
        "cat /tmp/ipv6eth0_status.txt",
        "cat /tmp/ipv4eth2_status.txt",
        "cat /tmp/ipv6eth2_status.txt",
    ]
    for cmd in cmds_check_file:
        output = tgen.net["r1"].cmd(cmd)
        logger.info("dump for {0} is {1}".format(cmd, output))
        assert output == "0", "r1, failure with notification to file"


def test_pm_connection():
    "Assert that the PM peers can find themselves."
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    topotest.sleep(5, "waiting that PM initialises")
    output = tgen.gears["r1"].vtysh_cmd("show running-config", isjson=False)
    logger.info("==== result from show running-config")
    logger.info(output)
    output = tgen.gears["r1"].vtysh_cmd(
        "show pm vrf r1-cust1 session 192.168.5.4", isjson=False
    )
    logger.info("==== result from show pm vrf r1-cust1 session 192.168.5.4")
    logger.info(output)
    output = tgen.gears["r1"].vtysh_cmd(
        "show pm vrf r1-cust1 session 1005:1::4", isjson=False
    )
    logger.info("==== result from show pm vrf r1-cust1 session 1005:1::4")
    logger.info(output)
    output = tgen.gears["r1"].vtysh_cmd(
        "show pm vrf r1-cust1 session 192.168.0.2", isjson=False
    )
    logger.info("==== result from show pm vrf r1-cust1 session 192.168.0.2")
    logger.info(output)
    output = tgen.gears["r1"].vtysh_cmd(
        "show pm vrf r1-cust1 session 1000:1::2", isjson=False
    )
    logger.info("==== result from show pm vrf r1-cust1 session 1000:1::2")
    logger.info(output)
    logger.info(
        "==== result from show ip route vrf r1-cust1 and show ipv6 route vrf r1-cust1"
    )
    output = tgen.gears["r1"].vtysh_cmd("show ip route vrf r1-cust1", isjson=False)
    logger.info(output)
    output = tgen.gears["r1"].vtysh_cmd("show ipv6 route vrf r1-cust1", isjson=False)
    logger.info(output)

    check_pm_ip_nominal_state()


def test_pm_fast_convergence():
    """
    Assert that PM notices the link down after simulating network
    failure.
    """

    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    logger.info("=========== disabling r4 device")
    logger.info("waiting for pm sessions to go down")
    #
    # Disable r4-eth0 and r4-eth1 link.
    tgen.gears["r4"].link_enable("r4-eth1", enabled=False)
    tgen.gears["r4"].link_enable("r4-eth0", enabled=False)
    topotest.sleep(5, "waiting that PM event propagates")
    output = tgen.gears["r1"].vtysh_cmd(
        "show pm vrf r1-cust1 session 192.168.5.4", isjson=False
    )
    logger.info("==== result from show pm vrf r1-cust1 session 192.168.5.4")
    logger.info(output)
    output = tgen.gears["r1"].vtysh_cmd(
        "show pm vrf r1-cust1 session 1005:1::4", isjson=False
    )
    logger.info("==== result from show pm vrf r1-cust1 session 1005:1::4")
    logger.info(output)
    output = tgen.gears["r1"].vtysh_cmd(
        "show pm vrf r1-cust1 session 192.168.0.2", isjson=False
    )
    logger.info("==== result from show pm vrf r1-cust1 session 192.168.0.2")
    logger.info(output)
    output = tgen.gears["r1"].vtysh_cmd(
        "show pm vrf r1-cust1 session 1000:1::2", isjson=False
    )
    logger.info("==== result from show pm vrf r1-cust1 session 1000:1::2")
    logger.info(output)
    logger.info(
        "==== result from show ip route vrf r1-cust1 and show ipv6 route vrf r1-cust1"
    )
    output = tgen.gears["r1"].vtysh_cmd("show ip route vrf r1-cust1", isjson=False)
    logger.info(output)
    output = tgen.gears["r1"].vtysh_cmd("show ipv6 route vrf r1-cust1", isjson=False)
    logger.info(output)
    output = tgen.gears["r1"].vtysh_cmd("show static routing pm", isjson=False)
    logger.info("==== result from show static routing pm")
    logger.info(output)
    # check pm entries
    donna = tgen.gears["r1"].vtysh_cmd(
        "show pm vrf r1-cust1 session 192.168.5.4 json", isjson=True
    )
    assert donna[0]["peer"] == "192.168.5.4", "r1, 192.168.5.4, pm entry not present"
    assert donna[0]["status"] == "down", "r1, 192.168.5.4, pm status not down"
    assert (
        donna[0]["diagnostic"] == "echo timeout"
    ), "r1, 192.168.5.4, pm diagnostic not timeout"
    donna = tgen.gears["r1"].vtysh_cmd(
        "show pm vrf r1-cust1 session 1005:1::4 json", isjson=True
    )
    assert donna[0]["peer"] == "1005:1::4", "r1, 1005:1::4, pm entry not present"
    assert donna[0]["status"] == "down", "r1, 1005:1::4, pm status not down"
    assert (
        donna[0]["diagnostic"] == "echo timeout"
    ), "r1, 1005:1::4, pm diagnostic not timeout"
    donna = tgen.gears["r1"].vtysh_cmd(
        "show pm vrf r1-cust1 session 192.168.0.2 json", isjson=True
    )
    assert donna[0]["peer"] == "192.168.0.2", "r1, 192.168.0.2, pm entry not present"
    assert (
        donna[0]["local"] == "192.168.0.1"
    ), "r1, 192.168.0.2, pm local address not 192.168.0.1"
    assert donna[0]["status"] == "up", "r1, 192.168.0.2, pm status not up"
    assert donna[0]["diagnostic"] == "echo ok", "r1, 192.168.0.2, pm diagnostic not ok"
    donna = tgen.gears["r1"].vtysh_cmd(
        "show pm vrf r1-cust1 session 1000:1::2 json", isjson=True
    )
    assert donna[0]["peer"] == "1000:1::2", "r1, 1005:1::3, pm entry not present"
    assert donna[0]["status"] == "up", "r1, 1000:1::2, pm status not up"
    assert donna[0]["diagnostic"] == "echo ok", "r1, 1000:1::2, pm diagnostic not ok"

    # check routing entries
    donna = tgen.gears["r1"].vtysh_cmd(
        "show ip route vrf r1-cust1 0.0.0.0/0 json", isjson=True
    )
    if "0.0.0.0/0" not in donna.keys():
        assert 0, "r1, route 0.0.0.0/0 not present"
    routeid = donna["0.0.0.0/0"]
    if "selected" not in routeid[0].keys():
        assert 0, "r1, route 0.0.0.0/0 found in BGP RIB is not selected"
    assert routeid[0]["selected"] == True, "r1, route 0.0.0.0/0 not set to true"
    if "nexthops" not in routeid[0].keys():
        assert 0, "r1, route 0.0.0.0/0 does not have nexthops"
    nhop = routeid[0]["nexthops"]
    if nhop[0]["ip"] == "192.168.0.2":
        assert (
            nhop[0]["interfaceName"] == "r1-eth0"
        ), "r1, nh 192.168.0.2 does not use r1-eth0"
    donna = tgen.gears["r1"].vtysh_cmd(
        "show ipv6 route vrf r1-cust1 ::/0 json", isjson=True
    )
    if "::/0" not in donna.keys():
        assert 0, "r1, route ::/0 not present"
    routeid = donna["::/0"]
    if "selected" not in routeid[0].keys():
        assert 0, "r1, route ::/0 found in BGP RIB is not selected"
    assert routeid[0]["selected"] == True, "r1, route ::/0 not set to true"
    if "nexthops" not in routeid[0].keys():
        assert 0, "r1, route ::/0 does not have nexthops"
    nhop = routeid[0]["nexthops"]
    if nhop[0]["ip"] == "1000:1::2":
        assert nhop[0]["interfaceName"] == "r1-eth0", "r1, nh ::/0 does not use r1-eth0"
    cmds_check_file_1 = ["cat /tmp/ipv4eth0_status.txt", "cat /tmp/ipv6eth0_status.txt"]
    cmds_check_file_0 = ["cat /tmp/ipv4eth2_status.txt", "cat /tmp/ipv6eth2_status.txt"]
    for cmd in cmds_check_file_1:
        output = tgen.net["r1"].cmd(cmd)
        logger.info("dump for {0} is {1}".format(cmd, output))
        assert output == "0", "r1, failure with notification to file, expected 1"
    for cmd in cmds_check_file_0:
        output = tgen.net["r1"].cmd(cmd)
        logger.info("dump for {0} is {1}".format(cmd, output))
        assert output == "1", "r1, failure with notification to file, expected 0"

    # expected = 2 mhop sessions should use 192.168.0.2 as gateway
    # as well as r1-eth0 interface
    logger.info("=========== enabling r4 device")
    logger.info("waiting for pm peers to go up again")
    tgen.gears["r4"].link_enable("r4-eth0", enabled=True)
    tgen.gears["r4"].link_enable("r4-eth1", enabled=True)
    topotest.sleep(5, "waiting that PM event propagates")
    output = tgen.gears["r1"].vtysh_cmd(
        "show pm vrf r1-cust1 session 192.168.5.4", isjson=False
    )
    logger.info("==== result from show pm vrf r1-cust1 session 192.168.5.4")
    logger.info(output)
    output = tgen.gears["r1"].vtysh_cmd(
        "show pm vrf r1-cust1 session 1005:1::4", isjson=False
    )
    logger.info("==== result from show pm vrf r1-cust1 session 1005:1::4")
    logger.info(output)
    logger.info(
        "==== result from show ip route vrf r1-cust1 and show ipv6 route vrf r1-cust1"
    )
    output = tgen.gears["r1"].vtysh_cmd("show ip route vrf r1-cust1", isjson=False)
    logger.info(output)
    output = tgen.gears["r1"].vtysh_cmd("show ipv6 route vrf r1-cust1", isjson=False)
    logger.info(output)
    output = tgen.gears["r1"].vtysh_cmd("show static routing pm", isjson=False)
    logger.info("==== result from show static routing pm")
    logger.info(output)
    check_pm_ip_nominal_state()


def test_memory_leak():
    "Run the memory leak test and report results."
    tgen = get_topogen()
    if not tgen.is_memleak_enabled():
        pytest.skip("Memory leak test/report is disabled")

    tgen.report_memory_leaks()


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
