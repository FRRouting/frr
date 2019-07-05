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


def check_bfd_ip_nominal_state():
    tgen = get_topogen()
    # check pm entries
    donna = tgen.gears["r1"].vtysh_cmd("show bfd vrf r1-cust1 peer 192.168.5.4 json")
    donna = json.loads(donna)
    assert donna["peer"] == "192.168.5.4", "r1, 192.168.5.4, bfd entry not present"
    assert donna["status"] == "up", "r1, 192.168.5.4, bfd status not up"
    assert donna["diagnostic"] == "ok", "r1, 192.168.5.4, bfd diagnostic not ok"
    donna = tgen.gears["r1"].vtysh_cmd("show bfd vrf r1-cust1 peer 1005:1::4 json")
    donna = json.loads(donna)
    assert donna["peer"] == "1005:1::4", "r1, 1005:1::4, bfd entry not present"
    assert donna["status"] == "up", "r1, 1005:1::4, bfd status not up"
    assert donna["diagnostic"] == "ok", "r1, 1005:1::4, bfd diagnostic not ok"
    donna = tgen.gears["r1"].vtysh_cmd("show bfd vrf r1-cust1 peer 192.168.0.2 json")
    donna = json.loads(donna)
    assert donna["peer"] == "192.168.0.2", "r1, 192.168.0.2, bfd entry not present"
    assert donna["status"] == "up", "r1, 192.168.0.2, bfd status not up"
    assert donna["diagnostic"] == "ok", "r1, 192.168.0.2, bfd diagnostic not ok"
    donna = tgen.gears["r1"].vtysh_cmd("show bfd vrf r1-cust1 peer 1000:1::2 json")
    donna = json.loads(donna)
    assert donna["peer"] == "1000:1::2", "r1, 1000:1::2, bfd entry not present"
    assert donna["status"] == "up", "r1, 1000:1::2, bfd status not up"
    assert donna["diagnostic"] == "ok", "r1, 1000:1::2, bfd diagnostic not ok"

    # check routing entries
    donna = tgen.gears["r1"].vtysh_cmd("show ip route vrf r1-cust1 0.0.0.0/0 json")
    donna = json.loads(donna)
    if "0.0.0.0/0" not in donna.keys():
        assert 0, "r1, route 0.0.0.0/0 not present"
    routeid = donna["0.0.0.0/0"]
    id_route = 0
    if "selected" not in routeid[id_route].keys():
        id_route = 1
        if "selected" not in routeid[id_route].keys():
            assert 0, "r1, route 0.0.0.0/0 found in BGP RIB is not selected"
    assert routeid[id_route]["selected"] == True, "r1, route 0.0.0.0/0 not set to true"
    if "nexthops" not in routeid[id_route].keys():
        assert 0, "r1, route 0.0.0.0/0 does not have nexthops"
    nhop = routeid[0]["nexthops"]
    if nhop[0]["ip"] == "192.168.5.4":
        assert (
            nhop[0]["interfaceName"] == "r1-eth2"
        ), "r1, nh 192.168.5.3 does not use r1-eth2"
    donna = tgen.gears["r1"].vtysh_cmd("show ipv6 route vrf r1-cust1 ::/0 json")
    donna = json.loads(donna)
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


def test_bfd_connection():
    "Assert that the BFD peers can find themselves."
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    topotest.sleep(5, "waiting that BFD initialises")
    output = tgen.gears["r1"].vtysh_cmd("show running-config")
    logger.info("==== result from show running-config")
    logger.info(output)
    output = tgen.gears["r1"].vtysh_cmd("show bfd vrf r1-cust1 peer 192.168.5.4")
    logger.info("==== result from show bfd vrf r1-cust1 peer 192.168.5.4")
    logger.info(output)
    output = tgen.gears["r1"].vtysh_cmd("show bfd vrf r1-cust1 peer 1005:1::4")
    logger.info("==== result from show bfd vrf r1-cust1 peer 1005:1::4")
    logger.info(output)
    output = tgen.gears["r1"].vtysh_cmd("show bfd vrf r1-cust1 peer 192.168.0.2")
    logger.info("==== result from show bfd vrf r1-cust1 peer 192.168.0.2")
    logger.info(output)
    output = tgen.gears["r1"].vtysh_cmd("show bfd vrf r1-cust1 peer 1000:1::2")
    logger.info("==== result from show bfd vrf r1-cust1 peer 1000:1::2")
    logger.info(output)
    logger.info(
        "==== result from show ip route vrf r1-cust1 and show ipv6 route vrf r1-cust1"
    )
    output = tgen.gears["r1"].vtysh_cmd("show ip route vrf r1-cust1")
    logger.info(output)
    output = tgen.gears["r1"].vtysh_cmd("show ipv6 route vrf r1-cust1")
    logger.info(output)
    check_bfd_ip_nominal_state()


def test_bfd_fast_convergence():
    """
    Assert that BFD notices the link down after simulating network
    failure.
    """

    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    logger.info("=========== disabling r4 device")
    logger.info("waiting for bfd sessions to go down")
    #
    # Disable r4-eth0 and r4-eth1 link.
    tgen.gears["r4"].link_enable("r4-eth1", enabled=False)
    tgen.gears["r4"].link_enable("r4-eth0", enabled=False)
    topotest.sleep(5, "waiting that BFD event propagates")
    output = tgen.gears["r1"].vtysh_cmd("show bfd vrf r1-cust1 peer 192.168.5.4")
    logger.info("==== result from show bfd vrf r1-cust1 peer 192.168.5.4")
    logger.info(output)
    output = tgen.gears["r1"].vtysh_cmd("show bfd vrf r1-cust1 peer 1005:1::4")
    logger.info("==== result from show bfd vrf r1-cust1 peer 1005:1::4")
    logger.info(output)
    output = tgen.gears["r1"].vtysh_cmd("show bfd vrf r1-cust1 peer 192.168.0.2")
    logger.info("==== result from show bfd vrf r1-cust1 peer 192.168.0.2")
    logger.info(output)
    output = tgen.gears["r1"].vtysh_cmd("show bfd vrf r1-cust1 peer 1000:1::2")
    logger.info("==== result from show bfd vrf r1-cust1 peer 1000:1::2")
    logger.info(output)
    logger.info(
        "==== result from show ip route vrf r1-cust1 and show ipv6 route vrf r1-cust1"
    )
    output = tgen.gears["r1"].vtysh_cmd("show ip route vrf r1-cust1")
    logger.info(output)
    output = tgen.gears["r1"].vtysh_cmd("show ipv6 route vrf r1-cust1")
    logger.info(output)
    output = tgen.gears["r1"].vtysh_cmd("show bfd static route")
    logger.info("==== result from show bfd static route")
    logger.info(output)
    # check bfd entries
    donna = tgen.gears["r1"].vtysh_cmd("show bfd vrf r1-cust1 peer 192.168.5.4 json")
    donna = json.loads(donna)
    assert donna["peer"] == "192.168.5.4", "r1, 192.168.5.4, bfd entry not present"
    assert donna["status"] == "down", "r1, 192.168.5.4, bfd status not down"
    assert (
        donna["diagnostic"] == "control detection time expired"
    ), "r1, 192.168.5.4, bfd diagnostic not timeout"
    donna = tgen.gears["r1"].vtysh_cmd("show bfd vrf r1-cust1 peer 1005:1::4 json")
    donna = json.loads(donna)
    assert donna["peer"] == "1005:1::4", "r1, 1005:1::4, bfd entry not present"
    assert donna["status"] == "down", "r1, 1005:1::4, bfd status not down"
    assert (
        donna["diagnostic"] == "control detection time expired"
    ), "r1, 1005:1::4, bfd diagnostic not timeout"
    donna = tgen.gears["r1"].vtysh_cmd("show bfd vrf r1-cust1 peer 192.168.0.2 json")
    donna = json.loads(donna)
    assert donna["peer"] == "192.168.0.2", "r1, 192.168.0.2, bfd entry not present"
    assert donna["status"] == "up", "r1, 192.168.0.2, bfd status not up"
    assert donna["diagnostic"] == "ok", "r1, 192.168.0.2, bfd diagnostic not ok"
    donna = tgen.gears["r1"].vtysh_cmd("show bfd vrf r1-cust1 peer 1000:1::2 json")
    donna = json.loads(donna)
    assert donna["peer"] == "1000:1::2", "r1, 1005:1::3, bfd entry not present"
    assert donna["status"] == "up", "r1, 1000:1::2, bfd status not up"
    assert donna["diagnostic"] == "ok", "r1, 1000:1::2, bfd diagnostic not ok"

    # check routing entries
    donna = tgen.gears["r1"].vtysh_cmd("show ip route vrf r1-cust1 0.0.0.0/0 json")
    donna = json.loads(donna)
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
    donna = tgen.gears["r1"].vtysh_cmd("show ipv6 route vrf r1-cust1 ::/0 json")
    donna = json.loads(donna)
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
    logger.info("waiting for bfd peers to go up again")
    tgen.gears["r4"].link_enable("r4-eth0", enabled=True)
    tgen.gears["r4"].link_enable("r4-eth1", enabled=True)
    topotest.sleep(5, "waiting that BFD event propagates")
    output = tgen.gears["r1"].vtysh_cmd("show bfd vrf r1-cust1 peer 192.168.5.4")
    logger.info("==== result from show bfd vrf r1-cust1 peer 192.168.5.4")
    logger.info(output)
    output = tgen.gears["r1"].vtysh_cmd("show bfd vrf r1-cust1 peer 1005:1::4")
    logger.info("==== result from show bfd vrf r1-cust1 peer 1005:1::4")
    logger.info(output)
    logger.info(
        "==== result from show ip route vrf r1-cust1 and show ipv6 route vrf r1-cust1"
    )
    output = tgen.gears["r1"].vtysh_cmd("show ip route vrf r1-cust1")
    logger.info(output)
    output = tgen.gears["r1"].vtysh_cmd("show ipv6 route vrf r1-cust1")
    logger.info(output)
    output = tgen.gears["r1"].vtysh_cmd("show bfd static route")
    logger.info("==== result from show bfd static route")
    logger.info(output)
    check_bfd_ip_nominal_state()


def test_memory_leak():
    "Run the memory leak test and report results."
    tgen = get_topogen()
    if not tgen.is_memleak_enabled():
        pytest.skip("Memory leak test/report is disabled")

    tgen.report_memory_leaks()


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
