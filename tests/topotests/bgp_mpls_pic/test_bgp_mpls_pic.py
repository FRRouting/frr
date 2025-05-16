#!/usr/bin/env python
# SPDX-License-Identifier: ISC

#
# Part of NetDEF Topology Tests
#
# Copyright (c) 2025 by 6WIND
#

import os
import sys
import json
import functools
import pytest

CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

# pylint: disable=C0413
# Import topogen and topotest helpers
from lib import topotest
from lib.topogen import Topogen, TopoRouter, get_topogen
from lib.common_config import required_linux_kernel_version
from lib.topolog import logger
from lib.checkping import check_ping

pytestmark = [pytest.mark.bgpd, pytest.mark.staticd]


def build_topo(tgen):
    tgen.add_router("r1")
    tgen.add_router("r2")
    tgen.add_router("r3")

    tgen.add_router("c11")
    tgen.add_router("c21")
    tgen.add_router("c22")
    tgen.add_router("c31")
    tgen.add_router("c32")

    tgen.add_link(tgen.gears["r1"], tgen.gears["r2"], "eth0", "eth0")
    tgen.add_link(tgen.gears["r1"], tgen.gears["r3"], "eth1", "eth0")
    tgen.add_link(tgen.gears["r1"], tgen.gears["c11"], "eth2", "eth0")
    tgen.add_link(tgen.gears["r2"], tgen.gears["c21"], "eth1", "eth0")
    tgen.add_link(tgen.gears["r2"], tgen.gears["c22"], "eth2", "eth0")
    tgen.add_link(tgen.gears["r3"], tgen.gears["c31"], "eth1", "eth0")
    tgen.add_link(tgen.gears["r3"], tgen.gears["c32"], "eth2", "eth0")


def setup_module(mod):
    result = required_linux_kernel_version("5.15")
    if result is not True:
        pytest.skip("Kernel requirements are not met")

    tgen = Topogen(build_topo, mod.__name__)
    tgen.start_topology()

    for rname, router in tgen.routers().items():
        if rname in ("r1", "r2", "r3"):
            router.use_pic_mode()
        router.load_frr_config(os.path.join(CWD, "{}/frr.conf".format(rname)))

    tgen.gears["r1"].run("sysctl net.vrf.strict_mode=1")
    tgen.gears["r1"].run("ip link add vrf10 type vrf table 10")
    tgen.gears["r1"].run("ip link set vrf10 up")
    tgen.gears["r1"].run("ip link add vrf20 type vrf table 20")
    tgen.gears["r1"].run("ip link set vrf20 up")
    tgen.gears["r1"].run("ip link set eth2 master vrf10")
    tgen.gears["r1"].run("ip link set eth3 master vrf20")

    tgen.gears["r2"].run("sysctl net.vrf.strict_mode=1")
    tgen.gears["r2"].run("ip link add vrf10 type vrf table 10")
    tgen.gears["r2"].run("ip link set vrf10 up")
    tgen.gears["r2"].run("ip link add vrf20 type vrf table 20")
    tgen.gears["r2"].run("ip link set vrf20 up")
    tgen.gears["r2"].run("ip link set eth1 master vrf10")
    tgen.gears["r2"].run("ip link set eth2 master vrf20")

    tgen.gears["r3"].run("sysctl net.vrf.strict_mode=1")
    tgen.gears["r3"].run("ip link add vrf10 type vrf table 10")
    tgen.gears["r3"].run("ip link set vrf10 up")
    tgen.gears["r3"].run("ip link add vrf20 type vrf table 20")
    tgen.gears["r3"].run("ip link set vrf20 up")
    tgen.gears["r3"].run("ip link set eth1 master vrf10")
    tgen.gears["r3"].run("ip link set eth2 master vrf20")

    tgen.start_router()


def teardown_module(mod):
    tgen = get_topogen()
    tgen.stop_topology()


def open_json_file(filename):
    try:
        with open(filename, "r") as f:
            return json.load(f)
    except IOError:
        assert False, "Could not read file {}".format(filename)


def check_rib(name, cmd, expected_file):
    def _check(name, cmd, expected_file):
        logger.info("polling")
        tgen = get_topogen()
        router = tgen.gears[name]
        output = json.loads(router.vtysh_cmd(cmd))
        expected = open_json_file("{}/{}".format(CWD, expected_file))
        return topotest.json_cmp(output, expected)

    logger.info('[+] check {} "{}" {}'.format(name, cmd, expected_file))
    tgen = get_topogen()
    func = functools.partial(_check, name, cmd, expected_file)
    _, result = topotest.run_and_expect(func, None, count=30, wait=0.5)
    assert result is None, "Failed"


def test_bgp_route_presence():
    """
    Assert that the 192.168.2.0/24 prefix is present in unicast and vpn RIB
    """
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)
    logger.info("Check that 192.168.2.0/24 vpnv4 entry has 4 entry with remote-sid")
    check_rib("r1", "show bgp ipv4 vpn 192.168.2.0/24 json", "json/r1_vpnv4_route.json")

    logger.info("Check that 192.168.2.0/24 unicast entry has 4 entry with remote-sid")

    check_rib(
        "r1",
        "show bgp vrf vrf10 ipv4 unicast 192.168.2.0/24 json",
        "json/r1_bgp_vrf10_route.json",
    )

    logger.info(
        "Check that 192.168.2.0/24 unicast entry in fib has 4 entry with remote-sid"
    )

    check_rib(
        "r1",
        "show ip route vrf vrf10 192.168.2.0/24 json",
        "json/r1_ip_vrf10_route.json",
    )

    r1 = tgen.gears["r1"]
    json_ip_route = json.loads(
        r1.vtysh_cmd("show ip route vrf vrf10 192.168.2.0/24 json")
    )
    logger.info(json_ip_route)
    nexthopGroupId = json_ip_route.get("192.168.2.0/24")[0].get("nexthopGroupId")
    picNexthopId = json_ip_route.get("192.168.2.0/24")[0].get("picNexthopId")
    installedNexthopGroupId = json_ip_route.get("192.168.2.0/24")[0].get(
        "installedNexthopGroupId"
    )
    installedPicNexthopGroupId = json_ip_route.get("192.168.2.0/24")[0].get(
        "installedPicNexthopGroupId"
    )
    logger.info(f"nexthopGroupId: {nexthopGroupId}")
    logger.info(f"picNexthopId: {picNexthopId}")
    logger.info(f"installedNexthopGroupId: {installedNexthopGroupId}")
    logger.info(f"installedPicNexthopGroupId: {installedPicNexthopGroupId}")

    logger.info("Check pic nexthop")

    def _check_pic_nexthop():
        nh_cmd = "show nexthop-group rib " + str(picNexthopId) + " json"
        output = json.loads(tgen.gears["r1"].vtysh_cmd(nh_cmd))
        output_subdict = output.get(str(picNexthopId), {})
        expected = {
            "type": "zebra",
            "vrf": "default",
            "valid": True,
            "installed": True,
            "nexthops": [
                {
                    "ip": "2001:db8:12::2",
                    "afi": "ipv6",
                    "vrf": "default",
                    "active": True,
                },
                {
                    "ip": "2001:db8:13::3",
                    "afi": "ipv6",
                    "vrf": "default",
                    "active": True,
                },
            ],
            "pic_dependents": [nexthopGroupId],
        }
        return topotest.json_cmp(output_subdict, expected)

    test_func = functools.partial(_check_pic_nexthop)
    _, result = topotest.run_and_expect(test_func, None, count=5, wait=0.5)
    assert result is None, "Failed to check that pic nh has pic_dependents."


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
