#!/usr/bin/env python
# SPDX-License-Identifier: ISC

#
# Part of NetDEF Topology Tests
#
# Copyright (c) 2018, LabN Consulting, L.L.C.
# Authored by Lou Berger <lberger@labn.net>
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
from lib.topolog import logger
from lib.common_config import required_linux_kernel_version
from lib.checkping import check_ping

pytestmark = [pytest.mark.bgpd]


def build_topo(tgen):
    tgen.add_router("r1")
    tgen.add_router("r2")
    tgen.add_router("ce1")
    tgen.add_router("ce2")
    tgen.add_router("ce3")
    tgen.add_router("ce4")
    tgen.add_router("ce5")
    tgen.add_router("ce6")

    tgen.add_link(tgen.gears["r1"], tgen.gears["r2"], "eth0", "eth0")
    tgen.add_link(tgen.gears["ce1"], tgen.gears["r1"], "eth0", "eth1")
    tgen.add_link(tgen.gears["ce2"], tgen.gears["r2"], "eth0", "eth1")
    tgen.add_link(tgen.gears["ce3"], tgen.gears["r1"], "eth0", "eth2")
    tgen.add_link(tgen.gears["ce4"], tgen.gears["r2"], "eth0", "eth2")
    tgen.add_link(tgen.gears["ce5"], tgen.gears["r1"], "eth0", "eth3")
    tgen.add_link(tgen.gears["ce6"], tgen.gears["r2"], "eth0", "eth3")


def setup_module(mod):
    result = required_linux_kernel_version("5.15")
    if result is not True:
        pytest.skip("Kernel requirements are not met")

    tgen = Topogen(build_topo, mod.__name__)
    tgen.start_topology()
    for rname, router in tgen.routers().items():
        if os.path.exists("{}/{}/setup.sh".format(CWD, rname)):
            router.run("/bin/bash {}/{}/setup.sh".format(CWD, rname))
        router.load_config(
            TopoRouter.RD_ZEBRA, os.path.join(CWD, "{}/zebra.conf".format(rname))
        )
        router.load_config(
            TopoRouter.RD_BGP, os.path.join(CWD, "{}/bgpd.conf".format(rname))
        )

    tgen.gears["r1"].run("sysctl net.vrf.strict_mode=1")
    tgen.gears["r1"].run("ip link add vrf10 type vrf table 10")
    tgen.gears["r1"].run("ip link set vrf10 up")
    tgen.gears["r1"].run("ip link add vrf20 type vrf table 20")
    tgen.gears["r1"].run("ip link set vrf20 up")
    tgen.gears["r1"].run("ip link set eth1 master vrf10")
    tgen.gears["r1"].run("ip link set eth2 master vrf10")
    tgen.gears["r1"].run("ip link set eth3 master vrf20")

    tgen.gears["r2"].run("sysctl net.vrf.strict_mode=1")
    tgen.gears["r2"].run("ip link add vrf10 type vrf table 10")
    tgen.gears["r2"].run("ip link set vrf10 up")
    tgen.gears["r2"].run("ip link add vrf20 type vrf table 20")
    tgen.gears["r2"].run("ip link set vrf20 up")
    tgen.gears["r2"].run("ip link set eth1 master vrf10")
    tgen.gears["r2"].run("ip link set eth2 master vrf20")
    tgen.gears["r2"].run("ip link set eth3 master vrf20")
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
    def _check(name, dest_addr, match):
        logger.info("polling")
        tgen = get_topogen()
        router = tgen.gears[name]
        output = json.loads(router.vtysh_cmd(cmd))
        expected = open_json_file("{}/{}".format(CWD, expected_file))
        return topotest.json_cmp(output, expected)

    logger.info('[+] check {} "{}" {}'.format(name, cmd, expected_file))
    tgen = get_topogen()
    func = functools.partial(_check, name, cmd, expected_file)
    _, result = topotest.run_and_expect(func, None, count=10, wait=0.5)
    assert result is None, "Failed"


def test_rib():
    check_rib("r1", "show bgp ipv4 vpn json", "r1/vpnv4_rib.json")
    check_rib("r2", "show bgp ipv4 vpn json", "r2/vpnv4_rib.json")
    check_rib("r1", "show ip route vrf vrf10 json", "r1/vrf10_rib.json")
    check_rib("r1", "show ip route vrf vrf20 json", "r1/vrf20_rib.json")
    check_rib("r2", "show ip route vrf vrf10 json", "r2/vrf10_rib.json")
    check_rib("r2", "show ip route vrf vrf20 json", "r2/vrf20_rib.json")
    check_rib("ce1", "show ip route json", "ce1/ip_rib.json")
    check_rib("ce2", "show ip route json", "ce2/ip_rib.json")
    check_rib("ce3", "show ip route json", "ce3/ip_rib.json")
    check_rib("ce4", "show ip route json", "ce4/ip_rib.json")
    check_rib("ce5", "show ip route json", "ce5/ip_rib.json")
    check_rib("ce6", "show ip route json", "ce6/ip_rib.json")


def test_ping():
    check_ping("ce1", "192.168.2.2", True, 10, 0.5)
    check_ping("ce1", "192.168.3.2", True, 10, 0.5)
    check_ping("ce1", "192.168.4.2", False, 10, 0.5)
    check_ping("ce1", "192.168.5.2", False, 10, 0.5)
    check_ping("ce1", "192.168.6.2", False, 10, 0.5)
    check_ping("ce4", "192.168.1.2", False, 10, 0.5)
    check_ping("ce4", "192.168.2.2", False, 10, 0.5)
    check_ping("ce4", "192.168.3.2", False, 10, 0.5)
    check_ping("ce4", "192.168.5.2", True, 10, 0.5)
    check_ping("ce4", "192.168.6.2", True, 10, 0.5)


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
