#!/usr/bin/env python
# SPDX-License-Identifier: ISC

# Copyright (c) 2025, Onvox LLC
# Authored by Jonathan Voss <jvoss@onvox.net>
#
# Test SRv6 L3VPN with CE BGP peers within a VRF
#

import os
import re
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

    tgen.add_link(tgen.gears["r1"], tgen.gears["r2"], "eth0", "eth0")
    tgen.add_link(tgen.gears["ce1"], tgen.gears["r1"], "eth0", "eth1")
    tgen.add_link(tgen.gears["ce2"], tgen.gears["r2"], "eth0", "eth1")


def setup_module(mod):
    result = required_linux_kernel_version("5.14")
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


def check_rib(name, cmd, expected_file, count=30, wait=0.5):
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
    _, result = topotest.run_and_expect(func, None, count, wait)
    assert result is None, "Failed"


def test_rib():
    check_rib("r1", "show bgp ipv4 vpn json", "r1/vpnv4_rib.json", 120, 1)
    check_rib("r2", "show bgp ipv4 vpn json", "r2/vpnv4_rib.json")
    check_rib("r1", "show ip route vrf vrf10 json", "r1/vrf10v4_rib.json")
    check_rib("r2", "show ip route vrf vrf10 json", "r2/vrf10v4_rib.json")
    check_rib("ce1", "show ip route json", "ce1/ip_rib.json")
    check_rib("ce2", "show ip route json", "ce2/ip_rib.json")

    check_rib("r1", "show bgp ipv6 vpn json", "r1/vpnv6_rib.json")
    check_rib("r2", "show bgp ipv6 vpn json", "r2/vpnv6_rib.json")
    check_rib("r1", "show ipv6 route vrf vrf10 json", "r1/vrf10v6_rib.json")
    check_rib("r2", "show ipv6 route vrf vrf10 json", "r2/vrf10v6_rib.json")
    check_rib("ce1", "show ipv6 route json", "ce1/ipv6_rib.json")
    check_rib("ce2", "show ipv6 route json", "ce2/ipv6_rib.json")


def test_ping():
    # IPv4 CE1 to CE2
    check_ping("ce1", "192.168.2.1", True, 10, 3, "192.168.1.1")
    # IPv4 CE2 to CE1
    check_ping("ce2", "192.168.1.1", True, 10, 3, "192.168.2.1")
    # IPv6 CE1 to CE2
    check_ping("ce1", "2001:2::1", True, 10, 3, "2001:1::1")
    # IPv6 CE2 to CE1
    check_ping("ce2", "2001:1::1", True, 10, 3, "2001:2::1")


def test_ce_neighbor_reset():
    # Clear CE to R peerings and ensure route exports after
    # re-established propogate to VPNv4/VPNv6 and function correctly
    tgen = get_topogen()

    for router in ["ce1", "ce2"]:
        tgen.gears[router].vtysh_cmd("clear bgp *")

    test_ping()
    test_rib()


def test_pe_neighbor_reset():
    # Clear R to R peering and ensure route exports after
    # re-established propogate to VPNv4/VPNv6 and function correctly
    tgen = get_topogen()

    tgen.gears["r1"].vtysh_cmd("clear bgp *")

    test_ping()
    test_rib()


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
