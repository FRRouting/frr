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
    r"""
    ┌──────┐                  ┌──────┐                   ┌──────┐
    │  CE1 ┼─┐            ┌───┤  P1  ┼──┐              ┌─┤  CE3 │
    └──────┘ │ Vrf1       │   └───|──┘  │              │ └──────┘
                │ ┌──────┐   │       |     │    ┌──────┐  │ Vrf1
                ┼─┼  PE1 ┼───┤       |     ┼────┤  PE2 ┼──┤
                │ └──────┘   │       |     │    └──────┘  │ Vrf2
    ┌──────┐ │ Vrf2       │   ┌───|──┐  │              │ ┌──────┐
    │  CE2 ┼─┘            └───┤  P2  ┼──┘              └─┼  CE4 │
    └──────┘                  └──────┘                   └──────┘
    """
    tgen.add_router("pe1")
    tgen.add_router("pe2")
    tgen.add_router("ce1")
    tgen.add_router("ce2")
    tgen.add_router("ce3")
    tgen.add_router("ce4")
    tgen.add_router("p1")
    tgen.add_router("p2")

    tgen.add_link(tgen.gears["pe1"], tgen.gears["p1"], "eth1", "eth1")
    tgen.add_link(tgen.gears["pe1"], tgen.gears["p2"], "eth2", "eth1")
    tgen.add_link(tgen.gears["pe2"], tgen.gears["p1"], "eth1", "eth2")
    tgen.add_link(tgen.gears["pe2"], tgen.gears["p2"], "eth2", "eth2")
    tgen.add_link(tgen.gears["ce1"], tgen.gears["pe1"], "eth0", "eth3")
    tgen.add_link(tgen.gears["ce2"], tgen.gears["pe1"], "eth0", "eth4")
    tgen.add_link(tgen.gears["ce3"], tgen.gears["pe2"], "eth0", "eth3")
    tgen.add_link(tgen.gears["ce4"], tgen.gears["pe2"], "eth0", "eth4")
    tgen.add_link(tgen.gears["p1"], tgen.gears["p2"], "eth3", "eth3")

def setup_module(mod):
    result = required_linux_kernel_version("5.4.0")
    if result is not True:
        pytest.skip("Kernel requirements are not met")

    tgen = Topogen(build_topo, mod.__name__)
    tgen.start_topology()
    router_list = tgen.routers()
    for rname, router in tgen.routers().items():
        if os.path.exists("{}/{}/setup.sh".format(CWD, rname)):
            router.run("/bin/bash {}/{}/setup.sh".format(CWD, rname))
        router.load_config(
            TopoRouter.RD_ZEBRA, os.path.join(CWD, "{}/zebra.conf".format(rname))
        )
        router.load_config(
            TopoRouter.RD_PATH, os.path.join(CWD, "{}/pathd.conf".format(rname))
        )
        router.load_config(
            TopoRouter.RD_BGP, os.path.join(CWD, "{}/bgpd.conf".format(rname))
        )

    tgen.gears["pe1"].run("ip link add vrf1 type vrf table 1")
    tgen.gears["pe1"].run("ip link set vrf1 up")
    tgen.gears["pe1"].run("ip link add vrf2 type vrf table 2")
    tgen.gears["pe1"].run("ip link set vrf2 up")
    tgen.gears["pe1"].run("ip link set eth3 master vrf1")
    tgen.gears["pe1"].run("ip link set eth4 master vrf2")
    tgen.gears["pe1"].run("ip link add Loopback1 type dummy")
    tgen.gears["pe1"].run("ip link set dev Loopback1 up")

    tgen.gears["pe2"].run("ip link add vrf1 type vrf table 1")
    tgen.gears["pe2"].run("ip link set vrf1 up")
    tgen.gears["pe2"].run("ip link add vrf2 type vrf table 2")
    tgen.gears["pe2"].run("ip link set vrf2 up")
    tgen.gears["pe2"].run("ip link set eth3 master vrf1")
    tgen.gears["pe2"].run("ip link set eth4 master vrf2")
    tgen.gears["pe2"].run("ip link add Loopback1 type dummy")
    tgen.gears["pe2"].run("ip link set dev Loopback1 up")

    tgen.start_router()

    # FOR DEVELOPER:
    # If you want to stop some specific line and start interactive shell,
    # please use tgen.mininet_cli() to start it.


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
    _, result = topotest.run_and_expect(func, None, count=10, wait=0.5)
    assert result is None, "Failed"

def create_srv6_policy(rname, endpoint, color=100):
    get_topogen().net[rname].cmd(
        """ \
        vtysh -c "conf t" \
              -c "segment-routing" \
              -c "traffic-eng" \
              -c "policy color """
        + str(color)
        + " endpoint "
        + endpoint
        + '''"'''
    )


def delete_srv6_policy(rname, endpoint, color=100):
    get_topogen().net[rname].cmd(
        """ \
        vtysh -c "conf t" \
              -c "segment-routing" \
              -c "traffic-eng" \
              -c "no policy color """
        + str(color)
        + " endpoint "
        + endpoint
        + '''"'''
    )

def add_candidate_path(rname, endpoint, pref, name, segment_list="default", color=100):
    get_topogen().net[rname].cmd(
        """ \
        vtysh -c "conf t" \
              -c "segment-routing" \
              -c "traffic-eng" \
              -c "policy color """
        + str(color)
        + " endpoint "
        + endpoint
        + """" \
              -c "candidate-path preference """
        + str(pref)
        + """ name """
        + name
        + """ explicit segment-list """
        + segment_list
        + '''"'''
    )


def delete_candidate_path(rname, endpoint, pref, color=100):
    get_topogen().net[rname].cmd(
        """ \
        vtysh -c "conf t" \
              -c "segment-routing" \
              -c "traffic-eng" \
              -c "policy color """
        + str(color)
        + " endpoint "
        + endpoint
        + """" \
              -c "no candidate-path preference """
        + str(pref)
        + '''"'''
    )

def router_bgp_shutdown_neighbor(rname, neighbor):
    get_topogen().net[rname].cmd(
        """ \
        vtysh -c "conf t" \
              -c "router bgp 2" \
              -c " neighbor """
        + neighbor
        + ' shutdown"'
    )


def router_bgp_no_shutdown_neighbor(rname, neighbor):
    get_topogen().net[rname].cmd(
        """ \
        vtysh -c "conf t" \
              -c "router bgp 2" \
              -c " no neighbor """
        + neighbor
        + ' shutdown"'
    )

def test_bgp_srv6_ipv4_vpn_route():
    check_ping("pe1", "2000::1", False, 5, 1, "1000::1")
    check_ping("pe2", "1000::1", False, 5, 1, "2000::1")
    check_rib("pe2", "show bgp ipv4 vpn 192.168.1.0/24 json", "json/vpnv4_vrf1_rib_route.json")
    check_rib("pe2", "show bgp ipv4 vpn 192.168.2.0/24 json", "json/vpnv4_vrf2_rib_route.json")
    check_rib("pe2", "show ip route vrf vrf1 192.168.1.0/24 json", "json/vrf1_ipv4_route.json")
    check_rib("pe2", "show ip route vrf vrf2 192.168.2.0/24 json", "json/vrf2_ipv4_route.json")

    add_candidate_path("pe2", "1000::1", 100, "test", "test", 100)

    add_candidate_path("pe2", "1000::1", 100, "default", "default", 200)
    check_rib("pe2", "show ip route vrf vrf1 192.168.1.0/24 json", "json/vrf1_ipv4_route_te_policy.json")
    check_rib("pe2", "show ip route vrf vrf2 192.168.2.0/24 json", "json/vrf2_ipv4_route_te_policy.json")

    delete_candidate_path("pe2", "1000::1", 100)
    delete_candidate_path("pe2", "1000::1", 100, 200)
    check_rib("pe2", "show ip route vrf vrf1 192.168.1.0/24 json", "json/vrf1_ipv4_route.json")
    check_rib("pe2", "show ip route vrf vrf2 192.168.2.0/24 json", "json/vrf2_ipv4_route.json")

def test_bgp_srv6_ipv6_vpn_route():
    check_rib("pe2", "show bgp ipv6 vpn 1001:1::/64 json", "json/vpnv6_vrf1_rib_route.json")
    check_rib("pe2", "show bgp ipv6 vpn 1001:2::/64 json", "json/vpnv6_vrf2_rib_route.json")
    check_rib("pe2", "show ipv6 route vrf vrf1 1001:1::/64 json", "json/vrf1_ipv6_route.json")
    check_rib("pe2", "show ipv6 route vrf vrf2 1001:2::/64 json", "json/vrf2_ipv6_route.json")

    add_candidate_path("pe2", "1000::1", 100, "test", "test", 100)

    add_candidate_path("pe2", "1000::1", 100, "default", "default", 200)
    check_rib("pe2", "show ipv6 route vrf vrf1 1001:1::/64 json", "json/vrf1_ipv6_route_te_policy.json")
    check_rib("pe2", "show ipv6 route vrf vrf2 1001:2::/64 json", "json/vrf2_ipv6_route_te_policy.json")

    delete_srv6_policy("pe2", "1000::1", 100)
    delete_srv6_policy("pe2", "1000::1", 200)
    check_rib("pe2", "show ipv6 route vrf vrf1 1001:1::/64 json", "json/vrf1_ipv6_route.json")
    check_rib("pe2", "show ipv6 route vrf vrf2 1001:2::/64 json", "json/vrf2_ipv6_route.json")

if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
