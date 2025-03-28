#!/usr/bin/env python
# SPDX-License-Identifier: ISC

#
# test_bgp_srv6_sid_explicit.py
#
# Copyright (c) 2025 by
# Alibaba Inc, Yuqing Zhao <galadriel.zyq@alibaba-inc.com>
#

"""
test_bgp_srv6_sid_explicit.py:
Test for VPN route with SRv6 SID set by bgp
"""

import os
import sys
import json
import pytest
import functools

CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

# pylint: disable=C0413
from lib import topotest
from lib.topogen import Topogen, TopoRouter, get_topogen
from lib.common_config import required_linux_kernel_version
from lib.checkping import check_ping
from lib.topolog import logger

pytestmark = [pytest.mark.bgpd]


def open_json_file(filename):
    try:
        with open(filename, "r") as f:
            return json.load(f)
    except IOError:
        assert False, "Could not read file {}".format(filename)


def build_topo(tgen):
    tgen.add_router("r1")
    tgen.add_router("r2")

    tgen.add_router("c11")
    tgen.add_router("c12")
    tgen.add_router("c21")
    tgen.add_router("c22")

    tgen.add_link(tgen.gears["r1"], tgen.gears["r2"], "eth10", "eth10")
    tgen.add_link(tgen.gears["r1"], tgen.gears["c11"], "eth2", "eth10")
    tgen.add_link(tgen.gears["r1"], tgen.gears["c12"], "eth3", "eth10")
    tgen.add_link(tgen.gears["r2"], tgen.gears["c21"], "eth1", "eth10")
    tgen.add_link(tgen.gears["r2"], tgen.gears["c22"], "eth2", "eth10")


def setup_module(mod):
    result = required_linux_kernel_version("5.15")
    if result is not True:
        pytest.skip("Kernel requirements are not met")
    
    tgen = Topogen(build_topo, mod.__name__)
    tgen.start_topology()

    for rname, router in tgen.routers().items():
        router.run("/bin/bash {}/{}/setup.sh".format(CWD, rname))
        router.load_frr_config("frr.conf")
    
    tgen.start_router()


def teardown_module(mod):
    tgen = get_topogen()
    tgen.stop_topology()


# Configure 'sid vpn per-vrf export explicit' in vrf and
# check whether bgp vpn route contains the static SRv6 SIDs
# in sending end,
# by command 'show bgp ipv4 vpn X.X.X.X/M json'
def test_sent_bgp_vpn_srv6_sid():
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)
    router = tgen.gears["r1"]

    def _check_sent_bgp_vpn_srv6_sid(router, expected_route_file):
        logger.info("checking bgp ipv4 vpn route with SRv6 SIDs in sending end")
        output = json.loads(router.vtysh_cmd("show bgp ipv4 vpn 192.168.1.0/24 json"))
        expected = open_json_file("{}/{}".format(CWD, expected_route_file))
        return topotest.json_cmp(output, expected)

    def check_sent_bgp_vpn_srv6_sid(router, expected_file):
        func = functools.partial(_check_sent_bgp_vpn_srv6_sid, router, expected_file)
        _, result = topotest.run_and_expect(func, None, count=15, wait=1)
        assert result is None, "Failed"

    router.vtysh_cmd(
        """
        configure terminal
         segment-routing
          srv6
          static-sids
           sid 2001:db8:1:1:1000::/80 locator MAIN behavior uDT46 vrf Vrf10
           sid 2001:db8:1:1:2000::/80 locator MAIN behavior uDT46 vrf Vrf20
        """
    )
    router.vtysh_cmd(
        """
        configure terminal
         router bgp 65001
          segment-routing srv6
           locator MAIN
        """
    )
    router.vtysh_cmd(
        """
        configure terminal
         router bgp 65001 vrf Vrf10
          sid vpn per-vrf export explicit
         exit
         router bgp 65001 vrf Vrf20
          sid vpn per-vrf export explicit
        """
    )

    # FOR DEVELOPER:
    # If you want to stop some specific line and start interactive shell,
    # please use tgen.mininet_cli() to start it.
    logger.info("--1--Test for static sids configuration in bgp vpn route")
    check_sent_bgp_vpn_srv6_sid(router, "expected_sent_bgp_vpn_srv6_sid.json")


# Check SRv6 SIDs in receiving end
# by command 'show bgp ipv4 vpn json X.X.X.X/M json'
# by command 'show bgp vrf Vrf10/20 ipv4 X.X.X.X/M json'
# by command 'show ip route vrf Vrf10/20 X.X.X.X/M json'
def test_rcvd_bgp_vpn_srv6_sid():
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)
    router = tgen.gears["r2"]

    def _check_rcvd_bgp_vpn_srv6_sid(router, expected_route_file):
        logger.info("checking bgp ipv4 vpn route with SRv6 SIDs in receiving end")
        output = json.loads(router.vtysh_cmd("show bgp ipv4 vpn 192.168.1.0/24 json"))
        expected = open_json_file("{}/{}".format(CWD, expected_route_file))
        return topotest.json_cmp(output, expected)
    
    def check_rcvd_bgp_vpn_srv6_sid(router, expected_file):
        func = functools.partial(_check_rcvd_bgp_vpn_srv6_sid, router, expected_file)
        _, result = topotest.run_and_expect(func, None, count=15, wait=1)
        assert result is None, "Failed"

    logger.info("--2--Test for SRv6 SIDs of bgp vpn in receiving end")
    check_rcvd_bgp_vpn_srv6_sid(router, "expected_rcvd_bgp_vpn_srv6_sid.json")


def test_rcvd_bgp_vrf_srv6_sid():
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)
    router = tgen.gears["r2"]

    def _check_rcvd_bgp_vrf_srv6_sid(router, vrf_name, expected_route_file):
        logger.info("checking bgp vrf {} ipv4 route with SRv6 SIDs in receiving end".format(vrf_name))
        output = json.loads(router.vtysh_cmd("show bgp vrf {} ipv4 192.168.1.0/24 json".format(vrf_name)))
        expected = open_json_file("{}/{}".format(CWD, expected_route_file))
        return topotest.json_cmp(output, expected)
    
    def check_rcvd_bgp_vrf_srv6_sid(router, vrf_name, expected_file):
        func = functools.partial(_check_rcvd_bgp_vrf_srv6_sid, router, vrf_name, expected_file)
        _, result = topotest.run_and_expect(func, None, count=15, wait=1)
        assert result is None, "Failed"

    logger.info("--3--Test for SRv6 SIDs of bgp vrf in receiving end")
    check_rcvd_bgp_vrf_srv6_sid(router, "Vrf10", "expected_rcvd_bgp_vrf_srv6_sid_1.json")
    check_rcvd_bgp_vrf_srv6_sid(router, "Vrf20", "expected_rcvd_bgp_vrf_srv6_sid_2.json")


def test_rcvd_zebra_vrf_srv6_sid():
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)
    router = tgen.gears["r2"]

    def _check_rcvd_zebra_vrf_srv6_sid(router, vrf_name, expected_route_file):
        logger.info("checking zebra vrf {} ipv4 route with SRv6 SIDs in receiving end".format(vrf_name))
        output = json.loads(router.vtysh_cmd("show ip route vrf {} 192.168.1.0/24 json".format(vrf_name)))
        expected = open_json_file("{}/{}".format(CWD, expected_route_file))
        return topotest.json_cmp(output, expected)
    
    def check_rcvd_zebra_vrf_srv6_sid(router, vrf_name, expected_file):
        func = functools.partial(_check_rcvd_zebra_vrf_srv6_sid, router, vrf_name, expected_file)
        _, result = topotest.run_and_expect(func, None, count=15, wait=1)
        assert result is None, "Failed"

    logger.info("--4--Test for SRv6 SIDs of zebra vrf in receiving end")
    check_rcvd_zebra_vrf_srv6_sid(router, "Vrf10", "expected_rcvd_zebra_vrf_srv6_sid_1.json")
    check_rcvd_zebra_vrf_srv6_sid(router, "Vrf20", "expected_rcvd_zebra_vrf_srv6_sid_2.json")



if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))

