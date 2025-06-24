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


def _check_explicit_srv6_sid_allocated(router, expected_sid_file, exact=False):
    logger.info("checking bgp explicit srv6 sid allocated in sending end")
    output = json.loads(router.vtysh_cmd("show segment-routing srv6 sid json"))
    expected = open_json_file("{}/{}".format(CWD, expected_sid_file))
    return topotest.json_cmp(output, expected, exact=exact)


def check_explicit_srv6_sid_allocated(router, expected_file, exact=False):
    func = functools.partial(
        _check_explicit_srv6_sid_allocated, router, expected_file, exact=exact
    )
    _, result = topotest.run_and_expect(func, None, count=15, wait=1)
    assert result is None, "Failed"


def _check_sent_bgp_vpn_srv6_sid(router, expected_route_file):
    logger.info("checking bgp vpn route with SRv6 SIDs in sending end")
    output = json.loads(router.vtysh_cmd("show bgp ipv4 vpn 192.168.1.0/24 json"))
    expected = open_json_file("{}/{}".format(CWD, expected_route_file))
    return topotest.json_cmp(output, expected)


def check_sent_bgp_vpn_srv6_sid(router, expected_file):
    func = functools.partial(_check_sent_bgp_vpn_srv6_sid, router, expected_file)
    _, result = topotest.run_and_expect(func, None, count=15, wait=1)
    assert result is None, "Failed"


def _check_rcvd_bgp_vpn_srv6_sid(router, expected_route_file):
    logger.info("checking bgp ipv4 vpn route with SRv6 SIDs in receiving end")
    output = json.loads(router.vtysh_cmd("show bgp ipv4 vpn 192.168.1.0/24 json"))
    expected = open_json_file("{}/{}".format(CWD, expected_route_file))
    return topotest.json_cmp(output, expected)


def check_rcvd_bgp_vpn_srv6_sid(router, expected_file):
    func = functools.partial(_check_rcvd_bgp_vpn_srv6_sid, router, expected_file)
    _, result = topotest.run_and_expect(func, None, count=15, wait=1)
    assert result is None, "Failed"


def _check_rcvd_bgp_vrf_srv6_sid(router, vrf_name, expected_route_file):
    logger.info(
        "checking bgp vrf {} ipv4 route with SRv6 SIDs in receiving end".format(
            vrf_name
        )
    )
    output = json.loads(
        router.vtysh_cmd("show bgp vrf {} ipv4 192.168.1.0/24 json".format(vrf_name))
    )
    expected = open_json_file("{}/{}".format(CWD, expected_route_file))
    return topotest.json_cmp(output, expected)


def check_rcvd_bgp_vrf_srv6_sid(router, vrf_name, expected_file):
    func = functools.partial(
        _check_rcvd_bgp_vrf_srv6_sid, router, vrf_name, expected_file
    )
    _, result = topotest.run_and_expect(func, None, count=15, wait=1)
    assert result is None, "Failed"


def _check_rcvd_zebra_vrf_srv6_sid(router, vrf_name, expected_route_file):
    logger.info(
        "checking zebra vrf {} ipv4 route with SRv6 SIDs in receiving end".format(
            vrf_name
        )
    )
    output = json.loads(
        router.vtysh_cmd("show ip route vrf {} 192.168.1.0/24 json".format(vrf_name))
    )
    expected = open_json_file("{}/{}".format(CWD, expected_route_file))
    return topotest.json_cmp(output, expected)


def check_rcvd_zebra_vrf_srv6_sid(router, vrf_name, expected_file):
    func = functools.partial(
        _check_rcvd_zebra_vrf_srv6_sid, router, vrf_name, expected_file
    )
    _, result = topotest.run_and_expect(func, None, count=15, wait=1)
    assert result is None, "Failed"


# Configure 'sid vpn per-vrf export explicit X:X::X:X' in vrf and
# check whether zebra allocates the explicit SRv6 SIDs.
# By command 'show segment-routing srv6 sid json'
def test_explicit_srv6_sid_per_vrf_allocated():
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)
    router = tgen.gears["r1"]

    router.vtysh_cmd(
        """
        configure terminal
         router bgp 65001 vrf Vrf10
          sid vpn per-vrf export explicit 2001:db8:1:1:1000::
        """
    )
    router.vtysh_cmd(
        """
        configure terminal
         router bgp 65001 vrf Vrf20
          sid vpn per-vrf export explicit 2001:db8:1:1:2000::
        """
    )

    # FOR DEVELOPER:
    # If you want to stop some specific line and start interactive shell,
    # please use tgen.mininet_cli() to start it.
    logger.info("--1--Test for bgp explicit srv6 sid allocated in zebra")
    check_explicit_srv6_sid_allocated(
        router, "expected_explicit_srv6_sid_allocated.json"
    )


# Check whether bgp vpn route contains the static SRv6 SIDs
# in sending end.
# By command 'show bgp ipv4 vpn X.X.X.X/M json'
def _test_sent_bgp_vpn_srv6_sid(step):
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)
    router = tgen.gears["r1"]

    # FOR DEVELOPER:
    # If you want to stop some specific line and start interactive shell,
    # please use tgen.mininet_cli() to start it.
    logger.info(
        f"--{step}--Test for bgp explicit SRv6 SIDs in bgp vpn route in sending end"
    )
    check_sent_bgp_vpn_srv6_sid(router, "expected_sent_bgp_vpn_srv6_sid.json")


def test_sent_bgp_vpn_srv6_sid():
    _test_sent_bgp_vpn_srv6_sid(2)


# Check SRv6 SIDs in bgp vpn route in receiving end.
# By command 'show bgp ipv4 vpn json X.X.X.X/M json'
def _test_rcvd_bgp_vpn_srv6_sid(step):
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)
    router = tgen.gears["r2"]

    logger.info(f"--{step}--Test for SRv6 SID in bgp vpn in receiving end")
    check_rcvd_bgp_vpn_srv6_sid(router, "expected_rcvd_bgp_vpn_srv6_sid.json")


def test_rcvd_bgp_vpn_srv6_sid():
    _test_rcvd_bgp_vpn_srv6_sid(3)


# Check SRv6 SIDs in bgp vrf route in receiving end.
# By command 'show bgp vrf VrfName ipv4 X.X.X.X/M json'
def _test_rcvd_bgp_vrf_srv6_sid(step):
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)
    router = tgen.gears["r2"]

    logger.info(f"--{step}--Test for SRv6 SIDs in bgp vrf route in receiving end")
    check_rcvd_bgp_vrf_srv6_sid(
        router, "Vrf10", "expected_rcvd_bgp_vrf_srv6_sid_1.json"
    )
    check_rcvd_bgp_vrf_srv6_sid(
        router, "Vrf20", "expected_rcvd_bgp_vrf_srv6_sid_2.json"
    )


def test_rcvd_bgp_vrf_srv6_sid():
    _test_rcvd_bgp_vrf_srv6_sid(4)


# Check SRv6 SIDs in zebra vrf route in receiving end.
# By command 'show ip route vrf VrfName X.X.X.X/M json'
def _test_rcvd_zebra_vrf_srv6_sid(step):
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)
    router = tgen.gears["r2"]

    logger.info(f"--{step}--Test for SRv6 SIDs in zebra vrf route in receiving end")
    check_rcvd_zebra_vrf_srv6_sid(
        router, "Vrf10", "expected_rcvd_zebra_vrf_srv6_sid_1.json"
    )
    check_rcvd_zebra_vrf_srv6_sid(
        router, "Vrf20", "expected_rcvd_zebra_vrf_srv6_sid_2.json"
    )


def test_rcvd_zebra_vrf_srv6_sid():
    _test_rcvd_zebra_vrf_srv6_sid(5)


# Configure 'no sid vpn per-vrf export explicit X:X::X:X' in vrf and
# check whether zebra allocates the explicit SRv6 SIDs.
# By command 'show segment-routing srv6 sid json'
def test_explicit_srv6_sid_per_vrf_disabled():
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)
    router = tgen.gears["r1"]

    router.vtysh_cmd(
        """
        configure terminal
         router bgp 65001 vrf Vrf10
          no sid vpn per-vrf export explicit 2001:db8:1:1:1000::
        """
    )
    router.vtysh_cmd(
        """
        configure terminal
         router bgp 65001 vrf Vrf20
          no sid vpn per-vrf export explicit 2001:db8:1:1:2000::
        """
    )

    # FOR DEVELOPER:
    # If you want to stop some specific line and start interactive shell,
    # please use tgen.mininet_cli() to start it.
    logger.info("--6--Test for bgp explicit srv6 sid disabled in zebra")
    check_explicit_srv6_sid_allocated(
        router, "expected_explicit_srv6_sid_disabled.json", exact=True
    )


# Configure 'sid vpn export explicit X:X::X:X' in ipv4 address-family and
# check whether zebra allocates the explicit SRv6 SIDs.
# By command 'show segment-routing srv6 sid json'
def test_explicit_srv6_sid_per_af_allocated():
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)
    router = tgen.gears["r1"]

    router.vtysh_cmd(
        """
        configure terminal
         router bgp 65001 vrf Vrf10
          address-family ipv4 unicast
           sid vpn export explicit 2001:db8:1:1:1000::
          exit-address-family
        """
    )
    router.vtysh_cmd(
        """
        configure terminal
         router bgp 65001 vrf Vrf20
          address-family ipv4 unicast
           sid vpn export explicit 2001:db8:1:1:2000::
          exit-address-family
        """
    )

    # FOR DEVELOPER:
    # If you want to stop some specific line and start interactive shell,
    # please use tgen.mininet_cli() to start it.
    logger.info("--7--Test for bgp explicit srv6 sid allocated in zebra")
    check_explicit_srv6_sid_allocated(
        router, "expected_explicit_srv6_sid_per_af_allocated.json"
    )


def test_sent_bgp_vpn_srv6_per_af_sid():
    _test_sent_bgp_vpn_srv6_sid(8)


def test_rcvd_bgp_vpn_srv6_per_af_sid():
    _test_rcvd_bgp_vpn_srv6_sid(9)


# Check SRv6 SIDs in bgp vrf route in receiving end.
# By command 'show bgp vrf VrfName ipv4 X.X.X.X/M json'
def test_rcvd_bgp_vrf_srv6_per_af_sid():
    _test_rcvd_bgp_vrf_srv6_sid(10)


# Check SRv6 SIDs in zebra vrf route in receiving end.
# By command 'show ip route vrf VrfName X.X.X.X/M json'
def test_rcvd_zebra_vrf_srv6_per_af_sid():
    _test_rcvd_zebra_vrf_srv6_sid(11)


# Configure 'no sid vpn export explicit X:X::X:X' in af and
# check whether zebra allocates the explicit SRv6 SIDs.
# By command 'show segment-routing srv6 sid json'
def test_explicit_srv6_sid_per_af_disabled():
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)
    router = tgen.gears["r1"]

    router.vtysh_cmd(
        """
        configure terminal
         router bgp 65001 vrf Vrf10
          address-family ipv4 unicast
           no sid vpn export explicit 2001:db8:1:1:1000::
        """
    )
    router.vtysh_cmd(
        """
        configure terminal
         router bgp 65001 vrf Vrf20
          address-family ipv4 unicast
           no sid vpn export explicit 2001:db8:1:1:2000::
        """
    )

    # FOR DEVELOPER:
    # If you want to stop some specific line and start interactive shell,
    # please use tgen.mininet_cli() to start it.
    logger.info("--12--Test for bgp explicit srv6 sid disabled in zebra")
    check_explicit_srv6_sid_allocated(
        router, "expected_explicit_srv6_sid_disabled.json", exact=True
    )


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
