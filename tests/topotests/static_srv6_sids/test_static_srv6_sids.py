#!/usr/bin/env python
# SPDX-License-Identifier: ISC

#
# test_static_srv6_sids.py
#
# Copyright (c) 2025 by
# Alibaba Inc, Yuqing Zhao <galadriel.zyq@alibaba-inc.com>
#              Lingyu Zhang <hanyu.zly@alibaba-inc.com>
#

"""
test_static_srv6_sids.py:
Test for SRv6 static route on zebra
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
from lib.topolog import logger
from lib.checkping import check_ping

pytestmark = [pytest.mark.staticd]


def open_json_file(filename):
    try:
        with open(filename, "r") as f:
            return json.load(f)
    except IOError:
        assert False, "Could not read file {}".format(filename)


def setup_module(mod):
    tgen = Topogen({"s1": ("r1", "r2")}, mod.__name__)
    tgen.start_topology()
    for rname, router in tgen.routers().items():
        router.run("/bin/bash {}/{}/setup.sh".format(CWD, rname))
        router.load_frr_config("frr.conf")
    tgen.start_router()


def teardown_module():
    tgen = get_topogen()
    tgen.stop_topology()


def test_srv6_static_sids():
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)
    router = tgen.gears["r1"]

    def _check_srv6_static_sids(router, expected_route_file):
        logger.info("checking zebra srv6 static sids")
        output = json.loads(router.vtysh_cmd("show ipv6 route static json"))
        expected = open_json_file("{}/{}".format(CWD, expected_route_file))
        return topotest.json_cmp(output, expected)

    def check_srv6_static_sids(router, expected_file):
        func = functools.partial(_check_srv6_static_sids, router, expected_file)
        _, result = topotest.run_and_expect(func, None, count=15, wait=1)
        assert result is None, "Failed"

    # FOR DEVELOPER:
    # If you want to stop some specific line and start interactive shell,
    # please use tgen.mininet_cli() to start it.

    logger.info("Test for srv6 sids configuration")
    check_srv6_static_sids(router, "expected_srv6_sids.json")


def test_srv6_static_sids_sid_delete():
    """
    Remove the static SID and verify it gets removed
    """
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)
    router = tgen.gears["r1"]

    def _check_srv6_static_sids(router, expected_route_file):
        logger.info("checking zebra srv6 static sids")
        output = json.loads(router.vtysh_cmd("show ipv6 route static json"))
        expected = open_json_file("{}/{}".format(CWD, expected_route_file))
        return topotest.json_cmp(output, expected)

    def check_srv6_static_sids(router, expected_file):
        func = functools.partial(_check_srv6_static_sids, router, expected_file)
        _, result = topotest.run_and_expect(func, None, count=15, wait=1)
        assert result is None, "Failed"

    router.vtysh_cmd(
        """
        configure terminal
         segment-routing
          srv6
           static-sids
            no sid fcbb:bbbb:1::/48
        """
    )

    # FOR DEVELOPER:
    # If you want to stop some specific line and start interactive shell,
    # please use tgen.mininet_cli() to start it.

    logger.info("Test for srv6 sids configuration")
    check_srv6_static_sids(router, "expected_srv6_sids_sid_delete_1.json")

    router.vtysh_cmd(
        """
        configure terminal
         segment-routing
          srv6
           static-sids
            no sid fcbb:bbbb:1:fe20::/64 locator MAIN behavior uDT6 vrf Vrf20
        """
    )

    # FOR DEVELOPER:
    # If you want to stop some specific line and start interactive shell,
    # please use tgen.mininet_cli() to start it.

    logger.info("Test for srv6 sids configuration")
    check_srv6_static_sids(router, "expected_srv6_sids_sid_delete_2.json")


def test_srv6_static_sids_sid_readd():
    """
    Re-add the static SID and verify the routing table
    """
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)
    router = tgen.gears["r1"]

    def _check_srv6_static_sids(router, expected_route_file):
        logger.info("checking zebra srv6 static sids")
        output = json.loads(router.vtysh_cmd("show ipv6 route static json"))
        expected = open_json_file("{}/{}".format(CWD, expected_route_file))
        return topotest.json_cmp(output, expected)

    def check_srv6_static_sids(router, expected_file):
        func = functools.partial(_check_srv6_static_sids, router, expected_file)
        _, result = topotest.run_and_expect(func, None, count=15, wait=1)
        assert result is None, "Failed"

    router.vtysh_cmd(
        """
        configure terminal
         segment-routing
          srv6
           static-sids
            sid fcbb:bbbb:1::/48 locator MAIN behavior uN
            sid fcbb:bbbb:1:fe20::/64 locator MAIN behavior uDT6 vrf Vrf20
        """
    )

    # FOR DEVELOPER:
    # If you want to stop some specific line and start interactive shell,
    # please use tgen.mininet_cli() to start it.

    logger.info("Test for srv6 sids configuration")
    check_srv6_static_sids(router, "expected_srv6_sids.json")


def test_srv6_static_sids_sid_modify():
    """
    Modify the static SIDs and verify the routing table
    """
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)
    router = tgen.gears["r1"]

    def _check_srv6_static_sids(router, expected_route_file):
        logger.info("checking zebra srv6 static sids")
        output = json.loads(router.vtysh_cmd("show ipv6 route static json"))
        expected = open_json_file("{}/{}".format(CWD, expected_route_file))
        return topotest.json_cmp(output, expected)

    def check_srv6_static_sids(router, expected_file):
        func = functools.partial(_check_srv6_static_sids, router, expected_file)
        _, result = topotest.run_and_expect(func, None, count=15, wait=1)
        assert result is None, "Failed"

    router.vtysh_cmd(
        """
        configure terminal
         segment-routing
          srv6
           static-sids
            sid fcbb:bbbb:1:fe20::/64 locator MAIN behavior uDT46 vrf Vrf40
        """
    )

    # FOR DEVELOPER:
    # If you want to stop some specific line and start interactive shell,
    # please use tgen.mininet_cli() to start it.

    logger.info("Test for srv6 sids configuration")
    check_srv6_static_sids(router, "expected_srv6_sids_sid_modify.json")


def test_srv6_static_sids_wrong_sid_block():
    """
    The purpose of this test is to verify how FRR behaves when the user
    provides an invalid configuration.
    Add a new static Sid with a mismatch in locator and sid block
    to make sure no Sid is allocated by zebra (TBD: Strict verify once show cmd
    commit is merged (#16836))
    """
    router = get_topogen().gears["r1"]
    router.vtysh_cmd(
        """
        configure terminal
         segment-routing
          srv6
           locators
            locator MAIN1
             prefix fcbb:1234:1::/48 block-len 32 node-len 16 func-bits 16
          srv6
           static-sids
            sid fcbb:bbbb:1:fe50::/64 locator MAIN1 behavior uA interface sr0 nexthop 2001::3
        """
    )

    output = json.loads(router.vtysh_cmd("show ipv6 route static json"))
    if "fcbb:bbbb:1:fe50::/64" in output:
        assert (
            False
        ), "Failed. Expected no entry for fcbb:bbbb:1:fe50::/64 since loc and node block dont match"


def test_srv6_static_sids_sid_delete_all():
    """
    Remove all static SIDs and verify they get removed
    """
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)
    router = tgen.gears["r1"]

    def _check_srv6_static_sids(router, expected_route_file):
        logger.info("checking zebra srv6 static sids")
        output = json.loads(router.vtysh_cmd("show ipv6 route static json"))
        expected = open_json_file("{}/{}".format(CWD, expected_route_file))
        return topotest.json_cmp(output, expected, exact=True)

    def check_srv6_static_sids(router, expected_file):
        func = functools.partial(_check_srv6_static_sids, router, expected_file)
        _, result = topotest.run_and_expect(func, None, count=15, wait=1)
        assert result is None, "Failed"

    router.vtysh_cmd(
        """
        configure terminal
         segment-routing
          srv6
           no static-sids
        """
    )

    # FOR DEVELOPER:
    # If you want to stop some specific line and start interactive shell,
    # please use tgen.mininet_cli() to start it.

    logger.info("Test for srv6 sids configuration")
    check_srv6_static_sids(router, "expected_srv6_sids_delete_all.json")


def test_srv6_static_sids_sid_readd_all():
    """
    Re-add the static SIDs and verify the routing table
    """
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)
    router = tgen.gears["r1"]

    def _check_srv6_static_sids(router, expected_route_file):
        logger.info("checking zebra srv6 static sids")
        output = json.loads(router.vtysh_cmd("show ipv6 route static json"))
        expected = open_json_file("{}/{}".format(CWD, expected_route_file))
        return topotest.json_cmp(output, expected)

    def check_srv6_static_sids(router, expected_file):
        func = functools.partial(_check_srv6_static_sids, router, expected_file)
        _, result = topotest.run_and_expect(func, None, count=15, wait=1)
        assert result is None, "Failed"

    router.vtysh_cmd(
        """
        configure terminal
         segment-routing
          srv6
           static-sids
            sid fcbb:bbbb:1::/48 locator MAIN behavior uN
            sid fcbb:bbbb:1:fe10::/64 locator MAIN behavior uDT4 vrf Vrf10
            sid fcbb:bbbb:1:fe20::/64 locator MAIN behavior uDT6 vrf Vrf20
            sid fcbb:bbbb:1:fe30::/64 locator MAIN behavior uDT46 vrf Vrf30
            sid fcbb:bbbb:1:fe40::/64 locator MAIN behavior uA interface sr0 nexthop 2001::2
            sid fcbb:bbbb:1:fe60::/64 locator MAIN behavior uDT4 vrf default
            sid fcbb:bbbb:1:fe70::/64 locator MAIN behavior uDT6 vrf default
            sid fcbb:bbbb:1:fe80::/64 locator MAIN behavior uDT46 vrf default
        """
    )

    # FOR DEVELOPER:
    # If you want to stop some specific line and start interactive shell,
    # please use tgen.mininet_cli() to start it.

    logger.info("Test for srv6 sids configuration")
    check_srv6_static_sids(router, "expected_srv6_sids.json")


def test_srv6_static_sids_srv6_disable():
    """
    Disable SRv6
    """
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)
    router = tgen.gears["r1"]

    def _check_srv6_static_sids(router, expected_route_file):
        logger.info("checking zebra srv6 static sids")
        output = json.loads(router.vtysh_cmd("show ipv6 route static json"))
        expected = open_json_file("{}/{}".format(CWD, expected_route_file))
        return topotest.json_cmp(output, expected, exact=True)

    def check_srv6_static_sids(router, expected_file):
        func = functools.partial(_check_srv6_static_sids, router, expected_file)
        _, result = topotest.run_and_expect(func, None, count=15, wait=1)
        assert result is None, "Failed"

    router.vtysh_cmd(
        """
        configure terminal
         segment-routing
          no srv6
        """
    )

    # FOR DEVELOPER:
    # If you want to stop some specific line and start interactive shell,
    # please use tgen.mininet_cli() to start it.

    logger.info("Test for srv6 sids configuration")
    check_srv6_static_sids(router, "expected_srv6_sids_srv6_disable.json")


def test_srv6_static_sids_srv6_reenable():
    """
    Re-enable SRv6
    """
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)
    router = tgen.gears["r1"]

    def _check_srv6_static_sids(router, expected_route_file):
        logger.info("checking zebra srv6 static sids")
        output = json.loads(router.vtysh_cmd("show ipv6 route static json"))
        expected = open_json_file("{}/{}".format(CWD, expected_route_file))
        return topotest.json_cmp(output, expected)

    def check_srv6_static_sids(router, expected_file):
        func = functools.partial(_check_srv6_static_sids, router, expected_file)
        _, result = topotest.run_and_expect(func, None, count=15, wait=1)
        assert result is None, "Failed"

    router.vtysh_cmd(
        """
        configure terminal
         segment-routing
          srv6
           locators
            locator MAIN
             prefix fcbb:bbbb:1::/48 block-len 32 node-len 16 func-bits 16
            !
           !
           static-sids
            sid fcbb:bbbb:1::/48 locator MAIN behavior uN
            sid fcbb:bbbb:1:fe10::/64 locator MAIN behavior uDT4 vrf Vrf10
            sid fcbb:bbbb:1:fe20::/64 locator MAIN behavior uDT6 vrf Vrf20
            sid fcbb:bbbb:1:fe30::/64 locator MAIN behavior uDT46 vrf Vrf30
            sid fcbb:bbbb:1:fe40::/64 locator MAIN behavior uA interface sr0 nexthop 2001::2
            sid fcbb:bbbb:1:fe60::/64 locator MAIN behavior uDT4 vrf default
            sid fcbb:bbbb:1:fe70::/64 locator MAIN behavior uDT6 vrf default
            sid fcbb:bbbb:1:fe80::/64 locator MAIN behavior uDT46 vrf default
        """
    )

    # FOR DEVELOPER:
    # If you want to stop some specific line and start interactive shell,
    # please use tgen.mininet_cli() to start it.

    logger.info("Test for srv6 sids configuration")
    check_srv6_static_sids(router, "expected_srv6_sids.json")


def test_srv6_static_sids_interface_down_up():
    """
    Test SRv6 route behavior when sr0 interface goes down and up
    """
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)
    router = tgen.gears["r1"]

    def _check_srv6_static_sids(router, expected_route_file):
        logger.info("checking zebra srv6 static sids")
        output = json.loads(router.vtysh_cmd("show ipv6 route static json"))
        expected = open_json_file("{}/{}".format(CWD, expected_route_file))
        return topotest.json_cmp(output, expected)

    def check_srv6_static_sids(router, expected_file):
        func = functools.partial(_check_srv6_static_sids, router, expected_file)
        _, result = topotest.run_and_expect(func, None, count=15, wait=1)
        assert result is None, "Failed"

    # First verify initial state
    logger.info("Verifying initial SRv6 routes")
    check_srv6_static_sids(router, "expected_srv6_sids.json")

    # Bring down sr0 interface using ip link
    logger.info("Bringing down sr0 interface using ip link")
    router.run("ip link set sr0 down")

    # Verify routes using sr0 are removed
    logger.info("Verifying routes using sr0 are removed")
    check_srv6_static_sids(router, "expected_srv6_sids_interface_down.json")

    # Bring up sr0 interface using ip link
    logger.info("Bringing up sr0 interface using ip link")
    router.run("ip link set sr0 up")

    # Verify routes are restored
    logger.info("Verifying routes are restored")
    check_srv6_static_sids(router, "expected_srv6_sids.json")


def test_srv6_static_sids_overlapping_locators():
    """
    Test SRv6 SID allocation with overlapping locators.

    This test creates a secondary locator with overlapping prefix:
    - MAIN: fcbb:bbbb:1::/48 (already configured)
    - LOC2: fcbb:bbbb:1:1::/64 (more specific prefix within MAIN)

    When allocating an explicit SID fcbb:bbbb:1:1:fe00::/80 with locator LOC2,
    the SID Manager should respect the specified locator and not allocate
    from MAIN even though MAIN also matches the SID prefix.
    """
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)
    router = tgen.gears["r1"]

    def _check_srv6_static_sids(router, expected_route_file):
        logger.info("checking zebra srv6 static sids")
        output = json.loads(router.vtysh_cmd("show ipv6 route static json"))
        expected = open_json_file("{}/{}".format(CWD, expected_route_file))
        return topotest.json_cmp(output, expected)

    def check_srv6_static_sids(router, expected_file):
        func = functools.partial(_check_srv6_static_sids, router, expected_file)
        _, result = topotest.run_and_expect(func, None, count=15, wait=1)
        assert result is None, "Failed"

    # Add LOC2 locator with overlapping prefix
    router.vtysh_cmd(
        """
        configure terminal
         segment-routing
          srv6
           locators
            locator LOC2
             prefix fcbb:bbbb:1:1::/64
             format usid-f4816
            !
           !
        """
    )

    # Add a SID that could potentially match both locators, but explicitly specify LOC2
    # The SID Manager should allocate the SID from LOC2 (the specified locator)
    # and not from MAIN, even though MAIN also matches the SID prefix
    router.vtysh_cmd(
        """
        configure terminal
         segment-routing
          srv6
           static-sids
            sid fcbb:bbbb:1:1:fe00::/80 locator LOC2 behavior uDT46 vrf Vrf10
        """
    )

    # Verify the SID is correctly allocated from the LOC2 locator
    logger.info("Test for SRv6 SID allocation with overlapping locators")
    check_srv6_static_sids(router, "expected_srv6_sids_overlapping_locators.json")

    # Clean up
    router.vtysh_cmd(
        """
        configure terminal
         segment-routing
          srv6
           static-sids
            no sid fcbb:bbbb:1:1:fe00::/80 locator LOC2 behavior uDT46 vrf Vrf10
           !
           locators
            no locator LOC2
           !
        """
    )


def test_srv6_static_sids_ua_basic_resolution():
    """Test that uA SID resolves neighbor when interface is up and neighbor is present"""
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)
    router = tgen.gears["r1"]

    def _check_srv6_static_sids(router, expected_route_file):
        logger.info("checking zebra srv6 static sids")
        output = json.loads(router.vtysh_cmd("show ipv6 route static json"))
        expected = open_json_file("{}/{}".format(CWD, expected_route_file))
        return topotest.json_cmp(output, expected)

    def check_srv6_static_sids(router, expected_file):
        func = functools.partial(_check_srv6_static_sids, router, expected_file)
        _, result = topotest.run_and_expect(func, None, count=15, wait=1)
        assert result is None, "Failed"

    # Configure uA SID without explicit nexthop
    router.vtysh_cmd(
        """
        configure terminal
         segment-routing
          srv6
           static-sids
            sid fcbb:bbbb:1:fe41::/64 locator MAIN behavior uA interface r1-eth0
        """
    )

    # Ensure r2 interface is up and reachable
    check_ping("r1", "2001::2", True, 10, 1)

    # Verify SID is installed with resolved nexthop
    logger.info("Test uA SID resolution with available neighbor")
    check_srv6_static_sids(router, "expected_srv6_sids_and_ua.json")


def test_srv6_static_sids_ua_neighbor_down():
    """Test that uA SID is removed when neighbor becomes unreachable"""
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)
    router = tgen.gears["r1"]

    def _check_srv6_static_sids(router, expected_route_file):
        logger.info("checking zebra srv6 static sids")
        output = json.loads(router.vtysh_cmd("show ipv6 route static json"))
        expected = open_json_file("{}/{}".format(CWD, expected_route_file))
        return topotest.json_cmp(output, expected)

    def check_srv6_static_sids(router, expected_file):
        func = functools.partial(_check_srv6_static_sids, router, expected_file)
        _, result = topotest.run_and_expect(func, None, count=15, wait=1)
        assert result is None, "Failed"

    # Start with neighbor up and SID configured (from previous test)
    check_ping("r1", "2001::2", True, 10, 1)
    check_srv6_static_sids(router, "expected_srv6_sids_and_ua.json")

    # Bring down r2 interface
    logger.info("Taking down r2-eth0 interface")
    tgen.gears["r2"].run("ip link set r2-eth0 down")

    # Flush neighbor entry on r1 to simulate neighbor unreachable
    logger.info("Flushing neighbor entry on r1")
    router.vtysh_cmd("ip neigh flush 2001::2 dev r1-eth0")

    # Ensure neighbor is unreachable
    check_ping("r1", "2001::2", False, 10, 1)

    # Wait for neighbor to expire and verify SID is removed
    logger.info("Verify uA SID is removed when neighbor goes down")
    check_srv6_static_sids(router, "expected_srv6_sids.json")


def test_srv6_static_sids_ua_neighbor_recovery():
    """Test that uA SID is reinstalled when neighbor recovers"""
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)
    router = tgen.gears["r1"]

    def _check_srv6_static_sids(router, expected_route_file):
        logger.info("checking zebra srv6 static sids")
        output = json.loads(router.vtysh_cmd("show ipv6 route static json"))
        expected = open_json_file("{}/{}".format(CWD, expected_route_file))
        return topotest.json_cmp(output, expected)

    def check_srv6_static_sids(router, expected_file):
        func = functools.partial(_check_srv6_static_sids, router, expected_file)
        _, result = topotest.run_and_expect(func, None, count=15, wait=1)
        assert result is None, "Failed"

    # Start with neighbor down and SID configured but not installed
    check_ping("r1", "2001::2", False, 10, 1)
    check_srv6_static_sids(router, "expected_srv6_sids.json")

    # Bring up r2 interface
    logger.info("Bringing up r2-eth0 interface")
    tgen.gears["r2"].run("ip link set r2-eth0 up")

    # Wait for neighbor discovery and verify SID is installed
    check_ping("r1", "2001::2", True, 10, 1)

    logger.info("Verify uA SID is installed after neighbor recovery")
    check_srv6_static_sids(router, "expected_srv6_sids_and_ua.json")


def test_srv6_static_sids_ua_sid_removal():
    """Test cleanup when uA SID with resolution is removed"""
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)
    router = tgen.gears["r1"]

    def _check_srv6_static_sids(router, expected_route_file):
        logger.info("checking zebra srv6 static sids")
        output = json.loads(router.vtysh_cmd("show ipv6 route static json"))
        expected = open_json_file("{}/{}".format(CWD, expected_route_file))
        return topotest.json_cmp(output, expected)

    def check_srv6_static_sids(router, expected_file):
        func = functools.partial(_check_srv6_static_sids, router, expected_file)
        _, result = topotest.run_and_expect(func, None, count=15, wait=1)
        assert result is None, "Failed"

    # Remove the SID
    router.vtysh_cmd(
        """
        configure terminal
         segment-routing
          srv6
           static-sids
            no sid fcbb:bbbb:1:fe41::/64
        """
    )

    # Verify SID is removed and neighbor notifications unregistered
    check_srv6_static_sids(router, "expected_srv6_sids.json")


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
