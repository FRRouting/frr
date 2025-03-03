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

pytestmark = [pytest.mark.staticd]


def open_json_file(filename):
    try:
        with open(filename, "r") as f:
            return json.load(f)
    except IOError:
        assert False, "Could not read file {}".format(filename)


def setup_module(mod):
    tgen = Topogen({None: "r1"}, mod.__name__)
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


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
