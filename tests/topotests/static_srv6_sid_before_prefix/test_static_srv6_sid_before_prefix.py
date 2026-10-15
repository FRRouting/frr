#!/usr/bin/env python
# SPDX-License-Identifier: ISC
#
# Copyright 2026, Nvidia Inc.
#                 Donald Sharp
#
"""
Request an explicit SRv6 static SID before the locator prefix exists.

`locator NAME` creates the locator with prefix ::/0 and no SID block.
prefix_match() treats that prefix as matching every address, so an explicit
SID request used to walk a NULL SID-context list and SIGSEGV zebra in
zebra_srv6_sid_ctx_lookup().

This test applies that order on purpose. Zebra must stay up, and the SID
must be installed only after the prefix is configured.
"""

import functools
import json
import os
import sys
import time

import pytest

CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

# pylint: disable=C0413
from lib import topotest
from lib.topogen import Topogen, get_topogen
from lib.topolog import logger

pytestmark = [pytest.mark.staticd]

SID_PREFIX = "fcbb:bbbb:1::/48"
# staticd's get-locator / get-sid exchange is asynchronous. Hold this long
# after the SID is configured; zebra used to SIGSEGV in that window.
ZEBRA_SURVIVE_SECS = 20

EXPECTED_UNREADY_LOCATOR = {
    "locators": [
        {
            "name": "MAIN",
            "blockBitsLength": 0,
            "nodeBitsLength": 0,
            "functionBitsLength": 0,
        }
    ]
}

EXPECTED_UN_SID = {
    SID_PREFIX: [
        {
            "prefix": SID_PREFIX,
            "protocol": "static",
            "installed": True,
            "nexthops": [
                {
                    "interfaceName": "sr0",
                    "fib": True,
                    "seg6local": {"action": "uN"},
                }
            ],
        }
    ]
}


def setup_module(mod):
    tgen = Topogen({"s1": ("r1",)}, mod.__name__)
    tgen.start_topology()

    router = tgen.gears["r1"]
    # uN SIDs are installed on the default SRv6 interface.
    router.run("ip link add sr0 type dummy")
    router.run("ip link set sr0 up")
    router.load_frr_config("frr.conf")

    tgen.start_router()


def teardown_module():
    get_topogen().stop_topology()


def _static_routes(router):
    output = router.vtysh_cmd("show ipv6 route static json")
    try:
        return json.loads(output)
    except json.JSONDecodeError as error:
        return "show ipv6 route static json: {}: {}".format(error, output)


def _zebra_still_running(router, started):
    """Stay unmatched until ZEBRA_SURVIVE_SECS have elapsed.

    run_and_expect() returns on the first match, so a plain "zebra is up"
    check would succeed immediately. A dead daemon fails the test here
    instead of being polled again.
    """
    status = router.check_router_running()
    if status:
        raise AssertionError(status)
    if time.monotonic() - started < ZEBRA_SURVIVE_SECS:
        return "waiting"
    return None


def _check_un_sid(router):
    status = router.check_router_running()
    if status:
        raise AssertionError(status)

    routes = _static_routes(router)
    if isinstance(routes, str):
        return routes
    return topotest.json_cmp(routes, EXPECTED_UN_SID)


def test_static_sid_before_locator_prefix():
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)
    router = tgen.gears["r1"]

    logger.info("Create locator MAIN with no prefix")
    router.vtysh_cmd(
        """
        configure terminal
         segment-routing
          srv6
           locators
            locator MAIN
        """
    )
    locators = json.loads(router.vtysh_cmd("show segment-routing srv6 locator json"))
    result = topotest.json_cmp(locators, EXPECTED_UNREADY_LOCATOR)
    assert result is None, result

    logger.info("Request explicit uN SID before the locator prefix exists")
    router.vtysh_cmd(
        """
        configure terminal
         segment-routing
          srv6
           static-sids
            sid fcbb:bbbb:1::/48 locator MAIN behavior uN
        """
    )

    # count=21 and wait=1: twenty mismatches, then one sample after 20s.
    logger.info("Wait %ss for the SID request to reach zebra", ZEBRA_SURVIVE_SECS)
    success, result = topotest.run_and_expect(
        functools.partial(_zebra_still_running, router, time.monotonic()),
        None,
        count=ZEBRA_SURVIVE_SECS + 1,
        wait=1,
    )
    assert success, result

    routes = _static_routes(router)
    assert not isinstance(routes, str), routes
    assert SID_PREFIX not in routes, (
        "SID was installed while locator MAIN had no prefix: {}".format(routes)
    )

    logger.info("Configure the locator prefix; the SID must be allocated now")
    router.vtysh_cmd(
        """
        configure terminal
         segment-routing
          srv6
           locators
            locator MAIN
             prefix fcbb:bbbb:1::/48 block-len 32 node-len 16 func-bits 16
        """
    )

    _, result = topotest.run_and_expect(
        functools.partial(_check_un_sid, router), None, count=5, wait=3
    )
    assert result is None, result
