#!/usr/bin/env python
# SPDX-License-Identifier: ISC

#
# test_srv6_manager.py
# Part of NetDEF Topology Tests
#
# Copyright (c) 2020 by
# LINE Corporation, Hiroki Shirokura <slank.dev@gmail.com>
#

"""
test_srv6_manager.py:
Test for SRv6 manager on zebra
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

pytestmark = [pytest.mark.bgpd, pytest.mark.sharpd]


def open_json_file(filename):
    try:
        with open(filename, "r") as f:
            return json.load(f)
    except IOError:
        assert False, "Could not read file {}".format(filename)


def _check_sharpd_chunk(router, expected_chunk_file):
    logger.info("checking sharpd locator chunk status")
    output = json.loads(router.vtysh_cmd("show sharp segment-routing srv6 json"))
    expected = open_json_file("{}/{}".format(CWD, expected_chunk_file))
    return topotest.json_cmp(output, expected)


def _check_srv6_locator(router, expected_locator_file):
    logger.info("checking zebra locator status")
    output = json.loads(router.vtysh_cmd("show segment-routing srv6 locator json"))
    expected = open_json_file("{}/{}".format(CWD, expected_locator_file))
    return topotest.json_cmp(output, expected)


def check_srv6_locator(router, expected_file):
    func = functools.partial(_check_srv6_locator, router, expected_file)
    _, result = topotest.run_and_expect(func, None, count=15, wait=1)
    assert result is None, "Failed"


def check_sharpd_chunk(router, expected_file):
    func = functools.partial(_check_sharpd_chunk, router, expected_file)
    _, result = topotest.run_and_expect(func, None, count=15, wait=1)
    assert result is None, "Failed"


def setup_module(mod):
    tgen = Topogen({None: "r1"}, mod.__name__)
    tgen.start_topology()
    for rname, router in tgen.routers().items():
        router.run("/bin/bash {}/{}/setup.sh".format(CWD, rname))
        router.load_config(
            TopoRouter.RD_ZEBRA, os.path.join(CWD, "{}/zebra.conf".format(rname))
        )
        router.load_config(
            TopoRouter.RD_BGP, os.path.join(CWD, "{}/bgpd.conf".format(rname))
        )
        router.load_config(
            TopoRouter.RD_SHARP, os.path.join(CWD, "{}/sharpd.conf".format(rname))
        )
    tgen.start_router()


def teardown_module():
    tgen = get_topogen()
    tgen.stop_topology()


def test_srv6():
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)
    router = tgen.gears["r1"]

    # FOR DEVELOPER:
    # If you want to stop some specific line and start interactive shell,
    # please use tgen.mininet_cli() to start it.

    logger.info("Test1 for Locator Configuration")
    check_srv6_locator(router, "expected_locators1.json")
    check_sharpd_chunk(router, "expected_chunks1.json")

    logger.info("Test2 get chunk for locator loc1")
    router.vtysh_cmd("sharp srv6-manager get-locator-chunk loc1")
    check_srv6_locator(router, "expected_locators2.json")
    check_sharpd_chunk(router, "expected_chunks2.json")

    logger.info("Test3 release chunk for locator loc1")
    router.vtysh_cmd("sharp srv6-manager release-locator-chunk loc1")
    check_srv6_locator(router, "expected_locators3.json")
    check_sharpd_chunk(router, "expected_chunks3.json")

    logger.info("Test4 additional locator loc3")
    router.vtysh_cmd(
        """
        configure terminal
         segment-routing
          srv6
           locators
            locator loc3
             prefix 2001:db8:3:3::/64
        """
    )
    check_srv6_locator(router, "expected_locators4.json")
    check_sharpd_chunk(router, "expected_chunks4.json")

    logger.info("Test5 delete locator and chunk is released automatically")
    router.vtysh_cmd(
        """
        configure terminal
         segment-routing
          srv6
           locators
            no locator loc1
        """
    )
    check_srv6_locator(router, "expected_locators5.json")
    check_sharpd_chunk(router, "expected_chunks5.json")

    logger.info("Test6 delete srv6 all configuration")
    router.vtysh_cmd(
        """
        configure terminal
         segment-routing
          no srv6
        """
    )
    check_srv6_locator(router, "expected_locators6.json")
    check_sharpd_chunk(router, "expected_chunks6.json")


def test_srv6_no_locator():
    """Delete a locator after removing its prefix."""
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)
    router = tgen.gears["r1"]

    router.vtysh_cmd(
        """
        configure terminal
         segment-routing
          srv6
           locators
            locator loc1
             prefix fcbb:bbbb:1::/48
             format usid-f3216
        """
    )
    check_srv6_locator(router, "expected_locators7.json")

    router.vtysh_cmd(
        """
        configure terminal
         segment-routing
          srv6
           locators
            no locator loc1
        """
    )
    assert router.check_router_running() == ""
    check_srv6_locator(router, "expected_locators6.json")

    router.vtysh_cmd(
        """
        configure terminal
         segment-routing
          srv6
           locators
            locator loc1
             prefix fcbb:bbbb:1::/48
        """
    )
    check_srv6_locator(router, "expected_locators7.json")


<<<<<<< HEAD
=======
def test_srv6_locator_status_lifecycle():
    """Keep locator state consistent across prefix changes and re-entry."""
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)
    router = tgen.gears["r1"]
    locator_name = "loc3"
    locator_prefix = "fcbb:bbbb:3::/48"

    step("Create loc3 without a prefix", reset=True)
    router.vtysh_cmd(
        """
        configure terminal
         segment-routing
          srv6
           locators
            locator loc3
        """
    )
    check_srv6_locator_state(router, locator_name, "UNK prefix", False)

    step("Re-enter the locator and verify it stays down")
    router.vtysh_cmd(
        """
        configure terminal
         segment-routing
          srv6
           locators
            locator loc3
        """
    )
    check_srv6_locator_state(router, locator_name, "UNK prefix", False)

    step("Configure a valid uSID locator prefix")
    router.vtysh_cmd(
        """
        configure terminal
         segment-routing
          srv6
           locators
            locator loc3
             prefix fcbb:bbbb:3::/48
             format usid-f3216
        """
    )
    check_srv6_locator_state(router, locator_name, locator_prefix, True)

    step("Attempt an incompatible prefix update")
    output = router.vtysh_cmd(
        """
        configure terminal
         segment-routing
          srv6
           locators
            locator loc3
             prefix fcbb:bbbb:4::/64
        """
    )
    assert "inconsistent with configured format" in output
    check_srv6_locator_state(router, locator_name, locator_prefix, True)

    step("Remove the prefix and verify the locator goes down")
    router.vtysh_cmd(
        """
        configure terminal
         segment-routing
          srv6
           locators
            locator loc3
             no prefix
        """
    )
    check_srv6_locator_state(router, locator_name, "::/0", False)

    step("Restore the prefix and verify the locator comes up")
    router.vtysh_cmd(
        """
        configure terminal
         segment-routing
          srv6
           locators
            locator loc3
             prefix fcbb:bbbb:3::/48
        """
    )
    check_srv6_locator_state(router, locator_name, locator_prefix, True)

    step("Remove the locator")
    router.vtysh_cmd(
        """
        configure terminal
         segment-routing
          srv6
           locators
            no locator loc3
        """
    )
    check_srv6_locator_absent(router, locator_name)


def test_srv6_sid_format_no_wide_local_id_block():
    """'no wide-local-id-block' restores the default Wide LIB without crashing zebra."""
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)
    router = tgen.gears["r1"]

    # The formats block is only shown in the running config while a locator exists
    router.vtysh_cmd(
        """
        configure terminal
         segment-routing
          srv6
           locators
            locator loc1
             prefix fcbb:bbbb:1::/48
        """
    )

    for sid_format in ["usid-f3216", "usid-f4816"]:
        router.vtysh_cmd(
            """
            configure terminal
             segment-routing
              srv6
               formats
                format {}
                 wide-local-id-block start 100 end 200
            """.format(
                sid_format
            )
        )
        output = router.vtysh_cmd("show running-config")
        assert (
            "wide-local-id-block start 100 end 200" in output
        ), "{}: wide-local-id-block was not configured".format(sid_format)

        router.vtysh_cmd(
            """
            configure terminal
             segment-routing
              srv6
               formats
                format {}
                 no wide-local-id-block
            """.format(
                sid_format
            )
        )
        assert router.check_router_running() == ""
        output = router.vtysh_cmd("show running-config")
        assert (
            "wide-local-id-block" not in output
        ), "{}: wide-local-id-block was not removed".format(sid_format)


def test_srv6_sid_format_no_explicit():
    """'no explicit' restores the default explicit range of uncompressed-f4024."""
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)
    router = tgen.gears["r1"]

    # The formats block is only shown in the running config while a locator exists
    router.vtysh_cmd(
        """
        configure terminal
         segment-routing
          srv6
           locators
            locator loc1
             prefix fcbb:bbbb:1::/48
        """
    )

    router.vtysh_cmd(
        """
        configure terminal
         segment-routing
          srv6
           formats
            format uncompressed-f4024
             explicit start 65000
        """
    )
    output = router.vtysh_cmd("show running-config")
    assert "explicit start 65000" in output, "explicit start was not configured"

    router.vtysh_cmd(
        """
        configure terminal
         segment-routing
          srv6
           formats
            format uncompressed-f4024
             no explicit
        """
    )
    assert router.check_router_running() == ""
    output = router.vtysh_cmd("show running-config")
    assert "explicit start 65000" not in output, "explicit start was not removed"


>>>>>>> eeb030d (tests: check no wide-local-id-block and no explicit in srv6_locator)
if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
