#!/usr/bin/env python
# SPDX-License-Identifier: ISC

# Copyright (c) 2022, University of Rome Tor Vergata
# Authored by Carmine Scarpitta <carmine.scarpitta@uniroma2.it>
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


def teardown_module(mod):
    tgen = get_topogen()
    tgen.stop_topology()


def test_srv6():
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)
    router = tgen.gears["r1"]

    def _check_srv6_locator(router, expected_locator_file):
        logger.info("checking zebra locator status")
        output = json.loads(router.vtysh_cmd("show segment-routing srv6 locator json"))
        expected = open_json_file("{}/{}".format(CWD, expected_locator_file))
        return topotest.json_cmp(output, expected)

    def _check_sharpd_chunk(router, expected_chunk_file):
        logger.info("checking sharpd locator chunk status")
        output = json.loads(router.vtysh_cmd("show sharp segment-routing srv6 json"))
        expected = open_json_file("{}/{}".format(CWD, expected_chunk_file))
        return topotest.json_cmp(output, expected)

    def check_srv6_locator(router, expected_file):
        func = functools.partial(_check_srv6_locator, router, expected_file)
        success, result = topotest.run_and_expect(func, None, count=10, wait=0.5)
        assert result is None, "Failed"

    def check_sharpd_chunk(router, expected_file):
        func = functools.partial(_check_sharpd_chunk, router, expected_file)
        success, result = topotest.run_and_expect(func, None, count=10, wait=0.5)
        assert result is None, "Failed"

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
             prefix 2001:db8:3::/48 block-len 32 node-len 16 func-bits 16
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


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
