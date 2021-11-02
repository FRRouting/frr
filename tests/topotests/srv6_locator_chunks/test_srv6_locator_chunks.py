#!/usr/bin/env python

#
# test_srv6_locator_chunks.py
# Part of NetDEF Topology Tests
#
# Copyright (c) 2021 by
# Yamato Sugawara <yamato.sugawara@linecorp.com>
#
# Permission to use, copy, modify, and/or distribute this software
# for any purpose with or without fee is hereby granted, provided
# that the above copyright notice and this permission notice appear
# in all copies.
#
# THE SOFTWARE IS PROVIDED "AS IS" AND NETDEF DISCLAIMS ALL WARRANTIES
# WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
# MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL NETDEF BE LIABLE FOR
# ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY
# DAMAGES WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS,
# WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS
# ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE
# OF THIS SOFTWARE.
#

"""
test_srv6_locator_chunks.py:
Test SRv6 manager for multi chunks on zebra
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


def get_locator_chunk_from_bgpd(router, locator):
    router.vtysh_cmd(
        """
        configure terminal
         router bgp 100
          segment-routing srv6
           locator {}
        """.format(
            locator
        )
    )


def get_locator_chunk_from_sharpd(router, locator):
    router.vtysh_cmd("sharp srv6-manager get-locator-chunk {}".format(locator))


def release_locator_chunk_from_bgpd(router, locator):
    router.vtysh_cmd(
        """
        configure terminal
         router bgp 100
          segment-routing srv6
           no locator {}
        """.format(
            locator
        )
    )


def release_locator_chunk_from_sharpd(router, locator):
    router.vtysh_cmd("sharp srv6-manager release-locator-chunk {}".format(locator))


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

    def _check_bgpd_chunk(router, expected_chunk_file):
        logger.info("checking bgpd locator chunk status")
        output = json.loads(router.vtysh_cmd("show bgp segment-routing srv6 json"))
        expected = open_json_file("{}/{}".format(CWD, expected_chunk_file))
        return topotest.json_cmp(output, expected)

    def check_srv6_locator(router, expected_file):
        func = functools.partial(_check_srv6_locator, router, expected_file)
        success, result = topotest.run_and_expect(func, None, count=5, wait=1)
        assert result is None, "Failed"

    def check_sharpd_chunk(router, expected_file):
        func = functools.partial(_check_sharpd_chunk, router, expected_file)
        success, result = topotest.run_and_expect(func, None, count=5, wait=1)
        assert result is None, "Failed"

    def check_bgpd_chunk(router, expected_file):
        func = functools.partial(_check_bgpd_chunk, router, expected_file)
        success, result = topotest.run_and_expect(func, None, count=5, wait=1)
        assert result is None, "Failed"

    # FOR DEVELOPER:
    # If you want to stop some specific line and start interactive shell,
    # please use tgen.mininet_cli() to start it.

    logger.info("Test STEP1: locator configuration")
    check_srv6_locator(router, "step1/expected_locators.json")
    check_sharpd_chunk(router, "step1/expected_sharpd_chunks.json")
    check_bgpd_chunk(router, "step1/expected_bgpd_chunks.json")

    logger.info("Test STEP2: get locator chunk for locator loc1 from sharpd")
    get_locator_chunk_from_sharpd(router, "loc1")
    check_srv6_locator(router, "step2/expected_locators.json")
    check_sharpd_chunk(router, "step2/expected_sharpd_chunks.json")
    check_bgpd_chunk(router, "step2/expected_bgpd_chunks.json")

    logger.info("Test STEP3: get locator chunk for locator loc1 from bgpd")
    get_locator_chunk_from_bgpd(router, "loc1")
    check_srv6_locator(router, "step3/expected_locators.json")
    check_sharpd_chunk(router, "step3/expected_sharpd_chunks.json")
    check_bgpd_chunk(router, "step3/expected_bgpd_chunks.json")

    logger.info("Test STEP4: release locator chunk loc1 by sharpd")
    release_locator_chunk_from_sharpd(router, "loc1")
    check_srv6_locator(router, "step4/expected_locators.json")
    check_sharpd_chunk(router, "step4/expected_sharpd_chunks.json")
    check_bgpd_chunk(router, "step4/expected_bgpd_chunks.json")

    logger.info("Test STEP5: release locator chunk loc1 by bgpd")
    get_locator_chunk_from_sharpd(router, "loc1")
    release_locator_chunk_from_bgpd(router, "loc1")
    check_srv6_locator(router, "step5/expected_locators.json")
    check_sharpd_chunk(router, "step5/expected_sharpd_chunks.json")
    check_bgpd_chunk(router, "step5/expected_bgpd_chunks.json")

    logger.info("Test STEP6: release all chunk")
    release_locator_chunk_from_sharpd(router, "loc1")
    check_srv6_locator(router, "step6/expected_locators.json")
    check_sharpd_chunk(router, "step6/expected_sharpd_chunks.json")
    check_bgpd_chunk(router, "step6/expected_bgpd_chunks.json")


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
