#!/usr/bin/env python
# SPDX-License-Identifier: ISC

# Copyright (c) 2022, University of Rome Tor Vergata
# Authored by Carmine Scarpitta <carmine.scarpitta@uniroma2.it>
#

"""
test_srv6_locator_usid.py:
Test for SRv6 Locator uSID on zebra
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
            TopoRouter.RD_SHARP, os.path.join(CWD, "{}/sharpd.conf".format(rname))
        )
    tgen.start_router()


def teardown_module():
    tgen = get_topogen()
    tgen.stop_topology()


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
    _, result = topotest.run_and_expect(func, None, count=5, wait=3)
    assert result is None, "Failed"


def check_sharpd_chunk(router, expected_file):
    func = functools.partial(_check_sharpd_chunk, router, expected_file)
    _, result = topotest.run_and_expect(func, None, count=5, wait=3)
    assert result is None, "Failed"


def test_srv6_usid_locator_configuration():
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)
    router = tgen.gears["r1"]

    # FOR DEVELOPER:
    # If you want to stop some specific line and start interactive shell,
    # please use tgen.mininet_cli() to start it.

    logger.info("Verify SRv6 Locators instantiated from config file")
    check_srv6_locator(router, "expected_locators_1.json")
    check_sharpd_chunk(router, "expected_chunks_1.json")


def test_srv6_usid_locator_get_chunk():
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)
    router = tgen.gears["r1"]

    # FOR DEVELOPER:
    # If you want to stop some specific line and start interactive shell,
    # please use tgen.mininet_cli() to start it.

    logger.info("Get chunk for the locator loc1")
    router.vtysh_cmd("sharp srv6-manager get-locator-chunk loc1")
    check_srv6_locator(router, "expected_locators_2.json")
    check_sharpd_chunk(router, "expected_chunks_2.json")


def test_srv6_usid_locator_release_chunk():
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)
    router = tgen.gears["r1"]

    # FOR DEVELOPER:
    # If you want to stop some specific line and start interactive shell,
    # please use tgen.mininet_cli() to start it.

    logger.info("Release chunk for the locator loc1")
    router.vtysh_cmd("sharp srv6-manager release-locator-chunk loc1")
    check_srv6_locator(router, "expected_locators_3.json")
    check_sharpd_chunk(router, "expected_chunks_3.json")


def test_srv6_usid_locator_create_locator():
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)
    router = tgen.gears["r1"]

    # FOR DEVELOPER:
    # If you want to stop some specific line and start interactive shell,
    # please use tgen.mininet_cli() to start it.

    logger.info("Create an additional SRv6 Locator")
    router.vtysh_cmd(
        """
        configure terminal
         segment-routing
          srv6
           locators
            locator loc2
             prefix fc00:0:2::/48 block-len 32 node-len 16 func-bits 16
        """
    )
    check_srv6_locator(router, "expected_locators_4.json")
    check_sharpd_chunk(router, "expected_chunks_4.json")


def test_srv6_usid_locator_set_behavior_usid():
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)
    router = tgen.gears["r1"]

    # FOR DEVELOPER:
    # If you want to stop some specific line and start interactive shell,
    # please use tgen.mininet_cli() to start it.

    logger.info("Specify the SRv6 Locator loc2 as a Micro-segment (uSID) Locator")
    router.vtysh_cmd(
        """
        configure terminal
         segment-routing
          srv6
           locators
            locator loc2
             behavior usid
        """
    )
    check_srv6_locator(router, "expected_locators_5.json")
    check_sharpd_chunk(router, "expected_chunks_5.json")


def test_srv6_usid_locator_unset_behavior_usid():
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)
    router = tgen.gears["r1"]

    # FOR DEVELOPER:
    # If you want to stop some specific line and start interactive shell,
    # please use tgen.mininet_cli() to start it.

    logger.info("Clear Micro-segment (uSID) Locator flag for loc2")
    router.vtysh_cmd(
        """
        configure terminal
         segment-routing
          srv6
           locators
            locator loc2
             no behavior usid
        """
    )
    check_srv6_locator(router, "expected_locators_6.json")
    check_sharpd_chunk(router, "expected_chunks_6.json")


def test_srv6_usid_locator_delete():
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)
    router = tgen.gears["r1"]

    # FOR DEVELOPER:
    # If you want to stop some specific line and start interactive shell,
    # please use tgen.mininet_cli() to start it.

    logger.info(
        "Delete locator loc1 and verify that the chunk is released automatically"
    )
    router.vtysh_cmd(
        """
        configure terminal
         segment-routing
          srv6
           locators
            no locator loc1
        """
    )
    check_srv6_locator(router, "expected_locators_7.json")
    check_sharpd_chunk(router, "expected_chunks_7.json")


def test_srv6_usid_locator_delete_all():
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)
    router = tgen.gears["r1"]

    # FOR DEVELOPER:
    # If you want to stop some specific line and start interactive shell,
    # please use tgen.mininet_cli() to start it.

    logger.info("Delete all the SRv6 configuration")
    router.vtysh_cmd(
        """
        configure terminal
         segment-routing
          no srv6
        """
    )
    check_srv6_locator(router, "expected_locators_8.json")
    check_sharpd_chunk(router, "expected_chunks_8.json")


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
