#!/usr/bin/env python
# SPDX-License-Identifier: ISC
#
# Copyright 2026 6WIND S.A.
# Justin Iurman <justin.iurman@6wind.com>
#

import os
import sys
import json
import pytest
import functools

# pylint: disable=C0413
from lib import topotest
from lib.topogen import Topogen, get_topogen
from lib.topolog import logger
from lib.common_config import required_linux_kernel_version

CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

pytestmark = [pytest.mark.staticd]


def open_json_file(filename):
    try:
        with open(filename, "r") as f:
            return json.load(f)
    except IOError:
        assert False, "Could not read file {}".format(filename)


def setup_module(mod):
    result = required_linux_kernel_version("7.1")
    if result is not True:
        pytest.skip("SRv6 encap-source: kernel version should be >=7.1")

    topodef = {None: ("r1")}
    tgen = Topogen(topodef, mod.__name__)
    tgen.start_topology()

    router_list = tgen.routers()
    for _, (rname, router) in enumerate(router_list.items()):
        router.run("/bin/bash {}/{}/setup.sh".format(CWD, rname))
        router.load_frr_config("frr.conf")

    tgen.start_router()


def teardown_module():
    tgen = get_topogen()
    tgen.stop_topology()


def test_srv6_static_route_encap_source():
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    def _check_rib(router, expected_route_file):
        logger.info("checking Zebra RIB")
        output = json.loads(router.vtysh_cmd("show ip route static json"))
        expected = open_json_file("{}/{}".format(CWD, expected_route_file))
        return topotest.json_cmp(output, expected)

    def check_rib(router, expected_file):
        func = functools.partial(_check_rib, router, expected_file)
        _, result = topotest.run_and_expect(func, None, count=10, wait=2)
        assert result is None, "Failed"

    def _check_rib_v6(router, expected_route_file):
        logger.info("checking Zebra RIB")
        output = json.loads(router.vtysh_cmd("show ipv6 route static json"))
        expected = open_json_file("{}/{}".format(CWD, expected_route_file))
        return topotest.json_cmp(output, expected)

    def check_rib_v6(router, expected_file):
        func = functools.partial(_check_rib_v6, router, expected_file)
        _, result = topotest.run_and_expect(func, None, count=10, wait=2)
        assert result is None, "Failed"

    router = tgen.gears["r1"]
    logger.info("Test for SRv6 (with encap-source) route configuration")
    check_rib(router, "r1/show_ip_route.json")
    check_rib_v6(router, "r1/show_ipv6_route.json")


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
