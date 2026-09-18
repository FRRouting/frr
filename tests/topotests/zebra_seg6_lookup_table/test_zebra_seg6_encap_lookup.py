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
    result = required_linux_kernel_version("7.3")
    if result is not True:
        pytest.skip("SRv6 lookup table: kernel version should be >=7.3")

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


def test_zebra_seg6_lookup_table():
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    def _check_rib(router, cmd, expected_file):
        logger.info("checking the RIB: {}".format(cmd))
        output = json.loads(router.vtysh_cmd(cmd))
        expected = open_json_file("{}/{}".format(CWD, expected_file))
        return topotest.json_cmp(output, expected)

    def check_rib(router, cmd, expected_file):
        func = functools.partial(_check_rib, router, cmd, expected_file)
        _, result = topotest.run_and_expect(func, None, count=10, wait=2)
        assert result is None, "Failed"

    def _check_fib(router, cmd, expected_file):
        logger.info("checking the FIB: {}".format(cmd))
        output = json.loads(router.cmd(cmd))
        expected = open_json_file("{}/{}".format(CWD, expected_file))
        return topotest.json_cmp(output, expected)

    def check_fib(router, cmd, expected_file):
        func = functools.partial(_check_fib, router, cmd, expected_file)
        _, result = topotest.run_and_expect(func, None, count=10, wait=2)
        assert result is None, "Failed"

    router = tgen.gears["r1"]
    logger.info("Test for SRv6 lookup table")

    check_rib(router, "show ip route json", "r1/rib_v4.json")
    check_rib(router, "show ip route vrf vrfA json", "r1/rib_v4_vrfA.json")
    check_rib(router, "show ipv6 route json", "r1/rib_v6.json")
    check_rib(router, "show ipv6 route vrf vrfA json", "r1/rib_v6_vrfA.json")

    check_fib(router, "ip -j route show", "r1/fib_v4.json")
    check_fib(router, "ip -j route show table 1001", "r1/fib_v4_vrfA.json")
    check_fib(router, "ip -j -6 route show", "r1/fib_v6.json")
    check_fib(router, "ip -j -6 route show table 1001", "r1/fib_v6_vrfA.json")


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
