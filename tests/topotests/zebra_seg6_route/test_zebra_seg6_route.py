#!/usr/bin/env python
# SPDX-License-Identifier: ISC

#
# test_zebra_seg6_route.py
#
# Copyright (c) 2020 by
# LINE Corporation, Hiroki Shirokura <slank.dev@gmail.com>
#

"""
test_zebra_seg6_route.py: Test seg6 route addition with zapi.
"""

import os
import sys
import pytest
import json
from functools import partial

CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

# pylint: disable=C0413
from lib import topotest
from lib.topogen import Topogen, TopoRouter, get_topogen
from lib.topolog import logger

pytestmark = [pytest.mark.sharpd]


def open_json_file(filename):
    try:
        with open(filename, "r") as f:
            return json.load(f)
    except IOError:
        assert False, "Could not read file {}".format(filename)


def setup_module(mod):
    tgen = Topogen({None: "r1"}, mod.__name__)
    tgen.start_topology()
    router_list = tgen.routers()
    for rname, router in tgen.routers().items():
        router.run(
            "/bin/bash {}".format(os.path.join(CWD, "{}/setup.sh".format(rname)))
        )
        router.load_config(
            TopoRouter.RD_ZEBRA, os.path.join(CWD, "{}/zebra.conf".format(rname))
        )
        router.load_config(
            TopoRouter.RD_SHARP, os.path.join(CWD, "{}/sharpd.conf".format(rname))
        )
    tgen.start_router()


def teardown_module(_mod):
    tgen = get_topogen()
    tgen.stop_topology()


def test_zebra_seg6_routes():
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)
    logger.info("Test for seg6 route install via ZAPI was start.")
    r1 = tgen.gears["r1"]

    def check(router, dest, expected):
        output = json.loads(router.vtysh_cmd("show ipv6 route {} json".format(dest)))
        output = output.get("{}/128".format(dest))
        if output is None:
            return False
        return topotest.json_cmp(output, expected)

    def check_connected(router, dest, expected):
        logger.info("Checking for connected")
        output = json.loads(router.vtysh_cmd("show ipv6 route {} json".format(dest)))
        return topotest.json_cmp(output, expected)

    expected = open_json_file(os.path.join(CWD, "{}/routes_setup.json".format("r1")))
    test_func = partial(check_connected, r1, "2001::/64", expected)
    _, result = topotest.run_and_expect(test_func, None, count=20, wait=1)
    assert result is None, "Failed to fully setup connected routes needed"

    manifests = open_json_file(os.path.join(CWD, "{}/routes.json".format("r1")))
    for manifest in manifests:
        dest = manifest["in"]["dest"]
        nh = manifest["in"]["nh"]
        sid = manifest["in"]["sid"]

        r1.vtysh_cmd(
            "sharp install seg6-routes {} nexthop-seg6 {} encap {} 1".format(
                dest, nh, sid
            )
        )
        logger.info("CHECK {} {} {}".format(dest, nh, sid))
        test_func = partial(check, r1, dest, manifest["out"])
        _, result = topotest.run_and_expect(test_func, None, count=20, wait=1)
        assert result is None, "Failed"


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
