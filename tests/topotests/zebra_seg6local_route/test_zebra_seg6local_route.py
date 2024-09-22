#!/usr/bin/env python
# SPDX-License-Identifier: ISC

#
# test_zebra_seg6local_route.py
#
# Copyright (c) 2020 by
# LINE Corporation, Hiroki Shirokura <slank.dev@gmail.com>
#

"""
test_zebra_seg6local_route.py: Test seg6local route addition with zapi.
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
from lib.common_config import required_linux_kernel_version

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
    for rname, router in router_list.items():
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


def test_zebra_seg6local_routes():
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)
    logger.info("Test for seg6local route install via ZAPI was start.")
    r1 = tgen.gears["r1"]

    def check(router, dest, expected):
        output = json.loads(router.vtysh_cmd("show ipv6 route {} json".format(dest)))
        output = output.get("{}/128".format(dest))
        if output is None:
            return False
        return topotest.json_cmp(output, expected)

    manifests = open_json_file(os.path.join(CWD, "{}/routes.json".format("r1")))
    for manifest in manifests:
        dest = manifest["in"]["dest"]
        context = manifest["in"]["context"]

        logger.info("CHECK {} {}".format(dest, context))

        if manifest.get("required_kernel") is not None:
            if required_linux_kernel_version(manifest["required_kernel"]) is not True:
                logger.info(
                    "Kernel requirements are not met. Skipping {} {}".format(
                        dest, context
                    )
                )
                continue

        r1.vtysh_cmd(
            "sharp install seg6local-routes {} nexthop-seg6local dum0 {} 1".format(
                dest, context
            )
        )
        test_func = partial(
            check,
            r1,
            dest,
            manifest["out"],
        )
        _, result = topotest.run_and_expect(test_func, None, count=25, wait=1)
        assert result is None, "Failed"


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
