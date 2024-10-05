#!/usr/bin/env python
# SPDX-License-Identifier: ISC

# Copyright (c) 2024 by Nvidia Corporation
# Donald Sharp <sharpd@nvidia.com>

import os
import sys
import json
import pytest
import functools
from lib.topolog import logger

pytestmark = [pytest.mark.bgpd]

CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

# pylint: disable=C0413
from lib import topotest
from lib.topogen import Topogen, get_topogen


def setup_module(mod):
    topodef = {"s1": ("r1", "r2")}
    tgen = Topogen(topodef, mod.__name__)
    tgen.start_topology()

    router_list = tgen.routers()

    for _, (rname, router) in enumerate(router_list.items(), 1):
        router.load_frr_config(os.path.join(CWD, "{}/frr.conf".format(rname)))

    tgen.start_router()


def teardown_module(mod):
    tgen = get_topogen()
    tgen.stop_topology()


def test_bgp_dump():
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    logger.info("Test the ability for bgp to dump a file specified")
    r1 = tgen.gears["r1"]

    logger.info("Converge BGP")
    def _converge():
        output = json.loads(r1.vtysh_cmd("show bgp ipv4 unicast 10.10.10.10/32 json"))
        expected = {
            "paths": [
                {
                    "valid": True,
                    "nexthops": [
                        {
                            "hostname": "r2",
                            "accessible": True,
                        }
                    ],
                }
            ]
        }
        return topotest.json_cmp(output, expected)

    test_func = functools.partial(
        _converge,
    )
    _, result = topotest.run_and_expect(test_func, None, count=30, wait=1)
    assert result is None, "Can't converge"

    logger.info("Dumping file")
    ####
    # Create a dump file
    ####
    r1.vtysh_cmd(
        """
    configure terminal
    dump bgp all bgp_dump.file
    """
    )

    def _test_dump_file_existence():
        dump_file = "{}/r1/bgp_dump.file".format(tgen.logdir)

        logger.info("Looking for {} file".format(dump_file))
        logger.info(os.path.isfile(dump_file))
        return os.path.isfile(dump_file)

    logger.info("Ensure that Log file exists")
    _, result = topotest.run_and_expect(_test_dump_file_existence, True, count=30, wait = 3)
    assert result is True

    # At this point all we have done is ensure that the dump file
    # is generated for r1.  What is correctness of the dump anyways?

if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
