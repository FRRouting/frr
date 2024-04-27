#!/usr/bin/env python
# SPDX-License-Identifier: ISC

#
# scale_test_common.py
#
# Copyright (c) 2020 by
# Cumulus Networks, Inc.
# Donald Sharp
#

"""
scale_test_common.py: Common routines for testing route scale

"""

import os
import re
import sys
import pytest
import json
from functools import partial

# Save the Current Working Directory to find configuration files.
CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

# pylint: disable=C0413
# Import topogen and topotest helpers
from lib import topotest
from lib.topogen import Topogen, TopoRouter, get_topogen
from lib.topolog import logger


#####################################################
##
##   Network Topology Definition
##
#####################################################


def scale_build_common(tgen):
    "Build function"

    # Populate routers
    for routern in range(1, 2):
        tgen.add_router("r{}".format(routern))

    # Populate switches
    for switchn in range(1, 33):
        switch = tgen.add_switch("sw{}".format(switchn))
        switch.add_link(tgen.gears["r1"])


def scale_setup_module(module):
    "Setup topology"
    tgen = Topogen(scale_build_common, module.__name__)
    tgen.start_topology()

    router_list = tgen.routers()
    for rname, router in router_list.items():
        router.load_config(
            TopoRouter.RD_ZEBRA, os.path.join(CWD, "{}/zebra.conf".format(rname))
        )
        router.load_config(
            TopoRouter.RD_SHARP, os.path.join(CWD, "{}/sharpd.conf".format(rname))
        )

    tgen.start_router()
    # tgen.mininet_cli()


def scale_teardown_module(_mod):
    "Teardown the pytest environment"
    tgen = get_topogen()

    # This function tears down the whole topology.
    tgen.stop_topology()


def scale_converge_protocols():
    "Wait for protocol convergence"

    tgen = get_topogen()
    # Don't run this test if we have any failure.
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)


def run_one_setup(r1, s):
    "Run one ecmp config"

    # Extract params
    expected_installed = s["expect_in"]
    expected_removed = s["expect_rem"]

    retries = s["retries"]
    wait = s["wait"]

    for d in expected_installed["routes"]:
        if d["type"] == "sharp":
            count = d["rib"]
            break

    logger.info("Testing {} routes X {} ecmp".format(count, s["ecmp"]))

    r1.vtysh_cmd(
        "sharp install route 1.0.0.0 \
                  nexthop-group {} {}".format(
            s["nhg"], count
        ),
        isjson=False,
    )

    test_func = partial(
        topotest.router_json_cmp, r1, "show ip route summary json", expected_installed
    )
    success, result = topotest.run_and_expect(test_func, None, retries, wait)
    assert success, "Route scale test install failed:\n{}".format(result)

    output = r1.vtysh_cmd("sharp data route", isjson=False)
    logger.info("{} routes X {} ecmp installed".format(count, s["ecmp"]))
    logger.info(output)
    r1.vtysh_cmd("sharp remove route 1.0.0.0 {}".format(count), isjson=False)
    test_func = partial(
        topotest.router_json_cmp, r1, "show ip route summary json", expected_removed
    )
    success, result = topotest.run_and_expect(test_func, None, retries, wait)
    assert success, "Route scale test remove failed:\n{}".format(result)

    output = r1.vtysh_cmd("sharp data route", isjson=False)
    logger.info("{} routes x {} ecmp removed".format(count, s["ecmp"]))
    logger.info(output)


def route_install_helper(iter):
    "Test route install for a variety of ecmp"

    tgen = get_topogen()
    # Don't run this test if we have any failure.
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]

    # Avoid top ecmp case for runs with < 4G memory
    output = tgen.net.cmd_raises("free")
    m = re.search(r"Mem:\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)", output)
    total_mem = int(m.group(2))
    if total_mem < 4000000 and iter == 5:
        logger.info(
            "Limited memory available: {}, skipping x32 testcase".format(total_mem)
        )
        return

    installed_file = "{}/r1/installed.routes.json".format(CWD)
    expected_installed = json.loads(open(installed_file).read())

    removed_file = "{}/r1/no.routes.json".format(CWD)
    expected_removed = json.loads(open(removed_file).read())

    # dict keys of params: ecmp number, corresponding nhg name, timeout,
    # number of times to wait
    scale_keys = ["ecmp", "nhg", "wait", "retries", "expect_in", "expect_rem"]

    # Table of defaults, used for timeout values and 'expected' objects
    scale_defaults = dict(
        zip(scale_keys, [None, None, 10, 50, expected_installed, expected_removed])
    )

    # List of params for each step in the test; note extra time given
    # for the highest ecmp steps. Executing 'show' at scale can be costly
    # so we widen the interval there too.
    scale_steps = [
        [1, "one"],
        [2, "two"],
        [4, "four"],
        [8, "eight"],
        [16, "sixteen", 10, 40],
        [32, "thirtytwo", 10, 40],
    ]

    # Build up a list of dicts with params for each step of the test;
    # use defaults where the step doesn't supply a value
    scale_setups = []
    s = scale_steps[iter]

    d = dict(zip(scale_keys, s))
    for k in scale_keys:
        if k not in d:
            d[k] = scale_defaults[k]

    run_one_setup(r1, d)


# Mem leak testcase
def scale_test_memory_leak():
    "Run the memory leak test and report results."
    tgen = get_topogen()
    if not tgen.is_memleak_enabled():
        pytest.skip("Memory leak test/report is disabled")
    tgen.report_memory_leaks()
