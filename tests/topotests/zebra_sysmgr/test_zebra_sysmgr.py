#!/usr/bin/env python
# SPDX-License-Identifier: ISC
#
# test_zebra_sysmgr.py
#
# Copyright (c) 2026 by
# Nvidia Corporation
# Donald Sharp
#
"""
zebra_sysmgr topotest:
Validate ZEBRA_PORTS_UP/DOWN notifications via sharpd.
"""

import os
import sys
import functools
import pytest

pytestmark = [pytest.mark.sharpd]

CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

# pylint: disable=C0413
from lib import topotest
from lib.topogen import Topogen, TopoRouter, get_topogen


def build_topo(tgen):
    tgen.add_router("r1")


def setup_module(module):
    tgen = Topogen(build_topo, module.__name__)
    tgen.start_topology()

    router = tgen.gears["r1"]
    router.load_frr_config(
        os.path.join(CWD, "r1/frr.conf"),
        [
            (TopoRouter.RD_ZEBRA, None),
            (TopoRouter.RD_SHARP, None),
        ],
    )

    tgen.start_router()


def teardown_module(_mod):
    tgen = get_topogen()
    tgen.stop_topology()


def _sysmgr_last_cmd(expected_cmd):
    r1 = get_topogen().gears["r1"]
    output = r1.vtysh_cmd("show sharp sysmgr")
    if f"Last sysmgr command: {expected_cmd}" in output:
        return None
    return output


def test_sysmgr_ports_notifications():
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]
    r1.vtysh_cmd("sharp watch sysmgr")

    r1.vtysh_cmd("zebra send sysmgr test port down")
    test_func = functools.partial(_sysmgr_last_cmd, "ZEBRA_PORTS_DOWN")
    _, result = topotest.run_and_expect(test_func, None, count=60, wait=0.5)
    assert result is None, f"Did not receive PORTS_DOWN: {result}"

    r1.vtysh_cmd("zebra send sysmgr test port up")
    test_func = functools.partial(_sysmgr_last_cmd, "ZEBRA_PORTS_UP")
    _, result = topotest.run_and_expect(test_func, None, count=60, wait=0.5)
    assert result is None, f"Did not receive PORTS_UP: {result}"


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
