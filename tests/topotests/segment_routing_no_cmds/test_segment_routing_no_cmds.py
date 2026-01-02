#!/usr/bin/env python
# SPDX-License-Identifier: ISC

#
# test_segment_routing_no_cmds.py
#
# Copyright (c) 2026 by
# VyOS, Kyrylo Yatsenko <hedrok@gmail.com>
#

"""
test_segment_routing_no_cmds.py
Test for 'no' commands under segment-routing
"""

import os
import sys
import json
import pytest
import functools

from lib.common_config import step

CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

# pylint: disable=C0413
from lib import topotest
from lib.topogen import Topogen, TopoRouter, get_topogen
from lib.topolog import logger
from lib.checkping import check_ping

pytestmark = [pytest.mark.staticd]


def setup_module(mod):
    tgen = Topogen({None: "r1"}, mod.__name__)
    tgen.start_topology()
    for rname, router in tgen.routers().items():
        router.load_config(
            TopoRouter.RD_ZEBRA, os.path.join(CWD, f"{rname}/zebra.conf")
        )
        router.load_config(
            TopoRouter.RD_PATH,
            os.path.join(CWD, f"{rname}/pathd.conf"),
            " -M pathd_pcep",
        )
    tgen.start_router()


def teardown_module():
    tgen = get_topogen()
    tgen.stop_topology()


def test_segment_routing_no_cmds():
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)
    r1 = tgen.gears["r1"]

    def check_convergence_no_str_in_config(no_str):
        output = r1.vtysh_cmd("write terminal")
        if no_str in output:
            return f"'{no_str}' still in configuration output. Full output: {output}"
        return None

    step("Precheck configuration...")
    output = r1.vtysh_cmd("write terminal")
    assert "pcep" in output, 'no "pcep" in configuration before tests...'
    assert "traffic-eng" in output, 'no "traffic-eng" in configuration before tests...'

    step("Run 'no pcep'...")
    assert "% Unknown command" not in r1.vtysh_cmd(
        """
        configure
            segment-routing
                traffic-eng
                    no pcep
        """,
        raises=True,
    )

    step("Check that there is no 'pcep' in configuration...")
    check_pcep = functools.partial(check_convergence_no_str_in_config, "pcep")
    _, result = topotest.run_and_expect(check_pcep, None, count=60, wait=1)
    assert result is None, f"r1 failed to converge, result: {result}"

    step("Run 'no traffic-eng'...")
    assert "% Unknown command" not in r1.vtysh_cmd(
        """
        configure terminal
            segment-routing
                no traffic-eng
        """,
        raises=True,
    )

    step("Check that there is no 'traffic-eng' in configuration...")
    check_te = functools.partial(check_convergence_no_str_in_config, "traffic-eng")
    _, result = topotest.run_and_expect(check_te, None, count=60, wait=1)
    assert result is None, f"r1 failed to converge, result: {result}"


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
