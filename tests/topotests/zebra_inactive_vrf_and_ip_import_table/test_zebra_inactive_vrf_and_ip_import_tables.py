#!/usr/bin/env python
# SPDX-License-Identifier: ISC
#
# test_zebra_inactive_vrf_and_ip_import_tables.py
#
# Copyright (c) 2026 by
# VyOS, Kyrylo Yatsenko
#

"""
test_zebra_inactive_vrf_and_ip_import_tables.py: test crash that happened when
there was inactive VRF and ip import-table
"""

import os
import re
import sys
import pytest

# Save the Current Working Directory to find configuration files.
CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

# pylint: disable=C0413
# Import topogen and topotest helpers
from lib import topotest
from lib.topogen import Topogen, get_topogen
from lib.topolog import logger


pytestmark = [pytest.mark.staticd]


def build_topo(tgen):
    tgen.add_router("r1")


def setup_module(mod):
    tgen = Topogen(build_topo, mod.__name__)
    tgen.start_topology()

    for _, (rname, router) in enumerate(tgen.routers().items(), 1):
        router.load_frr_config(os.path.join(CWD, "{}/frr.conf".format(rname)))

    tgen.start_router()


def teardown_module(mod):
    tgen = get_topogen()
    tgen.stop_topology()


def test_zebra_inactive_vrf_and_ip_import_tables():
    tgen = get_topogen()
    r1 = tgen.gears["r1"]

    thisDir = os.path.dirname(os.path.realpath(__file__))

    static_rmapfile = f"{thisDir}/r1/foo_rmap.ref"
    expected = open(static_rmapfile).read().rstrip()
    expected = ("\n".join(expected.splitlines()) + "\n").rstrip()
    logger.info(
        "Wait till route map is processed"
    )

    def check_static_map_correct_runs():
        actual = r1.vtysh_cmd("show route-map foo-map-in")
        actual = re.sub(r"\([0-9].* milli", "(X milli", actual)
        actual = ("\n".join(actual.splitlines()) + "\n").rstrip()
        return topotest.get_textdiff(
            actual,
            expected,
            title1="Actual Route-map output",
            title2="Expected Route-map output",
        )

    ok, result = topotest.run_and_expect(
        check_static_map_correct_runs, "", count=10, wait=1
    )
    assert ok, result

    # Just in case check that zebra still runs
    r1.vtysh_cmd("show zebra client")
    daemons = r1.vtysh_cmd("show daemons").split()

    assert "zebra" in daemons, "Zebra not in daemons - probably crashed"


def test_memory_leak():
    "Run the memory leak test and report results."
    tgen = get_topogen()
    if not tgen.is_memleak_enabled():
        pytest.skip("Memory leak test/report is disabled")

    tgen.report_memory_leaks()


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
