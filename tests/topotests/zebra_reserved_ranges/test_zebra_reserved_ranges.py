#!/usr/bin/env python
# SPDX-License-Identifier: ISC

#
# Copyright (c) 2025 by
# Donatas Abraitis <donatas@opensourcerouting.org>
#

import os
import sys
import json
import pytest
import functools

CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

# pylint: disable=C0413
from lib import topotest
from lib.topogen import Topogen, get_topogen, TopoRouter

pytestmark = [pytest.mark.mgmtd]


def build_topo(tgen):
    r1 = tgen.add_router("r1")

    switch = tgen.add_switch("s1")
    switch.add_link(r1)


def setup_module(mod):
    tgen = Topogen(build_topo, mod.__name__)
    tgen.start_topology()

    for _, (rname, router) in enumerate(tgen.routers().items(), 1):
        router.load_frr_config(
            os.path.join(CWD, "{}/frr.conf".format(rname)),
            [
                (TopoRouter.RD_ZEBRA, None),
                (TopoRouter.RD_MGMTD, None),
            ],
        )

    tgen.start_router()


def teardown_module(mod):
    tgen = get_topogen()
    tgen.stop_topology()


def test_zebra_reserved_ranges():
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]

    def _check_interfaces():
        output = json.loads(r1.vtysh_cmd("show interface r1-eth0 json"))
        expected = {
            "r1-eth0": {
                "administrativeStatus": "up",
                "operationalStatus": "up",
                "ipAddresses": [
                    {
                        "address": "0.1.2.3/24",
                    },
                    {
                        "address": "127.1.2.3/24",
                    },
                    {
                        "address": "240.1.2.3/24",
                    },
                ],
            }
        }
        return topotest.json_cmp(output, expected)

    test_func = functools.partial(_check_interfaces)
    _, result = topotest.run_and_expect(test_func, None, count=20, wait=1)
    assert result is None, "Can't see reserved IP ranges assigned for r1-eth0 interface"


def test_memory_leak():
    "Run the memory leak test and report results."
    tgen = get_topogen()
    if not tgen.is_memleak_enabled():
        pytest.skip("Memory leak test/report is disabled")

    tgen.report_memory_leaks()


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
