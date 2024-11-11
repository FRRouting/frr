#!/usr/bin/env python
# SPDX-License-Identifier: ISC

#
# Copyright (c) 2024 by
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
from lib.common_config import step

pytestmark = [pytest.mark.bgpd]


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
                (TopoRouter.RD_BFD, None),
                (TopoRouter.RD_BGP, None),
            ],
        )

    tgen.start_router()


def teardown_module(mod):
    tgen = get_topogen()
    tgen.stop_topology()


def test_bgp_bfd_session():
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]

    def _bfd_session():
        output = json.loads(r1.vtysh_cmd("show bfd peers json"))
        expected = [
            {
                "multihop": True,
                "peer": "192.168.1.2",
                "local": "10.0.0.1",
                "vrf": "default",
                "minimum-ttl": 246,
                "status": "down",
                "diagnostic": "ok",
                "remote-diagnostic": "ok",
                "type": "dynamic",
            }
        ]
        return topotest.json_cmp(output, expected)

    test_func = functools.partial(_bfd_session)
    _, result = topotest.run_and_expect(test_func, None, count=30, wait=1)
    assert result is None, "Can't see BFD session created"


def test_memory_leak():
    "Run the memory leak test and report results."
    tgen = get_topogen()
    if not tgen.is_memleak_enabled():
        pytest.skip("Memory leak test/report is disabled")

    tgen.report_memory_leaks()


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
