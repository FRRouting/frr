#!/usr/bin/env python
# SPDX-License-Identifier: ISC
#
# test_zebra_nhg_max_backups.py
#
# Copyright (c) 2026 by Andrei-Alexandru Bleortu
#

"""
A route whose nexthop carries exactly NEXTHOP_MAX_BACKUPS backup indices is
accepted by zebra with all of its backups, the Linux kernel FIB holds it through
its primary nexthop, and zebra keeps running.

zapi validation admits up to NEXTHOP_MAX_BACKUPS backups per nexthop, so a
nexthop using all of them must also survive every copy zebra makes of it.
isisd sends such a nexthop when a prefix has eight equal-cost LFAs.
"""

import os
import sys
import json
from functools import partial
import pytest

CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

# pylint: disable=C0413
from lib import topotest
from lib.topogen import Topogen, get_topogen

pytestmark = [pytest.mark.sharpd]


def build_topo(tgen):
    tgen.add_router("r1")
    tgen.add_router("r2")
    switch = tgen.add_switch("s1")
    switch.add_link(tgen.gears["r1"])
    switch.add_link(tgen.gears["r2"])


def setup_module(mod):
    tgen = Topogen(build_topo, mod.__name__)
    tgen.start_topology()

    for rname, router in tgen.routers().items():
        router.load_frr_config(
            os.path.join(CWD, "{}/frr.conf".format(rname)), extra_daemons=["sharpd"]
        )

    tgen.start_router()


def teardown_module(_mod):
    tgen = get_topogen()
    tgen.stop_topology()


def _kernel_route(router):
    "The route in the Linux kernel FIB, through its primary nexthop."
    routes = json.loads(router.cmd("ip -j route show 10.0.0.1/32"))
    return topotest.json_cmp(routes, [{"dst": "10.0.0.1", "gateway": "192.168.1.2"}])


def test_route_with_max_backups():
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]
    r1.vtysh_cmd("sharp install routes 10.0.0.1 nexthop-group primary 1")

    expected = {
        "10.0.0.1/32": [
            {
                "protocol": "sharp",
                "installed": True,
                "nexthops": [{"ip": "192.168.1.2", "backupIndex": list(range(8))}],
                "backupNexthops": [
                    {"ip": "192.168.1.{}".format(host)} for host in range(11, 19)
                ],
            }
        ]
    }
    test_func = partial(
        topotest.router_json_cmp, r1, "show ip route 10.0.0.1/32 json", expected
    )
    _, result = topotest.run_and_expect(test_func, None, count=30, wait=1)
    assert result is None, "route with eight backup nexthops not installed"

    test_func = partial(_kernel_route, r1)
    _, result = topotest.run_and_expect(test_func, None, count=30, wait=1)
    assert result is None, "route not in the kernel through its primary nexthop"

    assert not tgen.routers_have_failure(), "zebra did not survive the route"


def test_memory_leak():
    "Run the memory leak test and report results."
    tgen = get_topogen()
    if not tgen.is_memleak_enabled():
        pytest.skip("Memory leak test/report is disabled")

    tgen.report_memory_leaks()


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
