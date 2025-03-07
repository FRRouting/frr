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
from lib.topogen import Topogen, get_topogen

pytestmark = [pytest.mark.bgpd]


def build_topo(tgen):
    r1 = tgen.add_router("r1")
    r2 = tgen.add_router("r2")
    r3 = tgen.add_router("r3")
    r4 = tgen.add_router("r4")
    r5 = tgen.add_router("r5")
    r6 = tgen.add_router("r6")

    switch = tgen.add_switch("s1")
    switch.add_link(r1)
    switch.add_link(r2)
    switch.add_link(r3)
    switch.add_link(r4)
    switch.add_link(r5)

    switch = tgen.add_switch("s2")
    switch.add_link(r3)
    switch.add_link(r6)

    switch = tgen.add_switch("s3")
    switch.add_link(r4)
    switch.add_link(r5)
    switch.add_link(r6)


def setup_module(mod):
    tgen = Topogen(build_topo, mod.__name__)
    tgen.start_topology()

    for _, (rname, router) in enumerate(tgen.routers().items(), 1):
        router.load_frr_config(os.path.join(CWD, "{}/frr.conf".format(rname)))

    tgen.start_router()


def teardown_module(mod):
    tgen = get_topogen()
    tgen.stop_topology()


def test_bgp_addpath_disable_rx():
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]
    r2 = tgen.gears["r2"]
    r6 = tgen.gears["r6"]

    def _bgp_check_aspath(aspath):
        output = json.loads(r2.vtysh_cmd("show bgp ipv4 10.0.0.0/24 json"))
        expected = {
            "paths": [
                {
                    "aspath": {
                        "string": aspath,
                    },
                }
            ]
        }
        return topotest.json_cmp(output, expected)

    test_func = functools.partial(_bgp_check_aspath, "65100 65444 65444")
    _, result = topotest.run_and_expect(test_func, None, count=30, wait=1)
    assert result is None, "10.0.0.0/24 should have aspath (65100 65444 65444)"

    # Send 10.0.0.0/24 from r6 towards r2.
    # This should be the best path for r2 without any prepends.
    r6.vtysh_cmd(
        """
    configure terminal
    ip prefix-list v4_our_to65200 seq 2 permit 10.0.0.0/24
    """
    )

    test_func = functools.partial(_bgp_check_aspath, "65200 65444")
    _, result = topotest.run_and_expect(test_func, None, count=30, wait=1)
    assert result is None, "10.0.0.0/24 should have aspath (65200 65444)"

    # Drop 10.0.0.0/24 from r6 towards r2.
    # This should be removed from r2 and the old path (65100 65444 65444)
    # should be used.
    r6.vtysh_cmd(
        """
    configure terminal
    no ip prefix-list v4_our_to65200 seq 2 permit 10.0.0.0/24
    """
    )

    test_func = functools.partial(_bgp_check_aspath, "65100 65444 65444")
    _, result = topotest.run_and_expect(test_func, None, count=30, wait=1)
    assert result is None, "10.0.0.0/24 should have aspath (65100 65444 65444)"


def test_memory_leak():
    "Run the memory leak test and report results."
    tgen = get_topogen()
    if not tgen.is_memleak_enabled():
        pytest.skip("Memory leak test/report is disabled")

    tgen.report_memory_leaks()


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
