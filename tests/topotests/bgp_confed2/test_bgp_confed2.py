#!/usr/bin/env python
# SPDX-License-Identifier: ISC

# Copyright (c) 2025 by
# Donatas Abraitis <donatas@opensourcerouting.org>

import os
import sys
import json
import pytest
import functools

CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

from lib import topotest
from lib.topogen import Topogen, get_topogen

pytestmark = [pytest.mark.bgpd]


def setup_module(mod):
    topodef = {
        "s1": ("r1", "r3"),
        "s2": ("r1", "r6"),
        "s3": ("r1", "r9"),
        "s4": ("r3", "r6"),
        "s5": ("r3", "r13"),
        "s6": ("r6", "r7"),
        "s7": ("r6", "r12"),
        "s8": ("r7", "r8"),
        "s9": ("r8", "r9"),
    }
    tgen = Topogen(topodef, mod.__name__)
    tgen.start_topology()

    router_list = tgen.routers()

    for _, (rname, router) in enumerate(router_list.items(), 1):
        router.load_frr_config(os.path.join(CWD, "{}/frr.conf".format(rname)))

    tgen.start_router()


def teardown_module(mod):
    tgen = get_topogen()
    tgen.stop_topology()


def test_bgp_confed2():
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]
    r3 = tgen.gears["r3"]
    r13 = tgen.gears["r13"]

    def _bgp_path_check_confederation(router):
        output = json.loads(router.vtysh_cmd("show bgp ipv4 10.0.8.0/24 json"))
        expected = {
            "paths": [
                {
                    "aspath": {
                        "segments": [
                            {"type": "as-set", "list": [800, 900]},
                            {"type": "as-confed-set", "list": [65506, 65507]},
                        ],
                    },
                }
            ]
        }

        return topotest.json_cmp(output, expected)

    test_func = functools.partial(
        _bgp_path_check_confederation, r1
    )
    _, result = topotest.run_and_expect(test_func, None, count=30, wait=1)
    assert result is None, "10.0.8.0/24 MUST have as-set and as-confed-set on r1"

    test_func = functools.partial(
        _bgp_path_check_confederation, r3
    )
    _, result = topotest.run_and_expect(test_func, None, count=30, wait=1)
    assert result is None, "10.0.8.0/24 MUST have as-set and as-confed-set on r3"

    def _bgp_path_check_external():
        output = json.loads(r13.vtysh_cmd("show bgp ipv4 10.0.8.0/24 json"))
        expected = {
            "paths": [
                {
                    "aspath": {
                        "string": "100 {800,900}",
                    }
                }
            ]
        }

        return topotest.json_cmp(output, expected)

    test_func = functools.partial(
        _bgp_path_check_external,
    )
    _, result = topotest.run_and_expect(test_func, None, count=30, wait=1)
    assert result is None, "10.0.8.0/24 MUST NOT have as-confed-set received on r13"


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
