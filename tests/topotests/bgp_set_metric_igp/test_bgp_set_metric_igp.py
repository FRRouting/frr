#!/usr/bin/env python
# SPDX-License-Identifier: ISC

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
from lib.topogen import Topogen, get_topogen

pytestmark = [pytest.mark.bgpd]


def setup_module(mod):
    topodef = {
        "s1": ("r1", "r2"),
        "s2": ("r1", "r3"),
        "s3": ("r2", "r4"),
        "s4": ("r3", "r4"),
        "s5": ("r4", "r5"),
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


def test_bgp_set_metric_igp():
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]
    r2 = tgen.gears["r2"]

    def _bgp_converge():
        output = json.loads(r1.vtysh_cmd("show bgp ipv4 unicast json"))
        expected = {
            "routes": {
                "10.5.5.5/32": [
                    {
                        "valid": True,
                        "bestpath": True,
                        "selectionReason": "MED",
                        "metric": 20,
                        "nexthops": [
                            {
                                "ip": "10.0.0.2",
                                "hostname": "r2",
                            }
                        ],
                    },
                    {
                        "valid": True,
                        "bestpath": None,
                        "metric": 110,
                        "nexthops": [
                            {
                                "ip": "10.0.1.2",
                                "hostname": "r3",
                            }
                        ],
                    },
                ]
            }
        }
        return topotest.json_cmp(output, expected)

    test_func = functools.partial(
        _bgp_converge,
    )
    _, result = topotest.run_and_expect(test_func, None, count=120, wait=5)
    assert result is None, "10.5.5.5/32 best path is not via r2 (MED == 20)"

    r2.vtysh_cmd(
        """
configure terminal
interface r2-eth1
 isis metric level-2 6000
"""
    )

    def _bgp_converge_after_isis_metric_changes():
        output = json.loads(r1.vtysh_cmd("show bgp ipv4 unicast json"))
        expected = {
            "routes": {
                "10.5.5.5/32": [
                    {
                        "valid": True,
                        "bestpath": None,
                        "metric": 6010,
                        "nexthops": [
                            {
                                "ip": "10.0.0.2",
                                "hostname": "r2",
                            }
                        ],
                    },
                    {
                        "valid": True,
                        "bestpath": True,
                        "selectionReason": "MED",
                        "metric": 110,
                        "nexthops": [
                            {
                                "ip": "10.0.1.2",
                                "hostname": "r3",
                            }
                        ],
                    },
                ]
            }
        }
        return topotest.json_cmp(output, expected)

    test_func = functools.partial(
        _bgp_converge_after_isis_metric_changes,
    )
    _, result = topotest.run_and_expect(test_func, None, count=120, wait=5)
    assert result is None, "10.5.5.5/32 best path is not via r3 (MED == 110)"


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
