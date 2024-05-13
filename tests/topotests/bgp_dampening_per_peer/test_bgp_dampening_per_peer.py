#!/usr/bin/env python
# SPDX-License-Identifier: ISC

# Copyright (c) 2024 by
# Donatas Abraitis <donatas@opensourcerouting.org>
#

import os
import re
import sys
import json
import pytest
import functools

pytestmark = [pytest.mark.bgpd]

CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

# pylint: disable=C0413
from lib import topotest
from lib.topogen import Topogen, get_topogen


def setup_module(mod):
    topodef = {"s1": ("r1", "r2")}
    tgen = Topogen(topodef, mod.__name__)
    tgen.start_topology()

    router_list = tgen.routers()

    for _, (rname, router) in enumerate(router_list.items(), 1):
        router.load_frr_config(os.path.join(CWD, "{}/frr.conf".format(rname)))

    tgen.start_router()


def teardown_module(mod):
    tgen = get_topogen()
    tgen.stop_topology()


def test_bgp_dampening_per_peer():
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]
    r2 = tgen.gears["r2"]

    def _converge():
        output = json.loads(r1.vtysh_cmd("show bgp ipv4 unicast 10.10.10.10/32 json"))
        expected = {
            "paths": [
                {
                    "valid": True,
                    "nexthops": [
                        {
                            "hostname": "r2",
                            "accessible": True,
                        }
                    ],
                }
            ]
        }
        return topotest.json_cmp(output, expected)

    test_func = functools.partial(
        _converge,
    )
    _, result = topotest.run_and_expect(test_func, None, count=30, wait=1)
    assert result is None, "Can't converge"

    ####
    # Withdraw 10.10.10.10/32, and check if it's flagged as history.
    ####
    r2.vtysh_cmd(
        """
    configure terminal
     router bgp
      address-family ipv4 unicast
       no redistribute connected
    """
    )

    def _check_bgp_dampening_history():
        output = json.loads(r1.vtysh_cmd("show bgp ipv4 unicast 10.10.10.10/32 json"))
        expected = {
            "paths": [
                {
                    "dampeningHistoryEntry": True,
                    "nexthops": [
                        {
                            "hostname": "r2",
                            "accessible": True,
                        }
                    ],
                }
            ],
        }
        return topotest.json_cmp(output, expected)

    test_func = functools.partial(
        _check_bgp_dampening_history,
    )
    _, result = topotest.run_and_expect(test_func, None, count=30, wait=1)
    assert result is None, "10.10.10.10/32 is not flagged as history entry"

    ####
    # Reannounce 10.10.10.10/32, and check if it's flagged as dampened.
    ####
    r2.vtysh_cmd(
        """
    configure terminal
     router bgp
      address-family ipv4 unicast
       redistribute connected
    """
    )

    def _check_bgp_dampening_dampened():
        output = json.loads(r1.vtysh_cmd("show bgp ipv4 unicast 10.10.10.10/32 json"))
        expected = {
            "paths": [
                {
                    "valid": True,
                    "dampeningSuppressed": True,
                    "nexthops": [
                        {
                            "hostname": "r2",
                            "accessible": True,
                        }
                    ],
                }
            ],
        }
        return topotest.json_cmp(output, expected)

    test_func = functools.partial(
        _check_bgp_dampening_dampened,
    )
    _, result = topotest.run_and_expect(test_func, None, count=30, wait=1)
    assert result is None, "10.10.10.10/32 is not flagged as dampened entry"

    ####
    # Check if the route becomes non-dampened again after some time.
    ####
    def _check_bgp_dampening_undampened():
        output = json.loads(r1.vtysh_cmd("show bgp ipv4 unicast 10.10.10.10/32 json"))
        expected = {
            "paths": [
                {
                    "valid": True,
                    "dampeningHistoryEntry": None,
                    "dampeningSuppressed": None,
                    "nexthops": [
                        {
                            "hostname": "r2",
                            "accessible": True,
                        }
                    ],
                }
            ],
        }
        return topotest.json_cmp(output, expected)

    test_func = functools.partial(
        _check_bgp_dampening_undampened,
    )
    _, result = topotest.run_and_expect(test_func, None, count=120, wait=10)
    assert result is None, "10.10.10.10/32 is flagged as history/dampened"


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
