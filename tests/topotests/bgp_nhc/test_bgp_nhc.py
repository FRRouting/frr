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
        "s1": ("r1", "r2"),
        "s2": ("r2", "r3", "r4", "r5"),
        "s3": ("r1", "r6"),
        "s4": ("r6", "r7"),
        "s5": ("r6", "r8"),
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


def test_bgp_r6_peers():
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r6 = tgen.gears["r6"]

    def _bgp_r6_peers_check():
        output = json.loads(r6.vtysh_cmd("show bgp ipv4 uni summ json"))
        expected = {
            "peers": {
                "10.255.16.1": {
                    "state": "Idle (Admin)",
                    "peerState": "Admin",
                },
                "10.255.67.7": {
                    "hostname": "r7",
                    "remoteAs": 65007,
                    "state": "Established",
                    "peerState": "OK",
                },
                "10.255.68.8": {
                    "hostname": "r8",
                    "remoteAs": 65008,
                    "state": "Established",
                    "peerState": "OK",
                },
            },
            "totalPeers": 3,
        }
        return topotest.json_cmp(output, expected)

    test_func = functools.partial(_bgp_r6_peers_check)
    _, result = topotest.run_and_expect(test_func, None, count=30, wait=1)
    assert result is None, "r6 does not have expected peer states (r7/r8 Established, r1 Idle)"

    r6.vtysh_cmd(
        """
        configure terminal
        router bgp 65006
        no neighbor 10.255.16.1 shutdown
        """
    )

    def _bgp_r6_r1_established():
        output = json.loads(r6.vtysh_cmd("show bgp ipv4 uni summ json"))
        expected = {
            "peers": {
                "10.255.16.1": {
                    "hostname": "r1",
                    "remoteAs": 65001,
                    "state": "Established",
                    "peerState": "OK",
                },
            },
        }
        return topotest.json_cmp(output, expected)

    test_func = functools.partial(_bgp_r6_r1_established)
    _, result = topotest.run_and_expect(test_func, None, count=30, wait=1)
    assert result is None, "r1 did not reach Established state on r6"


def test_bgp_nhc():
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]

    def _bgp_converge():
        output = json.loads(r1.vtysh_cmd("show bgp ipv4 json detail"))
        expected = {
            "routes": {
                "10.0.0.1/32": {
                    "pathCount": 2,
                    "paths": [
                        {
                            "nextNextHopNodes": [
                                "10.255.0.3",
                                "10.255.0.4",
                                "10.255.0.5",
                            ],
                        },
                        {
                            "nextNextHopNodes": ["10.255.0.7", "10.255.0.8"],
                        },
                    ],
                },
                "10.0.0.2/32": {
                    "pathCount": 1,
                    "paths": [
                        {
                            "bgpId": "10.255.0.2",
                        }
                    ],
                },
                "10.0.0.3/32": {
                    "pathCount": 1,
                    "paths": [
                        {
                            "bgpId": "10.255.0.3",
                        }
                    ],
                },
            },
            "totalRoutes": 3,
            "totalPaths": 4,
        }

        return topotest.json_cmp(output, expected)

    test_func = functools.partial(
        _bgp_converge,
    )
    _, result = topotest.run_and_expect(test_func, None, count=30, wait=1)
    assert result is None, "Can't see NHC attributes as expected"

    def check_weighted_ecmp_with_nnhn():
        output = json.loads(r1.vtysh_cmd("show ip route 10.0.0.1/32 json"))
        expected = {
            "10.0.0.1/32": [
                {
                    "nexthops": [
                        {"ip": "10.255.16.6", "weight": 170},
                        {"ip": "10.255.0.2", "weight": 255},
                    ]
                }
            ]
        }

        return topotest.json_cmp(output, expected)

    test_func = functools.partial(
        check_weighted_ecmp_with_nnhn,
    )
    _, result = topotest.run_and_expect(test_func, None, count=30, wait=1)
    assert result is None, "Can't see weighted ECMP with NNHN as expected"


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
