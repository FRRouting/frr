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

CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

# pylint: disable=C0413
from lib import topotest
from lib.topogen import Topogen, get_topogen

pytestmark = [pytest.mark.bgpd]


def setup_module(mod):
    topodef = {"s1": ("r1", "r2", "r3"), "s2": ("r1", "r4")}
    tgen = Topogen(topodef, mod.__name__)
    tgen.start_topology()

    router_list = tgen.routers()

    for _, (rname, router) in enumerate(router_list.items(), 1):
        router.load_frr_config(os.path.join(CWD, "{}/frr.conf".format(rname)))

    tgen.start_router()


def teardown_module(mod):
    tgen = get_topogen()
    tgen.stop_topology()


def test_bgp_remote_as_auto():
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]
    r2 = tgen.gears["r2"]
    r3 = tgen.gears["r3"]
    r4 = tgen.gears["r4"]

    def _bgp_converge():
        output = json.loads(r1.vtysh_cmd("show bgp ipv4 unicast summary json"))
        expected = {
            "peers": {
                "r1-eth1": {
                    "hostname": "r4",
                    "remoteAs": 65004,
                    "localAs": 65001,
                    "state": "Established",
                },
                "192.168.1.2": {
                    "hostname": "r2",
                    "remoteAs": 65001,
                    "localAs": 65001,
                    "state": "Established",
                },
                "192.168.1.3": {
                    "hostname": "r3",
                    "remoteAs": 65003,
                    "localAs": 65001,
                    "state": "Established",
                },
            }
        }
        return topotest.json_cmp(output, expected)

    test_func = functools.partial(
        _bgp_converge,
    )
    _, result = topotest.run_and_expect(test_func, None, count=30, wait=1)
    assert result is None, "Can't see automatic iBGP/eBGP peerings"

    def _bgp_converge_internal():
        output = json.loads(r2.vtysh_cmd("show bgp ipv4 unicast 10.0.0.1/32 json"))
        expected = {
            "paths": [
                {
                    "aspath": {
                        "string": "Local",
                    },
                    "valid": True,
                    "peer": {
                        "hostname": "r1",
                        "type": "internal",
                    },
                }
            ]
        }
        return topotest.json_cmp(output, expected)

    test_func = functools.partial(
        _bgp_converge_internal,
    )
    _, result = topotest.run_and_expect(test_func, None, count=30, wait=1)
    assert result is None, "Can't see automatic iBGP peering"

    def _bgp_converge_external():
        output = json.loads(r3.vtysh_cmd("show bgp ipv4 unicast 10.0.0.1/32 json"))
        expected = {
            "paths": [
                {
                    "aspath": {
                        "string": "65001",
                    },
                    "valid": True,
                    "peer": {
                        "hostname": "r1",
                        "type": "external",
                    },
                }
            ]
        }
        return topotest.json_cmp(output, expected)

    test_func = functools.partial(
        _bgp_converge_external,
    )
    _, result = topotest.run_and_expect(test_func, None, count=30, wait=1)
    assert result is None, "Can't see automatic eBGP peering"

    def _bgp_converge_external_unnumbered():
        output = json.loads(r4.vtysh_cmd("show bgp ipv4 unicast 10.0.0.1/32 json"))
        expected = {
            "paths": [
                {
                    "aspath": {
                        "string": "65001",
                    },
                    "valid": True,
                    "peer": {
                        "hostname": "r1",
                        "type": "external",
                    },
                }
            ]
        }
        return topotest.json_cmp(output, expected)

    test_func = functools.partial(
        _bgp_converge_external_unnumbered,
    )
    _, result = topotest.run_and_expect(test_func, None, count=30, wait=1)
    assert result is None, "Can't see automatic unnumbered eBGP peering"


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
