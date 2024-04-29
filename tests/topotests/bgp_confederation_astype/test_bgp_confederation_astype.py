#!/usr/bin/env python
# SPDX-License-Identifier: ISC

# Copyright (c) 2022 by
# Donatas Abraitis <donatas@opensourcerouting.org>
#

"""
Test if BGP confederation works properly when using
remote-as internal/external.

Also, check if the same works with peer-groups as well.
"""

import os
import sys
import json
import pytest
import functools

pytestmark = [pytest.mark.bgpd]

CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

# pylint: disable=C0413
from lib import topotest
from lib.topogen import Topogen, TopoRouter, get_topogen


def setup_module(mod):
    topodef = {"s1": ("r1", "r2"), "s2": ("r1", "r3")}
    tgen = Topogen(topodef, mod.__name__)
    tgen.start_topology()

    router_list = tgen.routers()

    for i, (rname, router) in enumerate(router_list.items(), 1):
        router.load_config(
            TopoRouter.RD_ZEBRA, os.path.join(CWD, "{}/zebra.conf".format(rname))
        )
        router.load_config(
            TopoRouter.RD_BGP, os.path.join(CWD, "{}/bgpd.conf".format(rname))
        )

    tgen.start_router()


def teardown_module(mod):
    tgen = get_topogen()
    tgen.stop_topology()


def test_bgp_confederation_astype():
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]

    def _bgp_converge():
        output = json.loads(r1.vtysh_cmd("show bgp summary json"))
        expected = {
            "ipv4Unicast": {
                "peerCount": 2,
                "peers": {
                    "192.168.1.2": {
                        "hostname": "r2",
                        "remoteAs": 65002,
                        "localAs": 65001,
                        "pfxRcd": 1,
                        "state": "Established",
                    },
                    "192.168.2.2": {
                        "hostname": "r3",
                        "remoteAs": 65003,
                        "localAs": 65001,
                        "pfxRcd": 1,
                        "state": "Established",
                    },
                },
            }
        }
        return topotest.json_cmp(output, expected)

    test_func = functools.partial(_bgp_converge)
    _, result = topotest.run_and_expect(test_func, None, count=60, wait=0.5)
    assert result is None, "Can't converge"

    def _bgp_check_neighbors():
        output = json.loads(r1.vtysh_cmd("show bgp neighbors json"))
        expected = {
            "192.168.1.2": {
                "nbrCommonAdmin": True,
                "nbrConfedExternalLink": True,
                "hostname": "r2",
            },
            "192.168.2.2": {
                "nbrCommonAdmin": True,
                "nbrConfedExternalLink": True,
                "hostname": "r3",
            },
        }
        return topotest.json_cmp(output, expected)

    test_func = functools.partial(_bgp_check_neighbors)
    _, result = topotest.run_and_expect(test_func, None, count=60, wait=0.5)
    assert result is None, "Can't see neighbors to be in BGP confederation"

    def _bgp_check_routes():
        output = json.loads(r1.vtysh_cmd("show bgp ipv4 unicast json"))
        expected = {
            "routes": {
                "172.16.255.254/32": [
                    {
                        "valid": True,
                        "pathFrom": "external",
                        "path": "(65003)",
                    },
                    {
                        "valid": True,
                        "pathFrom": "external",
                        "path": "(65002)",
                    },
                ]
            }
        }
        return topotest.json_cmp(output, expected)

    test_func = functools.partial(_bgp_check_routes)
    _, result = topotest.run_and_expect(test_func, None, count=60, wait=0.5)
    assert result is None, "Can't see routes to be in BGP confederation"


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
