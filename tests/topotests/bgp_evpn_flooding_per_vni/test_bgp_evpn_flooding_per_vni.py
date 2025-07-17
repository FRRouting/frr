#!/usr/bin/env python
# SPDX-License-Identifier: ISC

# Copyright (c) 2025 by
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


def test_bgp_evpn_flooding_per_vni():
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]
    r2 = tgen.gears["r2"]

    r1.run(f"/bin/bash {CWD}/r1/setup.sh")
    r2.run(f"/bin/bash {CWD}/r2/setup.sh")

    def _bgp_converge():
        output = json.loads(r1.vtysh_cmd("show bgp l2vpn evpn json"))
        expected = {
            "192.168.1.1:3": {
                "rd": "192.168.1.1:3",
                "[3]:[0]:[32]:[192.168.1.1]": {
                    "paths": [
                        {
                            "valid": True,
                            "routeType": 3,
                            "extendedCommunity": {"string": "ET:8 RT:65001:20"},
                            "nexthops": [
                                {
                                    "ip": "192.168.1.1",
                                    "hostname": "r1",
                                    "afi": "ipv4",
                                }
                            ],
                        }
                    ]
                },
            },
            "192.168.1.2:2": {
                "rd": "192.168.1.2:2",
                "[3]:[0]:[32]:[192.168.1.2]": {
                    "paths": [
                        {
                            "valid": True,
                            "routeType": 3,
                            "extendedCommunity": {"string": "RT:65002:10 ET:8"},
                            "nexthops": [
                                {
                                    "ip": "192.168.1.2",
                                    "hostname": "r2",
                                    "afi": "ipv4",
                                }
                            ],
                        }
                    ]
                },
            },
            "192.168.1.2:3": {
                "rd": "192.168.1.2:3",
                "[3]:[0]:[32]:[192.168.1.2]": {
                    "paths": [
                        {
                            "valid": True,
                            "routeType": 3,
                            "extendedCommunity": {"string": "RT:65002:20 ET:8"},
                            "nexthops": [
                                {
                                    "ip": "192.168.1.2",
                                    "hostname": "r2",
                                    "afi": "ipv4",
                                }
                            ],
                        }
                    ]
                },
            },
            "192.168.1.2:4": {
                "rd": "192.168.1.2:4",
                "[3]:[0]:[32]:[192.168.1.2]": {
                    "paths": [
                        {
                            "valid": True,
                            "routeType": 3,
                            "extendedCommunity": {"string": "RT:65002:30 ET:8"},
                            "nexthops": [
                                {
                                    "ip": "192.168.1.2",
                                    "hostname": "r2",
                                    "afi": "ipv4",
                                }
                            ],
                        }
                    ]
                },
            },
            "numPrefix": 4,
            "totalPrefix": 4,
        }

        return topotest.json_cmp(output, expected)

    test_func = functools.partial(
        _bgp_converge,
    )
    _, result = topotest.run_and_expect(test_func, None, count=60, wait=2)
    assert result is None, "Can't see expected EVPN prefix"

    def check_flood_entry():
        if not topotest.iproute2_is_fdb_get_capable():
            return None

        output = int(r2.run("bridge fdb show | grep dst -c"))

        if output == 1:
            return None

        return f"Found more than one FDB entry: {output}"

    test_func = functools.partial(check_flood_entry)
    _, result = topotest.run_and_expect(test_func, None, count=60, wait=2)
    assert result is None, result


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
