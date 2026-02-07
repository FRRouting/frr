#!/usr/bin/env python
# SPDX-License-Identifier: ISC

# Copyright (c) 2025 by
# Donatas Abraitis <donatas@opensourcerouting.org>
#

import os
import sys
import json
import pytest
import functools

pytestmark = pytest.mark.ospf6d

CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

# pylint: disable=C0413
from lib import topotest
from lib.topogen import Topogen, get_topogen


def setup_module(mod):
    topodef = {"s1": ("r1", "r2", "r3")}
    tgen = Topogen(topodef, mod.__name__)
    tgen.start_topology()

    router_list = tgen.routers()

    for _, (rname, router) in enumerate(router_list.items(), 1):
        router.load_frr_config(os.path.join(CWD, "{}/frr.conf".format(rname)))

    tgen.start_router()


def teardown_module():
    tgen = get_topogen()
    tgen.stop_topology()


def test_ospf_forwarding_address_self():
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r3 = tgen.gears["r3"]

    def _show_ospf_database_external():
        output = json.loads(r3.vtysh_cmd("show ip ospf database external json"))
        expected = {
            "asExternalLinkStates": [
                {
                    "linkStateId": "172.16.10.0",
                    "advertisingRouter": "172.16.0.1",
                    "forwardAddress": "0.0.0.0",
                },
                {
                    "linkStateId": "172.16.10.0",
                    "advertisingRouter": "172.16.0.2",
                    "forwardAddress": "0.0.0.0",
                },
            ]
        }
        return topotest.json_cmp(output, expected)

    test_func = functools.partial(
        _show_ospf_database_external,
    )
    _, result = topotest.run_and_expect(test_func, None, count=60, wait=1)
    assert result is None, "OSPF external database is not as expected"

    def _show_ip_route():
        output = json.loads(r3.vtysh_cmd("show ip route 172.16.10.0/24 json"))
        expected = {
            "172.16.10.0/24": [
                {
                    "protocol": "ospf",
                    "installed": True,
                    "internalNextHopNum": 2,
                    "internalNextHopActiveNum": 2,
                    "internalNextHopFibInstalledNum": 2,
                    "nexthops": [
                        {
                            "fib": True,
                            "ip": "172.16.0.1",
                            "interfaceName": "r3-eth0",
                        },
                        {
                            "fib": True,
                            "ip": "172.16.0.2",
                            "interfaceName": "r3-eth0",
                        },
                    ],
                }
            ]
        }
        return topotest.json_cmp(output, expected)

    test_func = functools.partial(
        _show_ip_route,
    )
    _, result = topotest.run_and_expect(test_func, None, count=60, wait=1)
    assert result is None, "172.16.10.0/24 route does not have ECMP entries"


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
