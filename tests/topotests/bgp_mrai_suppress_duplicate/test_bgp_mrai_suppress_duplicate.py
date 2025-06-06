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


def test_bgp_mrai_suppress_duplicate():
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]
    r2 = tgen.gears["r2"]

    def _bgp_converge():
        output = json.loads(r1.vtysh_cmd("show bgp ipv4 unicast summary json"))
        expected = {
            "peers": {
                "192.168.1.2": {
                    "remoteAs": 65002,
                    "state": "Established",
                    "peerState": "OK",
                },
            },
            "totalPeers": 1,
        }

        return topotest.json_cmp(output, expected)

    test_func = functools.partial(
        _bgp_converge,
    )
    _, result = topotest.run_and_expect(test_func, None, count=30, wait=1)
    assert result is None, "Can't converge initial state"

    # Trigger "route flag" (flap) during MRAI timer
    r1.cmd(
        """
# Add first route, should trigger BGP UPDATE advertisement.
ip route add 10.1.0.0/16 dev r1-eth0
sleep 1
# Add second route, but no BGP UPDATE message yet, because MRAI timer.
ip route add 10.2.0.0/16 dev r1-eth0
sleep 0.25
# Emulate 10.1.0.0/16 flap (del/add), where 10.1.0.0/16 will be
# eventually withdrawn and advertised again. But the advertisement
# is suppressed as a duplicate. This should happen within the MRAI timer.
ip route del 10.1.0.0/16 dev r1-eth0
sleep 0.25
ip route add 10.1.0.0/16 dev r1-eth0
"""
    )

    def _bgp_check_received_routes():
        output = json.loads(r2.vtysh_cmd("show bgp ipv4 unicast json"))
        expected = {
            "routes": {
                "10.1.0.0/16": [
                    {
                        "valid": True,
                    }
                ],
                "10.2.0.0/16": [
                    {
                        "valid": True,
                    }
                ],
            }
        }

        return topotest.json_cmp(output, expected)

    test_func = functools.partial(
        _bgp_check_received_routes,
    )
    _, result = topotest.run_and_expect(test_func, None, count=30, wait=1)
    assert result is None, "Can't see 10.1.0.0/16 and 10.2.0.0/16 received"


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
