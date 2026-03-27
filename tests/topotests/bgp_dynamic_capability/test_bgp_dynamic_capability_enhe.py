#!/usr/bin/env python
# SPDX-License-Identifier: ISC

# Copyright (c) 2024 by
# Donatas Abraitis <donatas@opensourcerouting.org>
#

"""
Test if extended nexthop capability is exchanged dynamically.
"""

import os
import sys
import json
import pytest
import functools
import time

pytestmark = [pytest.mark.bgpd]

CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

# pylint: disable=C0413
from lib import topotest
from lib.topogen import Topogen, get_topogen
from lib.common_config import step


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


def test_bgp_dynamic_capability_enhe():
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]
    r2 = tgen.gears["r2"]

    def _bgp_converge():
        output = json.loads(r1.vtysh_cmd("show bgp neighbor 2001:db8::2 json"))
        expected = {
            "2001:db8::2": {
                "bgpState": "Established",
                "localRole": "undefined",
                "remoteRole": "undefined",
                "neighborCapabilities": {
                    "dynamic": "advertisedAndReceived",
                    "extendedNexthop": "received",
                },
            }
        }
        return topotest.json_cmp(output, expected)

    test_func = functools.partial(
        _bgp_converge,
    )
    _, result = topotest.run_and_expect(test_func, None, count=30, wait=1)
    assert result is None, "Can't converge"

    def _bgp_check_nexthop():
        output = json.loads(r1.vtysh_cmd("show ip route 10.10.10.10/32 json"))
        expected = {
            "10.10.10.10/32": [
                {
                    "protocol": "bgp",
                    "selected": True,
                    "nexthops": [
                        {
                            "ip": "192.168.1.2",
                            "afi": "ipv4",
                            "interfaceName": "r1-eth0",
                            "active": True,
                        },
                        {
                            "duplicate": True,
                            "ip": "192.168.1.2",
                            "afi": "ipv4",
                            "interfaceName": "r1-eth0",
                            "active": True,
                        },
                    ],
                }
            ]
        }
        return topotest.json_cmp(output, expected)

    test_func = functools.partial(
        _bgp_check_nexthop,
    )
    _, result = topotest.run_and_expect(test_func, None, count=30, wait=1)
    assert result is None, "Can't see 10.10.10.10/32 with IPv4 only nexthops"

    step("Enable ENHE capability")

    # Clear message stats to check if we receive a notification or not after we
    # change the role.
    r2.vtysh_cmd("clear bgp 2001:db8::1 message-stats")
    r1.vtysh_cmd(
        """
    configure terminal
    router bgp
      neighbor 2001:db8::2 capability extended-nexthop
    """
    )

    def _bgp_check_if_session_not_reset():
        output = json.loads(r2.vtysh_cmd("show bgp neighbor 2001:db8::1 json"))
        expected = {
            "2001:db8::1": {
                "bgpState": "Established",
                "neighborCapabilities": {
                    "dynamic": "advertisedAndReceived",
                    "extendedNexthop": "advertisedAndReceived",
                    "extendedNexthopFamililesByPeer": {
                        "ipv4Unicast": "recieved",
                    },
                },
                "messageStats": {
                    "notificationsRecv": 0,
                    "capabilityRecv": 1,
                },
            }
        }
        return topotest.json_cmp(output, expected)

    test_func = functools.partial(
        _bgp_check_if_session_not_reset,
    )
    _, result = topotest.run_and_expect(test_func, None, count=30, wait=1)
    assert result is None, "Session was reset after setting ENHE capability"

    def _bgp_check_nexthop_enhe():
        output = json.loads(r1.vtysh_cmd("show ip route 10.10.10.10/32 json"))
        expected = {
            "10.10.10.10/32": [
                {
                    "protocol": "bgp",
                    "selected": True,
                    "installed": True,
                    "nexthops": [
                        {
                            "fib": True,
                            "ip": "192.168.1.2",
                            "afi": "ipv4",
                            "interfaceName": "r1-eth0",
                            "active": True,
                        },
                        {
                            "fib": True,
                            "afi": "ipv6",
                            "interfaceName": "r1-eth0",
                            "active": True,
                        },
                    ],
                }
            ]
        }
        return topotest.json_cmp(output, expected)

    test_func = functools.partial(
        _bgp_check_nexthop_enhe,
    )
    _, result = topotest.run_and_expect(test_func, None, count=30, wait=1)
    assert result is None, "Can't see 10.10.10.10/32 with IPv4 only nexthops"


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
