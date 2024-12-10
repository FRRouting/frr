#!/usr/bin/env python
# SPDX-License-Identifier: ISC

# Copyright (c) 2023 by
# Donatas Abraitis <donatas@opensourcerouting.org>
#

"""
Test if role capability is exchanged dynamically.
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


def test_bgp_dynamic_capability_role():
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]
    r2 = tgen.gears["r2"]

    def _bgp_converge():
        output = json.loads(r1.vtysh_cmd("show bgp neighbor json"))
        expected = {
            "192.168.1.2": {
                "bgpState": "Established",
                "localRole": "undefined",
                "remoteRole": "undefined",
                "neighborCapabilities": {
                    "dynamic": "advertisedAndReceived",
                },
                "addressFamilyInfo": {
                    "ipv4Unicast": {
                        "acceptedPrefixCounter": 3,
                    }
                },
            }
        }
        return topotest.json_cmp(output, expected)

    test_func = functools.partial(
        _bgp_converge,
    )
    _, result = topotest.run_and_expect(test_func, None, count=30, wait=1)
    assert result is None, "Can't converge"

    step("Set local-role and check if it's exchanged dynamically")

    # Clear message stats to check if we receive a notification or not after we
    # change the role.
    r1.vtysh_cmd("clear bgp 192.168.1.2 message-stats")
    r1.vtysh_cmd(
        """
    configure terminal
    router bgp
      neighbor 192.168.1.2 local-role customer
    """
    )

    r2.vtysh_cmd(
        """
    configure terminal
    router bgp
      neighbor 192.168.1.1 local-role provider
    """
    )

    def _bgp_check_if_session_not_reset():
        output = json.loads(r1.vtysh_cmd("show bgp neighbor json"))
        expected = {
            "192.168.1.2": {
                "bgpState": "Established",
                "localRole": "customer",
                "remoteRole": "provider",
                "neighborCapabilities": {
                    "dynamic": "advertisedAndReceived",
                    "role": "advertisedAndReceived",
                },
                "addressFamilyInfo": {
                    "ipv4Unicast": {
                        "acceptedPrefixCounter": 3,
                    }
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
    assert result is None, "Session was reset after setting role capability"

    # Clear message stats to check if we receive a notification or not after we
    # change the role.
    r1.vtysh_cmd("clear bgp 192.168.1.2 message-stats")
    r1.vtysh_cmd(
        """
    configure terminal
    router bgp
      no neighbor 192.168.1.2 local-role customer
    """
    )

    def _bgp_check_if_role_capability_is_absent():
        output = json.loads(r1.vtysh_cmd("show bgp neighbor json"))
        expected = {
            "192.168.1.2": {
                "bgpState": "Established",
                "localRole": "undefined",
                "remoteRole": "provider",
                "neighborCapabilities": {
                    "dynamic": "advertisedAndReceived",
                    "role": "received",
                },
                "messageStats": {
                    "notificationsRecv": 0,
                },
            }
        }
        return topotest.json_cmp(output, expected)

    test_func = functools.partial(
        _bgp_check_if_role_capability_is_absent,
    )
    _, result = topotest.run_and_expect(test_func, None, count=30, wait=1)
    assert result is None, "Failed to disable role capability"


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
