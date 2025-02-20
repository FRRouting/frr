#!/usr/bin/env python
# SPDX-License-Identifier: ISC

# Copyright (c) 2023 by
# Donatas Abraitis <donatas@opensourcerouting.org>
#

"""
Test if ORF capability is adjusted dynamically.
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


def test_bgp_dynamic_capability_orf():
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

    step(
        "Apply incoming prefix-list to r1 and check if we advertise only 10.10.10.20/32 from r2"
    )

    # Clear message stats to check if we receive a notification or not after we
    # enable ORF capability.
    r1.vtysh_cmd("clear bgp 192.168.1.2 message-stats")
    r1.vtysh_cmd(
        """
    configure terminal
    router bgp
     address-family ipv4 unicast
      neighbor 192.168.1.2 prefix-list r2 in
      neighbor 192.168.1.2 capability orf prefix-list both
    """
    )

    r2.vtysh_cmd(
        """
    configure terminal
    router bgp
     address-family ipv4 unicast
      neighbor 192.168.1.1 capability orf prefix-list both
    """
    )

    def _bgp_check_if_session_not_reset():
        output = json.loads(r1.vtysh_cmd("show bgp neighbor json"))
        expected = {
            "192.168.1.2": {
                "bgpState": "Established",
                "neighborCapabilities": {
                    "dynamic": "advertisedAndReceived",
                },
                "messageStats": {
                    "notificationsRecv": 0,
                    "notificationsSent": 0,
                    "capabilityRecv": 1,
                    "capabilitySent": 1,
                },
                "addressFamilyInfo": {
                    "ipv4Unicast": {
                        "acceptedPrefixCounter": 1,
                        "afDependentCap": {
                            "orfPrefixList": {
                                "sendMode": "advertisedAndReceived",
                                "recvMode": "advertisedAndReceived",
                            }
                        },
                        "incomingUpdatePrefixFilterList": "r2",
                    }
                },
            }
        }
        return topotest.json_cmp(output, expected)

    test_func = functools.partial(
        _bgp_check_if_session_not_reset,
    )
    _, result = topotest.run_and_expect(test_func, None, count=30, wait=1)
    assert result is None, "Session was reset after setting up ORF capability"

    r1.vtysh_cmd(
        """
    configure terminal
    ip prefix-list r2 seq 5 permit 10.10.10.20/32
    """
    )

    def _bgp_check_if_we_send_correct_prefix():
        output = json.loads(
            r2.vtysh_cmd(
                "show bgp ipv4 unicast neighbors 192.168.1.1 advertised-routes json"
            )
        )
        expected = {
            "advertisedRoutes": {
                "10.10.10.20/32": {
                    "valid": True,
                },
            },
            "totalPrefixCounter": 1,
        }
        return topotest.json_cmp(output, expected)

    test_func = functools.partial(
        _bgp_check_if_we_send_correct_prefix,
    )
    _, result = topotest.run_and_expect(test_func, None, count=30, wait=1)
    assert (
        result is None
    ), "Only 10.10.10.20/32 SHOULD be advertised due to ORF filtering"

    # Clear message stats to check if we receive a notification or not after we
    # disable ORF capability.
    r1.vtysh_cmd("clear bgp 192.168.1.2 message-stats")
    r1.vtysh_cmd(
        """
    configure terminal
    router bgp
     address-family ipv4 unicast
      no neighbor 192.168.1.2 capability orf prefix-list both
    """
    )

    def _bgp_check_if_orf_capability_is_absent():
        output = json.loads(r1.vtysh_cmd("show bgp neighbor json"))
        expected = {
            "192.168.1.2": {
                "bgpState": "Established",
                "neighborCapabilities": {
                    "dynamic": "advertisedAndReceived",
                },
                "messageStats": {
                    "notificationsRecv": 0,
                    "notificationsSent": 0,
                },
                "addressFamilyInfo": {
                    "ipv4Unicast": {
                        "acceptedPrefixCounter": 1,
                        "afDependentCap": {
                            "orfPrefixList": {
                                "sendMode": "received",
                                "recvMode": "received",
                            }
                        },
                    }
                },
            }
        }
        return topotest.json_cmp(output, expected)

    test_func = functools.partial(
        _bgp_check_if_orf_capability_is_absent,
    )
    _, result = topotest.run_and_expect(test_func, None, count=30, wait=1)
    assert result is None, "Failed to disable ORF capability"


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
