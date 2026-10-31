#!/usr/bin/env python
# SPDX-License-Identifier: ISC

# Copyright (c) 2026 by
# Donatas Abraitis <donatas@opensourcerouting.org>
#

"""
Test if activating/deactivating an address family is done without
resetting the BGP session when Dynamic Capability is negotiated.
T1: Deactivate IPv4 unicast, check that routes are withdrawn and the session stays up
T2: Activate IPv4 unicast, check that routes are back and the session stays up
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


def setup_module(mod):
    topodef = {"s1": ("r1", "r2")}
    tgen = Topogen(topodef, mod.__name__)
    tgen.start_topology()

    router_list = tgen.routers()

    for router in router_list.values():
        router.load_frr_config()

    tgen.start_router()


def teardown_module(mod):
    tgen = get_topogen()
    tgen.stop_topology()


def test_bgp_dynamic_capability_mp():
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]
    r2 = tgen.gears["r2"]
    r1_peer = "2001:db8::2"
    r2_peer = "2001:db8::1"
    r1_prefix = "10.0.0.1/32"

    r1.vtysh_cmd(
        """
    configure terminal
     router bgp
      no bgp network import-check
      address-family ipv4 unicast
       network {}
    """.format(
            r1_prefix
        )
    )

    def _neighbor(router, peer):
        return json.loads(router.vtysh_cmd("show bgp neighbor {} json".format(peer)))[
            peer
        ]

    def _has_ipv4_paths_from(router, peer):
        output = json.loads(router.vtysh_cmd("show bgp ipv4 unicast json"))
        for paths in output.get("routes", {}).values():
            for path in paths:
                if path.get("peerId") == peer:
                    return True
        return False

    def _converge():
        output = json.loads(r1.vtysh_cmd("show bgp neighbor {} json".format(r1_peer)))
        expected = {
            r1_peer: {
                "bgpState": "Established",
                "neighborCapabilities": {
                    "dynamic": "advertisedAndReceived",
                    "multiprotocolExtensions": {
                        "ipv4Unicast": {
                            "advertisedAndReceived": True,
                        },
                        "ipv6Unicast": {
                            "advertisedAndReceived": True,
                        },
                    },
                },
            }
        }
        if topotest.json_cmp(output, expected) is not None:
            return "Not converged"

        afi = output[r1_peer].get("addressFamilyInfo", {})
        for af in ["ipv4Unicast", "ipv6Unicast"]:
            if afi.get(af, {}).get("acceptedPrefixCounter", 0) == 0:
                return "No {} prefixes received by r1".format(af)

        if not _has_ipv4_paths_from(r2, r2_peer):
            return "No IPv4 unicast prefixes received by r2"

        return None

    test_func = functools.partial(_converge)
    _, result = topotest.run_and_expect(test_func, None, count=30, wait=1)
    assert result is None, "Can't converge: {}".format(result)

    neigh = _neighbor(r1, r1_peer)
    established = neigh["connectionsEstablished"]
    dropped = neigh["connectionsDropped"]
    r1.vtysh_cmd("clear bgp {} message-stats".format(r1_peer))

    def _check_session_not_reset(capability_sent):
        neigh = _neighbor(r1, r1_peer)
        if neigh["bgpState"] != "Established":
            return "Session is not Established"
        if neigh["connectionsEstablished"] != established:
            return "Session was re-established"
        if neigh["connectionsDropped"] != dropped:
            return "Session was dropped"

        stats = neigh["messageStats"]
        if stats["notificationsSent"] != 0 or stats["notificationsRecv"] != 0:
            return "NOTIFICATION message was exchanged"
        if stats["capabilitySent"] != capability_sent:
            return "CAPABILITY message was not sent"

        return None

    ###
    # T1: Deactivate IPv4 unicast
    ###
    r1.vtysh_cmd(
        """
    configure terminal
     router bgp
      address-family ipv4 unicast
       no neighbor {} activate
    """.format(
            r1_peer
        )
    )

    def _ipv4_deactivated():
        output = json.loads(r1.vtysh_cmd("show bgp neighbor {} json".format(r1_peer)))
        expected = {
            r1_peer: {
                "neighborCapabilities": {
                    "multiprotocolExtensions": {
                        "ipv4Unicast": {
                            "advertisedAndReceived": None,
                            "received": True,
                        },
                        "ipv6Unicast": {
                            "advertisedAndReceived": True,
                        },
                    },
                },
                "addressFamilyInfo": {
                    "ipv4Unicast": None,
                },
            }
        }
        if topotest.json_cmp(output, expected) is not None:
            return "IPv4 unicast is still active"

        if _has_ipv4_paths_from(r1, r1_peer):
            return "IPv4 unicast routes are not withdrawn at r1"

        if _has_ipv4_paths_from(r2, r2_peer):
            return "IPv4 unicast routes are not withdrawn at r2"

        return _check_session_not_reset(1)

    test_func = functools.partial(_ipv4_deactivated)
    _, result = topotest.run_and_expect(test_func, None, count=30, wait=1)
    assert result is None, "Failed deactivating IPv4 unicast: {}".format(result)

    ###
    # T2: Activate IPv4 unicast
    ###
    r1.vtysh_cmd(
        """
    configure terminal
     router bgp
      address-family ipv4 unicast
       neighbor {} activate
    """.format(
            r1_peer
        )
    )

    def _ipv4_activated():
        output = json.loads(r1.vtysh_cmd("show bgp neighbor {} json".format(r1_peer)))
        expected = {
            r1_peer: {
                "neighborCapabilities": {
                    "multiprotocolExtensions": {
                        "ipv4Unicast": {
                            "advertisedAndReceived": True,
                        },
                        "ipv6Unicast": {
                            "advertisedAndReceived": True,
                        },
                    },
                },
            }
        }
        if topotest.json_cmp(output, expected) is not None:
            return "IPv4 unicast is not active"

        if not _has_ipv4_paths_from(r1, r1_peer):
            return "No IPv4 unicast prefixes received by r1"

        if not _has_ipv4_paths_from(r2, r2_peer):
            return "No IPv4 unicast prefixes received by r2"

        return _check_session_not_reset(2)

    test_func = functools.partial(_ipv4_activated)
    _, result = topotest.run_and_expect(test_func, None, count=30, wait=1)
    assert result is None, "Failed activating IPv4 unicast: {}".format(result)


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
