#!/usr/bin/env python
# SPDX-License-Identifier: ISC

# Copyright (c) 2023 by
# Donatas Abraitis <donatas@opensourcerouting.org>
#

"""
Test if BGP graceful restart / long-lived graceful restart capabilities
(restart time, stale time and notification flag) are exchanged dynamically
via BGP dynamic capability.
"""

import os
import re
import sys
import json
import pytest
import functools

pytestmark = pytest.mark.bgpd

CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

# pylint: disable=C0413
from lib import topotest
from lib.topogen import Topogen, TopoRouter, get_topogen
from lib.common_config import step

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


def test_bgp_dynamic_capability_graceful_restart():
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
                    "gracefulRestart": "advertisedAndReceived",
                    "longLivedGracefulRestart": "advertisedAndReceived",
                },
                "addressFamilyInfo": {
                    "ipv4Unicast": {
                        "acceptedPrefixCounter": 3,
                    }
                },
                "gracefulRestartInfo": {
                    "nBit": True,
                    "timers": {
                        "receivedRestartTimer": 120,
                        "configuredLlgrStaleTime": 10,
                    },
                    "ipv4Unicast": {
                        "timers": {
                            "llgrStaleTime": 10,
                        }
                    },
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
        "Change Graceful-Restart restart-time, LLGR stale-time and check if they changed dynamically"
    )

    # Clear message stats to check if we receive a notification or not after we
    # change the settings fo LLGR.
    r1.vtysh_cmd("clear bgp 192.168.1.2 message-stats")
    r2.vtysh_cmd(
        """
    configure terminal
    router bgp
     bgp graceful-restart restart-time 123
     bgp long-lived-graceful-restart stale-time 5
    """
    )

    def _bgp_check_if_session_not_reset_after_changing_gr_settings():
        output = json.loads(r1.vtysh_cmd("show bgp neighbor json"))
        expected = {
            "192.168.1.2": {
                "bgpState": "Established",
                "neighborCapabilities": {
                    "dynamic": "advertisedAndReceived",
                    "gracefulRestart": "advertisedAndReceived",
                    "longLivedGracefulRestart": "advertisedAndReceived",
                },
                "addressFamilyInfo": {
                    "ipv4Unicast": {
                        "acceptedPrefixCounter": 3,
                    }
                },
                "gracefulRestartInfo": {
                    "nBit": True,
                    "timers": {
                        "receivedRestartTimer": 123,
                        "configuredLlgrStaleTime": 10,
                    },
                    "ipv4Unicast": {
                        "timers": {
                            "llgrStaleTime": 5,
                        }
                    },
                },
                "messageStats": {
                    "notificationsRecv": 0,
                    "capabilityRecv": 2,
                },
            }
        }
        return topotest.json_cmp(output, expected)

    test_func = functools.partial(
        _bgp_check_if_session_not_reset_after_changing_gr_settings,
    )
    _, result = topotest.run_and_expect(test_func, None, count=30, wait=1)
    assert (
        result is None
    ), "Session was reset after changing Graceful-Restart restart-time"

    step(
        "Disable Graceful-Restart notification support, and check if it's changed dynamically"
    )

    # Clear message stats to check if we receive a notification or not after we
    # disable graceful-restart notification support.
    r1.vtysh_cmd("clear bgp 192.168.1.2 message-stats")
    r2.vtysh_cmd(
        """
    configure terminal
    router bgp
     no bgp graceful-restart notification
    """
    )

    def _bgp_check_if_session_not_reset_after_changing_notification():
        output = json.loads(r1.vtysh_cmd("show bgp neighbor json"))
        expected = {
            "192.168.1.2": {
                "bgpState": "Established",
                "neighborCapabilities": {
                    "dynamic": "advertisedAndReceived",
                    "gracefulRestart": "advertisedAndReceived",
                    "longLivedGracefulRestart": "advertisedAndReceived",
                },
                "gracefulRestartInfo": {
                    "nBit": False,
                    "timers": {
                        "receivedRestartTimer": 123,
                        "configuredLlgrStaleTime": 10,
                    },
                    "ipv4Unicast": {
                        "timers": {
                            "llgrStaleTime": 5,
                        }
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
        _bgp_check_if_session_not_reset_after_changing_notification,
    )
    _, result = topotest.run_and_expect(test_func, None, count=30, wait=1)
    assert (
        result is None
    ), "Session was reset after changing Graceful-Restart notification support"

    # Clear message stats to check if we receive a notification or not after we
    # disable GR.
    r1.vtysh_cmd("clear bgp 192.168.1.2 message-stats")
    r1.vtysh_cmd(
        """
    configure terminal
    router bgp
     bgp graceful-restart-disable
    """
    )

    def _bgp_check_if_gr_llgr_capability_is_absent():
        output = json.loads(r1.vtysh_cmd("show bgp neighbor json"))
        expected = {
            "192.168.1.2": {
                "bgpState": "Established",
                "neighborCapabilities": {
                    "dynamic": "advertisedAndReceived",
                    "gracefulRestartCapability": "received",
                    "longLivedGracefulRestart": "received",
                },
                "messageStats": {
                    "notificationsRecv": 0,
                },
            }
        }
        return topotest.json_cmp(output, expected)

    test_func = functools.partial(
        _bgp_check_if_gr_llgr_capability_is_absent,
    )
    _, result = topotest.run_and_expect(test_func, None, count=30, wait=1)
    assert result is None, "Failed to disable GR/LLGR capabilities"


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
