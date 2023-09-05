#!/usr/bin/env python
# SPDX-License-Identifier: ISC

# Copyright (c) 2023 by
# Donatas Abraitis <donatas@opensourcerouting.org>
#

"""
Test if BGP graceful restart capability's restart time and notification
flag are exchanged dynamically.
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
                },
                "gracefulRestartInfo": {
                    "nBit": True,
                    "timers": {
                        "receivedRestartTimer": 120,
                    },
                },
                "connectionsEstablished": 1,
                "connectionsDropped": 0,
            }
        }
        return topotest.json_cmp(output, expected)

    test_func = functools.partial(
        _bgp_converge,
    )
    _, result = topotest.run_and_expect(test_func, None, count=30, wait=1)
    assert result is None, "Can't converge"

    step("Change Graceful-Restart restart-time, and check if it's changed dynamically")

    r2.vtysh_cmd(
        """
    configure terminal
    router bgp
     bgp graceful-restart restart-time 123
    """
    )

    def _bgp_check_if_session_not_reset_after_changing_restart_time():
        output = json.loads(r1.vtysh_cmd("show bgp neighbor json"))
        expected = {
            "192.168.1.2": {
                "bgpState": "Established",
                "neighborCapabilities": {
                    "dynamic": "advertisedAndReceived",
                    "gracefulRestart": "advertisedAndReceived",
                },
                "gracefulRestartInfo": {
                    "nBit": True,
                    "timers": {
                        "receivedRestartTimer": 123,
                    },
                },
                "connectionsEstablished": 1,
                "connectionsDropped": 0,
            }
        }
        return topotest.json_cmp(output, expected)

    test_func = functools.partial(
        _bgp_check_if_session_not_reset_after_changing_restart_time,
    )
    _, result = topotest.run_and_expect(test_func, None, count=30, wait=1)
    assert (
        result is None
    ), "Session was reset after changing Graceful-Restart restart-time"

    step(
        "Disable Graceful-Restart notification support, and check if it's changed dynamically"
    )

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
                },
                "gracefulRestartInfo": {
                    "nBit": False,
                    "timers": {
                        "receivedRestartTimer": 123,
                    },
                },
                "connectionsEstablished": 1,
                "connectionsDropped": 0,
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


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
