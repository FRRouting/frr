#!/usr/bin/env python
# SPDX-License-Identifier: ISC

# Copyright (c) 2024 by
# Donatas Abraitis <donatas@opensourcerouting.org>
#

"""
Test if fqdn capability is exchanged dynamically.
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


def test_bgp_dynamic_capability_fqdn():
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
                    "hostName": {
                        "advHostName": "r1",
                        "rcvHostName": "r2",
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

    step("Disable fqdn capability and check if it's exchanged dynamically")

    # Clear message stats to check if we receive a notification or not after we
    # disable fqdn capability.
    r1.vtysh_cmd("clear bgp 192.168.1.2 message-stats")
    r1.vtysh_cmd(
        """
    configure terminal
    router bgp
      no neighbor 192.168.1.2 capability fqdn
    """
    )

    def _bgp_check_if_fqdn_capability_is_absent():
        output = json.loads(r1.vtysh_cmd("show bgp neighbor json"))
        expected = {
            "192.168.1.2": {
                "bgpState": "Established",
                "neighborCapabilities": {
                    "dynamic": "advertisedAndReceived",
                    "hostName": {
                        "advHostName": None,
                        "rcvHostName": "r2",
                    },
                },
                "messageStats": {
                    "notificationsRecv": 0,
                },
            }
        }
        return topotest.json_cmp(output, expected)

    test_func = functools.partial(
        _bgp_check_if_fqdn_capability_is_absent,
    )
    _, result = topotest.run_and_expect(test_func, None, count=30, wait=1)
    assert result is None, "Failed to disable fqdn capability"


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
