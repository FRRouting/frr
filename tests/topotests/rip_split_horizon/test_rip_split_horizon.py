#!/usr/bin/env python
# -*- coding: utf-8 eval: (blacken-mode 1) -*-
# SPDX-License-Identifier: ISC
#
# test_rip_split_horizon.py:
# RIP Split Horizon Test
#
# Copyright (c) 2025 by Dustin Rosarius
#

r"""
test_rip_split_horizon.py: Test to verify that split-horizon and poisoned-reversed works correctly.
"""

import os
import sys
import pytest
import json
import functools

# Import topogen and required test moduless
CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

from lib import topotest
from lib.topogen import Topogen, TopoRouter
from lib.common_config import step

pytestmark = [
    pytest.mark.ripd,
]


@pytest.fixture(scope="module")
def tgen(request):
    "Setup/Teardown the environment and provide tgen argument to tests"

    topodef = {"s1": ("r1", "r2", "r3")}

    tgen = Topogen(topodef, request.module.__name__)
    tgen.start_topology()

    router_list = tgen.routers()

    # For all routers arrange for:
    # - starting zebra using config file from <rtrname>/zebra.conf
    # - starting ripd using an empty config file.
    # - loading frr config file from <rtrname>/frr.conf
    for rname, router in router_list.items():
        router.load_config(TopoRouter.RD_ZEBRA)
        router.load_config(TopoRouter.RD_RIP)
        router.load_frr_config(os.path.join(CWD, f"{rname}/frr.conf"))

    # Start and configure the router daemons
    tgen.start_router()

    # Provide tgen as argument to each test function
    yield tgen

    # Teardown after last test runs
    tgen.stop_topology()


# ===================
# The tests functions
# ===================


def test_rip_split_horizon(tgen):

    r1 = tgen.gears["r1"]
    r3 = tgen.gears["r3"]

    def check_output(router, command, expected=None, unexpected=None):
        output = json.loads(router.vtysh_cmd(command))

        if expected:
            result = topotest.json_cmp(output, expected)

            if result is not None:
                return result

        if unexpected:
            if unexpected in output:
                return (
                    f"Error: Route {unexpected} should be removed but is still present"
                )

        return None

    step("Verify r1 has rip route 100.100.100.100/32")
    expected = {
        "100.100.100.100/32": [{"protocol": "rip"}],
    }
    command = "show ip route rip json"
    test_func = functools.partial(check_output, r1, command, expected)
    _, result = topotest.run_and_expect(test_func, None, count=30, wait=1)

    assert result is None, "Route 100.100.100.100/32 is not present in r1 routing table"

    step("Verify r3 does not have rip route 100.100.100.100/32")
    unexpected = "100.100.100.100/32"
    command = "show ip route rip json"
    test_func = functools.partial(check_output, r3, command, unexpected=unexpected)
    _, result = topotest.run_and_expect(test_func, None, count=30, wait=1)

    assert result is None, "Route 100.100.100.100/32 is present in r3 routing table"

    step("Disable split-horizon on r1")
    r1.vtysh_cmd(
        """
        configure terminal
        interface r1-eth0
        no ip rip split-horizon
        exit
        """
    )

    step("Verify r3 has rip route 100.100.100.100/32")
    expected = {
        "100.100.100.100/32": [{"protocol": "rip"}],
    }
    command = "show ip route rip json"
    test_func = functools.partial(check_output, r3, command, expected)
    _, result = topotest.run_and_expect(test_func, None, count=30, wait=1)

    assert result is None, "Route 100.100.100.100/32 is not present in r3 routing table"

    step("Enable split-hoizon poisoned-reverse on r1")
    r1.vtysh_cmd(
        """
        configure terminal
        interface r1-eth0
        ip rip split-horizon poisoned-reverse
        exit
        """
    )

    step("Verify r3 has rip entry 100.100.100.100/32 with metric of 16")
    expected = {
        "frr-ripd:route": [
            {
                "prefix": "100.100.100.100/32",
                "nexthops": {
                    "nexthop": [
                        {
                            "nh-type": "ip4",
                            "protocol": "rip",
                            "rip-type": "normal",
                            "gateway": "10.1.1.2",
                            "from": "10.1.1.1",
                        }
                    ]
                },
                "metric": 16,
                "next-hop": "10.1.1.2",
            }
        ]
    }
    command = "show mgmt get-data /frr-ripd:ripd/instance/state/routes/route[prefix='100.100.100.100/32'] exact"
    test_func = functools.partial(check_output, r3, command, expected)
    _, result = topotest.run_and_expect(test_func, None, count=30, wait=1)

    assert (
        result is None
    ), "Route 100.100.100.100/32 is not present in r3 with a metric of 16"


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
