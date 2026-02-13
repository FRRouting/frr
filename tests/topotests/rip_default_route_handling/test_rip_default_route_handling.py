#!/usr/bin/env python
# SPDX-License-Identifier: ISC
#
# Copyright 2026 by Nvidia Inc.
#                   Donald Sharp
#
# test_rip_default_route_handling.py
#
# Test RIP default-information originate: r1 originates default, r2 receives it.
#

import os
import sys
import pytest
from functools import partial

CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

from lib import topotest
from lib.topogen import Topogen, TopoRouter, get_topogen
from lib.topolog import logger

pytestmark = [pytest.mark.ripd]


def build_topo(tgen):
    "Two routers directly connected."
    r1 = tgen.add_router("r1")
    r2 = tgen.add_router("r2")
    tgen.add_link(r1, r2)


def setup_module(module):
    "Setup topology and load integrated config (frr.conf)."
    tgen = Topogen(build_topo, module.__name__)
    tgen.start_topology()

    router_list = tgen.routers()
    for rname, router in router_list.items():
        router.load_frr_config(
            os.path.join(CWD, "{}/frr.conf".format(rname)),
            [
                (TopoRouter.RD_ZEBRA, None),
                (TopoRouter.RD_RIP, None),
                (TopoRouter.RD_STATIC, None),
            ],
        )

    tgen.start_router()


def teardown_module(_mod):
    "Teardown the pytest environment"
    tgen = get_topogen()
    tgen.stop_topology()


def test_rip_default_route_received_on_r2():
    "r2 should receive default route 0.0.0.0/0 from r1 via RIP."
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    logger.info("Ensure that the default route is received on r2 from r1")
    r2 = tgen.gears["r2"]

    expected = {
        "0.0.0.0/0": [
            {
                "protocol": "rip",
            }
        ]
    }
    test_func = partial(
        topotest.router_json_cmp, r2, "show ip route 0.0.0.0/0 json", expected
    )
    _, result = topotest.run_and_expect(test_func, None, count=60, wait=1)
    assert result is None, "r2 did not receive default route via RIP: {}".format(result)

    # Verify RIP sees the default route as from r1 (R(n)), not kernel
    output = r2.vtysh_cmd("show ip rip", isjson=False)
    default_lines = [line for line in output.splitlines() if "0.0.0.0/0" in line]
    assert (
        default_lines
    ), "Default route 0.0.0.0/0 not found in 'show ip rip'. Output:\n{}".format(output)
    for line in default_lines:
        assert (
            "R(n)" in line
        ), "RIP should show default route as from r1: R(n) 0.0.0.0/0. Line: {}".format(
            line
        )


def test_kernel_default_route_selected_on_r2():
    "Add a kernel default route on r2 and verify it becomes the selected route in the RIB."
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r2 = tgen.gears["r2"]
    # r1's address on the link
    gateway = "10.0.0.1"

    logger.info("Ensure that the newly added kernel default route takes over on r2")
    r2.run("ip route add default via {}".format(gateway))

    expected = {
        "0.0.0.0/0": [
            {
                "protocol": "kernel",
                "selected": True,
            }
        ]
    }
    test_func = partial(
        topotest.router_json_cmp, r2, "show ip route 0.0.0.0/0 json", expected
    )
    _, result = topotest.run_and_expect(test_func, None, count=60, wait=1)
    assert (
        result is None
    ), "Kernel default route did not become the selected route on r2: {}".format(result)

    # Verify RIP sees the default route as kernel-redistribute (K(r)), not from r1 (R)
    def _check_rip_default_is_kernel():
        output = r2.vtysh_cmd("show ip rip", isjson=False)
        default_lines = [line for line in output.splitlines() if "0.0.0.0/0" in line]
        if not default_lines:
            return "Default route 0.0.0.0/0 not found in 'show ip rip'. Output:\n{}".format(
                output
            )
        for line in default_lines:
            if "K(r)" not in line:
                return (
                    "RIP should show default route as kernel-redistribute K(r) 0.0.0.0/0, "
                    "not from r1. Line: {}".format(line)
                )
        return None

    _, result = topotest.run_and_expect(
        _check_rip_default_is_kernel, None, count=60, wait=1
    )
    assert (
        result is None
    ), "RIP default route selection did not reflect kernel: {}".format(result)


def test_static_default_route_brought_into_rip_on_r2():
    "Remove kernel default on r2, add static default and redistribute static; verify RIP sees it."
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r2 = tgen.gears["r2"]
    gateway = "10.0.0.1"

    logger.info("Remove kernel default route on r2 if present")
    r2.run("ip route del default", warn=False)

    logger.info("Enable redistribute static and add static default on r2")
    r2.vtysh_cmd(
        "configure terminal\n"
        "router rip\n"
        "redistribute static\n"
        "exit\n"
        "ip route 0.0.0.0/0 {}\n"
        "end\n".format(gateway)
    )

    def _check_static_default_in_rip():
        output = r2.vtysh_cmd("show ip rip", isjson=False)
        default_lines = [line for line in output.splitlines() if "0.0.0.0/0" in line]
        if not default_lines:
            return "Default route 0.0.0.0/0 not found in 'show ip rip'"
        for line in default_lines:
            if "S(r)" in line:
                return None
        return "RIP should show static default as S(r) 0.0.0.0/0. " "Lines: {}".format(
            default_lines
        )

    _, result = topotest.run_and_expect(
        _check_static_default_in_rip, None, count=60, wait=1
    )
    assert result is None, "Static default route not brought into RIP: {}".format(
        result
    )

    # Verify RIB has static default selected
    expected = {
        "0.0.0.0/0": [
            {
                "protocol": "static",
                "selected": True,
            }
        ]
    }
    test_func = partial(
        topotest.router_json_cmp, r2, "show ip route 0.0.0.0/0 json", expected
    )
    _, result = topotest.run_and_expect(test_func, None, count=20, wait=1)
    assert result is None, "Static default not selected in RIB: {}".format(result)


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
