#!/usr/bin/env python
# SPDX-License-Identifier: ISC

# Copyright (c) 2026 by
# Bing Shui <bingshui@smail.nju.edu.cn>
#

"""
Test that `clear ip rip` removes every ECMP path of a learned prefix.

With allow-ecmp > 1, clear_rip_route() used to withdraw the whole prefix
from zebra but removed only the first dynamic path from the RIP RIB, so
the surviving paths were never re-added to zebra and the kernel FIB
could lack a prefix the RIP RIB still held.  The test silences both
advertising neighbors before the clear so no later update can mask the
residual paths, then checks the re-learning once the neighbors come
back.
"""

import os
import sys
import json

import pytest

CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

# pylint: disable=C0413
from lib import topotest
from lib.topogen import Topogen, get_topogen
from lib.common_config import step

pytestmark = [pytest.mark.ripd]

P_ECMP = "10.10.10.1/32"
P_SINGLE = "10.10.20.1/32"
NH_R2 = "192.168.1.2"
NH_R3 = "192.168.1.3"


def setup_module(mod):
    topodef = {"s1": ("r1", "r2", "r3")}
    tgen = Topogen(topodef, mod.__name__)
    tgen.start_topology()

    router_list = tgen.routers()

    for router in router_list.values():
        router.load_frr_config()

    tgen.start_router()


def teardown_module():
    tgen = get_topogen()
    tgen.stop_topology()


def rip_routes(router, prefix):
    """Finite-metric nexthops of the prefix in the RIP RIB, [] when the
    RIB holds no usable route for it."""
    xpath = (
        "/frr-ripd:ripd/instance[vrf='default']"
        f"/state/routes/route[prefix='{prefix}']"
    )
    try:
        output = json.loads(
            router.vtysh_cmd(f"show yang operational-data {xpath} ripd")
        )
        output = output["frr-ripd:ripd"]["instance"][0]["state"]["routes"]
    except Exception:
        return []
    try:
        routes = output["route"]
    except KeyError:
        return []
    if isinstance(routes, dict):
        routes = [routes]
    out = []
    for route in routes:
        if route.get("metric", 16) >= 16:
            continue
        nhs = route.get("nexthops", {}).get("nexthop", [])
        if isinstance(nhs, dict):
            nhs = [nhs]
        out.extend(nh.get("gateway") for nh in nhs)
    return out


def zebra_nexthops(router, prefix):
    try:
        output = json.loads(router.vtysh_cmd("show ip route json"))
    except Exception:
        return None
    route = output.get(prefix)
    if not route:
        return []
    nhs = route[0].get("nexthops", [])
    return [nh.get("ip") for nh in nhs if nh.get("ip")]


def fib_nexthops(router, prefix):
    output = router.cmd(f"ip -j route show {prefix}")
    if not output.strip():
        return []
    try:
        routes = json.loads(output)
    except Exception:
        return None
    out = []
    for route in routes:
        if "nexthops" in route:
            out.extend(nh.get("gateway") for nh in route["nexthops"])
        elif "gateway" in route:
            out.append(route["gateway"])
    return out


def check_paths(router, prefix, expected):
    """Expected sorted nexthop list in RIP RIB, zebra and the kernel
    FIB; returns None when all three match, an error string otherwise."""

    def _cmp():
        if sorted(rip_routes(router, prefix)) != expected:
            return "rib {} != {}".format(rip_routes(router, prefix), expected)
        if sorted(zebra_nexthops(router, prefix) or []) != expected:
            return "zebra {} != {}".format(
                zebra_nexthops(router, prefix), expected
            )
        if sorted(fib_nexthops(router, prefix) or []) != expected:
            return "fib {} != {}".format(
                fib_nexthops(router, prefix), expected
            )
        return None

    return _cmp


def test_rip_clear_ecmp_convergence():
    "Test that RIP learns the prefix as two-path ECMP in RIB, zebra and FIB."
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]

    test_func = check_paths(r1, P_ECMP, sorted([NH_R2, NH_R3]))
    _, result = topotest.run_and_expect(test_func, None, count=60, wait=1)
    assert result is None, f"Can't see {P_ECMP} as two-path ECMP: {result}"

    test_func = check_paths(r1, P_SINGLE, [NH_R2])
    _, result = topotest.run_and_expect(test_func, None, count=30, wait=1)
    assert result is None, f"Can't see {P_SINGLE} from r2: {result}"


def test_rip_clear_ecmp():
    "Test that `clear ip rip` removes every ECMP path, not just one."
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]
    r2 = tgen.gears["r2"]
    r3 = tgen.gears["r3"]

    # Silence both advertisers so no periodic update can re-add the
    # prefix while the clear is being checked.
    step("Kill ripd on r2 and r3 to freeze the RIB")
    r2.killDaemons(["ripd"], wait=True)
    r3.killDaemons(["ripd"], wait=True)
    topotest.sleep(3, "waiting for the last updates to settle")

    step("Clear all RIP routes on r1")
    r1.vtysh_cmd("clear ip rip")

    def _cleared():
        if zebra_nexthops(r1, P_ECMP) != []:
            return "zebra still has {}: {}".format(
                P_ECMP, zebra_nexthops(r1, P_ECMP)
            )
        if fib_nexthops(r1, P_ECMP) != []:
            return "FIB still has {}: {}".format(
                P_ECMP, fib_nexthops(r1, P_ECMP)
            )
        if zebra_nexthops(r1, P_SINGLE) != []:
            return "zebra still has {}: {}".format(
                P_SINGLE, zebra_nexthops(r1, P_SINGLE)
            )
        if fib_nexthops(r1, P_SINGLE) != []:
            return "FIB still has {}: {}".format(
                P_SINGLE, fib_nexthops(r1, P_SINGLE)
            )
        if rip_routes(r1, P_SINGLE) != []:
            return "RIP RIB still has {}: {}".format(
                P_SINGLE, rip_routes(r1, P_SINGLE)
            )
        if rip_routes(r1, P_ECMP) != []:
            return "RIP RIB still has finite {} paths: {}".format(
                P_ECMP, rip_routes(r1, P_ECMP)
            )
        return None

    # The whole prefix must disappear from zebra and the FIB, and every
    # dynamic path must leave the RIP RIB.  Unpatched ripd keeps one
    # finite ECMP path in the RIB here while zebra and the FIB stay
    # empty, which is exactly the inconsistency being tested.  The poll
    # window is kept well below the 60 s RIP timeout so the residual
    # cannot expire mid-assertion.
    _, result = topotest.run_and_expect(_cleared, None, count=10, wait=2)
    assert result is None, f"`clear ip rip` left residual state: {result}"


def test_rip_clear_ecmp_relearn():
    "Test that cleared routes are legally re-learned from the neighbors."
    tgen = get_topogen()

    r1 = tgen.gears["r1"]
    r2 = tgen.gears["r2"]
    r3 = tgen.gears["r3"]

    # Bring the advertisers back before checking re-learning: the clear
    # test intentionally left them down.
    step("Restart ripd on r2 and r3")
    r2.startDaemons(["ripd"])
    r3.startDaemons(["ripd"])

    test_func = check_paths(r1, P_ECMP, sorted([NH_R2, NH_R3]))
    _, result = topotest.run_and_expect(test_func, None, count=60, wait=1)
    assert result is None, f"{P_ECMP} not re-learned as ECMP: {result}"

    test_func = check_paths(r1, P_SINGLE, [NH_R2])
    _, result = topotest.run_and_expect(test_func, None, count=30, wait=1)
    assert result is None, f"{P_SINGLE} not re-learned: {result}"


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
