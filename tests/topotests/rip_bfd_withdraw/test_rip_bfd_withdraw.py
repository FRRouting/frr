#!/usr/bin/env python
# SPDX-License-Identifier: ISC

#
# test_rip_bfd_withdraw.py
# Part of NetDEF Topology Tests
#

"""
test_rip_bfd_withdraw.py: Test that RIP fully withdraws a peer's routes
when the BFD session to that peer goes down.

rip_bfd_session_change() calls rip_peer_delete_routes() on BFD UP->DOWN.
The single-path branch used to free the rip_info without the ZAPI DELETE
and without the metric-16 garbage collection the normal last-path
deletion performs, and the multi-path branch stopped at the first
matching entry, leaving zebra/FIB and downstream peers with stale paths.
"""

import sys
import re
import json
import pytest

from lib import topotest
from lib.topogen import Topogen, TopoRouter

pytestmark = [
    pytest.mark.bfdd,
    pytest.mark.mgmtd,
    pytest.mark.ripd,
    pytest.mark.staticd,
]

P_SINGLE = "203.0.113.1/32"  # advertised by r2 only
P_R3 = "203.0.113.2/32"  # advertised by r3 only
P_ECMP = "198.18.2.0/24"  # advertised by r2 and r3
P_SAMEPEER = "198.18.3.0/24"  # two paths, both from r2
P_METRIC16 = "198.18.5.0/24"  # advertised by r3 only

R2_ADDR = "10.0.12.2"
R2_ADDR2 = "10.0.12.3"
R3_ADDR = "10.0.13.3"


@pytest.fixture(scope="module")
def tgen(request):
    "Setup/Teardown the environment and provide tgen argument to tests"

    topodef = {"s1": ("r1", "r2"), "s2": ("r1", "r3"), "s3": ("r1", "r4")}
    tgen = Topogen(topodef, request.module.__name__)
    tgen.start_topology()

    router_list = tgen.routers()

    for router_name, router in router_list.items():
        router.load_config(TopoRouter.RD_BFD, "bfdd.conf")
        router.load_config(TopoRouter.RD_RIP, "ripd.conf")
        router.load_config(TopoRouter.RD_ZEBRA, "zebra.conf")

    tgen.start_router()
    yield tgen
    tgen.stop_topology()


@pytest.fixture(autouse=True)
def skip_on_failure(tgen):
    "Test if routers is still running otherwise skip tests"
    if tgen.routers_have_failure():
        pytest.skip("skipped because of previous test failure")


def show_rip_paths(router):
    "Parse `show ip rip` -> {prefix: [{nh, metric, from}, ...]}"
    output = router.vtysh_cmd("show ip rip")
    routes = {}
    for line in output.splitlines():
        parts = line.split()
        if len(parts) < 5 or not re.fullmatch(r"\d+", parts[3]):
            continue
        if not re.fullmatch(r"R\(.\)", parts[0]):
            continue
        routes.setdefault(parts[1], []).append(
            {"nh": parts[2], "metric": int(parts[3]), "from": parts[4]}
        )
    return routes


def finite_paths(router, prefix, src=None):
    "Finite-metric paths for prefix, optionally only those learned from src"
    paths = [
        p
        for p in show_rip_paths(router).get(prefix, [])
        if p["metric"] < 16
    ]
    if src:
        paths = [p for p in paths if p["from"] == src]
    return paths


def zebra_nhs(router, prefix):
    "Nexthops of the zebra RIB entry for prefix"
    output = router.vtysh_cmd("show ip route {}".format(prefix))
    return re.findall(r"(\d+\.\d+\.\d+\.\d+), via", output)


def fib_nhs(router, prefix):
    "Nexthops of the kernel FIB entry for prefix"
    output = router.cmd("ip route show {}".format(prefix))
    return re.findall(r"via (\d+\.\d+\.\d+\.\d+)", output)


def expect_that(test_function, time_amount=30):
    "Run test_function until it returns True"
    _, result = topotest.run_and_expect(test_function, True, count=time_amount, wait=1)
    assert result is True


def expect_bfd_up(router, peers, time_amount=30):
    "Expect BFD sessions to peers to be up"

    def test_function():
        output = router.vtysh_cmd("show bfd peers json")
        try:
            sessions = json.loads(output)
        except ValueError:
            return False
        status = {s["peer"]: s.get("status") for s in sessions}
        return all(status.get(p) == "up" for p in peers)

    expect_that(test_function, time_amount)


def test_rip_convergence(tgen):
    "Test that RIP and BFD converge before any trigger"

    r1 = tgen.gears["r1"]
    r4 = tgen.gears["r4"]

    expect_bfd_up(r1, [R2_ADDR, R3_ADDR], 60)

    def routes_up():
        paths = show_rip_paths(r1)
        return bool(
            len(paths.get(P_SINGLE, [])) == 1
            and len(paths.get(P_R3, [])) == 1
            and len(paths.get(P_ECMP, [])) == 2
            and len(paths.get(P_METRIC16, [])) == 1
            and zebra_nhs(r1, P_SINGLE)
            and zebra_nhs(r1, P_ECMP)
            and fib_nhs(r1, P_SINGLE)
            and zebra_nhs(r4, P_SINGLE)
            and zebra_nhs(r4, P_ECMP)
        )

    expect_that(routes_up, 90)


def test_same_peer_two_paths(tgen):
    "Test that one peer can hold two paths for the same prefix"

    r1 = tgen.gears["r1"]
    r2 = tgen.gears["r2"]

    # r2 advertises 198.18.3.0/24 with next hop 10.0.12.3; switch the
    # outbound route-map to 10.0.12.2 so the next periodic update adds a
    # second path from the same peer.
    r2.vtysh_cmd(
        "configure terminal\n"
        "route-map RMOUT permit 10\n"
        " set ip next-hop {}\n"
        "end".format(R2_ADDR)
    )

    def two_paths():
        paths = finite_paths(r1, P_SAMEPEER, R2_ADDR)
        return len(paths) == 2

    expect_that(two_paths, 40)


def test_bfd_down_withdraws_routes(tgen):
    "Test that BFD down fully withdraws the failed peer's routes"

    r1 = tgen.gears["r1"]
    r2 = tgen.gears["r2"]
    r4 = tgen.gears["r4"]

    # Real link failure: r2 stops sending RIP updates and BFD control
    # packets, so r1's BFD session goes UP->DOWN through the state machine.
    r2.link_enable("r2-eth0", False)

    # The BFD down callback must withdraw every path from r2, notify
    # zebra (RIB and FIB) and poison the downstream peer r4.
    def withdrawn():
        return (
            not finite_paths(r1, P_SINGLE)
            and not finite_paths(r1, P_SAMEPEER, R2_ADDR)
            and not zebra_nhs(r1, P_SINGLE)
            and not fib_nhs(r1, P_SINGLE)
            and not zebra_nhs(r4, P_SINGLE)
        )

    expect_that(withdrawn, 40)

    # The other peer's routes and the ECMP fallback must be intact.
    assert len(finite_paths(r1, P_R3)) == 1
    assert zebra_nhs(r1, P_R3)
    ecmp_paths = finite_paths(r1, P_ECMP)
    assert [p["from"] for p in ecmp_paths] == [R3_ADDR]
    assert zebra_nhs(r1, P_ECMP)
    assert zebra_nhs(r4, P_ECMP)


def test_bfd_down_keeps_other_bfd(tgen):
    "Test that the BFD session to the surviving peer stays up"
    r1 = tgen.gears["r1"]
    expect_bfd_up(r1, [R3_ADDR], 10)


def test_bfd_recovery(tgen):
    "Test that routes come back when the failed peer recovers"

    r1 = tgen.gears["r1"]
    r2 = tgen.gears["r2"]
    r4 = tgen.gears["r4"]

    r2.link_enable("r2-eth0", True)

    expect_bfd_up(r1, [R2_ADDR, R3_ADDR], 60)

    def routes_back():
        return bool(
            len(finite_paths(r1, P_SINGLE)) == 1
            and zebra_nhs(r1, P_SINGLE)
            and fib_nhs(r1, P_SINGLE)
            and zebra_nhs(r4, P_SINGLE)
        )

    expect_that(routes_back, 90)


def test_metric16_withdraw(tgen):
    "Test that a normal metric-16 withdrawal still works"

    r1 = tgen.gears["r1"]
    r3 = tgen.gears["r3"]
    r4 = tgen.gears["r4"]

    r3.vtysh_cmd(
        "configure terminal\n"
        "interface lo\n"
        " no ip address 198.18.5.1/24\n"
        "end"
    )

    def gone():
        return (
            not finite_paths(r1, P_METRIC16)
            and not zebra_nhs(r1, P_METRIC16)
            and not fib_nhs(r1, P_METRIC16)
            and not zebra_nhs(r4, P_METRIC16)
        )

    expect_that(gone, 60)


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
