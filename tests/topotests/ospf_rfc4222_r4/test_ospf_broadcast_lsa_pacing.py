#!/usr/bin/env python
# SPDX-License-Identifier: ISC
#
# Functional broadcast-LAN coverage for RFC4222 Recommendation 4 LSA pacing.
#

import os
import time
from functools import partial

import pytest

from lib import topotest
from lib.common_config import step
from lib.topogen import Topogen
from lib.topolog import logger

pytestmark = [pytest.mark.ospfd]

CWD = os.path.dirname(os.path.realpath(__file__))

NUM_ROUTES = 12
TEST_PREFIXES = ["10.77.{}.0/24".format(i) for i in range(1, NUM_ROUTES + 1)]
PREFIX_TAG = "10.77."

GAP_MS = 200
MAX_LSAS = 1
ADJINT_MS = 60000

LINK_RATE = "100kbit"
LINK_BURST = "8kb"
LINK_LATENCY = "100ms"
R1_BCAST_IF = "r1-eth0"
LAN_NEIGHBORS = ["r2", "r3", "r4", "r5"]
LAN_NEIGHBOR_IDS = {
    "r2": "1.1.1.2",
    "r3": "1.1.1.3",
    "r4": "1.1.1.4",
    "r5": "1.1.1.5",
}


def build_topo(tgen):
    r1 = tgen.add_router("r1")
    r2 = tgen.add_router("r2")
    r3 = tgen.add_router("r3")
    r4 = tgen.add_router("r4")
    r5 = tgen.add_router("r5")

    switch = tgen.add_switch("s0")
    switch.add_link(r1)
    switch.add_link(r2)
    switch.add_link(r3)
    switch.add_link(r4)
    switch.add_link(r5)


@pytest.fixture(scope="function")
def tgen(request):
    tgen = Topogen(build_topo, request.module.__name__)
    tgen.start_topology()

    for rname, router in tgen.routers().items():
        router.load_frr_config(os.path.join(CWD, "{}_broadcast".format(rname), "frr.conf"))

    tgen.start_router()

    r1 = tgen.gears["r1"]
    r1.vtysh_cmd(
        "configure terminal\n"
        "router ospf\n"
        "redistribute static\n"
        "end"
    )

    time.sleep(12)

    yield tgen

    tgen.stop_topology()


def _wait_neighbor_full(router, neighbor_id, timeout_s=30):
    deadline = time.time() + timeout_s
    while time.time() < deadline:
        data = router.vtysh_cmd(
            "show ip ospf neighbor {} json".format(neighbor_id), isjson=True
        )
        nbrs = data.get("default", {}).get(neighbor_id)
        if nbrs:
            state = nbrs[0].get("nbrState", "")
            if state.split("/", 1)[0] == "Full":
                return True
        time.sleep(0.5)
    return False


def _wait_broadcast_interface(router, expected, timeout_s=30):
    test_func = partial(
        topotest.router_json_cmp,
        router,
        "show ip ospf interface {} json".format(expected["ifname"]),
        {"interfaces": {expected["ifname"]: expected["data"]}},
    )
    count = max(1, int(timeout_s))
    _, result = topotest.run_and_expect(test_func, None, count=count, wait=1)
    return result is None


def _verify_dr_bdr_state(tgen):
    step("Verify broadcast interface state: r1 is DR and r2 is Backup")
    assert _wait_broadcast_interface(
        tgen.gears["r1"],
        {
            "ifname": "r1-eth0",
            "data": {
                "ospfEnabled": True,
                "ipAddress": "198.51.100.1",
                "ipAddressPrefixlen": 24,
                "ospfIfType": "Broadcast",
                "area": "0.0.0.0",
                "routerId": "1.1.1.1",
                "networkType": "BROADCAST",
                "nbrCount": 4,
                "nbrAdjacentCount": 4,
                "state": "DR",
            },
        },
    ), "r1 did not become DR on the broadcast LAN"
    assert _wait_broadcast_interface(
        tgen.gears["r2"],
        {
            "ifname": "r2-eth0",
            "data": {
                "ospfEnabled": True,
                "ipAddress": "198.51.100.2",
                "ipAddressPrefixlen": 24,
                "ospfIfType": "Broadcast",
                "area": "0.0.0.0",
                "routerId": "1.1.1.2",
                "networkType": "BROADCAST",
                "nbrCount": 4,
                "nbrAdjacentCount": 4,
                "state": "Backup",
            },
        },
    ), "r2 did not become Backup on the broadcast LAN"


def _wait_all_full(tgen, routers=None, timeout_s=30):
    routers = routers or LAN_NEIGHBORS
    for rname in routers:
        assert _wait_neighbor_full(
            tgen.gears["r1"], LAN_NEIGHBOR_IDS[rname], timeout_s=timeout_s
        ), "r1 neighbor {} failed to reach Full".format(LAN_NEIGHBOR_IDS[rname])


def _count_external_lsas(router):
    out = router.vtysh_cmd("show ip ospf database external")
    return sum(
        1 for line in out.splitlines()
        if "Link State ID" in line and PREFIX_TAG in line
    )


def _wait_all_receivers(expected, receivers, timeout_s):
    deadline = time.time() + timeout_s
    while time.time() < deadline:
        counts = {name: _count_external_lsas(router) for name, router in receivers.items()}
        if all(count == expected for count in counts.values()):
            return counts
        time.sleep(0.2)
    return {name: _count_external_lsas(router) for name, router in receivers.items()}


def _wait_receiver_at_least(router, minimum, timeout_s):
    deadline = time.time() + timeout_s
    while time.time() < deadline:
        count = _count_external_lsas(router)
        if count >= minimum:
            return count
        time.sleep(0.1)
    return _count_external_lsas(router)


def _enable_lsa_pacing(r1):
    r1.vtysh_cmd(
        "configure terminal\n"
        "interface r1-eth0\n"
        "ip ospf lsa-pacing\n"
        "ip ospf lsa-pacing initial-gap {gap}\n"
        "ip ospf lsa-pacing min-gap {gap} max-gap {gap}\n"
        "ip ospf lsa-pacing max-lsas-per-update {max_lsas}\n"
        "ip ospf lsa-pacing adjust-interval {adjint}\n"
        "end".format(gap=GAP_MS, max_lsas=MAX_LSAS, adjint=ADJINT_MS)
    )
    cfg = r1.vtysh_cmd("show running-config")
    assert "ip ospf lsa-pacing" in cfg, "R4 lsa-pacing missing from running-config"


def _enable_dynamic_adjacency_pacing(r1):
    r1.vtysh_cmd(
        "configure terminal\n"
        "interface r1-eth0\n"
        "ip ospf adjacency-pacing dynamic\n"
        "ip ospf adjacency-pacing dynamic thresholds 20 6\n"
        "end"
    )
    cfg = r1.vtysh_cmd("show running-config")
    assert "ip ospf adjacency-pacing dynamic" in cfg, (
        "R5 adjacency-pacing dynamic missing from running-config"
    )
    assert "ip ospf adjacency-pacing dynamic thresholds 20 6" in cfg, (
        "R5 adjacency-pacing dynamic thresholds missing from running-config"
    )


def _add_routes(r1):
    r1.vtysh_cmd(
        "configure terminal\n"
        + "".join("ip route {} null0\n".format(prefix) for prefix in TEST_PREFIXES)
        + "end"
    )


def _apply_constraint(r1):
    r1.cmd("tc qdisc del dev {} root 2>/dev/null || true".format(R1_BCAST_IF))
    r1.cmd(
        "tc qdisc add dev {} root handle 1: tbf rate {} burst {} latency {}".format(
            R1_BCAST_IF, LINK_RATE, LINK_BURST, LINK_LATENCY
        )
    )


def _r1_log_matches(tgen, pattern):
    log_path = os.path.join(tgen.logdir, "r1", "ospfd.log")
    return tgen.net["r1"].cmd("grep -a '{}' {} | tail -20".format(pattern, log_path))


def _exercise_lsa_pacing(tgen, constrained):
    r1 = tgen.gears["r1"]
    r2 = tgen.gears["r2"]

    _verify_dr_bdr_state(tgen)
    _wait_all_full(tgen)

    if constrained:
        step("Apply constrained bandwidth on r1 broadcast interface")
        _apply_constraint(r1)

    step("Enable LSA pacing on r1 broadcast interface")
    _enable_lsa_pacing(r1)

    step("Inject external LSAs through redistributed static routes")
    _add_routes(r1)

    first = _wait_receiver_at_least(r2, 1, timeout_s=4)
    assert first >= 1, "No Type-5 LSA reached r2 after enabling broadcast LSA pacing"

    count_now = _count_external_lsas(r2)
    assert count_now < NUM_ROUTES, (
        "Broadcast LSA pacing did not gate the flood: r2 already has {}/{} LSAs".format(
            count_now, NUM_ROUTES
        )
    )

    receivers = {name: tgen.gears[name] for name in LAN_NEIGHBORS}
    timeout_s = 12
    counts = _wait_all_receivers(NUM_ROUTES, receivers, timeout_s=timeout_s)
    assert all(count == NUM_ROUTES for count in counts.values()), (
        "Not all receivers learned all Type-5 LSAs within {}s: {}".format(
            timeout_s, counts
        )
    )

    # Log check is informational only: it depends on 'debug ospf lsa flooding'
    # staying enabled and the message text staying stable, which has proven
    # fragile under the NetDEF CI pipeline (see R5's
    # test_ospf_broadcast_router_dynamic_pacing.py step 8). The functional
    # assertions above (partial delivery while pacing is active, then full
    # delivery to all receivers) are the real proof that pacing gated the
    # flood.
    r4_log = _r1_log_matches(tgen, "RFC4222 R4: flood enqueue LSA")
    logger.info("RFC4222 R4 enqueue log entries (informational):\n%s", r4_log)

    _wait_all_full(tgen)


def _exercise_adj_and_lsa_pacing(tgen, constrained):
    r1 = tgen.gears["r1"]

    _verify_dr_bdr_state(tgen)
    _wait_all_full(tgen)

    if constrained:
        step("Apply constrained bandwidth on r1 broadcast interface")
        _apply_constraint(r1)

    step("Enable both adjacency pacing and LSA pacing on r1")
    _enable_dynamic_adjacency_pacing(r1)
    _enable_lsa_pacing(r1)

    step("Inject external LSAs while flapping three DROther neighbors")
    _add_routes(r1)

    for rname in ["r3", "r4", "r5"]:
        tgen.net[rname].cmd("ip link set {}-eth0 down".format(rname))
    time.sleep(1)
    for rname in ["r3", "r4", "r5"]:
        tgen.net[rname].cmd("ip link set {}-eth0 up".format(rname))

    _wait_all_full(tgen, routers=["r3", "r4", "r5"], timeout_s=40)

    receivers = {name: tgen.gears[name] for name in LAN_NEIGHBORS}
    timeout_s = 20
    counts = _wait_all_receivers(NUM_ROUTES, receivers, timeout_s=timeout_s)
    assert all(count == NUM_ROUTES for count in counts.values()), (
        "Combined R4/R5 broadcast pacing did not deliver all Type-5 LSAs: {}".format(
            counts
        )
    )

    # Log checks are informational only — see note in _exercise_lsa_pacing.
    # The functional assertions above (all neighbors recover to Full, all
    # receivers learn every Type-5 LSA) are the real proof that combined
    # R4/R5 pacing worked.
    r4_log = _r1_log_matches(tgen, "RFC4222 R4: flood enqueue LSA")
    logger.info("RFC4222 R4 enqueue log entries (informational):\n%s", r4_log)

    r5_log = _r1_log_matches(tgen, "R5-DYN:")
    logger.info("RFC4222 R5 dynamic pacing log entries (informational):\n%s", r5_log)

    _wait_all_full(tgen)


def test_broadcast_neighbors_full(tgen):
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    _verify_dr_bdr_state(tgen)
    _wait_all_full(tgen)


def test_broadcast_lsa_pacing_external_unconstrained(tgen):
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    _exercise_lsa_pacing(tgen, constrained=False)


def test_broadcast_lsa_pacing_external_constrained(tgen):
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    _exercise_lsa_pacing(tgen, constrained=True)


def test_broadcast_adj_and_lsa_pacing_external_unconstrained(tgen):
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    _exercise_adj_and_lsa_pacing(tgen, constrained=False)


def test_broadcast_adj_and_lsa_pacing_external_constrained(tgen):
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    _exercise_adj_and_lsa_pacing(tgen, constrained=True)
