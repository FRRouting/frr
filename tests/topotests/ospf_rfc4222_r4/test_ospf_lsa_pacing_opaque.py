#!/usr/bin/env python
# SPDX-License-Identifier: ISC

"""
Opaque/TE Rec4 regression scenario.

This keeps the topology intentionally small: two routers with opaque capability
and MPLS-TE enabled while Rec4 interface pacing is active on the sender side.
The test validates the MPLS-TE database rather than the generic opaque-area
LSDB view, which matches FRR's existing TE topotests.
"""

import json
import time

import pytest

from lib import topotest
from lib.topogen import Topogen


pytestmark = [pytest.mark.ospfd]


def build_topo(tgen):
    r3 = tgen.add_router("r3")
    r4 = tgen.add_router("r4")
    tgen.add_link(r3, r4, ifname1="eth1", ifname2="eth1")


@pytest.fixture(scope="function")
def tgen(request):
    tgen = Topogen(build_topo, request.module.__name__)
    tgen.start_topology()

    for _, router in tgen.routers().items():
        router.load_frr_config("frr.conf")

    tgen.start_router()
    yield tgen
    tgen.stop_topology()


def _wait_neighbor_full(router, rid, timeout_s=30):
    deadline = time.time() + timeout_s
    while time.time() < deadline:
        out = router.vtysh_cmd("show ip ospf neighbor json")
        try:
            data = json.loads(out)
        except json.JSONDecodeError:
            time.sleep(1)
            continue

        neighbors = data.get("neighbors", {})
        if rid in neighbors:
            state = neighbors[rid][0].get(
                "converged", neighbors[rid][0].get("state", "")
            )
            if state == "Full" or str(state).startswith("Full"):
                return
        time.sleep(1)

    pytest.fail(f"neighbor {rid} did not reach Full")


def _te_router_ids(router):
    out = router.vtysh_cmd("show ip ospf mpls-te database json")
    data = json.loads(out)
    return {
        vertex.get("router-id")
        for vertex in data.get("ted", {}).get("vertices", [])
        if vertex.get("router-id")
    }


def _wait_for_te_router(router, name, rid, timeout_s=30):
    deadline = time.time() + timeout_s
    while time.time() < deadline:
        if rid in _te_router_ids(router):
            return
        time.sleep(1)
    pytest.fail(f"MPLS-TE database on {name} did not include router {rid}")


def test_opaque_lsa_with_rec4_pacing_survives_interface_flap(tgen):
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r3 = tgen.gears["r3"]
    r4 = tgen.gears["r4"]

    _wait_neighbor_full(r3, "4.4.4.4")
    _wait_neighbor_full(r4, "3.3.3.3")

    cfg = r3.vtysh_cmd("show running-config")
    assert "ip ospf lsa-pacing" in cfg
    # Opaque capability is enabled by default; only its disabled form is
    # emitted in running-config.
    assert "no capability opaque" not in cfg
    assert "mpls-te on" in cfg

    _wait_for_te_router(r3, "r3", "3.3.3.3")
    _wait_for_te_router(r3, "r3", "4.4.4.4")
    _wait_for_te_router(r4, "r4", "3.3.3.3")
    _wait_for_te_router(r4, "r4", "4.4.4.4")

    tgen.net["r3"].cmd("ip link set eth1 down")
    time.sleep(2)
    tgen.net["r3"].cmd("ip link set eth1 up")

    _wait_neighbor_full(r3, "4.4.4.4")
    _wait_neighbor_full(r4, "3.3.3.3")
    _wait_for_te_router(r3, "r3", "3.3.3.3")
    _wait_for_te_router(r3, "r3", "4.4.4.4")
    _wait_for_te_router(r4, "r4", "3.3.3.3")
    _wait_for_te_router(r4, "r4", "4.4.4.4")

    assert not tgen.routers_have_failure(), tgen.errors

    rc, _, _ = tgen.net["r3"].cmd_status(
        "grep -q 'Assertion' ospfd.err || grep -q 'Backtrace' ospfd.err",
        warn=False,
    )
    assert rc != 0, "ospfd.err shows an assertion/backtrace on r3"
