#!/usr/bin/env python3
# SPDX-License-Identifier: ISC
#
# Copyright (c) 2026 by
# Yufan Zhou <zyivon1019@gmail.com>
#
"""Multipath AS_PATH aggregation must inherit ATOMIC_AGGREGATE.

r2 and r3 advertise the same /32 with equal relevant metrics. r2 has the
lower router ID and no ATOMIC_AGGREGATE; r3 carries ATOMIC_AGGREGATE.
r1 enables as-path multipath-relax as-set and maximum-paths 2.
"""

import json
import os
import sys

import pytest

CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

from lib import topotest
from lib.common_config import step
from lib.topogen import Topogen, get_topogen

pytestmark = [pytest.mark.bgpd]
PREFIX = "203.0.113.254/32"


def build_topo(tgen):
    for name in ("r1", "r2", "r3", "r4"):
        tgen.add_router(name)
    for name, left, right in (
        ("s12", "r1", "r2"),
        ("s13", "r1", "r3"),
        ("s14", "r1", "r4"),
    ):
        switch = tgen.add_switch(name)
        switch.add_link(tgen.gears[left])
        switch.add_link(tgen.gears[right])


def setup_module(mod):
    tgen = Topogen(build_topo, mod.__name__)
    tgen.start_topology()
    for name, router in tgen.routers().items():
        router.load_frr_config(os.path.join(CWD, f"{name}/frr.conf"))
    tgen.start_router()


def teardown_module(mod):
    get_topogen().stop_topology()


def paths(router):
    output = json.loads(router.vtysh_cmd(f"show bgp ipv4 unicast {PREFIX} json"))
    return output.get("paths", [])


def summary(path_list):
    return [
        {
            "asPath": path.get("aspath", {}).get("string"),
            "atomicAggregate": path.get("atomicAggregate", False),
            "best": path.get("bestpath", {}).get("overall", False),
            "multipath": path.get("multipath", False),
            "peerRouterId": path.get("peer", {}).get("routerId"),
        }
        for path in path_list
    ]


def test_multipath_atomic_inheritance():
    step("Wait for both equal paths and deterministic r2 bestpath")
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)
    r1 = tgen.gears["r1"]

    def _multipath_ready():
        path_list = paths(r1)
        best = [p for p in path_list if p.get("bestpath", {}).get("overall")]
        multipath = [p for p in path_list if p.get("multipath")]
        atomic = [p for p in path_list if p.get("atomicAggregate")]
        if (
            len(path_list) == 2
            and len(best) == 1
            and len(multipath) == 2
            and len(atomic) == 1
            and not best[0].get("atomicAggregate", False)
            and best[0].get("aspath", {}).get("string") == "65100"
            and atomic[0].get("aspath", {}).get("string") == "65200"
        ):
            return None
        return json.dumps(summary(path_list), sort_keys=True)

    _, result = topotest.run_and_expect(_multipath_ready, None, count=60, wait=0.5)
    print(f"MULTIPATH_INPUT={json.dumps(summary(paths(r1)), sort_keys=True)}")
    assert result is None, f"Unexpected multipath input state: {result}"

    step("Wait for the merged AS_SET at r4, then inspect ATOMIC_AGGREGATE")
    r4 = tgen.gears["r4"]

    def _merged_as_set():
        path_list = paths(r4)
        if len(path_list) != 1:
            return json.dumps(summary(path_list), sort_keys=True)
        aspath = path_list[0].get("aspath", {}).get("string", "")
        if "{" in aspath and "65100" in aspath and "65200" in aspath:
            return None
        return aspath

    _, result = topotest.run_and_expect(_merged_as_set, None, count=60, wait=0.5)
    observed = summary(paths(r4))
    assert result is None, f"Merged AS_SET not observed: {result}"

    # RFC 4271 section 9.2.2.2: one constituent (r3) has the attribute,
    # therefore the aggregated route shall have it as well. Even though r2 is
    # the bestpath, r3's ATOMIC_AGGREGATE must be inherited by the merged route.
    print(f"MULTIPATH_OUTPUT={json.dumps(observed, sort_keys=True)}")
    assert observed[0]["atomicAggregate"] is True, (
        "ATOMIC_AGGREGATE from a non-best multipath must be inherited: "
        f"observed={observed}"
    )


def test_multipath_atomic_with_swapped_router_ids():
    step("Swap r2/r3 router IDs so the ATOMIC-carrying path becomes best")
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)
    for name, as_number, router_id in (
        ("r2", 65100, "10.255.0.3"),
        ("r3", 65200, "10.255.0.2"),
    ):
        tgen.gears[name].vtysh_cmd(
            f"configure terminal\nrouter bgp {as_number}\nbgp router-id {router_id}"
        )

    r1 = tgen.gears["r1"]

    def _atomic_path_is_best():
        path_list = paths(r1)
        best = [p for p in path_list if p.get("bestpath", {}).get("overall")]
        multipath = [p for p in path_list if p.get("multipath")]
        if (
            len(path_list) == 2
            and len(best) == 1
            and len(multipath) == 2
            and best[0].get("atomicAggregate")
            and best[0].get("aspath", {}).get("string") == "65200"
            and best[0].get("peer", {}).get("routerId") == "10.255.0.2"
        ):
            return None
        return json.dumps(summary(path_list), sort_keys=True)

    _, result = topotest.run_and_expect(
        _atomic_path_is_best, None, count=120, wait=0.5
    )
    print(f"SWAPPED_INPUT={json.dumps(summary(paths(r1)), sort_keys=True)}")
    assert result is None, f"Swapped multipath input state: {result}"

    step("Check that the merged advertisement inherits ATOMIC from its bestpath")
    r4 = tgen.gears["r4"]

    def _merged_atomic():
        path_list = paths(r4)
        if (
            len(path_list) == 1
            and path_list[0].get("aspath", {}).get("string", "")
            == "65000 {65100,65200}"
            and path_list[0].get("atomicAggregate")
        ):
            return None
        return json.dumps(summary(path_list), sort_keys=True)

    _, result = topotest.run_and_expect(_merged_atomic, None, count=120, wait=0.5)
    observed = summary(paths(r4))
    print(f"SWAPPED_OUTPUT={json.dumps(observed, sort_keys=True)}")
    assert result is None, f"Swapped merged advertisement: {result}"


def test_multipath_atomic_removed():
    step("Make the ATOMIC-carrying path non-best again")
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)
    for name, as_number, router_id in (
        ("r2", 65100, "10.255.0.2"),
        ("r3", 65200, "10.255.0.3"),
    ):
        tgen.gears[name].vtysh_cmd(
            f"configure terminal\nrouter bgp {as_number}\nbgp router-id {router_id}"
        )

    def _non_best_has_atomic():
        path_list = paths(tgen.gears["r1"])
        best = [p for p in path_list if p.get("bestpath", {}).get("overall")]
        atomic = [p for p in path_list if p.get("atomicAggregate")]
        if (
            len(path_list) == 2
            and len(best) == 1
            and best[0].get("aspath", {}).get("string") == "65100"
            and len(atomic) == 1
            and atomic[0].get("aspath", {}).get("string") == "65200"
            and not atomic[0].get("bestpath", {}).get("overall")
        ):
            return None
        return json.dumps(summary(path_list), sort_keys=True)

    _, result = topotest.run_and_expect(
        _non_best_has_atomic, None, count=120, wait=0.5
    )
    assert result is None, f"ATOMIC-carrying path did not become non-best: {result}"

    step("Remove ATOMIC from the non-best path")
    tgen.gears["r3"].vtysh_cmd(
        "configure terminal\n"
        "route-map SET_ATOMIC permit 10\n"
        " no set atomic-aggregate"
    )

    def _merged_without_atomic(router, input_router):
        path_list = paths(router)
        best = [p for p in path_list if p.get("bestpath", {}).get("overall")]
        if input_router:
            ready = (
                len(path_list) == 2
                and len(best) == 1
                and len([p for p in path_list if p.get("multipath")]) == 2
                and not any(p.get("atomicAggregate") for p in path_list)
            )
        else:
            ready = (
                len(path_list) == 1
                and len(best) == 1
                and path_list[0].get("aspath", {}).get("string")
                == "65000 {65100,65200}"
                and not path_list[0].get("atomicAggregate")
            )
        if ready:
            return None
        return json.dumps(summary(path_list), sort_keys=True)

    r1 = tgen.gears["r1"]
    _, result = topotest.run_and_expect(
        lambda: _merged_without_atomic(r1, True), None, count=60, wait=0.5
    )
    print(f"NO_ATOMIC_INPUT={json.dumps(summary(paths(r1)), sort_keys=True)}")
    assert result is None, f"ATOMIC was not removed from the input: {result}"

    r4 = tgen.gears["r4"]
    _, result = topotest.run_and_expect(
        lambda: _merged_without_atomic(r4, False), None, count=60, wait=0.5
    )
    print(f"NO_ATOMIC_OUTPUT={json.dumps(summary(paths(r4)), sort_keys=True)}")
    assert result is None, f"ATOMIC became sticky in merged output: {result}"


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
