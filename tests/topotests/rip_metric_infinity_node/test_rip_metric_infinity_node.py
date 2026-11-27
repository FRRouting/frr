#!/usr/bin/env python
# SPDX-License-Identifier: ISC
#
# test_rip_metric_infinity_node.py
# Part of NetDEF Topology Tests
#
# Copyright (c) 2026 by
# Bing Shui <bingshui@smail.nju.edu.cn>
#

"""
test_rip_metric_infinity_node.py: RIPv2 metric-16 updates for new prefixes
must not leave route-less route nodes behind.

rip_rte_process() takes a node reference with route_node_get() before it
knows whether the route is usable.  When no matching route exists and the
metric is infinity (on-wire 15 or 16 plus interface cost), no rip_info is
created, so the node reference must be dropped again; otherwise every new
prefix leaves a permanently locked empty node in the RIP table, growing
memory and the per-update table walk until the process exits.

The empty node is invisible in "show ip rip", so the test counts route
node allocations in ripd ("show memory ripd json", Route node) and checks
the full lifecycle: leak-free infinity updates, duplicates, invalid
metrics, normal finite-metric routes, and poison/withdraw with GC.
"""

import json
import os
import sys
import time
import pytest
from functools import partial

CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

from lib import topotest
from lib.topogen import Topogen, get_topogen
from lib.topolog import logger

pytestmark = [pytest.mark.ripd]

# RFC 2544 benchmarking space, subnetted into /24s.
INFINITY16 = ["198.18.{}.0".format(i) for i in range(0, 32)]
INFINITY15 = ["198.18.{}.0".format(i) for i in range(32, 64)]
INVALID = ["198.18.{}.0".format(i) for i in range(64, 72)]
FINITE = ["198.18.{}.0".format(i) for i in range(72, 88)]
POISON = FINITE[:8]


def build_topo(tgen):
    "Victim r1 and injector r2, directly connected."
    r1 = tgen.add_router("r1")
    r2 = tgen.add_router("r2")
    tgen.add_link(r1, r2)


def setup_module(module):
    "Setup topology and load integrated config (frr.conf)."
    tgen = Topogen(build_topo, module.__name__)
    tgen.start_topology()

    for router in tgen.routers().values():
        router.load_frr_config()

    tgen.start_router()


def teardown_module(_mod):
    "Teardown the pytest environment"
    tgen = get_topogen()
    tgen.stop_topology()


def route_node_count(router):
    "Current Route node allocations in ripd, or None."
    out = json.loads(router.vtysh_cmd("show memory ripd json"))
    for group in out.get("ripd", {}).values():
        for mt in group:
            if mt.get("name") == "Route node":
                return mt["currentAllocations"]
    return None


def wait_node_count(router, predicate, count=30, wait=1):
    "Poll until `predicate(current)` is true; returns None or an error string."

    def _check():
        current = route_node_count(router)
        if current is not None and predicate(current):
            return None
        return "Route node count {} did not reach expected value".format(current)

    _, result = topotest.run_and_expect(_check, None, count=count, wait=wait)
    return result


def inject(r2, entries):
    "Send RIPv2 RESPONSEs for [prefix, metric] pairs from r2."
    spec = json.dumps(entries)
    r2.run(
        "python3 {}/rip_inject.py r2-eth0 '{}'".format(CWD, spec),
        warn=False,
    )


def test_rip_metric_infinity_node_duplicate_and_invalid():
    "Duplicates of one prefix and out-of-range metrics must not add nodes."
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]
    r2 = tgen.gears["r2"]

    # First advertisement of the prefix may create a node (unpatched) or
    # none (patched); only the duplicates must not add anything.
    inject(r2, [[INFINITY16[0], 16]])
    time.sleep(1)
    after_first = route_node_count(r1)

    inject(r2, [[INFINITY16[0], 16]] * 15)
    result = wait_node_count(r1, lambda c: c == after_first)
    assert result is None, "duplicate updates moved node count: {}".format(
        result
    )

    inject(r2, [[p, 100] for p in INVALID])
    result = wait_node_count(r1, lambda c: c == after_first)
    assert result is None, "invalid metrics moved node count: {}".format(
        result
    )


def test_rip_metric_infinity_node_finite_and_poison():
    "Finite-metric routes install normally; poison withdraws and GC frees."
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]
    r2 = tgen.gears["r2"]

    base = route_node_count(r1)

    # Each new route holds at least its own route node.
    inject(r2, [[p, 2] for p in FINITE])
    time.sleep(2)
    result = wait_node_count(r1, lambda c: c >= base + len(FINITE))
    assert result is None, "finite-metric routes missing: {}".format(result)

    for prefix in FINITE:
        expected = {prefix + "/24": [{"protocol": "rip"}]}
        test_func = partial(
            topotest.router_json_cmp, r1, "show ip route {} json".format(prefix),
            expected,
        )
        _, result = topotest.run_and_expect(test_func, None, count=20, wait=1)
        assert result is None, "{} not installed via zebra: {}".format(
            prefix, result
        )

    # Poison: metric-16 for existing routes.  zebra DELETE is immediate,
    # the garbage collector frees the nodes after garbage time (10s).
    after_finite = route_node_count(r1)
    inject(r2, [[p, 16] for p in POISON])
    for prefix in POISON:
        expected = {prefix + "/24": None}
        test_func = partial(
            topotest.router_json_cmp, r1, "show ip route {} json".format(prefix),
            expected,
        )
        _, result = topotest.run_and_expect(test_func, None, count=20, wait=1)
        assert result is None, "{} not withdrawn from zebra: {}".format(
            prefix, result
        )

    # Each withdrawn route frees at least its own route node.
    result = wait_node_count(
        r1, lambda c: c <= after_finite - len(POISON), count=30, wait=1
    )
    assert result is None, "GC did not free poisoned nodes: {}".format(result)


def test_rip_metric_infinity_node_no_leak():
    "Metric-16 updates for new prefixes must not leave empty route nodes."
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]
    r2 = tgen.gears["r2"]

    base = route_node_count(r1)
    assert base is not None, "cannot read ripd Route node count"

    # 64 new prefixes: on-wire metric 16 (stays 16) and 15 (+1 cost -> 16).
    inject(r2, [[p, 16] for p in INFINITY16] + [[p, 15] for p in INFINITY15])
    time.sleep(2)

    result = wait_node_count(r1, lambda c: c == base)
    assert result is None, "metric-16 updates leaked route nodes: {}".format(
        result
    )

    # The prefixes must not have become routes either.
    out = r1.vtysh_cmd("show ip rip")
    leaked = [p for p in INFINITY16 + INFINITY15 if p in out]
    assert not leaked, "infinity prefixes visible in 'show ip rip': {}".format(
        leaked
    )


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
