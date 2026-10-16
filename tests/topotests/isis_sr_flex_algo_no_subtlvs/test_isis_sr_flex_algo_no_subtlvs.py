#!/usr/bin/env python
# SPDX-License-Identifier: ISC

# Copyright (c) 2026 Minghan Chan <mhchann082@gmail.com>

"""
IS-IS Flex-Algo SPF over a link that is advertised without sub-TLVs.

An Extended IS Reachability entry may carry no sub-TLV at all (RFC 5305
section 3), and isisd then leaves its sub-TLV pointer NULL. The Flex-Algo
SPF dereferenced it while looking for the link's admin groups, so every
router taking part in the algorithm crashed on its first SPF run.

FRR sends such an entry itself for a link that has neither MPLS-TE nor an
Adj-SID. The rt2-rt3 link below is unnumbered: each end only has its own
loopback address, so no IPv4 Adj-SID can be allocated, and mpls-te is off on
both routers. rt2 and rt3 meet that link in their own LSP, rt1 in rt2's LSP;
the two are separate code paths in the SPF.

rt1 advertises three definitions. A link without sub-TLVs has no admin group,
so 128 (no constraint) and 129 (exclude-any blue) must keep it and 130
(include-any red) must drop it. The rt1-rt2 link has affinity red and stays
in all three.

         10.0.12.0/24, red             unnumbered
    rt1 ------------------- rt2 ------------------- rt3
    1.1.1.1/32              2.2.2.2/32              3.3.3.3/32
    mpls-te on              mpls-te off             mpls-te off
"""

import os
import sys
from functools import partial

import pytest

CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

# pylint: disable=C0413
from lib import topotest
from lib.topogen import Topogen, get_topogen

pytestmark = [pytest.mark.isisd]


def setup_module(mod):
    topodef = {"s1": ("rt1", "rt2"), "s2": ("rt2", "rt3")}
    tgen = Topogen(topodef, mod.__name__)
    tgen.start_topology()

    for router in tgen.routers().values():
        router.load_frr_config(os.path.join(CWD, "{}/frr.conf".format(router.name)))

    tgen.start_router()


def teardown_module():
    get_topogen().stop_topology()


def spf_vertices(router, algorithm):
    "Vertices of the level-1 IPv4 SPF tree of a Flex-Algo."
    output = router.vtysh_cmd(
        "show isis route algorithm {} json".format(algorithm), isjson=True
    )
    vertices = set()
    for area in output if isinstance(output, list) else []:
        for path in area.get("level-1", {}).get("ipv4-paths", []):
            vertices.add(path["vertex"])
    return vertices


def check_spf(router, expected):
    """
    expected maps an algorithm to (vertices that must be in its SPF tree,
    vertices that must not be). Returns None when every algorithm matches.
    """
    errors = []
    for algorithm, (present, absent) in expected.items():
        vertices = spf_vertices(router, algorithm)
        missing = present - vertices
        unexpected = absent & vertices
        if missing or unexpected:
            errors.append(
                "algorithm {}: missing {}, unexpected {} (got {})".format(
                    algorithm, sorted(missing), sorted(unexpected), sorted(vertices)
                )
            )
    return "; ".join(errors) or None


def assert_no_crash(tgen):
    # The bug is a crash: report it as one, rather than as whatever check
    # happened to time out while isisd was gone.
    assert not tgen.routers_have_failure(), tgen.errors


def test_link_without_subtlvs():
    "rt2 advertises the unnumbered link to rt3 without any sub-TLV."
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    def _check():
        output = tgen.gears["rt1"].vtysh_cmd(
            "show isis database detail rt2.00-00 json", isjson=True
        )
        for area in output.get("areas", []):
            for level in area.get("levels", []):
                for lsp in level.get("lsps", []):
                    for reach in lsp.get("extReach", []):
                        if reach.get("id") != "0000.0000.0003.00":
                            continue
                        # Any sub-TLV would show up as another key.
                        if set(reach) == {"mtId", "id", "metric"}:
                            return None
                        return "the link carries sub-TLVs: {}".format(reach)
        return "rt2 does not advertise the link to rt3 yet"

    _, result = topotest.run_and_expect(_check, None, count=60, wait=1)
    assert_no_crash(tgen)
    assert result is None, result


def test_flex_algo_spf_neighbor_lsp():
    "rt1 runs the Flex-Algo SPF over rt2's link without sub-TLVs."
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    expected = {
        128: ({"rt2", "rt3", "2.2.2.2/32", "3.3.3.3/32"}, set()),
        129: ({"rt2", "rt3", "2.2.2.2/32", "3.3.3.3/32"}, set()),
        130: ({"rt2", "2.2.2.2/32"}, {"rt3", "3.3.3.3/32"}),
    }
    test_func = partial(check_spf, tgen.gears["rt1"], expected)
    _, result = topotest.run_and_expect(test_func, None, count=60, wait=1)
    assert_no_crash(tgen)
    assert result is None, "rt1: {}".format(result)


def test_flex_algo_spf_own_lsp():
    "rt3 runs the Flex-Algo SPF over its own link without sub-TLVs."
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    expected = {
        128: ({"rt1", "rt2", "1.1.1.1/32", "2.2.2.2/32"}, set()),
        129: ({"rt1", "rt2", "1.1.1.1/32", "2.2.2.2/32"}, set()),
        130: ({"rt3", "3.3.3.3/32"}, {"rt2", "rt1", "1.1.1.1/32"}),
    }
    test_func = partial(check_spf, tgen.gears["rt3"], expected)
    _, result = topotest.run_and_expect(test_func, None, count=60, wait=1)
    assert_no_crash(tgen)
    assert result is None, "rt3: {}".format(result)


def test_memory_leak():
    "Run the memory leak test and report results."
    tgen = get_topogen()
    if not tgen.is_memleak_enabled():
        pytest.skip("Memory leak test/report is disabled")

    tgen.report_memory_leaks()


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
