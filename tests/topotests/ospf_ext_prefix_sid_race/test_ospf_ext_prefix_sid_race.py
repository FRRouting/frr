#!/usr/bin/env python
# SPDX-License-Identifier: ISC

#
# test_ospf_ext_prefix_sid_race.py
# Part of NetDEF Topology Tests
#
# Copyright (c) 2026 by
# Wataru Mishima <watal.i27e@gmail.com>
#

"""
test_ospf_ext_prefix_sid_race.py:

Regression test for malformed Extended Prefix Opaque-LSA origination
when a Prefix-SID candidate has no Prefix-SID configured.
"""

from lib.topogen import Topogen, get_topogen
from lib import topotest
import os
import sys

import pytest

CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

# pylint: disable=C0413

pytestmark = [pytest.mark.ospfd]


def build_topo(tgen):
    "Build the topology: r1 <-> r2 over a single switch"
    tgen.add_router("r1")
    tgen.add_router("r2")

    switch = tgen.add_switch("s1")
    switch.add_link(tgen.gears["r1"])
    switch.add_link(tgen.gears["r2"])


def setup_module(mod):
    tgen = Topogen(build_topo, mod.__name__)
    tgen.start_topology()

    for rname, router in tgen.routers().items():
        router.load_frr_config(os.path.join(CWD, "{}/frr.conf".format(rname)))

    tgen.start_router()


def teardown_module():
    tgen = get_topogen()
    tgen.stop_topology()


def opaque_area_lsas(router, area="0.0.0.0"):
    "Return the list of Area-Local Opaque-LSAs in `area`"
    output = router.vtysh_cmd(
        "show ip ospf database opaque-area json", isjson=True
    )
    return output.get("areaLocalOpaqueLsa", {}).get("areas", {}).get(area, [])


def find_lsa(lsas, opaque_type):
    "Return the first LSA of `opaque_type` in `lsas`, or None"
    for lsa in lsas:
        if lsa.get("opaqueType") == opaque_type:
            return lsa
    return None


def test_ospf_convergence():
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    tgen.gears["r1"].expect_ospfv2_neighbor("2.2.2.2")
    tgen.gears["r2"].expect_ospfv2_neighbor("1.1.1.1")


def test_no_extended_prefix_lsa_without_prefix_sid():
    """
    Verify that the Opaque-LSA origination batch does not produce an
    Extended Prefix Opaque-LSA for a loopback without a configured
    Prefix-SID or otherwise produce a malformed self-originated LSA.
    """
    tgen = get_topogen()
    r1 = tgen.gears["r1"]

    def extended_link_lsa_exists():
        return (
            find_lsa(opaque_area_lsas(r1), "Extended Link Opaque LSA")
            is not None
        )

    _, result = topotest.run_and_expect(
        extended_link_lsa_exists, True, count=60, wait=1
    )
    assert result, "r1 never originated its Extended Link Opaque-LSA"

    lsas = opaque_area_lsas(r1)
    for lsa in lsas:
        assert lsa.get("opaqueLengthValid", True), (
            "Malformed Opaque-LSA {} (link-state-id {}) on r1: declared "
            "TLV length exceeds the LSA body".format(
                lsa.get("opaqueType"), lsa.get("linkStateId")
            )
        )

    assert find_lsa(lsas, "Extended Prefix Opaque LSA") is None, (
        "r1 originated an Extended Prefix Opaque-LSA for a loopback "
        "that was never assigned a Prefix-SID"
    )


def test_prefix_sid_after_configuration():
    "Prefix-SID origination must still work once actually configured"
    tgen = get_topogen()
    r1 = tgen.gears["r1"]

    r1.vtysh_multicmd(
        [
            "configure terminal",
            "router ospf",
            "segment-routing prefix 1.1.1.1/32 index 10",
        ]
    )

    def configured_index():
        lsa = find_lsa(opaque_area_lsas(r1), "Extended Prefix Opaque LSA")
        if lsa is None:
            return None
        return lsa["opaqueValues"]["extendedPrefix"]["prefixSID"]["index"]

    _, result = topotest.run_and_expect(
        configured_index, 10, count=60, wait=1
    )
    assert result == 10, "r1 failed to originate the configured Prefix-SID LSA"

    lsa = find_lsa(opaque_area_lsas(r1), "Extended Prefix Opaque LSA")
    assert lsa["opaqueLengthValid"] is True
    assert lsa["opaqueValues"]["extendedPrefix"]["address"] == "1.1.1.1"
    assert lsa["opaqueValues"]["extendedPrefix"]["prefixLength"] == 32


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
