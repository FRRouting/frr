#!/usr/bin/env python
# SPDX-License-Identifier: ISC

"""
Test IS-IS distributed flooding reduction (draft-ietf-lsr-distoptflood).

Leaf-spine topology: spines s1 and s2 are each linked to all of the
leaves l1, l2, l3 and l4.

All links are point-to-point and every router has "flood-reduction"
configured. Both spines are adjacent to every leaf, so an LSP
originated by a leaf has no two-hop neighbors left to cover once it
reaches another leaf: the other leaves must never reflood it.
"""

import functools
import json
import os
import re
import sys

import pytest

CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

# pylint: disable=C0413
from lib import topotest
from lib.topogen import Topogen, get_topogen

pytestmark = [pytest.mark.isisd]

SPINES = ("s1", "s2")
LEAVES = ("l1", "l2", "l3", "l4")
ROUTERS = SPINES + LEAVES
NEIGHBORS = {r: set(LEAVES) for r in SPINES}
NEIGHBORS.update({r: set(SPINES) for r in LEAVES})
# System IDs from the routers' NETs, as printed in extended IS reachability
SYSIDS = {
    "0000.0000.0001": "s1",
    "0000.0000.0002": "s2",
    "0000.0000.0011": "l1",
    "0000.0000.0012": "l2",
    "0000.0000.0013": "l3",
    "0000.0000.0014": "l4",
}


def build_topo(tgen):
    for router in ROUTERS:
        tgen.add_router(router)
    for spine in SPINES:
        for leaf in LEAVES:
            tgen.add_link(
                tgen.gears[spine], tgen.gears[leaf], "eth-" + leaf, "eth-" + spine
            )


def setup_module(mod):
    tgen = Topogen(build_topo, mod.__name__)
    tgen.start_topology()

    for router in tgen.routers().values():
        router.load_frr_config()

    tgen.start_router()


def teardown_module():
    get_topogen().stop_topology()


def _lsdb(router):
    """{lsp id: (seqno, checksum)} of the level-2 LSPDB"""
    output = json.loads(router.vtysh_cmd("show isis database json"))
    rv = {}
    for area in output.get("areas", []):
        for level in area["levels"]:
            if level["id"] != 2:
                continue
            for lsp in level.get("lsps", []):
                rv[lsp["lsp"]["id"]] = (lsp["seqNumber"], lsp["chksum"])
    return rv


def _find_ext_reach(obj):
    """All extended IS reachability entries found anywhere in obj"""
    if isinstance(obj, dict):
        for key, value in obj.items():
            if key == "extReach" and isinstance(value, list):
                yield from value
            else:
                yield from _find_ext_reach(value)
    elif isinstance(obj, list):
        for value in obj:
            yield from _find_ext_reach(value)


def _check_topology_complete(router):
    """
    Every router's LSP advertises exactly its expected neighbors. Until
    then, LSPs originated before the adjacencies came up may still be
    waiting on lsp-gen-interval to be regenerated.
    """
    output = json.loads(router.vtysh_cmd("show isis database detail json"))
    reach = {}
    for area in output.get("areas", []):
        for level in area["levels"]:
            if level["id"] != 2:
                continue
            for lsp in level.get("lsps", []):
                name = lsp["lsp"]["id"].split(".")[0]
                reach[name] = {
                    SYSIDS.get(r["id"][:14], r["id"]) for r in _find_ext_reach(lsp)
                }
    for name in ROUTERS:
        if reach.get(name) != NEIGHBORS[name]:
            return "{} LSP advertises {}, expected {}".format(
                name, sorted(reach.get(name, ())), sorted(NEIGHBORS[name])
            )
    return None


def _check_lsdbs_synced(tgen, previous=None):
    """
    All routers hold one LSP per router and agree on its contents.
    If previous is given, the LSPs that differ from it must be exactly
    the ones listed in the "changed" key.
    """
    expected_ids = {"{}.00-00".format(r) for r in ROUTERS}
    result = _check_topology_complete(tgen.gears[ROUTERS[0]])
    if result:
        return result
    reference = _lsdb(tgen.gears[ROUTERS[0]])
    if set(reference) != expected_ids:
        return "{} LSPDB: {}, expected {}".format(
            ROUTERS[0], sorted(reference), sorted(expected_ids)
        )
    for name in ROUTERS[1:]:
        lsdb = _lsdb(tgen.gears[name])
        if lsdb != reference:
            return "{} LSPDB {} differs from {} LSPDB {}".format(
                name, lsdb, ROUTERS[0], reference
            )
    if previous is not None:
        changed = {i for i in reference if reference[i] != previous["lsdb"][i]}
        if changed != previous["changed"]:
            return "changed LSPs: {}, expected {}".format(
                sorted(changed), sorted(previous["changed"])
            )
    return None


def _wait_lsdbs_synced(tgen, previous=None):
    test_func = functools.partial(_check_lsdbs_synced, tgen, previous)
    _, result = topotest.run_and_expect(test_func, None, count=60, wait=1)
    assert result is None, result


def _lsp_tx_count(router):
    output = json.loads(router.vtysh_cmd("show isis summary json"))
    return output["vrfs"][0]["areas"][0]["tx-pdu-type"].get("l2-lsp", 0)


def _log_has(router, pattern):
    logfile = os.path.join(router.gearlogdir, "isisd.log")
    with open(logfile, "r") as f:
        return any(re.search(pattern, line) for line in f)


def test_flood_reduction_configured():
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    for name in ROUTERS:
        config = tgen.gears[name].vtysh_cmd("show running-config")
        assert re.search(r"^ flood-reduction$", config, re.M), (
            "{}: flood-reduction missing from running-config".format(name)
        )


def test_lsdb_converged():
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    _wait_lsdbs_synced(tgen)


def test_leaf_lsp_not_reflooded_by_leaves():
    """
    A new LSP from l1 reaches l2-l4 from the spines and must not be
    sent anywhere by them; it still has to reach every LSPDB.
    """
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    others = [name for name in LEAVES if name != "l1"]
    before = {name: _lsp_tx_count(tgen.gears[name]) for name in others}
    lsdb = _lsdb(tgen.gears["l1"])

    tgen.gears["l1"].vtysh_cmd(
        """
        configure terminal
        interface lo
         ip address 10.255.1.11/32
        """
    )
    _wait_lsdbs_synced(tgen, {"lsdb": lsdb, "changed": {"l1.00-00"}})

    for name in others:
        sent = _lsp_tx_count(tgen.gears[name]) - before[name]
        assert sent == 0, "{} sent {} LSPs, expected none".format(name, sent)

    for name in others:
        assert _log_has(
            tgen.gears[name],
            r"Flooding LSP 0000\.0000\.0011\.00-00 with reduction: .*suppressed [1-9]",
        ), "{}: no reduced flooding decision logged for l1's LSP".format(name)


def test_spine_lsp_flooded_with_reduction():
    """
    A new LSP from s1 must still reach s2, which only hears it through
    the leaf picked by the decision.
    """
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    lsdb = _lsdb(tgen.gears["s1"])
    tgen.gears["s1"].vtysh_cmd(
        """
        configure terminal
        interface eth-l1
         isis metric 20
        """
    )
    _wait_lsdbs_synced(tgen, {"lsdb": lsdb, "changed": {"s1.00-00"}})


def test_flood_reduction_disabled():
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    for name in ROUTERS:
        tgen.gears[name].vtysh_cmd(
            """
            configure terminal
            router isis 1
             no flood-reduction
            """
        )
        config = tgen.gears[name].vtysh_cmd("show running-config")
        assert not re.search(r"^ flood-reduction$", config, re.M), (
            "{}: flood-reduction still in running-config".format(name)
        )

    lsdb = _lsdb(tgen.gears["l1"])
    tgen.gears["l1"].vtysh_cmd(
        """
        configure terminal
        interface lo
         no ip address 10.255.1.11/32
        """
    )
    _wait_lsdbs_synced(tgen, {"lsdb": lsdb, "changed": {"l1.00-00"}})


def test_memory_leak():
    "Run the memory leak test and report results."
    tgen = get_topogen()
    if not tgen.is_memleak_enabled():
        pytest.skip("Memory leak test/report is disabled")

    tgen.report_memory_leaks()


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
