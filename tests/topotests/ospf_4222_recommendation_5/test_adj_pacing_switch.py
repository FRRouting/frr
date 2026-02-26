#!/usr/bin/env python3
# SPDX-License-Identifier: ISC

import os
import sys
import time
import pytest
import json

# CWD = os.path.dirname(os.path.realpath(__file__))
# sys.path.append(os.path.join(CWD, "../"))

# ensure topotests dir on sys.path
sys.path.insert(0, os.path.dirname(__file__))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
CWD = os.getcwd()


from lib import topotest
from lib.topogen import Topogen, TopoRouter, get_topogen
from lib.topolog import logger

pytestmark = [pytest.mark.ospfd]

def _vty(router, cmd):
    return get_topogen().gears[router].vtysh_cmd(cmd)

def _collect_neighbors(obj):
    found = []
    if isinstance(obj, dict):
        if "neighbors" in obj:
            nb = obj["neighbors"]
            if isinstance(nb, dict):
                for nbr_id, v in nb.items():
                    if isinstance(v, list):
                        for item in v:
                            if isinstance(item, dict):
                                item = dict(item)
                                item.setdefault("nbrId", nbr_id)
                                found.append(item)
                    elif isinstance(v, dict):
                        v = dict(v)
                        v.setdefault("nbrId", nbr_id)
                        found.append(v)
            elif isinstance(nb, list):
                for v in nb:
                    if isinstance(v, dict):
                        found.append(v)
        for v in obj.values():
            found.extend(_collect_neighbors(v))
    elif isinstance(obj, list):
        for v in obj:
            found.extend(_collect_neighbors(v))
    return found

def build_topo(tgen):
    # Routers
    for n in range(1, 6):
        tgen.add_router(f"r{n}")

    # Single broadcast segment: r1-eth0 has multiple adjacencies
    sw = tgen.add_switch("s1")
    sw.add_link(tgen.gears["r1"])
    sw.add_link(tgen.gears["r2"])
    sw.add_link(tgen.gears["r3"])
    sw.add_link(tgen.gears["r4"])
    sw.add_link(tgen.gears["r5"])


def setup_module(mod):
    tgen = Topogen(build_topo, mod.__name__)
    tgen.start_topology()

    router_list = tgen.routers()
    for rname, router in router_list.items():
        router.load_frr_config(os.path.join(CWD, rname, "frr.conf"))

    tgen.start_router()


def teardown_module():
    tgen = get_topogen()
    tgen.stop_topology()


# def _neighbor_states(router):
#     tgen = get_topogen()
#     data = tgen.gears[router].vtysh_cmd("show ip ospf neighbor json", isjson=True)
#     states = []
#     if not isinstance(data, dict):
#         return states
#     neighbors = data.get("neighbors", {})
#     if isinstance(neighbors, dict):
#         for _, lst in neighbors.items():
#             if isinstance(lst, list):
#                 for item in lst:
#                     st = item.get("state") or item.get("nbrState") or item.get("converged")
#                     if st:
#                         states.append(st)
#     return states

def neighbor_states(router):
    raw = _vty(router, "show ip ospf neighbor json")
    try:
        data = json.loads(raw) if raw.strip() else {}
    except json.JSONDecodeError:
        return {}

    states = {}
    for n in _collect_neighbors(data):
        nbr_id = n.get("nbrId") or n.get("neighborId") or n.get("neighborRouterId") or n.get("neighbors")
        if not nbr_id:
            nbr_id = n.get("routerId")
        st = n.get("nbrState") or n.get("state") or ""
        if nbr_id:
            states[nbr_id] = st
    return states

def test_adj_pacing_n1_serializes_exstart():
    tgen = get_topogen()
    full_seen = set()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    # Poll until all neighbors are Full, while asserting at most 1 in-progress.
    deadline = time.time() + 60
    while time.time() < deadline:
        states = neighbor_states("r1")
        
        for rid, st in states.items():
            if isinstance(st, str) and st.startswith("Full"):
                full_seen.add(rid)
        logger.info("Full state neighbors so far: %s", len(full_seen)," list ", full_seen)


        # count in-progress adjacencies
        in_progress = sum(1 for s in states if s in ("ExStart", "Exchange", "Loading"))
        assert in_progress <= 1, f"more than one adjacency in progress: {states}"

        # all full?
        full = sum(1 for s in states if s.startswith("Full"))
        if full >= 5:
            break
        time.sleep(1)

    assert full >= 5, "not all neighbors reached Full on r1"
