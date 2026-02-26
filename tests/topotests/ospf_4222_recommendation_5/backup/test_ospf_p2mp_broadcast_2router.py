#!/usr/bin/env python
# SPDX-License-Identifier: ISC
#
# test_ospf_p2mp_broadcast_2router.py
#
# Copyright (c) 2024 LabN Consulting
#

import os
import sys
from functools import partial
import pytest

# pylint: disable=C0413
from lib import topotest
from lib.topogen import Topogen, get_topogen
from lib.topolog import logger

from lib.common_config import step
from util_pcap import PerInterfacePcapManager

"""
Simplified 2-router OSPF P2MP broadcast test.
"""

TOPOLOGY = """
        +-----+  +-----+  +-----+  +-----+  +-----+
        | r1  |  | r2  |  | r3  |  | r4  |  | r5  |
        +--+--+  +--+--+  +--+--+  +--+--+  +--+--+
           |        |        |        |        |
           +--------+--------+--------+--------+
                     192.0.2.0/24 (s0)
"""

CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

pytestmark = [pytest.mark.ospfd]
PM = None


def build_topo(tgen):
    "Build function"
    tgen.add_router("r1")
    tgen.add_router("r2")
    tgen.add_router("r3")
    tgen.add_router("r4")
    tgen.add_router("r5")

    switch = tgen.add_switch("s0")
    switch.add_link(tgen.gears["r1"])
    switch.add_link(tgen.gears["r2"])
    switch.add_link(tgen.gears["r3"])
    switch.add_link(tgen.gears["r4"])
    switch.add_link(tgen.gears["r5"])


def setup_module(mod):
    logger.info("OSPF P2MP 2-router topology:\n %s", TOPOLOGY)

    tgen = Topogen(build_topo, mod.__name__)
    tgen.start_topology()

    router_list = tgen.routers()
    for rname, router in router_list.items():
        if rname == "r1":
            router.load_frr_config(os.path.join(CWD, "r1_br", "frr.conf"))
        elif rname == "r2":
            router.load_frr_config(os.path.join(CWD, "r2_br", "frr.conf"))
        elif rname == "r3":
            router.load_frr_config(os.path.join(CWD, "r3_br", "frr.conf"))
        elif rname == "r4":
            router.load_frr_config(os.path.join(CWD, "r4_br", "frr.conf"))
        elif rname == "r5":
            router.load_frr_config(os.path.join(CWD, "r5_br", "frr.conf"))

    tgen.start_router()

    global PM
    PM = PerInterfacePcapManager(outdir="pcaps", tag="ospf4")
    PM.start_all(tgen)


def teardown_module():
    tgen = get_topogen()
    global PM
    if PM:
        PM.stop_all(tgen)
    tgen.stop_topology()


def wait_for_ospf_ifname(topo_router):
    ifname_holder = {}

    def _poll():
        data = topo_router.vtysh_cmd("show ip ospf interface json", isjson=True)
        interfaces = data.get("interfaces", {})
        ifname = next(iter(interfaces.keys()), None)
        if ifname:
            ifname_holder["name"] = ifname
            return None
        return "missing"

    _, result = topotest.run_and_expect(_poll, None, count=60, wait=1)
    assert result is None, f"No OSPF interface found on {topo_router.name}"
    return ifname_holder["name"]


def verify_p2mp_interface(tgen, router, ifname, ip, router_id, nbr_cnt, nbr_adj_cnt):
    topo_router = tgen.gears[router]

    step(f"Verify {router} P2MP interface settings")
    input_dict = {
        "interfaces": {
            ifname: {
                "ospfEnabled": True,
                "ipAddress": ip,
                "ipAddressPrefixlen": 24,
                "ospfIfType": "Broadcast",
                "area": "0.0.0.0",
                "routerId": router_id,
                "networkType": "POINTOMULTIPOINT",
                "state": "Point-To-Point",
                "nbrCount": nbr_cnt,
                "nbrAdjacentCount": nbr_adj_cnt,
            }
        }
    }
    test_func = partial(
        topotest.router_json_cmp,
        topo_router,
        f"show ip ospf interface {ifname} json",
        input_dict,
    )
    _, result = topotest.run_and_expect(test_func, None, count=60, wait=1)
    assertmsg = f"P2MP interface mismatch on {router}"
    assert result is None, assertmsg


def wait_for_neighbor_full(tgen, router, neighbor_id):
    topo_router = tgen.gears[router]

    step(f"Verify {router} neighbor {neighbor_id} FULL")

    def _poll():
        data = topo_router.vtysh_cmd(
            f"show ip ospf neighbor {neighbor_id} json", isjson=True
        )
        nbr_list = data.get("default", {}).get(neighbor_id)
        if not nbr_list:
            return "missing"
        state = nbr_list[0].get("nbrState", "")
        if state.split("/", 1)[0] == "Full":
            return None
        return state or "unknown"

    _, result = topotest.run_and_expect(_poll, None, count=60, wait=1)
    assertmsg = f"Neighbor {neighbor_id} not FULL on {router}"
    assert result is None, assertmsg


def test_p2mp_5router_neighbors_full():
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1_if = wait_for_ospf_ifname(tgen.gears["r1"])
    r2_if = wait_for_ospf_ifname(tgen.gears["r2"])

    r3_if = wait_for_ospf_ifname(tgen.gears["r3"])
    r4_if = wait_for_ospf_ifname(tgen.gears["r4"])
    r5_if = wait_for_ospf_ifname(tgen.gears["r5"])

    verify_p2mp_interface(tgen, "r1", r1_if, "192.0.2.1", "1.1.1.1", 4, 4)
    verify_p2mp_interface(tgen, "r2", r2_if, "192.0.2.2", "1.1.1.2", 4, 4)
    verify_p2mp_interface(tgen, "r3", r3_if, "192.0.2.3", "1.1.1.3", 4, 4)
    verify_p2mp_interface(tgen, "r4", r4_if, "192.0.2.4", "1.1.1.4", 4, 4)
    verify_p2mp_interface(tgen, "r5", r5_if, "192.0.2.5", "1.1.1.5", 4, 4)

    wait_for_neighbor_full(tgen, "r1", "1.1.1.2")
    wait_for_neighbor_full(tgen, "r1", "1.1.1.3")
    wait_for_neighbor_full(tgen, "r1", "1.1.1.4")
    wait_for_neighbor_full(tgen, "r1", "1.1.1.5")
