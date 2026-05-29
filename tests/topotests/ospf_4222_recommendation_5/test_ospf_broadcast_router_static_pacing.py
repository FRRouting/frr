#!/usr/bin/env python
# SPDX-License-Identifier: ISC
#
# test_ospf_broadcast_2router_static_constraint.py
# Test RFC4222 Rec5 static adjacency pacing with constrained link
#

import os
import sys
from functools import partial
import pytest
from time import sleep

# pylint: disable=C0413
from lib import topotest
from lib.topogen import Topogen, get_topogen
from lib.topolog import logger
from lib.common_config import step
from util_pcap import PerInterfacePcapManager

TOPOLOGY = """
                  +-----+  +-----+  +-----+  +-----+
                  | r2  |  | r3  |  | r4  |  | r5  |
                  +--+--+  +--+--+  +--+--+  +--+--+
                     |        |        |        |
        +-----+      +--------+--------+--------+--------+
        | r1  |--------------- 198.51.100.0/24 (s0)
        +--+--+
           |
           |         +-----+  +-----+
           +---------| r6  |  | r7  |
                     +--+--+  +--+--+
                        |        |
                        +--------+-------- 198.51.101.0/24 (s1)
"""

CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

pytestmark = [pytest.mark.ospfd]
PM = None


def build_topo(tgen):
    tgen.add_router("r1")
    tgen.add_router("r2")
    tgen.add_router("r3")
    tgen.add_router("r4")
    tgen.add_router("r5")
    tgen.add_router("r6")
    tgen.add_router("r7")

    switch = tgen.add_switch("s0")
    switch.add_link(tgen.gears["r1"])
    switch.add_link(tgen.gears["r2"])
    switch.add_link(tgen.gears["r3"])
    switch.add_link(tgen.gears["r4"])
    switch.add_link(tgen.gears["r5"])

    switch = tgen.add_switch("s1")
    switch.add_link(tgen.gears["r1"])
    switch.add_link(tgen.gears["r6"])
    switch.add_link(tgen.gears["r7"])


def setup_module(mod):
    logger.info("OSPF broadcast static topology:\n %s", TOPOLOGY)

    tgen = Topogen(build_topo, mod.__name__)
    tgen.start_topology()

    r1 = tgen.gears["r1"]
    r1.cmd("tc qdisc add dev r1-eth0 root handle 1: tbf rate 10kbit burst 10kb latency 50ms")
    r1.cmd("tc qdisc add dev r1-eth0 parent 1:1 handle 10: netem loss 1% delay 5ms")

    router_list = tgen.routers()
    for rname, router in router_list.items():
        if rname == "r1":
            router.load_frr_config(
                os.path.join(CWD, "r1_broadcast_static", "frr.conf")
            )
        elif rname == "r2":
            router.load_frr_config(os.path.join(CWD, "r2_broadcast", "frr.conf"))
        elif rname == "r3":
            router.load_frr_config(os.path.join(CWD, "r3_broadcast", "frr.conf"))
        elif rname == "r4":
            router.load_frr_config(os.path.join(CWD, "r4_broadcast", "frr.conf"))
        elif rname == "r5":
            router.load_frr_config(os.path.join(CWD, "r5_broadcast", "frr.conf"))
        elif rname == "r6":
            router.load_frr_config(os.path.join(CWD, "r6_broadcast", "frr.conf"))
        elif rname == "r7":
            router.load_frr_config(os.path.join(CWD, "r7_broadcast", "frr.conf"))

    tgen.start_router()

    global PM
    PM = PerInterfacePcapManager(outdir="pcaps", tag="ospf4-static")
    PM.start_all(tgen)
    for (rname, ifn), pid in list(PM.pids.items()):
        if rname != "r1":
            router = tgen.routers().get(rname)
            if router:
                router.cmd(f"kill -TERM {pid} >/dev/null 2>&1 || true")
                router.cmd(f"kill -KILL {pid} >/dev/null 2>&1 || true")
            PM.pids.pop((rname, ifn), None)


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


def wait_for_ospf_ifname_by_ip(topo_router, ip):
    ifname_holder = {}

    def _poll():
        data = topo_router.vtysh_cmd("show ip ospf interface json", isjson=True)
        interfaces = data.get("interfaces", {})
        for ifname, attrs in interfaces.items():
            if attrs.get("ipAddress") == ip:
                ifname_holder["name"] = ifname
                return None
        return "missing"

    _, result = topotest.run_and_expect(_poll, None, count=60, wait=1)
    assert result is None, f"No OSPF interface with IP {ip} on {topo_router.name}"
    return ifname_holder["name"]


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
    assert result is None, f"Neighbor {neighbor_id} not FULL on {router}"


def verify_broadcast_interface(
    tgen, router, ifname, ip, router_id, nbr_cnt, nbr_adj_cnt, state=None
):
    topo_router = tgen.gears[router]

    step(f"Verify {router} broadcast interface settings")
    iface = {
        "ospfEnabled": True,
        "ipAddress": ip,
        "ipAddressPrefixlen": 24,
        "ospfIfType": "Broadcast",
        "area": "0.0.0.0",
        "routerId": router_id,
        "networkType": "BROADCAST",
        "nbrCount": nbr_cnt,
        "nbrAdjacentCount": nbr_adj_cnt,
    }
    if state:
        iface["state"] = state
    input_dict = {"interfaces": {ifname: iface}}
    test_func = partial(
        topotest.router_json_cmp,
        topo_router,
        f"show ip ospf interface {ifname} json",
        input_dict,
    )
    _, result = topotest.run_and_expect(test_func, None, count=60, wait=1)
    assert result is None, f"Broadcast interface mismatch on {router}"


def verify_adjacency_static_pacing(tgen, router, ifname, limit):
    step(f"Verify {router} adjacency pacing static {limit} on {ifname}")
    cmd = (
        f"vtysh -c 'show running ospfd' | "
        f"awk -v ifname='{ifname}' "
        "'($1==\"interface\" && $2==ifname){f=1} "
        "($1==\"interface\" && $2!=ifname){f=0} "
        "($1==\"exit\" || $1==\"!\"){f=0} "
        "f{print}' | "
        f"grep -q 'ip ospf adjacency-pacing static {limit}'"
    )
    rc, _, _ = tgen.net[router].cmd_status(cmd, warn=False)
    assert rc == 0, f"adjacency pacing static {limit} not present on {router} {ifname}"


def verify_dynamic_adjacency_pacing(tgen, router, ifname):
    step(f"Verify {router} adjacency pacing dynamic on {ifname}")
    rc, _, _ = tgen.net[router].cmd_status(
        f"vtysh -c 'show running ospfd' | grep -q 'ip ospf adjacency-pacing dynamic'",
        warn=False,
    )
    assert rc == 0, f"adjacency pacing dynamic not present on {router} {ifname}"


def test_ospf_broadcast_static_pacing_neighbors_full():
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1_if = wait_for_ospf_ifname_by_ip(tgen.gears["r1"], "198.51.100.1")
    r2_if = wait_for_ospf_ifname(tgen.gears["r2"])
    r3_if = wait_for_ospf_ifname(tgen.gears["r3"])
    r4_if = wait_for_ospf_ifname(tgen.gears["r4"])
    r5_if = wait_for_ospf_ifname(tgen.gears["r5"])
    r6_if = wait_for_ospf_ifname(tgen.gears["r6"])
    r7_if = wait_for_ospf_ifname(tgen.gears["r7"])
    r1_if2 = wait_for_ospf_ifname_by_ip(tgen.gears["r1"], "198.51.101.1")
    assert r1_if and r1_if2 and r2_if and r3_if and r4_if and r5_if and r6_if and r7_if

    verify_adjacency_static_pacing(tgen, "r1", r1_if, 1)
    verify_dynamic_adjacency_pacing(tgen, "r1", r1_if2)

    verify_broadcast_interface(
        tgen, "r1", r1_if, "198.51.100.1", "1.1.1.1", 4, 4, state="DR"
    )
    verify_broadcast_interface(
        tgen, "r2", r2_if, "198.51.100.2", "1.1.1.2", 4, 4, state="Backup"
    )
    verify_broadcast_interface(tgen, "r3", r3_if, "198.51.100.3", "1.1.1.3", 4, 2)
    verify_broadcast_interface(tgen, "r4", r4_if, "198.51.100.4", "1.1.1.4", 4, 2)
    verify_broadcast_interface(tgen, "r5", r5_if, "198.51.100.5", "1.1.1.5", 4, 2)

    verify_broadcast_interface(
        tgen, "r1", r1_if2, "198.51.101.1", "1.1.1.1", 2, 2, state="DR"
    )
    verify_broadcast_interface(
        tgen, "r6", r6_if, "198.51.101.2", "1.1.1.6", 2, 2, state="Backup"
    )
    verify_broadcast_interface(tgen, "r7", r7_if, "198.51.101.3", "1.1.1.7", 2, 2)

    wait_for_neighbor_full(tgen, "r1", "1.1.1.2")
    wait_for_neighbor_full(tgen, "r1", "1.1.1.3")
    wait_for_neighbor_full(tgen, "r1", "1.1.1.4")
    wait_for_neighbor_full(tgen, "r1", "1.1.1.5")
    wait_for_neighbor_full(tgen, "r1", "1.1.1.6")
    wait_for_neighbor_full(tgen, "r1", "1.1.1.7")
    wait_for_neighbor_full(tgen, "r2", "1.1.1.1")
    wait_for_neighbor_full(tgen, "r6", "1.1.1.1")
    wait_for_neighbor_full(tgen, "r6", "1.1.1.7")

    sleep(5)
