#!/usr/bin/env python
# -*- coding: utf-8 eval: (blacken-mode 1) -*-
# SPDX-License-Identifier: ISC
#
# <template>.py
# Part of NetDEF Topology Tests
#
# Copyright (c) 2017 by
# Network Device Education Foundation, Inc. ("NetDEF")
#

"""
<template>.py: Test <template>.
"""

import sys
import os
import pytest
import json
import time
from time import sleep

sys.path.insert(0, os.path.dirname(__file__))  # ensure local dir on sys.path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from lib.topogen import Topogen, get_topogen, TopoRouter


def test_01_full_before_storm():
    assert neighbors_full("r1") and neighbors_full("r2")


from lib.topolog import logger
from util_pcap import PerInterfacePcapManager  # or from util_pcap import ...

CWD = os.getcwd()

# TODO: select markers based on daemons used during test
# pytest module level markers
pytestmark = [
    # pytest.mark.babeld,
    # pytest.mark.bfdd,
    # pytest.mark.bgpd,
    # pytest.mark.eigrpd,
    # pytest.mark.isisd,
    # pytest.mark.ldpd,
    # pytest.mark.nhrpd,
    # pytest.mark.ospf6d,
    pytest.mark.ospfd,
    # pytest.mark.pathd,
    # pytest.mark.pbrd,
    # pytest.mark.pimd,
    # pytest.mark.ripd,
    # pytest.mark.ripngd,
    # pytest.mark.sharpd,
    # pytest.mark.staticd,
    # pytest.mark.vrrpd,
]


def first_data_if(gear):
    # 1) Prefer classic topotest name: rN-eth0 (matches the router name)
    cand = f"{gear.name}-eth0"
    if gear.cmd(f"ip link show {cand} 2>/dev/null || true").strip():
        return cand

    # 2) Fall back to container-style: eth0
    if gear.cmd("ip link show eth0 2>/dev/null || true").strip():
        return "eth0"

    # 3) Last resort: first non-lo interface; strip '@peer' suffix (e.g. eth0@if5 -> eth0)
    name = gear.cmd("ip -o link | awk -F': ' '$2!=\"lo\"{print $2; exit}'").strip()
    return name.split("@", 1)[0] if name else None

def shape_link(
    r1,
    r2,
    *,
    rate="1mbit",
    delay="40ms",
    jitter=None,
    loss=None,
    fq=False,
    txqlen=20,
    wmem=32768,
    netem_limit=None,
):
    """
    Apply egress shaping on r1/r2 data IFs:
      - HTB rate cap at `rate`
      - netem delay `delay` (+ optional `jitter`, optional `loss`)
      - optional fq_codel under netem when fq=True
      - tx queue length and socket wmem tightened for faster backpressure
    """

    def one(gear):
        ifname = first_data_if(gear)
        assert ifname, f"no data iface in {gear.name}"

        # Root scheduler (rate)
        gear.cmd(f"tc qdisc replace dev {ifname} root handle 1: htb default 10")
        gear.cmd(
            f"tc class  replace dev {ifname} parent 1: classid 1:10 htb rate {rate} ceil {rate}"
        )

        # Child: netem (delay/jitter/loss)
        opt = f"delay {delay}"
        if jitter:
            opt += f" {jitter}"
        if loss:
            opt += f" loss {loss}"
        if netem_limit:
            opt += f" limit {netem_limit}"
        gear.cmd(f"tc qdisc replace dev {ifname} parent 1:10 handle 10: netem {opt}")

        # Small device TX queue
        gear.cmd(f"ip link set dev {ifname} txqueuelen {txqlen}")

        # Optional fair queueing (stacked after netem). If you hit syntax issues, skip it.
        if fq:
            gear.cmd(f"tc qdisc replace dev {ifname} parent 1:10 fq_codel")

        # Tighten socket send buffers (per netns)
        gear.cmd(f"sysctl -w net.core.wmem_default={wmem}")
        gear.cmd(f"sysctl -w net.core.wmem_max={wmem}")

    one(r1)
    one(r2)
    """
    def shape_prioritized(r, total="100kbit", ctrl="15kbit", data="85kbit", delay="100ms",
                      ctrl_limit=80, ack_limit=60, bulk_limit=40, txqlen=50):
    
    #Shape OSPF traffic with three priority levels:
    #- Highest (1:10): HELLO, DBD, LSR - adjacency critical
    #- Medium  (1:20): LSAck - reliability but not time-critical  
    #- Lowest  (1:30): LSU - bulk updates
    
    ifn = first_data_if(r)
    
    # Remove existing qdisc
    r.cmd(f"tc qdisc del dev {ifn} root 2>/dev/null || true")
    
    # Root qdisc with default to lowest priority
    r.cmd(f"tc qdisc replace dev {ifn} root handle 1: htb default 30")
    
    # Three priority classes
    r.cmd(f"tc class replace dev {ifn} parent 1: classid 1:10 htb rate {ctrl} ceil {total} prio 0")
    r.cmd(f"tc class replace dev {ifn} parent 1: classid 1:20 htb rate 10kbit ceil {total} prio 1")  
    r.cmd(f"tc class replace dev {ifn} parent 1: classid 1:30 htb rate {data} ceil {total} prio 2")
    
    # Apply netem with different queue limits
    r.cmd(f"tc qdisc replace dev {ifn} parent 1:10 handle 10: netem delay {delay} limit {ctrl_limit}")
    r.cmd(f"tc qdisc replace dev {ifn} parent 1:20 handle 20: netem delay {delay} limit {ack_limit}")
    r.cmd(f"tc qdisc replace dev {ifn} parent 1:30 handle 30: netem delay {delay} limit {bulk_limit}")
    
    # Clear old filters
    r.cmd(f"tc filter del dev {ifn} parent 1: 2>/dev/null || true")
    
    # Highest priority: Hello(1), DBD(2), LSR(3)
    for ospf_type in (1, 2, 3):
        r.cmd(f"tc filter add dev {ifn} parent 1: protocol ip prio 10 u32 "
              f"match ip protocol 89 0xff match u8 {ospf_type} 0xff at 21 flowid 1:10")
    
    # Medium priority: LSAck(5)
    r.cmd(f"tc filter add dev {ifn} parent 1: protocol ip prio 20 u32 "
          f"match ip protocol 89 0xff match u8 5 0xff at 21 flowid 1:20")
    
    # Lowest priority: LSU(4)
    r.cmd(f"tc filter add dev {ifn} parent 1: protocol ip prio 30 u32 "
          f"match ip protocol 89 0xff match u8 4 0xff at 21 flowid 1:30")
    
    # Catch-all for other OSPF traffic
    r.cmd(f"tc filter add dev {ifn} parent 1: protocol ip prio 40 u32 "
          f"match ip protocol 89 0xff flowid 1:30")
    
    # Reduce tx queue to prevent bufferbloat
    r.cmd(f"ip link set dev {ifn} txqueuelen {txqlen}")
    
    
    print(f"Applied 3-tier OSPF traffic shaping on {ifn}")

    """
def shape_prioritized(r, total="100kbit", ctrl="15kbit", delay="100ms",
                      ctrl_limit=15, bulk_limit=8, txqlen=50):
    ifn = first_data_if(r)
    r.cmd(f"tc qdisc del dev {ifn} root 2>/dev/null || true")
    r.cmd(f"tc qdisc replace dev {ifn} root handle 1: htb default 20")
    r.cmd(f"tc class  replace dev {ifn} parent 1: classid 1:10 htb rate {ctrl} ceil {total} prio 0")
    r.cmd(f"tc class  replace dev {ifn} parent 1: classid 1:20 htb rate {total} ceil {total} prio 1")
    r.cmd(f"tc qdisc  replace dev {ifn} parent 1:10 handle 10: netem delay {delay} limit {ctrl_limit}")
    r.cmd(f"tc qdisc  replace dev {ifn} parent 1:20 handle 20: netem delay {delay} limit {bulk_limit}")
    # filters (IPv4 OSPFv2; Hello/DBD/LS-Req/LSAck to 1:10, LSU to 1:20)
    r.cmd(f"tc filter del dev {ifn} parent 1: 2>/dev/null || true")
    for t in (1,2,3,5):
        r.cmd(f"tc filter add dev {ifn} parent 1: protocol ip prio 10 u32 "
              f"match ip protocol 89 0xff match u8 {t} 0xff at 21 flowid 1:10")
    r.cmd(f"tc filter add dev {ifn} parent 1: protocol ip prio 20 u32 "
          f"match ip protocol 89 0xff match u8 4 0xff at 21 flowid 1:20")
    r.cmd(f"tc filter add dev {ifn} parent 1: protocol ip prio 30 u32 "
          f"match ip protocol 89 0xff flowid 1:20")
    r.cmd(f"ip link set dev {ifn} txqueuelen {txqlen}")

    
def unshape_link(r1, r2):
    for g in (r1, r2):
        ifn = first_data_if(g)
        if ifn:
            g.cmd(f"tc qdisc del dev {ifn} root || true")
            g.cmd(f"ip link set dev {ifn} txqueuelen 1000 || true")


def apply_delay(r1, r2, delay="10ms", jitter=None):
    if1 = first_data_if(r1)
    if2 = first_data_if(r2)
    assert if1 and if2
    opt = f"delay {delay}" + (f" {jitter}" if jitter else "")
    r1.cmd(f"tc qdisc replace dev {if1} root netem {opt}")
    r2.cmd(f"tc qdisc replace dev {if2} root netem {opt}")


def clear_delay(r1, r2):
    if1 = first_data_if(r1)
    if2 = first_data_if(r2)
    r1.cmd(f"tc qdisc del dev {if1} root || true")
    r2.cmd(f"tc qdisc del dev {if2} root || true")


# Function we pass to Topogen to create the topology
def build_topo(tgen):
    "Build function"

    # Create 2 routers
    r1 = tgen.add_router("r1")
    r2 = tgen.add_router("r2")

    # Create a p2p connection between r1 and r2
    tgen.add_link(r1, r2, ifname1="eth0", ifname2="eth0")

    # Create a p2p connection between r1 and r2
    # switch = tgen.add_switch("s1")
    # switch.add_link(r1)
    # switch.add_link(r2)


# New form of setup/teardown using pytest fixture
@pytest.fixture(scope="module")
def tgen(request):
    "Setup/Teardown the environment and provide tgen argument to tests"

    # This function initiates the topology build with Topogen...

    # A basic topology similar to the above could also have be more easily specified
    # using a # dictionary, remove the build_topo function and use the following
    # instead:
    #
    # topodef = {
    #     "s1": "r1"
    #     "s2": ("r1", "r2")
    # }
    # topodef = {
    #    "s1": ("r1", "r2")
    # }

    tgen = Topogen(build_topo, request.module.__name__)

    # ... and here it calls initialization functions.
    tgen.start_topology()

    router_list = tgen.routers()

    for _, router in router_list.items():
        router.load_frr_config("frr.conf")
    tgen.start_router()
    PM = PerInterfacePcapManager(outdir="pcaps", tag="ospf4")
    PM.start_all(tgen)  # ← pass the valid tgen here

    tgen.gears["r1"].cmd("ip -o link show")
    tgen.gears["r2"].cmd("ip -o link show")
    r1 = tgen.gears["r1"]
    r2 = tgen.gears["r2"]

    # apply_delay(r1, r2, delay="60ms")
    # 30 kbit/s total, reserve 6 kbit/s for OSPF control, add 100 ms one-way delay
    # Apply to both ends:
    #shape_link (r1,r2, rate="100kbit", loss="5%");
    shape_link (r1,r2, rate="200kbit");
    #shape_prioritized(r1, total="8kbit",ctrl="3Kbit")
    #shape_prioritized(r2, total="8kbit",ctrl="3Kbit")
    # This is a sample of configuration loading.

    # for _, (rname, router) in enumerate(router_list.items(), 1):
    #    router.load_frr_config(os.path.join(CWD, "topotests/ospf_4222_baseline/{}/frr.conf".format(rname)), [
    #        (TopoRouter.RD_ZEBRA, "-s 90000000"),
    #        (TopoRouter.RD_OSPF, None),
    #        (TopoRouter.RD_BGP, None)])

    # For all routers arrange for:
    # - starting zebra using config file from <rtrname>/zebra.conf
    # - starting ospfd using an empty config file.
    # for rname, router in router_list.items():
    #    router.load_config(TopoRouter.RD_ZEBRA, "zebra.conf")
    #    router.load_config(TopoRouter.RD_OSPF)

    # Start and configure the router daemons

    # Provide tgen as argument to each test function
    yield tgen
    if PM:
        PM.stop_all()
    unshape_link(r1, r2)

    # Teardown after last test runs
    tgen.stop_topology()


# Fixture that executes before each test
@pytest.fixture(autouse=True)
def skip_on_failure(tgen):
    if tgen.routers_have_failure():
        pytest.skip("skipped because of previous test failure")


def _collect_neighbors(obj):
    """
    Recursively walk any JSON shape and collect neighbor dicts.
    Neighbor dicts typically have fields like 'nbrState' or 'state',
    and often 'ifaceName', 'ifaceAddress', etc.
    """
    found = []
    if isinstance(obj, dict):
        # Direct 'neighbors' container (can be dict or list)
        if "neighbors" in obj:
            nb = obj["neighbors"]
            if isinstance(nb, dict):
                for v in nb.values():
                    if isinstance(v, list):
                        found.extend(v)
                    elif isinstance(v, dict) and ("nbrState" in v or "state" in v):
                        found.append(v)
            elif isinstance(nb, list):
                for v in nb:
                    if isinstance(v, dict):
                        found.append(v)
        # In some versions, neighbor lists are nested under VRF/areas/interfaces
        for v in obj.values():
            found.extend(_collect_neighbors(v))
    elif isinstance(obj, list):
        for v in obj:
            found.extend(_collect_neighbors(v))
    return found


def _vty(router, cmd):
    return get_topogen().gears[router].vtysh_cmd(cmd)


def neighbors_full(router):
    """
    Return True if at least one neighbor on this router is Full.
    Robust to FRR JSON shape differences.
    """
    raw = _vty(router, "show ip ospf neighbor json")
    try:
        data = json.loads(raw) if raw.strip() else {}
    except json.JSONDecodeError:
        # Fall back to non-JSON if something odd happened
        return False

    neigh = _collect_neighbors(data)
    if not neigh:
        return False

    # FRR sometimes uses 'nbrState' ("Full/-") or 'state' ("Full")
    for n in neigh:
        st = n.get("nbrState") or n.get("state") or ""
        if isinstance(st, str) and st.startswith("Full"):
            return True
    return False


def vty_json(router: str, cmd: str):
    """Run a vtysh *json command and return {} if empty/unparseable."""
    raw = get_topogen().gears[router].vtysh_cmd(cmd)
    raw = (raw or "").strip()
    if not raw:
        return {}
    try:
        return json.loads(raw)
    except Exception:
        return {}


# ===================
# The tests functions
# ===================

def test_dump_running_config():
    tgen = get_topogen()
    r1 = tgen.gears["r1"]            # pick your router name
    cfg = r1.vtysh_cmd("show running-config")
    print(cfg)                       # shows in pytest -s output
    assert "router ospf" in cfg      # example sanity check


def test_01_full_before_storm():
    retry = True
    retry_times = 10
    while retry and retry_times > 0:
        if  neighbors_full("r1"):          
            retry = False
        else:
            sleep(1)
            retry_times -= 1

    retry = True
    retry_times = 10
    while retry and retry_times > 0:
        if  neighbors_full("r2"):          
            retry = False
        else:
            sleep(1)
            retry_times -= 1

    assert neighbors_full("r1") and neighbors_full("r2")


def test_02_lsa_storm_and_stability():
    tgen = get_topogen()
    r1 = tgen.gears["r1"]
    r2 = tgen.gears["r2"]

    # Flood: add 200 loopbacks on r1 and redistribute connected
    r1.vtysh_cmd("conf t\nrouter ospf\n redistribute connected\n exit")
    for i in range(1, 201):
        r1.cmd(f"ip addr add 198.51.100.{i}/32 dev lo")
        """if i % 50 == 0:
            for g in (r1, r2):
                IF = first_data_if(g)
                print(g.cmd(f"tc -s qdisc show dev {IF}"))
                print(g.cmd(f"tc -s class show dev {IF}"))
                print(g.cmd(f"tc -s filter show dev {IF} parent 1:")) """
    for i in range(1, 201):
        r1.cmd(f"ip addr add 198.51.101.{i}/32 dev lo")
    for i in range(1, 201):
        r1.cmd(f"ip addr add 198.51.102.{i}/32 dev lo")
    for i in range(1, 201):
        r1.cmd(f"ip addr add 198.51.103.{i}/32 dev lo")

    # Observe for 100s: link should stay FULL; Hellos should not be missed
    t_deadline = time.time() + 100
    lost = 0
    while time.time() < t_deadline:
        if not neighbors_full("r1") or not neighbors_full("r2"):
            lost += 1
        time.sleep(1)

    # Baseline assertion: no sustained loss of FULL state
    assert lost == 0, "Neighbor state dropped during LSA storm"




def test_connectivity(tgen):
    "Test the logs the FRR version"

    r1 = tgen.gears["r1"]
    r2 = tgen.gears["r2"]
    ping_resp = r1.cmd("ping -c1 192.0.2.2")
    logger.info("Ping is: " + ping_resp)
    neigh_resp = r1.vtysh_cmd ("show ip ospf neighbor detail all")
    logger.info("R1: " + neigh_resp)

    ping_resp = r1.cmd("ping -c1 192.0.2.2")
    logger.info("Ping is: " + ping_resp)
    neigh_resp = r2.vtysh_cmd ("show ip ospf neighbor detail all")
    logger.info("R2: " + neigh_resp)


# Memory leak test template
def test_memory_leak(tgen):
    "Run the memory leak test and report results."

    if not tgen.is_memleak_enabled():
        pytest.skip("Memory leak test/report is disabled")

    tgen.report_memory_leaks()


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
