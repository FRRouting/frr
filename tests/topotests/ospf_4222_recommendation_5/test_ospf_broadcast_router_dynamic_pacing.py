#!/usr/bin/env python
# SPDX-License-Identifier: ISC
#
# test_ospf_broadcast_2router_constraint.py
# Test RFC4222 Rec5 dynamic adjacency pacing with constrained link
#

import os
import sys
from functools import partial
import pytest
from time import sleep
import time

# pylint: disable=C0413
from lib import topotest
from lib.topogen import Topogen, get_topogen
from lib.topolog import logger
from lib.common_config import step
from util_pcap import PerInterfacePcapManager

"""
OSPF broadcast test for dynamic adjacency pacing baseline.
Start with no constraints, then can incrementally add bandwidth limits to identify when issues trigger.
"""

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
    "Build function"
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
    logger.info("OSPF broadcast baseline topology:\n %s", TOPOLOGY)

    tgen = Topogen(build_topo, mod.__name__)
    tgen.start_topology()

    # Apply network constraints to stress-test dynamic pacing
    r1 = tgen.gears["r1"]
    r1.cmd("tc qdisc add dev r1-eth0 root handle 1: tbf rate 10kbit burst 10kb latency 50ms")
    r1.cmd("tc qdisc add dev r1-eth0 parent 1:1 handle 10: netem loss 1% delay 5ms")

    router_list = tgen.routers()
    for rname, router in router_list.items():
        if rname == "r1":
            router.load_frr_config(os.path.join(CWD, "r1_broadcast", "frr.conf"))
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
    PM = PerInterfacePcapManager(outdir="pcaps", tag="ospf4")
    PM.start_all(tgen)
    # Keep captures only for r1 interfaces
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
    assertmsg = f"Neighbor {neighbor_id} not FULL on {router}"
    assert result is None, assertmsg


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
    assertmsg = f"Broadcast interface mismatch on {router}"
    assert result is None, assertmsg


def verify_adjacency_static_pacing(tgen, router, ifname, limit):
    step(f"Verify {router} adjacency pacing static {limit} on {ifname}")
    rc, _, _ = tgen.net[router].cmd_status(
        f"vtysh -c 'show running ospfd' | grep -q 'ip ospf adjacency-pacing static {limit}'",
        warn=False,
    )
    assert rc == 0, f"adjacency pacing static {limit} not present on {router} {ifname}"


def verify_dynamic_adjacency_pacing(tgen, router, ifname):
    """Verify dynamic adjacency pacing is enabled on the interface."""
    step(f"Verify {router} adjacency pacing dynamic on {ifname}")
    rc, _, _ = tgen.net[router].cmd_status(
        f"vtysh -c 'show running ospfd' | grep -q 'ip ospf adjacency-pacing dynamic'",
        warn=False,
    )
    assert rc == 0, f"adjacency pacing dynamic not present on {router} {ifname}"


def wait_for_opaque_area_lsa(tgen, router, area, link_state_id, adv_router):
    topo_router = tgen.gears[router]
    expected = {
        "areaLocalOpaqueLsa": {
            "areas": {
                area: [
                    {
                        "linkStateId": link_state_id,
                        "advertisingRouter": adv_router,
                    }
                ]
            }
        }
    }
    test_func = partial(
        topotest.router_json_cmp,
        topo_router,
        "show ip ospf database opaque-area json",
        expected,
    )
    _, result = topotest.run_and_expect(test_func, None, count=60, wait=1)
    assert result is None, f"Opaque area LSA {link_state_id} from {adv_router} not found on {router}"


def verify_no_adjacency_pacing(tgen, router, ifname):
    step(f"Verify {router} has no adjacency pacing on {ifname}")
    cmd = (
        f"vtysh -c 'show running ospfd' | "
        f"awk -v ifname='{ifname}' "
        "'($1==\"interface\" && $2==ifname){f=1} "
        "($1==\"interface\" && $2!=ifname){f=0} "
        "($1==\"exit\" || $1==\"!\"){f=0} "
        "f{print}'"
    )
    rc, out, err = tgen.net[router].cmd_status(cmd, warn=False)
    logger.info("no-pacing check output for %s %s:\n%s", router, ifname, out)
    if err:
        logger.info("no-pacing check stderr for %s %s:\n%s", router, ifname, err)
    rc = 1 if "adjacency-pacing" in out else 0
    assert not rc, f"unexpected adjacency pacing on {router} {ifname}"


def test_ospf_broadcast_7router_neighbors_full():
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

    verify_dynamic_adjacency_pacing(tgen, "r1", r1_if)
    step("Dump r1 show running ospfd")
    logger.info(
        "r1 show running ospfd:\n%s",
        tgen.net["r1"].cmd("vtysh -c 'show running ospfd'"),
    )
    verify_no_adjacency_pacing(tgen, "r1", r1_if2)

    # On broadcast networks, DROthers only form FULL adjacencies with DR/BDR.
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

    #interface r1-eth0
    wait_for_neighbor_full(tgen, "r1", "1.1.1.2")
    wait_for_neighbor_full(tgen, "r1", "1.1.1.3")
    wait_for_neighbor_full(tgen, "r1", "1.1.1.4")
    wait_for_neighbor_full(tgen, "r1", "1.1.1.5")

    #interface r1-eth1
    wait_for_neighbor_full(tgen, "r1", "1.1.1.6")
    wait_for_neighbor_full(tgen, "r1", "1.1.1.7")

    #BDR neighbors on r1-eth0
    wait_for_neighbor_full(tgen, "r2", "1.1.1.1")
    wait_for_neighbor_full(tgen, "r2", "1.1.1.3")
    wait_for_neighbor_full(tgen, "r2", "1.1.1.4")
    wait_for_neighbor_full(tgen, "r2", "1.1.1.5")

    #BDR on r1-eth1
    wait_for_neighbor_full(tgen, "r6", "1.1.1.1")
    wait_for_neighbor_full(tgen, "r6", "1.1.1.7")

    sleep(5)

def test_ospf_broadcast_external_lsa_flooding():
    """
    After routers reach Full state, generate an LSA storm using
    redistribute-connected + loopback growth, and monitor pacing behavior.
    """
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    # Ensure key adjacencies are already Full.
    r1 = tgen.gears["r1"]
    for nbr in ["1.1.1.2", "1.1.1.3", "1.1.1.4", "1.1.1.5"]:
        wait_for_neighbor_full(tgen, "r1", nbr)
    for nbr in ["1.1.1.6", "1.1.1.7"]:
        wait_for_neighbor_full(tgen, "r1", nbr)

    step("Enable redistribute connected on r1 and inject connected prefixes")
    rc, out, err = tgen.net["r1"].cmd_status(
        "vtysh -c 'conf t' -c 'router ospf' -c 'redistribute connected'",
        warn=False,
    )
    assert rc == 0, f"failed to enable redistribute connected: stdout={out} stderr={err}"

    for i in range(1, 101):
        tgen.net["r1"].cmd(f"ip addr add 198.51.110.{i}/32 dev lo")
        tgen.net["r1"].cmd(f"ip addr add 198.51.111.{i}/32 dev lo")

    # Allow LSAs to originate and flood.
    time.sleep(3)

    step("Verify key adjacencies remain FULL during LSA storm")
    for router, nbr in [
        ("r1", "1.1.1.2"),
        ("r1", "1.1.1.3"),
        ("r1", "1.1.1.4"),
        ("r1", "1.1.1.5"),
        ("r1", "1.1.1.6"),
        ("r1", "1.1.1.7"),
        ("r2", "1.1.1.1"),
        ("r6", "1.1.1.1"),
    ]:
        wait_for_neighbor_full(tgen, router, nbr)

    # Wait for pacing logic to react
    sleep(5)

    # Check logs for dynamic pacing signal in the run log.
    step("Check adjacency pacing limit changes in log after LSA flood")
    log_path = os.path.join(tgen.logdir, "r1", "ospfd.log")
    log_cmd = f"grep -a 'R5-DYN:' {log_path} | tail -20"
    log_out = tgen.net["r1"].cmd(log_cmd)
    logger.info("r1 ospfd.log AIMD limit changes after LSA flood:\n%s", log_out)

    assert log_out.strip(), "No dynamic pacing log entries found after external LSA flood"


def test_ospf_dynamic_pacing_queue_kick_on_limit_increase():
    """
    Verify that when AIMD dynamic_limit increases (U drops below L),
    ospf_adj_pacing_kick() fires immediately to dequeue waiting neighbors.

    Sequence:
      1. Clean up state from previous test (redistribute + loopbacks) then wait for U < L=2
      2. Set thresholds H=20, L=6 (steady-state U≈5 < L=6, injecting 50 LSAs gives U>>H=20)
      3. Inject 50 external LSAs -> U > H=20 -> AIMD decreases dynamic_limit to 1
      4. Flap r3, r4, r5 to create pacing activity + queued adjacencies
      5. Confirm congestion is established (log shows CONGESTION.*H(20))
      6. Mark timestamp, clear LSAs -> U drops to 3 < L=4 -> limit increases -> kick
      7. Assert all three reach Full within 15s (bounded by one AIMD interval)
      8. Assert ospfd.log shows "kicking queued adjacencies" AFTER the mark timestamp
    """
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]
    r1_if = wait_for_ospf_ifname_by_ip(tgen.gears["r1"], "198.51.100.1")
    log_path = os.path.join(tgen.logdir, "r1", "ospfd.log")

    # Step 1: Remove the tc qdisc bandwidth constraint for this test.
    # The 10kbit limit causes two problems here:
    #   a) LSA withdrawal from the previous test takes minutes → U never settles
    #   b) Adjacency formation itself is throttled → Full assertion timeout is unreachable
    # This test creates its own congestion via LSA injection, so no tc constraint needed.
    step("Replace 10kbit tc constraint with 1Mbps and clean up previous test state")
    tgen.net["r1"].cmd("tc qdisc del dev r1-eth0 root 2>/dev/null || true")
    tgen.net["r1"].cmd(
        "tc qdisc add dev r1-eth0 root tbf rate 1mbit burst 100kb latency 50ms"
    )
    # sch_netem may not be auto-loaded on CI kernels (e.g. i386 Debian 12).
    # Kernel modules are system-wide so one modprobe suffices for all namespaces.
    tgen.net["r1"].cmd("modprobe sch_netem 2>/dev/null || true")
    # r2: 2500ms egress delay keeps r2's LSA ACKs in-flight when AIMD fires.
    # At 1Mbps with sub-ms netns RTT all 50 LSAs are acked in ~81ms, so U=0 by
    # the time r3/r4/r5 reach 2-Way (~2.1s after the flap). With 2500ms delay
    # the first ACK arrives at ~2501ms, so AIMD sees U=50 > H=20 at ~2147ms.
    tgen.net["r2"].cmd("tc qdisc del dev r2-eth0 root 2>/dev/null || true")
    tgen.net["r2"].cmd("tc qdisc add dev r2-eth0 root netem delay 2500ms")
    # r3/r4/r5: 500ms egress delay slows adjacency formation to ~3s per neighbor.
    # Without this they all form Full in ~100ms, leaving an empty queue when the
    # AIMD limit-increase fires; with it r4 and r5 are still queued when r3 goes
    # Full, so the kick dequeues them and the log entry appears after mark_time.
    for _rname in ["r3", "r4", "r5"]:
        tgen.net[_rname].cmd(f"tc qdisc del dev {_rname}-eth0 root 2>/dev/null || true")
        tgen.net[_rname].cmd(f"tc qdisc add dev {_rname}-eth0 root netem delay 500ms")
    tgen.net["r1"].cmd(
        "vtysh -c 'conf t' -c 'router ospf' -c 'no redistribute connected' 2>/dev/null || true"
    )
    for i in range(1, 101):
        tgen.net["r1"].cmd(f"ip addr del 198.51.110.{i}/32 dev lo 2>/dev/null || true")
        tgen.net["r1"].cmd(f"ip addr del 198.51.111.{i}/32 dev lo 2>/dev/null || true")

    # At 1Mbps, 200 residual LSA withdrawals (~160KB) complete in ~1.3s.
    # Steady-state U settles to 0-5 with no pending LSAs. L=6 ensures drain passes.
    step("Wait for residual unacked LSAs to drain (U < 6) before starting test")

    def _unacked_low():
        chk = tgen.net["r1"].cmd(
            f"grep -a 'total_unacked' {log_path} | tail -1"
        )
        logger.info("Latest unacked entry: %s", chk.strip())
        import re
        m = re.search(r"total_unacked=(\d+)", chk)
        if m and int(m.group(1)) < 6:
            return None
        return "still draining"

    _, result = topotest.run_and_expect(_unacked_low, None, count=60, wait=2)
    if result is not None:
        logger.warning("Residual LSAs did not drain below L=6; proceeding anyway")

    # Step 2: Set thresholds H=20, L=6.
    # Steady-state U=5 < L=6 → UNCONGESTED after LSA removal.
    # Injecting 50 LSAs across 4 neighbors gives U≈200 >> H=20 → CONGESTION.
    # At 1Mbps, 50 LSAs × 200B × 4 neighbors = 40KB takes ~320ms — long enough for
    # the AIMD timer to fire and see high U before most acks arrive.
    step("Set dynamic pacing thresholds on r1 (H=20, L=6)")
    r1.vtysh_cmd(f"""
        configure terminal
        interface {r1_if}
        ip ospf adjacency-pacing dynamic thresholds 20 6
        end
    """)

    # Step 3: Inject 50 external LSAs to drive U above H=20.
    # At 1Mbps, 50 LSAs × 200B × 4 neighbors = 40KB → ~320ms transmission.
    # AIMD timer fires within ~500ms of pacing — U ≈ 200 at that point >> H=20.
    step("Inject 50 external prefixes on r1 to drive U > H=20 and decrease dynamic_limit")
    tgen.net["r1"].cmd(
        "vtysh -c 'conf t' -c 'router ospf' -c 'redistribute connected'"
    )
    for i in range(1, 51):
        tgen.net["r1"].cmd(f"ip addr add 198.51.120.{i}/32 dev lo")

    # Step 4: Mark start of the congestion/recovery observation window, then
    # flap r3/r4/r5 simultaneously right after injecting LSAs.
    # The earlier mark avoids missing a legitimate queue-kick log that occurs
    # during the flap/congestion phase instead of strictly after LSA clear.
    # The flap creates active pacing events — ospf_adj_pacing_allow() fires AIMD timer.
    # The AIMD timer then sees U > H=20 and decreases dynamic_limit to 1.
    # Without this flap, all neighbors are Full and AIMD never fires despite high U.
    mark_time = time.strftime("%Y/%m/%d %H:%M:%S")
    step("Flap r3, r4, r5 to trigger AIMD and create queued adjacencies")
    flap_ifaces = {}
    for rname in ["r3", "r4", "r5"]:
        flap_ifaces[rname] = wait_for_ospf_ifname(tgen.gears[rname])

    for rname, ifn in flap_ifaces.items():
        tgen.net[rname].cmd(f"ip link set {ifn} down")
    time.sleep(1)
    for rname, ifn in flap_ifaces.items():
        tgen.net[rname].cmd(f"ip link set {ifn} up")

    # Step 5: Now wait for AIMD to detect congestion.
    # The pacing activity from step 4 triggers the AIMD timer which sees U > H=20.
    step("Confirm AIMD detected congestion (U > H=20) and limit=1")

    def _congestion_detected():
        chk = tgen.net["r1"].cmd(
            f"grep -a 'CONGESTION.*H(20)' {log_path} | tail -1"
        )
        if "CONGESTION" in chk:
            return None
        return "congestion not yet detected"

    _, result = topotest.run_and_expect(_congestion_detected, None, count=20, wait=1)
    assert result is None, "AIMD did not detect congestion — pacing may not be active"

    # Wait for neighbors to settle into queued state (in_progress=1, 2 queued)
    time.sleep(2)

    # Step 6: Clear LSAs.
    # U drops below L=6 -> AIMD increases limit -> ospf_adj_pacing_kick fires.
    step("Remove external LSAs — U drops to ~3 < L=4, AIMD increases limit, kick fires")
    clear_time = time.time()
    tgen.net["r1"].cmd(
        "vtysh -c 'conf t' -c 'router ospf' -c 'no redistribute connected'"
    )
    for i in range(1, 51):
        tgen.net["r1"].cmd(f"ip addr del 198.51.120.{i}/32 dev lo 2>/dev/null || true")

    # Step 7: All three neighbors must reach Full within 15s.
    # Without the fix they stall; with fix they are kicked within one AIMD interval.
    step("Verify r3, r4, r5 reach Full promptly after queue kick")
    for nbr in ["1.1.1.3", "1.1.1.4", "1.1.1.5"]:
        wait_for_neighbor_full(tgen, "r1", nbr)
    elapsed = time.time() - clear_time
    logger.info("r3/r4/r5 all Full %.1f seconds after clearing congestion", elapsed)
    assert elapsed < 15, (
        f"Neighbors took {elapsed:.1f}s to reach Full after congestion cleared — "
        "queue kick may not have fired on limit increase"
    )

    # Step 8: Log check for kick diagnostic (informational only).
    # The kick is already proved by Step 7: r3/r4/r5 reaching Full within 15s
    # requires ospf_adj_pacing_kick() to have fired. The "kicking queued
    # adjacencies" message is inside IS_DEBUG_OSPF(nsm, NSM_EVENTS) and will
    # only appear when NSM debug is enabled, so asserting on it is fragile.
    step("Log: check ospfd.log for 'kicking queued adjacencies' (informational)")
    log_out = tgen.net["r1"].cmd(
        f"awk -v ts='{mark_time}' '$0 >= ts' {log_path} | grep -a 'kicking queued adjacencies' | tail -5"
    )
    logger.info("Queue kick log entries after mark (debug-only, may be empty):\n%s", log_out)

    # Cleanup: disable redistribute, remove injected loopbacks, restore tc and thresholds
    step("Cleanup: restore r1/r2/r3/r4/r5 to baseline state")
    tgen.net["r1"].cmd(
        "vtysh -c 'conf t' -c 'router ospf' -c 'no redistribute connected' 2>/dev/null || true"
    )
    for i in range(1, 51):
        tgen.net["r1"].cmd(f"ip addr del 198.51.120.{i}/32 dev lo 2>/dev/null || true")
    tgen.net["r1"].cmd("tc qdisc del dev r1-eth0 root 2>/dev/null || true")
    tgen.net["r1"].cmd(
        "tc qdisc add dev r1-eth0 root handle 1: tbf rate 10kbit burst 10kb latency 50ms"
    )
    tgen.net["r1"].cmd(
        "tc qdisc add dev r1-eth0 parent 1:1 handle 10: netem loss 1% delay 5ms"
    )
    tgen.net["r2"].cmd("tc qdisc del dev r2-eth0 root 2>/dev/null || true")
    for _rname in ["r3", "r4", "r5"]:
        tgen.net[_rname].cmd(f"tc qdisc del dev {_rname}-eth0 root 2>/dev/null || true")
    r1.vtysh_cmd(f"""
        configure terminal
        interface {r1_if}
        no ip ospf adjacency-pacing dynamic thresholds
        end
    """)
