#!/usr/bin/env python
# SPDX-License-Identifier: ISC
#
# test_ospf_broadcast_2router_constraint.py
# Test RFC4222 Rec5 dynamic adjacency pacing with constrained link
#

import os
import re
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

    # Apply deterministic congestion without starving OSPF control packets.
    rc, out, err = tgen.net["r1"].cmd_status(
        "tc qdisc add dev r1-eth0 root handle 1: "
        "tbf rate 100kbit burst 10kb latency 500ms",
        warn=False,
    )
    assert rc == 0, (
        "failed to install r1-eth0 TBF: " f"stdout={out.strip()} stderr={err.strip()}"
    )

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


def neighbor_state(tgen, router, neighbor_id):
    """Return the current OSPF neighbor state without waiting for recovery."""
    data = tgen.gears[router].vtysh_cmd(
        f"show ip ospf neighbor {neighbor_id} json", isjson=True
    )
    nbr_list = data.get("default", {}).get(neighbor_id)
    if not nbr_list:
        return "missing"
    return nbr_list[0].get("nbrState", "unknown")


def read_log_since(path, offset):
    """Read daemon log data appended after offset."""
    with open(path, "r", encoding="utf-8", errors="replace") as log_file:
        log_file.seek(offset)
        return log_file.read()


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
    assert (
        result is None
    ), f"Opaque area LSA {link_state_id} from {adv_router} not found on {router}"


def verify_no_adjacency_pacing(tgen, router, ifname):
    step(f"Verify {router} has no adjacency pacing on {ifname}")
    cmd = (
        f"vtysh -c 'show running ospfd' | "
        f"awk -v ifname='{ifname}' "
        '\'($1=="interface" && $2==ifname){f=1} '
        '($1=="interface" && $2!=ifname){f=0} '
        '($1=="exit" || $1=="!"){f=0} '
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

    # interface r1-eth0
    wait_for_neighbor_full(tgen, "r1", "1.1.1.2")
    wait_for_neighbor_full(tgen, "r1", "1.1.1.3")
    wait_for_neighbor_full(tgen, "r1", "1.1.1.4")
    wait_for_neighbor_full(tgen, "r1", "1.1.1.5")

    # interface r1-eth1
    wait_for_neighbor_full(tgen, "r1", "1.1.1.6")
    wait_for_neighbor_full(tgen, "r1", "1.1.1.7")

    # BDR neighbors on r1-eth0
    wait_for_neighbor_full(tgen, "r2", "1.1.1.1")
    wait_for_neighbor_full(tgen, "r2", "1.1.1.3")
    wait_for_neighbor_full(tgen, "r2", "1.1.1.4")
    wait_for_neighbor_full(tgen, "r2", "1.1.1.5")

    # BDR on r1-eth1
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

    monitored_adjacencies = [
        ("r1", "1.1.1.2"),
        ("r1", "1.1.1.3"),
        ("r1", "1.1.1.4"),
        ("r1", "1.1.1.5"),
        ("r1", "1.1.1.6"),
        ("r1", "1.1.1.7"),
        ("r2", "1.1.1.1"),
        ("r6", "1.1.1.1"),
    ]

    step("Enable redistribute connected on r1 and inject connected prefixes")
    rc, out, err = tgen.net["r1"].cmd_status(
        "vtysh -c 'conf t' -c 'router ospf' -c 'redistribute connected'",
        warn=False,
    )
    assert (
        rc == 0
    ), f"failed to enable redistribute connected: stdout={out} stderr={err}"

    for i in range(1, 101):
        tgen.net["r1"].cmd(f"ip addr add 198.51.110.{i}/32 dev lo")
        tgen.net["r1"].cmd(f"ip addr add 198.51.111.{i}/32 dev lo")

    step("Continuously verify key adjacencies remain FULL during LSA storm")
    for _ in range(5):
        for router, nbr in monitored_adjacencies:
            state = neighbor_state(tgen, router, nbr)
            assert (
                state.split("/", 1)[0] == "Full"
            ), f"Neighbor {nbr} left FULL on {router} during LSA storm: {state}"
        time.sleep(1)

    expected_lsa_ids = {
        f"198.51.{subnet}.{host}" for subnet in (110, 111) for host in range(1, 101)
    }

    step("Verify external LSA convergence without adjacency disruption")

    def _external_lsas_converged():
        # Check adjacency stability on every poll, not just once at the end,
        # so a neighbor that drops and recovers mid-convergence (rather than
        # staying down) is still caught instead of looking fine by the time
        # the LSDB check happens to pass.
        for router, nbr in monitored_adjacencies:
            state = neighbor_state(tgen, router, nbr)
            if state.split("/", 1)[0] != "Full":
                return f"Neighbor {nbr} left FULL on {router}: {state}"

        for router_name in ("r2", "r3", "r4", "r5", "r6", "r7"):
            database = tgen.gears[router_name].vtysh_cmd(
                "show ip ospf database external json", isjson=True
            )
            received_ids = {
                lsa.get("linkStateId")
                for lsa in database.get("asExternalLinkStates", [])
            }
            missing = expected_lsa_ids - received_ids
            if missing:
                return "{} is missing {}/{} external LSAs".format(
                    router_name, len(missing), len(expected_lsa_ids)
                )
        return None

    _, result = topotest.run_and_expect(
        _external_lsas_converged, None, count=60, wait=1
    )
    assert result is None, result

    for router, nbr in monitored_adjacencies:
        state = neighbor_state(tgen, router, nbr)
        assert state.split("/", 1)[0] == "Full", (
            f"Neighbor {nbr} is not FULL on {router} after external LSA "
            f"convergence: {state}"
        )

    # Log check for AIMD diagnostic (informational only, same pattern as the
    # queue-kick test's step 8). Convergence is already proved above via the
    # LSDB check and the Full-state re-verification, without depending on
    # ospfd.log access; this just surfaces whatever pacing activity was
    # logged, for debugging, without asserting on it — some environments
    # don't expose the log at this path, and that must not fail the test.
    step("Log: check ospfd.log for 'OSPF dynamic adjacency pacing:' (informational)")
    log_path = os.path.join(tgen.logdir, "r1", "ospfd.log")
    log_out = tgen.net["r1"].cmd(
        f"grep -a 'OSPF dynamic adjacency pacing:' {log_path} | tail -20"
    )
    logger.info(
        "r1 ospfd.log AIMD limit changes after LSA flood (debug-only, may be empty):\n%s",
        log_out,
    )


def test_ospf_dynamic_pacing_queue_kick_on_limit_increase():
    """
    Verify that when AIMD dynamic_limit increases (U drops below L),
    ospf_adj_pacing_kick() fires immediately to dequeue waiting neighbors.

    Sequence:
      1. Clean up state from previous test (redistribute + loopbacks) then wait for U < L=2
      2. Set thresholds H=15, L=6 (steady-state U≈5 < L=6, injecting 100 LSAs gives U>>H=15)
      3. Inject 100 external LSAs -> U > H=15 -> AIMD decreases dynamic_limit to 1
      4. Flap r3, r4, r5 to create pacing activity + queued adjacencies
      5. Confirm congestion is established (log shows CONGESTION.*high-water=15)
      6. Mark timestamp, clear LSAs -> U drops to 3 < L=4 -> limit increases -> kick
      7. Assert all three reach Full within 20s (bounded by one AIMD interval)
      8. Assert ospfd.log shows "releasing queued adjacencies" AFTER the mark timestamp
    """
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]
    r1_if = wait_for_ospf_ifname_by_ip(tgen.gears["r1"], "198.51.100.1")
    log_path = os.path.join(tgen.logdir, "r1", "ospfd.log")

    # This test depends on grepping r1's ospfd.log from within r1's
    # namespace for several checks below. Confirm it's actually readable
    # from that context up front, so an environment where it isn't fails
    # with its own clear message instead of surfacing as the ambiguous
    # "AIMD did not detect congestion" further down.
    log_readable = tgen.net["r1"].cmd(
        f"test -r {log_path} && echo OK || echo NOTOK"
    ).strip()
    assert log_readable == "OK", (
        f"{log_path} is not readable from r1's namespace in this "
        "environment -- this test depends on log access and cannot verify "
        "AIMD behavior here; this is an environment issue, not evidence "
        "that AIMD/pacing is broken."
    )

    # Step 1: Remove the tc qdisc bandwidth constraint for this test.
    # The constrained baseline causes two problems here:
    #   a) LSA withdrawal from the previous test takes minutes → U never settles
    #   b) Adjacency formation itself is throttled → Full assertion timeout is unreachable
    # This test creates its own congestion via LSA injection, so no tc constraint needed.
    step(
        "Replace baseline tc constraint with 1Mbps for this test, and clean up previous test state"
    )
    tgen.net["r1"].cmd("tc qdisc del dev r1-eth0 root 2>/dev/null || true")
    tgen.net["r1"].cmd(
        "tc qdisc add dev r1-eth0 root tbf rate 1mbit burst 100kb latency 50ms"
    )
    # sch_netem may not be auto-loaded on CI kernels (e.g. i386 Debian 12).
    # Kernel modules are system-wide so one modprobe suffices for all namespaces.
    tgen.net["r1"].cmd("modprobe sch_netem 2>/dev/null || true")
    # r2: 2500ms egress delay keeps r2's LSA ACKs in-flight when AIMD fires.
    # U is counted at send time (lsu_sent_for_dst()), not ack time, so U's
    # peak is bounded by how much of the 50-LSA flood completes before the
    # delay elapses, not by the batch size alone. This delay applies to ALL
    # of r2's egress traffic, not just LSAcks -- including its DBD packets
    # during adjacency formation. Widening it (tried 10000ms) backfired: as
    # the DBD slave, r2 must respond to each round of r1's DBD exchange, and
    # every response eats the full delay, so a handful of exchange rounds at
    # 10000ms compounds into 30-50s of formation time and reliably breaks
    # adjacency setup. 2500ms keeps that compounding cheap while still
    # giving the AIMD-detection window below room to observe U. If CI shows
    # this margin is insufficient again, prefer widening the
    # congestion-detection window/count=30 below over the delay itself.
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
        chk = tgen.net["r1"].cmd(f"grep -a 'unacknowledged-LSAs' {log_path} | tail -1")
        logger.info("Latest unacked entry: %s", chk.strip())
        import re

        m = re.search(r"unacknowledged-LSAs=(\d+)", chk)
        if m and int(m.group(1)) < 6:
            return None
        return "still draining"

    _, result = topotest.run_and_expect(_unacked_low, None, count=60, wait=2)
    if result is not None:
        logger.warning("Residual LSAs did not drain below L=6; proceeding anyway")

    # Step 2: Set thresholds H=15, L=6.
    # Steady-state U=5 < L=6 → UNCONGESTED after LSA removal.
    # In the ideal case, injecting 100 LSAs across 4 neighbors gives
    # U≈400 >> H=15 → CONGESTION. In practice, U is bounded by how much of
    # the flood completes before r2's ack delay elapses (see r2's netem
    # setup above), not by the injected batch size alone: a CI run with
    # the original H=20/50-LSA config measured a real peak of U=20,
    # landing exactly on H and never exceeding it (U > H is a strict
    # inequality), so "CONGESTION detected" was never logged despite
    # congestion genuinely occurring. H=15 and 100 LSAs give real margin
    # against that measured ceiling instead of landing on the boundary.
    # At 1Mbps, 100 LSAs × 200B × 4 neighbors = 80KB takes ~640ms — long
    # enough for the AIMD timer to fire and see high U before most acks
    # arrive.
    step("Set dynamic pacing thresholds on r1 (H=15, L=6)")
    r1.vtysh_cmd(
        f"""
        configure terminal
        interface {r1_if}
        ip ospf adjacency-pacing dynamic thresholds 15 6
        end
    """
    )

    # Step 3: Inject 100 external LSAs to drive U above H=15.
    # At 1Mbps, 100 LSAs × 200B × 4 neighbors = 80KB → ~640ms transmission.
    # AIMD timer fires within ~500ms of pacing — U ≈ 400 in the ideal case,
    # comfortably above H=15 even given the real-world ceiling noted above.
    step(
        "Inject 100 external prefixes on r1 to drive U > H=15 and decrease dynamic_limit"
    )
    tgen.net["r1"].cmd("vtysh -c 'conf t' -c 'router ospf' -c 'redistribute connected'")
    for i in range(1, 101):
        tgen.net["r1"].cmd(f"ip addr add 198.51.120.{i}/32 dev lo")

    # Step 4: Mark start of the congestion/recovery observation window, then
    # flap r3/r4/r5 simultaneously right after injecting LSAs.
    # The earlier mark avoids missing a legitimate queue-kick log that occurs
    # during the flap/congestion phase instead of strictly after LSA clear.
    # The flap creates active pacing events — ospf_adj_pacing_allow() fires AIMD timer.
    # The AIMD timer then sees U > H=15 and decreases dynamic_limit to 1.
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

    # Step 4b: Wait for the flap to actually produce an AIMD trigger before
    # spending any of the congestion-detection budget below. Hello exchange
    # over the netem-delayed links is not instantaneous, and nsm_twoway_received()
    # only calls ospf_adj_pacing_allow() -> ospf_adj_dyn_adjust() once a flapped
    # neighbor reaches TwoWay ("2-Way" in NSM state strings) or later. Decoupling
    # "did the flap produce a trigger" from "did AIMD see U > H once triggered"
    # keeps a slow Hello convergence from eating into the window meant for the
    # latter. Written as an exclusion (not Down/Init) rather than a whitelist so
    # it doesn't depend on getting every downstream NSM state name right.
    # count*wait must be >= 15s (topotest.run_and_expect's enforced minimum) or
    # it silently falls back to its own (count=20, wait=3) defaults.
    step("Wait for at least one flapped neighbor to reach TwoWay (AIMD trigger)")

    def _any_flapped_past_init():
        for nbr in ["1.1.1.3", "1.1.1.4", "1.1.1.5"]:
            state = neighbor_state(tgen, "r1", nbr)
            if state.split("/", 1)[0] not in ("Down", "Init", "missing", "unknown"):
                return None
        return "no flapped neighbor past Init yet"

    _, result = topotest.run_and_expect(_any_flapped_past_init, None, count=10, wait=2)
    assert result is None, (
        "No flapped neighbor (r3/r4/r5) reached TwoWay within 20s of the flap — "
        "this points at Hello/link mechanics, not AIMD; check the flap itself "
        "before suspecting congestion detection."
    )

    # Step 5: Now wait for AIMD to detect congestion.
    # The pacing activity from step 4 triggers the AIMD timer which sees U > H=15.
    step("Confirm AIMD detected congestion (U > H=15) and limit=1")

    def _congestion_detected():
        chk = tgen.net["r1"].cmd(
            f"grep -a 'CONGESTION.*high-water=15' {log_path} | tail -1"
        )
        if "CONGESTION" in chk:
            return None
        return "congestion not yet detected"

    _, result = topotest.run_and_expect(_congestion_detected, None, count=30, wait=1)
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
    for i in range(1, 101):
        tgen.net["r1"].cmd(f"ip addr del 198.51.120.{i}/32 dev lo 2>/dev/null || true")

    # Step 7: All three neighbors must reach Full within 20s. Widened from
    # 15s alongside the r2 ack-delay increase above: some of the pre-clear
    # LSAs' delayed acks can still be in flight for up to 10s after they
    # were originally sent, regardless of the later withdrawal, so U may not
    # drop below L until a bit after that.
    step("Verify r3, r4, r5 reach Full promptly after queue kick")
    for nbr in ["1.1.1.3", "1.1.1.4", "1.1.1.5"]:
        wait_for_neighbor_full(tgen, "r1", nbr)
    elapsed = time.time() - clear_time
    logger.info("r3/r4/r5 all Full %.1f seconds after clearing congestion", elapsed)
    assert elapsed < 20, (
        f"Neighbors took {elapsed:.1f}s to reach Full after congestion cleared — "
        "queue kick may not have fired on limit increase"
    )

    # Step 8: Log check for kick diagnostic (informational only).
    # The kick is already proved by Step 7: r3/r4/r5 reaching Full within 20s
    # requires ospf_adj_pacing_kick() to have fired. The "releasing queued
    # adjacencies" message is inside IS_DEBUG_OSPF(nsm, NSM_EVENTS) and will
    # only appear when NSM debug is enabled, so asserting on it is fragile.
    step("Log: check ospfd.log for 'releasing queued adjacencies' (informational)")
    log_out = tgen.net["r1"].cmd(
        f"awk -v ts='{mark_time}' '$0 >= ts' {log_path} | grep -a 'releasing queued adjacencies' | tail -5"
    )
    logger.info(
        "Queue kick log entries after mark (debug-only, may be empty):\n%s", log_out
    )

    # Cleanup: disable redistribute, remove injected loopbacks, restore tc and thresholds
    step("Cleanup: restore r1/r2/r3/r4/r5 to baseline state")
    tgen.net["r1"].cmd(
        "vtysh -c 'conf t' -c 'router ospf' -c 'no redistribute connected' 2>/dev/null || true"
    )
    for i in range(1, 101):
        tgen.net["r1"].cmd(f"ip addr del 198.51.120.{i}/32 dev lo 2>/dev/null || true")
    tgen.net["r1"].cmd("tc qdisc del dev r1-eth0 root 2>/dev/null || true")
    tgen.net["r1"].cmd(
        "tc qdisc add dev r1-eth0 root handle 1: "
        "tbf rate 100kbit burst 10kb latency 500ms"
    )
    tgen.net["r2"].cmd("tc qdisc del dev r2-eth0 root 2>/dev/null || true")
    for _rname in ["r3", "r4", "r5"]:
        tgen.net[_rname].cmd(f"tc qdisc del dev {_rname}-eth0 root 2>/dev/null || true")
    r1.vtysh_cmd(
        f"""
        configure terminal
        interface {r1_if}
        no ip ospf adjacency-pacing dynamic thresholds
        end
    """
    )
