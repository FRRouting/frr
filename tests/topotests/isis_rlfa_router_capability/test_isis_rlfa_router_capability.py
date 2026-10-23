#!/usr/bin/env python
# SPDX-License-Identifier: ISC
#
# test_isis_rlfa_router_capability.py
# Part of NetDEF Topology Tests
#
# Copyright (c) 2026 by Bing Shui <bingshui@smail.nju.edu.cn>
#

"""
test_isis_rlfa_router_capability.py:

        r2 (observer)                    r4 (destination)
          |  r1-eth0 / r2-eth0              ^  r2-eth1 / r4-eth0
          v                                 |
        r1 (victim)                         |
          |  r1-eth1 / r3-eth0              |
          v                                 |
        r3 (injector) --- r3-eth1/r5-eth0 --- r5 (PQ node)
                            r5-eth1/r4-eth1 --^

All links are point-to-point, level-2-only, area 49.0001, wide metrics.
Link metrics: r1-r2=10, r2-r4=10, r1-r3=5, r3-r5=30, r5-r4=30.

r1 protects the destination 10.0.255.4/32 with local LFA and remote LFA
on both of its circuits.  The primary path r1->r2->r4 has metric 30; the
alternate path r1->r3->r5->r4 costs 75 and r3's best path to the
destination loops back through r1 (35 == 5+30), so local LFA finds no
repair and RLFA runs.  The extended P-space (r3, r5, r4) and Q-space
(r5, r3, r4) first intersect at r5 in the post-convergence DFS, so the
first PQ router-ID lookup is on r5's LSP.

rlfa_pq_node_rtr_id() read lsp->tlvs->router_cap->router_id without
checking that the LSP carries the Router Capability TLV, which RFC 7981
makes OPTIONAL; any other router_cap consumer in isisd checks for NULL
first.  The test re-sends r5's real LSP (captured on r3-eth1) from r3's
namespace toward r1 with a newer sequence number, the Router Capability
TLV removed, the PDU length fixed up and the ISO 8473 Fletcher checksum
recomputed.  On the unpatched build the next RLFA computation on r1
dereferences the missing router_cap and isisd dies; on the fixed build
the PQ candidate is skipped ("tentative PQ node ... doesn't have a
router-ID") and RLFA keeps working for the destinations whose PQ node
still carries a valid Router Capability.

Traffic is bounded: at most 2 PDUs per scenario, 1 PDU/s.
"""

import json
import os
import sys
import time

import pytest

# Save the Current Working Directory to find configuration files.
CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

# pylint: disable=C0413
# Import topogen and topotest helpers
from lib.topogen import Topogen, TopoRouter, get_topogen

pytestmark = [pytest.mark.isisd]

VICTIM = "r1"
OBSERVER = "r2"
INJECTOR = "r3"
DEST_ROUTER = "r4"
PQ_ROUTER = "r5"

PQ_SYSID = "000000000005"
INJECTOR_SYSID = "000000000003"
DEST_SYSID = "000000000004"
PQ_LSP_ID = PQ_SYSID + "0000"
INJECTOR_LSP_ID = INJECTOR_SYSID + "0000"

PQ_ROUTER_ID = "10.0.255.5"
DEST_ROUTER_ID = "10.0.255.4"
DEST_LOOPBACK = "10.0.255.4/32"
HELPER = os.path.join(CWD, "isis_rlfa_rc_helper.py")

FORGED_LIFETIME = 300
CAPTURE_TAIL = 2.0
CRASH_WAIT = 15.0


def build_topo(tgen):
    "Build function"

    for router in [VICTIM, OBSERVER, INJECTOR, DEST_ROUTER, PQ_ROUTER]:
        tgen.add_router(router)

    switch = tgen.add_switch("s1")
    switch.add_link(tgen.gears[VICTIM], nodeif="r1-eth0")
    switch.add_link(tgen.gears[OBSERVER], nodeif="r2-eth0")
    switch = tgen.add_switch("s2")
    switch.add_link(tgen.gears[VICTIM], nodeif="r1-eth1")
    switch.add_link(tgen.gears[INJECTOR], nodeif="r3-eth0")
    switch = tgen.add_switch("s3")
    switch.add_link(tgen.gears[OBSERVER], nodeif="r2-eth1")
    switch.add_link(tgen.gears[DEST_ROUTER], nodeif="r4-eth0")
    switch = tgen.add_switch("s4")
    switch.add_link(tgen.gears[INJECTOR], nodeif="r3-eth1")
    switch.add_link(tgen.gears[PQ_ROUTER], nodeif="r5-eth0")
    switch = tgen.add_switch("s5")
    switch.add_link(tgen.gears[DEST_ROUTER], nodeif="r4-eth1")
    switch.add_link(tgen.gears[PQ_ROUTER], nodeif="r5-eth1")


def setup_module(mod):
    "Sets up the pytest environment"
    tgen = Topogen(build_topo, mod.__name__)
    tgen.start_topology()

    router_list = tgen.routers()
    for rname, router in router_list.items():
        router.load_config(
            TopoRouter.RD_ZEBRA, os.path.join(CWD, "{}/zebra.conf".format(rname))
        )
        router.load_config(
            TopoRouter.RD_ISIS, os.path.join(CWD, "{}/isisd.conf".format(rname))
        )

    tgen.start_router()


def teardown_module():
    "Teardown the pytest environment"
    tgen = get_topogen()
    tgen.stop_topology()


def lsdb_by_sysid(router):
    "Map sysid hex -> {seqno, lifetime} for every LSP in the LSDB."
    data = json.loads(router.vtysh_cmd("show isis database json"))
    found = {}

    def parse_holdtime(value):
        hold = value.get("holdtime")
        if isinstance(hold, str):
            return 0
        return int(hold)

    def walk(value):
        if isinstance(value, dict):
            lsp = value.get("lsp")
            if isinstance(lsp, dict) and "id" in lsp and "seqNumber" in value:
                lsp_id = lsp["id"]
                sysid = lsp_id.replace(".", "").replace("-", "")[:12]
                found[sysid] = {
                    "seqno": int(value["seqNumber"], 16),
                    "lifetime": parse_holdtime(value),
                }
            for child in value.values():
                walk(child)
        elif isinstance(value, list):
            for child in value:
                walk(child)

    walk(data)
    return found


def lsp_router_cap(router, lsp_id_dotted):
    "The routerCapability object of the given LSP, or None when absent."
    data = json.loads(router.vtysh_cmd("show isis database detail json"))
    found = {}

    def walk(value):
        if isinstance(value, dict):
            lsp = value.get("lsp")
            if isinstance(lsp, dict) and lsp.get("id") == lsp_id_dotted:
                found["cap"] = value.get("routerCapability")
            for child in value.values():
                walk(child)
        elif isinstance(value, list):
            for child in value:
                walk(child)

    walk(data)
    return found.get("cap")


def adjacency_up(router, peer_ip):
    raw = router.vtysh_cmd("show isis neighbor detail")
    for block in raw.split("\n\n"):
        if peer_ip in block and "State: Up" in block:
            return True
    return False


def isisd_alive(router):
    pid = router.cmd("cat /var/run/frr/isisd.pid 2>/dev/null").strip()
    if not pid:
        return False
    return router.cmd("kill -0 {} 2>/dev/null; echo $?".format(pid)).strip() == "0"


def log_offset(router):
    log_path = os.path.join(get_topogen().logdir, router.name, "isisd.log")
    try:
        with open(log_path) as fp:
            return sum(1 for _ in fp)
    except FileNotFoundError:
        return 0


def log_since(router, offset):
    log_path = os.path.join(get_topogen().logdir, router.name, "isisd.log")
    with open(log_path) as fp:
        lines = fp.readlines()
    return lines[offset:]


def count_pq_logs(lines):
    found = {}
    for line in lines:
        if "found PQ node:" in line:
            rtr_id = line.split("found PQ node:")[1].strip()
            found[rtr_id] = found.get(rtr_id, 0) + 1
    return found


def run_helper(router, cfg, marker):
    cfg_path = os.path.join(get_topogen().logdir, cfg["name"] + "_input.json")
    with open(cfg_path, "w") as fp:
        json.dump(cfg, fp)
    raw = router.cmd("python3 {} {}".format(HELPER, cfg_path))
    for line in reversed(raw.splitlines()):
        if line.startswith(marker):
            return json.loads(line.split("=", 1)[1])
    raise RuntimeError("helper failed: {}".format(raw))


def start_observer(router, cfg):
    cfg_path = os.path.join(get_topogen().logdir, cfg["name"] + "_input.json")
    with open(cfg_path, "w") as fp:
        json.dump(cfg, fp)
    for stale in (cfg["stop_file"], cfg.get("out_json")):
        if stale and os.path.exists(stale):
            os.remove(stale)
    router.cmd(
        "cd {logdir} && (nohup python3 {helper} {cfg} > {name}.out 2>&1 &)".format(
            logdir=get_topogen().logdir, helper=HELPER, cfg=cfg_path, name=cfg["name"]
        )
    )


def stop_observer(cfg, timeout=20):
    with open(cfg["stop_file"], "w") as fp:
        fp.write("stop\n")
    out_log = os.path.join(get_topogen().logdir, cfg["name"] + ".out")
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            with open(out_log) as fp:
                if "OBS_DONE" in fp.read():
                    return
        except FileNotFoundError:
            pass
        time.sleep(0.5)
    raise RuntimeError("observer did not finish")


def check_convergence():
    "Wait until all adjacencies are up and the LSDB is complete."
    tgen = get_topogen()
    victim = tgen.gears[VICTIM]
    deadline = time.monotonic() + 120
    while time.monotonic() < deadline:
        try:
            if (
                adjacency_up(victim, "10.12.0.2")
                and adjacency_up(victim, "10.13.0.2")
                and len(lsdb_by_sysid(victim)) >= 5
            ):
                return True
        except Exception:
            pass
        time.sleep(1)
    return False


def test_isis_convergence():
    "Check IS-IS adjacencies, LSDB content and initial RLFA computation."
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    assert check_convergence(), "IS-IS adjacencies or LSDB did not converge"

    victim = tgen.gears[VICTIM]
    lsdb = lsdb_by_sysid(victim)
    assert PQ_SYSID in lsdb and DEST_SYSID in lsdb, "r5/r4 LSP missing from r1 LSDB"

    # Both PQ candidates carry the Router Capability TLV once zebra's
    # router-id has propagated; poll until it shows up.
    deadline = time.monotonic() + 60
    pq_cap = None
    while time.monotonic() < deadline and not pq_cap:
        try:
            pq_cap = lsp_router_cap(victim, "0000.0000.0005.00-00")
        except Exception:
            pq_cap = None
        if not pq_cap:
            time.sleep(1)
    dest_cap = lsp_router_cap(victim, "0000.0000.0004.00-00")
    assert pq_cap and pq_cap.get("id") == PQ_ROUTER_ID, (
        "r5 LSP lacks the Router Capability TLV in the baseline"
    )
    assert dest_cap and dest_cap.get("id") == DEST_ROUTER_ID, (
        "r4 LSP lacks the Router Capability TLV in the baseline"
    )

    # RLFA ran during convergence and found the PQ node; the log lines
    # appear as the topology converges, so poll for them.
    deadline = time.monotonic() + 90
    pq_logs = {}
    while time.monotonic() < deadline and not pq_logs.get(PQ_ROUTER_ID):
        pq_logs = count_pq_logs(log_since(victim, 0))
        if not pq_logs.get(PQ_ROUTER_ID):
            time.sleep(1)
    assert pq_logs.get(PQ_ROUTER_ID, 0) >= 1, (
        "no 'found PQ node: 10.0.255.5' in r1 log; RLFA did not run"
    )

    route = victim.vtysh_cmd("show isis route")
    assert DEST_LOOPBACK in route, "r1 has no IS-IS route to 10.0.255.4/32"


def test_isis_rlfa_missing_router_capability():
    "Forged PQ-node LSP without Router Capability must not crash isisd."
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    victim = tgen.gears[VICTIM]
    injector = tgen.gears[INJECTOR]
    observer = tgen.gears[OBSERVER]

    # Capture r5's and r3's LSPs as forging templates (PSNP-elicited, only
    # accepting a post-convergence LSP that carries the Router Capability
    # TLV).
    pq_template = run_helper(injector, {
        "role": "template",
        "name": "pq_template",
        "iface": "r3-eth1",
        "lsp_id": PQ_LSP_ID,
        "source_sysid": INJECTOR_SYSID,
        "require_router_cap": True,
        "timeout": 30,
        "pcap_path": os.path.join(tgen.logdir, "pq_template.pcap"),
    }, "TEMPLATE_JSON=")
    assert pq_template["template_hex"], "failed to capture r5 LSP template"
    inj_template = run_helper(injector, {
        "role": "template",
        "name": "inj_template",
        "iface": "r3-eth0",
        "lsp_id": INJECTOR_LSP_ID,
        "source_sysid": INJECTOR_SYSID,
        "require_router_cap": True,
        "timeout": 30,
        "pcap_path": os.path.join(tgen.logdir, "inj_template.pcap"),
    }, "TEMPLATE_JSON=")
    assert inj_template["template_hex"], "failed to capture r3 LSP template"

    pq_seq_base = lsdb_by_sysid(victim)[PQ_SYSID]["seqno"]
    inj_seq_base = lsdb_by_sysid(victim)[INJECTOR_SYSID]["seqno"]

    # Control 1: forged r5 LSP with the Router Capability TLV kept.
    log_mark = log_offset(victim)
    run_helper(injector, {
        "role": "inject",
        "name": "valid_lsp",
        "iface": "r3-eth0",
        "template_hex": pq_template["template_hex"],
        "lifetime": FORGED_LIFETIME,
        "frames": [[pq_seq_base + 1, False]],
        "tail": CAPTURE_TAIL,
        "pcap_path": os.path.join(tgen.logdir, "valid_lsp.pcap"),
    }, "ISIS_CAPTURE_JSON=")
    time.sleep(3)
    assert isisd_alive(victim), "r1 isisd died on a valid r5 LSP (TLV kept)"
    assert count_pq_logs(log_since(victim, log_mark)).get(PQ_ROUTER_ID, 0) >= 1, (
        "RLFA did not recompute after the valid forged LSP"
    )

    # Control 2: forged r3 LSP without the TLV; r3 is not a PQ candidate.
    run_helper(injector, {
        "role": "inject",
        "name": "non_pq_lsp",
        "iface": "r3-eth0",
        "template_hex": inj_template["template_hex"],
        "lifetime": FORGED_LIFETIME,
        "frames": [[inj_seq_base + 1, True]],
        "tail": CAPTURE_TAIL,
        "pcap_path": os.path.join(tgen.logdir, "non_pq_lsp.pcap"),
    }, "ISIS_CAPTURE_JSON=")
    time.sleep(3)
    assert isisd_alive(victim), "r1 isisd died on a non-PQ LSP without the TLV"

    # Attack: forged r5 LSP with the Router Capability TLV removed.  r1
    # must accept it (observed as r1's re-flood on the r1-r2 link), the
    # PQ candidate must be skipped, and isisd must stay alive.
    observer_cfg = {
        "role": "observer",
        "name": "observer",
        "iface": "r2-eth0",
        "stop_file": os.path.join(tgen.logdir, "observer.stop"),
        "out_json": os.path.join(tgen.logdir, "observer.json"),
        "pcap_path": os.path.join(tgen.logdir, "observer.pcap"),
    }
    start_observer(observer, observer_cfg)
    time.sleep(1)
    log_mark = log_offset(victim)
    victim_mac = victim.cmd("cat /sys/class/net/r1-eth0/address").strip()
    current_pq_seq = lsdb_by_sysid(victim)[PQ_SYSID]["seqno"]
    injected_seq = current_pq_seq + 1
    run_helper(injector, {
        "role": "inject",
        "name": "missing_tlv",
        "iface": "r3-eth0",
        "template_hex": pq_template["template_hex"],
        "lifetime": FORGED_LIFETIME,
        "frames": [[injected_seq, True]],
        "tail": CAPTURE_TAIL,
        "pcap_path": os.path.join(tgen.logdir, "missing_tlv.pcap"),
    }, "ISIS_CAPTURE_JSON=")

    deadline = time.monotonic() + CRASH_WAIT
    while isisd_alive(victim) and time.monotonic() < deadline:
        time.sleep(0.5)
    time.sleep(1)
    stop_observer(observer_cfg)
    with open(observer_cfg["out_json"]) as fp:
        observer_events = json.load(fp)["events"]
    refloods = [
        event for event in observer_events
        if event.get("pdutype") == 20
        and event.get("lspid") == PQ_LSP_ID
        and event.get("seqno") == injected_seq
        and event.get("src_mac") == victim_mac
    ]
    assert refloods, (
        "r1 did not re-flood the forged r5 LSP; the victim never processed it"
    )

    lines = log_since(victim, log_mark)
    assert isisd_alive(victim), (
        "r1 isisd died after processing the PQ-node LSP without Router "
        "Capability (NULL dereference in rlfa_pq_node_rtr_id)"
    )
    assert any("doesn't have a router-ID" in line for line in lines), (
        "r1 did not log 'tentative PQ node ... doesn't have a router-ID'"
    )
    assert any("no acceptable PQ node found" in line for line in lines), (
        "r1 did not log 'no acceptable PQ node found'"
    )
    # r5 fights the forged LSP back within lsp-gen-interval; once the real
    # LSP (with the TLV) is reinstalled, RLFA must compute again.
    deadline = time.monotonic() + 15
    recovered = False
    while time.monotonic() < deadline and not recovered:
        lines = log_since(victim, log_mark)
        recovered = count_pq_logs(lines).get(PQ_ROUTER_ID, 0) >= 1
        if not recovered:
            time.sleep(1)
    assert recovered, "RLFA did not recover after r5's fight-back LSP"
    route = victim.vtysh_cmd("show isis route")
    assert DEST_LOOPBACK in route, "r1 lost its IS-IS route to 10.0.255.4/32"


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    ret = pytest.main(args)
    sys.exit(ret)
