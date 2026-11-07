#!/usr/bin/env python
# SPDX-License-Identifier: ISC
#
# test_ospf_adj_reset_damping.py
#
# Copyright (c) 2026
#

"""
test_ospf_adj_reset_damping.py
==============================

Regression for ospfd adjacency reset loops without damping (RFC 2328
Sections 10.7/10.8).  A non-duplicate Database Description packet or an
LS Request for an absent LSA forces a Full (or Exchange/Loading) neighbor
back to ExStart; every restart clears and rebuilds the database summary
list from the whole LSDB, re-originates the router/network LSAs and, with
log-adjacency-changes detail, logs an unthrottled "Negotiation done
(Master)." line.  An on-link attacker can therefore retrigger the full
exchange cost once per packet.  The mandated transition must stay, but
repeats within the reset hold-down window are suppressed.

Topology
--------

    r1 (RID 10.255.5.2, DD Master) ----sw---- r2 (RID 10.255.5.1)

r2 injects unicast OSPF packets (TTL 1, protocol 89) with r2's address
towards r1, so they are attributed to the real r1-r2 adjacency.

Test plan
---------

1. test_adjacency_full_and_default_config
     Baseline: adjacency reaches Full both ways, LSDB and loopback route
     are present, and no adjacency-pacing is configured (default).
2. test_baseline_no_injection
     Without triggers the adjacency stays Full with no resets.
3. test_invalid_checksum_control
     A corrupted-checksum DD and LS Request are rejected before the NSM;
     no reset.
4. test_valid_lsreq_control
     An LS Request for an LSA present in the LSDB is served with an LSU;
     no reset.
5. test_nonduplicate_dd_resets_damped / test_bad_lsreq_resets_damped
     Four Full-paced triggers (one per re-formed adjacency).  The first
     reset must happen (the RFC 2328 transition is preserved); repeats
     inside the hold-down window must be suppressed, bounding exchange
     restarts, db_sum rebuilds and negotiation logs.  The reset bound
     is derived from the measured injection times, so runner speed
     alone cannot invalidate the assertions; unpatched ospfd resets
     once per input and fails these tests.
"""

import json
import os
import shlex
import socket
import struct
import sys
import time

import pytest
from scapy.layers.inet import IP  # noqa: F401  (registers layers for rdpcap)
from scapy.layers.l2 import Ether  # noqa: F401  (registers layers for rdpcap)
from scapy.utils import rdpcap

# pylint: disable=C0413
from lib import topotest
from lib.topogen import Topogen, get_topogen
from lib.topolog import logger
from lib.common_config import step

CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

pytestmark = [pytest.mark.ospfd]

R1 = "r1"
R2 = "r2"
R1_IP = "10.215.5.1"
R2_IP = "10.215.5.2"
R1_RID = "10.255.5.2"
R2_RID = "10.255.5.1"
R1_LOOPBACK = "198.51.100.1"
R2_LOOPBACK = "198.51.100.2"
R1_IFACE = "r1-eth0"
R2_IFACE = "r2-eth0"
DD_BASE_SEQ = 0x42500000
BURST_COUNT = 4
# Re-negotiation after a one-sided reset takes one RetransmitInterval
# (~5s): the slave misses the master's first initial DBD and the master
# retransmits.  The first trigger's tail must cover it so the db_sum
# rebuild is observed.
CAPTURE_TAIL = 6.0
# Follow-up trigger phases use a short tail: only a reset produces
# renegotiation traffic worth capturing, and the first trigger always
# resets.  Keeping the tail short keeps the next injection inside the
# hold-down window even on slow runners.
TRIGGER_FOLLOWUP_TAIL = 1.5
PACKET_SPACING = 0.2
RECOVERY_WAIT_SECONDS = 15
POLL_INTERVAL = 0.05
# Reset hold-down window; must match OSPF_NSM_RESET_HOLDDOWN_USEC in
# ospfd/ospf_nsm.c.  The per-burst reset bound is computed from the
# measured injection times against this window, so the bound adapts to
# the runner's actual timing instead of assuming a fixed phase spacing.
RESET_HOLD_DOWN_SECONDS = 10


def build_topo(tgen):
    tgen.add_router(R1)
    tgen.add_router(R2)
    switch = tgen.add_switch("sw1")
    switch.add_link(tgen.gears[R1])
    switch.add_link(tgen.gears[R2])


def setup_module(mod):
    tgen = Topogen(build_topo, mod.__name__)
    tgen.start_topology()

    for rname, router in tgen.routers().items():
        router.load_frr_config(os.path.join(CWD, rname, "frr.conf"))

    tgen.start_router()


def teardown_module():
    tgen = get_topogen()
    tgen.stop_topology()


def internet_checksum(data):
    if len(data) % 2:
        data += b"\x00"
    total = sum(struct.unpack("!%dH" % (len(data) // 2), data))
    total = (total & 0xFFFF) + (total >> 16)
    total = (total & 0xFFFF) + (total >> 16)
    return (~total) & 0xFFFF


def ospf_header(packet_type, body, corrupt):
    packet = bytearray(
        struct.pack(
            "!BBH4s4sHH8s",
            2,
            packet_type,
            24 + len(body),
            socket.inet_aton(R2_RID),
            socket.inet_aton("0.0.0.0"),
            0,
            0,
            b"\x00" * 8,
        )
        + body
    )
    struct.pack_into("!H", packet, 12, internet_checksum(bytes(packet)))
    if corrupt:
        packet[13] ^= 0x01
    valid = internet_checksum(bytes(packet)) == 0
    if valid == corrupt:
        raise ValueError("incorrect generated OSPF checksum state")
    return bytes(packet)


def packet_record(label, packet_type, body, fields, corrupt=False):
    packet = ospf_header(packet_type, body, corrupt)
    return {
        "ospf_hex": packet.hex(),
        "fields": {
            "label": label,
            "ospf_type": packet_type,
            "ospf_router_id": R2_RID,
            "checksum_corrupted": corrupt,
            **fields,
        },
    }


def make_dd(label, sequence, corrupt=False):
    body = struct.pack("!HBBI", 1500, 0x02, 0, sequence)
    return packet_record(
        label,
        2,
        body,
        {
            "dd_seq": "0x%08x" % sequence,
            "dd_lsa_headers": 0,
        },
        corrupt,
    )


def make_ls_request(label, ls_id, adv_router, corrupt=False):
    body = struct.pack(
        "!I4s4s", 1, socket.inet_aton(ls_id), socket.inet_aton(adv_router)
    )
    return packet_record(
        label,
        3,
        body,
        {
            "request_count": 1,
            "ls_type": 1,
            "ls_id": ls_id,
            "adv_router": adv_router,
        },
        corrupt,
    )


def vty_json(router, command):
    return router.vtysh_cmd(command, isjson=True)


def find_neighbor(value, peer_ip):
    if isinstance(value, dict):
        if (
            "nbrState" in value
            and "databaseSummaryListCounter" in value
            and value.get("ifaceAddress") == peer_ip
        ):
            return value
        for child in value.values():
            found = find_neighbor(child, peer_ip)
            if found is not None:
                return found
    elif isinstance(value, list):
        for child in value:
            found = find_neighbor(child, peer_ip)
            if found is not None:
                return found
    return None


def neighbor_snapshot(router, peer_rid, peer_ip):
    data = vty_json(router, "show ip ospf neighbor %s detail json" % peer_rid)
    neighbor = find_neighbor(data, peer_ip)
    if neighbor is None:
        return {"state": "Absent", "state_change": None, "db_sum": None}
    return {
        "state": neighbor.get("nbrState"),
        "state_change": neighbor.get("stateChangeCounter"),
        "db_sum": neighbor.get("databaseSummaryListCounter"),
        "ls_req": neighbor.get("linkStateRequestListCounter"),
        "last_regress_reason": neighbor.get("lastRegressiveChangeReason"),
    }


def neighbor_full(router, peer_rid, peer_ip):
    snapshot = neighbor_snapshot(router, peer_rid, peer_ip)
    return bool(snapshot["state"] and snapshot["state"].startswith("Full/"))


def expect_full(tgen):
    for rname, peer_rid, peer_ip in ((R1, R2_RID, R2_IP), (R2, R1_RID, R1_IP)):
        wait_neighbor_full(tgen.gears[rname], peer_rid, peer_ip)


def traffic(router):
    data = vty_json(router, "show ip ospf interface traffic %s json" % R1_IFACE)
    counters = data.get(R1_IFACE)
    if counters is None:
        raise RuntimeError("traffic counters absent for %s: %s" % (R1_IFACE, data))
    return counters


def ospfd_log_path(tgen, rname):
    return os.path.join(tgen.logdir, rname, "ospfd.log")


def log_offset(path):
    try:
        return os.path.getsize(path)
    except OSError:
        return 0


def read_log_since(path, offset):
    with open(path, encoding="utf-8", errors="replace") as fp:
        fp.seek(offset)
        return fp.read()


def log_metrics(text):
    lines = text.splitlines()
    return {
        "line_count": len(lines),
        "seq_full_to_exstart": sum(
            "State change Full -> ExStart (SeqNumberMismatch)" in line for line in lines
        ),
        "bad_lsreq_full_to_exstart": sum(
            "State change Full -> ExStart (BadLSReq)" in line for line in lines
        ),
        "negotiation_master": sum(
            "Negotiation done (Master)." in line for line in lines
        ),
        "initializing_dd": sum("Initializing [DD]" in line for line in lines),
        "reset_suppressed": sum(
            "exchange restart suppressed" in line for line in lines
        ),
    }


def packet_events(pcap_path, epoch, injected):
    """Parse the pcap into the manul reproducer's per-packet event dicts."""
    events = []
    for packet in rdpcap(pcap_path):
        if not packet.haslayer("IP"):
            continue
        raw = bytes(packet["IP"].payload)
        if len(raw) < 24 or raw[0] != 2:
            continue
        packet_type = raw[1]
        declared_length = struct.unpack("!H", raw[2:4])[0]
        if declared_length < 24 or declared_length > len(raw):
            continue
        raw = raw[:declared_length]
        event = {
            "time": round(float(packet.time) - epoch, 6),
            "src": packet["IP"].src,
            "dst": packet["IP"].dst,
            "type": packet_type,
        }
        label = injected.get(raw.hex())
        if label is not None:
            event["injection_label"] = label
        if packet_type == 2 and declared_length >= 32:
            event["lsa_headers"] = (declared_length - 32) // 20
        elif packet_type == 4 and declared_length >= 28:
            count = struct.unpack("!I", raw[24:28])[0]
            lsas = []
            offset = 28
            for _ in range(count):
                if offset + 20 > declared_length:
                    break
                length = struct.unpack("!H", raw[offset + 18 : offset + 20])[0]
                if length < 20 or offset + length > declared_length:
                    break
                lsas.append(
                    {
                        "type": raw[offset + 3],
                        "id": socket.inet_ntoa(raw[offset + 4 : offset + 8]),
                        "adv_router": socket.inet_ntoa(raw[offset + 8 : offset + 12]),
                    }
                )
                offset += length
            event["lsas"] = lsas
        events.append(event)
    return events


def capture_cycles(capture, events):
    sent = sorted(capture["sent"], key=lambda item: item["time"])
    cycles = []
    for index, item in enumerate(sent):
        end = (
            sent[index + 1]["time"]
            if index + 1 < len(sent)
            else capture["capture_duration_seconds"]
        )
        window_events = [
            event for event in events if item["time"] <= event["time"] < end
        ]
        target_dd = [
            event
            for event in window_events
            if event["src"] == R1_IP and event["type"] == 2
        ]
        target_lsu = [
            event
            for event in window_events
            if event["src"] == R1_IP and event["type"] == 4
        ]
        cycles.append(
            {
                "label": item["label"],
                "window": [item["time"], end],
                "injected_copies": sum(
                    1
                    for event in window_events
                    if event.get("injection_label") == item["label"]
                ),
                "target_dd_packets": len(target_dd),
                "target_summary_dd_packets": sum(
                    1 for event in target_dd if event.get("lsa_headers", 0) > 0
                ),
                "target_lsu_lsas": [
                    lsa for event in target_lsu for lsa in event.get("lsas", [])
                ],
            }
        )
    return cycles


def wait_neighbor_full(router, peer_rid, peer_ip, timeout=90):
    def _poll():
        state = neighbor_snapshot(router, peer_rid, peer_ip)["state"]
        return None if state and state.startswith("Full/") else state or "missing"

    _, result = topotest.run_and_expect(_poll, None, count=timeout, wait=1)
    assert result is None, "%s not Full with %s: %s" % (
        router.name,
        peer_rid,
        result,
    )


def run_phase(
    tgen, name, packets, spacing=PACKET_SPACING, tail=CAPTURE_TAIL, duration=0
):
    r1 = tgen.gears[R1]
    r2 = tgen.gears[R2]
    wait_neighbor_full(r1, R2_RID, R2_IP)

    pcap_path = os.path.join(tgen.logdir, "%s.pcap" % name)
    result_path = os.path.join(tgen.logdir, "%s_capture.json" % name)
    before = neighbor_snapshot(r1, R2_RID, R2_IP)
    before_traffic = traffic(r1)
    log_path = ospfd_log_path(tgen, R1)
    before_log = log_offset(log_path)

    src_mac = r2.cmd("cat /sys/class/net/%s/address" % R2_IFACE).strip()
    dst_mac = r1.cmd("cat /sys/class/net/%s/address" % R1_IFACE).strip()
    helper_cfg = {
        "iface": R2_IFACE,
        "src_ip": R2_IP,
        "dst_ip": R1_IP,
        "src_mac": src_mac,
        "dst_mac": dst_mac,
        "packets": packets,
        "spacing": spacing,
        "tail": tail,
        "duration": duration,
        "pcap_path": pcap_path,
        "result_path": result_path,
    }
    r2.cmd_raises(
        "python3 %s/inject_ospf.py %s"
        % (shlex.quote(CWD), shlex.quote(json.dumps(helper_cfg)))
    )

    recovered = False
    deadline = time.monotonic() + RECOVERY_WAIT_SECONDS
    while time.monotonic() < deadline:
        if neighbor_full(r1, R2_RID, R2_IP):
            recovered = True
            break
        time.sleep(POLL_INTERVAL)
    assert recovered, "%s: r1 did not return to Full within %ds" % (
        name,
        RECOVERY_WAIT_SECONDS,
    )

    after = neighbor_snapshot(r1, R2_RID, R2_IP)
    with open(result_path) as fp:
        capture = json.load(fp)
    injected = {item["ospf_hex"]: item["label"] for item in capture["sent"]}
    events = packet_events(pcap_path, capture["epoch"], injected)
    metrics = log_metrics(read_log_since(log_path, before_log))
    after_traffic = traffic(r1)
    return {
        "name": name,
        "before": before,
        "after": after,
        "recovered_full": recovered,
        "cycles": capture_cycles(capture, events),
        "inject_times": [capture["epoch"] + item["time"] for item in capture["sent"]],
        "log": metrics,
        "traffic_delta": {
            key: after_traffic[key] - before_traffic[key]
            for key in (
                "dbDescIn",
                "dbDescOut",
                "lsReqIn",
                "lsReqOut",
                "lsUpdIn",
                "lsUpdOut",
            )
        },
        "capture_result_path": result_path,
        "pcap_path": pcap_path,
    }


def no_reset(phase):
    logs = phase["log"]
    return (
        logs["seq_full_to_exstart"] == 0
        and logs["bad_lsreq_full_to_exstart"] == 0
        and logs["negotiation_master"] == 0
        and logs["initializing_dd"] == 0
        and phase["recovered_full"]
    )


def run_trigger_sequence(tgen, name, packets):
    phases = []
    for index, packet in enumerate(packets):
        label = packet["fields"]["label"]
        tail = CAPTURE_TAIL if index == 0 else TRIGGER_FOLLOWUP_TAIL
        phases.append(run_phase(tgen, "%s_%s" % (name, label), [packet], tail=tail))
    return phases


def damped_reset_allowance(phases):
    """Resets a correctly damped ospfd may produce for these injections.

    Simulate the per-neighbor hold-down: an input resets only when it
    lands at least RESET_HOLD_DOWN_SECONDS after the previous reset.
    Injection times double as reset times; the scheduled event executes
    within milliseconds of the packet.
    """
    times = sorted(t for phase in phases for t in phase["inject_times"])
    allowance = 0
    last_reset = None
    for inject_time in times:
        if last_reset is None or inject_time - last_reset >= RESET_HOLD_DOWN_SECONDS:
            allowance += 1
            last_reset = inject_time
    return allowance


def check_damped_burst(phases, event_name, reset_key):
    resets = sum(phase["log"][reset_key] for phase in phases)
    allowance = damped_reset_allowance(phases)
    master_logs = sum(phase["log"]["negotiation_master"] for phase in phases)
    summary_dd = sum(
        cycle["target_summary_dd_packets"]
        for phase in phases
        for cycle in phase["cycles"]
    )
    injected = [cycle for phase in phases for cycle in phase["cycles"]]
    logger.info(
        "%s burst: resets=%d allowance=%d negotiation_master=%d "
        "summary_dd=%d suppressed=%d",
        event_name,
        resets,
        allowance,
        master_logs,
        summary_dd,
        sum(phase["log"]["reset_suppressed"] for phase in phases),
    )
    assert all(
        cycle["injected_copies"] == 1 for cycle in injected
    ), "every injected packet must be observed exactly once on the wire"
    assert phases[0]["log"][reset_key] >= 1, (
        "the first %s trigger must still reset Full -> ExStart (RFC 2328)" % event_name
    )
    assert allowance < len(phases), (
        "no trigger landed inside the %ds hold-down window; "
        "the runner is too slow to verify damping" % RESET_HOLD_DOWN_SECONDS
    )
    assert resets <= allowance, (
        "%s resets not damped: %d resets for %d Full-paced inputs "
        "(damped allowance %d)" % (event_name, resets, len(phases), allowance)
    )
    assert master_logs <= resets, (
        "unthrottled negotiation logs: %d 'Negotiation done (Master).' "
        "for %d resets" % (master_logs, resets)
    )
    assert summary_dd >= 1, "db_sum was never rebuilt after the reset"
    assert all(
        phase["recovered_full"] for phase in phases
    ), "adjacency did not recover to Full after every input"


def test_adjacency_full_and_default_config():
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    step("Wait for Full adjacency both ways")
    expect_full(tgen)

    r1 = tgen.gears[R1]
    running = r1.vtysh_cmd("show running-config")
    pacing_lines = [line for line in running.splitlines() if "adjacency-pacing" in line]
    assert not pacing_lines, (
        "adjacency-pacing must not be configured by default: %s" % pacing_lines
    )

    database = r1.vtysh_cmd("show ip ospf database json", isjson=True)
    database_raw = json.dumps(database)
    assert (
        R1_RID in database_raw and R2_RID in database_raw
    ), "baseline LSDB is missing a router-LSA"

    def _route_ready():
        route_raw = r1.vtysh_cmd("show ip route %s/32 json" % R2_LOOPBACK)
        if R2_LOOPBACK in route_raw and "ospf" in route_raw.lower():
            return None
        return route_raw

    _, result = topotest.run_and_expect(_route_ready, None, count=30, wait=1)
    assert result is None, "no OSPF route to r2 loopback: %s" % result


def test_baseline_no_injection():
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    step("Baseline: no injection must not reset the adjacency")
    phase = run_phase(tgen, "baseline_no_injection", [], duration=3.0)
    assert len(phase["cycles"]) == 0
    assert no_reset(phase), "untriggered baseline was not stable: %s" % phase["log"]


def test_invalid_checksum_control():
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    step("Control: corrupted-checksum packets are rejected before the NSM")
    phase = run_phase(
        tgen,
        "invalid_checksum_control",
        [
            make_dd("invalid_dd", DD_BASE_SEQ - 1, True),
            make_ls_request("invalid_lsreq", "10.255.5.99", R2_RID, True),
        ],
        spacing=0.5,
        tail=1.5,
    )
    assert len(phase["cycles"]) == 2
    assert all(
        cycle["injected_copies"] == 1 for cycle in phase["cycles"]
    ), "corrupted packets were not observed on the wire"
    assert phase["traffic_delta"]["dbDescIn"] == 0, (
        "corrupted DD reached the DD handler: %s" % phase["traffic_delta"]
    )
    assert phase["traffic_delta"]["lsReqIn"] == 0, (
        "corrupted LS Request reached the LS Request handler: %s"
        % phase["traffic_delta"]
    )
    assert no_reset(phase), "corrupted packets caused a reset: %s" % phase["log"]


def test_valid_lsreq_control():
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    step("Control: a valid LS Request is served with the requested LSA")
    phase = run_phase(
        tgen,
        "valid_existing_lsa_request_control",
        [make_ls_request("valid_existing_lsreq", R1_RID, R1_RID)],
        tail=1.5,
    )
    assert len(phase["cycles"]) == 1
    assert phase["cycles"][0]["injected_copies"] == 1
    assert phase["traffic_delta"]["lsReqIn"] >= 1, (
        "valid LS Request did not reach the handler: %s" % phase["traffic_delta"]
    )
    served = any(
        lsa["type"] == 1 and lsa["id"] == R1_RID and lsa["adv_router"] == R1_RID
        for cycle in phase["cycles"]
        for lsa in cycle["target_lsu_lsas"]
    )
    assert served, "requested router-LSA was not returned in an LSU"
    assert no_reset(phase), "valid LS Request caused a reset: %s" % phase["log"]


def test_nonduplicate_dd_resets_damped():
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    step("Trigger: %d Full-paced non-duplicate DD packets" % BURST_COUNT)
    phases = run_trigger_sequence(
        tgen,
        "nonduplicate_dd",
        [make_dd("dd_%d" % index, DD_BASE_SEQ + index) for index in range(BURST_COUNT)],
    )
    check_damped_burst(phases, "SeqNumberMismatch", "seq_full_to_exstart")
    expect_full(tgen)


def test_bad_lsreq_resets_damped():
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    absent_ids = ["10.255.5.%d" % (100 + index) for index in range(BURST_COUNT)]
    database = tgen.gears[R1].vtysh_cmd("show ip ospf database json", isjson=True)
    database_raw = json.dumps(database)
    assert not any(
        ls_id in database_raw for ls_id in absent_ids
    ), "a BadLSReq target already exists in the baseline LSDB"

    step("Trigger: %d Full-paced LS Requests for absent LSAs" % BURST_COUNT)
    # The reset hold-down is per-neighbor and shared by both event types;
    # wait it out so the first BadLSReq exercises the RFC 2328 transition
    # instead of being damped as a repeat of the DD burst.
    time.sleep(RESET_HOLD_DOWN_SECONDS + 1)
    phases = run_trigger_sequence(
        tgen,
        "bad_lsreq",
        [
            make_ls_request("bad_lsreq_%d" % index, absent_ids[index], R2_RID)
            for index in range(BURST_COUNT)
        ],
    )
    check_damped_burst(phases, "BadLSReq", "bad_lsreq_full_to_exstart")
    expect_full(tgen)
