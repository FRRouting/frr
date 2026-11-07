#!/usr/bin/env python
# SPDX-License-Identifier: ISC
#
# test_ospf_crypto_replay.py
#
# Copyright (c) 2026 ATCorp
# Jafar Al-Gharaibeh
#

"""
test_ospf_crypto_replay.py
==========================

Regression for the OSPFv2 cryptographic sequence number window being
reinitialized when the neighbor FSM tears the adjacency down
(ospf_nsm.c cleared nbr->crypt_seqnum on NSM_Down, and every kill event
deletes the neighbor structure whose first accepted packet seeds the
window).  An attacker who recorded authenticated traffic can replay the
captured Hello/DD sequence after the adjacency drops and resurrect a
phantom adjacency with a peer that is no longer sending.

Topology
--------

    r1 (RID 10.255.14.1) ----eth1---- r2 (RID 10.255.14.2)
    10.214.14.1/24 point-to-point      10.214.14.2/24
    MD5 key 14 "b14replaykey" on both, area 0, hello 10s / dead 40s.

Test plan
---------

1. test_baseline_authenticated_full
     Baseline: authenticated Full adjacency, LSDB, route and ping.
2. test_capture_authenticated_exchange
     Capture r2's authenticated packets while the adjacency re-forms,
     then select a two-way Hello and the complete master DD chain with
     strictly increasing, digest-valid sequence numbers.
3. test_unreset_old_hello_rejected (control)
     With the adjacency still Full, replay the captured Hello: must be
     rejected as a stale sequence, adjacency untouched.
4. test_invalid_digest_fresh_hello_rejected (control)
     A fresh-sequence Hello with a corrupted digest must be rejected by
     the MD5 check.
5. test_replay_after_neighbor_down (regression)
     Stop r2's ospfd, clear the neighbor on r1, then replay the captured
     Hello and DD chain.  Every replayed packet must be rejected by the
     preserved sequence window: no new neighbor, no phantom Full.
6. test_legitimate_restart_recovers
     Restart r2's ospfd: the adjacency must re-form (a restarted peer
     uses the current time as its first sequence number, which is above
     the preserved window), proving the fix does not break legitimate
     restarts or authentication negotiation.
7. test_old_replay_still_rejected_after_recovery
     The captured packets from before the restart must still be
     rejected once the adjacency is back.
"""

import hashlib
import json
import os
import re
import shlex
import socket
import struct
import sys
import time
from functools import partial

import pytest
from scapy.all import Ether, IP, Raw, conf
from scapy.utils import rdpcap

conf.verb = 0

from lib.topogen import Topogen, get_topogen
from lib.topolog import logger

CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

pytestmark = [pytest.mark.ospfd]

R1_RID = "10.255.14.1"
R2_RID = "10.255.14.2"
R1_IP = "10.214.14.1"
R2_IP = "10.214.14.2"
R1_LOOPBACK = "198.18.14.1"
R2_LOOPBACK = "198.18.14.2"
KEY_ID = 14
AUTH_KEY = b"b14replaykey"
ALLSPFROUTERS = "224.0.0.5"
ALLSPFROUTERS_MAC = "01:00:5e:00:00:05"

BASELINE_TIMEOUT = 90
INJECT_SETTLE = 0.45
FINAL_FULL_WAIT = 6

# Populated by test_capture_authenticated_exchange, consumed by the
# later tests: the recorded frames (full L2 bytes) and their fields.
PLAN = {}
# Recorded observations, dumped to replay-evidence.json for review.
EVIDENCE = {}


def build_topo(tgen):
    r1 = tgen.add_router("r1")
    r2 = tgen.add_router("r2")
    tgen.add_link(r1, r2, ifname1="eth1", ifname2="eth1")


def setup_module(mod):
    tgen = Topogen(build_topo, mod.__name__)
    tgen.start_topology()

    for router in tgen.routers().values():
        router.load_frr_config()

    tgen.start_router()


def teardown_module():
    tgen = get_topogen()
    tgen.stop_topology()


def vty_json(router, command):
    return json.loads(router.vtysh_cmd(command))


def neighbor_entries(router):
    raw = vty_json(router, "show ip ospf neighbor json")
    entries = []
    for router_id, values in raw.get("neighbors", {}).items():
        for value in values:
            if value.get("ifaceAddress") in (R1_IP, R2_IP):
                entries.append({"router_id": router_id, **value})
    return entries


def neighbor_state(router, peer_ip):
    matches = [e for e in neighbor_entries(router) if e.get("ifaceAddress") == peer_ip]
    if not matches:
        return "Absent"
    if len(matches) != 1:
        return "Ambiguous"
    return matches[0].get("converged", "Unknown")


def compact_neighbors(router):
    return [
        {
            key: entry.get(key)
            for key in (
                "router_id",
                "converged",
                "ifaceAddress",
                "ifaceName",
                "linkStateRetransmissionListCounter",
                "linkStateRequestListCounter",
                "databaseSummaryListCounter",
            )
        }
        for entry in neighbor_entries(router)
    ]


def traffic(router):
    data = vty_json(router, "show ip ospf interface traffic eth1 json")
    if "eth1" in data:
        return data["eth1"]
    for iface in data.get("interfaces", {}).values():
        return iface
    raise RuntimeError("traffic counters absent for eth1: {}".format(data))


def counter_delta(before, after, keys):
    return {key: after.get(key, 0) - before.get(key, 0) for key in keys}


def ospfd_log_path(router):
    return os.path.join(get_topogen().logdir, router.name, "ospfd.log")


def log_offset(router):
    try:
        return os.path.getsize(ospfd_log_path(router))
    except FileNotFoundError:
        return 0


def log_since(router, offset):
    try:
        with open(ospfd_log_path(router), errors="replace") as fp:
            fp.seek(offset)
            return fp.read()
    except FileNotFoundError:
        return ""


def interesting_log(text):
    tokens = (
        "State change",
        "AdjChg:",
        "bad sequence",
        "checksum mismatch",
        "Negotiation done",
        "Sequence number",
    )
    return [line for line in text.splitlines() if any(t in line for t in tokens)]


def bad_sequence_records(text):
    pattern = re.compile(r"bad sequence (\d+) \(expect (>=|>) (\d+)\)")
    return [
        {
            "packet_seq": int(m.group(1)),
            "operator": m.group(2),
            "stored_seq": int(m.group(3)),
        }
        for m in pattern.finditer(text)
    ]


def _proc_alive(router, pid):
    out = router.cmd("kill -0 %s 2>/dev/null; echo $?" % pid).strip()
    try:
        return int(out.splitlines()[-1]) == 0
    except (ValueError, IndexError):
        return False


def _file_ready(path):
    try:
        return os.path.exists(path) and os.path.getsize(path) > 0
    except OSError:
        return False


def _wait_until(func, timeout_s=5, interval_s=0.25):
    deadline = time.time() + timeout_s
    while time.time() < deadline:
        if func():
            return True
        time.sleep(interval_s)
    return bool(func())


def start_capture(router, pcap_path, bpf):
    err_path = pcap_path + ".err"
    ready_path = pcap_path + ".ready"
    router.cmd(
        "rm -f %s %s %s"
        % (shlex.quote(pcap_path), shlex.quote(err_path), shlex.quote(ready_path))
    )
    pid = router.cmd(
        "nohup python3 %s/capture_ospf.py --iface eth1 --pcap %s "
        "--filter %s --ready-file %s </dev/null >%s 2>&1 & echo $!"
        % (
            shlex.quote(CWD),
            shlex.quote(pcap_path),
            shlex.quote(bpf),
            shlex.quote(ready_path),
            shlex.quote(err_path),
        )
    ).strip()
    if pid:
        pid = pid.splitlines()[-1]
    assert pid.isdigit(), "scapy capture did not start on %s (pid %r)" % (
        router.name,
        pid,
    )
    if not _wait_until(partial(_file_ready, ready_path)):
        err = router.cmd("cat %s 2>/dev/null || true" % shlex.quote(err_path))
        assert False, "scapy capture not ready on %s (pid %s): %s" % (
            router.name,
            pid,
            err.strip(),
        )
    return pid


def stop_capture(router, pid, pcap_path):
    err_path = pcap_path + ".err"
    router.cmd("kill -TERM %s >/dev/null 2>&1 || true" % pid)
    if not _wait_until(lambda: not _proc_alive(router, pid), timeout_s=8):
        router.cmd("kill -KILL %s >/dev/null 2>&1 || true" % pid)
        _wait_until(lambda: not _proc_alive(router, pid))
    assert _wait_until(
        lambda: os.path.exists(pcap_path) and os.path.getsize(pcap_path) >= 24
    ), "pcap %s missing after stopping capture: %s" % (
        pcap_path,
        router.cmd("cat %s 2>/dev/null || true" % shlex.quote(err_path)).strip(),
    )


def ospf_payload(frame):
    """Return the OSPF payload of an Ethernet+IPv4 frame, or None."""
    if len(frame) < 14 + 20 or frame[12:14] != b"\x08\x00":
        return None
    ihl = (frame[14] & 0xF) * 4
    if len(frame) < 14 + ihl or frame[23] != 89:
        return None
    return frame[14 + ihl :]


def packet_fields(frame):
    payload = ospf_payload(frame)
    if payload is None or len(payload) < 24 or payload[0] != 2:
        return None
    declared_length = struct.unpack("!H", payload[2:4])[0]
    auth_type = struct.unpack("!H", payload[14:16])[0]
    fields = {
        "ospf_type": payload[1],
        "router_id": socket.inet_ntoa(payload[4:8]),
        "declared_length": declared_length,
        "wire_ospf_length": len(payload),
        "auth_type": auth_type,
        "crypt_seq": struct.unpack("!I", payload[20:24])[0] if auth_type == 2 else None,
        "sha256": hashlib.sha256(frame).hexdigest(),
    }
    if auth_type == 2 and len(payload) >= 20:
        auth_data_len = payload[19]
        fields["key_id"] = payload[18]
        if len(payload) == declared_length + auth_data_len:
            expected = hashlib.md5(
                payload[:declared_length] + AUTH_KEY.ljust(16, b"\x00")
            ).digest()
            fields["digest_valid"] = payload[declared_length:] == expected
        else:
            fields["digest_valid"] = False
    if payload[1] == 1 and declared_length >= 44:
        fields["hello_neighbors"] = [
            socket.inet_ntoa(payload[offset : offset + 4])
            for offset in range(44, declared_length - 3, 4)
        ]
    elif payload[1] == 2 and declared_length >= 32:
        fields["dd_flags"] = payload[27]
        fields["dd_seq"] = struct.unpack("!I", payload[28:32])[0]
    return fields


def read_capture(pcap_path, label):
    records = []
    for packet in rdpcap(pcap_path):
        frame = bytes(packet)
        fields = packet_fields(frame)
        if fields is None:
            continue
        fields["label"] = label
        records.append({"frame": frame, "fields": fields})
    return records


def select_replay_plan(records):
    """Pick a Hello plus the complete master DD chain that follows it.

    Mirrors the manual reproducer: the chain must start with an I/M/MS DD,
    run with consecutive DD sequence numbers and end with the More bit
    clear, and every selected packet must carry a valid digest with a
    strictly increasing crypt_seqnum.  The Hello itself may have an empty
    neighbor list: on re-formation the adjacency is driven to Full by the
    DD chain alone (a DD received in Init executes TwoWayReceived,
    ospf_packet.c), which is exactly the flow the replay reproduces.
    """
    peer_records = [r for r in records if r["fields"].get("router_id") == R2_RID]
    for hello_index, hello in enumerate(peer_records):
        fields = hello["fields"]
        if fields["ospf_type"] != 1:
            continue
        initial_index = None
        for index in range(hello_index + 1, len(peer_records)):
            candidate = peer_records[index]["fields"]
            if candidate["ospf_type"] == 2 and candidate.get("dd_flags") == 7:
                initial_index = index
                break
        if initial_index is None:
            continue
        chain = [peer_records[initial_index]]
        for record in peer_records[initial_index + 1 :]:
            fields = record["fields"]
            if fields["ospf_type"] != 2:
                continue
            if fields.get("dd_flags", 0) & 4 or not fields.get("dd_flags", 0) & 1:
                continue
            if fields["dd_seq"] == chain[-1]["fields"]["dd_seq"]:
                continue
            if fields["dd_seq"] != chain[-1]["fields"]["dd_seq"] + 1:
                break
            chain.append(record)
            if not fields["dd_flags"] & 2:
                break
        if len(chain) < 2 or chain[-1]["fields"]["dd_flags"] & 2:
            continue
        sequence = [hello] + chain
        if any(
            sequence[i]["fields"]["crypt_seq"] >= sequence[i + 1]["fields"]["crypt_seq"]
            for i in range(len(sequence) - 1)
        ):
            continue
        if not all(record["fields"].get("digest_valid") for record in sequence):
            continue
        return hello, chain
    return None, None


def make_invalid_digest_hello(template_frame, crypt_seq):
    """One-way Hello with a fresh sequence number and a corrupted digest."""
    payload = bytearray(ospf_payload(template_frame)[:44])
    struct.pack_into("!H", payload, 2, 44)
    payload[12:14] = b"\x00\x00"
    struct.pack_into("!H", payload, 14, 2)
    payload[16:18] = b"\x00\x00"
    payload[18] = KEY_ID
    payload[19] = 16
    struct.pack_into("!I", payload, 20, crypt_seq)
    digest = bytearray(
        hashlib.md5(bytes(payload) + AUTH_KEY.ljust(16, b"\x00")).digest()
    )
    digest[0] ^= 1
    frame = (
        Ether(
            src=":".join("%02x" % b for b in template_frame[6:12]),
            dst=ALLSPFROUTERS_MAC,
        )
        / IP(src=R2_IP, dst=ALLSPFROUTERS, ttl=1, proto=89)
        / Raw(bytes(payload) + bytes(digest))
    )
    return bytes(frame)


def inject(r2, r1, frame, label):
    """Send one recorded frame from r2's namespace and watch r1."""
    fields = packet_fields(frame)
    before_traffic = traffic(r1)
    before_log = log_offset(r1)
    started = time.monotonic()
    r2.cmd_raises("python3 %s/send_frame.py eth1 %s" % (CWD, frame.hex()))
    time.sleep(INJECT_SETTLE)
    after_traffic = traffic(r1)
    log_text = log_since(r1, before_log)
    result = {
        "label": label,
        "crypt_seq": fields["crypt_seq"],
        "ospf_type": fields["ospf_type"],
        "sha256": fields["sha256"],
        "elapsed_seconds": round(time.monotonic() - started, 3),
        "traffic_delta": counter_delta(
            before_traffic,
            after_traffic,
            ("helloIn", "dbDescIn", "lsReqIn", "lsUpdIn", "lsAckIn"),
        ),
        "neighbor_state": neighbor_state(r1, R2_IP),
        "bad_sequence": bad_sequence_records(log_text),
        "log_excerpt": interesting_log(log_text),
    }
    logger.info("injection %s: %s", label, json.dumps(result))
    return result


def wait_for_state(router, peer_ip, expected, timeout):
    deadline = time.monotonic() + timeout
    states = []
    while time.monotonic() < deadline:
        state = neighbor_state(router, peer_ip)
        if not states or states[-1] != state:
            states.append(state)
        if state == expected:
            return True, states
        time.sleep(0.1)
    return False, states


def ospf_route_present(router, prefix):
    route = vty_json(router, "show ip route {}/32 json".format(prefix))
    return prefix + "/32" in route and "ospf" in json.dumps(route).lower()


def wait_for_ospf_route(router, prefix, timeout):
    """The router-LSA carrying the peer's loopback stub is re-originated
    around Full; the route lands a moment after the adjacency completes."""
    return _wait_until(
        lambda: ospf_route_present(router, prefix), timeout_s=timeout, interval_s=0.5
    )


def ospfd_pid(router):
    return router.cmd("cat /var/run/frr/ospfd.pid 2>/dev/null || true").strip()


def ospfd_running(router, pid):
    """The daemons share the host PID namespace, so liveness must be
    checked against the pid recorded in this router's pidfile, not pidof."""
    if not pid or not pid.isdigit():
        return False
    stat = router.cmd("cat /proc/%s/stat 2>/dev/null || true" % pid).strip()
    if not stat:
        return False
    return stat.split()[2] != "Z"


def wait_ospfd_stopped(router, pid, timeout=10):
    return _wait_until(lambda: not ospfd_running(router, pid), timeout_s=timeout)


def wait_ospfd_started(router, timeout=15):
    return _wait_until(
        lambda: ospfd_running(router, ospfd_pid(router)), timeout_s=timeout
    )


def write_evidence(tgen):
    path = os.path.join(tgen.logdir, "replay-evidence.json")
    with open(path, "w") as fp:
        json.dump(EVIDENCE, fp, indent=2, sort_keys=True)
        fp.write("\n")


def test_baseline_authenticated_full():
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)
    r1 = tgen.gears["r1"]
    r2 = tgen.gears["r2"]

    r1.expect_ospfv2_neighbor(R2_RID)
    r2.expect_ospfv2_neighbor(R1_RID)

    running = r1.vtysh_cmd("show running-config")
    assert (
        "no compatible rfc7474" not in running
    ), "strict RFC 7474 sequence validation is disabled"
    assert "message-digest-key 14" in running, "MD5 key missing on r1"

    database = r1.vtysh_cmd("show ip ospf database json")
    assert R1_RID in database and R2_RID in database, "LSDB missing a router-LSA"

    assert wait_for_ospf_route(
        r1, R2_LOOPBACK, 30
    ), "no OSPF route to {} within 30s of Full".format(R2_LOOPBACK)

    ping = r1.cmd_raises("ping -c 2 -W 2 {}".format(R2_LOOPBACK))
    assert (
        "2 received" in ping or "0% packet loss" in ping
    ), "ping to {} failed: {}".format(R2_LOOPBACK, ping)

    EVIDENCE["baseline"] = {
        "checks": "Full/LSDB/route/ping/strict-mode",
        "neighbors": compact_neighbors(r1),
    }
    write_evidence(tgen)


def test_capture_authenticated_exchange():
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)
    r1 = tgen.gears["r1"]
    r2 = tgen.gears["r2"]

    r1.expect_ospfv2_neighbor(R2_RID)

    capture = os.path.join(tgen.logdir, "b14_initial.pcap")
    cap_pid = start_capture(r1, capture, "ip proto 89 and src host %s" % R2_IP)
    r2.vtysh_cmd("clear ip ospf process")
    r1.expect_ospfv2_neighbor(R2_RID)
    r2.expect_ospfv2_neighbor(R1_RID)
    stop_capture(r1, cap_pid, capture)

    records = read_capture(capture, "captured_initial")
    peer_count = sum(1 for r in records if r["fields"]["router_id"] == R2_RID)
    hello, chain = select_replay_plan(records)
    assert hello is not None, (
        "no Hello + complete master DD chain in capture "
        "({} peer packets): {}".format(peer_count, [r["fields"] for r in records])
    )
    assert 2 <= len(chain) <= 16, "unexpected DD chain length: {}".format(len(chain))

    PLAN["hello_frame"] = hello["frame"]
    PLAN["dd_frames"] = [record["frame"] for record in chain]
    PLAN["hello_fields"] = hello["fields"]
    PLAN["dd_fields"] = [record["fields"] for record in chain]
    PLAN["hello_two_way"] = R1_RID in hello["fields"].get("hello_neighbors", [])
    PLAN["high_water"] = max(
        [
            record["fields"]["crypt_seq"] or 0
            for record in records
            if record["fields"]["router_id"] == R2_RID
        ]
    )

    plan_public = {
        "hello": hello["fields"],
        "hello_two_way": PLAN["hello_two_way"],
        "dd_chain": [record["fields"] for record in chain],
        "captured_peer_packets": peer_count,
        "captured_max_crypt_seq": PLAN["high_water"],
    }
    with open(os.path.join(tgen.logdir, "replay-plan.json"), "w") as fp:
        json.dump(plan_public, fp, indent=2, sort_keys=True)
        fp.write("\n")
    logger.info(
        "replay plan: hello seq=%s dd_seqs=%s",
        hello["fields"]["crypt_seq"],
        [f["dd_seq"] for f in PLAN["dd_fields"]],
    )


def test_unreset_old_hello_rejected():
    """Control: replaying the captured Hello while the adjacency is up must
    be rejected by the sequence check, without touching the adjacency."""
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)
    r1 = tgen.gears["r1"]
    r2 = tgen.gears["r2"]

    r1.expect_ospfv2_neighbor(R2_RID)

    result = inject(r2, r1, PLAN["hello_frame"], "unreset_old_hello")
    rejected = [
        item
        for item in result["bad_sequence"]
        if item["packet_seq"] == PLAN["hello_fields"]["crypt_seq"]
        and item["operator"] == ">"
        and item["stored_seq"] > PLAN["hello_fields"]["crypt_seq"]
    ]
    # The peer is alive here, so a legitimate periodic Hello may land in
    # the same window; the bad-sequence record for the injected sequence
    # number is the evidence that the replayed packet was dropped.
    assert rejected, "stale Hello was not rejected by the sequence check: {}".format(
        result
    )
    assert (
        result["neighbor_state"] == "Full"
    ), "adjacency disturbed by stale Hello: {}".format(result)

    PLAN["high_water"] = max(
        [PLAN["high_water"]] + [item["stored_seq"] for item in rejected]
    )
    EVIDENCE["unreset_old_hello"] = result
    write_evidence(tgen)


def test_invalid_digest_fresh_hello_rejected():
    """Control: a fresh-sequence Hello with a corrupted digest must be
    rejected by the MD5 check."""
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)
    r1 = tgen.gears["r1"]
    r2 = tgen.gears["r2"]

    r1.expect_ospfv2_neighbor(R2_RID)

    fresh_base = max([PLAN["high_water"], int(time.time())]) + 120
    assert fresh_base + 2 < 0xFFFFFFFF, "fresh sequence bound would wrap around"
    frame = make_invalid_digest_hello(PLAN["hello_frame"], fresh_base)

    result = inject(r2, r1, frame, "invalid_digest_fresh_hello")
    # As above, the checksum-mismatch record is the evidence; a live
    # periodic Hello may share the window.
    assert (
        result["neighbor_state"] == "Full"
    ), "adjacency disturbed by corrupt-digest Hello: {}".format(result)
    assert any(
        "checksum mismatch" in line for line in result["log_excerpt"]
    ), "corrupt-digest Hello was not rejected by the MD5 check: {}".format(result)
    EVIDENCE["invalid_digest_fresh_hello"] = result
    write_evidence(tgen)


def test_replay_after_neighbor_down():
    """Regression: after the neighbor is torn down, replaying the captured
    Hello/DD chain must not resurrect the adjacency."""
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)
    r1 = tgen.gears["r1"]
    r2 = tgen.gears["r2"]

    r1.expect_ospfv2_neighbor(R2_RID)

    # Take the peer out of service; the target must hold the adjacency
    # until the neighbor is explicitly cleared below.
    old_pid = ospfd_pid(r2)
    r2.killDaemons(["ospfd"])
    assert wait_ospfd_stopped(r2, old_pid), "r2 ospfd did not stop"
    try:
        time.sleep(1.0)
        no_attack_state = neighbor_state(r1, R2_IP)
        assert no_attack_state == "Full", (
            "untriggered adjacency did not stay Full: %s" % no_attack_state
        )

        replay_pcap = os.path.join(tgen.logdir, "b14_replay.pcap")
        cap_pid = start_capture(r1, replay_pcap, "ip proto 89 and src host %s" % R2_IP)

        clear_offset = log_offset(r1)
        r1.vtysh_cmd("clear ip ospf neighbor %s" % R2_RID)
        time.sleep(INJECT_SETTLE)
        clear_log = log_since(r1, clear_offset)
        deleted_logged = any(
            "Full -> Deleted (KillNbr)" in line for line in clear_log.splitlines()
        )
        absent_after_clear = neighbor_state(r1, R2_IP) == "Absent"
        EVIDENCE["down_transition"] = {
            "command": "clear ip ospf neighbor %s" % R2_RID,
            "full_to_deleted_logged": deleted_logged,
            "neighbor_absent_after_clear": absent_after_clear,
            "log_excerpt": interesting_log(clear_log),
        }
        assert deleted_logged, "neighbor teardown was not logged: {}".format(
            EVIDENCE["down_transition"]
        )
        assert absent_after_clear, "neighbor still present after clear: {}".format(
            EVIDENCE["down_transition"]
        )

        phases = []
        phases.append(inject(r2, r1, PLAN["hello_frame"], "post_down_old_hello_first"))
        phases.append(
            inject(r2, r1, PLAN["hello_frame"], "post_down_old_hello_duplicate")
        )
        for index, frame in enumerate(PLAN["dd_frames"]):
            phases.append(inject(r2, r1, frame, "post_down_old_dd_%d" % index))

        full_observed, states = wait_for_state(r1, R2_IP, "Full", FINAL_FULL_WAIT)
        route = vty_json(r1, "show ip route {}/32 json".format(R2_LOOPBACK))

        stop_capture(r1, cap_pid, replay_pcap)

        expected_wire = {}
        for item in phases:
            expected_wire[item["sha256"]] = expected_wire.get(item["sha256"], 0) + 1
        actual_wire = {}
        for record in read_capture(replay_pcap, "captured_replay"):
            sha = record["fields"]["sha256"]
            actual_wire[sha] = actual_wire.get(sha, 0) + 1
        wire_ok = actual_wire == expected_wire

        EVIDENCE["replay_after_down"] = {
            "no_attack_state": no_attack_state,
            "phases": phases,
            "phantom_full_observed": full_observed,
            "states_polled": states,
            "target_neighbors": compact_neighbors(r1),
            "target_route_to_peer_loopback": route,
            "wire_has_only_planned_peer_packets": wire_ok,
            "expected_injected_sha256_counts": expected_wire,
            "actual_peer_sha256_counts": actual_wire,
        }
        write_evidence(tgen)

        old_seq = PLAN["hello_fields"]["crypt_seq"]
        high_water = PLAN["high_water"]
        first = phases[0]
        first_reject = [
            item
            for item in first["bad_sequence"]
            if item["packet_seq"] == old_seq
            and item["operator"] == ">"
            and item["stored_seq"] >= high_water
        ]
        detail = json.dumps(EVIDENCE["replay_after_down"], indent=2, sort_keys=True)
        assert (
            wire_ok
        ), "wire check failed, injections did not reach the link as planned: {}".format(
            detail
        )
        assert first["traffic_delta"]["helloIn"] == 0, (
            "replayed Hello was accepted after the neighbor went down "
            "(phantom adjacency possible): {}".format(detail)
        )
        assert first_reject, (
            "replayed Hello was not rejected at the preserved high-water mark "
            "(old seq {}, high water {}): {}".format(old_seq, high_water, detail)
        )
        assert (
            first["neighbor_state"] == "Absent"
        ), "replayed Hello recreated the neighbor: {}".format(detail)
        for item in phases[1:]:
            assert (
                item["traffic_delta"]["helloIn"] == 0
                and item["traffic_delta"]["dbDescIn"] == 0
            ), "replayed packet %s was accepted after the neighbor went down: %s" % (
                item["label"],
                detail,
            )
            assert (
                item["neighbor_state"] == "Absent"
            ), "replayed packet %s recreated the neighbor: %s" % (item["label"], detail)
        assert not full_observed, (
            "phantom Full adjacency restored by replayed packets "
            "(states polled: {}): {}".format(states, detail)
        )
    finally:
        # Bring the peer back even when the assertions above fail, so the
        # topology stays healthy for the remaining tests.
        r2.startDaemons(["ospfd"])
        if not wait_ospfd_started(r2, timeout=30):
            logger.warning("r2 ospfd did not restart during cleanup")


def test_legitimate_restart_recovers():
    """A legitimately restarted peer must still be able to form the
    adjacency: its first packets carry the current time as sequence
    number, which is above the preserved window.  The restart itself is
    triggered at the end of test_replay_after_neighbor_down."""
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)
    r1 = tgen.gears["r1"]
    r2 = tgen.gears["r2"]

    assert ospfd_running(r2, ospfd_pid(r2)), "r2 ospfd is not running after the restart"

    deadline = time.monotonic() + BASELINE_TIMEOUT
    while time.monotonic() < deadline:
        if neighbor_state(r1, R2_IP) == "Full" and neighbor_state(r2, R1_IP) == "Full":
            break
        time.sleep(1)
    assert (
        neighbor_state(r1, R2_IP) == "Full"
    ), "adjacency did not re-form after legitimate restart: %s" % compact_neighbors(r1)
    assert (
        neighbor_state(r2, R1_IP) == "Full"
    ), "adjacency did not re-form on r2: %s" % compact_neighbors(r2)

    assert wait_for_ospf_route(
        r1, R2_LOOPBACK, 30
    ), "no OSPF route to {} after restart".format(R2_LOOPBACK)
    route = vty_json(r1, "show ip route {}/32 json".format(R2_LOOPBACK))
    ping = r1.cmd_raises("ping -c 2 -W 2 {}".format(R2_LOOPBACK))
    assert (
        "2 received" in ping or "0% packet loss" in ping
    ), "ping to {} failed after restart: {}".format(R2_LOOPBACK, ping)

    EVIDENCE["legitimate_restart"] = {
        "full_re-established": True,
        "target_neighbors": compact_neighbors(r1),
        "target_route_to_peer_loopback": route,
    }
    write_evidence(tgen)


def test_old_replay_still_rejected_after_recovery():
    """Once the adjacency is back, the pre-restart capture must still be
    rejected by the sequence window."""
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)
    r1 = tgen.gears["r1"]
    r2 = tgen.gears["r2"]

    r1.expect_ospfv2_neighbor(R2_RID)

    hello_result = inject(r2, r1, PLAN["hello_frame"], "post_recovery_old_hello")
    dd_result = inject(r2, r1, PLAN["dd_frames"][0], "post_recovery_old_dd")

    old_seq = PLAN["hello_fields"]["crypt_seq"]
    hello_reject = [
        item
        for item in hello_result["bad_sequence"]
        if item["packet_seq"] == old_seq and item["operator"] == ">"
    ]
    assert (
        hello_result["traffic_delta"]["helloIn"] == 0
    ), "pre-restart Hello accepted after recovery: {}".format(hello_result)
    assert (
        hello_reject
    ), "pre-restart Hello was not sequence-rejected after recovery: {}".format(
        hello_result
    )
    assert hello_result["neighbor_state"] == "Full", "adjacency disturbed: {}".format(
        hello_result
    )
    assert (
        dd_result["traffic_delta"]["dbDescIn"] == 0
    ), "pre-restart DD accepted after recovery: {}".format(dd_result)
    assert dd_result["neighbor_state"] == "Full", "adjacency disturbed: {}".format(
        dd_result
    )

    EVIDENCE["post_recovery_replay"] = {"hello": hello_result, "dd": dd_result}
    write_evidence(tgen)


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
