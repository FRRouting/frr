#!/usr/bin/env python
# SPDX-License-Identifier: ISC
#
# test_isis_equal_lsp_churn.py
#
# Copyright (c) 2026
#

"""
test_isis_equal_lsp_churn.py
============================

Regression for isisd doing repeated database-replacement, SPF-schedule
and TED-parse work when a byte-identical non-self LSP is replayed.

ISO/IEC 10589 (RFC 1142) 7.3.15.1 e) 2) requires only SRM/SSN flag
maintenance when the received LSP is equal to the database copy.  The
unfixed isisd also calls lsp_update() from the LSP_EQUAL branch, which
replaces the database contents and unconditionally schedules SPF and
posts LSP_UPD (a full TED re-parse when mpls-te is enabled).  The SPF
timer merges executions but does not remove the repeated database
replacement and TED work.

Topology
--------

    r2 (injector) ----eth1---- r1 (DUT) ----eth2---- r3 (observer)

All links are point-to-point, level-2-only, area 49.0001.  r2's LSP is
captured on the wire (template tracker accepts only genuine floods from
r2's MAC) and replayed byte-identical.  Injected frames use a locally
administered source MAC; r1 does not check the source MAC on
point-to-point LSP receipt, so the replay exercises the normal receive
path while the template tracker never mistakes an injected frame for a
genuine flood.

Test plan
---------

1. test_adjacency_and_template
     Baseline: adjacencies reach Up, r1 holds r2's LSP, and the
     template tracker captured r2's current LSP from the wire.

2. test_equal_lsp_replay_no_spf_work
     Replay 8 identical LSPs at r1.  r1 must acknowledge (PSNP, the
     SSN maintenance the standard requires) but must not schedule SPF,
     must not replace the database copy (remaining lifetime keeps
     decaying), and must not reflood.  Unfixed isisd schedules SPF once
     per replay and resets the stored lifetime.

3. test_equal_lsp_replay_no_ted_parse
     Enable mpls-te on all routers and replay 8 identical LSPs again.
     r1 must not re-parse the LSP into the TED.  Unfixed isisd parses
     once per replay.

4. test_invalid_lsp_dropped
     One replay with corrupted checksum is dropped before lsp_compare:
     no SPF schedule, no TED parse, no database change.

5. test_newer_lsp_still_processed
     One genuinely newer valid LSP (seqno+1, recomputed checksum) must
     still be processed as new information: flooded to the observer,
     SPF scheduled, TED re-parsed.  The originator fights back with a
     higher seqno; r1 must converge on it.

6. test_post_stop_stability
     After the injections stop, r1 must stay quiet (no SPF schedules),
     keep the adjacency up and hold the final LSP state.
"""

import json
import os
import shlex
import sys
import time
from functools import partial

import pytest
from scapy.utils import rdpcap

from lib.topogen import Topogen, get_topogen
from lib.topolog import logger


CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

pytestmark = [pytest.mark.isisd]

R1 = "r1"
R2 = "r2"
R3 = "r3"
PEER_LSP_ID_HEX = "0000000000020000"
PEER_LSP_ID_STR = "0000.0000.0002.00-00"
INJECTOR_MAC = "02:00:00:00:00:02"
BURST_COUNT = 8
BURST_SPACING = 0.2
REPLAY_SETTLE_S = 2.5

# Populated by test_adjacency_and_template, torn down in teardown_module.
_template_sniffer_pid = None


def build_topo(tgen):
    r1 = tgen.add_router(R1)
    r2 = tgen.add_router(R2)
    r3 = tgen.add_router(R3)
    tgen.add_link(r1, r2, ifname1="eth1", ifname2="eth1")
    tgen.add_link(r1, r3, ifname1="eth2", ifname2="eth1")


def setup_module(mod):
    tgen = Topogen(build_topo, mod.__name__)
    tgen.start_topology()

    for router in tgen.routers().values():
        router.load_frr_config()

    tgen.start_router()


def teardown_module():
    tgen = get_topogen()
    if _template_sniffer_pid is not None:
        tgen.gears[R2].cmd(
            "kill -TERM %s >/dev/null 2>&1 || true" % _template_sniffer_pid
        )
    tgen.stop_topology()


# ---------------------------------------------------------------------------
# r1 isisd log helpers
# ---------------------------------------------------------------------------


def _isisd_log_path(tgen, router):
    return os.path.join(tgen.logdir, router, "isisd.log")


def _log_offset(path):
    try:
        with open(path) as fp:
            return sum(1 for _ in fp)
    except FileNotFoundError:
        return 0


def _log_lines_since(path, offset):
    with open(path) as fp:
        lines = fp.readlines()
    return lines[offset:]


def _log_counts(lines):
    # "is equal to ours" is printed by lsp_compare() for both LSP receipts
    # and SNP (CSNP/PSNP) entry checks; only the receipt-driven ones are
    # evidence for the replay path, so attribute compares by the line that
    # triggered them.
    needles = {
        "spf_schedule_call": "SPF schedule called",
        "spf_timer_arm": "SPF scheduled",
        "spf_run": "SPF needed, periodic SPF",
        "te_parse": "Parse LSP",
        "invalid_cksum": "invalid LSP checksum",
    }
    counts = {name: sum(needle in line for line in lines) for name, needle in needles.items()}
    counts.update(
        {
            "lsp_received": 0,
            "equal_lsp_receipt": 0,
            "newer_lsp_receipt": 0,
            "snp_equal_compare": 0,
        }
    )
    for index, line in enumerate(lines):
        if "Rcvd L2 LSP %s" % PEER_LSP_ID_STR in line:
            counts["lsp_received"] += 1
        if "Compare LSP %s" % PEER_LSP_ID_STR not in line:
            continue
        verdict = lines[index + 1] if index + 1 < len(lines) else ""
        from_lsp = index > 0 and "Rcvd L2 LSP %s" % PEER_LSP_ID_STR in lines[index - 1]
        from_snp = index > 0 and (
            "CSNP entry %s" % PEER_LSP_ID_STR in lines[index - 1]
            or "PSNP entry %s" % PEER_LSP_ID_STR in lines[index - 1]
        )
        if from_lsp and "is equal to ours" in verdict:
            counts["equal_lsp_receipt"] += 1
        elif from_lsp and "is newer than ours" in verdict:
            counts["newer_lsp_receipt"] += 1
        elif from_snp and "is equal to ours" in verdict:
            counts["snp_equal_compare"] += 1
    return counts


# ---------------------------------------------------------------------------
# r1 database helpers
# ---------------------------------------------------------------------------


def _find_peer_lsp(value):
    if isinstance(value, dict):
        lsp = value.get("lsp")
        if isinstance(lsp, dict) and PEER_LSP_ID_STR in str(lsp.get("id", "")):
            return value
        for child in value.values():
            found = _find_peer_lsp(child)
            if found is not None:
                return found
    elif isinstance(value, list):
        for child in value:
            found = _find_peer_lsp(child)
            if found is not None:
                return found
    return None


def _peer_lsp_state(router):
    data = json.loads(router.vtysh_cmd("show isis database json"))
    lsp = _find_peer_lsp(data)
    if lsp is None:
        raise RuntimeError("peer LSP absent on %s: %s" % (router.name, data))
    return {
        "seqno": int(lsp["seqNumber"], 16),
        "chksum": lsp["chksum"],
        "holdtime": lsp["holdtime"],
    }


def _template_path(tgen):
    return os.path.join(tgen.logdir, "r2_lsp_template.hex")


def _neighbor_up(router, ifname):
    try:
        output = router.vtysh_cmd("show isis neighbor json", isjson=True)
    except Exception:
        return False
    # P2P adjacencies are printed directly into their circuit object;
    # the brief output carries the circuit name but no address, so match
    # by interface.
    for area in output.get("areas", []):
        for circuit in area.get("circuits", []):
            if circuit.get("state") == "Up" and circuit.get("interface") == ifname:
                return True
    return False


def _wait_neighbor_up(router, ifname, timeout_s=90):
    assert _wait_until(
        partial(_neighbor_up, router, ifname), timeout_s=timeout_s
    ), "IS-IS neighbor on %s not Up on %s" % (ifname, router.name)


def _template_seq(path):
    try:
        with open(path) as fp:
            pdu = bytes.fromhex(fp.read().strip())
    except (FileNotFoundError, ValueError):
        return None
    if len(pdu) < 26:
        return None
    return int.from_bytes(pdu[20:24], "big")


def _wait_for_new_template(tgen, previous_seq):
    template = _template_path(tgen)
    log_path = _isisd_log_path(tgen, R1)
    offset = _log_offset(log_path)
    stable_since = None
    last_seq = None

    def ready():
        nonlocal offset, stable_since, last_seq
        lines = _log_lines_since(log_path, offset)
        offset += len(lines)
        counts = _log_counts(lines)
        seq = _template_seq(template)
        if seq is None or seq <= previous_seq:
            stable_since = None
            return False
        try:
            states = [_peer_lsp_state(tgen.gears[name]) for name in (R1, R2, R3)]
        except (RuntimeError, ValueError, json.JSONDecodeError):
            stable_since = None
            return False
        if any(state["seqno"] != seq for state in states):
            stable_since = None
            return False
        if (
            seq != last_seq
            or counts["spf_schedule_call"]
            or counts["te_parse"]
            or stable_since is None
        ):
            stable_since = time.monotonic()
        last_seq = seq
        return time.monotonic() - stable_since >= REPLAY_SETTLE_S

    # Equality with the old database can hold while configuration-triggered
    # regeneration is still pending. Require the new flood at every router,
    # then observe a quiet interval before recording replay work.
    assert _wait_until(ready, timeout_s=60), (
        "r2 LSP did not advance past 0x%08x and settle at all routers" % previous_seq
    )
    logger.info(
        "new template settled: r2 LSP 0x%08x -> 0x%08x",
        previous_seq,
        last_seq,
    )


# ---------------------------------------------------------------------------
# Capture / replay process helpers (run inside the node netns)
# ---------------------------------------------------------------------------


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


def _start_capture(router, pcap_path, extra_args, bpf="isis"):
    """Sniff with scapy in the router netns. tcpdump is not used: it is often
    missing in CI images and it exits when the peer interface goes down.
    """
    err_path = pcap_path + ".err"
    ready_path = pcap_path + ".ready"
    router.cmd(
        "rm -f %s %s %s"
        % (shlex.quote(pcap_path), shlex.quote(err_path), shlex.quote(ready_path))
    )
    # nohup: router.cmd() closing the session would otherwise SIGHUP the sniffer.
    pid = router.cmd(
        "nohup python3 %s/capture_isis.py --iface %s --pcap %s "
        "--filter %s %s --ready-file %s </dev/null >%s 2>&1 & echo $!"
        % (
            shlex.quote(CWD),
            shlex.quote("eth1"),
            shlex.quote(pcap_path),
            shlex.quote(bpf),
            extra_args,
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
        if os.path.exists(err_path):
            with open(err_path) as fp:
                err = err or fp.read()
        assert False, "scapy capture did not become ready on %s (pid %s): %s" % (
            router.name,
            pid,
            err.strip() or "no capture stderr",
        )
    return pid


def _stop_capture(router, pid, pcap_path):
    err_path = pcap_path + ".err"
    router.cmd("kill -TERM %s >/dev/null 2>&1 || true" % pid)
    if not _wait_until(lambda: not _proc_alive(router, pid), timeout_s=8):
        router.cmd("kill -KILL %s >/dev/null 2>&1 || true" % pid)
        _wait_until(lambda: not _proc_alive(router, pid))
    if not _wait_until(
        lambda: os.path.exists(pcap_path) and os.path.getsize(pcap_path) >= 24
    ):
        err = router.cmd("cat %s 2>/dev/null || true" % shlex.quote(err_path))
        if os.path.exists(err_path):
            with open(err_path) as fp:
                err = err or fp.read()
        assert False, "pcap %s missing after stopping capture: %s" % (
            pcap_path,
            err.strip() or "empty/missing file",
        )


def _parse_isis(raw):
    if len(raw) < 20:
        return None
    if raw[14] != 0xFE or raw[15] != 0xFE or raw[16] != 0x03:
        return None
    pdu = raw[17:]
    if len(pdu) < 8 or pdu[0] != 0x83:
        return None
    info = {"pdutype": pdu[4], "src_mac": ":".join("%02x" % b for b in raw[6:12])}
    if pdu[4] in (18, 20) and len(pdu) >= 27:
        info["lifetime"] = int.from_bytes(pdu[10:12], "big")
        info["lspid"] = pdu[12:20].hex()
        info["seqno"] = int.from_bytes(pdu[20:24], "big")
    return info


def _pcap_events(pcap_path):
    events = []
    for pkt in rdpcap(pcap_path):
        try:
            info = _parse_isis(bytes(pkt))
        except Exception:
            continue
        if info is not None:
            events.append(info)
    return events


def _lsp_events(events, lspid_hex):
    return [
        event
        for event in events
        if event.get("pdutype") in (18, 20) and event.get("lspid") == lspid_hex
    ]


def _replay(tgen, mode, count=1):
    tgen.gears[R2].cmd_raises(
        "python3 %s/replay_lsp.py --iface eth1 --template %s "
        "--mode %s --count %d --spacing %s"
        % (
            shlex.quote(CWD),
            shlex.quote(_template_path(tgen)),
            mode,
            count,
            BURST_SPACING,
        )
    )


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


def test_adjacency_and_template():
    """Adjacencies reach Up, r1 holds r2's LSP, template captured from the wire."""
    global _template_sniffer_pid
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears[R1]
    r2 = tgen.gears[R2]

    # Track r2's genuine LSP floods for the whole module.  The tracker
    # only accepts frames from r2's real MAC, so the injector's frames
    # can never poison the template.
    accept_mac = r2.cmd("cat /sys/class/net/eth1/address").strip()
    template = _template_path(tgen)
    ready = template + ".ready"
    r2.cmd("rm -f %s %s" % (shlex.quote(template), shlex.quote(ready)))
    pid = r2.cmd(
        "nohup python3 %s/capture_isis.py --iface eth1 "
        "--template-out %s --accept-mac %s --lsp-id %s "
        "--ready-file %s </dev/null >%s 2>&1 & echo $!"
        % (
            shlex.quote(CWD),
            shlex.quote(template),
            shlex.quote(accept_mac),
            shlex.quote(PEER_LSP_ID_HEX),
            shlex.quote(ready),
            shlex.quote(template + ".err"),
        )
    ).strip()
    pid = pid.splitlines()[-1]
    assert pid.isdigit(), "template tracker did not start on r2 (pid %r)" % pid
    _template_sniffer_pid = pid
    assert _wait_until(partial(_file_ready, ready)), "template tracker not ready"

    # The bring-up floods may predate the tracker, so force a fresh
    # flood of r2's LSP: a metric-style toggle schedules a regeneration
    # (lsp-gen-interval is 1s) and lsp_regenerate() always floods with a
    # new seqno.  The tracker only accepts r2's real MAC, so the
    # template then holds r2's current LSP byte-for-byte.
    previous_seq = _peer_lsp_state(r2)["seqno"]
    r2.vtysh_cmd(
        "configure terminal\nrouter isis CHURN\n"
        "metric-style narrow\nmetric-style wide"
    )

    _wait_neighbor_up(r1, "eth1")
    _wait_neighbor_up(r1, "eth2")

    _wait_for_new_template(tgen, previous_seq)


def test_equal_lsp_replay_no_spf_work():
    """Identical LSP replays must not schedule SPF or replace the database copy."""
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears[R1]
    r2 = tgen.gears[R2]
    r3 = tgen.gears[R3]

    log_path = _isisd_log_path(tgen, R1)
    holdtime_before = _peer_lsp_state(r1)["holdtime"]
    offset = _log_offset(log_path)

    inject_pcap = os.path.join(tgen.logdir, "equal_inject.pcap")
    observer_pcap = os.path.join(tgen.logdir, "equal_observer.pcap")
    inject_pid = _start_capture(r2, inject_pcap, "")
    observer_pid = _start_capture(r3, observer_pcap, "")

    _replay(tgen, "equal", BURST_COUNT)
    time.sleep(REPLAY_SETTLE_S)

    _stop_capture(r2, inject_pid, inject_pcap)
    _stop_capture(r3, observer_pid, observer_pcap)

    counts = _log_counts(_log_lines_since(log_path, offset))
    holdtime_after = _peer_lsp_state(r1)["holdtime"]

    logger.info("equal replay counts: %s", json.dumps(counts, sort_keys=True))
    assert counts["lsp_received"] == BURST_COUNT, (
        "r1 did not receive all %d replayed LSPs: %s" % (BURST_COUNT, counts)
    )
    assert counts["equal_lsp_receipt"] == BURST_COUNT, (
        "replayed LSPs did not all compare LSP_EQUAL: %s" % counts
    )
    assert counts["spf_schedule_call"] == 0, (
        "equal LSP replay scheduled SPF %d times (expected 0): %s"
        % (counts["spf_schedule_call"], counts)
    )
    assert counts["te_parse"] == 0, (
        "equal LSP replay re-parsed TED %d times without mpls-te: %s"
        % (counts["te_parse"], counts)
    )
    assert holdtime_after <= holdtime_before, (
        "database copy was replaced: remaining lifetime %d -> %d after replays"
        % (holdtime_before, holdtime_after)
    )

    inject_events = _pcap_events(inject_pcap)
    sent = [
        event
        for event in _lsp_events(inject_events, PEER_LSP_ID_HEX)
        if event["src_mac"] == INJECTOR_MAC
    ]
    psnps = [
        event
        for event in inject_events
        if event.get("pdutype") in (26, 27) and event["src_mac"] != INJECTOR_MAC
    ]
    refloods = [
        event
        for event in _lsp_events(inject_events, PEER_LSP_ID_HEX)
        if event["src_mac"] != INJECTOR_MAC
    ]
    observer_lsps = _lsp_events(_pcap_events(observer_pcap), PEER_LSP_ID_HEX)

    assert len(sent) == BURST_COUNT, (
        "inject link saw %d replayed LSPs, expected %d" % (len(sent), BURST_COUNT)
    )
    assert len(psnps) >= 1, "no PSNP acknowledgement from r1 (SSN maintenance lost)"
    assert not refloods, "r1 reflooded the equal LSP on the receiving circuit"
    assert not observer_lsps, "r1 reflooded the equal LSP towards the observer"


def test_equal_lsp_replay_no_ted_parse():
    """With mpls-te on, identical replays must not re-parse the LSP into the TED."""
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears[R1]
    r2 = tgen.gears[R2]
    r3 = tgen.gears[R3]

    # Enable TE on all routers so the replayed LSP carries TE sub-TLVs.
    # Each router re-originates its LSP; wait for the template to track
    # r2's new seqno before measuring.
    previous_seq = _peer_lsp_state(r2)["seqno"]
    for router in (r1, r2, r3):
        router.vtysh_cmd("configure terminal\nrouter isis CHURN\nmpls-te on")

    _wait_for_new_template(tgen, previous_seq)

    log_path = _isisd_log_path(tgen, R1)
    offset = _log_offset(log_path)

    observer_pcap = os.path.join(tgen.logdir, "equal_te_observer.pcap")
    observer_pid = _start_capture(r3, observer_pcap, "")

    _replay(tgen, "equal", BURST_COUNT)
    time.sleep(REPLAY_SETTLE_S)

    _stop_capture(r3, observer_pid, observer_pcap)

    counts = _log_counts(_log_lines_since(log_path, offset))
    logger.info("equal replay (mpls-te) counts: %s", json.dumps(counts, sort_keys=True))
    assert counts["lsp_received"] == BURST_COUNT, (
        "r1 did not receive all %d replayed LSPs: %s" % (BURST_COUNT, counts)
    )
    assert counts["equal_lsp_receipt"] == BURST_COUNT, (
        "replayed LSPs did not all compare LSP_EQUAL: %s" % counts
    )
    assert counts["te_parse"] == 0, (
        "equal LSP replay re-parsed TED %d times (expected 0): %s"
        % (counts["te_parse"], counts)
    )
    assert counts["spf_schedule_call"] == 0, (
        "equal LSP replay scheduled SPF %d times (expected 0): %s"
        % (counts["spf_schedule_call"], counts)
    )
    observer_lsps = _lsp_events(_pcap_events(observer_pcap), PEER_LSP_ID_HEX)
    assert not observer_lsps, "r1 reflooded the equal LSP towards the observer"


def test_invalid_lsp_dropped():
    """A corrupted replay is dropped before lsp_compare and triggers no work."""
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears[R1]

    log_path = _isisd_log_path(tgen, R1)
    offset = _log_offset(log_path)

    _replay(tgen, "invalid", 1)
    time.sleep(1.5)

    counts = _log_counts(_log_lines_since(log_path, offset))
    logger.info("invalid replay counts: %s", json.dumps(counts, sort_keys=True))
    assert counts["invalid_cksum"] >= 1, "corrupted LSP was not checksum-rejected"
    assert counts["lsp_received"] == 1
    assert counts["equal_lsp_receipt"] == 0
    assert counts["newer_lsp_receipt"] == 0
    assert counts["spf_schedule_call"] == 0
    assert counts["te_parse"] == 0


def test_newer_lsp_still_processed():
    """A genuinely newer valid LSP must still flood, schedule SPF and re-parse."""
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears[R1]
    r3 = tgen.gears[R3]

    # The TED assertion needs mpls-te on r1.  In the full module run the
    # mpls-te test already enabled it; enable it here (idempotently) so
    # this test also stands alone.
    if "mpls-te" not in r1.vtysh_cmd("show running-config"):
        r1.vtysh_cmd("configure terminal\nrouter isis CHURN\nmpls-te on")
        # r1 re-originates its LSP and the TED is filled on enable.
        time.sleep(REPLAY_SETTLE_S)

    template_seq = _template_seq(_template_path(tgen))
    assert template_seq is not None

    log_path = _isisd_log_path(tgen, R1)
    offset = _log_offset(log_path)

    observer_pcap = os.path.join(tgen.logdir, "newer_observer.pcap")
    observer_pid = _start_capture(r3, observer_pcap, "")

    _replay(tgen, "newer", 1)
    # The originator fights back via the PSNP report within one
    # psnp-interval (2s); give the exchange time to finish.
    time.sleep(4)

    _stop_capture(r3, observer_pid, observer_pcap)

    counts = _log_counts(_log_lines_since(log_path, offset))
    logger.info("newer LSP counts: %s", json.dumps(counts, sort_keys=True))
    assert counts["lsp_received"] >= 1
    assert counts["newer_lsp_receipt"] >= 1, (
        "newer LSP was not processed as new information: %s" % counts
    )
    assert counts["spf_schedule_call"] >= 1, (
        "newer LSP did not schedule SPF: %s" % counts
    )
    assert counts["te_parse"] >= 1, "newer LSP did not re-parse the TED: %s" % counts

    observer_lsps = _lsp_events(_pcap_events(observer_pcap), PEER_LSP_ID_HEX)
    assert any(event["seqno"] > template_seq for event in observer_lsps), (
        "newer LSP was not flooded to the observer: %s" % observer_lsps
    )
    assert _peer_lsp_state(r1)["seqno"] > template_seq, (
        "r1 database did not advance past template seq 0x%08x" % template_seq
    )


def test_post_stop_stability():
    """After the injections stop, r1 stays quiet, the adjacency and LSDB stay up."""
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears[R1]

    log_path = _isisd_log_path(tgen, R1)
    offset = _log_offset(log_path)
    time.sleep(5)

    counts = _log_counts(_log_lines_since(log_path, offset))
    logger.info("post-stop counts: %s", json.dumps(counts, sort_keys=True))
    assert counts["lsp_received"] == 0
    assert counts["spf_schedule_call"] == 0
    assert counts["te_parse"] == 0

    _wait_neighbor_up(r1, "eth1")
    _wait_neighbor_up(r1, "eth2")
    state = _peer_lsp_state(r1)
    assert state["holdtime"] > 0
