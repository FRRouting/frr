#!/usr/bin/env python
# SPDX-License-Identifier: ISC
#
# test_isis_snp_placeholder.py
# Part of NetDEF Topology Tests
#
# Copyright (c) 2026 Bing Shui <bingshui@smail.nju.edu.cn>
#
r"""
test_isis_snp_placeholder.py:

                 +---------+
                 |   r2    |  injector
                 |         |
                 +---------+
                      |eth-r1
                      |
                      |eth-r2
                 +---------+
                 |   r1    |  victim
                 |         |
                 +---------+
                      |eth-r3
                      |
                      |eth-r1
                 +---------+
                 |   r3    |  observer
                 |         |
                 +---------+

A CSNP/PSNP entry whose LSP ID is unknown and whose rem_lifetime,
checksum and seqno are all non-zero makes isisd record the LSP header
and set SSNflag on the receiving circuit (ISO 10589 7.3.15.2 b) 5),
process_snp).  lsp_new() creates the placeholder with an MTU-sized
stream (LLC_LEN + lsp_mtu), although the placeholder carries no LSP
data: it is never transmitted (SRM flags are cleared and seqno==0
entries are excluded from CSNP lists), never parsed for display, and
the stream is freed again when the real LSP arrives (lsp_update_data).
The (pseudonode, fragment) byte pair of the ID space is unbounded, so
without a quota an adjacent attacker can pin one LSDB entry and one
MTU-sized buffer per injected ID for the attacker-chosen lifetime plus
ZeroAgeLifetime.

This test checks that:
1. entries with a zero lifetime/seqno/checksum, the victim's own system
   ID, or a source without adjacency do not create placeholders;
2. a single unknown entry creates exactly one header-only placeholder
   and triggers the PSNP request (protocol behaviour preserved);
3. re-injecting the same LSP ID does not create more placeholders;
4. 16 distinct unknown IDs create 16 placeholders, but the per-entry
   stream footprint stays header-sized instead of MTU-sized;
5. an entry matching a real LSP in the LSDB does not create a
   placeholder;
6. a placeholder is updated in place when the real LSP arrives and the
   real LSP floods to other circuits (normal database sync preserved);
7. placeholders are reclaimed after their lifetime plus
   ZeroAgeLifetime.
"""

import json
import os
import re
import shlex
import sys
import time

import pytest

# Save the Current Working Directory to find configuration files.
CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

# pylint: disable=C0413
# Import topogen and topotest helpers
from lib.topogen import Topogen, TopoRouter, get_topogen
from lib.topolog import logger

pytestmark = [pytest.mark.isisd]

HELPER = os.path.join(CWD, "inject_snp.py")

R1_SYSID = "000000000001"
R2_SYSID = "000000000002"
R1_LSP_ID = R1_SYSID + "0000"
ENTRY_SEQNO = 0x00000100
ENTRY_CKSUM = 0xBEEF
INJECT_LIFETIME = 600
GC_LIFETIME = 30
# ZeroAgeLifetime (60s) plus lifetime, tick and polling margin
GC_WAIT = 150
TEMPLATE_WAIT = 45
PSNP_TAIL = 3.0
# The per-entry stream footprint of a placeholder must stay close to the
# LSP header size (27 bytes data + 48 bytes stream descriptor); the
# unpatched build pins LLC_LEN + lsp_mtu (1500 + 48) per entry.
STREAM_BYTES_PER_ENTRY_MAX = 400


def build_topo(tgen):
    "Build function"

    for router in ["r1", "r2", "r3"]:
        tgen.add_router(router)

    switch = tgen.add_switch("s1")
    switch.add_link(tgen.gears["r2"], nodeif="eth-r1")
    switch.add_link(tgen.gears["r1"], nodeif="eth-r2")

    switch = tgen.add_switch("s2")
    switch.add_link(tgen.gears["r1"], nodeif="eth-r3")
    switch.add_link(tgen.gears["r3"], nodeif="eth-r1")


def _start_template_sniffer(tgen, role, pdutype, source, lsp_id, name):
    "Sniff a template PDU on r2 before the phases start."
    logdir = tgen.logdir
    out_file = os.path.join(logdir, name + ".hex")
    stop_file = os.path.join(logdir, name + ".stop")
    pcap = os.path.join(logdir, name + ".pcap")
    tgen.gears["r2"].cmd("rm -f %s %s" % (shlex.quote(out_file),
                                          shlex.quote(stop_file)))
    tgen.gears["r2"].cmd(
        "nohup python3 %s --role %s --iface eth-r1 --pdutype %d "
        "--source %s --lsp-id %s --out-file %s --stop-file %s --pcap %s "
        "</dev/null >%s 2>&1 &"
        % (
            shlex.quote(HELPER),
            role,
            pdutype,
            source,
            lsp_id or '""',
            shlex.quote(out_file),
            shlex.quote(stop_file),
            shlex.quote(pcap),
            shlex.quote(os.path.join(logdir, name + ".out")),
        )
    )
    return {"out_file": out_file, "stop_file": stop_file,
            "out_log": os.path.join(logdir, name + ".out")}


def _stop_helper(tgen, cfg, done_marker):
    tgen.gears["r2"].cmd("touch %s" % shlex.quote(cfg["stop_file"]))
    deadline = time.monotonic() + 20
    while time.monotonic() < deadline:
        try:
            with open(cfg["out_log"]) as fp:
                if done_marker in fp.read():
                    return
        except FileNotFoundError:
            pass
        time.sleep(0.5)


def setup_module(mod):
    "Sets up the pytest environment"
    tgen = Topogen(build_topo, mod.__name__)
    tgen.start_topology()

    # For all registered routers, load the zebra configuration file
    for rname, router in tgen.routers().items():
        router.load_config(
            TopoRouter.RD_ZEBRA, os.path.join(CWD, "{}/zebra.conf".format(rname))
        )
        router.load_config(
            TopoRouter.RD_ISIS, os.path.join(CWD, "{}/isisd.conf".format(rname))
        )

    # Start sniffing the templates before the daemons start so the
    # initial flood is captured deterministically.
    mod.csnp_template = _start_template_sniffer(
        tgen, "csnp_template", 25, R2_SYSID, None, "csnp_template")
    mod.lsp_template = _start_template_sniffer(
        tgen, "lsp_template", 20, R1_SYSID, R1_LSP_ID, "lsp_template")
    tgen.csnp_template = mod.csnp_template
    tgen.lsp_template = mod.lsp_template

    tgen.start_router()


def teardown_module(mod):
    "Teardown the pytest environment"
    tgen = get_topogen()
    try:
        _stop_helper(tgen, mod.csnp_template, "TEMPLATE_DONE")
        _stop_helper(tgen, mod.lsp_template, "TEMPLATE_DONE")
    except Exception:
        pass
    tgen.stop_topology()


def lsdb_entries(router):
    "Map LSDB entry key (id|seq|chksum) -> entry dict for every LSP."
    data = json.loads(router.vtysh_cmd("show isis database json"))
    found = {}

    def walk(value):
        if isinstance(value, dict):
            lsp = value.get("lsp")
            if isinstance(lsp, dict) and "id" in lsp and "seqNumber" in value:
                key = "%s|%s|%s" % (
                    lsp["id"], value["seqNumber"], value.get("chksum"))
                found[key] = {
                    "id": lsp["id"],
                    "seq": value["seqNumber"],
                    "holdtime": value.get("holdtime"),
                    "pduLen": value.get("pduLen"),
                    "ownLSP": lsp.get("ownLSP", False),
                    "lspid": lspid_hex_of_id(lsp["id"]),
                }
            for child in value.values():
                walk(child)
        elif isinstance(value, list):
            for child in value:
                walk(child)

    walk(data)
    return found


def lspid_hex_of_id(id_str):
    "'0000.0000.00a1.00-00' style ids -> 16-hex-digit LSP ID."
    core = id_str.split(".")
    if len(core) >= 4 and all(re.fullmatch(r"[0-9a-f]{4}", p) for p in core[:3]):
        return "".join(core[:3]) + core[3].replace("-", "")
    raise RuntimeError("unparsed LSP id: %s" % id_str)


def mem_snapshot(router):
    "Per-memtype allocation counters from the running isisd."
    data = json.loads(router.vtysh_cmd("show memory isisd json"))
    found = {}

    def walk(value):
        if isinstance(value, dict):
            if "name" in value and "currentAllocations" in value:
                if value["name"] in ("ISIS LSP", "Stream"):
                    found[value["name"]] = {
                        "allocs": value["currentAllocations"],
                        "totalBytes": value.get("totalBytes") or 0,
                    }
            for child in value.values():
                walk(child)
        elif isinstance(value, list):
            for child in value:
                walk(child)

    walk(data)
    return found


def mem_delta(before, after):
    return {
        name: {
            "allocs": after.get(name, {}).get("allocs", 0)
            - before.get(name, {}).get("allocs", 0),
            "totalBytes": after.get(name, {}).get("totalBytes", 0)
            - before.get(name, {}).get("totalBytes", 0),
        }
        for name in ("ISIS LSP", "Stream")
    }


def adjacency_count(router):
    "Number of adjacencies in State: Up."
    raw = router.vtysh_cmd("show isis neighbor detail")
    count = 0
    current = None
    for line in raw.splitlines():
        if line.startswith(" ") and not line.startswith("    ") and line.strip():
            if current and "State: Up" in current:
                count += 1
            current = line
        elif current is not None:
            current += "\n" + line
    if current and "State: Up" in current:
        count += 1
    return count


def wait_adjacencies(tgen, timeout=90):
    "Wait until r1 has 2 Up adjacencies and r2/r3 have 1 each."
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            if (
                adjacency_count(tgen.gears["r1"]) == 2
                and adjacency_count(tgen.gears["r2"]) == 1
                and adjacency_count(tgen.gears["r3"]) == 1
            ):
                return True
        except (ValueError, json.JSONDecodeError):
            pass
        time.sleep(1)
    return False


def wait_template(path, timeout=TEMPLATE_WAIT):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if os.path.exists(path) and os.path.getsize(path) > 0:
            return True
        time.sleep(1)
    return False


def csnp_frame(source, entries):
    return {
        "kind": "csnp",
        "source": source,
        "entries": [
            {
                "id": lspid,
                "lifetime": lifetime,
                "seqno": seqno,
                "cksum": cksum,
            }
            for lspid, lifetime, seqno, cksum in entries
        ],
    }


def entry(sysid_hex, lifetime=INJECT_LIFETIME, seqno=ENTRY_SEQNO,
          cksum=ENTRY_CKSUM, frag=0):
    return (sysid_hex + "00" + "%02x" % frag, lifetime, seqno, cksum)


def lsp_frame(sysid_hex, seqno=ENTRY_SEQNO, lifetime=INJECT_LIFETIME):
    return {
        "kind": "lsp",
        "sysid": sysid_hex,
        "seqno": seqno,
        "lifetime": lifetime,
        "minimal": True,
    }


def injected_lspids(frames):
    ids = set()
    for frame in frames:
        if frame["kind"] == "csnp":
            for e in frame["entries"]:
                ids.add(e["id"])
        else:
            ids.add(frame["sysid"] + "0000")
    return ids


def inject(r2, frames, name, tgen, tail=1.5):
    "Run the inject role on r2 and return the capture dict."
    frames_arg = shlex.quote(json.dumps(frames))
    raw = r2.cmd_raises(
        "python3 %s --role inject --iface eth-r1 --csnp-template %s "
        "--lsp-template %s --frames %s --spacing 0.2 --tail %s --pcap %s"
        % (
            shlex.quote(HELPER),
            shlex.quote(os.path.join(tgen.logdir, "csnp_template.hex")),
            shlex.quote(os.path.join(tgen.logdir, "lsp_template.hex")),
            frames_arg,
            tail,
            shlex.quote(os.path.join(tgen.logdir, name + ".pcap")),
        )
    )
    for line in reversed(raw.splitlines()):
        if line.startswith("ISIS_CAPTURE_JSON="):
            return json.loads(line.split("=", 1)[1])
    raise RuntimeError("inject helper produced no capture: %s" % raw[-500:])


def placeholders_added(before, after, lspids):
    "Placeholder (seqno 0) entries for the given LSP IDs added in a phase."
    return {
        key: entry
        for key, entry in after.items()
        if key not in before
        and entry["lspid"] in lspids
        and entry["seq"] == "0x00000000"
    }


def entries_for(lsdb, lspids):
    return {k: v for k, v in lsdb.items() if v["lspid"] in lspids}


def psnp_requests_for(capture, lspids):
    "PSNPs seen on the inject link carrying any of the given LSP IDs."
    requests = []
    for event in capture["events"]:
        if event.get("pdutype") not in (26, 27):
            continue
        hits = [e for e in event.get("entries", []) if e["lspid"] in lspids]
        if hits:
            requests.append({"time": event["time"], "entries": hits})
    return requests


def start_observer(r3, tgen):
    stop_file = os.path.join(tgen.logdir, "observer.stop")
    out_json = os.path.join(tgen.logdir, "observer_events.json")
    out_log = os.path.join(tgen.logdir, "observer.out")
    r3.cmd("rm -f %s %s" % (shlex.quote(stop_file), shlex.quote(out_json)))
    r3.cmd(
        "nohup python3 %s --role observer --iface eth-r1 --stop-file %s "
        "--out-json %s --pcap %s </dev/null >%s 2>&1 &"
        % (
            shlex.quote(HELPER),
            shlex.quote(stop_file),
            shlex.quote(out_json),
            shlex.quote(os.path.join(tgen.logdir, "observer.pcap")),
            shlex.quote(out_log),
        )
    )
    return {"stop_file": stop_file, "out_json": out_json, "out_log": out_log}


def stop_observer(r3, observer):
    r3.cmd("touch %s" % shlex.quote(observer["stop_file"]))
    deadline = time.monotonic() + 20
    while time.monotonic() < deadline:
        if os.path.exists(observer["out_json"]):
            with open(observer["out_json"]) as fp:
                return json.load(fp)
        time.sleep(0.5)
    raise RuntimeError("observer did not finish")


def wait_gone(router, lspids, timeout):
    "Wait until no LSDB entry for any of the given LSP IDs remains."
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            if not entries_for(lsdb_entries(router), lspids):
                return True
        except (ValueError, json.JSONDecodeError):
            pass
        time.sleep(5)
    return False


def test_isis_snp_placeholder():
    "SNP placeholder creation: guards, request, footprint, conversion, GC."
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]
    r2 = tgen.gears["r2"]
    r3 = tgen.gears["r3"]

    # Precondition: adjacencies up and both templates captured.
    assert wait_adjacencies(tgen), "IS-IS adjacencies did not come up"
    assert wait_template(
        os.path.join(tgen.logdir, "csnp_template.hex")
    ), "r2 CSNP template not captured"
    assert wait_template(
        os.path.join(tgen.logdir, "lsp_template.hex")
    ), "r1 LSP template not captured"
    _stop_helper(tgen, tgen.csnp_template, "TEMPLATE_DONE")
    _stop_helper(tgen, tgen.lsp_template, "TEMPLATE_DONE")

    baseline = lsdb_entries(r1)
    baseline_count = len(baseline)

    # Injected unknown system IDs are all >= 0xa0 so the forged CSNP
    # start/stop range never covers the real LSP IDs.
    single_id = "0000000000a1"
    burst_ids = ["0000000000%02x" % i for i in range(0xA2, 0xB2)]
    convert_id = "0000000000b2"
    gc_ids = ["0000000000%02x" % i for i in range(0xB3, 0xB7)]

    # 1a. A CSNP from a system ID without adjacency is discarded before
    #     entry processing.
    before = lsdb_entries(r1)
    mem_before = mem_snapshot(r1)
    capture = inject(r2, [csnp_frame("0000000000ff", [entry(single_id)])],
                     "unknown_source", tgen)
    after = lsdb_entries(r1)
    assert not placeholders_added(before, after, {single_id + "0000"})
    assert mem_delta(mem_before, mem_snapshot(r1))["ISIS LSP"]["allocs"] == 0

    # 1b. Entries with a zero lifetime / seqno / checksum are skipped by
    #     the 7.3.15.2 b) 5) guard.
    zero_ids = ["0000000000a30000", "0000000000a40000", "0000000000a50000"]
    before = lsdb_entries(r1)
    capture = inject(
        r2,
        [csnp_frame(R2_SYSID, [
            entry("0000000000a3", lifetime=0),
            entry("0000000000a4", seqno=0),
            entry("0000000000a5", cksum=0),
        ])],
        "zero_fields", tgen)
    after = lsdb_entries(r1)
    assert not placeholders_added(before, after, set(zero_ids))
    assert mem_delta(mem_before, mem_snapshot(r1))["ISIS LSP"]["allocs"] == 0

    # 1c. An entry with the victim's own system ID is skipped by the
    #     own-system-ID check: fragment 1 of the victim's own LSP, which
    #     does not exist in the LSDB (a fragment-0 entry with a
    #     different checksum would trigger a fight-back seqno bump, so
    #     it must not be used here).
    before = lsdb_entries(r1)
    capture = inject(r2, [csnp_frame(R2_SYSID, [entry(R1_SYSID, frag=1)])],
                     "own_sysid", tgen)
    after = lsdb_entries(r1)
    assert not placeholders_added(before, after, {R1_SYSID + "0001"})
    assert mem_delta(mem_before, mem_snapshot(r1))["ISIS LSP"]["allocs"] == 0

    # 2. A single unknown entry creates exactly one header-only
    #    placeholder (seqno 0) and triggers the PSNP request.
    before = lsdb_entries(r1)
    mem_before = mem_snapshot(r1)
    capture = inject(r2, [csnp_frame(R2_SYSID, [entry(single_id)])],
                     "single", tgen, tail=PSNP_TAIL)
    after = lsdb_entries(r1)
    current = placeholders_added(before, after, {single_id + "0000"})
    assert len(current) == 1, (
        "expected exactly 1 placeholder, got %d: %s" % (len(current), sorted(current))
    )
    single_ph = list(current.values())[0]
    assert single_ph["pduLen"] == 27, "placeholder is not header-only: %s" % single_ph
    delta = mem_delta(mem_before, mem_snapshot(r1))
    assert delta["ISIS LSP"]["allocs"] == 1
    assert psnp_requests_for(capture, {single_id + "0000"}), (
        "no PSNP request for the placeholder"
    )

    # 3. Re-injecting the same LSP ID must not create more placeholders.
    before = lsdb_entries(r1)
    mem_before = mem_snapshot(r1)
    capture = inject(
        r2, [csnp_frame(R2_SYSID, [entry(single_id)]) for _ in range(8)],
        "repeat", tgen, tail=PSNP_TAIL)
    after = lsdb_entries(r1)
    assert not placeholders_added(before, after, {single_id + "0000"})
    assert len(entries_for(after, {single_id + "0000"})) == 1
    assert mem_delta(mem_before, mem_snapshot(r1))["ISIS LSP"]["allocs"] == 0

    # 4. 16 distinct unknown IDs: one placeholder each, but the
    #    per-entry stream footprint must stay header-sized; the
    #    unpatched build pins an MTU-sized buffer per entry.
    burst_lspids = {u + "0000" for u in burst_ids}
    before = lsdb_entries(r1)
    mem_before = mem_snapshot(r1)
    capture = inject(
        r2, [csnp_frame(R2_SYSID, [entry(u) for u in burst_ids])],
        "burst", tgen, tail=PSNP_TAIL)
    after = lsdb_entries(r1)
    current = placeholders_added(before, after, burst_lspids)
    assert len(current) == len(burst_ids), (
        "expected %d placeholders, got %d" % (len(burst_ids), len(current))
    )
    delta = mem_delta(mem_before, mem_snapshot(r1))
    assert delta["ISIS LSP"]["allocs"] == len(burst_ids)
    per_entry = delta["Stream"]["totalBytes"] / len(burst_ids)
    assert per_entry <= STREAM_BYTES_PER_ENTRY_MAX, (
        "placeholder pins an MTU-sized stream: %.0f stream bytes per entry"
        % per_entry)

    # 5. An entry matching a real LSP in the LSDB (LSP_EQUAL) does not
    #    create a placeholder.
    known = None
    for e in lsdb_entries(r1).values():
        if e["lspid"] == R2_SYSID + "0000" and not e["ownLSP"]:
            known = e
            break
    assert known is not None, "r2 LSP not found in r1 LSDB"
    before = lsdb_entries(r1)
    mem_before = mem_snapshot(r1)
    capture = inject(
        r2,
        [csnp_frame(R2_SYSID, [
            entry(R2_SYSID, seqno=int(known["seq"], 16),
                  cksum=int(known.get("chksum", "0x0"), 16)),
        ])],
        "known", tgen)
    after = lsdb_entries(r1)
    assert not placeholders_added(before, after, {R2_SYSID + "0000"})
    assert mem_delta(mem_before, mem_snapshot(r1))["ISIS LSP"]["allocs"] == 0

    # 6. A placeholder is updated in place when the real LSP arrives
    #    (lsp_update, not a second entry), and the real LSP floods to
    #    the observer segment (normal database sync preserved).
    observer = start_observer(r3, tgen)
    time.sleep(2)
    mem_before = mem_snapshot(r1)
    capture = inject(
        r2,
        [
            csnp_frame(R2_SYSID, [entry(convert_id)]),
            lsp_frame(convert_id),
        ],
        "convert", tgen, tail=PSNP_TAIL)
    after = lsdb_entries(r1)
    # The real LSP follows the CSNP within 0.2s, so the post-phase
    # snapshot may already show the converted entry; the placeholder's
    # creation is proven by the PSNP request (SSN is only set on the
    # placeholder) and by the net +1 LSDB object.
    assert len(entries_for(after, {convert_id + "0000"})) == 1, (
        "conversion phase did not leave exactly one LSDB entry"
    )
    assert psnp_requests_for(capture, {convert_id + "0000"}), (
        "no PSNP request for the conversion placeholder"
    )

    def converted(lsdb):
        return {
            k: v for k, v in entries_for(lsdb, {convert_id + "0000"}).items()
            if v["seq"] == "0x%08x" % ENTRY_SEQNO
        }

    deadline = time.monotonic() + 15
    final = {}
    while time.monotonic() < deadline:
        final = converted(lsdb_entries(r1))
        if final:
            break
        time.sleep(1)
    assert final, "placeholder not updated in place by the real LSP"
    assert mem_delta(mem_before, mem_snapshot(r1))["ISIS LSP"]["allocs"] == 1, (
        "real LSP created a second LSDB entry instead of updating the placeholder"
    )

    observer_data = stop_observer(r3, observer)
    floods = [
        event for event in observer_data["events"]
        if event.get("pdutype") in (18, 20)
        and event.get("lspid") == convert_id + "0000"
        and (event.get("seqno") or 0) == ENTRY_SEQNO
    ]
    assert floods, "converted real LSP did not flood to the observer segment"

    # 7. Placeholders are reclaimed after their attacker-chosen
    #    lifetime plus ZeroAgeLifetime; the allocations are released.
    gc_lspids = {u + "0000" for u in gc_ids}
    before = lsdb_entries(r1)
    mem_before = mem_snapshot(r1)
    capture = inject(
        r2,
        [csnp_frame(R2_SYSID, [entry(u, lifetime=GC_LIFETIME) for u in gc_ids])],
        "gc_batch", tgen)
    after = lsdb_entries(r1)
    assert len(placeholders_added(before, after, gc_lspids)) == len(gc_ids)
    assert wait_gone(r1, gc_lspids, GC_WAIT), (
        "short-lifetime placeholders not reclaimed"
    )
    delta = mem_delta(mem_before, mem_snapshot(r1))
    assert delta["ISIS LSP"]["allocs"] == 0, (
        "placeholder LSDB objects not released after GC"
    )

    # The long-lived placeholders from the earlier phases are still
    # present (their lifetime has not expired) and nothing leaked: the
    # LSDB holds exactly the baseline entries plus the injected set.
    current = lsdb_entries(r1)
    expected_placeholders = {u + "0000" for u in burst_ids}
    assert len(entries_for(current, expected_placeholders)) == len(burst_ids)
    assert len(entries_for(current, {single_id + "0000"})) == 1
    assert len(entries_for(current, {convert_id + "0000"})) == 1
    assert len(current) == baseline_count + len(burst_ids) + 2

    assert adjacency_count(r1) == 2, "adjacency lost on r1"


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
