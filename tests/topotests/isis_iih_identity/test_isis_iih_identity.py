#!/usr/bin/env python
# SPDX-License-Identifier: ISC
#
# test_isis_iih_identity.py
# Part of NetDEF Topology Tests
#
# Copyright (c) 2026 by Bing Shui <bingshui@smail.nju.edu.cn>
#
"""
test_isis_iih_identity.py

A LAN hello from a different SNPA must not rewrite an existing
adjacency.

process_lan_hello() looks the adjacency up by system-id only.  When
an IIH arrives with the same system-id but a different source MAC,
the recorded SNPA of the adjacency is silently overwritten and the
adjacency is forced to Initializing, before the LAN Neighbours TLV
immediately drives it back to Up.  ISO 10589 8.4.1.4 identifies an
existing LAN adjacency by the (system-id, SNPA) pair, so an IIH from
a different SNPA belongs to a different adjacency (8.4.1.5) and must
not rewrite the identity or reset the state of the recorded one.
While the bogus SNPA is recorded, LSPs from the genuine neighbour's
MAC are silently discarded and LSPs from the attacker's MAC are
accepted, and each forged hello flaps the adjacency on both routers.

The demotion of an Up adjacency whose LAN Neighbours TLV no longer
contains the local SNPA is a separate, ISO-mandated rule (8.4.1.5)
and is pinned here as a protocol-behaviour control: it must keep
working on both the unpatched and the patched build.

Topology (level-2-only, area 49.0001):

    r2 ----+
    h1 ----+---- LAN1 ---- r1 (DIS, prio 64)
  injector        (prio 10)

h1 replays captured genuine hellos and r2's genuine LSP with edited
fields, unicast to r1.  All frames are protocol-valid except the
field under test (system-id / source MAC / LAN Neighbours TLV).
"""

import json
import os
import re
import sys
import time

import pytest

CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

# pylint: disable=C0413
from lib import topotest
from lib.topogen import Topogen, get_topogen
from lib.topolog import logger

pytestmark = [pytest.mark.isisd]

INJECTOR = os.path.join(CWD, "isis_inject.py")

SYSID = {
    "r1": "000000000001",
    "r2": "000000000002",
    "r9": "000000000009",
}
R2_LSP = SYSID["r2"] + "0000"
ATT_MAC = "02:00:00:00:00:09"
R9_MAC = "02:00:00:00:00:0a"
BOGUS_MAC = "02:00:00:00:00:ff"


def build_topo(tgen):
    "Build function"

    for rname in ["r1", "r2"]:
        tgen.add_router(rname)
    tgen.add_host("h1", "10.0.1.100/24", "via 10.0.1.1")

    lan1 = tgen.add_switch("lan1")
    lan1.add_link(tgen.gears["r1"], nodeif="eth-lan1")
    lan1.add_link(tgen.gears["r2"], nodeif="eth-lan1")
    lan1.add_link(tgen.gears["h1"], nodeif="eth0")


def setup_module(module):
    "Sets up the pytest environment"

    tgen = Topogen(build_topo, module.__name__)
    tgen.start_topology()

    for router in tgen.routers().values():
        router.load_frr_config()

    tgen.start_router()


def teardown_module():
    "Teardown the pytest environment"
    get_topogen().stop_topology()


def router_out(rname, command, isjson=False):
    return get_topogen().gears[rname].vtysh_cmd(command, isjson=isjson)


def dotted(sysid):
    return "{}.{}.{}".format(sysid[0:4], sysid[4:8], sysid[8:12])


def snpa_dotted(mac):
    hexed = mac.replace(":", "")
    return "{}.{}.{}".format(hexed[0:4], hexed[4:8], hexed[8:12])


def marked(holdtime):
    "True when an LSDB entry carries the spoof marker lifetime (333)."
    return isinstance(holdtime, int) and holdtime <= 333


def neighbor_rows(rname):
    "Parse `show isis neighbor detail`: {sysid: {state, snpa, flaps}}."
    rows = {}
    current = None
    for line in router_out(rname, "show isis neighbor detail").splitlines():
        stripped = line.strip()
        if line.startswith(" ") and not line.startswith("    ") and stripped:
            current = stripped.split()[0]
            rows[current] = {}
        elif current and "State:" in stripped:
            match = re.search(r"State: (\w+)", stripped)
            if match:
                rows[current]["state"] = match.group(1)
        elif current and stripped.startswith("SNPA:"):
            match = re.search(r"SNPA: ([0-9a-fA-F.]+)", stripped)
            if match:
                rows[current]["snpa"] = match.group(1)
        elif current and "Adjacency flaps:" in stripped:
            match = re.search(r"Adjacency flaps: (\d+)", stripped)
            if match:
                rows[current]["flaps"] = int(match.group(1))
    return rows


def adjacency_up(rname, peer):
    "True when rname has an Up adjacency to peer (hostname or sysid)."
    rows = neighbor_rows(rname)
    row = rows.get(dotted(SYSID[peer])) or rows.get(peer)
    return bool(row) and row.get("state") == "Up"


def lsdb_map(rname):
    "Map normalized LSP id -> {seqno, holdtime} from rname's LSDB."

    def walk(value, out):
        if isinstance(value, dict):
            lsp = value.get("lsp")
            if isinstance(lsp, dict) and "id" in lsp and "seqNumber" in value:
                key = lsp["id"].replace(".", "").replace("-", "").lower()
                out[key] = {
                    "id": lsp["id"],
                    "seqno": int(value["seqNumber"], 16),
                    "holdtime": value.get("holdtime"),
                }
            for child in value.values():
                walk(child, out)
        elif isinstance(value, list):
            for child in value:
                walk(child, out)

    out = {}
    walk(router_out(rname, "show isis database json", isjson=True), out)
    return out


def pseudo_of(db, owner):
    "The owner's pseudonode LSP entry in an lsdb_map, or None."
    for key, entry in db.items():
        if key.startswith(SYSID[owner]) and key[12:14] != "00":
            return entry
    return None


def lan_dis_state(rname):
    "Map interface -> {priority, is_dis} for broadcast circuits."

    def walk(value, out):
        if isinstance(value, dict):
            iface = value.get("interface")
            if isinstance(iface, dict) and "name" in iface:
                for level in iface.get("levels", []):
                    lan = level.get("lan")
                    if isinstance(lan, dict) and "is-dis" in lan:
                        out[iface["name"]] = {
                            "priority": lan.get("priority"),
                            "is_dis": lan.get("is-dis") == "yes",
                        }
            for child in value.values():
                walk(child, out)
        elif isinstance(value, list):
            for child in value:
                walk(child, out)

    out = {}
    walk(router_out(rname, "show isis interface detail json", isjson=True), out)
    return out


def drop_counters(rname):
    "PDU drop counters from `show isis summary` (text only)."
    drops = {}
    in_drops = False
    for line in router_out(rname, "show isis summary").splitlines():
        if "Drop counters" in line:
            in_drops = True
            continue
        if in_drops:
            match = re.match(r"\s+(.+): (\d+)$", line)
            if match:
                drops[match.group(1).strip()] = int(match.group(2))
            elif line.strip() and not line.startswith(" "):
                in_drops = False
    return drops


def wait_until(fn, timeout, interval=0.5):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            if fn():
                return True
        except Exception:
            pass
        time.sleep(interval)
    return False


def templates_path():
    return os.path.join(get_topogen().logdir, "iih_identity_templates.json")


def templates(trigger=None):
    "Captured {iih: {sysid: {pdu, src_mac}}, lsp: {lspid: {pdu, seqno}}}."
    cache = templates._cache
    if cache is None:
        # Sniff in the background: an LSP flood is an event-driven
        # one-shot, so TRIGGER must run while the sniffer is up.
        out_path = templates_path() + ".out"
        get_topogen().net["h1"].cmd(
            "python3 {} template eth0 {} 60 > {} 2>&1 &".format(
                INJECTOR, templates_path(), out_path
            )
        )
        if trigger is not None:
            time.sleep(3)
            trigger()
        out = ""
        for _ in range(90):
            if os.path.exists(out_path):
                with open(out_path) as fp:
                    out = fp.read()
                if "TEMPLATE_DONE" in out:
                    break
            time.sleep(1)
        assert "TEMPLATE_DONE" in out, "template capture failed: {}".format(out)
        with open(templates_path()) as fp:
            cache = json.load(fp)
        templates._cache = cache
    return cache


templates._cache = None


def inject(edits, src_mac, dst_mac, count, spacing):
    "Replay one variant on LAN1, COUNT times, SPACING seconds apart."
    args = "python3 {} send eth0 {} {} {} {} {} '{}'".format(
        INJECTOR, templates_path(), src_mac, dst_mac, count, spacing,
        json.dumps(edits),
    )
    out = get_topogen().net["h1"].cmd(args, timeout=60)
    assert "SENT={}".format(count) in out, "injection failed: {}".format(out)


def r1_mac():
    return templates()["iih"][SYSID["r1"]]["src_mac"]


def r2_mac():
    return templates()["iih"][SYSID["r2"]]["src_mac"]


def r2_lsp_spoof_edits(seqno):
    return {"template": "lsp:" + R2_LSP, "seqno_set": seqno, "lifetime_set": 333}


def test_wait_convergence():
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    def check():
        for rname, peer in (("r1", "r2"), ("r2", "r1")):
            if not adjacency_up(rname, peer):
                return "{} has no adjacency to {}".format(rname, peer)
        if not lan_dis_state("r1").get("eth-lan1", {}).get("is_dis"):
            return "r1 is not DIS on eth-lan1"
        db = lsdb_map("r1")
        if pseudo_of(db, "r1") is None:
            return "r1's pseudonode LSP not in r1's LSDB"
        if R2_LSP not in db:
            return "r2's LSP not in r1's LSDB"
        if "2.2.2.2/32" not in router_out("r1", "show ip route json", isjson=True):
            return "r1 has no route to r2's loopback"
        return None

    _, result = topotest.run_and_expect(check, None, count=90, wait=1)
    assert result is None, "IS-IS did not converge:\n{}".format(result)

    # Force one r2 LSP regeneration so the template capture also sees
    # r2's LSP on the wire (steady state has no LSP floods).  The
    # sandbox kernel has no dummy device type, so add an address to the
    # existing passive loopback instead of a fresh interface.
    def trigger():
        get_topogen().net["r2"].cmd("ip addr add 10.0.99.2/32 dev lo")

    capture = templates(trigger=trigger)
    assert set(capture["iih"]) == {SYSID["r1"], SYSID["r2"]}
    assert R2_LSP in capture["lsp"], "r2's LSP template not captured"


def test_legal_refresh():
    """
    Replaying r2's genuine hello unchanged must produce no work: the
    adjacency is refreshed, nothing is dropped, no state changes.
    """
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    templates()
    row0 = neighbor_rows("r1")[dotted(SYSID["r2"])]
    flaps0 = row0.get("flaps", 0)
    pseudo0 = pseudo_of(lsdb_map("r1"), "r1")["seqno"]
    drops0 = drop_counters("r1")

    inject({"template": SYSID["r2"]}, r2_mac(), r1_mac(), count=8, spacing=0.5)
    time.sleep(3)

    row1 = neighbor_rows("r1")[dotted(SYSID["r2"])]
    assert row1.get("flaps", 0) == flaps0, "legal refresh flapped the adjacency"
    assert row1.get("state") == "Up"
    assert row1.get("snpa") == snpa_dotted(r2_mac())
    assert pseudo_of(lsdb_map("r1"), "r1")["seqno"] == pseudo0, (
        "legal refresh regenerated the pseudonode LSP")
    drops1 = drop_counters("r1")
    assert drops1.get("L2 IIH", 0) == drops0.get("L2 IIH", 0), (
        "legal refresh was dropped")


def test_spoofed_snpa_iih():
    """
    The attack: hellos with r2's system-id but the injector's source
    MAC, then r2's genuine LSP replayed from the injector's MAC.

    Unpatched, each forged hello rewrites the recorded SNPA and flaps
    the adjacency to Initializing and back; the spoofed LSP is then
    accepted from the injector's MAC while the genuine SNPA is
    overwritten.  Patched, the forged hellos belong to no adjacency
    (ISO 10589 8.4.1.4) and are discarded: the adjacency stays Up
    with the genuine SNPA, the spoofed LSP is dropped, and the drop
    counters show the rejections.
    """
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    templates()
    genuine_seq = lsdb_map("r1")[R2_LSP]["seqno"]
    flaps0 = neighbor_rows("r1")[dotted(SYSID["r2"])].get("flaps", 0)
    drops0 = drop_counters("r1")

    # Control: the spoofed LSP from the injector's MAC is discarded
    # while the recorded SNPA is genuine (both builds).  The marker
    # lifetime makes an accepted copy unmistakable in the LSDB.
    inject(r2_lsp_spoof_edits(genuine_seq + 1), ATT_MAC, r1_mac(), count=2,
           spacing=0.2)
    time.sleep(1)
    entry = lsdb_map("r1")[R2_LSP]
    assert entry["seqno"] == genuine_seq and not marked(entry["holdtime"]), (
        "stranger-MAC LSP was accepted before any forgery")

    # 4 forged hellos, then the spoofed LSP right after the 4th (the
    # genuine neighbour cannot have answered yet), then 4 more.
    inject({"template": SYSID["r2"]}, ATT_MAC, r1_mac(), count=4, spacing=0.5)
    inject(r2_lsp_spoof_edits(genuine_seq + 1), ATT_MAC, r1_mac(), count=3,
           spacing=0.1)
    inject({"template": SYSID["r2"]}, ATT_MAC, r1_mac(), count=4, spacing=0.5)

    def poisoned():
        return marked(lsdb_map("r1")[R2_LSP]["holdtime"])

    saw_poison = wait_until(poisoned, 5, interval=0.2)
    time.sleep(2)

    row1 = neighbor_rows("r1")[dotted(SYSID["r2"])]
    drops1 = drop_counters("r1")
    iih_drops = drops1.get("L2 IIH", 0) - drops0.get("L2 IIH", 0)
    lsp_drops = drops1.get("L2 LSP", 0) - drops0.get("L2 LSP", 0)

    assert row1.get("state") == "Up", "adjacency to r2 did not stay Up"
    assert row1.get("flaps", 0) == flaps0, (
        "forged hellos flapped the adjacency: flaps {} -> {}".format(
            flaps0, row1.get("flaps")))
    assert row1.get("snpa") == snpa_dotted(r2_mac()), (
        "recorded SNPA was rewritten to {}".format(row1.get("snpa")))
    assert not saw_poison, "spoofed LSP from the injector's MAC was accepted"
    assert iih_drops >= 8, "forged hellos were not rejected ({} drops)".format(
        iih_drops)
    assert lsp_drops >= 5, "spoofed LSPs were not rejected ({} drops)".format(
        lsp_drops)


def test_no_own_snpa_protocol_rule():
    """
    ISO 10589 8.4.1.5 mandates Up -> Initializing when a neighbour's
    LAN Neighbours TLV no longer contains the local SNPA.  This rule
    must keep working on the patched build; the SNPA of the sender is
    unchanged here, so the IIH is processed normally.
    """
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    templates()
    flaps0 = neighbor_rows("r1")[dotted(SYSID["r2"])].get("flaps", 0)
    r1_hex = r1_mac().replace(":", "")

    inject({"template": SYSID["r2"], "tlv6_replace": [r1_hex, BOGUS_MAC.replace(":", "")]},
           r2_mac(), r1_mac(), count=4, spacing=0.5)
    time.sleep(4)

    row1 = neighbor_rows("r1")[dotted(SYSID["r2"])]
    assert row1.get("flaps", 0) > flaps0, (
        "ISO-mandated demotion did not happen: flaps {} -> {}".format(
            flaps0, row1.get("flaps")))
    assert row1.get("state") == "Up", "adjacency did not recover"
    assert row1.get("snpa") == snpa_dotted(r2_mac())


def test_legal_new_adjacency():
    """
    A hello with a fresh system-id must still create a legal new
    adjacency (and let it expire): the fix must not reject new
    neighbours wholesale.
    """
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    templates()
    r1_hex = r1_mac().replace(":", "")

    inject({"template": SYSID["r2"], "sysid": SYSID["r9"]},
           R9_MAC, r1_mac(), count=2, spacing=0.5)

    def r9_up():
        row = neighbor_rows("r1").get(dotted(SYSID["r9"]))
        return bool(row) and row.get("state") == "Up"

    assert wait_until(r9_up, 10), "legal new adjacency to r9 did not form"
    assert wait_until(
        lambda: dotted(SYSID["r9"]) not in neighbor_rows("r1"), 20), (
        "r9 adjacency did not expire")


def test_invalid_controls():
    """
    Invalid IIHs are rejected with no state change: an L1 hello on an
    L2-only circuit, a hello without Protocols Supported TLV, and a
    hello with a bogus PDU length.
    """
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    templates()
    flaps0 = neighbor_rows("r1")[dotted(SYSID["r2"])].get("flaps", 0)
    drops0 = drop_counters("r1")
    l1_drops0 = drops0.get("L1 IIH", 0)
    l2_drops0 = drops0.get("L2 IIH", 0)

    inject({"template": SYSID["r2"], "pdu_type": 15}, r2_mac(), r1_mac(),
           count=2, spacing=0.3)
    inject({"template": SYSID["r2"], "drop_tlvs": [129]}, r2_mac(), r1_mac(),
           count=2, spacing=0.3)
    inject({"template": SYSID["r2"], "bad_pdu_len": 9999}, r2_mac(), r1_mac(),
           count=2, spacing=0.3)
    time.sleep(2)

    drops1 = drop_counters("r1")
    assert drops1.get("L1 IIH", 0) - l1_drops0 >= 2, "L1 IIH not rejected"
    assert drops1.get("L2 IIH", 0) - l2_drops0 >= 4, "invalid L2 IIHs not rejected"
    row1 = neighbor_rows("r1")[dotted(SYSID["r2"])]
    assert row1.get("flaps", 0) == flaps0, "invalid IIHs changed the adjacency"
    assert row1.get("state") == "Up"
    assert len(neighbor_rows("r1")) == 1, "invalid IIHs created an adjacency"
