#!/usr/bin/env python
# SPDX-License-Identifier: ISC
#
# test_isis_own_purge_placeholder.py
# Part of NetDEF Topology Tests
#
# Copyright (c) 2026 Bing Shui <bingshui@smail.nju.edu.cn>
#
r"""
test_isis_own_purge_placeholder.py:

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

An LSP whose ID carries the receiver's own system ID, with non-zero
seqno, valid checksum and non-zero remaining lifetime, and which is not
in the LSDB, makes isisd initiate a purge (ISO 10589 7.3.15.1 c)) by
retaining a header-only placeholder for ZeroAgeLifetime
(lsp_purge_non_exist).  The (pseudonode, fragment) byte pair of the ID
space is unbounded, so without a quota an adjacent attacker can pin one
LSDB entry, one stream and one flood per injected ID.

This test checks that:
1. a single unknown own LSP still creates exactly one purge placeholder
   and the purge is flooded to other circuits (protocol behaviour is
   preserved);
2. re-injecting the same LSP ID does not create more placeholders;
3. placeholders are reclaimed after ZeroAgeLifetime;
4. at most ISIS_OWN_PURGE_PLACEHOLDER_MAX (512) placeholders are
   retained concurrently per level; excess purges are dropped and
   counted;
5. a placeholder that is adopted as a real pseudonode LSP (DIS
   takeover, lsp_regenerate_pseudo) releases its placeholder slot;
6. the quota is per level: after the level-1 quota is saturated, an
   unknown own level-2 LSP still gets its purge placeholder.
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

HELPER = os.path.join(CWD, "inject_own_lsp.py")

R1_SYSID = "000000000001"
R1_LSP_ID = R1_SYSID + "0000"
INJECT_SEQNO = 0x00000100
INJECT_LIFETIME = 600
# must match ISIS_OWN_PURGE_PLACEHOLDER_MAX in isisd/isis_constants.h
PLACEHOLDER_MAX = 512
# ZeroAgeLifetime (60s) plus tick and polling margin
ZERO_AGE_WAIT = 90
TEMPLATE_WAIT = 75


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


def _start_template_sniffer(tgen):
    "Sniff r1's fragment-0 LSP on r2 before the daemons start flooding."
    logdir = tgen.logdir
    out_file = os.path.join(logdir, "r1_lsp_template.hex")
    stop_file = os.path.join(logdir, "template.stop")
    pcap = os.path.join(logdir, "template.pcap")
    tgen.gears["r2"].cmd(
        "rm -f %s %s" % (shlex.quote(out_file), shlex.quote(stop_file))
    )
    tgen.gears["r2"].cmd(
        "nohup python3 %s --role template --iface eth-r1 --lsp-id %s "
        "--out-file %s --stop-file %s --pcap %s </dev/null >%s 2>&1 &"
        % (
            shlex.quote(HELPER),
            R1_LSP_ID,
            shlex.quote(out_file),
            shlex.quote(stop_file),
            shlex.quote(pcap),
            shlex.quote(os.path.join(logdir, "template.out")),
        )
    )
    return {"out_file": out_file, "stop_file": stop_file}


def _stop_helper(tgen, stop_file, out_log, done_marker):
    tgen.gears["r2"].cmd("touch %s" % shlex.quote(stop_file))
    deadline = time.monotonic() + 20
    while time.monotonic() < deadline:
        try:
            with open(out_log) as fp:
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

    # Start sniffing r1's LSP before the daemons start so the initial
    # flood is captured deterministically.
    mod.template = _start_template_sniffer(tgen)

    tgen.start_router()


def teardown_module(mod):
    "Teardown the pytest environment"
    tgen = get_topogen()
    try:
        _stop_helper(
            tgen,
            mod.template["stop_file"],
            os.path.join(tgen.logdir, "template.out"),
            "TEMPLATE_DONE",
        )
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
                }
            for child in value.values():
                walk(child)
        elif isinstance(value, list):
            for child in value:
                walk(child)

    walk(data)
    return found


def placeholders(entries):
    "Zero-age placeholder entries created by the injections."
    return {
        key: entry
        for key, entry in entries.items()
        if entry["seq"] == "0x%08x" % INJECT_SEQNO
        and isinstance(entry["holdtime"], str)
        and entry["holdtime"].startswith("(")
    }


def summary_counter(router, key, level=None):
    "Read a counter from 'show isis summary json', optionally per level."
    data = json.loads(router.vtysh_cmd("show isis summary json"))

    if level is not None:
        # New per-level shape: counters live in the areas[].levels[]
        # objects, matched by their "id" (1 = L1, 2 = L2).
        def search_level(value):
            if isinstance(value, dict):
                if value.get("id") == level and key in value:
                    return value[key]
                for child in value.values():
                    found = search_level(child)
                    if found is not None:
                        return found
            elif isinstance(value, list):
                for child in value:
                    found = search_level(child)
                    if found is not None:
                        return found
            return None

        value = search_level(data)
        return 0 if value is None else value

    def search(value):
        if isinstance(value, dict):
            if key in value:
                return value[key]
            for child in value.values():
                found = search(child)
                if found is not None:
                    return found
        elif isinstance(value, list):
            for child in value:
                found = search(child)
                if found is not None:
                    return found
        return None

    value = search(data)
    return 0 if value is None else value


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


def adjacency_level_up(router, iface, level):
    "True if an Up adjacency on the interface covers the given level."
    raw = router.vtysh_cmd("show isis neighbor detail")
    blocks = []
    current = None
    for line in raw.splitlines():
        if line.startswith(" ") and not line.startswith("    ") and line.strip():
            if current:
                blocks.append(current)
            current = line
        elif current is not None:
            current += "\n" + line
    if current:
        blocks.append(current)
    for block in blocks:
        if "State: Up" not in block:
            continue
        if ("Interface: %s," % iface) not in block:
            continue
        match = re.search(r"Level: (\d+)", block)
        if match and (int(match.group(1)) & level):
            return True
    return False


def wait_l1_adjacencies(tgen, timeout=90):
    "After switching to level-1-2: L1 up on the r1-r2 link and r1 originated L1 LSPs."
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            if (
                adjacency_level_up(tgen.gears["r1"], "eth-r2", 1)
                and adjacency_level_up(tgen.gears["r2"], "eth-r1", 1)
                and summary_counter(tgen.gears["r1"], "lsp0-regenerated", level=1)
                >= 1
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


def inject(r2, frames, name, tgen, spacing=0.2):
    "Run the inject role on r2 and return the capture dict."
    frames_arg = shlex.quote(json.dumps(frames))
    raw = r2.cmd_raises(
        "python3 %s --role inject --iface eth-r1 --template %s "
        "--frames %s --spacing %s --tail 1.5 --pcap %s"
        % (
            shlex.quote(HELPER),
            shlex.quote(os.path.join(tgen.logdir, "r1_lsp_template.hex")),
            frames_arg,
            spacing,
            shlex.quote(os.path.join(tgen.logdir, name + ".pcap")),
        )
    )
    for line in reversed(raw.splitlines()):
        if line.startswith("ISIS_CAPTURE_JSON="):
            return json.loads(line.split("=", 1)[1])
    raise RuntimeError("inject helper produced no capture: %s" % raw[-500:])


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


def wait_zero_age_gone(r1, timeout=ZERO_AGE_WAIT):
    "Wait until no zero-age placeholder remains in the LSDB."
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if not placeholders(lsdb_entries(r1)):
            return True
        time.sleep(5)
    return False


def wait_placeholder_count(router, level, value, timeout=ZERO_AGE_WAIT):
    "Wait until the per-level placeholder counter reaches the value."
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if summary_counter(router, "own-purge-placeholders", level=level) == value:
            return True
        time.sleep(5)
    return False


def own_frame(frag, pseudo=0, level=2, seqno=INJECT_SEQNO):
    return {
        "sysid": R1_SYSID,
        "pseudo": pseudo,
        "frag": frag,
        "seqno": seqno,
        "lifetime": INJECT_LIFETIME,
        "corrupt": False,
        "level": level,
    }


def cap_burst_frames(count, level=2):
    "Distinct own-LSP IDs covering the (pseudonode, fragment) byte space."
    frames = []
    for pseudo in range(0, 256):
        for frag in range(0, 256):
            if pseudo == 0 and frag == 0:
                continue  # r1's own fragment-0
            frames.append(own_frame(frag=frag, pseudo=pseudo, level=level))
            if len(frames) == count:
                return frames
    return frames


def circuit_id_of(router, iface):
    "Circuit ID of an IS-IS interface from 'show isis interface detail'."
    raw = router.vtysh_cmd("show isis interface detail")
    for block in re.split(r"\n\s*\n", raw):
        if f"Interface: {iface}," in block:
            match = re.search(r"Circuit Id: 0x([0-9a-fA-F]+)", block)
            if match:
                return int(match.group(1), 16)
    raise RuntimeError("no circuit id for %s: %s" % (iface, raw[:400]))


def wait_converted(r1, cid, timeout=30):
    "Wait until the placeholder for r1.<cid>-00 became a real pseudonode LSP."
    expected_id = "r1.%02x-00" % cid
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            for entry in lsdb_entries(r1).values():
                zero_age = (
                    isinstance(entry["holdtime"], str)
                    and entry["holdtime"].startswith("(")
                )
                if (
                    entry["id"] == expected_id
                    and not zero_age
                    and (entry["pduLen"] or 0) > 27
                ):
                    return entry
        except (ValueError, json.JSONDecodeError):
            pass
        time.sleep(1)
    return None


def test_isis_own_purge_placeholder():
    "Unknown own-LSP purge placeholders: protocol behaviour, dedup, GC, cap."
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]
    r2 = tgen.gears["r2"]
    r3 = tgen.gears["r3"]

    # Precondition: adjacencies up and the r1 LSP template captured.
    assert wait_adjacencies(tgen), "IS-IS adjacencies did not come up"
    assert wait_template(
        os.path.join(tgen.logdir, "r1_lsp_template.hex")
    ), "r1 LSP template not captured on r2"

    baseline = lsdb_entries(r1)
    baseline_count = len(baseline)
    purged_base = summary_counter(r1, "lsp-purged", level=2)

    # 1. A single unknown own LSP must create exactly one placeholder
    #    (header-only, zero-age) and flood the purge to other circuits.
    observer = start_observer(r3, tgen)
    time.sleep(2)
    capture = inject(r2, [own_frame(frag=10)], "single", tgen)
    assert len(capture["sent"]) == 1
    entries = lsdb_entries(r1)
    current = placeholders(entries)
    assert len(current) == 1, (
        "expected exactly 1 purge placeholder, got %d: %s"
        % (len(current), sorted(current))
    )
    entry = list(current.values())[0]
    assert entry["pduLen"] == 27, "placeholder is not header-only: %s" % entry
    assert entry["ownLSP"] is False
    assert summary_counter(r1, "lsp-purged", level=2) == purged_base + 1

    observer_data = stop_observer(r3, observer)
    injected_id = R1_LSP_ID[:-2] + "0a"
    purges_on_r3 = [
        event
        for event in observer_data["events"]
        if event.get("pdutype") in (18, 20)
        and event.get("lspid") == injected_id
        and event.get("lifetime") == 0
    ]
    assert purges_on_r3, "purge for %s did not reach r3" % injected_id

    # 2. Re-injecting the same LSP ID must not create more placeholders.
    capture = inject(r2, [own_frame(frag=10) for _ in range(8)], "repeat", tgen)
    assert len(capture["sent"]) == 8
    current = placeholders(lsdb_entries(r1))
    assert len(current) == 1, "repeat injection created extra placeholders"
    assert summary_counter(r1, "lsp-purged", level=2) == purged_base + 1

    # 3. Placeholders are reclaimed after ZeroAgeLifetime.
    assert wait_zero_age_gone(r1), "placeholders not reclaimed after ZeroAgeLifetime"
    assert len(lsdb_entries(r1)) == baseline_count
    assert summary_counter(r1, "own-purge-placeholders", level=2) == 0

    # 4. More than PLACEHOLDER_MAX distinct unknown own LSP IDs: the
    #    number of retained placeholders is capped and the excess is
    #    dropped and counted.  The burst must finish within the
    #    ZeroAgeLifetime (60s) GC window, otherwise early placeholders
    #    are reclaimed before the cap is reached; 520 frames at 20 pkt/s
    #    take ~26s.
    purged_base = summary_counter(r1, "lsp-purged", level=2)
    frames = cap_burst_frames(PLACEHOLDER_MAX + 8)
    capture = inject(r2, frames, "cap_burst", tgen, spacing=0.05)
    assert len(capture["sent"]) == PLACEHOLDER_MAX + 8
    current = placeholders(lsdb_entries(r1))
    assert len(current) == PLACEHOLDER_MAX, (
        "expected %d capped placeholders, got %d"
        % (PLACEHOLDER_MAX, len(current))
    )
    assert summary_counter(r1, "own-purge-placeholders", level=2) == PLACEHOLDER_MAX
    assert summary_counter(r1, "own-purge-placeholders-dropped", level=2) == 8, (
        "excess purges were not dropped and counted"
    )
    assert summary_counter(r1, "lsp-purged", level=2) == purged_base + PLACEHOLDER_MAX

    # 5. The capped placeholders are still reclaimed normally.
    assert wait_zero_age_gone(r1), "capped placeholders not reclaimed"
    assert len(lsdb_entries(r1)) == baseline_count
    assert summary_counter(r1, "own-purge-placeholders", level=2) == 0

    # 6. A placeholder for a pseudonode ID that is later adopted as the
    #    real pseudonode LSP (r1 wins the DIS election on the broadcast
    #    link to r2) must release its placeholder slot at the conversion:
    #    the accounting follows the creation origin, not mutable header
    #    fields.  r1 resigns afterwards; the purge/destroy of the
    #    converted LSP must not decrement the counter again.
    cid = circuit_id_of(r1, "eth-r2")
    capture = inject(r2, [own_frame(frag=0, pseudo=cid)], "pseudo_single", tgen)
    assert len(capture["sent"]) == 1
    current = placeholders(lsdb_entries(r1))
    assert len(current) == 1, "pseudonode placeholder not created"
    assert summary_counter(r1, "own-purge-placeholders", level=2) == 1

    r1.vtysh_cmd("configure terminal\ninterface eth-r2\nisis priority 127\nend")
    converted = wait_converted(r1, cid)
    assert converted is not None, "placeholder not adopted as pseudonode LSP"
    assert summary_counter(r1, "own-purge-placeholders", level=2) == 0, (
        "placeholder slot not released at conversion"
    )

    r1.vtysh_cmd("configure terminal\ninterface eth-r2\nisis priority 10\nend")
    assert summary_counter(r1, "own-purge-placeholders", level=2) == 0, (
        "placeholder counter moved after resign"
    )

    # 7. The quota is per level: after the level-1 quota is saturated by
    #    a burst of distinct L1 IDs, an unknown own L2 LSP must still get
    #    its purge placeholder (L1 placeholders must not eat the L2
    #    quota).  Switch the area to level-1-2 and wait for the L1
    #    adjacency on the injection link: received LSPs are silently
    #    discarded when no same-level adjacency exists (7.3.15.1 a) 6).
    for gear in (r1, r2, r3):
        gear.vtysh_cmd(
            "configure terminal\nrouter isis 1\nis-type level-1-2\nend"
        )
    assert wait_l1_adjacencies(tgen), "L1 adjacency did not come up"

    frames = cap_burst_frames(PLACEHOLDER_MAX + 8, level=1)
    capture = inject(r2, frames, "l1_cap_burst", tgen, spacing=0.05)
    assert len(capture["sent"]) == PLACEHOLDER_MAX + 8
    assert summary_counter(r1, "own-purge-placeholders", level=1) == PLACEHOLDER_MAX
    assert summary_counter(r1, "own-purge-placeholders-dropped", level=1) == 8

    # A legitimate-shaped unknown own L2 LSP must still be purged: the
    #    L2 quota is untouched by the L1 saturation.  A distinct seqno
    #    keeps the LSDB keys of the L1 and L2 entries apart.  The
    #    dropped counter is cumulative since daemon start (step 4
    #    already dropped 8 at L2), so assert it does not move.
    l2_dropped_base = summary_counter(
        r1, "own-purge-placeholders-dropped", level=2
    )
    capture = inject(
        r2, [own_frame(frag=200, level=2, seqno=INJECT_SEQNO + 1)],
        "l2_after_l1", tgen,
    )
    assert len(capture["sent"]) == 1
    assert summary_counter(r1, "own-purge-placeholders", level=2) == 1
    assert summary_counter(
        r1, "own-purge-placeholders-dropped", level=2
    ) == l2_dropped_base, "L2 purge dropped after L1 saturation"
    l2_entry = [
        entry
        for entry in lsdb_entries(r1).values()
        if entry["id"] == "r1.00-c8"
        and entry["seq"] == "0x%08x" % (INJECT_SEQNO + 1)
    ]
    assert len(l2_entry) == 1 and l2_entry[0]["pduLen"] == 27, (
        "L2 placeholder missing after L1 saturation: %s" % l2_entry
    )

    # The saturated L1 placeholders are still reclaimed normally; the
    # L2 placeholder was created a few seconds later and follows on its
    # own ZeroAgeLifetime schedule.
    assert wait_placeholder_count(r1, 1, 0), (
        "capped L1 placeholders not reclaimed"
    )
    assert wait_placeholder_count(r1, 2, 0), (
        "L2 placeholder not reclaimed"
    )


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
