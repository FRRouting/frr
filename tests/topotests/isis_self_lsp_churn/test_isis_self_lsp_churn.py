#!/usr/bin/env python
# SPDX-License-Identifier: ISC
#
# test_isis_self_lsp_churn.py
# Part of NetDEF Topology Tests
#
# Copyright (c) 2026 by Bing Shui <bingshui@smail.nju.edu.cn>
#

"""
test_isis_self_lsp_churn.py:

          +---------+             +---------+
          |   r2    |             |   r3    |
          | injector|             | observer|
          +---------+             +---------+
               |eth0                   |eth0
               |  10.213.12.0/24      |  10.213.13.0/24
               |                      |
          +----+----------------------+----+
          |            r1 (victim)          |
          |      net 49.0001.0000.0001.00   |
          +---------------------------------+
               |eth2 (broadcast LAN, 10.213.14.0/24, r1 is DIS)
          +----+----+
          |    s1   |
          +----+----+
               |eth1
          +---------+
          |   r2    |
          +---------+

r1-r2 and r1-r3 links are point-to-point; r1-r2 are additionally
connected through the broadcast LAN s1 (r1 is the level-2 DIS and
originates a pseudonode LSP).  All routers are level-2-only, area
49.0001.  r1 runs with lsp-mtu 300 and advertises a block of loopback
/32 prefixes, so its own LSP is split into fragments 0, 1, 2, ....

An on-link attacker keeps injecting forged copies of the victim's own
LSPs with genuinely higher sequence numbers.  ISO 10589 requires the
victim to fight back with an even higher sequence number, but the
regeneration must be rate limited: without a limit, every injected PDU
drives one synchronous lsp_inc_seqno() plus a full flood, so the
attacker fully controls the victim's self-LSP regeneration and flooding
rate (control-plane churn, and an unbounded drain of the sequence
number space).  The lsp-gen-interval knob gates the periodic
regeneration timer only; the fight-back paths used to bypass it.

ISO 10589 7.3.16.1 requires sequence numbers to be independent per LSP
number, so the rate limiting must track pending fight-backs per LSP ID:
a forged copy of fragment 1 may only drive fragment 1 (never fragment
0 or 2), and every attacked LSP must still end up with a sequence
number above every forged copy of that specific LSP.

The test drives three fight-back paths with bounded traffic (<=16 PDUs,
<=5 PDU/s per scenario) and checks:
  - a single forged newer LSP causes exactly one prompt fight-back
    (protocol-required behaviour, must keep working);
  - a burst of forged newer LSPs causes at most one fight-back per
    lsp-gen-interval (the rate limit), while the victim still ends up
    with a sequence number above every forged copy;
  - the same holds for forged own purges and for newer own-LSP entries
    in PSNPs;
  - a burst against own fragment 1 only drives fragment 1, leaves
    fragments 0 and 2 untouched, and is rate limited;
  - fragments 0 and 1 attacked in the same throttling window each end
    above their own forged sequence numbers (no cross-LSP seqno leak);
  - forged copies of the victim's pseudonode LSP only drive the
    pseudonode LSP and are rate limited;
  - two circuits requesting the same own LSP by PSNP in the same
    window each get the deferred response while the LSP is still
    regenerated at most once per lsp-gen-interval;
  - a PSNP request mixed into a pending flood fight-back does not
    downgrade it to unicast (the widest propagation scope wins);
  - once the injection stops, the sequence number and the adjacencies
    stay stable.
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
from lib import topotest
from lib.topogen import Topogen, TopoRouter, get_topogen
from lib.topolog import logger

pytestmark = [pytest.mark.isisd]

TARGET = "r1"
PEER = "r2"
OBSERVER = "r3"
TARGET_LSP_ID = "0000000000010000"
TARGET_FRAG1_LSP_ID = "0000000000010001"
TARGET_FRAG2_LSP_ID = "0000000000010002"
PEER_SYSID = "000000000002"
PEER_IP = "10.213.12.2"
OBSERVER_IP = "10.213.13.3"
TARGET_IP = "10.213.12.1"
TARGET_IP2 = "10.213.13.1"
LAN_PEER_IP = "10.213.14.2"
LAN_TARGET_IP = "10.213.14.1"
HELPER = os.path.join(CWD, "isis_churn_helper.py")

BURST_COUNT = 8
BURST_SPACING = 0.2
CAPTURE_TAIL = 1.5
LSP_GEN_INTERVAL = 2
# multi_id_same_window makes the fragment-1 forged seqnos much higher
# than the fragment-0 ones, so any cross-fragment seqno leak shows up
# unambiguously.
MULTI_ID_PER_LSP = 4
MULTI_ID_FRAG_B_OFFSET = 100

STATE = {"template_hex": None}


def lsp_id_dotted(lsp_id_hex):
    "Hex LSP ID -> the dotted form used in isisd log lines (%pLS)."
    return "{}.{}-{}".format(
        ".".join(lsp_id_hex[i:i + 4] for i in range(0, 12, 4)),
        lsp_id_hex[12:14],
        lsp_id_hex[14:16],
    )


def lsp_id_tuple(lsp_id_hex):
    "Hex LSP ID -> (pseudonode, fragment) byte tuple."
    return int(lsp_id_hex[12:14], 16), int(lsp_id_hex[14:16], 16)


def target_lsp_ids():
    "All target LSP IDs used for per-ID accounting, plus the pseudonode LSP."
    ids = [TARGET_LSP_ID, TARGET_FRAG1_LSP_ID, TARGET_FRAG2_LSP_ID]
    if STATE.get("pseudo_lsp_id"):
        ids.append(STATE["pseudo_lsp_id"])
    return ids


def build_topo(tgen):
    "Build function"
    r1 = tgen.add_router(TARGET)
    r2 = tgen.add_router(PEER)
    r3 = tgen.add_router(OBSERVER)
    tgen.add_link(r1, r2)
    tgen.add_link(r1, r3)
    # Broadcast LAN between r1 and r2 (r1 is the DIS); lets the victim
    # originate a pseudonode LSP and gives the pseudonode fight-back
    # scenario a place to run.
    sw = tgen.add_switch("s1")
    tgen.add_link(r1, sw)
    tgen.add_link(r2, sw)


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

    # After loading the configurations, this function loads configured daemons.
    tgen.start_router()


def teardown_module():
    "Teardown the pytest environment"
    tgen = get_topogen()
    tgen.stop_topology()


def victim_lsp_seqnos(router):
    "Map (pseudonode, fragment) -> seqno for every own LSP of the victim."
    data = json.loads(router.vtysh_cmd("show isis database json"))
    found = {}

    def walk(value):
        if isinstance(value, dict):
            lsp = value.get("lsp")
            if isinstance(lsp, dict) and lsp.get("ownLSP") is True and "seqNumber" in value:
                id_str = lsp["id"]
                # The id always ends with ".PP-FF" (pseudonode, fragment),
                # whether the sysid part is a dynamic hostname or dotted hex.
                found[(int(id_str[-5:-3], 16), int(id_str[-2:], 16))] = int(
                    value["seqNumber"], 16
                )
            for child in value.values():
                walk(child)
        elif isinstance(value, list):
            for child in value:
                walk(child)

    walk(data)
    assert found, "no own LSP found in database json: {}".format(data)
    return found


def victim_seqno(router):
    "Sequence number of the victim's own fragment-0 LSP."
    return victim_lsp_seqnos(router)[(0, 0)]


def adjacency_up(router, peer_ip):
    "True when the adjacency towards peer_ip is Up."
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
    return any(peer_ip in block and "State: Up" in block for block in blocks)


def target_lsp_events(events, lspid_hex):
    return [
        event
        for event in events
        if event.get("pdutype") in (18, 20) and event.get("lspid") == lspid_hex
    ]


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


def fightback_log_count_by_id(router, offset):
    "Number of fight-back re-originations per LSP ID since offset."
    counts = {lsp_id: 0 for lsp_id in target_lsp_ids()}
    for line in log_since(router, offset):
        if "re-originating LSP" not in line:
            continue
        for lsp_id in target_lsp_ids():
            if lsp_id_dotted(lsp_id) in line:
                counts[lsp_id] += 1
    return counts


def run_helper(router, cfg, marker):
    cfg_path = os.path.join(get_topogen().logdir, cfg["name"] + "_input.json")
    with open(cfg_path, "w") as fp:
        json.dump(cfg, fp)
    raw = router.cmd("python3 {} {}".format(HELPER, cfg_path))
    for line in reversed(raw.splitlines()):
        if line.startswith(marker):
            return json.loads(line.split("=", 1)[1])
    raise AssertionError("helper failed: {}".format(raw))


def start_observer(router, cfg):
    cfg_path = os.path.join(get_topogen().logdir, cfg["name"] + "_input.json")
    with open(cfg_path, "w") as fp:
        json.dump(cfg, fp)
    for stale in (cfg["stop_file"], cfg["out_json"]):
        if os.path.exists(stale):
            os.remove(stale)
    router.cmd(
        "cd {logdir} && (nohup python3 {helper} {cfg} > {name}.out 2>&1 &)".format(
            logdir=get_topogen().logdir,
            helper=HELPER,
            cfg=cfg_path,
            name=cfg["name"],
        )
    )


def stop_observer(cfg, timeout=20):
    with open(cfg["stop_file"], "w") as fp:
        fp.write("stop\n")
    deadline = time.monotonic() + timeout
    out_log = os.path.join(get_topogen().logdir, cfg["name"] + ".out")
    while time.monotonic() < deadline:
        try:
            with open(out_log) as fp:
                if "OBS_DONE" in fp.read():
                    return
        except FileNotFoundError:
            pass
        time.sleep(0.5)
    raise AssertionError("observer helper did not finish")


def inject_phase(name, mode, count, iface="r2-eth0", frag=None, pseudo=None, ids=None):
    "Run one bounded injection scenario and return its measurements."
    tgen = get_topogen()
    r1 = tgen.gears[TARGET]
    r2 = tgen.gears[PEER]
    r3 = tgen.gears[OBSERVER]
    base_seqnos = victim_lsp_seqnos(r1)
    log_mark = log_offset(r1)

    observer_cfg = {
        "name": name + "_obs",
        "role": "observer",
        "iface": "r3-eth0",
        "stop_file": os.path.join(tgen.logdir, name + ".stop"),
        "out_json": os.path.join(tgen.logdir, name + "_obs.json"),
        "pcap_path": os.path.join(tgen.logdir, name + "_obs.pcap"),
    }
    start_observer(r3, observer_cfg)
    time.sleep(1)

    base_key = (pseudo or 0, frag or 0)
    inject_cfg = {
        "name": name + "_inj",
        "role": "inject",
        "iface": iface,
        "lsp_id": TARGET_LSP_ID,
        "source_sysid": PEER_SYSID,
        "template_hex": STATE["template_hex"],
        "mode": mode,
        "count": count,
        "base_seq": base_seqnos[base_key],
        "spacing": BURST_SPACING,
        "tail": CAPTURE_TAIL,
        "pcap_path": os.path.join(tgen.logdir, name + "_inj.pcap"),
    }
    if frag is not None:
        inject_cfg["frag"] = frag
    if pseudo is not None:
        inject_cfg["pseudo"] = pseudo
    if ids is not None:
        inject_cfg["ids"] = ids
    window_start = time.time()
    capture = run_helper(r2, inject_cfg, "ISIS_CAPTURE_JSON=")
    window_end = time.time()
    stop_observer(observer_cfg)
    with open(observer_cfg["out_json"]) as fp:
        observer_events = json.load(fp)["events"]
    window_events = [
        event
        for event in observer_events
        if window_start <= event["abs_time"] <= window_end
    ]
    floods_by_id = {
        lsp_id: target_lsp_events(window_events, lsp_id)
        for lsp_id in target_lsp_ids()
    }
    return {
        "base_seq": base_seqnos[(0, 0)],
        "base_seqnos": base_seqnos,
        "capture": capture,
        "floods_by_id": floods_by_id,
        "floods": floods_by_id[TARGET_LSP_ID],
        "reorig_by_id": fightback_log_count_by_id(r1, log_mark),
    }


def expect_lsp_seqno_above(router, id_tuple, seqno):
    "Wait until the victim's LSP identified by id_tuple exceeds seqno."
    def _check():
        try:
            current = victim_lsp_seqnos(router).get(id_tuple)
        except (AssertionError, ValueError, KeyError) as error:
            return "could not read victim seqnos: {}".format(error)
        if current is not None and current > seqno:
            return None
        return "victim LSP {} seqno {} not above forged 0x{:08x}".format(
            id_tuple, current, seqno
        )

    result, diff = topotest.run_and_expect(_check, None, wait=1, count=6)
    assert result, "deferred fight-back did not happen:\n{}".format(diff)


def inject_dual(name, frames, base_seq):
    "Send an ordered frame list over r2's two circuits, capturing on both."
    tgen = get_topogen()
    cfg = {
        "name": name,
        "role": "dual_inject",
        "ifaces": ["r2-eth0", "r2-eth1"],
        "lsp_id": TARGET_LSP_ID,
        "source_sysid": PEER_SYSID,
        "template_hex": STATE["template_hex"],
        "frames": frames,
        "base_seq": base_seq,
        "spacing": 0.3,
        "tail": 2.5,
        "pcap_path": os.path.join(tgen.logdir, name + ".pcap"),
    }
    capture = run_helper(tgen.gears[PEER], cfg, "ISIS_CAPTURE_JSON=")
    return {"capture": capture}


def test_isis_convergence():
    "Wait for the protocol to converge before starting to test"
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    logger.info("waiting for ISIS adjacencies to come up")

    def _check():
        r1 = tgen.gears[TARGET]
        r2 = tgen.gears[PEER]
        r3 = tgen.gears[OBSERVER]
        try:
            if (
                adjacency_up(r1, PEER_IP)
                and adjacency_up(r1, OBSERVER_IP)
                and adjacency_up(r2, TARGET_IP)
                and adjacency_up(r3, TARGET_IP2)
                and adjacency_up(r1, LAN_PEER_IP)
                and adjacency_up(r2, LAN_TARGET_IP)
            ):
                return None
        except Exception as error:
            return "adjacency check failed: {}".format(error)
        return "adjacencies not up yet"

    result, diff = topotest.run_and_expect(_check, None, wait=1, count=90)
    assert result, "ISIS adjacencies did not come up:\n{}".format(diff)


def test_template_capture():
    "Fetch the victim's own LSP as a forging template"
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    logger.info("capturing the victim's own LSP as a template")
    cfg = {
        "name": "template",
        "role": "template",
        "iface": "r2-eth0",
        "lsp_id": TARGET_LSP_ID,
        "source_sysid": PEER_SYSID,
        "timeout": 15,
        "pcap_path": os.path.join(tgen.logdir, "template.pcap"),
    }
    data = run_helper(tgen.gears[PEER], cfg, "TEMPLATE_JSON=")
    assert data["template_hex"] is not None, "could not capture victim LSP template"
    STATE["template_hex"] = data["template_hex"]


def test_invalid_checksum_control():
    "A forged own LSP with a corrupted checksum must be dropped"
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    logger.info("injecting one corrupted-checksum forged own LSP")
    result = inject_phase("invalid", "invalid", 1)
    r1 = tgen.gears[TARGET]
    assert victim_seqno(r1) == result["base_seq"], "corrupted LSP changed the victim seqno"
    assert result["floods"] == [], "corrupted LSP caused floods on the observer link"
    assert result["reorig_by_id"][TARGET_LSP_ID] == 0, "corrupted LSP caused a fight-back"


def test_fightback_single_legal():
    "One genuinely newer forged own LSP causes exactly one prompt fight-back"
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    logger.info("injecting one genuinely newer forged own LSP")
    result = inject_phase("single", "single", 1)
    r1 = tgen.gears[TARGET]
    assert victim_seqno(r1) == result["base_seq"] + 3, "single fight-back did not happen"
    assert result["reorig_by_id"][TARGET_LSP_ID] == 1, (
        "expected exactly one fight-back, got {}".format(result["reorig_by_id"][TARGET_LSP_ID])
    )
    assert len(result["floods"]) >= 1, "fight-back flood did not reach the observer link"
    assert result["floods"][0]["seqno"] == result["base_seq"] + 3, "fight-back flood has wrong seqno"


def test_fightback_burst_rate():
    "A burst of forged newer own LSPs is rate limited by lsp-gen-interval"
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    logger.info("injecting {} forged newer own LSPs".format(BURST_COUNT))
    result = inject_phase("burst", "burst", BURST_COUNT)
    r1 = tgen.gears[TARGET]
    reorig = result["reorig_by_id"][TARGET_LSP_ID]
    assert reorig <= 3, (
        "fight-back not rate limited: {} re-originations for {} injected LSPs "
        "(lsp-gen-interval {}s)".format(reorig, BURST_COUNT, LSP_GEN_INTERVAL)
    )
    assert len(result["floods"]) <= 4, (
        "fight-back floods not rate limited: {} floods for {} injected LSPs "
        "(lsp-gen-interval {}s)".format(len(result["floods"]), BURST_COUNT, LSP_GEN_INTERVAL)
    )
    expect_lsp_seqno_above(r1, (0, 0), result["base_seq"] + 2 * BURST_COUNT)


def test_own_purge_burst_rate():
    "A burst of forged own purges is rate limited by lsp-gen-interval"
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    logger.info("injecting {} forged own purges".format(BURST_COUNT))
    result = inject_phase("purge", "purge", BURST_COUNT)
    r1 = tgen.gears[TARGET]
    reorig = result["reorig_by_id"][TARGET_LSP_ID]
    assert reorig <= 3, (
        "purge fight-back not rate limited: {} re-originations for {} injected "
        "purges (lsp-gen-interval {}s)".format(reorig, BURST_COUNT, LSP_GEN_INTERVAL)
    )
    assert len(result["floods"]) <= 4, (
        "purge fight-back floods not rate limited: {} floods for {} injected "
        "purges (lsp-gen-interval {}s)".format(len(result["floods"]), BURST_COUNT, LSP_GEN_INTERVAL)
    )
    expect_lsp_seqno_above(r1, (0, 0), result["base_seq"] + 2 * BURST_COUNT)


def test_psnp_fightback_rate():
    "A burst of PSNPs reporting a newer own LSP is rate limited"
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    logger.info("injecting {} PSNPs with newer own-LSP entries".format(BURST_COUNT))
    result = inject_phase("psnp", "psnp", BURST_COUNT)
    r1 = tgen.gears[TARGET]
    r2_mac = tgen.gears[PEER].cmd("cat /sys/class/net/r2-eth0/address").strip()
    replies = [
        event
        for event in target_lsp_events(result["capture"]["events"], TARGET_LSP_ID)
        if event["src_mac"] != r2_mac
    ]
    assert len(replies) <= 4, (
        "PSNP-triggered regeneration not rate limited: {} LSP transmissions "
        "for {} injected PSNPs (lsp-gen-interval {}s)".format(
            len(replies), BURST_COUNT, LSP_GEN_INTERVAL
        )
    )
    assert result["reorig_by_id"][TARGET_LSP_ID] <= 3, (
        "PSNP-triggered fight-back not rate limited: {} re-originations "
        "for {} injected PSNPs".format(
            result["reorig_by_id"][TARGET_LSP_ID], BURST_COUNT
        )
    )
    expect_lsp_seqno_above(r1, (0, 0), result["base_seq"] + 2 * BURST_COUNT)


def test_psnp_two_requesters():
    "Two circuits PSNP the same own LSP in one window; each gets the deferred response"
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears[TARGET]
    base_seq = victim_seqno(r1)
    logger.info("two circuits sending ordered PSNPs for the victim's LSP")
    frames = [
        {"iface": "r2-eth0", "kind": "psnp", "seq": base_seq + 2},
        {"iface": "r2-eth1", "kind": "psnp", "seq": base_seq + 4},
        {"iface": "r2-eth0", "kind": "psnp", "seq": base_seq + 6},
        {"iface": "r2-eth1", "kind": "psnp", "seq": base_seq + 8},
    ]
    result = inject_dual("psnp2", frames, base_seq)
    per_circuit_replies = {}
    total_replies = 0
    for iface in ("r2-eth0", "r2-eth1"):
        r2_mac = (
            tgen.gears[PEER]
            .cmd("cat /sys/class/net/{}/address".format(iface))
            .strip()
        )
        replies = [
            event["seqno"]
            for event in target_lsp_events(
                result["capture"]["events"][iface], TARGET_LSP_ID
            )
            if event["src_mac"] != r2_mac
        ]
        per_circuit_replies[iface] = replies
        total_replies += len(replies)
    assert total_replies <= 3, (
        "PSNP-triggered regeneration not rate limited: {} LSP transmissions "
        "to the two requesters for 4 PSNPs (lsp-gen-interval {}s)".format(
            total_replies, LSP_GEN_INTERVAL
        )
    )
    expect_lsp_seqno_above(r1, (0, 0), base_seq + 8)
    after = victim_lsp_seqnos(r1)
    assert after[(0, 0)] == base_seq + 9, (
        "final seqno 0x{:08x} != own forged max + 1 (0x{:08x})".format(
            after[(0, 0)], base_seq + 9
        )
    )
    for iface in ("r2-eth0", "r2-eth1"):
        sent_max = max(
            frame["seq"]
            for frame in result["capture"]["sent"]
            if frame["iface"] == iface
        )
        assert any(seqno > sent_max for seqno in per_circuit_replies[iface]), (
            "requesting circuit {} got no response above its own PSNP seq "
            "0x{:08x} (replies: {})".format(
                iface, sent_max, per_circuit_replies[iface]
            )
        )


def test_flood_unicast_mixed():
    "A PSNP request in the same window does not downgrade a pending flood fight-back"
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears[TARGET]
    r3 = tgen.gears[OBSERVER]
    base_seq = victim_seqno(r1)
    logger.info("forged LSPs on one circuit plus PSNPs on another in one window")
    frames = [
        {"iface": "r2-eth0", "kind": "lsp", "seq": base_seq + 2},
        {"iface": "r2-eth1", "kind": "psnp", "seq": base_seq + 4},
        {"iface": "r2-eth0", "kind": "lsp", "seq": base_seq + 6},
        {"iface": "r2-eth1", "kind": "psnp", "seq": base_seq + 8},
    ]
    observer_cfg = {
        "name": "mixed_obs",
        "role": "observer",
        "iface": "r3-eth0",
        "stop_file": os.path.join(tgen.logdir, "mixed.stop"),
        "out_json": os.path.join(tgen.logdir, "mixed_obs.json"),
        "pcap_path": os.path.join(tgen.logdir, "mixed_obs.pcap"),
    }
    start_observer(r3, observer_cfg)
    time.sleep(1)
    window_start = time.time()
    result = inject_dual("mixed", frames, base_seq)
    window_end = time.time()
    stop_observer(observer_cfg)

    r2_mac_eth1 = (
        tgen.gears[PEER].cmd("cat /sys/class/net/r2-eth1/address").strip()
    )
    eth1_replies = [
        event["seqno"]
        for event in target_lsp_events(
            result["capture"]["events"]["r2-eth1"], TARGET_LSP_ID
        )
        if event["src_mac"] != r2_mac_eth1
    ]
    assert len(eth1_replies) <= 3, (
        "mixed-triggered regeneration not rate limited: {} LSP transmissions "
        "on the PSNP circuit for 4 inputs (lsp-gen-interval {}s)".format(
            len(eth1_replies), LSP_GEN_INTERVAL
        )
    )
    expect_lsp_seqno_above(r1, (0, 0), base_seq + 8)
    after = victim_lsp_seqnos(r1)
    assert after[(0, 0)] == base_seq + 9, (
        "final seqno 0x{:08x} != own forged max + 1 (0x{:08x})".format(
            after[(0, 0)], base_seq + 9
        )
    )
    with open(observer_cfg["out_json"]) as fp:
        observer_events = json.load(fp)["events"]
    window_events = [
        event
        for event in observer_events
        if window_start <= event["abs_time"] <= window_end
    ]
    observer_seqnos = [
        event["seqno"] for event in target_lsp_events(window_events, TARGET_LSP_ID)
    ]
    assert base_seq + 9 in observer_seqnos, (
        "deferred fight-back was downgraded to unicast: observer link saw "
        "{} instead of a flood at 0x{:08x}".format(observer_seqnos, base_seq + 9)
    )


def test_fragments_present():
    "The victim originates non-zero LSP fragments and a pseudonode LSP (precondition)"
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    logger.info("waiting for the victim to originate LSP fragments")
    r1 = tgen.gears[TARGET]

    def _check():
        try:
            seqnos = victim_lsp_seqnos(r1)
        except (AssertionError, ValueError, KeyError) as error:
            return "could not read victim seqnos: {}".format(error)
        missing = {(0, 0), (0, 1), (0, 2)} - set(seqnos)
        if missing:
            return "missing own fragments: {}".format(sorted(missing))
        if not any(key[0] != 0 for key in seqnos):
            return "pseudonode LSP not originated yet"
        return None

    result, diff = topotest.run_and_expect(_check, None, wait=1, count=30)
    assert result, "victim did not originate fragments 0-2:\n{}".format(diff)

    # The pseudonode LSP's pseudonode byte is the DIS circuit ID (not
    # necessarily 1), so discover it instead of hardcoding.
    seqnos = victim_lsp_seqnos(r1)
    pseudo_keys = [key for key in seqnos if key[0] != 0 and key[1] == 0]
    assert len(pseudo_keys) == 1, "expected exactly one pseudonode LSP, got {}".format(
        sorted(pseudo_keys)
    )
    STATE["pseudo_lsp_id"] = "000000000001{:02x}{:02x}".format(*pseudo_keys[0])


def test_fightback_fragment_rate():
    "Forged newer copies of own fragment 1 only drive fragment 1, rate limited"
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    logger.info("injecting {} forged newer own fragment-1 LSPs".format(BURST_COUNT))
    result = inject_phase("fragburst", "frag_burst", BURST_COUNT, frag=1)
    r1 = tgen.gears[TARGET]
    base1 = result["base_seqnos"][(0, 1)]
    frag1_floods = result["floods_by_id"][TARGET_FRAG1_LSP_ID]
    assert result["reorig_by_id"][TARGET_FRAG1_LSP_ID] <= 3, (
        "fragment fight-back not rate limited: {} re-originations for {} "
        "injected LSPs (lsp-gen-interval {}s)".format(
            result["reorig_by_id"][TARGET_FRAG1_LSP_ID], BURST_COUNT, LSP_GEN_INTERVAL
        )
    )
    assert len(frag1_floods) <= 4, (
        "fragment fight-back floods not rate limited: {} floods for {} "
        "injected LSPs".format(len(frag1_floods), BURST_COUNT)
    )
    expect_lsp_seqno_above(r1, (0, 1), base1 + 2 * BURST_COUNT)
    after = victim_lsp_seqnos(r1)
    assert after[(0, 1)] <= base1 + 2 * BURST_COUNT + 1, (
        "fragment 1 seqno 0x{:08x} exceeds its own forged max + 1 (0x{:08x}); "
        "sequence numbers leaked from another LSP".format(
            after[(0, 1)], base1 + 2 * BURST_COUNT + 1
        )
    )
    assert after[(0, 0)] == result["base_seqnos"][(0, 0)], (
        "fragment-1 trigger modified fragment 0"
    )
    assert after[(0, 2)] == result["base_seqnos"][(0, 2)], (
        "fragment-1 trigger modified fragment 2"
    )


def test_multi_id_same_window():
    "Fragments 0 and 1 attacked in one window each end above their own forged seqno"
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    logger.info(
        "injecting {}+{} forged LSPs for fragments 0 and 1 in one window".format(
            MULTI_ID_PER_LSP, MULTI_ID_PER_LSP
        )
    )
    r1 = tgen.gears[TARGET]
    seqnos = victim_lsp_seqnos(r1)
    ids = [
        {"lsp_id": TARGET_LSP_ID, "base_seq": seqnos[(0, 0)]},
        {
            "lsp_id": TARGET_FRAG1_LSP_ID,
            "base_seq": seqnos[(0, 1)] + MULTI_ID_FRAG_B_OFFSET,
        },
    ]
    result = inject_phase("multiid", "multi_id", MULTI_ID_PER_LSP, ids=ids)
    forged_max0 = ids[0]["base_seq"] + 2 * MULTI_ID_PER_LSP
    forged_max1 = ids[1]["base_seq"] + 2 * MULTI_ID_PER_LSP
    total_reorig = sum(result["reorig_by_id"].values())
    assert total_reorig <= 4, (
        "multi-ID fight-back not rate limited: {} re-originations for {} "
        "injected LSPs (lsp-gen-interval {}s)".format(
            total_reorig, 2 * MULTI_ID_PER_LSP, LSP_GEN_INTERVAL
        )
    )
    expect_lsp_seqno_above(r1, (0, 0), forged_max0)
    expect_lsp_seqno_above(r1, (0, 1), forged_max1)
    after = victim_lsp_seqnos(r1)
    assert forged_max0 < after[(0, 0)] <= forged_max0 + 1, (
        "fragment 0 seqno 0x{:08x} not in (0x{:08x}, 0x{:08x}]; sequence "
        "numbers leaked from another LSP".format(
            after[(0, 0)], forged_max0, forged_max0 + 1
        )
    )
    assert forged_max1 < after[(0, 1)] <= forged_max1 + 1, (
        "fragment 1 seqno 0x{:08x} not in (0x{:08x}, 0x{:08x}]; sequence "
        "numbers leaked from another LSP".format(
            after[(0, 1)], forged_max1, forged_max1 + 1
        )
    )
    assert after[(0, 2)] == result["base_seqnos"][(0, 2)], (
        "multi-ID triggers modified fragment 2"
    )


def test_pseudonode_fightback_rate():
    "Forged newer copies of the victim's pseudonode LSP only drive it, rate limited"
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    logger.info("waiting for the victim's pseudonode LSP (r1 must be DIS)")
    r1 = tgen.gears[TARGET]

    def _check():
        try:
            if any(key[0] != 0 for key in victim_lsp_seqnos(r1)):
                return None
        except (AssertionError, ValueError, KeyError) as error:
            return "could not read victim seqnos: {}".format(error)
        return "pseudonode LSP not originated yet"

    result, diff = topotest.run_and_expect(_check, None, wait=1, count=30)
    assert result, "victim did not originate a pseudonode LSP:\n{}".format(diff)
    pseudo_lsp_id = STATE.get("pseudo_lsp_id")
    assert pseudo_lsp_id is not None, "pseudonode LSP id not discovered"
    pseudo_key = lsp_id_tuple(pseudo_lsp_id)
    pseudo_byte = pseudo_key[0]

    logger.info(
        "injecting {} forged newer pseudonode LSPs (pseudo=0x{:02x})".format(
            BURST_COUNT, pseudo_byte
        )
    )
    result = inject_phase(
        "pseudo", "pseudo_burst", BURST_COUNT, iface="r2-eth1", pseudo=pseudo_byte
    )
    base_pseudo = result["base_seqnos"][pseudo_key]
    assert result["reorig_by_id"][pseudo_lsp_id] <= 3, (
        "pseudonode fight-back not rate limited: {} re-originations for {} "
        "injected LSPs (lsp-gen-interval {}s)".format(
            result["reorig_by_id"][pseudo_lsp_id], BURST_COUNT, LSP_GEN_INTERVAL
        )
    )
    expect_lsp_seqno_above(r1, pseudo_key, base_pseudo + 2 * BURST_COUNT)
    after = victim_lsp_seqnos(r1)
    assert after[pseudo_key] <= base_pseudo + 2 * BURST_COUNT + 1, (
        "pseudonode seqno 0x{:08x} exceeds its own forged max + 1 (0x{:08x}); "
        "sequence numbers leaked from another LSP".format(
            after[pseudo_key], base_pseudo + 2 * BURST_COUNT + 1
        )
    )
    assert after[(0, 0)] == result["base_seqnos"][(0, 0)], (
        "pseudonode trigger modified fragment 0"
    )


def test_stability_after_stop():
    "After the injection stops, the seqno and adjacencies stay stable"
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    logger.info("checking stability after the injection stopped")
    r1 = tgen.gears[TARGET]
    time.sleep(2 * LSP_GEN_INTERVAL + 1)
    before = victim_seqno(r1)
    time.sleep(2)
    assert victim_seqno(r1) == before, "seqno moved after injection stopped"
    assert adjacency_up(r1, PEER_IP), "adjacency to r2 went down"
    assert adjacency_up(r1, OBSERVER_IP), "adjacency to r3 went down"


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
