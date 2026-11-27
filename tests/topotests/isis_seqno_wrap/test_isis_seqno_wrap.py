#!/usr/bin/env python
# SPDX-License-Identifier: ISC
#
# test_isis_seqno_wrap.py
# Part of NetDEF Topology Tests
#
# Copyright (c) 2026 by Bing Shui <bingshui@smail.nju.edu.cn>
#

"""
test_isis_seqno_wrap.py:

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
               |eth2               |eth1
               |  10.213.14.0/24   |
               +----[ s1 LAN ]-----+
               r1 (DIS, priority 100), r2 (priority 10)

r1-r2 and r1-r3 links are point-to-point; the r1-r2 link is duplicated by
a broadcast LAN on switch s1 where r1 is the DIS.  All routers are
level-2-only, area 49.0001.  r1 advertises a loopback /32 and runs with
max-lsp-lifetime 350 (the YANG floor is refresh-interval + 300, so the
refresh interval is 50s), which bounds the ISO 10589 7.3.16.1
re-origination wait to 350 + 60s.

An on-link attacker forges copies of the victim's own LSP with sequence
number 0xFFFFFFFF (SequenceModulus - 1).  ISO 10589 7.3.16.1 requires the
victim to generate attemptToExceedMaximumSequenceNumber and to not
increase its sequence number past SequenceModulus - 1; instead the LSP
must be purged and re-originated with sequence number 1 after
MaxAge + ZeroAgeLifetime.  lsp_inc_seqno() used to assign the wrapped 0
and flood it with a non-zero remaining lifetime; 0 is reserved to be
less than any generated LSP (7.3.16.1), so every later comparison loses
and the attacker can drive one wrapped flood per injected PDU, forever.

The same attack is driven against the victim's pseudonode LSP on the
LAN.  The exhaustion wait is tracked per LSP (fragment 0 of the own LSP
chain vs. the pseudonode LSP of a circuit), so neither wait may block
the other LSP's normal refresh.

The test drives the wrap with bounded traffic (<=4 PDUs per scenario,
<=5 PDU/s) over three trigger paths (newer own LSP, PSNP entry) and
checks:
  - a corrupted-checksum forgery is dropped (control);
  - a normal newer forgery and a normal forged purge each still cause
    exactly one legal fight-back (protocol-required behaviour);
  - a MaxSeq forgery causes one purge (seqno 0xFFFFFFFF, lifetime 0),
    never a seqno-0 LSP with non-zero lifetime, for the fragment 0 LSP
    and for the pseudonode LSP alike;
  - the pseudonode wait does not block the fragment 0 chain's legal
    fight-back, and the fragment 0 wait does not block the pseudonode
    refresh;
  - repeated MaxSeq forgeries only get the stored purge re-sent;
  - a MaxSeq PSNP entry also only purges;
  - while the pseudonode LSP waits, neither the periodic refresh nor a
    LAN adjacency Down/Up churn resurrects it;
  - after max-lsp-lifetime + ZeroAgeLifetime both LSPs are
    re-originated with sequence number 1 and the observer route to the
    victim loopback returns;
  - with the two LSPs exhausted at staggered times, each is only
    re-originated with sequence number 1 at its own boundary: at the
    fragment 0 boundary the pseudonode LSP is still purged, and it
    only comes back at its own, later boundary;
  - adjacencies stay up throughout.
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
PEER_SYSID = "000000000002"
PEER_IP = "10.213.12.2"
OBSERVER_IP = "10.213.13.3"
TARGET_IP = "10.213.12.1"
TARGET_IP2 = "10.213.13.1"
PEER_LAN_IP = "10.213.14.2"
TARGET_LAN_IP = "10.213.14.1"
VICTIM_LOOPBACK = "10.99.0.1/32"
HELPER = os.path.join(CWD, "isis_seqno_wrap_helper.py")

MAX_SEQ = 0xFFFFFFFF
FORGED_LIFETIME = 300
BURST_COUNT = 4
BURST_SPACING = 0.2
CAPTURE_TAIL = 1.5
MAX_LSP_LIFETIME = 350
ZERO_AGE_LIFETIME = 60
# Poll the re-origination starting a bit after MaxAge + ZeroAgeLifetime.
RESTART_WAIT = MAX_LSP_LIFETIME + ZERO_AGE_LIFETIME + 15
RESTART_POLL = 60
# The pseudonode wait window must cross at least one 50s periodic
# refresh boundary.
PSEUDO_WAIT_SECONDS = 75
# Staggered exhaustion: the two objects are exhausted this far apart,
# so their MaxAge + ZeroAgeLifetime boundaries are distinguishable.
STAGGER_DELTA = 90

STATE = {
    "template_hex": None,
    "pseudo_template_hex": None,
    "pseudo_key": None,
    "pseudo_id": None,
    "pseudo_purge_time": None,
}


def lsp_id_dotted(lsp_id_hex):
    "Hex LSP ID -> the dotted form used in isisd log lines (%pLS)."
    return "{}.{}-{}".format(
        ".".join(lsp_id_hex[i:i + 4] for i in range(0, 12, 4)),
        lsp_id_hex[12:14],
        lsp_id_hex[14:16],
    )


def build_topo(tgen):
    "Build function"
    r1 = tgen.add_router(TARGET)
    r2 = tgen.add_router(PEER)
    r3 = tgen.add_router(OBSERVER)
    sw = tgen.add_switch("s1")
    tgen.add_link(r1, r2)
    tgen.add_link(r1, r3)
    # Broadcast LAN between r1 and r2; r1 (priority 100) is the DIS and
    # originates the pseudonode LSP under test.
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


def own_lsp_entries(router):
    "Map (pseudonode, fragment) -> (seqno, remaining lifetime) for own LSPs."
    data = json.loads(router.vtysh_cmd("show isis database json"))
    found = {}

    def parse_holdtime(value):
        # A purged LSP prints its age_out as a string "(...)"; a live LSP
        # prints the remaining lifetime as an integer.
        hold = value.get("holdtime")
        if isinstance(hold, str):
            return 0
        return int(hold)

    def walk(value):
        if isinstance(value, dict):
            lsp = value.get("lsp")
            if isinstance(lsp, dict) and lsp.get("ownLSP") is True and "seqNumber" in value:
                id_str = lsp["id"]
                # The id always ends with ".PP-FF" (pseudonode, fragment),
                # whether the sysid part is a dynamic hostname or dotted hex.
                found[(int(id_str[-5:-3], 16), int(id_str[-2:], 16))] = (
                    int(value["seqNumber"], 16),
                    parse_holdtime(value),
                )
            for child in value.values():
                walk(child)
        elif isinstance(value, list):
            for child in value:
                walk(child)

    walk(data)
    return found


def victim_lsp_entry(router):
    "The victim's own fragment-0 LSP: (seqno, remaining lifetime)."
    found = own_lsp_entries(router)
    assert (0, 0) in found, "no own fragment-0 LSP in database json"
    return found[(0, 0)]


def pseudo_lsp_entry(router):
    "The victim's own pseudonode LSP: ((pseudo, fragment), (seqno, lifetime))."
    found = own_lsp_entries(router)
    pseudos = {key: value for key, value in found.items() if key[0] != 0}
    assert len(pseudos) == 1, "expected exactly one own pseudonode LSP: {}".format(
        pseudos
    )
    key = next(iter(pseudos))
    return key, pseudos[key]


def victim_seqno(router):
    "Sequence number of the victim's own fragment-0 LSP."
    return victim_lsp_entry(router)[0]


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


def observer_has_loopback_route(router):
    return VICTIM_LOOPBACK in router.vtysh_cmd("show isis route")


def target_lsp_events(events, lspid_hex):
    return [
        event
        for event in events
        if event.get("pdutype") in (18, 20) and event.get("lspid") == lspid_hex
    ]


def wrapped_zero_floods(events, lspid=TARGET_LSP_ID):
    "LSP PDUs carrying the anomalous seqno-0 / lifetime>0."
    return [
        event
        for event in target_lsp_events(events, lspid)
        if event["seqno"] == 0 and event["lifetime"] != 0
    ]


def purge_floods(events, lspid=TARGET_LSP_ID):
    "Purge PDUs (seqno 0xFFFFFFFF, lifetime 0)."
    return [
        event
        for event in target_lsp_events(events, lspid)
        if event["seqno"] == MAX_SEQ and event["lifetime"] == 0
    ]


def live_floods(events, lspid=TARGET_LSP_ID):
    "LSP PDUs with a non-zero remaining lifetime (any seqno)."
    return [
        event
        for event in target_lsp_events(events, lspid)
        if event["lifetime"] != 0
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


def inject_phase(name, mode, count=1, pseudo=False, tail=CAPTURE_TAIL):
    "Run one bounded injection scenario and return its measurements."
    tgen = get_topogen()
    r1 = tgen.gears[TARGET]
    r2 = tgen.gears[PEER]
    r3 = tgen.gears[OBSERVER]
    base_seq = victim_seqno(r1)
    log_mark = log_offset(r1)

    if pseudo:
        iface = "r2-eth1"
        lsp_id = STATE["pseudo_id"]
        template_hex = STATE["pseudo_template_hex"]
        victim_mac_inject = r1.cmd("cat /sys/class/net/r1-eth2/address").strip()
    else:
        iface = "r2-eth0"
        lsp_id = TARGET_LSP_ID
        template_hex = STATE["template_hex"]
        victim_mac_inject = r1.cmd("cat /sys/class/net/r1-eth0/address").strip()
    # Floods forwarded by r1 towards the observer always leave from r1-eth0.
    victim_mac_observer = r1.cmd("cat /sys/class/net/r1-eth0/address").strip()

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

    inject_cfg = {
        "name": name + "_inj",
        "role": "inject",
        "iface": iface,
        "lsp_id": lsp_id,
        "source_sysid": PEER_SYSID,
        "template_hex": template_hex,
        "mode": mode,
        "count": count,
        "base_seq": base_seq,
        "lifetime": FORGED_LIFETIME,
        "spacing": BURST_SPACING,
        "tail": tail,
        "pcap_path": os.path.join(tgen.logdir, name + "_inj.pcap"),
    }
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
    lines = log_since(r1, log_mark)
    return {
        "base_seq": base_seq,
        "capture": capture,
        "observer_events": window_events,
        "inject_events": capture["events"],
        "wrapped_zero_observer": [
            event
            for event in wrapped_zero_floods(window_events, lsp_id)
            if event["src_mac"] == victim_mac_observer
        ],
        "wrapped_zero_inject": [
            event
            for event in wrapped_zero_floods(capture["events"], lsp_id)
            if event["src_mac"] == victim_mac_inject
        ],
        "purge_observer": [
            event
            for event in purge_floods(window_events, lsp_id)
            if event["src_mac"] == victim_mac_observer
        ],
        "purge_inject": [
            event
            for event in purge_floods(capture["events"], lsp_id)
            if event["src_mac"] == victim_mac_inject
        ],
        "live_observer": [
            event
            for event in live_floods(window_events, lsp_id)
            if event["src_mac"] == victim_mac_observer
        ],
        "live_inject": [
            event
            for event in live_floods(capture["events"], lsp_id)
            if event["src_mac"] == victim_mac_inject
        ],
        "target_lsp_observer": target_lsp_events(window_events, lsp_id),
        "reorig_zero_log_count": sum(
            "re-originating LSP" in line and "0x00000000" in line for line in lines
        ),
        "reorig_log_count": sum("re-originating LSP" in line for line in lines),
        "exhausted_log_count": sum(
            "seqno space exhausted, purging" in line for line in lines
        ),
        "invalid_cksum_log_count": sum(
            "invalid LSP checksum" in line for line in lines
        ),
        "confused_cksum_log_count": sum(
            "with confused checksum received" in line for line in lines
        ),
        "window": [window_start, window_end],
    }


def zero_floods_total(phase):
    return len(phase["wrapped_zero_observer"]) + len(phase["wrapped_zero_inject"])


def purge_floods_total(phase):
    return len(phase["purge_observer"]) + len(phase["purge_inject"])


def live_floods_total(phase):
    return len(phase["live_observer"]) + len(phase["live_inject"])


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
                and adjacency_up(r1, PEER_LAN_IP)
                and adjacency_up(r2, TARGET_IP)
                and adjacency_up(r2, TARGET_LAN_IP)
                and adjacency_up(r3, TARGET_IP2)
                and victim_seqno(r1) > 0
            ):
                return None
        except Exception as error:
            return "adjacency check failed: {}".format(error)
        return "adjacencies not up yet"

    result, diff = topotest.run_and_expect(_check, None, wait=1, count=90)
    assert result, "ISIS adjacencies did not come up:\n{}".format(diff)

    # The observer must reach the victim loopback before the trigger.
    r3 = tgen.gears[OBSERVER]

    def _route():
        if observer_has_loopback_route(r3):
            return None
        return "observer has no route to {}".format(VICTIM_LOOPBACK)

    result, diff = topotest.run_and_expect(_route, None, wait=1, count=30)
    assert result, "observer route to the victim loopback missing:\n{}".format(diff)


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


def test_pseudo_template_capture():
    "Fetch the victim's pseudonode LSP as a forging template"
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    logger.info("capturing the victim's pseudonode LSP as a template")
    r1 = tgen.gears[TARGET]

    def _discover():
        try:
            key, _entry = pseudo_lsp_entry(r1)
        except AssertionError as error:
            return "pseudonode LSP not found: {}".format(error)
        STATE["pseudo_key"] = key
        STATE["pseudo_id"] = "{}{:02x}00".format(TARGET_LSP_ID[:12], key[0])
        return None

    result, diff = topotest.run_and_expect(_discover, None, wait=1, count=30)
    assert result, "victim pseudonode LSP did not appear:\n{}".format(diff)

    cfg = {
        "name": "pseudo_template",
        "role": "template",
        "iface": "r2-eth1",
        "lsp_id": STATE["pseudo_id"],
        "source_sysid": PEER_SYSID,
        "timeout": 15,
        "pcap_path": os.path.join(tgen.logdir, "pseudo_template.pcap"),
    }
    data = run_helper(tgen.gears[PEER], cfg, "TEMPLATE_JSON=")
    assert data["template_hex"] is not None, (
        "could not capture victim pseudonode LSP template"
    )
    STATE["pseudo_template_hex"] = data["template_hex"]


def test_invalid_checksum_control():
    "A forged own LSP with a corrupted checksum must be dropped"
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    logger.info("injecting one corrupted-checksum forged own LSP at MaxSeq")
    result = inject_phase("invalid", "invalid")
    r1 = tgen.gears[TARGET]
    # A periodic refresh (lsp-refresh-interval 50s) may bump the seqno by
    # one inside the measurement window; anything beyond that is a reaction
    # to the forged PDU.
    assert victim_seqno(r1) in (result["base_seq"], result["base_seq"] + 1), (
        "corrupted LSP changed the victim seqno"
    )
    assert zero_floods_total(result) == 0, "corrupted LSP caused an anomalous flood"
    assert purge_floods_total(result) == 0, "corrupted LSP caused a purge"
    assert result["reorig_log_count"] == 0, "corrupted LSP caused a fight-back"
    assert result["invalid_cksum_log_count"] >= 1, "corrupted LSP not logged"


def test_legal_newer_fightback():
    "One genuinely newer forged own LSP causes exactly one prompt fight-back"
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    logger.info("injecting one genuinely newer forged own LSP")
    result = inject_phase("single", "single")
    r1 = tgen.gears[TARGET]
    assert victim_seqno(r1) == result["base_seq"] + 3, "single fight-back did not happen"
    assert result["reorig_log_count"] == 1, (
        "expected exactly one fight-back, got {}".format(result["reorig_log_count"])
    )
    floods = [event["seqno"] for event in result["target_lsp_observer"]]
    assert result["base_seq"] + 3 in floods, "fight-back flood has wrong seqno: {}".format(floods)
    assert all(event["lifetime"] != 0 for event in result["target_lsp_observer"]), (
        "legal fight-back must not purge"
    )


def test_legal_purge_fightback():
    "One forged own purge with a higher seqno still causes one fight-back"
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    logger.info("injecting one forged own purge with a higher seqno")
    result = inject_phase("purge", "purge")
    r1 = tgen.gears[TARGET]
    assert victim_seqno(r1) == result["base_seq"] + 3, "purge fight-back did not happen"
    assert result["reorig_log_count"] == 1, (
        "expected exactly one fight-back, got {}".format(result["reorig_log_count"])
    )


def test_pseudo_wrap_single():
    "A forged pseudonode LSP at SequenceModulus-1 must purge, never wrap"
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    logger.info("injecting one forged pseudonode LSP with seqno 0xFFFFFFFF")
    result = inject_phase("pseudo_wrap_single", "maxseq_single", pseudo=True)
    r1 = tgen.gears[TARGET]
    r2 = tgen.gears[PEER]
    STATE["pseudo_purge_time"] = result["window"][0]

    assert zero_floods_total(result) == 0, (
        "victim flooded the anomalous seqno-0 pseudonode LSP: {}".format(
            result["wrapped_zero_observer"] + result["wrapped_zero_inject"]
        )
    )
    assert purge_floods_total(result) >= 1, (
        "victim did not purge the exhausted pseudonode LSP: observer {} inject {}".format(
            result["purge_observer"], result["purge_inject"]
        )
    )
    _key, (seqno, lifetime) = pseudo_lsp_entry(r1)
    assert seqno == MAX_SEQ and lifetime == 0, (
        "victim pseudonode LSP is (0x{:08x}, {}), expected the purge (0xffffffff, 0)".format(
            seqno, lifetime
        )
    )
    assert result["exhausted_log_count"] >= 1, "exhaustion purge not logged"
    assert result["reorig_zero_log_count"] == 0, "victim re-originated at seqno 0"

    # The pseudonode wait must not block the fragment 0 chain: a legal
    # newer forgery still drives exactly one prompt fight-back.
    logger.info("checking fragment 0 fight-back during the pseudonode wait")
    fightback = inject_phase("pseudo_independence", "single")
    assert victim_seqno(r1) == fightback["base_seq"] + 3, (
        "fragment 0 fight-back did not happen during the pseudonode wait"
    )
    assert fightback["reorig_log_count"] == 1, (
        "expected exactly one fight-back, got {}".format(fightback["reorig_log_count"])
    )
    _key, (seqno, lifetime) = pseudo_lsp_entry(r1)
    assert seqno == MAX_SEQ and lifetime == 0, (
        "fragment 0 fight-back disturbed the pseudonode purge: (0x{:08x}, {})".format(
            seqno, lifetime
        )
    )
    assert adjacency_up(r1, PEER_IP) and adjacency_up(r1, OBSERVER_IP), (
        "adjacency went down after the purge"
    )
    assert adjacency_up(r1, PEER_LAN_IP) and adjacency_up(r2, TARGET_LAN_IP), (
        "LAN adjacency went down after the purge"
    )


def test_seqno_wrap_single():
    "A forged own LSP at SequenceModulus-1 must purge, never wrap to 0"
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    logger.info("injecting one forged own LSP with seqno 0xFFFFFFFF")
    result = inject_phase("wrap_single", "maxseq_single")
    r1 = tgen.gears[TARGET]

    assert zero_floods_total(result) == 0, (
        "victim flooded the anomalous seqno-0 LSP: {}".format(
            result["wrapped_zero_observer"] + result["wrapped_zero_inject"]
        )
    )
    assert purge_floods_total(result) >= 1, (
        "victim did not purge the exhausted LSP: observer {} inject {}".format(
            result["purge_observer"], result["purge_inject"]
        )
    )
    seqno, lifetime = victim_lsp_entry(r1)
    assert seqno == MAX_SEQ and lifetime == 0, (
        "victim LSP is (0x{:08x}, {}), expected the purge (0xffffffff, 0)".format(
            seqno, lifetime
        )
    )
    assert result["exhausted_log_count"] >= 1, "exhaustion purge not logged"
    assert result["reorig_zero_log_count"] == 0, "victim re-originated at seqno 0"
    assert adjacency_up(r1, PEER_IP) and adjacency_up(r1, OBSERVER_IP), (
        "adjacency went down after the purge"
    )


def test_seqno_wrap_loop():
    "Repeated MaxSeq forgeries never produce a seqno-0 flood"
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    logger.info("injecting {} forged own LSPs with seqno 0xFFFFFFFF".format(BURST_COUNT))
    result = inject_phase("wrap_loop", "maxseq_burst", count=BURST_COUNT)
    r1 = tgen.gears[TARGET]
    assert zero_floods_total(result) == 0, (
        "victim flooded the anomalous seqno-0 LSP {} times".format(
            zero_floods_total(result)
        )
    )
    assert result["reorig_zero_log_count"] == 0, "victim re-originated at seqno 0"
    # With the purge stored, a repeated MaxSeq content copy carries the
    # same seqno but a different checksum, so 7.3.16.2 handles it as an
    # LSP confusion: it is neutralised without any reflood.  The confusion
    # log lines prove every injected PDU was processed.
    assert result["confused_cksum_log_count"] >= BURST_COUNT, (
        "repeated MaxSeq forgeries were not processed as confusion: {} logs".format(
            result["confused_cksum_log_count"]
        )
    )
    seqno, lifetime = victim_lsp_entry(r1)
    assert seqno == MAX_SEQ and lifetime == 0, (
        "victim LSP is (0x{:08x}, {}), expected the purge (0xffffffff, 0)".format(
            seqno, lifetime
        )
    )


def test_psnp_wrap():
    "A PSNP reporting the own LSP at SequenceModulus-1 also only purges"
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    logger.info("injecting one PSNP with a MaxSeq own-LSP entry")
    result = inject_phase("psnp_wrap", "psnp_max")
    r1 = tgen.gears[TARGET]
    assert zero_floods_total(result) == 0, (
        "victim answered the PSNP with the anomalous seqno-0 LSP: {}".format(
            result["wrapped_zero_inject"]
        )
    )
    assert purge_floods_total(result) >= 1, "PSNP did not drive the exhaustion purge"
    seqno, lifetime = victim_lsp_entry(r1)
    assert seqno == MAX_SEQ and lifetime == 0, (
        "victim LSP is (0x{:08x}, {}), expected the purge (0xffffffff, 0)".format(
            seqno, lifetime
        )
    )


def test_pseudo_wait_refresh():
    "The periodic refresh must not resurrect the exhausted pseudonode LSP"
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    logger.info(
        "re-injecting a forged MaxSeq pseudonode LSP and waiting %ds "
        "across the refresh boundary",
        PSEUDO_WAIT_SECONDS,
    )
    result = inject_phase(
        "pseudo_wait_refresh", "maxseq_single", pseudo=True,
        tail=PSEUDO_WAIT_SECONDS,
    )
    r1 = tgen.gears[TARGET]
    assert zero_floods_total(result) == 0, (
        "victim flooded the anomalous seqno-0 pseudonode LSP: {}".format(
            result["wrapped_zero_observer"] + result["wrapped_zero_inject"]
        )
    )
    assert live_floods_total(result) == 0, (
        "periodic refresh resurrected the exhausted pseudonode LSP: {}".format(
            result["live_observer"] + result["live_inject"]
        )
    )
    _key, (seqno, lifetime) = pseudo_lsp_entry(r1)
    assert seqno == MAX_SEQ and lifetime == 0, (
        "victim pseudonode LSP is (0x{:08x}, {}), expected the purge (0xffffffff, 0)".format(
            seqno, lifetime
        )
    )


def test_pseudo_adj_churn():
    "LAN adjacency Down/Up churn must not resurrect the exhausted pseudonode LSP"
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears[TARGET]
    r2 = tgen.gears[PEER]
    assert STATE.get("pseudo_id"), "pseudo template not captured"

    churn_cfg = {
        "name": "pseudo_churn_obs",
        "role": "observer",
        "iface": "r2-eth1",
        "stop_file": os.path.join(tgen.logdir, "pseudo_churn.stop"),
        "out_json": os.path.join(tgen.logdir, "pseudo_churn_obs.json"),
        "pcap_path": os.path.join(tgen.logdir, "pseudo_churn_obs.pcap"),
    }
    start_observer(r2, churn_cfg)
    time.sleep(1)
    r2.cmd(
        "vtysh -c 'configure terminal' -c 'interface r2-eth1' "
        "-c 'no ip router isis WRAP' -c 'end'"
    )

    def _down():
        if not adjacency_up(r1, PEER_LAN_IP):
            return None
        return "LAN adjacency still up"

    result, diff = topotest.run_and_expect(_down, None, wait=1, count=60)
    assert result, "LAN adjacency did not go down:\n{}".format(diff)
    r2.cmd(
        "vtysh -c 'configure terminal' -c 'interface r2-eth1' "
        "-c 'ip router isis WRAP' -c 'end'"
    )

    def _up():
        if adjacency_up(r1, PEER_LAN_IP):
            return None
        return "LAN adjacency still down"

    result, diff = topotest.run_and_expect(_up, None, wait=1, count=60)
    assert result, "LAN adjacency did not come back:\n{}".format(diff)
    # Let the throttled adjacency-triggered pseudonode regeneration fire.
    time.sleep(10)
    stop_observer(churn_cfg)
    with open(churn_cfg["out_json"]) as fp:
        events = json.load(fp)["events"]
    pseudo_id = STATE["pseudo_id"]
    victim_lan_mac = r1.cmd("cat /sys/class/net/r1-eth2/address").strip()
    zero = [
        event
        for event in wrapped_zero_floods(events, pseudo_id)
        if event["src_mac"] == victim_lan_mac
    ]
    live = [
        event
        for event in live_floods(events, pseudo_id)
        if event["src_mac"] == victim_lan_mac
    ]
    assert not zero, "churn resurrected the pseudonode LSP at seqno 0: {}".format(zero)
    assert not live, "churn resurrected the pseudonode LSP: {}".format(live)
    _key, (seqno, lifetime) = pseudo_lsp_entry(r1)
    assert seqno == MAX_SEQ and lifetime == 0, (
        "victim pseudonode LSP is (0x{:08x}, {}), expected the purge (0xffffffff, 0)".format(
            seqno, lifetime
        )
    )
def test_restart_after_wait():
    "After MaxAge + ZeroAgeLifetime both exhausted LSPs restart at seqno 1"
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears[TARGET]
    r3 = tgen.gears[OBSERVER]
    pseudo_purge_time = STATE.get("pseudo_purge_time")
    assert pseudo_purge_time is not None, "pseudo wrap scenario did not run"

    observer_cfg = {
        "name": "restart_obs",
        "role": "observer",
        "iface": "r3-eth0",
        "stop_file": os.path.join(tgen.logdir, "restart.stop"),
        "out_json": os.path.join(tgen.logdir, "restart_obs.json"),
        "pcap_path": os.path.join(tgen.logdir, "restart_obs.pcap"),
    }
    start_observer(r3, observer_cfg)

    # The restart timer is shared per level and was armed by the first
    # exhaustion (the pseudonode one); the fragment 0 purge followed
    # within seconds, so both purged copies have aged out by the time the
    # timer fires.
    logger.info("waiting for the seqno restart (purge + %ds)", RESTART_WAIT)
    deadline = pseudo_purge_time + RESTART_WAIT
    while time.time() < deadline:
        time.sleep(5)

    def _check():
        try:
            seqno, lifetime = victim_lsp_entry(r1)
        except (AssertionError, ValueError, KeyError) as error:
            return "could not read victim LSP: {}".format(error)
        if seqno <= 2 and lifetime != 0:
            return None
        return "victim LSP is (0x{:08x}, {}), waiting for re-origination".format(
            seqno, lifetime
        )

    result, diff = topotest.run_and_expect(_check, None, wait=2, count=RESTART_POLL // 2)
    assert result, "exhausted LSP was not re-originated with a low seqno:\n{}".format(diff)

    def _check_pseudo():
        try:
            _key, (seqno, lifetime) = pseudo_lsp_entry(r1)
        except (AssertionError, ValueError, KeyError) as error:
            return "could not read victim pseudonode LSP: {}".format(error)
        if seqno <= 2 and lifetime != 0:
            return None
        return "victim pseudonode LSP is (0x{:08x}, {}), waiting for re-origination".format(
            seqno, lifetime
        )

    result, diff = topotest.run_and_expect(
        _check_pseudo, None, wait=2, count=RESTART_POLL // 2
    )
    assert result, "exhausted pseudonode LSP was not re-originated:\n{}".format(diff)

    assert adjacency_up(r1, PEER_LAN_IP) and adjacency_up(
        tgen.gears[PEER], TARGET_LAN_IP
    ), "LAN adjacency down after the restart"

    def _route():
        if observer_has_loopback_route(r3):
            return None
        return "observer has no route to {}".format(VICTIM_LOOPBACK)

    result, diff = topotest.run_and_expect(_route, None, wait=2, count=15)
    assert result, "observer route to the victim loopback did not return:\n{}".format(diff)

    stop_observer(observer_cfg)
    with open(observer_cfg["out_json"]) as fp:
        events = json.load(fp)["events"]
    fresh = [
        event
        for event in target_lsp_events(events, TARGET_LSP_ID)
        if event["seqno"] <= 2 and event["lifetime"] != 0
    ]
    assert fresh, "re-originated LSP not seen on the observer link"
    fresh_pseudo = [
        event
        for event in target_lsp_events(events, STATE["pseudo_id"])
        if event["seqno"] <= 2 and event["lifetime"] != 0
    ]
    assert fresh_pseudo, "re-originated pseudonode LSP not seen on the observer link"


def test_staggered_restart():
    "Staggered exhaustion: each LSP restarts only at its own boundary"
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears[TARGET]
    r2 = tgen.gears[PEER]
    victim_lan_mac = r1.cmd("cat /sys/class/net/r1-eth2/address").strip()

    lan_cfg = {
        "name": "stagger_obs",
        "role": "observer",
        "iface": "r2-eth1",
        "stop_file": os.path.join(tgen.logdir, "stagger.stop"),
        "out_json": os.path.join(tgen.logdir, "stagger_obs.json"),
        "pcap_path": os.path.join(tgen.logdir, "stagger_obs.pcap"),
    }
    start_observer(r2, lan_cfg)
    time.sleep(1)

    def _inject(name, pseudo):
        if pseudo:
            iface = "r2-eth1"
            lsp_id = STATE["pseudo_id"]
            template_hex = STATE["pseudo_template_hex"]
        else:
            iface = "r2-eth0"
            lsp_id = TARGET_LSP_ID
            template_hex = STATE["template_hex"]
        cfg = {
            "name": name,
            "role": "inject",
            "iface": iface,
            "lsp_id": lsp_id,
            "source_sysid": PEER_SYSID,
            "template_hex": template_hex,
            "mode": "maxseq_single",
            "count": 1,
            "base_seq": 0,
            "lifetime": FORGED_LIFETIME,
            "spacing": BURST_SPACING,
            "tail": 2.0,
            "pcap_path": os.path.join(tgen.logdir, name + ".pcap"),
        }
        run_helper(r2, cfg, "ISIS_CAPTURE_JSON=")

    # Exhaust fragment 0 first, the pseudonode LSP STAGGER_DELTA later:
    # their MaxAge + ZeroAgeLifetime boundaries are far apart.
    logger.info("staggered step 1: exhausting fragment 0")
    _inject("stagger_frag", pseudo=False)
    frag_purge_time = time.time()
    time.sleep(STAGGER_DELTA)
    logger.info("staggered step 2: exhausting the pseudonode LSP")
    _inject("stagger_pseudo", pseudo=True)
    pseudo_purge_time = time.time()

    # Boundary 1 (fragment 0): poll for the fragment 0 restart and read
    # the pseudonode LSP at the same moment; a single shared restart
    # timer would have restarted both by now.
    logger.info("waiting for the fragment 0 boundary (purge + %ds)", RESTART_WAIT)
    deadline = frag_purge_time + RESTART_WAIT
    while time.time() < deadline:
        time.sleep(5)

    def _check_frag():
        try:
            seqno, lifetime = victim_lsp_entry(r1)
        except (AssertionError, ValueError, KeyError) as error:
            return "could not read victim LSP: {}".format(error)
        if 1 <= seqno <= 2 and lifetime != 0:
            return None
        return "victim LSP is (0x{:08x}, {}), waiting for re-origination".format(
            seqno, lifetime
        )

    result, diff = topotest.run_and_expect(_check_frag, None, wait=2, count=RESTART_POLL // 2)
    assert result, "fragment 0 was not re-originated at its own boundary:\n{}".format(diff)
    frag_restart_time = time.time()

    _key, (pseudo_seqno, pseudo_lifetime) = pseudo_lsp_entry(r1)
    assert pseudo_seqno == MAX_SEQ and pseudo_lifetime == 0, (
        "pseudonode LSP restarted at the fragment 0 boundary "
        "(0x{:08x}, {}), before its own boundary".format(pseudo_seqno, pseudo_lifetime)
    )
    assert frag_restart_time < pseudo_purge_time + MAX_LSP_LIFETIME + ZERO_AGE_LIFETIME, (
        "fragment 0 boundary observation ran past the pseudonode boundary"
    )

    # Boundary 2 (pseudonode): it may only restart at its own boundary.
    logger.info("waiting for the pseudonode boundary (purge + %ds)", RESTART_WAIT)
    deadline = pseudo_purge_time + RESTART_WAIT
    while time.time() < deadline:
        time.sleep(5)

    def _check_pseudo():
        try:
            _key, (seqno, lifetime) = pseudo_lsp_entry(r1)
        except (AssertionError, ValueError, KeyError) as error:
            return "could not read victim pseudonode LSP: {}".format(error)
        if 1 <= seqno <= 2 and lifetime != 0:
            return None
        return "victim pseudonode LSP is (0x{:08x}, {}), waiting for re-origination".format(
            seqno, lifetime
        )

    result, diff = topotest.run_and_expect(
        _check_pseudo, None, wait=2, count=RESTART_POLL // 2
    )
    assert result, "pseudonode LSP was not re-originated at its own boundary:\n{}".format(diff)

    # Wire evidence: no pseudonode flood with a fresh seqno between the
    # pseudonode purge and its own boundary; the restart itself is on
    # the wire.  Floods before the exhaustion are the routine periodic
    # refresh.
    stop_observer(lan_cfg)
    with open(lan_cfg["out_json"]) as fp:
        events = json.load(fp)["events"]
    pseudo_fresh = [
        event
        for event in target_lsp_events(events, STATE["pseudo_id"])
        if event["src_mac"] == victim_lan_mac
        and event["seqno"] <= 2 and event["lifetime"] != 0
        and event["abs_time"] >= pseudo_purge_time
    ]
    early = [
        event
        for event in pseudo_fresh
        if event["abs_time"]
        < pseudo_purge_time + MAX_LSP_LIFETIME + ZERO_AGE_LIFETIME - 10
    ]
    assert not early, (
        "pseudonode LSP flooded with a fresh seqno before its own boundary: {}".format(
            early
        )
    )
    assert pseudo_fresh, "pseudonode LSP restart not seen on the LAN"


def test_stability_after_stop():
    "After the restart, the seqno and adjacencies stay stable"
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    logger.info("checking stability at the end")
    r1 = tgen.gears[TARGET]
    r2 = tgen.gears[PEER]
    time.sleep(3)
    assert adjacency_up(r1, PEER_IP), "adjacency to r2 went down"
    assert adjacency_up(r1, OBSERVER_IP), "adjacency to r3 went down"
    assert adjacency_up(r1, PEER_LAN_IP), "LAN adjacency to r2 went down"
    assert adjacency_up(r2, TARGET_LAN_IP), "LAN adjacency to r1 went down"
    seqno, lifetime = victim_lsp_entry(r1)
    assert lifetime != 0, "victim LSP is purged at the end"
    _key, (pseudo_seqno, pseudo_lifetime) = pseudo_lsp_entry(r1)
    assert pseudo_lifetime != 0, "victim pseudonode LSP is purged at the end"


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
