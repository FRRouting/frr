#!/usr/bin/env python
# SPDX-License-Identifier: ISC
#
# test_isis_flexalgo_purge_election.py
#
# Copyright (c) 2026
#

"""
test_isis_flexalgo_purge_election.py
====================================

Regression for isisd electing a Flex-Algo Definition (FAD) from an LSP
that is not valid protocol state.

_isis_flex_algo_elected() walks the level-1 LSDB and only checks
lsp->tlvs->router_cap->fads[algorithm]; it never looks at
lsp->hdr.seqno or lsp->hdr.rem_lifetime.  The main SPF explicitly
ignores LSPs with seqno 0 (process_lsp()) and the flex-algo adjacency
parser skips LSPs with seqno 0 or zero remaining lifetime
(spf_adj_list_parse_lsp()), but the FAD election used to count both:

* an LSP with seqno 0 and a valid lifetime is installed into the LSDB
  and flooded, and its FAD won the election although the LSP
  contributes no reachability;
* a zero-lifetime purge keeps its full TLVs in the LSDB for the
  zero-age window (lsp_update_data() copies the received TLVs
  regardless of the lifetime field), so the purged copy kept winning
  the election as well.

A high-priority FAD from such an LSP is therefore elected although the
LSP carries no valid state; when the crafted FAD is unsupported, the
algorithm is driven into the disabled state (isis_run_spf() clears its
SPF tree) once an SPF run is scheduled.

RFC 9350 does not restrict the election to main-SPF-reachable nodes,
so the fix only skips LSPs with zero sequence number or zero remaining
lifetime; algorithm 0 is unaffected (flex_algo_id_valid()).

Topology
--------

    r2 (FAD publisher, injector) ----eth1---- r1 (DUT) ----eth2---- r3 (FAD publisher)

All links are point-to-point, level-1-only, area 49.0001.  r2 and r3
both advertise a FAD for flex-algo 201 with the default priority 128,
so r3 wins the baseline election on the higher system id.  The
injector re-sends crafted L1 LSPs on the r2-r1 link with a locally
administered source MAC; r1 does not check the source MAC on
point-to-point LSP receipt, so the frames take the normal receive
path while the template tracker only accepts genuine floods from r2's
MAC.  Crafted LSPs carry a Router Capability TLV (242) with a FAD
sub-TLV (26) for algorithm 201 with priority 200, which wins the
election whenever the LSP is counted.

Test plan
---------

1. test_adjacency_and_template
     Baseline: adjacencies reach Up, r1 elects r3's FAD, and the
     template tracker captured r2's current L1 LSP from the wire.

2. test_seqno0_lsp_not_elected
     Inject one L1 LSP with seqno 0, lifetime 1200 and a priority-200
     FAD (sysid aa).  r1 installs and floods it (normal receive path),
     but the FAD election must ignore it: r3's FAD stays elected.  The
     unfixed isisd elects aa.

3. test_zero_lifetime_lsp_not_elected
     Inject a valid LSP for sysid aa (seqno 0x10) followed by its
     zero-lifetime purge.  r1 keeps the purged copy in the database
     during the zero-age window (observed as a zero holdtime), but the
     FAD election must ignore it: r3's FAD stays elected.  The unfixed
     isisd keeps electing aa from the purged copy.

4. test_valid_high_prio_fad_wins
     Inject a fully valid LSP for sysid aa (seqno 0x20, lifetime 1200)
     with the priority-200 FAD.  A genuinely valid higher-priority FAD
     must win the election on any version (control).

5. test_unsupported_seqno0_fad_not_elected
     Inject one LSP with seqno 0 and a priority-200 FAD carrying an
     unknown FAD sub-sub-TLV (sysid bb), then a valid newer LSP for
     sysid aa (seqno 0x21) to schedule SPF.  The seqno-0 LSP must stay
     out of the election: aa's valid FAD keeps winning, flex-algo 201
     stays enabled and r1 keeps advertising participation.  The unfixed
     isisd elects the unsupported FAD, reports the algorithm disabled
     and drops the participation from its own LSP once SPF runs.
"""

import json
import os
import re
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
INJECTOR_MAC = "02:00:00:00:00:02"
ATTACKER_A_SYSID = "0000.0000.00aa"
ATTACKER_B_SYSID = "0000.0000.00bb"
OBSERVER_SYSID = "0000.0000.0003"
R1_SYSID = "0000.0000.0001"
ALGO = 201
LEGIT_PRIO = 128
ATTACK_PRIO = 200
INJECT_SPACING = 0.4
SETTLE_S = 2.5
REGEN_S = 8.0

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
# Generic helpers
# ---------------------------------------------------------------------------


def _wait_until(func, timeout_s=5, interval_s=0.25):
    deadline = time.time() + timeout_s
    while time.time() < deadline:
        if func():
            return True
        time.sleep(interval_s)
    return bool(func())


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


# ---------------------------------------------------------------------------
# r1 flex-algo / database helpers
# ---------------------------------------------------------------------------


def _flex_algo_state(router):
    raw = router.vtysh_cmd("show isis flex-algo")
    block = None
    for chunk in raw.replace("\r\n", "\n").split("Area "):
        lines = chunk.splitlines()
        if lines and "Algorithm %d" % ALGO in lines[0]:
            block = chunk
            break
    if block is None:
        raise RuntimeError("flex-algo %d block not found: %s" % (ALGO, raw))
    m = re.search(r"Source: (Not found|[0-9a-fA-F.]+)", block)
    source = None if m is None or m.group(1) == "Not found" else m.group(1)
    m = re.search(r"Priority: (\d+)", block)
    priority = int(m.group(1)) if m else None
    m = re.search(r"Local state: (\S+)", block)
    local_state = m.group(1) if m else None
    return {"source": source, "priority": priority, "local_state": local_state}


def _wait_flex_algo(router, source, priority=None, local_state=None, timeout_s=30):
    def check():
        state = _flex_algo_state(router)
        if state["source"] != source:
            return False
        if priority is not None and state["priority"] != priority:
            return False
        if local_state is not None and state["local_state"] != local_state:
            return False
        return True

    return _wait_until(check, timeout_s=timeout_s)


def _find_lsp(value, sysid):
    needle = sysid.replace(".", "")
    if isinstance(value, dict):
        lsp = value.get("lsp")
        if isinstance(lsp, dict) and needle in str(lsp.get("id", "")).replace(".", ""):
            return value
        for child in value.values():
            found = _find_lsp(child, sysid)
            if found is not None:
                return found
    elif isinstance(value, list):
        for child in value:
            found = _find_lsp(child, sysid)
            if found is not None:
                return found
    return None


def _lsp_state(router, sysid):
    data = json.loads(router.vtysh_cmd("show isis database json"))
    lsp = _find_lsp(data, sysid)
    if lsp is None:
        return None
    return {
        "seqno": int(lsp["seqNumber"], 16),
        "chksum": lsp["chksum"],
        "holdtime": lsp["holdtime"],
    }


def _lsp_is_purged(state):
    # A zero-aged database copy shows the remaining zero-age time as
    # "(N)" instead of a plain holdtime.
    if state is None:
        return False
    holdtime = state["holdtime"]
    if holdtime == 0:
        return True
    return isinstance(holdtime, str) and re.fullmatch(r"\(\d+\)", holdtime) is not None


def _own_lsp_advertises_algo(router):
    raw = router.vtysh_cmd("show isis database detail").replace("\r\n", "\n")
    # with dynamic hostname off the own LSP shows up under its system id
    blocks = re.split(r"\n(?=\S)", raw)
    for block in blocks:
        lines = block.splitlines()
        if not lines or "%s.00-00" % R1_SYSID not in lines[0]:
            continue
        m = re.search(r"SR Algorithm:\n((?:[ \t]+\d+: .*\n)+)", block)
        if m is None:
            return None
        return "%d: Flex-Algo" % ALGO in m.group(1)
    return None


def _wait_own_lsp_algo(router, advertised, timeout_s=30):
    return _wait_until(
        lambda: _own_lsp_advertises_algo(router) is advertised, timeout_s=timeout_s
    )


# ---------------------------------------------------------------------------
# Capture / injection process helpers (run inside the node netns)
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


def _start_capture(router, iface, pcap_path, extra_args, bpf="isis"):
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
        "--filter %s --lsp-id %s %s --ready-file %s </dev/null >%s 2>&1 & echo $!"
        % (
            shlex.quote(CWD),
            shlex.quote(iface),
            shlex.quote(pcap_path),
            shlex.quote(bpf),
            shlex.quote(PEER_LSP_ID_HEX),
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


def _template_path(tgen):
    return os.path.join(tgen.logdir, "r2_lsp_template.hex")


def _template_seq(path):
    try:
        with open(path) as fp:
            pdu = bytes.fromhex(fp.read().strip())
    except (FileNotFoundError, ValueError):
        return None
    if len(pdu) < 26:
        return None
    return int.from_bytes(pdu[20:24], "big")


def _inject(tgen, frames):
    tgen.gears[R2].cmd_raises(
        "python3 %s/inject_fad_lsp.py --iface eth1 --template %s "
        "--frames %s --spacing %s"
        % (
            shlex.quote(CWD),
            shlex.quote(_template_path(tgen)),
            shlex.quote(json.dumps(frames)),
            INJECT_SPACING,
        )
    )


def _fad_frame(sysid, seqno, lifetime, unsupported=False):
    return {
        "sysid": sysid,
        "seqno": seqno,
        "lifetime": lifetime,
        "algo": ALGO,
        "prio": ATTACK_PRIO,
        "unsupported": unsupported,
    }


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


def test_adjacency_and_template():
    """Adjacencies reach Up, r1 elects r3's FAD, template captured from the wire."""
    global _template_sniffer_pid
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears[R1]
    r2 = tgen.gears[R2]

    # Track r2's genuine L1 LSP floods for the whole module.  The tracker
    # only accepts frames from r2's real MAC, so the injector's frames
    # can never poison the template.
    accept_mac = r2.cmd("cat /sys/class/net/eth1/address").strip()
    template = _template_path(tgen)
    ready = template + ".ready"
    r2.cmd("rm -f %s %s" % (shlex.quote(template), shlex.quote(ready)))
    pid = r2.cmd(
        "nohup python3 %s/capture_isis.py --iface eth1 "
        "--template-out %s --accept-mac %s --lsp-id %s --pdutype 18 "
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
    r2.vtysh_cmd(
        "configure terminal\nrouter isis FLEX\n"
        "metric-style narrow\nmetric-style wide"
    )

    _wait_neighbor_up(r1, "eth1")
    _wait_neighbor_up(r1, "eth2")

    def _template_matches_db():
        seq = _template_seq(template)
        if seq is None:
            return False
        try:
            state = _lsp_state(r1, "0000.0000.0002")
        except (RuntimeError, ValueError, json.JSONDecodeError):
            return False
        return state is not None and state["seqno"] == seq

    assert _wait_until(_template_matches_db, timeout_s=60), (
        "template of r2's LSP not captured from the wire within 60s"
    )

    # Baseline election: r2 and r3 both advertise a FAD with the
    # default priority 128, so r3 wins on the higher system id.
    assert _wait_flex_algo(
        r1, OBSERVER_SYSID, priority=LEGIT_PRIO, local_state="enabled", timeout_s=30
    ), "baseline FAD election is not r3's definition: %s" % _flex_algo_state(r1)
    logger.info("baseline FAD election: %s", _flex_algo_state(r1))


def test_seqno0_lsp_not_elected():
    """A seqno=0 LSP is installed and flooded but must not feed the FAD election."""
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears[R1]
    r2 = tgen.gears[R2]
    r3 = tgen.gears[R3]

    inject_pcap = os.path.join(tgen.logdir, "seqno0_inject.pcap")
    observer_pcap = os.path.join(tgen.logdir, "seqno0_observer.pcap")
    inject_pid = _start_capture(r2, "eth1", inject_pcap, "")
    observer_pid = _start_capture(r3, "eth1", observer_pcap, "")

    _inject(tgen, [_fad_frame(ATTACKER_A_SYSID, 0, 1200)])
    time.sleep(SETTLE_S)

    _stop_capture(r2, inject_pid, inject_pcap)
    _stop_capture(r3, observer_pid, observer_pcap)

    # Receive path proof: the LSP is in r1's database with seqno 0.
    state = _lsp_state(r1, ATTACKER_A_SYSID)
    assert state is not None, "seqno=0 LSP not installed on r1"
    assert state["seqno"] == 0, "unexpected seqno for attacker LSP: %s" % state

    # Normal L1 flooding carried it to r3.
    observer_hits = [
        event
        for event in _pcap_events(observer_pcap)
        if event.get("pdutype") == 18
        and event.get("lspid", "").startswith(ATTACKER_A_SYSID.replace(".", ""))
        and event["src_mac"] != INJECTOR_MAC
    ]
    assert observer_hits, "seqno=0 LSP not flooded to r3"

    # But the FAD election must ignore it.
    assert _wait_flex_algo(
        r1, OBSERVER_SYSID, priority=LEGIT_PRIO, local_state="enabled", timeout_s=10
    ), "seqno=0 LSP took part in the FAD election: %s" % _flex_algo_state(r1)


def test_zero_lifetime_lsp_not_elected():
    """A purged LSP stays in the database during the zero-age window but must
    not feed the FAD election."""
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears[R1]

    # A valid LSP first, then its zero-lifetime purge: the purge wins
    # the comparison and the database copy is retained with its TLVs
    # for the zero-age window.
    _inject(
        tgen,
        [
            _fad_frame(ATTACKER_A_SYSID, 0x10, 1200),
            _fad_frame(ATTACKER_A_SYSID, 0x10, 0),
        ],
    )
    time.sleep(SETTLE_S)

    state = _lsp_state(r1, ATTACKER_A_SYSID)
    assert state is not None, "purged LSP not retained in r1's database"
    assert _lsp_is_purged(state), "attacker LSP is not the purged copy: %s" % state

    assert _wait_flex_algo(
        r1, OBSERVER_SYSID, priority=LEGIT_PRIO, local_state="enabled", timeout_s=10
    ), "purged LSP took part in the FAD election: %s" % _flex_algo_state(r1)


def test_valid_high_prio_fad_wins():
    """A fully valid higher-priority FAD must still win the election."""
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears[R1]

    _inject(tgen, [_fad_frame(ATTACKER_A_SYSID, 0x20, 1200)])

    assert _wait_flex_algo(
        r1, ATTACKER_A_SYSID, priority=ATTACK_PRIO, local_state="enabled", timeout_s=10
    ), "valid high-priority FAD did not win: %s" % _flex_algo_state(r1)


def test_unsupported_seqno0_fad_not_elected():
    """A seqno=0 LSP with an unsupported FAD must not disable the algorithm."""
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears[R1]

    # The unknown FAD sub-sub-TLV makes the definition unsupported; if
    # it were elected, flex-algo 201 would be driven into the disabled
    # state.  A seqno=0 receipt does not schedule SPF, so a valid newer
    # LSP for sysid aa follows to schedule SPF through the normal
    # receive path and let the disabled-state side effects fire on the
    # unfixed isisd.
    _inject(
        tgen,
        [
            _fad_frame(ATTACKER_B_SYSID, 0, 1200, unsupported=True),
            _fad_frame(ATTACKER_A_SYSID, 0x21, 1200),
        ],
    )
    time.sleep(REGEN_S)

    assert _wait_flex_algo(
        r1, ATTACKER_A_SYSID, priority=ATTACK_PRIO, local_state="enabled", timeout_s=10
    ), "seqno=0 unsupported FAD took part in the election: %s" % _flex_algo_state(r1)
    assert _wait_own_lsp_algo(r1, True, timeout_s=10), (
        "r1 dropped flex-algo %d participation from its own LSP" % ALGO
    )
