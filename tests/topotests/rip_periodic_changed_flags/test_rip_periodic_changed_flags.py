#!/usr/bin/env python
# SPDX-License-Identifier: ISC

#
# test_rip_periodic_changed_flags.py
# Part of NetDEF Topology Tests
#

"""
test_rip_periodic_changed_flags.py: RIP changed-flag lifecycle across a
periodic full-table update.

rip_update() sends the full table and suppresses a pending triggered
update, but (before the fix) it did not clear the per-route
RIP_RTF_CHANGED flags; only rip_triggered_update() cleared them.  When
the periodic update fired while a triggered merge window was pending,
the changed routes were carried in the full update (correct
suppression), yet their flags stayed set, so the NEXT triggered update
re-advertised them together with the routes that had genuinely changed
in the meantime.

Sequence per race round (update timer 5 s, merge window 1-5 s):
  1. remove static 198.18.0.1/32 -> immediate triggered update
     advertising only 198.18.0.1, clearing all flags and arming the
     merge timer;
  2. inside the merge window, remove statics 198.18.0.2-8/32 (K=7
     routes): their flags are set and rip->trigger is set;
  3. the periodic full-table update fires before the merge timer
     expires: it carries 198.18.0.2-8 (as poison) and cancels the
     merge timer, but must also clear their flags;
  4. re-add static 198.18.0.1/32 -> the next triggered update must
     carry ONLY 198.18.0.1.  A triggered update that also carries
     198.18.0.2-8 means the periodic update left stale flags behind.

Timing is driven from a packet-buffered pcap captured on r2-eth0: the
phase of the next periodic update is measured from the previous one,
the route changes are scheduled at (last periodic + 3.5 s), and every
round is classified post-hoc from the capture (periodic arrived before
the merge-timer triggered update -> round won; otherwise void, retry).
Controls verify that without any route change only periodic full-table
updates are sent, and that a single route change produces exactly one
triggered update carrying exactly that route.
"""

import os
import select
import subprocess
import struct
import sys
import time

import pytest

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from lib import topotest
from lib.topogen import Topogen, get_topogen

fatal_error = ""

pytestmark = [pytest.mark.ripd]

R1_IP = "10.0.12.1"
RIP_PORT = 520
PREFIXES = ["198.18.0.{}".format(i) for i in range(1, 9)]
NEW = PREFIXES[0]
STALE = PREFIXES[1:]
# The redistributed loopback is part of every full-table update and of
# no triggered update (its flag is never set after startup), so it marks
# periodic updates independently of the RTE count.
MARKER = "10.0.99.1"
PCAP = None

#####################################################
##
##   Network Topology Definition
##
#####################################################


def build_topo(tgen):
    tgen.add_router("r1")
    tgen.add_router("r2")

    switch = tgen.add_switch("sw1")
    switch.add_link(tgen.gears["r1"])
    switch.add_link(tgen.gears["r2"])


#####################################################
##
##   Helpers
##
#####################################################


def static_config(r1, prefixes, remove=False):
    cmds = ["configure terminal"]
    for pfx in prefixes:
        cmds.append("no ip route {}/32 Null0".format(pfx) if remove
                    else "ip route {}/32 Null0".format(pfx))
    cmds.append("end")
    r1.vtysh_multicmd(cmds)


def flush_changed_flags(r1):
    """Remove and re-add one route so the resulting triggered updates
    clear any change flags left pending from an earlier phase.  On an
    unpatched daemon a periodic update can suppress a merged triggered
    update without clearing the flags (the defect under test here),
    which would otherwise contaminate the next measurement."""
    static_config(r1, [NEW], remove=True)
    time.sleep(1)
    static_config(r1, [NEW])
    time.sleep(6)


def start_capture(r2):
    logfile = PCAP + ".log"
    with open(logfile, "w") as log:
        capture = r2.popen(
            ["python3", os.path.join(os.path.dirname(__file__), "capture_rip.py"),
             "--iface", "r2-eth0", "--pcap", PCAP],
            stdout=subprocess.PIPE,
            stderr=log,
            text=True,
        )
    ready = False
    try:
        readable, _, _ = select.select([capture.stdout], [], [], 10)
        if not readable or capture.stdout.readline().strip() != "ready":
            raise RuntimeError("RIP capture did not start; see {}".format(logfile))
        ready = True
    finally:
        if not ready:
            stop_capture(r2, capture)
    return capture


def stop_capture(r2, capture):
    logfile = PCAP + ".log"
    if capture.poll() is None:
        capture.terminate()
    try:
        status = capture.wait(timeout=5)
    except subprocess.TimeoutExpired:
        capture.kill()
        capture.wait()
        raise RuntimeError("RIP capture did not stop; see {}".format(logfile))
    finally:
        capture.stdout.close()
    if status != 0:
        raise RuntimeError("RIP capture exited with {}; see {}".format(status, logfile))


def parse_rip_pcap(pcap_path):
    """Minimal classic-pcap reader for RIPv2 responses."""
    with open(pcap_path, "rb") as fp:
        data = fp.read()
    if len(data) < 24:
        return []
    magic = data[:4]
    if magic == b"\xd4\xc3\xb2\xa1":
        endian, nano = "<", False
    elif magic == b"\xa1\xb2\xc3\xd4":
        endian, nano = ">", False
    elif magic == b"\x4d\x3c\xb2\xa1":
        endian, nano = "<", True
    elif magic == b"\xa1\xb2\x3c\x4d":
        endian, nano = ">", True
    else:
        return []
    off = 24
    packets = []
    while off + 16 <= len(data):
        ts_sec, ts_frac, incl, _orig = struct.unpack_from(
            endian + "IIII", data, off)
        off += 16
        pkt = data[off:off + incl]
        off += incl
        ts = ts_sec + ts_frac / (1e9 if nano else 1e6)
        if len(pkt) < 14 + 20 + 8 + 4:
            continue
        if pkt[12:14] != b"\x08\x00":
            continue
        ip = pkt[14:]
        ihl = (ip[0] & 0x0F) * 4
        if ip[9] != 17 or len(ip) < ihl + 8:
            continue
        udp = ip[ihl:]
        sport, dport = struct.unpack_from(">HH", udp, 0)
        if sport != RIP_PORT and dport != RIP_PORT:
            continue
        rip = udp[8:]
        if len(rip) < 4:
            continue
        cmd = rip[0]
        src = ".".join(str(b) for b in ip[12:16])
        entries = []
        rte_data = rip[4:]
        while len(rte_data) >= 20:
            family, _tag, addr, _mask, _nh, _metric = struct.unpack_from(
                ">HH4s4s4sI", rte_data, 0)
            if family == 2:
                entries.append(".".join(str(b) for b in addr))
            rte_data = rte_data[20:]
        packets.append({"ts": ts, "src": src, "cmd": cmd,
                        "entries": entries})
    return packets


def r1_updates(after=0.0):
    """r1's RIPv2 responses seen on r2-eth0, classified by the
    full-table marker."""
    out = []
    for p in parse_rip_pcap(PCAP):
        if p["src"] != R1_IP or p["cmd"] != 2 or p["ts"] <= after:
            continue
        p = dict(p)
        p["kind"] = "periodic" if MARKER in p["entries"] else "triggered"
        out.append(p)
    return out


def pkt_brief(p):
    return "{} ts={:.3f} entries={}".format(
        p["kind"], p["ts"], sorted(set(p["entries"])))


def wait_packet(kind, after, timeout):
    deadline = time.time() + timeout
    while time.time() < deadline:
        for p in r1_updates(after=after):
            if p["kind"] == kind:
                return p
        time.sleep(0.2)
    return None


def last_periodic():
    periodics = [p["ts"] for p in r1_updates() if p["kind"] == "periodic"]
    return max(periodics) if periodics else None


def wait_last_periodic(timeout):
    """Newest periodic update ts in the capture, waiting for the first
    one if the capture just started."""
    deadline = time.time() + timeout
    while True:
        base = last_periodic()
        if base is not None:
            return base
        if time.time() >= deadline:
            return None
        time.sleep(0.2)


def assert_routers_running():
    net = get_topogen().net
    for r in ("r1", "r2"):
        fatal = net[r].checkRouterRunning()
        assert fatal == "", fatal


#####################################################
##
##   Tests starting
##
#####################################################


def setup_module(module):
    global PCAP
    print("\n\n** %s: Setup Topology" % module.__name__)
    print("******************************************\n")

    thisDir = os.path.dirname(os.path.realpath(__file__))
    tgen = Topogen(build_topo, module.__name__)
    PCAP = os.path.join(tgen.logdir, "rip_periodic_changed_flags.pcap")
    tgen.start_topology()

    net = tgen.net
    for r in ("r1", "r2"):
        net[r].loadConf("zebra", "%s/%s/zebra.conf" % (thisDir, r))
        net[r].loadConf("ripd", "%s/%s/ripd.conf" % (thisDir, r))
        tgen.gears[r].start()


def teardown_module(module):
    print("\n\n** %s: Shutdown Topology" % module.__name__)
    print("******************************************\n")
    tgen = get_topogen()
    tgen.stop_topology()


def test_router_running():
    if fatal_error != "":
        pytest.skip(fatal_error)
    assert_routers_running()


def test_converge():
    if fatal_error != "":
        pytest.skip(fatal_error)

    print("\n\n** r1 originates 8 redistributed static routes")
    print("******************************************\n")
    r1 = get_topogen().gears["r1"]
    static_config(r1, PREFIXES)

    def _r2_learned_all():
        out = get_topogen().gears["r2"].vtysh_cmd("show ip rip")
        return all(p in out for p in PREFIXES)

    success, _ = topotest.run_and_expect(_r2_learned_all, True,
                                         count=60, wait=1)
    assert success, "r2 did not learn all static routes via RIP"
    assert_routers_running()


def test_no_trigger_control():
    """Without route changes r1 emits only periodic full-table updates,
    each carrying all eight routes."""
    if fatal_error != "":
        pytest.skip(fatal_error)

    print("\n\n** control: no route change, periodic updates only")
    print("******************************************\n")
    r2 = get_topogen().gears["r2"]
    pid = start_capture(r2)
    try:
        time.sleep(13)
    finally:
        stop_capture(r2, pid)
    pkts = r1_updates()
    periodics = [p for p in pkts if p["kind"] == "periodic"]
    triggered = [p for p in pkts if p["kind"] == "triggered"]
    brief = "\n".join(pkt_brief(p) for p in pkts)
    assert len(periodics) >= 2, "expected >=2 periodic updates:\n" + brief
    assert not triggered, "unexpected triggered updates:\n" + brief
    for p in periodics:
        assert set(PREFIXES) <= set(p["entries"]), \
            "periodic update misses routes: " + pkt_brief(p)
    assert_routers_running()


def test_single_triggered_control():
    """One route change produces exactly one triggered update carrying
    exactly that route, then the normal periodic update resumes."""
    if fatal_error != "":
        pytest.skip(fatal_error)

    print("\n\n** control: single route change, single triggered update")
    print("******************************************\n")
    r1 = get_topogen().gears["r1"]
    r2 = get_topogen().gears["r2"]
    flush_changed_flags(r1)
    pid = start_capture(r2)
    try:
        base = wait_last_periodic(timeout=10)
        assert base is not None, "no periodic update captured"
        static_config(r1, [NEW], remove=True)
        trig = wait_packet("triggered", after=time.time() - 2.0, timeout=4)
        assert trig is not None, "no triggered update after route removal"
        entries = set(trig["entries"])
        assert entries == {NEW}, \
            "triggered update carries unexpected routes: " + pkt_brief(trig)
        # Restore the route; its advertisement must not carry any other
        # route either (whether via a triggered update or, if a periodic
        # update wins the merge window, via the full table).
        static_config(r1, [NEW])
        time.sleep(7)
    finally:
        stop_capture(r2, pid)
    pkts = r1_updates(after=base)
    brief = "\n".join(pkt_brief(p) for p in pkts)
    trig_pkts = [p for p in pkts if p["kind"] == "triggered"]
    assert trig_pkts, "no triggered update captured:\n" + brief
    for p in trig_pkts:
        assert set(p["entries"]) == {NEW}, \
            "triggered update carries unexpected routes: " + pkt_brief(p)
    assert any(p["kind"] == "periodic" for p in pkts), \
        "no periodic update after triggered updates:\n" + brief
    assert_routers_running()


def test_periodic_update_clears_changed_flags():
    """Race: changes inside a triggered merge window must not be
    re-advertised by the NEXT triggered update once the periodic
    full-table update has carried them."""
    if fatal_error != "":
        pytest.skip(fatal_error)

    print("\n\n** race: periodic full-table update vs merge window")
    print("******************************************\n")
    r1 = get_topogen().gears["r1"]
    r2 = get_topogen().gears["r2"]
    flush_changed_flags(r1)

    pid = start_capture(r2)
    won = None
    try:
        for round_no in range(1, 11):
            base = wait_last_periodic(timeout=10)
            assert base is not None, "no periodic update captured"
            t0 = base + 3.2
            lead = t0 - time.time()
            if lead < 1.0:
                time.sleep(6)
                continue
            if lead > 0:
                time.sleep(lead)
            # Change 1: immediate triggered update, merge timer armed.
            static_config(r1, [NEW], remove=True)
            # Changes 2..8 inside the merge window.
            time.sleep(0.3)
            static_config(r1, STALE, remove=True)

            # Post-hoc classification of the race window.  The round is
            # won only when the periodic update arrived after the
            # in-window changes were processed (their flags set) but
            # before the merge timer fired.  A triggered update racing
            # the periodic update (merge timer won) voids the round; a
            # triggered update within 2s AFTER the periodic update means
            # the second batch of changes landed only after the periodic
            # update (so their flags were legitimately cleared by that
            # triggered update) and voids the round as well.
            deadline = time.time() + 5.0
            state = "UNDECIDED"
            winpkt = None
            while time.time() < deadline:
                pkts = r1_updates(after=t0 - 1.0)
                trig1 = next((p for p in pkts
                              if p["kind"] == "triggered"
                              and set(p["entries"]) == {NEW}), None)
                later = [p for p in pkts
                         if trig1 and p["ts"] > trig1["ts"] + 0.1]
                periodic = next((p for p in later
                                 if p["kind"] == "periodic"), None)
                trig2 = next((p for p in later
                              if p["kind"] == "triggered"), None)
                if trig2 and (not periodic or trig2["ts"] < periodic["ts"]):
                    state = "VOID"
                    break
                if periodic:
                    if trig2 and trig2["ts"] < periodic["ts"] + 2.0:
                        state = "VOID"
                        break
                    if time.time() > periodic["ts"] + 2.5:
                        state, winpkt = "WON", periodic
                        break
                time.sleep(0.2)
            if state != "WON":
                # The round removed routes without winning the race;
                # restore them and flush any pending change flags (a
                # suppressed merged triggered update on an unpatched
                # daemon leaves flags behind) before the next round.
                static_config(r1, PREFIXES)
                time.sleep(6)
                flush_changed_flags(r1)
                continue

            # Genuine new change after the periodic full-table update.
            time.sleep(0.5)
            static_config(r1, [NEW])
            final = wait_packet("triggered", after=time.time() - 2.0,
                                timeout=4)
            assert final is not None, \
                "no triggered update after the genuine new change"
            won = (round_no, final)
            break
    finally:
        stop_capture(r2, pid)

    assert won is not None, "no valid race round in 10 rounds"
    round_no, final = won
    entries = set(final["entries"])
    brief = "\n".join(pkt_brief(p) for p in r1_updates())
    assert entries == {NEW}, (
        "triggered update after the periodic full-table update "
        "re-advertises stale routes (round {}): {}\nall packets:\n{}"
        .format(round_no, pkt_brief(final), brief))
    assert_routers_running()


def test_shutdown_check_stderr():
    if fatal_error != "":
        pytest.skip(fatal_error)

    if os.environ.get("TOPOTESTS_CHECK_STDERR") is None:
        pytest.skip("Skipping test for Stderr output and memory leaks")

    net = get_topogen().net
    net["r1"].stopRouter()

    log = net["r1"].getStdErr("ripd")
    if log:
        print("\nRIPd StdErr Log:\n" + log)
    log = net["r1"].getStdErr("zebra")
    if log:
        print("\nZebra StdErr Log:\n" + log)


if __name__ == "__main__":
    retval = pytest.main(["-s"])
    sys.exit(retval)
