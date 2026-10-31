#!/usr/bin/env python
# SPDX-License-Identifier: ISC
#
# test_babel_late_hello_churn.py
#
# Copyright (c) 2026 by
# Bing Shui <bingshui@smail.nju.edu.cn>
#

"""
test_babel_late_hello_churn.py: replaying an already-seen (late) Babel Hello
must not re-trigger the association feedback on the receiver.

update_neighbour() handles a late hello (missed_hellos < 0, hello interval
unchanged) by resetting the expected seqno and setting hello = -1, but then
falls through to the feedback block instead of returning.  The feedback
block re-evaluates the *unchanged* reach value, so every replayed hello
re-fires:

  * send_self_update(): one Update per xroute, and flushupdates() does a
    linear find_xroute() per buffered prefix (O(X^2) comparisons for X
    xroutes);
  * send_unicast_request(neigh, NULL, 0): a wildcard Route Request;
  * send_ihu(neigh, NULL): a unicast IHU;

and update_neighbour_metric(neigh, 1) re-walks the whole route table.

Topology:

    r1-eth1 (10.99.0.0/24)  r1-eth2 (10.99.1.0/24)  r1-eth3 (10.99.2.0/24)
       |                       |                       |
    [ r1 ] ---- r1-eth0 ---- sw1 ---- r2-eth0 ---- [ r2 ] ---- r2-eth1 (10.98.0.0/24)
                              |
                           r3-eth0 (attacker, no daemons)

r1 redistributes its connected stubs (plus 10.0.0.0/24) as xroutes; r1-eth0
uses "babel update-interval 655340" so no periodic Update from r1 disturbs
the measurement windows.  The attacker is emulated by r3, a namespace
without any FRR daemon: inject_hello.py sends Hello TLVs with per-test
source addresses fe80::1b1..fe80::1b5 added to r3-eth0, so r1 keys a
separate, fresh neighbour for every test and r3 never originates protocol
traffic of its own.  Every injected hello carries the same non-zero
interval (4000), so replays of the last seqno take the late-hello branch.

The tests drive the exact seqno/reach sequence from the bug report:
100, 106, 107 (reach 0xC100) and then replay 107; or 100, 101 (reach
0xC000) and then replay 101.  On unfixed code every replay re-emits the
full self-update, a wildcard Route Request and an IHU; on fixed code the
late-hello branch returns before the feedback block and the burst window
stays empty, while in-order hellos, an interval-increase hello, and a
rebooted neighbour's seqno jump still get their (one-shot, protocol
normal) feedback.
"""

import contextlib
import ipaddress
import os
import re
import select
import struct
import subprocess
import sys
import time

import pytest

pytestmark = [pytest.mark.babeld]

CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

# pylint: disable=C0413
from lib import topotest
from lib.topogen import Topogen, TopoRouter, get_topogen
from lib.topolog import logger

ATTACKER_ADDRS = ["fe80::1b1", "fe80::1b2", "fe80::1b3", "fe80::1b4", "fe80::1b5"]
HELLO_INTERVAL = 4000  # raw TLV interval, identical for every injected hello
REPLAYS = 10
REPLAY_GAP = 1.0
CONTROL_SECONDS = 10
SETTLE_SECONDS = 4

XROUTE_PREFIXES = ["10.99.0.0/24", "10.99.1.0/24", "10.99.2.0/24"]
# one full self-update carries the three stubs plus the 10.0.0.0/24 link
# prefix (the xroute branch of flushupdates is not subject to split horizon)
FULL_DUMP_TLVS = 4
PEER_PREFIX = "10.98.0.0/24"


def build_topo(tgen):
    tgen.add_router("r1")
    tgen.add_router("r2")
    tgen.add_router("r3")

    # Babel link: r1-eth0 <-> r2-eth0, plus r3 (no daemons, injection host)
    sw1 = tgen.add_switch("sw1")
    sw1.add_link(tgen.gears["r1"])
    sw1.add_link(tgen.gears["r2"])
    sw1.add_link(tgen.gears["r3"])

    # xroute stubs on r1: r1-eth1, r1-eth2, r1-eth3
    for i in (1, 2, 3):
        sw = tgen.add_switch("sw{}".format(i + 1))
        sw.add_link(tgen.gears["r1"])

    # route stub on r2: r2-eth1
    sw5 = tgen.add_switch("sw5")
    sw5.add_link(tgen.gears["r2"])


def setup_module(module):
    tgen = Topogen(build_topo, module.__name__)
    tgen.start_topology()

    for rname, router in tgen.routers().items():
        if rname == "r3":
            continue
        router.load_config(
            TopoRouter.RD_ZEBRA, os.path.join(CWD, "{}/zebra.conf".format(rname))
        )
        router.load_config(
            TopoRouter.RD_BABEL, os.path.join(CWD, "{}/babeld.conf".format(rname))
        )

    tgen.start_router()

    # per-test attacker addresses on r3-eth0 (r3 runs no babeld, so these
    # addresses are never used as a source for protocol traffic)
    for addr in ATTACKER_ADDRS:
        tgen.gears["r3"].cmd("ip -6 addr add {}/64 dev r3-eth0".format(addr))


def teardown_module(_mod):
    tgen = get_topogen()
    tgen.stop_topology()


# ---------------- helpers ----------------

def _ll_addr(router, ifname):
    out = router.cmd("ip -6 addr show dev {} scope link".format(ifname))
    for line in out.splitlines():
        m = re.search(r"inet6 (fe80::[0-9a-fA-F:]+)/", line)
        if m:
            return str(ipaddress.IPv6Address(m.group(1)))
    return None


def _reach(router, addr):
    out = router.vtysh_cmd("show babel neighbor")
    for line in out.splitlines():
        if "Neighbour {} ".format(addr) in line:
            m = re.search(r"reach ([0-9a-fA-F]{4})", line)
            if m:
                return m.group(1).lower()
    return None


def _inject(addr, plan):
    """plan: list of (seqno, interval, gap_before)"""
    r3 = get_topogen().gears["r3"]
    args = " ".join("{}:{}:{}".format(s, i, g) for s, i, g in plan)
    out = r3.cmd(
        "python3 {}/inject_hello.py --src {} --iface r3-eth0 --plan {}".format(
            CWD, addr, args
        )
    )
    sent = len([l for l in out.splitlines() if l.startswith("sent")])
    assert sent == len(plan), "injection incomplete: {}".format(out)


def _assoc_107(addr):
    _inject(addr, [(100, HELLO_INTERVAL, 0), (106, HELLO_INTERVAL, 1.0), (107, HELLO_INTERVAL, 1.0)])


def _wait_quiet(r1, addr, expected_reach):
    """Wait until the attacker association reached expected_reach, the r1-r2
    association is fully ramped (reach ffff), and all transition feedback has
    been flushed, so a capture window sees only idle wire plus what a test
    injects afterwards."""
    r2_ll = _ll_addr(get_topogen().gears["r2"], "r2-eth0")

    def check():
        reach = _reach(r1, addr)
        if reach != expected_reach:
            return "attacker reach is {} not {} yet".format(reach, expected_reach)
        r2_reach = _reach(r1, r2_ll)
        if r2_reach is None or int(r2_reach, 16) < 0xFC00:
            return "r1-r2 association not fully ramped yet (reach {})".format(r2_reach)
        return None

    _, result = topotest.run_and_expect(check, None, count=45, wait=1)
    assert result is None, "associations did not settle: {}".format(result)
    time.sleep(SETTLE_SECONDS)


def _wait_wire_quiet(r1, src, tries=8):
    """Trial-capture short windows until r1 emits no Update and no wildcard
    Route Request.  Association feedback and route-change triggers are
    one-shot but can lag the association by seconds; the replay windows must
    start from a wire that is actually idle, not just from an idle-looking
    neighbour table."""
    tgen = get_topogen()
    for i in range(tries):
        pcap = os.path.join(tgen.logdir, "quiet{}.pcap".format(i))
        with _capture(r1, "r1-eth0", pcap):
            time.sleep(3)
        counts = _count_tlv_classes(pcap, src, 0, float("inf"))
        if counts["update"] == 0 and counts["wildcard_request"] == 0:
            return
        logger.info("wire not quiet yet ({}), retrying".format(counts))
        time.sleep(2)
    raise AssertionError("r1 never went wire-quiet: {}".format(counts))


# ---------------- pcap capture / parse ----------------

@contextlib.contextmanager
def _capture(router, ifname, pcap):
    logfile = pcap + ".log"
    with open(logfile, "w") as log:
        capture = router.popen(
            ["python3", os.path.join(CWD, "capture_babel.py"),
             "--iface", ifname, "--pcap", pcap],
            stdout=subprocess.PIPE,
            stderr=log,
            text=True,
        )
        try:
            readable, _, _ = select.select([capture.stdout], [], [], 10)
            if not readable or capture.stdout.readline().strip() != "ready":
                raise RuntimeError("Babel capture did not start; see {}".format(logfile))
            yield
        finally:
            if capture.poll() is None:
                capture.terminate()
            try:
                status = capture.wait(timeout=5)
            except subprocess.TimeoutExpired:
                capture.kill()
                capture.wait()
                raise RuntimeError("Babel capture did not stop; see {}".format(logfile))
            finally:
                capture.stdout.close()
            if status != 0:
                raise RuntimeError("Babel capture exited with {}; see {}".format(status, logfile))


def _iter_tlvs(body):
    i = 0
    while i + 2 <= len(body):
        t = body[i]
        if t == 0:
            i += 1
            continue
        ln = body[i + 1]
        tlv = body[i + 2:i + 2 + ln]
        i += 2 + ln
        if t == 5 and len(tlv) >= 6:
            yield "IHU", {}
        elif t == 8 and len(tlv) >= 10:
            ae, plen, omit = tlv[0], tlv[2], tlv[3]
            need = (plen + 7) // 8 - omit
            raw = tlv[10:10 + need]
            if ae == 1:
                pfx = ".".join(str(b) for b in raw.ljust(4, b"\x00")) + "/{}".format(plen)
            else:
                pfx = raw.hex() + "/{}".format(plen)
            metric = struct.unpack_from(">H", tlv, 8)[0]
            yield "Update", {"prefix": pfx, "metric": metric}
        elif t == 9 and len(tlv) >= 2:
            yield "Request", {"wildcard": tlv[0] == 0}
        else:
            yield "TLV{}".format(t), {}


def _count_tlv_classes(pcap, src, t0, t1):
    """Count IHU / Update / wildcard-Request TLVs sent by *src* in [t0, t1)."""
    counts = {"ihu": 0, "update": 0, "wildcard_request": 0}
    with open(pcap, "rb") as fp:
        data = fp.read()
    if len(data) < 24:
        return counts
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
        raise RuntimeError("not a classic pcap: {!r}".format(magic))
    off = 24
    while off + 16 <= len(data):
        ts_sec, ts_frac, incl, _orig = struct.unpack_from(endian + "IIII", data, off)
        off += 16
        pkt = data[off:off + incl]
        off += incl
        ts = ts_sec + ts_frac / (1e9 if nano else 1e6)
        if not (t0 <= ts < t1):
            continue
        if len(pkt) < 14 + 40 + 8 or pkt[12:14] != b"\x86\xdd":
            continue
        ipv6 = pkt[14:]
        if ipv6[6] != 17:
            continue
        udp = ipv6[40:]
        sport, dport, ulen = struct.unpack_from(">HHH", udp, 0)
        if 6696 not in (sport, dport):
            continue
        payload = udp[8:ulen] if 8 <= ulen <= len(udp) else udp[8:]
        if len(payload) < 4 or payload[0] != 42:
            continue
        pkt_src = str(ipaddress.IPv6Address(ipv6[8:24]))
        if pkt_src != src:
            continue
        for name, detail in _iter_tlvs(payload[4:]):
            if name == "IHU":
                counts["ihu"] += 1
            elif name == "Update":
                counts["update"] += 1
            elif name == "Request" and detail.get("wildcard"):
                counts["wildcard_request"] += 1
    return counts


def _r1_ll():
    return _ll_addr(get_topogen().gears["r1"], "r1-eth0")


def _prefix_reachable(router, prefix):
    def check():
        output = router.vtysh_cmd("show babel route {}".format(prefix), isjson=False)
        if prefix in output and "(installed)" in output:
            return None
        return "{} not installed yet on {}".format(prefix, router.name)

    return check


# ---------------- tests ----------------

def _bounce_redistribute(router):
    "Re-emit every xroute as a per-prefix triggered update."
    router.vtysh_cmd(
        "configure terminal\nrouter babel\nno redistribute ipv4 connected\n"
        "redistribute ipv4 connected\n"
    )


def test_converge_protocols():
    "Babel adjacency forms on r1-eth0 and the routes cross the link."
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]
    r2 = tgen.gears["r2"]
    r2_ll = _ll_addr(r2, "r2-eth0")
    assert r2_ll is not None, "no link-local address on r2-eth0"

    def check_neighbour():
        return None if _reach(r1, r2_ll) else "no babel neighbour for r2 on r1 yet"

    _, result = topotest.run_and_expect(check_neighbour, None, count=60, wait=1)
    assert result is None, "r1 failed to establish a babel neighbour with r2"

    # let the r1-r2 reachability ramp finish (full 0xFFFF takes ~16 hellos);
    # routes learned afterwards face a sane rxcost
    def check_ramp_done():
        reach = _reach(r1, r2_ll)
        if reach is not None and int(reach, 16) >= 0xFC00:
            return None
        return "r1-r2 reach is {} not yet >= 0xFC00".format(reach)

    _, result = topotest.run_and_expect(check_ramp_done, None, count=45, wait=1)
    assert result is None, "r1-r2 association never fully ramped: {}".format(result)

    def check_r1_xroutes():
        output = r1.vtysh_cmd("show babel route", isjson=False)
        missing = [p for p in XROUTE_PREFIXES if p not in output]
        return missing or None

    _, result = topotest.run_and_expect(check_r1_xroutes, None, count=15, wait=1)
    if result is not None:
        logger.info("r1 xroutes missing %s, bouncing redistribute", result)
        _bounce_redistribute(r1)
        _, result = topotest.run_and_expect(check_r1_xroutes, None, count=15, wait=1)
    assert result is None, "r1 never redistributed its connected routes: {}".format(
        result
    )

    # The initial association ramp never emits the feedback self-update in
    # FRR (the 1100/0011 branch is unreachable while ramping up: reach
    # 0xC000 matches the new-neighbour branch, later values have 0x3000
    # bits set), so whether r2 ever sees r1's routes depends on r2 joining
    # the multicast group before r1's startup full update leaves, and
    # wildcard requests are suppressed for a second after a full update.
    # Don't rely on that race: bounce r1's redistribution so every xroute
    # is re-sent as a per-prefix triggered update on a quiet association.
    _bounce_redistribute(r1)

    def check_routes_learned():
        missing = []
        for prefix in XROUTE_PREFIXES:
            output = r2.vtysh_cmd("show babel route {}".format(prefix), isjson=False)
            if prefix not in output or "(installed)" not in output:
                missing.append(prefix)
        return missing or None

    _, result = topotest.run_and_expect(check_routes_learned, None, count=30, wait=1)
    if result is not None:
        logger.error(
            "r1 babel routes:\n{}\nr1 babel neighbors:\n{}\n"
            "r2 babel routes:\n{}\nr2 babel neighbors:\n{}".format(
                r1.vtysh_cmd("show babel route"),
                r1.vtysh_cmd("show babel neighbor"),
                r2.vtysh_cmd("show babel route"),
                r2.vtysh_cmd("show babel neighbor"),
            )
        )
    assert result is None, "r2 did not learn {} via babel".format(result)

    # same race in the r2 -> r1 direction
    _bounce_redistribute(r2)
    _, result = topotest.run_and_expect(
        _prefix_reachable(r1, PEER_PREFIX), None, count=30, wait=1
    )
    assert result is None, "r1 did not learn {} via babel".format(PEER_PREFIX)


def test_replayed_late_hello_triggers_no_feedback():
    """Replaying hello 107 after 100,106,107 (reach 0xC100) must not emit
    self-updates, wildcard Route Requests or IHUs beyond the idle rate."""
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]
    addr = ATTACKER_ADDRS[0]
    src = _r1_ll()
    assert src is not None, "no link-local address on r1-eth0"

    _assoc_107(addr)
    _wait_quiet(r1, addr, "c100")
    _wait_wire_quiet(r1, src)

    pcap = os.path.join(tgen.logdir, "replay107.pcap")
    with _capture(r1, "r1-eth0", pcap):
        t0 = time.time()
        time.sleep(CONTROL_SECONDS)
        t1 = time.time()
        _inject(addr, [(107, HELLO_INTERVAL, REPLAY_GAP if i else 0) for i in range(REPLAYS)])
        time.sleep(2)
        t2 = time.time()

    control = _count_tlv_classes(pcap, src, t0, t1)
    burst = _count_tlv_classes(pcap, src, t1, t2)
    logger.info("replay107 control: {}".format(control))
    logger.info("replay107 burst: {}".format(burst))
    logger.info("attacker reach after burst: {}".format(_reach(r1, addr)))

    assert control["update"] <= 2 * FULL_DUMP_TLVS, (
        "idle wire carries {} Updates from r1; association never settled".format(
            control["update"]
        )
    )
    assert control["wildcard_request"] == 0, "idle wire already carries wildcard requests"
    # NB: a couple of legitimate full dumps may still fire in any window
    # (metric smoothing, reach transitions on the r1-r2 association); the
    # replay burst multiplies that background by an order of magnitude.
    assert burst["update"] <= control["update"] + FULL_DUMP_TLVS, (
        "Updates from r1 rose from {} to {} during the replay burst: "
        "late-hello replays re-trigger send_self_update()".format(
            control["update"], burst["update"]
        )
    )
    assert burst["wildcard_request"] == 0, (
        "{} wildcard Route Requests during the replay burst: late-hello "
        "replays re-trigger send_unicast_request()".format(burst["wildcard_request"])
    )
    assert burst["ihu"] <= control["ihu"] + 4, (
        "IHU rate rose from {} to {} during the replay burst: late-hello "
        "replays re-trigger send_ihu()".format(control["ihu"], burst["ihu"])
    )
    assert _reach(r1, addr) == "c100", "reach changed across replays"


def test_replayed_late_hello_no_wildcard_request():
    """Replaying hello 101 after 100,101 (reach 0xC000) must not emit
    wildcard Route Requests either."""
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]
    addr = ATTACKER_ADDRS[1]
    src = _r1_ll()

    _inject(addr, [(100, HELLO_INTERVAL, 0), (101, HELLO_INTERVAL, 1.0)])
    _wait_quiet(r1, addr, "c000")
    _wait_wire_quiet(r1, src)

    pcap = os.path.join(tgen.logdir, "replay101.pcap")
    with _capture(r1, "r1-eth0", pcap):
        t0 = time.time()
        time.sleep(CONTROL_SECONDS)
        t1 = time.time()
        _inject(addr, [(101, HELLO_INTERVAL, REPLAY_GAP if i else 0) for i in range(REPLAYS)])
        time.sleep(2)
        t2 = time.time()

    control = _count_tlv_classes(pcap, src, t0, t1)
    burst = _count_tlv_classes(pcap, src, t1, t2)
    logger.info("replay101 control: {}".format(control))
    logger.info("replay101 burst: {}".format(burst))

    assert control["wildcard_request"] == 0
    assert burst["wildcard_request"] == 0, (
        "{} wildcard Route Requests during the replay burst".format(
            burst["wildcard_request"]
        )
    )
    assert burst["update"] <= control["update"] + FULL_DUMP_TLVS, (
        "Updates from r1 rose from {} to {} during the replay burst".format(
            control["update"], burst["update"]
        )
    )
    assert _reach(r1, addr) == "c000", "reach changed across replays"


def test_inorder_hello_keeps_transition_feedback():
    """An in-order hello that moves reach into the 0xCxxx band (107 after
    100,106: reach 0x8200 -> 0xC100) is a real reachability transition: the
    one-shot self-update, wildcard Route Request and IHU must be preserved.
    (The natural 0xC000 ramp step takes the new-neighbour branch instead,
    and 0xE080 matches no feedback pattern, so the seqno jump is the only
    in-order way to hit the 1100 self-update.)"""
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]
    addr = ATTACKER_ADDRS[2]
    src = _r1_ll()

    _inject(addr, [(100, HELLO_INTERVAL, 0), (106, HELLO_INTERVAL, 1.0)])
    _wait_quiet(r1, addr, "8200")

    pcap = os.path.join(tgen.logdir, "inorder.pcap")
    with _capture(r1, "r1-eth0", pcap):
        t0 = time.time()
        # one in-order hello must produce the one-shot transition feedback;
        # repeat it so a single lost UDP datagram cannot fail the guard
        # (replays of 107 are late hellos and must be ignored on fixed code)
        _inject(addr, [(107, HELLO_INTERVAL, 0), (107, HELLO_INTERVAL, 1.5),
                       (107, HELLO_INTERVAL, 1.5)])
        time.sleep(3)
        t1 = time.time()

    window = _count_tlv_classes(pcap, src, t0, t1)
    logger.info("in-order 107 window: {}".format(window))
    assert window["update"] >= FULL_DUMP_TLVS, (
        "in-order hello produced no self-update; transition feedback broken"
    )
    assert window["wildcard_request"] >= 1, (
        "in-order hello produced no wildcard Route Request"
    )
    assert _reach(r1, addr) == "c100"


def test_interval_increase_hello_keeps_feedback():
    """A late hello with a larger interval (107 interval 8000 after interval
    4000) takes the interval-increase branch, which does mutate reach: its
    one-shot feedback must be preserved."""
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]
    addr = ATTACKER_ADDRS[3]
    src = _r1_ll()

    _assoc_107(addr)
    _wait_quiet(r1, addr, "c100")

    pcap = os.path.join(tgen.logdir, "interval_increase.pcap")
    with _capture(r1, "r1-eth0", pcap):
        t0 = time.time()
        # the interval-increase hello mutates reach and must keep its
        # one-shot feedback; the follow-up in-order hello covers a lost
        # first datagram
        _inject(addr, [(107, 8000, 0), (108, 8000, 1.5)])
        time.sleep(3)
        t1 = time.time()

    window = _count_tlv_classes(pcap, src, t0, t1)
    logger.info("interval-increase window: {}".format(window))
    assert window["update"] >= FULL_DUMP_TLVS, (
        "interval-increase hello produced no self-update; branch regressed"
    )
    # 107/8000 leaves reach at 0xC100, the follow-up in-order 108/8000 moves
    # it to 0xE080; either way the interval-increase feedback fired above
    assert _reach(r1, addr) == "e080"


def test_reboot_seqno_recovers():
    """A seqno jump back by more than 8 (90 after 107) is the reboot-universe
    branch: reach resets to 0 and the next hello re-associates from 0x8000."""
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]
    addr = ATTACKER_ADDRS[4]

    _assoc_107(addr)
    _wait_quiet(r1, addr, "c100")

    _inject(addr, [(90, HELLO_INTERVAL, 0)])
    time.sleep(2)
    assert _reach(r1, addr) == "8000", (
        "reboot-universe branch broken: reach is {} instead of 8000".format(
            _reach(r1, addr)
        )
    )

    # the association still converges afterwards
    _inject(addr, [(91, HELLO_INTERVAL, 0), (92, HELLO_INTERVAL, 1.0)])
    time.sleep(2)
    reach = _reach(r1, addr)
    assert reach in ("c000", "e000", "f000", "f800", "fc00", "fe00", "ff00"), (
        "post-reboot association did not converge, reach {}".format(reach)
    )


def test_routes_still_converged():
    "All the injections above must not have broken the routing state."
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]
    r2 = tgen.gears["r2"]
    for prefix in XROUTE_PREFIXES:
        _, result = topotest.run_and_expect(
            _prefix_reachable(r2, prefix), None, count=30, wait=1
        )
        assert result is None, "r2 lost {} via babel".format(prefix)
    _, result = topotest.run_and_expect(
        _prefix_reachable(r1, PEER_PREFIX), None, count=30, wait=1
    )
    assert result is None, "r1 lost {} via babel".format(PEER_PREFIX)


def test_shutdown_check_stderr():
    if os.environ.get("TOPOTESTS_CHECK_STDERR") is None:
        pytest.skip("Skipping test for Stderr output and memory leaks")

    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    for rname, router in tgen.routers().items():
        if rname == "r3":
            continue
        router.stop()
        for daemon in ["babeld", "zebra"]:
            log = tgen.net[router.name].getStdErr(daemon)
            if log:
                logger.error("{} {} StdErr Log:\n{}".format(router.name, daemon, log))


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
