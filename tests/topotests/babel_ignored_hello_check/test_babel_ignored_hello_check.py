#!/usr/bin/env python
# SPDX-License-Identifier: ISC
#
# test_babel_ignored_hello_check.py
#
# Copyright (c) 2026 Bing Shui
#

"""
test_babel_ignored_hello_check.py: a Hello that RFC 8966 sec.4.4 says must be
silently ignored (unknown mandatory sub-TLV) must not touch babeld's global
neighbour-check deadline.

Code path under test (babeld/message.c): the Hello handler used to call

    schedule_neighbours_check(interval * 15, 0);

before parsing sub-TLVs.  A Hello carrying an unknown mandatory sub-TLV is
ignored whole (parse_hello_subtlv() returns -2, "goto done"), but the logical
check_neighbours_timeout had already been pulled to now+15ms when interval=1.
The main loop (babeld/babeld.c) then runs check_neighbours() - a scan of every
neighbour - at its next wakeup, and every wakeup while the stream lasts.

Measurement: count "Checking neighbours." debug lines in r1's babeld.log over
fixed windows.  The scan itself only runs at main-loop wakeups (their cadence
is set by the per-interface hello timers), so the attack multiplies the scan
rate by the wakeup rate, it does not force one scan per packet.

Topology: r1 with four babel interfaces, each a point-to-point link to one
of r2's interfaces, so r1 holds four neighbour entries for r2.  The
injected packets use r2's own link-local address on that link, so ignored
hellos leave no state trace and the only observable is the deadline/scan
behaviour.
"""

import os
import re
import sys
import time

import pytest

pytestmark = [pytest.mark.babeld]

CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

from lib.topogen import Topogen, get_topogen
from lib.topolog import logger

WINDOW_S = 30
RATE = 10  # packets/s, bounded injection rate
COUNT = WINDOW_S * RATE
PEER_NET = "10.98."
SCAN_LINE = b"Checking neighbours."
IGNORED_LINE = b"ignoring entire Hello TLV"


def build_topo(tgen):
    r1 = tgen.add_router("r1")
    r2 = tgen.add_router("r2")
    for i in range(4):
        tgen.add_link(r1, r2, ifname1="eth{}".format(i), ifname2="eth{}".format(i))


def setup_module(mod):
    tgen = Topogen(build_topo, mod.__name__)
    tgen.start_topology()
    for router in tgen.routers().values():
        router.load_frr_config()
    tgen.start_router()


def teardown_module():
    tgen = get_topogen()
    tgen.stop_topology()


def _r1_log_path(tgen):
    return os.path.join(tgen.logdir, "r1", "babeld.log")


def _count_in_slice(path, off0, off1, needle):
    try:
        with open(path, "rb") as fp:
            fp.seek(off0)
            blob = fp.read(max(0, off1 - off0))
    except OSError:
        return -1
    return blob.count(needle)


def _log_size(path):
    try:
        return os.path.getsize(path)
    except OSError:
        return 0


def _neighbours_up(r1):
    out = r1.vtysh_cmd("show babel neighbor")
    ups = [
        ln
        for ln in out.splitlines()
        if "Neighbour" in ln and "reach 0000" not in ln
    ]
    return len(ups), out


def _route_present(r1):
    return PEER_NET in r1.vtysh_cmd("show babel route")


def _wait_converged(r1, timeout=90):
    deadline = time.time() + timeout
    while time.time() < deadline:
        ups, _out = _neighbours_up(r1)
        if ups >= 4 and _route_present(r1):
            return True
        time.sleep(1)
    return False


def _measure_window(tgen, r2, label, kind, r2_ll, valid_src):
    """One measurement window; returns scan count (and ignored-hello count)."""
    path = _r1_log_path(tgen)
    time.sleep(2)  # let the previous window's deadline state settle
    off0 = _log_size(path)
    t0 = time.time()
    if kind == "idle":
        time.sleep(WINDOW_S)
    else:
        src = valid_src if kind == "valid400" else r2_ll
        out = r2.cmd(
            "python3 {}/send_hello.py --iface eth0 --src {} --kind {} "
            "--count {} --rate {}".format(CWD, src, kind, COUNT, RATE)
        )
        logger.info("window %s sender: %s", label, out.strip())
        time.sleep(1.5)  # grace for the last packets to be processed
    t1 = time.time()
    off1 = _log_size(path)
    scans = _count_in_slice(path, off0, off1, SCAN_LINE)
    ignored = _count_in_slice(path, off0, off1, IGNORED_LINE)
    logger.info(
        "window %-8s duration=%.1fs scans=%d ignored_hellos=%d",
        label, t1 - t0, scans, ignored,
    )
    return {"label": label, "seconds": round(t1 - t0, 1), "scans": scans,
            "ignored_hellos": ignored}


def test_babel_ignored_hello_check():
    tgen = get_topogen()
    r1 = tgen.gears["r1"]
    r2 = tgen.gears["r2"]

    converged = _wait_converged(r1)
    ups, neigh_out = _neighbours_up(r1)
    assert converged, "babel did not converge: neighbours up={}\n{}".format(
        ups, neigh_out)

    # r2's own link-local on eth0: injected packets reuse it so ignored
    # hellos hit the existing neighbour entries and leave no state trace
    out = r2.cmd("ip -6 addr show dev eth0 scope link")
    m = re.search(r"inet6 (fe80::[0-9a-f:]+)/\d+ scope link", out)
    assert m, "no link-local on r2-eth0: {}".format(out)
    r2_ll = m.group(1)
    # a second link-local for the valid-hello control (its neighbour entries
    # on r1 are protocol-normal and not part of the assertions)
    r2.cmd("ip -6 addr add fe80::222/64 dev eth0")
    valid_src = "fe80::222"

    baseline = _measure_window(tgen, r2, "idle", "idle", r2_ll, valid_src)
    garbage = _measure_window(tgen, r2, "garbage", "garbage", r2_ll, valid_src)
    valid = _measure_window(tgen, r2, "valid400", "valid400", r2_ll, valid_src)
    attack = _measure_window(tgen, r2, "ignored", "ignored", r2_ll, valid_src)

    # every injected mandatory-sub-TLV hello was processed as ignored
    assert attack["ignored_hellos"] == COUNT, (
        "expected {} ignored hellos, log shows {}".format(
            COUNT, attack["ignored_hellos"]))

    # controls must not measurably change the scan cadence
    control_cap = max(2 * baseline["scans"], baseline["scans"] + 8)
    assert garbage["scans"] <= control_cap, (
        "garbage control changed scan cadence: {}".format(garbage))
    assert valid["scans"] <= control_cap, (
        "valid-hello control changed scan cadence: {}".format(valid))

    # the ignored-hello stream must not pull the global neighbour check
    assert attack["scans"] <= control_cap, (
        "ignored hellos triggered extra check_neighbours scans: "
        "baseline={} garbage={} valid={} attack={}".format(
            baseline["scans"], garbage["scans"], valid["scans"],
            attack["scans"]))

    # valid-hello timer maintenance must be intact: neighbours and route
    # survive the whole run
    ups, neigh_out = _neighbours_up(r1)
    assert ups >= 4, "neighbours lost after windows:\n{}".format(neigh_out)
    assert _route_present(r1), "babel route lost after windows"
