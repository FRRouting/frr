#!/usr/bin/env python
# SPDX-License-Identifier: ISC
#
# Copyright (c) 2026 by 6WIND S.A.
#

"""
VPNv4 route reflector fanning a full table out to many eBGP VPE peers, with
the configuration of the vmsr0 routers (BGP_VPE_GRP / BGP_BCGW_GRP peer
groups, packet quanta, queue limits, coalesce time, update delay).

On vmsr0 the bgpd RSS grows x45 during a reconvergence: the VPE update
subgroups are split per peer and each one builds the adj-out of the whole
table. This test reproduces it at a smaller scale.

Topology (one LAN 10.0.0.0/24):

    bcgw1 (exabgp, AS 65100) .101 --+
    bcgw2 (exabgp, AS 65100) .102 --+-- s1 -- rr (AS 65000) .1
    vpe1..vpeN (AS 65201..)  .11.. --+

* bcgw1 and bcgw2 announce the same VPNv4 table of /32 prefixes
  over many customers (RD/RT 65100:<n>). The rr peers them with a
  local-as 65001 no-prepend, as vmsr0 does with its BCGW.
* Each VPE has its own AS, exports one prefix from its vrf CUST and keeps
  the VPNv4 routes it receives in its VPN RIB (no import in a vrf, so that
  the VPEs do not install the table in their kernel).

Timeline: from the initial load to the end, the rr is sampled every
RR_SAMPLE_INTERVAL seconds:
* <logdir>/memory_timeline.csv: bgpd RSS, current count / KB of update
  subgroups, adj-out, adv, BGP packets and streams, number of VPE subgroups,
  established VPEs, total / max BGP output queue and TCP send queue
* <logdir>/links_timeline.csv: per VPE, session state, subgroup, BGP output
  queue and TCP send queue of the rr towards it
Rows are tagged with the current phase (load, scenario, merge, release).

Memory snapshots: the whole "show memory bgpd" of the rr, with its
/proc/<pid>/smaps_rollup, after the load and before / after each scenario:
* <logdir>/memory_<NN>_<label>.txt: raw snapshot
* <logdir>/memory_types.csv: count and KB of every memory type (section:
  type) at each snapshot, sorted by KB at the last one, with the VmRSS

Scenarios, from the converged state, each one followed by the merge of the
VPE subgroups back into one:
* vpe_refresh_one: one VPE sends a ROUTE-REFRESH to the rr ("clear bgp
  ipv4 vpn <rr> soft" on the VPE, no session reset), as the field VPEs do
  when a vrf / RT import is provisioned: the rr moves that peer to its own
  subgroup (update_subgroup_split_peer()) and rebuilds the adj-out of the
  whole table for it in one bgp_announce_route_timer_expired() call
* vpe_refresh_burst: RR_REFRESH_NB VPEs do the same, one every
  RR_REFRESH_INTERVAL seconds (more than the 500 ms announce delay, so that
  the rr does not combine them): one split and one whole-table adj-out per
  VPE, the suspected path to the field RSS peak
* vpe_refresh_churn: vpe_refresh_burst under organic background route churn
  (both BCGW continuously re-announce a small rotating slice of
  RR_CHURN_RATE routes every RR_CHURN_PERIOD seconds, toggling the MED,
  mimicking the low-rate ambient churn observed in the field): the ambient
  churn may keep the per-VPE subgroups from merging back for longer than
  in vpe_refresh_burst's quiet table
For each scenario (<logdir>/scenarios.csv): convergence time, bgpd RSS before
and peak, peaks of the memory types, of the VPE subgroups and of the queues,
min established VPEs, subgroup splits logged by "debug bgp update-groups",
and, sampled as a before/after snapshot around the scenario ("show event
cpu" counters are never reset: "clear thread cpu" is a known upstream
use-after-free on this branch, FRRouting/frr#16419, fixed upstream by
cae176e10a but not backported here):
* <event>_calls / <event>_wall_ms / max_<event>_wall_ms: number of calls,
  wall-clock time spent (avg x calls) during the scenario, and worst
  single-call wall-clock duration since bgpd started, of the bgpd
  event-loop callbacks most likely to monopolize it while rebuilding a VPE
  subgroup's adj-out ("show event cpu" on the rr, Real columns)
* refresh_recv: ROUTE-REFRESH messages received by the rr from the VPEs

Configurations: rr/frr.conf, vpe<N>/frr.conf, bcgw<N>/exabgp.cfg, generated
by gen_configs.py (20 VPEs, 20000 routes in 50 vrfs, update-delay 180 by
default); to change the scale, regenerate them, e.g.:
    ./gen_configs.py --vpe-nb 40 --routes 50000 --update-delay 0
The test takes the scale from these files.

Environment variables:
    RR_VPE_NB: run with fewer VPEs than configured (default: all)
    RR_SAMPLE_INTERVAL (2): seconds between two timeline samples
    RR_CHURN_RATE (50 routes), RR_CHURN_PERIOD (3s): size and period of the
    rotating slice re-announced by vpe_refresh_churn's background churn
    RR_REFRESH_NB (half of the VPEs), RR_REFRESH_INTERVAL (2s): VPEs sending
    a ROUTE-REFRESH in vpe_refresh_burst, and seconds between two of them
    RR_READ_QUANTA: override the "read-quanta" of rr/frr.conf (64 as on the
    field): each BGP connection of the rr allocates a read ring buffer of
    65535 x read-quanta bytes ("libfrr: Ring buffer" in show memory)
    RR_MAX_VPE_SUBGROUPS (0: report only, else fail a scenario when more
    VPE subgroups are seen)
"""

import contextlib
import functools
import os
import re
import sys
import threading
import time

import pytest

CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

# pylint: disable=C0413
from lib import topotest
from lib.common_config import step
from lib.topogen import Topogen, get_topogen
from lib.topolog import logger

pytestmark = [pytest.mark.bgpd]

MAX_VPE_SUBGROUPS = int(os.environ.get("RR_MAX_VPE_SUBGROUPS", "0"))
SAMPLE_INTERVAL = int(os.environ.get("RR_SAMPLE_INTERVAL", "2"))
# vtysh timeout of the latency probe: 12s is the yams timeout of the incident
VTY_TIMEOUT = int(os.environ.get("RR_VTY_TIMEOUT", "12"))
CHURN_RATE = int(os.environ.get("RR_CHURN_RATE", "50"))
CHURN_PERIOD = float(os.environ.get("RR_CHURN_PERIOD", "3"))
REFRESH_INTERVAL = float(os.environ.get("RR_REFRESH_INTERVAL", "2"))
# vpe_refresh_churn: organic churn before the first ROUTE-REFRESH, and kept
# running after the last one, to see if it prevents the subgroups merge
REFRESH_CHURN_WARMUP = float(os.environ.get("RR_REFRESH_CHURN_WARMUP", "30"))
REFRESH_CHURN_HOLD = float(os.environ.get("RR_REFRESH_CHURN_HOLD", "180"))
READ_QUANTA = os.environ.get("RR_READ_QUANTA")

RR_ADDR = "10.0.0.1"
BCGWS = {"bcgw1": "10.0.0.101", "bcgw2": "10.0.0.102"}



def read_scale():
    """Number of VPEs, routes, vrfs and update delay of the config files."""
    vpe_nb = 0
    while os.path.isfile(os.path.join(CWD, "vpe{}".format(vpe_nb + 1), "frr.conf")):
        vpe_nb += 1
    # run with fewer VPEs than configured on the rr (the others stay Active)
    vpe_nb = min(vpe_nb, int(os.environ.get("RR_VPE_NB", vpe_nb)))
    with open(os.path.join(CWD, "bcgw1", "exabgp.cfg"), encoding="utf-8") as f:
        match = re.search(r"exa-bcgw\.py \S+ \S+ (\d+) (\d+);", f.read())
    with open(os.path.join(CWD, "rr", "frr.conf"), encoding="utf-8") as f:
        delay = re.search(r"^ update-delay (\d+)", f.read(), re.MULTILINE)
    return (
        vpe_nb,
        int(match.group(1)),
        int(match.group(2)),
        int(delay.group(1)) if delay else 0,
    )


# Scale of the configuration files (see gen_configs.py)
VPE_NB, ROUTES, VRFS, UPDATE_DELAY = read_scale()


# convergence timeout: update-delay + advertisement-interval + table size
CONVERGENCE_WAIT = 5
CONVERGENCE_COUNT = (UPDATE_DELAY + 120 + ROUTES * VPE_NB // 2000) // CONVERGENCE_WAIT

assert VPE_NB >= 1, "no vpe<N>/frr.conf: run gen_configs.py"

# VPEs sending a ROUTE-REFRESH in vpe_refresh_burst
REFRESH_NB = min(VPE_NB, int(os.environ.get("RR_REFRESH_NB", max(1, VPE_NB // 2))))


def vpe_name(index):
    return "vpe{}".format(index)


def vpe_addr(index):
    return "10.0.0.{}".format(10 + index)


## Topology
def build_topo(tgen):
    switch = tgen.add_switch("s1")
    switch.add_link(tgen.add_router("rr"))
    for index in range(1, VPE_NB + 1):
        switch.add_link(tgen.add_router(vpe_name(index)))
    for name, addr in BCGWS.items():
        peer = tgen.add_exabgp_peer(
            name, ip="{}/24".format(addr), defaultRoute="via " + RR_ADDR
        )
        switch.add_link(peer)


def rr_config(tgen):
    """
    Path of the rr config: rr/frr.conf, or a copy in the logdir with the
    read-quanta set to RR_READ_QUANTA. It must be in the config loaded at
    start: a connection sizes its read ring buffer when it is created.
    """
    path = os.path.join(CWD, "rr", "frr.conf")
    if not READ_QUANTA:
        return path
    with open(path, encoding="utf-8") as f:
        config = f.read()
    line = " read-quanta {}".format(int(READ_QUANTA))
    config, count = re.subn(r"^ read-quanta \d+$", line, config, flags=re.MULTILINE)
    if not count:
        config = re.sub(
            r"^(router bgp \d+)$", r"\1\n" + line, config, count=1, flags=re.MULTILINE
        )
    path = os.path.join(tgen.logdir, "rr_frr.conf")
    with open(path, "w", encoding="utf-8") as f:
        f.write(config)
    logger.info("rr: read-quanta %s (%s)", READ_QUANTA, path)
    return path


def setup_module(mod):
    tgen = Topogen(build_topo, mod.__name__)
    tgen.start_topology()

    tgen.gears["rr"].load_frr_config(rr_config(tgen))
    for index in range(1, VPE_NB + 1):
        name = vpe_name(index)
        router = tgen.gears[name]
        router.cmd_raises("ip link add CUST type vrf table 10 && ip link set CUST up")
        router.load_frr_config(os.path.join(CWD, name, "frr.conf"))
    tgen.start_router()

    if not tgen.get_exabgp_cmd():
        # topogen hides why: run the version check again and show its errors
        details = []
        for cmd in ("exabgp --version", "python3 -m exabgp --version"):
            rc, out, err = tgen.net.cmd_status(cmd, warn=False)
            details.append(
                "{}: rc {}\nstdout: {}\nstderr: {}".format(cmd, rc, out, err)
            )
        pytest.fail("no usable ExaBGP in the namespace:\n" + "\n".join(details))

    # memory and rr-VPE links over the whole test, from the initial load
    TIMELINE.append(Timeline(tgen))
    TIMELINE[0].start()

    for name in BCGWS:
        peer_dir = os.path.join(CWD, name)
        tgen.gears[name].start(peer_dir, os.path.join(CWD, "exabgp.env"))


def teardown_module(mod):
    tgen = get_topogen()
    if TIMELINE:
        TIMELINE[0].stop()
    tgen.stop_topology()


## Helpers
COMMAND_SEQ = [0]


def bcgw_command(tgen, name, command, timeout=None):
    """
    Give a command to the exa-bcgw.py process of a BCGW (see the script) and
    wait until it is executed: the whole table is written to exabgp, allow
    one second per 1000 routes (60s at least).
    """
    if timeout is None:
        timeout = max(60, ROUTES // 1000)
    COMMAND_SEQ[0] += 1
    path = "/etc/exabgp/cmd-{:04d}".format(COMMAND_SEQ[0])
    gear = tgen.gears[name]
    # rename: the script never reads a partial file
    gear.run("echo '{0}' > {1}.tmp && chmod 644 {1}.tmp && mv {1}.tmp {1}".format(
        command, path
    ))

    def done():
        output = gear.run("test -f {}.done && echo DONE".format(path))
        return None if "DONE" in output else "not executed"

    _, result = topotest.run_and_expect(done, None, count=timeout, wait=1)
    assert result is None, "{}: command '{}' {} after {}s".format(
        name, command, result, timeout
    )


MEMORY_TYPES = (
    "BGP update subgroup",
    "BGP adj out",
    "BGP adv",
    "BGP packet",
    "Stream",
    "Ring buffer",
)


def bgpd_memory(router, types=MEMORY_TYPES):
    """
    ``show memory bgpd`` counters: {type: (current, current bytes, max,
    max bytes)}. Max is since bgpd start.
    """
    output = router.vtysh_cmd("show memory bgpd")
    memory = {}
    for line in output.splitlines():
        match = re.match(r"^(.+?)\s*:\s*(\d+)\s+\S+\s+(\d+)\s+(\d+)\s+(\d+)\s*$", line)
        if match and match.group(1) in types:
            memory[match.group(1)] = tuple(int(match.group(i)) for i in range(2, 6))
    return memory


def log_memory(router, label):
    for mtype, (cur, cur_bytes, mx, max_bytes) in bgpd_memory(router).items():
        logger.info(
            "%s: %s current %d (%d KB), max %d (%d KB)",
            label, mtype, cur, cur_bytes // 1024, mx, max_bytes // 1024,
        )


MEMORY_SNAPSHOTS = []
SHOW_MEMORY_LINE = re.compile(
    r"^(.+?)\s*:\s*(\d+)\s+(\S+)\s+(\d+)\s+(\d+)\s+(\d+)\s*$"
)


def parse_show_memory(output):
    """{"section: type": (current count, current bytes)} of show memory."""
    memory = {}
    section = ""
    for line in output.splitlines():
        if line.startswith("--- qmem "):
            section = line.strip("- ").replace("qmem ", "", 1)
            continue
        match = SHOW_MEMORY_LINE.match(line)
        if match:
            key = "{}: {}".format(section, match.group(1).strip())
            memory[key] = (int(match.group(2)), int(match.group(4)))
    return memory


def memory_snapshot(tgen, label):
    """
    Whole "show memory bgpd" of the rr and its smaps_rollup:
    <logdir>/memory_<NN>_<label>.txt, and one more column pair in
    <logdir>/memory_types.csv.
    """
    rr = tgen.gears["rr"]
    pid = rr.run("cat /var/run/frr/bgpd.pid").strip()
    output = rr.vtysh_cmd("show memory bgpd")
    smaps = rr.run("cat /proc/{}/smaps_rollup".format(pid))
    rss_kb = rr_bgpd_rss_kb(rr)
    name = "memory_{:02d}_{}.txt".format(
        len(MEMORY_SNAPSHOTS), re.sub(r"\W+", "_", label)
    )
    with open(os.path.join(tgen.logdir, name), "w", encoding="utf-8") as f:
        f.write(
            "=== {} VmRSS {} kB\n=== smaps_rollup\n{}\n".format(label, rss_kb, smaps)
        )
        f.write("=== show memory bgpd\n{}\n".format(output))
    memory = parse_show_memory(output)
    MEMORY_SNAPSHOTS.append((label, rss_kb, memory))

    types = set()
    for _, _, snapshot in MEMORY_SNAPSHOTS:
        types.update(snapshot)
    order = sorted(types, key=lambda t: -memory.get(t, (0, 0))[1])
    csv_path = os.path.join(tgen.logdir, "memory_types.csv")
    with open(csv_path, "w", encoding="utf-8") as f:
        header = ["type"]
        for snap_label, _, _ in MEMORY_SNAPSHOTS:
            header += [snap_label + " count", snap_label + " KB"]
        f.write(";".join(header) + "\n")
        f.write(
            ";".join(
                ["VmRSS"] + ["{};{}".format("", rss) for _, rss, _ in MEMORY_SNAPSHOTS]
            )
            + "\n"
        )
        for mtype in order:
            cells = [mtype]
            for _, _, snapshot in MEMORY_SNAPSHOTS:
                count, size = snapshot.get(mtype, (0, 0))
                cells += [str(count), str(size // 1024)]
            f.write(";".join(cells) + "\n")

    top = sorted(memory.items(), key=lambda item: -item[1][1])[:10]
    logger.info(
        "memory %s: VmRSS %d KB, top types: %s",
        label, rss_kb,
        ", ".join("{} {} KB".format(t, size // 1024) for t, (_, size) in top),
    )


# The two bgpd event-loop callbacks most likely to monopolize bm->master
# (the single shared threadmaster also serving vty, FSM and every other
# peer's I/O) while they rebuild a VPE subgroup's adj-out of the whole
# table: the coalesce timer that (re)announces a subgroup, and the packet
# generation triggered for a peer once its subgroup has something to send.
EVENT_CPU_FUNCS = (
    "subgroup_coalesce_timer",
    "bgp_generate_updgrp_packets",
    "bgp_announce_route_timer_expired",
)

# "show event cpu" row: Active Runtime(ms) Invoked AvgUsec MaxUsecs(CPU)
# AvgUsec MaxUsecs(Real) CPU_Warn Wall_Warn Starv_Warn  Type  Event
EVENT_CPU_LINE = re.compile(
    r"^\s*(\d+)\s+([\d.]+)\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)"
    r"\s+(\d+)\s+(\d+)\s+(\d+)\s+[RWTEX ]+\s+(\S.*)$"
)


def event_cpu_stats(router, funcs=EVENT_CPU_FUNCS):
    """
    {func: (calls, wall-clock us, worst single-call wall-clock us)} of
    ``func`` since the daemon started, summed over the pthreads, from "show
    event cpu" on ``router``. The wall-clock ("Real") columns are always
    accurate (unlike CPU time, gated by "service cputime-stats"); the total
    is rebuilt as Avg uSec x Invoked.

    These counters cannot be reset between scenarios on this branch: "clear
    thread cpu" there frees the CLI thread's own still-in-use stats record
    (upstream use-after-free FRRouting/frr#16419, fixed upstream by
    cae176e10a but not backported here) and crashes the daemon. Use
    event_cpu_delta() on a before/after pair of these snapshots instead.
    """
    output = router.vtysh_cmd("show event cpu")
    stats = {func: (0, 0, 0) for func in funcs}
    for line in output.splitlines():
        match = EVENT_CPU_LINE.match(line)
        if not match or match.group(11).strip() not in funcs:
            continue
        func = match.group(11).strip()
        calls, avg_us, max_us = (int(match.group(i)) for i in (3, 6, 7))
        prev = stats[func]
        stats[func] = (prev[0] + calls, prev[1] + calls * avg_us, max(prev[2], max_us))
    return stats


def event_cpu_delta(before, after):
    """
    From two event_cpu_stats() snapshots, for each ``func``:
    * "<func>_calls": calls between ``before`` and ``after``
    * "<func>_wall_ms": wall-clock time spent in these calls
    * "max_<func>_wall_ms": worst single-call duration since bgpd started
      (a cumulative maximum: it cannot be reset, see event_cpu_stats()),
      followed by "*" when this worst call happened in the window
    A long one-shot call here, concurrent with a vty or other-peer delay in
    the timeline, is the direct evidence of a cascade.
    """
    delta = {}
    for func, (calls, wall_us, max_us) in after.items():
        b_calls, b_wall_us, b_max_us = before.get(func, (0, 0, 0))
        delta["{}_calls".format(func)] = calls - b_calls
        delta["{}_wall_ms".format(func)] = round((wall_us - b_wall_us) / 1000)
        delta["max_{}_wall_ms".format(func)] = "{}{}".format(
            round(max_us / 1000, 1), "*" if max_us > b_max_us else ""
        )
    return delta


def vpe_update_groups(rr):
    """{vpe address: (update group, subgroup)} of the VPE peers in ipv4 vpn."""
    output = rr.vtysh_cmd("show bgp neighbors json", isjson=True) or {}
    groups = {}
    for index in range(1, VPE_NB + 1):
        neighbor = output.get(vpe_addr(index), {})
        afi = neighbor.get("addressFamilyInfo", {}).get("ipv4Vpn", {})
        groups[vpe_addr(index)] = (afi.get("updateGroupId"), afi.get("subGroupId"))
    return groups


## Checks
def check_rr_converged(rr):
    output = rr.vtysh_cmd("show bgp ipv4 vpn summary json", isjson=True) or {}
    peers = output.get("peers", {})
    for addr in BCGWS.values():
        peer = peers.get(addr, {})
        if peer.get("state") != "Established" or peer.get("pfxRcd") != ROUTES:
            return "bcgw {}: {} {}".format(addr, peer.get("state"), peer.get("pfxRcd"))
    for index in range(1, VPE_NB + 1):
        peer = peers.get(vpe_addr(index), {})
        if peer.get("state") != "Established" or peer.get("pfxRcd") != 1:
            return "vpe {}: {} {}".format(
                vpe_addr(index), peer.get("state"), peer.get("pfxRcd")
            )
    return None


def check_vpe_converged(vpe):
    # the table from the BCGW, plus the prefix of each other VPE
    expected = ROUTES + VPE_NB - 1
    output = vpe.vtysh_cmd("show bgp ipv4 vpn summary json", isjson=True) or {}
    peer = output.get("peers", {}).get(RR_ADDR, {})
    if peer.get("state") != "Established" or peer.get("pfxRcd") != expected:
        return "{} from rr: {} {}/{}".format(
            vpe.name, peer.get("state"), peer.get("pfxRcd"), expected
        )
    return None


def wait_convergence(tgen):
    rr = tgen.gears["rr"]
    _, result = topotest.run_and_expect(
        functools.partial(check_rr_converged, rr), None,
        count=CONVERGENCE_COUNT, wait=CONVERGENCE_WAIT,
    )
    assert result is None, "rr not converged: {}".format(result)
    for index in range(1, VPE_NB + 1):
        vpe = tgen.gears[vpe_name(index)]
        _, result = topotest.run_and_expect(
            functools.partial(check_vpe_converged, vpe), None,
            count=CONVERGENCE_COUNT, wait=CONVERGENCE_WAIT,
        )
        assert result is None, "VPE not converged: {}".format(result)


## Tests
def test_bgp_convergence():
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    step("Wait for the rr and the {} VPEs to get the VPNv4 routes".format(VPE_NB))
    wait_convergence(tgen)
    log_memory(tgen.gears["rr"], "initial load")
    memory_snapshot(tgen, "load")


def check_one_subgroup(rr):
    groups = vpe_update_groups(rr)
    updgrps = {g for g, _ in groups.values()}
    subgrps = set(groups.values())
    if len(updgrps) != 1 or None in updgrps or len(subgrps) != 1:
        return "update groups {}, subgroups {}".format(
            sorted(map(str, updgrps)), sorted(map(str, subgrps))
        )
    return None


def wait_one_subgroup(rr):
    _, result = topotest.run_and_expect(
        functools.partial(check_one_subgroup, rr), None, count=60, wait=5
    )
    assert result is None, "VPE peers not in one subgroup: {}".format(result)


def test_vpe_update_group():
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    rr = tgen.gears["rr"]

    step("All the VPE peers share one update group and, once merged, one subgroup")
    wait_one_subgroup(rr)
    log_memory(rr, "steady state")


## Timeline
def rr_bgpd_rss_kb(rr):
    pid = rr.run("cat /var/run/frr/bgpd.pid").strip()
    rss = rr.run("awk '/^VmRSS:/ {{print $2}}' /proc/{}/status".format(pid)).strip()
    return int(rss) if rss.isdigit() else 0


CLK_TCK = os.sysconf("SC_CLK_TCK")

# One command in the rr namespace: bgpd pid, CPU ticks of the process and
# of its main thread, latency of a vty request served by all the daemons
# (the yams / Zabbix one) and of one served by bgpd only.
RR_PROBE = (
    "pid=$(cat /var/run/frr/bgpd.pid); "
    "echo pid $pid; "
    "echo proc $(cat /proc/$pid/stat); "
    "echo main $(cat /proc/$pid/task/$pid/stat); "
    "t0=$(date +%s%N); "
    "timeout {0} vtysh -c 'show running-config' > /dev/null 2>&1; "
    "echo vty $? $(( ($(date +%s%N) - t0) / 1000000 )); "
    "t0=$(date +%s%N); "
    "timeout {0} vtysh -d bgpd -c 'show bgp ipv4 vpn summary' > /dev/null 2>&1; "
    "echo bgpd_vty $? $(( ($(date +%s%N) - t0) / 1000000 ))"
)


def stat_ticks(line):
    """utime + stime of a /proc/<pid>/stat line (the name may hold spaces)."""
    fields = line.rsplit(")", 1)[-1].split()
    # fields[0] is the state (field 3): utime and stime are fields 14 and 15
    return int(fields[11]) + int(fields[12])


def rr_probe(rr):
    """
    {"pid", "ticks", "main_ticks", "vty_ms", "vty_rc", "bgpd_vty_ms",
    "bgpd_vty_rc"} of the rr bgpd.
    """
    probe = {}
    for line in rr.run(RR_PROBE.format(VTY_TIMEOUT)).splitlines():
        fields = line.split(None, 1)
        if len(fields) < 2:
            continue
        key, value = fields
        try:
            if key == "pid":
                probe["pid"] = int(value)
            elif key == "proc":
                probe["ticks"] = stat_ticks(value)
            elif key == "main":
                probe["main_ticks"] = stat_ticks(value)
            elif key in ("vty", "bgpd_vty"):
                rc, ms = value.split()
                probe[key + "_rc"], probe[key + "_ms"] = int(rc), int(ms)
        except (ValueError, IndexError):
            continue
    return probe


def rr_tcp_queues(rr):
    """{peer address: (recv-q, send-q)} of the established BGP sockets of the rr."""
    queues = {}
    output = rr.run("ss -tnH state established '( sport = :179 or dport = :179 )'")
    for line in output.splitlines():
        fields = line.split()
        if len(fields) >= 4 and fields[0].isdigit() and fields[1].isdigit():
            queues[fields[3].rsplit(":", 1)[0]] = (int(fields[0]), int(fields[1]))
    return queues


class Timeline(threading.Thread):
    """
    Samples the rr every SAMPLE_INTERVAL seconds until stopped:
    * <logdir>/memory_timeline.csv: bgpd RSS, CPU of the bgpd process and
      of its main thread (% of one core since the previous sample), latency
      of "show running-config" (all daemons, timeout = 124) and of a bgpd
      only request, current count / KB of the MEMORY_TYPES, number of VPE
      subgroups, established VPEs, total and max BGP output queue and TCP
      send queue towards the VPEs
    * <logdir>/links_timeline.csv: per VPE, session state, subgroup, BGP
      output queue (messages) and TCP send queue (bytes) on the rr
    Each row is tagged with the current phase (set_phase()).
    """

    def __init__(self, tgen):
        super().__init__(daemon=True)
        self.rr = tgen.gears["rr"]
        self.begin = time.time()
        self.phase = "load"
        self.rows = []
        self.lock = threading.Lock()
        self.stopped = threading.Event()
        self.memory_file = open(  # pylint: disable=consider-using-with
            os.path.join(tgen.logdir, "memory_timeline.csv"), "w", encoding="utf-8"
        )
        self.links_file = open(  # pylint: disable=consider-using-with
            os.path.join(tgen.logdir, "links_timeline.csv"), "w", encoding="utf-8"
        )
        self.prev = None
        self.columns = [
            "time", "phase", "rss_kb", "cpu_pct", "main_cpu_pct",
            "vty_ms", "vty_rc", "bgpd_vty_ms", "bgpd_vty_rc",
        ]
        for mtype in MEMORY_TYPES:
            key = memory_key(mtype)
            self.columns += [key, key + "_kb"]
        self.columns += [
            "vpe_subgroups", "vpe_established", "outq_total", "outq_max",
            "sendq_total", "sendq_max",
        ]
        self.memory_file.write(";".join(self.columns) + "\n")
        self.links_file.write("time;phase;vpe;state;subgroup;outq;tcp_sendq\n")

    def set_phase(self, phase):
        self.phase = phase

    def stop(self):
        self.stopped.set()
        self.join(timeout=60)
        self.memory_file.close()
        self.links_file.close()

    def run(self):
        while not self.stopped.is_set():
            try:
                self.sample()
            except Exception as e:  # pylint: disable=broad-except
                # bgpd too busy or not started yet: the next sample will do
                logger.info("timeline sample failed: %s", e)
            self.stopped.wait(SAMPLE_INTERVAL)

    def sample(self):
        wall = time.time()
        now = round(wall - self.begin, 1)
        row = {"time": now, "phase": self.phase, "rss_kb": rr_bgpd_rss_kb(self.rr)}
        probe = rr_probe(self.rr)
        for key in ("vty_ms", "vty_rc", "bgpd_vty_ms", "bgpd_vty_rc"):
            row[key] = probe.get(key)
        row["cpu_pct"] = row["main_cpu_pct"] = None
        if "ticks" in probe and "main_ticks" in probe:
            current = (wall, probe.get("pid"), probe["ticks"], probe["main_ticks"])
            # no CPU on the first sample or after a bgpd restart
            if self.prev and self.prev[1] == current[1] and wall > self.prev[0]:
                elapsed = (wall - self.prev[0]) * CLK_TCK
                row["cpu_pct"] = round(100 * (current[2] - self.prev[2]) / elapsed, 1)
                row["main_cpu_pct"] = round(
                    100 * (current[3] - self.prev[3]) / elapsed, 1
                )
            self.prev = current
        memory = bgpd_memory(self.rr)
        for mtype in MEMORY_TYPES:
            cur, cur_bytes, _, _ = memory.get(mtype, (0, 0, 0, 0))
            row[memory_key(mtype)] = cur
            row[memory_key(mtype) + "_kb"] = cur_bytes // 1024
        neighbors = self.rr.vtysh_cmd("show bgp neighbors json", isjson=True) or {}
        tcp = rr_tcp_queues(self.rr)
        links = []
        for index in range(1, VPE_NB + 1):
            addr = vpe_addr(index)
            nbr = neighbors.get(addr, {})
            afi = nbr.get("addressFamilyInfo", {}).get("ipv4Vpn", {})
            links.append(
                {
                    "vpe": vpe_name(index),
                    "state": nbr.get("bgpState"),
                    "subgroup": "u{}:s{}".format(
                        afi.get("updateGroupId"), afi.get("subGroupId")
                    ),
                    "outq": nbr.get("messageStats", {}).get("depthOutq", 0),
                    "tcp_sendq": tcp.get(addr, (0, 0))[1],
                }
            )
        up = [link for link in links if link["state"] == "Established"]
        row["vpe_subgroups"] = len({link["subgroup"] for link in up})
        row["vpe_established"] = len(up)
        row["outq_total"] = sum(link["outq"] for link in links)
        row["outq_max"] = max((link["outq"] for link in links), default=0)
        row["sendq_total"] = sum(link["tcp_sendq"] for link in links)
        row["sendq_max"] = max((link["tcp_sendq"] for link in links), default=0)
        with self.lock:
            self.rows.append(row)
        self.memory_file.write(";".join(str(row[c]) for c in self.columns) + "\n")
        self.memory_file.flush()
        for link in links:
            self.links_file.write(
                "{};{};{vpe};{state};{subgroup};{outq};{tcp_sendq}\n".format(
                    now, self.phase, **link
                )
            )
        self.links_file.flush()

    def window(self, begin, end):
        """Rows sampled between two time.time() values."""
        with self.lock:
            return [
                r for r in self.rows
                if begin - self.begin <= r["time"] <= end - self.begin
            ]

    def last(self):
        with self.lock:
            return self.rows[-1] if self.rows else {}


TIMELINE = []


def memory_key(mtype):
    return mtype.lower().replace("bgp ", "").replace(" ", "_")


## Scenarios
def wait_until(check, timeout, wait=2, progress=30):
    """
    Wait until check() returns None. Returns the elapsed seconds. Logs the
    state and the last timeline sample every ``progress`` seconds.
    """
    begin = last = time.time()
    while True:
        result = check()
        elapsed = time.time() - begin
        if result is None:
            return elapsed
        assert elapsed < timeout, "timeout: {}".format(result)
        if time.time() - last >= progress:
            last = time.time()
            row = TIMELINE[0].last() if TIMELINE else {}
            logger.info(
                "waiting %ds: %s | rss %s KB, VPE subgroups %s, outq %s, sendq %s",
                elapsed, result, row.get("rss_kb"), row.get("vpe_subgroups"),
                row.get("outq_total"), row.get("sendq_total"),
            )
            logger.info(
                "        bgpd cpu %s%% (main thread %s%%), vty %s ms, bgpd vty %s ms",
                row.get("cpu_pct"), row.get("main_cpu_pct"), row.get("vty_ms"),
                row.get("bgpd_vty_ms"),
            )
        time.sleep(wait)


def all_converged(tgen):
    result = check_rr_converged(tgen.gears["rr"])
    if result:
        return result
    for index in range(1, VPE_NB + 1):
        result = check_vpe_converged(tgen.gears[vpe_name(index)])
        if result:
            return result
    return None


class DebugLog:
    """Update-group debug lines logged by the rr bgpd since creation."""

    SPLIT = re.compile(r"peer (\S+) split and moved")

    def __init__(self, tgen):
        self.path = os.path.join(tgen.logdir, "rr", "bgpd.log")
        self.offset = os.path.getsize(self.path) if os.path.exists(self.path) else 0

    def summary(self):
        splits, merges, created = 0, 0, 0
        peers = set()
        if os.path.exists(self.path):
            with open(self.path, encoding="utf-8", errors="replace") as f:
                f.seek(self.offset)
                for line in f:
                    match = self.SPLIT.search(line)
                    if match:
                        splits += 1
                        peers.add(match.group(1))
                    merges += "merged into" in line
                    created += "create subgroup" in line
        return {
            "splits": splits,
            "peers_split": len(peers),
            "subgroups_created": created,
            "merges": merges,
        }


RESULTS = []


def report(tgen, name, begin, converged_s, debug, extra=None):
    """
    One row of <logdir>/scenarios.csv from the timeline of the scenario:
    RSS before / peak, peaks of the memory types, of the VPE subgroups and
    of the queues, min of the established VPEs, subgroup debug summary,
    and ``extra`` (refresh_recv / event_cpu_delta() cascade signals).
    """
    rows = TIMELINE[0].window(begin, time.time())
    before = TIMELINE[0].window(begin - 3 * SAMPLE_INTERVAL, begin)
    row = {"scenario": name, "convergence_s": round(converged_s)}
    row["rss_before_kb"] = before[-1]["rss_kb"] if before else None
    row["rss_peak_kb"] = max((r["rss_kb"] for r in rows), default=None)
    for key in ["vpe_subgroups", "outq_total", "outq_max", "sendq_total", "sendq_max"]:
        row["max_" + key] = max((r[key] for r in rows), default=None)
    row["min_vpe_established"] = min((r["vpe_established"] for r in rows), default=None)
    for key in ["cpu_pct", "main_cpu_pct", "vty_ms", "bgpd_vty_ms"]:
        values = [r[key] for r in rows if r.get(key) is not None]
        row["max_" + key] = max(values, default=None)
        if key.endswith("cpu_pct"):
            row["avg_" + key] = round(sum(values) / len(values), 1) if values else None
    row["vty_timeouts"] = sum(1 for r in rows if r.get("vty_rc") == 124)
    row["bgpd_vty_timeouts"] = sum(1 for r in rows if r.get("bgpd_vty_rc") == 124)
    for mtype in MEMORY_TYPES:
        key = memory_key(mtype)
        row["max_" + key] = max((r[key] for r in rows), default=None)
        row["max_" + key + "_kb"] = max((r[key + "_kb"] for r in rows), default=None)
    row.update(debug.summary())
    if extra:
        row.update(extra)
    RESULTS.append(row)
    logger.info("scenario %s: %s", name, row)
    # union of the columns: the scenarios do not all report the same extras
    columns = []
    for result in RESULTS:
        columns += [c for c in result if c not in columns]
    with open(os.path.join(tgen.logdir, "scenarios.csv"), "w", encoding="utf-8") as f:
        f.write(";".join(columns) + "\n")
        for result in RESULTS:
            f.write(";".join(str(result.get(c)) for c in columns) + "\n")
    if MAX_VPE_SUBGROUPS:
        assert (row["max_vpe_subgroups"] or 0) <= MAX_VPE_SUBGROUPS, (
            "{}: {} VPE subgroups (max {}), {} peers split".format(
                name, row["max_vpe_subgroups"], MAX_VPE_SUBGROUPS, row["peers_split"]
            )
        )


def rr_refresh_recv(rr):
    """ROUTE-REFRESH messages received by the rr from the VPEs since start."""
    output = rr.vtysh_cmd("show bgp neighbors json", isjson=True) or {}
    return sum(
        output.get(vpe_addr(index), {}).get("messageStats", {}).get("routeRefreshRecv", 0)
        for index in range(1, VPE_NB + 1)
    )


def run_scenario(tgen, name, trigger, converged, timeout):
    """
    Trigger, wait for convergence, wait for the merge of the VPE subgroups,
    report. The timeline rows are tagged with the scenario name. ``trigger``
    may return a dict (e.g. subgroups_at_churn_stop) merged into the report;
    "show event cpu" is sampled right before it runs and right after the
    merge, to catch a new worst single-call stall set during the scenario
    (see event_cpu_delta()).
    """
    rr = tgen.gears["rr"]
    wait_one_subgroup(rr)
    debug = DebugLog(tgen)
    memory_snapshot(tgen, name + " before")
    event_cpu_before = event_cpu_stats(rr)
    refresh_before = rr_refresh_recv(rr)
    begin = time.time()
    TIMELINE[0].set_phase(name)
    extra = trigger() or {}
    wait_until(converged, timeout)
    converged_s = time.time() - begin
    # the subgroups merge back after the convergence
    TIMELINE[0].set_phase(name + " merge")
    wait_until(functools.partial(check_one_subgroup, rr), 300)
    extra["refresh_recv"] = rr_refresh_recv(rr) - refresh_before
    extra.update(event_cpu_delta(event_cpu_before, event_cpu_stats(rr)))
    TIMELINE[0].set_phase("idle")
    memory_snapshot(tgen, name + " after")
    report(tgen, name, begin, converged_s, debug, extra)


def scenario_timeout():
    return CONVERGENCE_COUNT * CONVERGENCE_WAIT


def bcgw_churn(tgen, offset, count, med):
    for name in BCGWS:
        bcgw_command(tgen, name, "churn {} {} {}".format(offset, count, med), timeout=30)


def organic_churn_loop(tgen, stop_event, rate=CHURN_RATE, period=CHURN_PERIOD):
    """
    Continuously re-announce a small rotating window of ``rate`` routes
    every ``period`` seconds from both BCGWs (see exa-bcgw.py's "churn"
    command), toggling the MED each time to force a real attribute change
    on every route touched. Mimics the ambient, low-rate background route
    churn observed in the field (~1200 updates/60s at 619 peers / 1.6M
    routes - see the bgpd_oom_monitor.sh field analysis): no slow or
    flapping VPE is involved there either, yet an "ipv4 vpn" subgroup
    eventually needs a full adj-out rebuild and the main thread stalls.
    Runs in its own thread until ``stop_event`` is set.
    """
    offset = 0
    med = 0
    while not stop_event.is_set():
        med = 0 if med else 1
        bcgw_churn(tgen, offset, rate, med)
        offset = (offset + rate) % ROUTES
        stop_event.wait(period)


@contextlib.contextmanager
def organic_churn(tgen):
    """Run organic_churn_loop() in a background thread for the block's duration."""
    stop_event = threading.Event()
    churner = threading.Thread(
        target=organic_churn_loop, args=(tgen, stop_event), daemon=True
    )
    churner.start()
    try:
        yield
    finally:
        stop_event.set()
        churner.join(timeout=30)


def vpe_refresh(tgen, index):
    """
    Soft clear of the rr session on a VPE: the VPE has no
    soft-reconfiguration inbound, so it sends a ROUTE-REFRESH to the rr, and
    re-sends its own prefix (the burst of UPDATEs from the VPE seen on the
    field together with the whole table sent back to it).
    """
    tgen.gears[vpe_name(index)].vtysh_cmd(
        "clear bgp ipv4 vpn {} soft".format(RR_ADDR)
    )


def refresh_converged(tgen, refresh_before, count):
    """None once the rr got ``count`` more ROUTE-REFRESH and all converged."""
    got = rr_refresh_recv(tgen.gears["rr"]) - refresh_before
    if got < count:
        return "rr got {}/{} ROUTE-REFRESH".format(got, count)
    return all_converged(tgen)


def refresh_burst(tgen, indexes, interval):
    """Send a ROUTE-REFRESH from each VPE of ``indexes``, ``interval`` seconds apart."""
    for turn, index in enumerate(indexes):
        if turn:
            time.sleep(interval)
        vpe_refresh(tgen, index)


def assert_refresh_recv(name, count):
    """The last RESULTS row's refresh_recv must be at least ``count``."""
    row = RESULTS[-1]
    assert row["refresh_recv"] >= count, "{}: rr got {} ROUTE-REFRESH, {} sent".format(
        name, row["refresh_recv"], count
    )


def run_refresh_scenario(tgen, name, indexes, interval):
    rr = tgen.gears["rr"]
    wait_one_subgroup(rr)
    refresh_before = rr_refresh_recv(rr)

    run_scenario(
        tgen, name, functools.partial(refresh_burst, tgen, indexes, interval),
        functools.partial(refresh_converged, tgen, refresh_before, len(indexes)),
        scenario_timeout(),
    )
    assert_refresh_recv(name, len(indexes))


def test_scenario_vpe_refresh_one():
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    step("ROUTE-REFRESH from one VPE ({}) to the rr".format(vpe_name(1)))
    run_refresh_scenario(tgen, "vpe_refresh_one", [1], 0)


def test_scenario_vpe_refresh_burst():
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    step(
        "ROUTE-REFRESH from {} VPEs to the rr, one every {}s".format(
            REFRESH_NB, REFRESH_INTERVAL
        )
    )
    run_refresh_scenario(
        tgen, "vpe_refresh_burst", list(range(1, REFRESH_NB + 1)), REFRESH_INTERVAL
    )


def vpe_subgroup_count(rr):
    "Number of distinct ipv4 vpn subgroups of the established VPE peers"
    return len(
        {sub for _, sub in vpe_update_groups(rr).values() if sub is not None}
    )


def test_scenario_vpe_refresh_churn():
    """
    vpe_refresh_burst under organic churn. In vpe_refresh_burst (quiet
    table) each per-VPE subgroup merges back within ~2s, so there are never
    more than 2 subgroups, while the field keeps 15-29 of them. Subgroups
    only merge when they are at the same table version: the ambient churn
    may keep them apart.

    Organic churn (organic_churn_loop()) runs for REFRESH_CHURN_WARMUP
    seconds, then REFRESH_NB VPEs send a ROUTE-REFRESH every
    REFRESH_INTERVAL seconds, and the churn keeps running for
    REFRESH_CHURN_HOLD seconds after the last one. Reported:
    - max_vpe_subgroups (Timeline): subgroups alive at the same time;
    - subgroups_at_churn_stop: subgroups still there when the churn stops.
      More than 1 means the churn kept them from merging for
      REFRESH_CHURN_HOLD seconds; the merge after the churn stops is then
      waited for by run_scenario() as usual.
    """
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    rr = tgen.gears["rr"]
    indexes = list(range(1, REFRESH_NB + 1))
    step(
        "ROUTE-REFRESH from {} VPEs, one every {}s, under organic churn "
        "({} routes every {}s, {}s before, {}s after)".format(
            REFRESH_NB, REFRESH_INTERVAL, CHURN_RATE, CHURN_PERIOD,
            REFRESH_CHURN_WARMUP, REFRESH_CHURN_HOLD,
        )
    )
    wait_one_subgroup(rr)
    refresh_before = rr_refresh_recv(rr)

    def trigger():
        with organic_churn(tgen):
            time.sleep(REFRESH_CHURN_WARMUP)
            refresh_burst(tgen, indexes, REFRESH_INTERVAL)
            time.sleep(REFRESH_CHURN_HOLD)
            subgroups = vpe_subgroup_count(rr)
            logger.info("vpe_refresh_churn: %d VPE subgroups when churn stops", subgroups)
        return {"subgroups_at_churn_stop": subgroups}

    run_scenario(
        tgen, "vpe_refresh_churn", trigger,
        functools.partial(refresh_converged, tgen, refresh_before, len(indexes)),
        scenario_timeout(),
    )
    assert_refresh_recv("vpe_refresh_churn", len(indexes))


def test_memory_leak():
    tgen = get_topogen()
    if not tgen.is_memleak_enabled():
        pytest.skip("Memory leak test/report is disabled")
    tgen.report_memory_leaks()


if __name__ == "__main__":
    sys.exit(pytest.main([os.path.basename(__file__)] + sys.argv[1:]))
