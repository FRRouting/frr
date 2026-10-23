#!/usr/bin/env python
# SPDX-License-Identifier: ISC
#
# Copyright (c) 2026 by
# Bing Shui <bingshui@smail.nju.edu.cn>
#
"""
RIP: an inbound interface route-map that does not run `set ip next-hop`
or `set tag` must leave the received RTE's next-hop and tag untouched.

rip_rte_process() zeroes the scratch rip_info and initializes nh.gate,
tag and metric_out from the wire RTE, but never initializes nexthop_out
and tag_out.  After route_map_apply() it unconditionally copies all
three fields back onto the RTE, so a permitted entry without an explicit
set lost its third-party next-hop (falling back to the advertiser) and
its non-zero tag.  The outbound direction initializes all three fields
before applying the route-map; the inbound direction now does the same.

Topology: r1 (victim) and r2 (downstream observer) on s1, advertiser h1
and third-party h2 on s2.  Every injected RTE carries next-hop 10.0.13.4
(h2, a real host on the receiving segment), tag 77 and metric 2, one
prefix per scenario; h2 also owns 198.18.20.1/32 on lo so only the
preserved next-hop delivers r1's ping.  Timers are 10/60/30.
"""

import json
import os
import re
import shutil
import subprocess
import sys
import time

import pytest

CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

# pylint: disable=C0413
from lib import topotest
from lib.topogen import Topogen, get_topogen

pytestmark = [pytest.mark.ripd]

R1_ETH0_IP = "10.0.12.1"
R2_ETH0_IP = "10.0.12.2"
R1_ETH1_IP = "10.0.13.1"
H1_IP = "10.0.13.3"
H2_IP = "10.0.13.4"
R2_LO_IP = "203.0.113.1"

S1_PREFIX = "198.18.20.0/24"
S1_CONTROL_PREFIX = "198.18.21.0/24"
S2_PREFIX = "198.18.22.0/24"
S3_PREFIX = "198.18.23.0/24"
S4_PREFIX = "198.18.24.0/24"
S5_PREFIX = "198.18.25.0/24"
WIRE_TAG = 77

PROCS = []


def build_topo(tgen):
    r1 = tgen.add_router("r1")
    r2 = tgen.add_router("r2")
    s1 = tgen.add_switch("s1")
    s1.add_link(r1)
    s1.add_link(r2)
    s2 = tgen.add_switch("s2")
    s2.add_link(r1)
    h1 = tgen.add_host("h1", "10.0.13.3/24", "via 10.0.13.1")
    s2.add_link(h1)
    h2 = tgen.add_host("h2", "10.0.13.4/24", "via 10.0.13.1")
    s2.add_link(h2)


def setup_module(mod):
    tgen = Topogen(build_topo, mod.__name__)
    tgen.start_topology()

    for rname in ("r1", "r2"):
        tgen.gears[rname].load_frr_config(os.path.join(CWD, rname,
                                                       "frr.conf"))
    tgen.start_router()
    # Only the preserved third-party next-hop delivers this address.
    tgen.gears["h2"].cmd("ip addr add 198.18.20.1/32 dev lo")


def teardown_module(mod):
    tgen = get_topogen()

    for proc in PROCS:
        if proc.poll() is None:
            proc.terminate()
            proc.wait()

    tgen.stop_topology()

    shutil.rmtree(os.path.join(CWD, "__pycache__"), ignore_errors=True)


def _pkt(prefix, metric=2, tag=WIRE_TAG, nexthop=H2_IP):
    return {"prefix": prefix, "mask": "255.255.255.0", "metric": metric,
            "tag": tag, "nexthop": nexthop, "at": 0, "src": H1_IP}


def _send(tgen, packets, tag):
    """Start rip_send.py on h1; returns the popen object."""
    h1 = tgen.gears["h1"]
    spec = {"iface": "h1-eth0", "src": H1_IP, "dst": R1_ETH1_IP,
            "packets": packets}
    spec_path = os.path.join(h1.logdir, "rip_send_{}.json".format(tag))
    with open(spec_path, "w") as fp:
        json.dump(spec, fp)
    log_path = os.path.join(h1.logdir, "rip_send_{}.log".format(tag))
    proc = h1.popen(["python3", os.path.join(CWD, "rip_send.py"), spec_path],
                    stdout=open(log_path, "w"), stderr=subprocess.STDOUT)
    PROCS.append(proc)
    return proc


def _apply_rmap(r1, rmap_lines, bind):
    if bind:
        lines = ["configure terminal", "no route-map RMAP-IN"]
        lines += rmap_lines
        lines += ["exit", "router rip", "route-map RMAP-IN in r1-eth1"]
    else:
        lines = ["configure terminal", "router rip",
                 "no route-map RMAP-IN in r1-eth1", "exit",
                 "no route-map RMAP-IN"]
    lines += ["exit", "end"]
    r1.vtysh_cmd("\n".join(lines))


def _route_entries(r1, prefix):
    """zebra RIB entries for prefix: [] when not installed."""
    output = r1.vtysh_cmd("show ip route {} json".format(prefix))
    start = output.find("{")
    if start < 0:
        return []
    return json.loads(output[start:]).get(prefix, [])


def _rip_paths(r1, prefix):
    """[(nexthop, metric, tag)] for the prefix in the RIP RIB."""
    output = r1.vtysh_cmd("show ip rip", isjson=False)
    out = []
    for line in output.splitlines():
        if prefix not in line:
            continue
        parts = line.split()
        if len(parts) >= 6 and re.fullmatch(r"\d+", parts[3]) \
                and re.fullmatch(r"\d+", parts[5]):
            out.append((parts[2], int(parts[3]), int(parts[5])))
    return out


def _fib_nexthops(r1, probe):
    fib = r1.cmd("ip route get {}".format(probe))
    return re.findall(r"via (\d+\.\d+\.\d+\.\d+)", fib)


def _require_r2_route(tgen):
    """Baseline: r1 learns r2's redistributed loopback via RIP."""
    r1 = tgen.gears["r1"]

    def _check():
        entries = _route_entries(r1, "{}/32".format(R2_LO_IP))
        if entries and R2_ETH0_IP in [nh.get("ip")
                                      for nh in entries[0].get("nexthops", [])]:
            return None
        return "missing"

    _, result = topotest.run_and_expect(_check, None, count=60, wait=1)
    assert result is None, "r1 never learned {}/32 from r2".format(R2_LO_IP)


def _expect_route(r1, prefix, probe, nexthop, metric, tag):
    """The route must be installed with exactly these RIB/zebra/FIB
    values; returns a list of problems (empty when correct)."""
    problems = []
    entries = _route_entries(r1, prefix)
    if not entries:
        return ["{} not installed".format(prefix)]
    nhs = sorted(nh.get("ip") for nh in entries[0].get("nexthops", [])
                 if nh.get("ip"))
    if nhs != [nexthop]:
        problems.append("zebra nexthops {} != [{}]".format(nhs, nexthop))
    if nexthop not in _fib_nexthops(r1, probe):
        problems.append("FIB nexthop missing {}: {}".format(
            nexthop, _fib_nexthops(r1, probe)))
    if _rip_paths(r1, prefix) != [(nexthop, metric, tag)]:
        problems.append("RIP RIB {} != [{}]".format(
            _rip_paths(r1, prefix), (nexthop, metric, tag)))
    return problems


def _expect_absent(r1, prefix, seconds, label):
    """The prefix must not appear in the RIP RIB or zebra for `seconds`."""
    deadline = time.time() + seconds
    while time.time() < deadline:
        entries = _route_entries(r1, prefix)
        paths = _rip_paths(r1, prefix)
        assert not entries and not paths, \
            "{}: {} appeared (zebra={}, rip={})".format(
                label, prefix, entries, paths)
        time.sleep(1)


def test_rip_inbound_routemap_permit_without_set(tgen):
    """A permit entry without set keeps the wire next-hop and tag; the
    non-matching control prefix is implicitly denied, proving the
    route-map is bound to r1-eth1 and filtering."""
    _require_r2_route(tgen)
    r1 = tgen.gears["r1"]

    packets = [_pkt("198.18.20.0"), _pkt("198.18.21.0")]
    proc = _send(tgen, packets, "permit_no_set")

    def _check():
        return _expect_route(r1, S1_PREFIX, "198.18.20.1", H2_IP, 3,
                             WIRE_TAG) or None

    _, result = topotest.run_and_expect(_check, None, count=15, wait=1)
    assert result is None, \
        "permit without set must preserve next-hop/tag: {}".format(result)
    proc.wait(timeout=30)
    _expect_absent(r1, S1_CONTROL_PREFIX, 6, "route-map implicit deny")

    # Data plane: only the preserved next-hop reaches h2's 198.18.20.1.
    ping = r1.cmd("ping -c 2 -W 2 198.18.20.1")
    loss = re.search(r"(\d+)% packet loss", ping)
    assert loss and loss.group(1) == "0", \
        "ping 198.18.20.1 must flow via the third-party next-hop: {}" \
        .format(ping)

    # Downstream propagation: r2 learns the prefix from r1 with the
    # original tag (metric 3 + 1 in-cost = 4).
    r2 = tgen.gears["r2"]

    def _r2_check():
        paths = _rip_paths(r2, S1_PREFIX)
        return paths or None

    _, result = topotest.run_and_expect(_r2_check, None, count=25, wait=1)
    assert result == [(R1_ETH0_IP, 4, WIRE_TAG)], \
        "r2 must learn {} with tag {}: {}".format(S1_PREFIX, WIRE_TAG,
                                                  result)


def test_rip_inbound_routemap_explicit_set(tgen):
    """Explicit `set ip next-hop` / `set tag` must still override the
    wire values on both the fixed and the unfixed version."""
    r1 = tgen.gears["r1"]
    _apply_rmap(r1, ["route-map RMAP-IN permit 10",
                     " set ip next-hop {}".format(H1_IP),
                     " set tag 99"], bind=True)

    proc = _send(tgen, [_pkt("198.18.22.0")], "explicit_set")

    def _check():
        return _expect_route(r1, S2_PREFIX, "198.18.22.1", H1_IP, 3,
                             99) or None

    _, result = topotest.run_and_expect(_check, None, count=15, wait=1)
    assert result is None, \
        "explicit set must override next-hop/tag: {}".format(result)
    proc.wait(timeout=30)


def test_rip_inbound_routemap_set_metric_only(tgen):
    """`set metric` alone must change only the metric; next-hop and tag
    stay at the wire values."""
    r1 = tgen.gears["r1"]
    _apply_rmap(r1, ["route-map RMAP-IN permit 10",
                     " set metric 7"], bind=True)

    proc = _send(tgen, [_pkt("198.18.23.0")], "set_metric")

    def _check():
        return _expect_route(r1, S3_PREFIX, "198.18.23.1", H2_IP, 8,
                             WIRE_TAG) or None

    _, result = topotest.run_and_expect(_check, None, count=15, wait=1)
    assert result is None, \
        "set metric only: metric 8 with wire next-hop/tag expected: {}" \
        .format(result)
    proc.wait(timeout=30)


def test_rip_inbound_routemap_deny(tgen):
    """A deny entry drops the route on both versions (control)."""
    r1 = tgen.gears["r1"]
    _apply_rmap(r1, ["route-map RMAP-IN deny 10"], bind=True)

    proc = _send(tgen, [_pkt("198.18.24.0")], "deny")
    _expect_absent(r1, S4_PREFIX, 8, "route-map deny")
    proc.wait(timeout=30)


def test_rip_inbound_routemap_no_routemap(tgen):
    """Without an inbound route-map the wire values pass through
    unchanged (control)."""
    r1 = tgen.gears["r1"]
    _apply_rmap(r1, [], bind=False)

    proc = _send(tgen, [_pkt("198.18.25.0")], "no_routemap")

    def _check():
        return _expect_route(r1, S5_PREFIX, "198.18.25.1", H2_IP, 3,
                             WIRE_TAG) or None

    _, result = topotest.run_and_expect(_check, None, count=15, wait=1)
    assert result is None, \
        "no route-map must pass wire values through: {}".format(result)
    proc.wait(timeout=30)


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
