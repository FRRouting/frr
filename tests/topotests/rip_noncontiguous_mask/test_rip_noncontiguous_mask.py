#!/usr/bin/env python
# SPDX-License-Identifier: ISC
#
# Copyright (c) 2026 by
# Bing Shui <bingshui@smail.nju.edu.cn>
#
"""
RIP: a RIPv2 RTE with a non-contiguous netmask must be ignored, not
silently folded into a different prefix.

rip_response_process() only validates prefix & mask == prefix on the
wire.  ip_masklen() assumes a contiguous mask and counts leading ones
only, and rip_rte_process() then rewrites the prefix with
apply_mask_ipv4().  A wire entry of 10.0.2.0 + 255.0.255.0 therefore
used to be folded into 10.0.0.0/8 in the RIP RIB, zebra and the FIB,
and was re-advertised to neighbors; a folded entry could also replace
a legitimate route for the folded prefix.  RFC 2453 §3.9.2 lists only
destination and metric validity checks; §4.3 defines the mask as the
subnet mask applied to the address.  FRR documents that ripd does not
support non-sequential netmasks, so the entry must be ignored.

Topology: r1 (victim) and r2 (RIP speaker, 172.16.0.0/16 redistributed
with metric 5) on s1, attacker host h1 on s2.  The wire prefix must
satisfy the existing prefix & mask == prefix check, i.e. bits under
mask 0-bits must be 0 (10.0.2.0 passes with 255.0.255.0; 172.16.5.0
would not, so the override test uses 172.16.0.5 with 255.255.0.255).
Timers are 5/30/15 to keep the test short.
"""

import json
import os
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

R1_IP = "10.0.13.1"
H1_IP = "10.0.13.3"
R2_IP = "10.0.12.2"
R2_PREFIX = "172.16.0.0/16"

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


def setup_module(mod):
    tgen = Topogen(build_topo, mod.__name__)
    tgen.start_topology()

    for rname in ("r1", "r2"):
        tgen.gears[rname].load_frr_config(os.path.join(CWD, rname,
                                                       "frr.conf"))
    tgen.start_router()


def teardown_module(mod):
    tgen = get_topogen()

    for proc in PROCS:
        if proc.poll() is None:
            proc.terminate()
            proc.wait()

    tgen.stop_topology()

    shutil.rmtree(os.path.join(CWD, "__pycache__"), ignore_errors=True)


def _pkt(prefix, mask, metric, at, version=2):
    return {"prefix": prefix, "mask": mask, "metric": metric, "tag": 0,
            "nexthop": "0.0.0.0", "at": at, "src": H1_IP,
            "version": version}


def _send(tgen, packets, tag):
    """Start rip_send.py on h1; returns the popen object."""
    h1 = tgen.gears["h1"]
    spec = {"iface": "h1-eth0", "src": H1_IP, "dst": R1_IP,
            "packets": packets}
    spec_path = os.path.join(h1.logdir, "rip_send_{}.json".format(tag))
    with open(spec_path, "w") as fp:
        json.dump(spec, fp)
    log_path = os.path.join(h1.logdir, "rip_send_{}.log".format(tag))
    proc = h1.popen(["python3", os.path.join(CWD, "rip_send.py"), spec_path],
                    stdout=open(log_path, "w"), stderr=subprocess.STDOUT)
    PROCS.append(proc)
    return proc


def _route_entries(r1, prefix):
    """zebra RIB entries for prefix: [] when not installed."""
    output = r1.vtysh_cmd("show ip route {} json".format(prefix))
    start = output.find("{")
    if start < 0:
        return []
    return json.loads(output[start:]).get(prefix, [])


def _rip_rib_lines(r1, prefix):
    """`show ip rip` lines mentioning prefix."""
    output = r1.vtysh_cmd("show ip rip", isjson=False)
    return [line for line in output.splitlines() if prefix in line]


def _require_r2_route(tgen):
    """Baseline: r1 learns r2's redistributed 172.16.0.0/16 (metric 6)."""
    r1 = tgen.gears["r1"]

    def _check():
        entries = _route_entries(r1, R2_PREFIX)
        if entries and R2_IP in [nh.get("ip")
                                 for nh in entries[0].get("nexthops", [])]:
            return None
        return "missing"

    _, result = topotest.run_and_expect(_check, None, count=60, wait=1)
    assert result is None, "r1 never learned {} from r2".format(R2_PREFIX)


def _assert_absent(r1, prefix, seconds, label):
    """The prefix must not appear in the RIP RIB or zebra for `seconds`."""
    deadline = time.time() + seconds
    while time.time() < deadline:
        entries = _route_entries(r1, prefix)
        lines = _rip_rib_lines(r1, prefix)
        assert not entries and not lines, \
            "{}: {} appeared (zebra={}, rip={})".format(
                label, prefix, entries, lines)
        time.sleep(1)


def _poll_until_present(r1, prefix, seconds, label):
    """Wait until zebra installs the route; returns the entries."""
    deadline = time.time() + seconds
    while time.time() < deadline:
        entries = _route_entries(r1, prefix)
        if entries:
            return entries
        time.sleep(1)
    raise AssertionError("{}: {} never installed".format(label, prefix))


def _nexthops(entries):
    return sorted(nh.get("ip") for nh in entries[0].get("nexthops", [])
                  if nh.get("ip"))


def test_rip_noncontiguous_mask_not_folded(tgen):
    """Regression: 10.0.2.0 + 255.0.255.0 must not become 10.0.0.0/8."""
    _require_r2_route(tgen)
    r1 = tgen.gears["r1"]
    packets = [_pkt("10.0.2.0", "255.0.255.0", 2, at=0)]

    proc = _send(tgen, packets, "noncontig_fold")
    _assert_absent(r1, "10.0.0.0/8", 10, "non-contiguous mask")
    proc.wait(timeout=30)


def test_rip_contiguous_mask_accepted(tgen):
    """Control: a legitimate contiguous /24 is installed."""
    _require_r2_route(tgen)
    r1 = tgen.gears["r1"]
    prefix = "198.18.7.0/24"
    packets = [_pkt("198.18.7.0", "255.255.255.0", 2, at=0)]

    proc = _send(tgen, packets, "contiguous")
    entries = _poll_until_present(r1, prefix, 15, "contiguous /24")
    assert _nexthops(entries) == [H1_IP], \
        "contiguous /24: wrong nexthops {}".format(_nexthops(entries))
    assert entries[0].get("metric") == 3, \
        "contiguous /24: wrong metric {}".format(entries[0].get("metric"))
    proc.wait(timeout=30)


def test_rip_unaligned_prefix_rejected(tgen):
    """Control: a prefix that fails prefix & mask == prefix is ignored
    by the pre-existing check on both versions."""
    _require_r2_route(tgen)
    r1 = tgen.gears["r1"]
    packets = [_pkt("192.168.7.0", "255.255.0.0", 2, at=0)]

    proc = _send(tgen, packets, "unaligned")
    _assert_absent(r1, "192.168.0.0/16", 8, "unaligned prefix")
    proc.wait(timeout=30)


def test_rip_default_route_nonzero_mask_normalized(tgen):
    """Control: the default route's netmask is ignored and normalized to
    0.0.0.0/0, including a non-contiguous one."""
    _require_r2_route(tgen)
    r1 = tgen.gears["r1"]
    packets = [_pkt("0.0.0.0", "0.0.0.0", 2, at=0),
               _pkt("0.0.0.0", "255.0.255.0", 3, at=3)]

    proc = _send(tgen, packets, "default_route")
    entries = _poll_until_present(r1, "0.0.0.0/0", 15, "default route")
    proc.wait(timeout=30)
    assert _nexthops(entries) == [H1_IP], \
        "default route: wrong nexthops {}".format(_nexthops(entries))
    # The second packet (metric 3, non-contiguous mask) must have been
    # processed with the mask normalized: metric becomes 4.
    deadline = time.time() + 10
    while time.time() < deadline:
        entries = _route_entries(r1, "0.0.0.0/0")
        if entries and entries[0].get("metric") == 4:
            break
        time.sleep(1)
    assert entries and entries[0].get("metric") == 4, \
        "default route: metric never became 4: {}".format(entries)


def test_ripv1_route_classful_derived(tgen):
    """Control: RIPv1 keeps the classful /24 derivation."""
    _require_r2_route(tgen)
    r1 = tgen.gears["r1"]
    prefix = "198.18.8.0/24"
    packets = [_pkt("198.18.8.0", "0.0.0.0", 2, at=0, version=1)]

    proc = _send(tgen, packets, "ripv1")
    entries = _poll_until_present(r1, prefix, 15, "RIPv1 /24")
    assert _nexthops(entries) == [H1_IP], \
        "RIPv1 /24: wrong nexthops {}".format(_nexthops(entries))
    proc.wait(timeout=30)


def test_rip_noncontiguous_mask_no_override(tgen):
    """Impact: a folded entry must not replace the legitimate route for
    the folded prefix."""
    _require_r2_route(tgen)
    r1 = tgen.gears["r1"]
    packets = [_pkt("172.16.0.5", "255.255.0.255", 2, at=0)]

    proc = _send(tgen, packets, "noncontig_override")
    deadline = time.time() + 10
    while time.time() < deadline:
        entries = _route_entries(r1, R2_PREFIX)
        assert entries and _nexthops(entries) == [R2_IP], \
            "legitimate {} overridden by folded entry: {}".format(
                R2_PREFIX, _nexthops(entries) if entries else entries)
        lines = _rip_rib_lines(r1, R2_PREFIX)
        assert lines and R2_IP in lines[0], \
            "RIP RIB for {} changed: {}".format(R2_PREFIX, lines)
        time.sleep(1)
    proc.wait(timeout=30)


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
