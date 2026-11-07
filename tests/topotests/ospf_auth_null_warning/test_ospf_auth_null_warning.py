#!/usr/bin/env python
# SPDX-License-Identifier: ISC
#
# test_ospf_auth_null_warning.py
#
# Copyright (c) 2026

"""
test_ospf_auth_null_warning.py
==============================

When `ip ospf authentication message-digest` is configured on an
interface but no message-digest key (and no key-chain) is present,
ospf_auth_type() deliberately falls back to NULL authentication for
Cisco compatibility.  The fallback is legitimate protocol behavior, but
an administrator must be able to observe it: the running-config keeps
showing message-digest while the wire carries unauthenticated packets.

This test verifies that:
1. the fallback still forms a Full adjacency with AuType=0 on the wire
   (compatibility preserved);
2. entering the fallback emits exactly one warning per episode, naming
   the interface, no matter how many packets follow;
3. restoring a valid key switches back to cryptographic authentication
   (AuType=2, key-id present) and NULL packets are no longer accepted;
4. deleting the last key re-enters the fallback and warns exactly once
   more (the warning state is reset when a usable key exists);
5. explicit `ip ospf authentication null` is an administrative choice
   and does not raise the fallback warning.

Topology
--------

    r1 (RID 100.1.1.1) ---- r2 (RID 100.1.1.2)

Point-to-point link, hello 1s / dead 4s to keep the cycle fast.  Only
r1 changes authentication configuration; r2 stays unauthenticated
(NULL) for the whole test.
"""

import os
import shlex
import struct
import sys
import time

import pytest
from scapy.all import IP
from scapy.utils import rdpcap

CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))
sys.path.append(os.path.join(CWD, "../lib/"))

from lib.topogen import Topogen, get_topogen
from lib.common_config import (
    start_topology,
    write_test_header,
    write_test_footer,
    step,
)
from lib.topolog import logger
from lib.topojson import build_config_from_json
from lib.ospf import verify_ospf_neighbor

pytestmark = [pytest.mark.ospfd]

topo = None

R1 = "r1"
R2 = "r2"
KEY_ID = 1
KEY = "c1topotest"
WARN_NEEDLE = "falling back to NULL authentication"
# Point-to-point, hello 1s: a 4s capture always contains several hellos.
CAPTURE_SECONDS = 4
# Long enough to cover the dead interval (4s) plus retransmitted hellos.
DOWNHOLD_SECONDS = 7


def setup_module(mod):
    """Set up the pytest environment."""
    testsuite_run_time = time.asctime(time.localtime(time.time()))
    logger.info("Testsuite start time: {}".format(testsuite_run_time))
    logger.info("=" * 40)

    logger.info("Running setup_module to create topology")

    json_file = "{}/ospf_auth_null_warning.json".format(CWD)
    tgen = Topogen(json_file, mod.__name__)
    global topo
    topo = tgen.json_topo

    start_topology(tgen)
    build_config_from_json(tgen, topo)

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    logger.info("Running setup_module() done")


def teardown_module():
    """Teardown the pytest environment."""
    logger.info("Running teardown_module to delete topology")

    tgen = get_topogen()
    tgen.stop_topology()

    logger.info(
        "Testsuite end time: {}".format(time.asctime(time.localtime(time.time())))
    )
    logger.info("=" * 40)


def _iface(router, link):
    return topo["routers"][router]["links"][link]["interface"]


def _link_ip(router, link):
    return topo["routers"][router]["links"][link]["ipv4"].split("/")[0]


def _config_r1(cmds):
    r1 = get_topogen().gears[R1]
    body = "\n".join(
        ["configure terminal", "interface {}".format(_iface(R1, R2))] + cmds + ["end"]
    )
    r1.vtysh_cmd(body)


def _clear_neighbors():
    get_topogen().gears[R1].vtysh_cmd("clear ip ospf neighbor")


def _fallback_warnings():
    log = get_topogen().gears[R1].net.getLog("log", "ospfd") or ""
    return [line for line in log.splitlines() if WARN_NEEDLE in line]


def _running_config_auth_lines():
    out = get_topogen().gears[R1].vtysh_cmd("show running-config")
    return [
        line.strip()
        for line in out.splitlines()
        if "ip ospf authentication" in line or "ip ospf message-digest-key" in line
    ]


def _wait_until(func, timeout_s=10, interval_s=0.25):
    deadline = time.time() + timeout_s
    while time.time() < deadline:
        if func():
            return True
        time.sleep(interval_s)
    return bool(func())


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


def _start_capture(router, pcap_path, bpf="ip proto 89"):
    """Sniff with scapy in the router netns; tcpdump is not used."""
    err_path = pcap_path + ".err"
    ready_path = pcap_path + ".ready"
    router.cmd(
        "rm -f %s %s %s"
        % (shlex.quote(pcap_path), shlex.quote(err_path), shlex.quote(ready_path))
    )
    # nohup: router.cmd() closing the session would otherwise SIGHUP the sniffer.
    pid = router.cmd(
        "nohup python3 %s/capture_ospf.py --iface %s --pcap %s "
        "--filter %s --ready-file %s </dev/null >%s 2>&1 & echo $!"
        % (
            shlex.quote(CWD),
            shlex.quote(_iface(R2, R1)),
            shlex.quote(pcap_path),
            shlex.quote(bpf),
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
    if not _wait_until(lambda: _file_ready(ready_path)):
        err = router.cmd("cat %s 2>/dev/null || true" % shlex.quote(err_path))
        assert False, "scapy capture did not become ready on %s (pid %s): %s" % (
            router.name,
            pid,
            err.strip() or "no capture stderr",
        )
    return pid


def _stop_capture(router, pid, pcap_path):
    router.cmd("kill -TERM %s >/dev/null 2>&1 || true" % pid)
    if not _wait_until(lambda: not _proc_alive(router, pid), timeout_s=8):
        router.cmd("kill -KILL %s >/dev/null 2>&1 || true" % pid)
        _wait_until(lambda: not _proc_alive(router, pid))
    assert _wait_until(
        lambda: os.path.exists(pcap_path) and os.path.getsize(pcap_path) >= 24
    ), "pcap %s missing after stopping capture" % pcap_path


def _capture_r1_auth_types(label, seconds=CAPTURE_SECONDS):
    """Capture packets r1 sends on the shared link and return per-packet
    (ospf_type, auth_type, key_id) tuples parsed from the raw header."""
    tgen = get_topogen()
    r2 = tgen.gears[R2]
    pcap_path = os.path.join(tgen.logdir, "{}.pcap".format(label))
    pid = _start_capture(r2, pcap_path, "ip proto 89 and host %s" % _link_ip(R1, R2))
    try:
        time.sleep(seconds)
    finally:
        _stop_capture(r2, pid, pcap_path)

    packets = []
    for pkt in rdpcap(pcap_path):
        if not pkt.haslayer(IP) or pkt[IP].proto != 89:
            continue
        if pkt[IP].src != _link_ip(R1, R2):
            continue
        raw = bytes(pkt[IP].payload)
        if len(raw) < 24 or raw[0] != 2:
            continue
        packets.append(
            {
                "ospf_type": raw[1],
                "auth_type": struct.unpack("!H", raw[14:16])[0],
                "key_id": raw[18] if struct.unpack("!H", raw[14:16])[0] == 2 else None,
            }
        )
    return packets


def _hello_auth_types(packets):
    return sorted({p["auth_type"] for p in packets if p["ospf_type"] == 1})


def _full_adjacency():
    tgen = get_topogen()
    result = verify_ospf_neighbor(tgen, topo, dut=R1)
    return result is True


def _no_full_adjacency(duration_s):
    r1 = get_topogen().gears[R1]
    deadline = time.time() + duration_s
    while time.time() < deadline:
        out = r1.vtysh_cmd("show ip ospf neighbor json", isjson=True)
        for rid, entries in (out.get("neighbors") or {}).items():
            for entry in entries:
                if entry.get("converged") == "Full":
                    return False
        time.sleep(0.5)
    return True


def test_01_unauthenticated_baseline(request):
    """Baseline: no authentication configured, adjacency Full, AuType=0,
    and no fallback warning."""
    tc_name = request.node.name
    write_test_header(tc_name)
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    step("Verify initial adjacency without authentication")
    assert _full_adjacency(), "Initial adjacency failed"

    step("Verify no fallback warning is logged at baseline")
    assert _fallback_warnings() == [], "unexpected fallback warning at baseline"

    step("Verify r1 sends NULL authentication on the wire")
    packets = _capture_r1_auth_types("baseline")
    hellos = [p for p in packets if p["ospf_type"] == 1]
    assert hellos, "no OSPF Hello captured from r1"
    assert _hello_auth_types(packets) == [0], "baseline hellos not AuType=0"

    write_test_footer(tc_name)


def test_02_md5_without_key_warns_once(request):
    """message-digest without any key: Full adjacency over NULL, running-
    config keeps message-digest, and exactly one warning per episode."""
    tc_name = request.node.name
    write_test_header(tc_name)
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    step("Configure message-digest on r1 without any key")
    _config_r1(["ip ospf authentication message-digest"])
    _clear_neighbors()

    step("Verify adjacency re-forms over the NULL fallback")
    assert _full_adjacency(), "adjacency did not re-form after fallback"

    step("Verify running-config still shows message-digest without a key")
    auth_lines = _running_config_auth_lines()
    assert "ip ospf authentication message-digest" in auth_lines, auth_lines
    assert not any("ip ospf message-digest-key" in line for line in auth_lines)

    step("Verify exactly one fallback warning naming the interface")
    warnings = _fallback_warnings()
    assert len(warnings) == 1, "expected exactly 1 fallback warning: %s" % warnings
    assert _iface(R1, R2) in warnings[0], warnings[0]

    step("Verify sustained traffic does not repeat the warning")
    time.sleep(6)  # ~6 hellos at 1s interval
    assert len(_fallback_warnings()) == 1, "fallback warning repeated per packet"

    step("Verify r1 sends NULL authentication on the wire")
    packets = _capture_r1_auth_types("no_key")
    hellos = [p for p in packets if p["ospf_type"] == 1]
    assert hellos, "no OSPF Hello captured from r1"
    assert _hello_auth_types(packets) == [0], "fallback hellos not AuType=0"

    write_test_footer(tc_name)


def test_03_valid_key_uses_cryptographic_auth(request):
    """With a valid key, r1 must use AuType=2 and stop accepting NULL, so
    the adjacency with the unauthenticated r2 stays down."""
    tc_name = request.node.name
    write_test_header(tc_name)
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    step("Add a valid message-digest key on r1")
    _config_r1(["ip ospf message-digest-key {} md5 {}".format(KEY_ID, KEY)])
    _clear_neighbors()

    step("Verify adjacency stays down (cryptographic vs NULL mismatch)")
    assert _no_full_adjacency(DOWNHOLD_SECONDS), (
        "adjacency formed despite cryptographic/NULL mismatch"
    )

    step("Verify the key is present in running-config")
    assert any(
        "ip ospf message-digest-key {} md5 {}".format(KEY_ID, KEY) in line
        for line in _running_config_auth_lines()
    )

    step("Verify r1 sends cryptographic authentication on the wire")
    packets = _capture_r1_auth_types("keyed")
    hellos = [p for p in packets if p["ospf_type"] == 1]
    assert hellos, "no OSPF Hello captured from r1"
    assert _hello_auth_types(packets) == [2], "keyed hellos not AuType=2"
    assert {p["key_id"] for p in hellos} == {KEY_ID}, hellos

    step("Verify no new fallback warning while the key is valid")
    assert len(_fallback_warnings()) == 1, "fallback warning fired with a valid key"

    write_test_footer(tc_name)


def test_04_delete_last_key_warns_again(request):
    """Deleting the last key re-enters the NULL fallback: Full adjacency
    returns and exactly one more warning is emitted (state was reset)."""
    tc_name = request.node.name
    write_test_header(tc_name)
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    step("Delete the last message-digest key on r1")
    _config_r1(["no ip ospf message-digest-key {} md5 {}".format(KEY_ID, KEY)])
    _clear_neighbors()

    step("Verify adjacency re-forms over the NULL fallback")
    assert _full_adjacency(), "adjacency did not re-form after last key deletion"

    step("Verify exactly one additional fallback warning")
    warnings = _fallback_warnings()
    assert len(warnings) == 2, "expected 2 fallback warnings total: %s" % warnings

    step("Verify sustained traffic does not repeat the warning")
    time.sleep(6)
    assert len(_fallback_warnings()) == 2, "fallback warning repeated per packet"

    step("Verify r1 sends NULL authentication on the wire")
    packets = _capture_r1_auth_types("last_key_deleted")
    hellos = [p for p in packets if p["ospf_type"] == 1]
    assert hellos, "no OSPF Hello captured from r1"
    assert _hello_auth_types(packets) == [0], "post-deletion hellos not AuType=0"

    write_test_footer(tc_name)


def test_05_explicit_null_no_warning(request):
    """Explicit `ip ospf authentication null` is an administrative choice:
    Full adjacency, no new fallback warning."""
    tc_name = request.node.name
    write_test_header(tc_name)
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    step("Replace message-digest with explicit null authentication on r1")
    _config_r1(["ip ospf authentication null"])
    _clear_neighbors()

    step("Verify adjacency re-forms with explicit null")
    assert _full_adjacency(), "adjacency did not re-form with explicit null"

    step("Verify no new fallback warning was emitted")
    assert len(_fallback_warnings()) == 2, (
        "explicit null authentication raised the fallback warning"
    )

    step("Verify r1 sends NULL authentication on the wire")
    packets = _capture_r1_auth_types("explicit_null")
    hellos = [p for p in packets if p["ospf_type"] == 1]
    assert hellos, "no OSPF Hello captured from r1"
    assert _hello_auth_types(packets) == [0], "explicit-null hellos not AuType=0"

    write_test_footer(tc_name)
