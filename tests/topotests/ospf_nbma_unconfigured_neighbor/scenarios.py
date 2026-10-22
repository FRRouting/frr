#!/usr/bin/env python3
# SPDX-License-Identifier: ISC
#
# scenarios.py
# Part of NetDEF Topology Tests
#
# Copyright (c) 2026
#
"""Shared scenario definitions and helpers for the static-neighbor
receive-enforcement topotests (NBMA and point-to-multipoint
non-broadcast)."""

import json
import os
import shlex
import time

from lib.topolog import logger

HELLO_INTERVAL = 2
DEAD_INTERVAL = 6
ADJACENCY_TIMEOUT = 60
CONTROL_DURATION = 1.5
ROGUE_OBSERVE_SECONDS = 8.0

SCENARIO_NBMA = {
    "receiver": "r1",
    "peer": "r2",
    "host": "h1",
    "switch": "s1",
    "receiver_ip": "10.248.8.1",
    "peer_ip": "10.248.8.2",
    "host_ip": "10.248.8.3",
    "invalid_ip": "10.248.8.4",
    "receiver_rid": "8.8.1.1",
    "peer_rid": "8.8.1.2",
    "host_rid": "8.8.1.3",
    "invalid_rid": "8.8.1.4",
    "network_command": "non-broadcast",
    "expected_network_type": "NBMA",
    "expected_p2mp_non_broadcast": None,
    "expected_neighbor_line": "neighbor 10.248.8.2 poll-interval 5",
}

SCENARIO_P2MP = {
    "receiver": "r3",
    "peer": "r4",
    "host": "h2",
    "switch": "s2",
    "receiver_ip": "10.248.9.1",
    "peer_ip": "10.248.9.2",
    "host_ip": "10.248.9.3",
    "invalid_ip": "10.248.9.4",
    "receiver_rid": "8.8.2.1",
    "peer_rid": "8.8.2.2",
    "host_rid": "8.8.2.3",
    "invalid_rid": "8.8.2.4",
    "network_command": "point-to-multipoint non-broadcast",
    "expected_network_type": "POINTOMULTIPOINT",
    "expected_p2mp_non_broadcast": True,
    "expected_neighbor_line": "neighbor 10.248.9.2 poll-interval 5",
}


def wait_until(func, timeout=15, interval=0.5):
    deadline = time.time() + timeout
    while time.time() < deadline:
        value = func()
        if value:
            return value
        time.sleep(interval)
    return func()


def vty_json(router, command):
    return json.loads(router.vtysh_cmd(command))


def neighbor_entry(router, router_id, source_ip):
    """Neighbor JSON entry whose interface address matches source_ip."""
    raw = vty_json(router, "show ip ospf neighbor json")
    for value in raw.get("neighbors", {}).get(router_id, []):
        if value.get("ifaceAddress") == source_ip:
            return value
    return None


def peer_full(tgen, scenario):
    """The configured adjacency is Full in both directions."""
    receiver = tgen.gears[scenario["receiver"]]
    peer = tgen.gears[scenario["peer"]]
    forward = neighbor_entry(receiver, scenario["peer_rid"], scenario["peer_ip"])
    reverse = neighbor_entry(peer, scenario["receiver_rid"], scenario["receiver_ip"])
    return bool(
        forward
        and reverse
        and forward.get("converged") == "Full"
        and reverse.get("converged") == "Full"
    )


def hello_in(router):
    data = vty_json(router, "show ip ospf interface traffic eth0 json")
    return data["eth0"]["helloIn"]


def iface_mac(node):
    return node.cmd("cat /sys/class/net/eth0/address").strip()


def log_offset(router):
    path = os.path.join(router.gearlogdir, "ospfd.out")
    try:
        return os.path.getsize(path)
    except OSError:
        return 0


def log_since(router, offset):
    path = os.path.join(router.gearlogdir, "ospfd.out")
    try:
        with open(path, errors="replace") as logf:
            logf.seek(offset)
            return logf.read()
    except OSError:
        return ""


def inject(
    tgen,
    cwd,
    scenario,
    label,
    mode,
    src_ip,
    packet_rid,
    neighbor_rids,
    count=1,
    corrupt_checksum=False,
):
    """Send crafted packets from the unconfigured host and prove wire
    transmission; return send evidence, helloIn delta and the log delta
    on the receiver."""
    receiver = tgen.gears[scenario["receiver"]]
    host = tgen.gears[scenario["host"]]
    pcap = os.path.join(tgen.logdir, "%s.pcap" % label)
    host.cmd("rm -f %s" % shlex.quote(pcap))
    hello_before = hello_in(receiver)
    offset = log_offset(receiver)
    cmd = (
        "python3 %s/send_packet.py --mode %s --iface eth0 --src-mac %s "
        "--src-ip %s --packet-rid %s --hello-interval %d --dead-interval %d "
        "--priority 1 --neighbors %s --count %d --spacing 0.6 %s--pcap %s"
        % (
            shlex.quote(cwd),
            shlex.quote(mode),
            shlex.quote(iface_mac(host)),
            shlex.quote(src_ip),
            shlex.quote(packet_rid),
            HELLO_INTERVAL,
            DEAD_INTERVAL,
            shlex.quote(",".join(neighbor_rids)),
            count,
            "--corrupt-checksum " if corrupt_checksum else "",
            shlex.quote(pcap),
        )
    )
    out = host.cmd_raises(cmd)
    markers = [line for line in out.splitlines() if line.startswith("B8_SEND_JSON=")]
    assert markers, "send_packet.py returned no result for %s: %s" % (label, out)
    send = json.loads(markers[-1].split("=", 1)[1])
    assert (
        send["captured"] == count
    ), "injection %s was not captured %d time(s) on the wire: %s" % (label, count, send)
    phase = {
        "label": label,
        "send": send,
        "hello_in_delta": hello_in(receiver) - hello_before,
        "log": log_since(receiver, offset),
    }
    logger.info(
        "injected %s: mode=%s src=%s rid=%s neighbors=%s corrupt=%s captured=%d "
        "hello_in_delta=%d",
        label,
        mode,
        src_ip,
        packet_rid,
        neighbor_rids,
        corrupt_checksum,
        send["captured"],
        phase["hello_in_delta"],
    )
    return phase


def observe_absence(tgen, scenario, router_id, source_ip, duration):
    """Sample the neighbor table for `duration`; return every entry ever
    seen for (router_id, source_ip)."""
    receiver = tgen.gears[scenario["receiver"]]
    started = time.monotonic()
    seen = []
    while time.monotonic() - started < duration:
        entry = neighbor_entry(receiver, router_id, source_ip)
        if entry and entry not in seen:
            seen.append(entry)
        time.sleep(0.1)
    return seen


def check_baseline(tgen, scenario):
    receiver = tgen.gears[scenario["receiver"]]

    assert wait_until(
        lambda: peer_full(tgen, scenario), timeout=ADJACENCY_TIMEOUT, interval=1
    ), ("%s: configured peer did not reach Full in both directions" % receiver.name)

    running = receiver.vtysh_cmd("show running-config")
    neighbor_lines = [
        line.strip()
        for line in running.splitlines()
        if line.strip().startswith("neighbor ")
    ]
    assert neighbor_lines == [
        scenario["expected_neighbor_line"]
    ], "%s: expected exactly one static neighbor line, got %s" % (
        receiver.name,
        neighbor_lines,
    )
    assert ("ip ospf network %s" % scenario["network_command"]) in running

    iface = vty_json(receiver, "show ip ospf interface eth0 json")["interfaces"]["eth0"]
    assert iface["networkType"] == scenario["expected_network_type"], iface
    if scenario["expected_p2mp_non_broadcast"] is not None:
        assert (
            iface["p2mpNonBroadcast"] == scenario["expected_p2mp_non_broadcast"]
        ), iface
    assert iface["mcastMemberOspfAllRouters"] is True, iface

    assert neighbor_entry(receiver, scenario["host_rid"], scenario["host_ip"]) is None
    assert (
        neighbor_entry(receiver, scenario["invalid_rid"], scenario["invalid_ip"])
        is None
    )
