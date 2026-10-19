#!/usr/bin/env python
# SPDX-License-Identifier: ISC
"""Keep existing neighbors' retransmit timers in sync with live CLI changes."""

import json
import os
import signal
import socket
import struct
import subprocess
import time
from pathlib import Path

import pytest

from lib import topotest
from lib.topogen import Topogen, get_topogen

pytestmark = [pytest.mark.ospfd, pytest.mark.staticd]
CWD = os.path.dirname(os.path.realpath(__file__))
PREFIX = "198.51.100.99/32"


def build_topo(tgen):
    r1 = tgen.add_router("r1")
    r2 = tgen.add_router("r2")
    tgen.add_switch("s1").add_link(r1)
    tgen.gears["s1"].add_link(r2)


def setup_module(mod):
    tgen = Topogen(build_topo, mod.__name__)
    tgen.start_topology()
    for name, router in tgen.routers().items():
        router.load_frr_config(os.path.join(CWD, name, "frr.conf"))
    tgen.start_router()


def teardown_module():
    get_topogen().stop_topology()


def _healthy():
    for name, remote in [("r1", "198.51.100.2/32"), ("r2", "198.51.100.1/32")]:
        router = get_topogen().gears[name]
        neighbors = json.loads(router.vtysh_cmd("show ip ospf neighbor json"))
        rows = [n for group in neighbors["neighbors"].values() for n in group]
        if len(rows) != 1 or not rows[0]["nbrState"].startswith("Full"):
            return "{} adjacency is not Full".format(name)
        routes = json.loads(router.vtysh_cmd("show ip route ospf json"))
        if not any(r.get("installed") for r in routes.get(remote, [])):
            return "{} control route is missing".format(name)
    return None


def _neighbor_epochs():
    """Bound the last progressive state change using the real CLI uptime."""
    epochs = {}
    for name, router in get_topogen().routers().items():
        before = time.monotonic()
        neighbors = json.loads(router.vtysh_cmd("show ip ospf neighbor json"))
        after = time.monotonic()
        rows = [n for group in neighbors["neighbors"].values() for n in group]
        assert len(rows) == 1 and rows[0]["nbrState"].startswith("Full")
        age = rows[0]["upTimeInMsec"] / 1000
        epochs[name] = (before - age, after - age)
    return epochs


def _assert_neighbor_continuity(initial, label):
    current = _neighbor_epochs()
    for name, (lower, upper) in current.items():
        old_lower, old_upper = initial[name]
        # The uptime must advance with elapsed time. Merely increasing can
        # miss a reset followed by reconvergence during a long capture.
        assert lower <= old_upper + 0.2 and upper >= old_lower - 0.2, (
            name,
            label,
            initial[name],
            current[name],
        )
    path = Path(get_topogen().gears["r1"].gearlogdir) / (label + "-neighbors.json")
    path.write_text(json.dumps({"initial": initial, "current": current}, indent=2))


def _sent_at(path):
    """Read actual native LSU timestamps; no packet generation is involved."""
    data = path.read_bytes()
    endian, scale = {
        b"\xd4\xc3\xb2\xa1": ("<", 1e6),
        b"\xa1\xb2\xc3\xd4": (">", 1e6),
        b"\x4d\x3c\xb2\xa1": ("<", 1e9),
        b"\xa1\xb2\x3c\x4d": (">", 1e9),
    }[data[:4]]
    assert struct.unpack_from(endian + "I", data, 20)[0] == 1
    offset = 24
    generations = {}
    while offset < len(data):
        seconds, fraction, size, original = struct.unpack_from(
            endian + "IIII", data, offset
        )
        offset += 16
        frame = data[offset : offset + size]
        offset += size
        assert size == original == len(frame)
        ip = frame[14:]
        if frame[12:14] != b"\x08\x00" or ip[9] != 89:
            continue
        ospf = ip[(ip[0] & 15) * 4 : struct.unpack_from("!H", ip, 2)[0]]
        if ospf[1] != 4 or socket.inet_ntoa(ip[12:16]) != "192.0.2.1":
            continue
        count = struct.unpack_from("!I", ospf, 24)[0]
        cursor = 28
        for _ in range(count):
            length = struct.unpack_from("!H", ospf, cursor + 18)[0]
            lsa = ospf[cursor : cursor + length]
            cursor += length
            if (
                lsa[3] == 5
                and socket.inet_ntoa(lsa[4:8]) == PREFIX.split("/")[0]
                and socket.inet_ntoa(lsa[8:12]) == "10.255.44.1"
                and struct.unpack_from("!H", lsa)[0] < 3600
            ):
                generations.setdefault(lsa[12:18], []).append(
                    seconds + fraction / scale
                )
    assert generations, "No target LSA was captured"
    return max(generations.values(), key=len)


def _observe(router, label, expected):
    path = Path(router.gearlogdir) / (label + ".pcap")
    log_path = path.with_suffix(".capture.log")
    with log_path.open("w") as log, path.open("wb") as output:
        capture = router.popen(
            [
                "python3",
                os.path.join(CWD, "packet_capture.py"),
                "r1-eth0",
                "89",
            ],
            stdout=output,
            stderr=log,
        )
        try:
            deadline = time.monotonic() + 5
            while "capture ready" not in log_path.read_text():
                assert (
                    capture.poll() is None and time.monotonic() < deadline
                ), log_path.read_text()
                time.sleep(0.1)
            time.sleep(max(22, expected * 3 + 6))
        finally:
            if capture.poll() is None:
                capture.send_signal(signal.SIGINT)
            try:
                capture.wait(timeout=5)
            except subprocess.TimeoutExpired:
                capture.kill()
                capture.wait(timeout=5)
    assert capture.returncode == 0, log_path.read_text()
    stamps = _sent_at(path)
    intervals = [b - a for a, b in zip(stamps, stamps[1:])]
    # An already scheduled event may retain its old deadline; steady retries
    # must use the new interval without resetting the adjacency or Dead timer.
    assert len(intervals) >= 2, "Insufficient repeated target LSAs: {}".format(
        intervals
    )
    assert all(abs(delta - expected) < 0.35 for delta in intervals[-2:]), intervals
    assert _healthy() is None


def test_live_retransmit_set_unset_and_address_override():
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)
    _, result = topotest.run_and_expect(_healthy, None, count=60, wait=1)
    assert result is None, result
    r1, r2 = tgen.gears["r1"], tgen.gears["r2"]
    # Ensure a very recent initial Full transition cannot fit the tolerance
    # used to compare CLI observation windows after each configuration change.
    time.sleep(1)
    epochs = _neighbor_epochs()
    pids = [r.cmd("cat /var/run/frr/ospfd.pid").strip() for r in [r1, r2]]
    try:
        # Drop only the peer's ordinary LSAcks so native LSUs repeat. Hellos,
        # database synchronization and control-route traffic remain enabled.
        r2.cmd_raises(
            "tc qdisc add dev r2-eth0 root handle 1: prio bands 3 "
            "priomap 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0"
        )
        r2.cmd_raises("tc qdisc add dev r2-eth0 parent 1:3 handle 30: netem loss 100%")
        r2.cmd_raises(
            "tc filter add dev r2-eth0 parent 1: protocol ip pref 31 u32 "
            "match ip protocol 89 0xff match u8 5 0xff at 21 flowid 1:3"
        )
        r1.vtysh_cmd(
            "configure terminal\ninterface r1-eth0\nip ospf retransmit-interval 1"
        )
        r1.vtysh_cmd("configure terminal\nip route {} Null0".format(PREFIX))
        for label, command, expected in [
            ("set-one", None, 1),
            ("address-two", "ip ospf retransmit-interval 2 192.0.2.1", 2),
            ("default-four-override-two", "ip ospf retransmit-interval 4", 2),
            ("unset-address-four", "no ip ospf retransmit-interval 192.0.2.1", 4),
            ("unset-default-five", "no ip ospf retransmit-interval", 5),
        ]:
            if command:
                r1.vtysh_cmd("configure terminal\ninterface r1-eth0\n" + command)
            _observe(r1, label, expected)
            _assert_neighbor_continuity(epochs, label)
            assert pids == [
                r.cmd("cat /var/run/frr/ospfd.pid").strip() for r in [r1, r2]
            ]
    finally:
        r2.cmd("tc qdisc del dev r2-eth0 root")
        r1.vtysh_cmd(
            "configure terminal\nno ip route {} Null0\n"
            "interface r1-eth0\nno ip ospf retransmit-interval 192.0.2.1\n"
            "ip ospf retransmit-interval 5".format(PREFIX)
        )
