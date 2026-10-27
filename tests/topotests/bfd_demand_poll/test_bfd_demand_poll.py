# SPDX-License-Identifier: ISC
# Copyright (c) 2026 Qipeng Ding
"""Changing a native BFD session's Demand bit must start a Poll Sequence."""

import json
import os
import signal
import struct
import subprocess
import time
from pathlib import Path

import pytest

from lib.topogen import Topogen, get_topogen

pytestmark = [pytest.mark.bfdd]
CWD = os.path.dirname(os.path.realpath(__file__))


def build_topo(tgen):
    r1 = tgen.add_router("r1")
    r2 = tgen.add_router("r2")
    switch = tgen.add_switch("s1")
    switch.add_link(r1)
    switch.add_link(r2)


def setup_module(mod):
    tgen = Topogen(build_topo, mod.__name__)
    tgen.start_topology()
    for name, router in tgen.routers().items():
        router.load_frr_config(os.path.join(CWD, name, "frr.conf"))
    tgen.start_router()


def teardown_module(_mod):
    get_topogen().stop_topology()


def wait_for(predicate, description, timeout=20):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        value = predicate()
        if value:
            return value
        time.sleep(0.1)
    raise AssertionError("Timed out waiting for " + description)


def packets(path):
    """Read complete captured Ethernet/IPv4/UDP/BFD records, never inject."""
    if not path.exists():
        return []
    data = path.read_bytes()
    if len(data) < 24:
        return []
    endian = {b"\xd4\xc3\xb2\xa1": "<", b"\xa1\xb2\xc3\xd4": ">"}[data[:4]]
    assert struct.unpack_from(endian + "I", data, 20)[0] == 1
    offset, records = 24, []
    while offset + 16 <= len(data):
        _, _, size, original = struct.unpack_from(endian + "IIII", data, offset)
        if offset + 16 + size > len(data):
            break
        frame = data[offset + 16 : offset + 16 + size]
        offset += 16 + size
        assert size == original
        if frame[12:14] != b"\x08\x00" or frame[23] != 17:
            continue
        ihl = (frame[14] & 15) * 4
        udp = 14 + ihl
        if struct.unpack_from("!H", frame, udp + 2)[0] != 3784:
            continue
        payload = frame[udp + 8 :]
        assert len(payload) >= 24 and payload[0] >> 5 == 1
        flags = payload[1]
        records.append(
            {
                "source": ".".join(str(b) for b in frame[26:30]),
                "state": flags >> 6,
                "demand": bool(flags & 2),
                "poll": bool(flags & 32),
                "final": bool(flags & 16),
                "local_discriminator": struct.unpack_from("!I", payload, 4)[0],
                "remote_discriminator": struct.unpack_from("!I", payload, 8)[0],
            }
        )
    return records


def test_demand_bit_poll_sequence():
    tgen = get_topogen()
    assert not tgen.routers_have_failure(), tgen.errors
    r1, r2 = tgen.gears["r1"], tgen.gears["r2"]

    def peer(router):
        entries = router.vtysh_cmd("show bfd peers json", isjson=True)
        assert len(entries) == 1, entries
        return entries[0]

    def up():
        return peer(r1)["status"] == peer(r2)["status"] == "up"

    def demand(enable):
        reply = r1.vtysh_cmd(
            "configure terminal\nbfd\npeer 192.0.2.2\n{}demand-mode\nend".format(
                "" if enable else "no "
            )
        )
        assert "%" not in reply, reply

    wait_for(up, "both BFD sessions to be Up")

    def down_count(router):
        counters = router.vtysh_cmd("show bfd peers counters json", isjson=True)
        assert len(counters) == 1 and "session-down" in counters[0], counters
        return counters[0]["session-down"]

    downs = {name: down_count(router) for name, router in tgen.routers().items()}
    pids = {
        name: router.cmd("cat /var/run/frr/bfdd.pid").strip()
        for name, router in tgen.routers().items()
    }
    output_dir = Path(r1.gearlogdir)
    capture_path = output_dir / "wire.pcap"
    capture_log = output_dir / "capture.log"
    with capture_log.open("w") as output, capture_path.open("wb") as wire:
        capture = r1.popen(
            [
                "python3",
                os.path.join(CWD, "packet_capture.py"),
                "r1-eth0",
                "17",
            ],
            stdout=wire,
            stderr=output,
        )
        try:

            def capture_ready():
                assert capture.poll() is None, capture_log.read_text()
                return "capture ready" in capture_log.read_text()

            wait_for(capture_ready, "packet capture readiness")
            wait_for(lambda: len(packets(capture_path)) >= 6, "baseline BFD packets")
            baseline = packets(capture_path)
            assert all(not p["demand"] for p in baseline)
            wait_for(
                lambda: all(not p["poll"] for p in packets(capture_path)[-4:]),
                "initial Poll Sequence to finish",
            )
            observations = []
            for cycle in range(2):
                for enable in [True, False]:
                    before = len(packets(capture_path))
                    demand(enable)

                    def changed():
                        return [
                            p
                            for p in packets(capture_path)[before:]
                            if p["source"] == "192.0.2.1"
                            and p["state"] == 3
                            and p["demand"] == enable
                        ]

                    changed_packets = wait_for(changed, "changed Demand bit")
                    first = changed_packets[0]
                    observations.append(
                        {"cycle": cycle, "enable": enable, "first": first}
                    )
                    (output_dir / "transitions.json").write_text(
                        json.dumps(observations, indent=2)
                    )
                    assert (
                        first["local_discriminator"] and first["remote_discriminator"]
                    )
                    assert first[
                        "poll"
                    ], "Demand bit changed without Poll Sequence: {}".format(first)
                    wait_for(
                        lambda: any(
                            p["source"] == "192.0.2.2" and p["final"]
                            for p in packets(capture_path)[before:]
                        ),
                        "peer Final response",
                    )
                    wait_for(
                        lambda: any(not p["poll"] for p in changed()),
                        "Poll Sequence completion",
                    )
                    assert up()
                    before = len(packets(capture_path))
                    demand(enable)

                    def repeated_packets():
                        records = [
                            p
                            for p in packets(capture_path)[before:]
                            if p["source"] == "192.0.2.1"
                        ]
                        return records if len(records) >= 2 else None

                    repeated = wait_for(
                        repeated_packets, "packets after repeated CLI command"
                    )
                    assert all(
                        p["demand"] == enable and not p["poll"] for p in repeated
                    ), repeated
                    assert up()
            for name, router in tgen.routers().items():
                assert router.cmd("cat /var/run/frr/bfdd.pid").strip() == pids[name]
                assert down_count(router) == downs[name]
        finally:
            if capture.poll() is None:
                capture.send_signal(signal.SIGINT)
            try:
                capture.wait(timeout=10)
            except subprocess.TimeoutExpired:
                capture.kill()
                capture.wait(timeout=5)
        assert "kernel_drops=0" in capture_log.read_text()
        assert capture.returncode == 0
