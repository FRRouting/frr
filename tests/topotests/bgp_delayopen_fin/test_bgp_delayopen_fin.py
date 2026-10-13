#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright (c) 2026 Qipeng Ding
"""Normal TCP close during DelayOpen retains Active and restarts retry."""

import json
import os
import re
import signal
import struct
from pathlib import Path
import subprocess
import time

import pytest
from lib.topogen import Topogen, TopoRouter, get_topogen

CWD = os.path.dirname(os.path.realpath(__file__))
pytestmark = [pytest.mark.bgpd]


def build_topo(tgen):
    r1, r2 = tgen.add_router("r1"), tgen.add_router("r2")
    tgen.add_link(r1, r2)


@pytest.fixture(autouse=True)
def topology(request):
    tgen = Topogen(
        build_topo, __name__ + "_" + request.node.callspec.id.replace("-", "_")
    )
    tgen.start_topology()
    tgen.gears["r1"].load_frr_config(os.path.join(CWD, "r1/frr.conf"))
    tgen.gears["r2"].load_frr_config(
        os.path.join(CWD, "r2/frr.conf"), daemons=[(TopoRouter.RD_ZEBRA, None)]
    )
    tgen.start_router()
    yield
    tgen.stop_topology()


def wait_for(predicate, timeout=20):
    end = time.monotonic() + timeout
    while time.monotonic() < end:
        result = predicate()
        if result:
            return result
        time.sleep(0.1)
    raise AssertionError("Native TCP/FSM observation timed out")


def captured_fin(path, source):
    if not path.exists():
        return False
    data = path.read_bytes()
    if len(data) < 24:
        return False
    endian = {b"\xd4\xc3\xb2\xa1": "<", b"\xa1\xb2\xc3\xd4": ">"}[data[:4]]
    offset = 24
    while offset + 16 <= len(data):
        size = struct.unpack_from(endian + "IIII", data, offset)[2]
        offset += 16
        if offset + size > len(data):
            return False
        frame = data[offset : offset + size]
        offset += size
        ip = frame[14:]
        tcp = ip[(ip[0] & 15) * 4 :]
        if ip[12:16] == source and tcp[13] & 1:
            return True
    return False


@pytest.mark.parametrize("delay,manual_stop", [(30, False), (0, False), (30, True)])
def test_peer_close(tmp_path, delay, manual_stop):
    tgen = get_topogen()
    assert not tgen.routers_have_failure(), tgen.errors
    r1, r2 = tgen.gears["r1"], tgen.gears["r2"]

    def configure(*commands):
        reply = r1.vtysh_cmd(
            "\n".join(["configure terminal", "router bgp 65001", *commands, "end"])
        )
        assert "%" not in reply, reply

    def state():
        return r1.vtysh_cmd("show bgp neighbors 192.0.2.2 json", isjson=True)[
            "192.0.2.2"
        ]["bgpState"]

    configure("neighbor 192.0.2.2 shutdown")
    wait_for(lambda: state() == "Idle")
    configure(
        "neighbor 192.0.2.2 timers delayopen 30"
        if delay
        else "no neighbor 192.0.2.2 timers delayopen"
    )
    pid = r1.cmd("cat /var/run/frr/bgpd.pid").strip()
    log = tmp_path / "peer.log"
    for name, router in tgen.routers().items():
        reply = router.cmd(
            "ethtool -K {}-eth0 tx off tso off gso off gro off".format(name)
        )
        assert "not found" not in reply and "No such device" not in reply, reply
    capture_log = tmp_path / "capture.log"
    with log.open("w") as output, capture_log.open("w") as capture_output:
        capture = r2.popen(
            [
                "tcpdump",
                "--immediate-mode",
                "-ni",
                "r2-eth0",
                "-U",
                "-s",
                "0",
                "-w",
                str(tmp_path / "wire.pcap"),
                "tcp port 179",
            ],
            stdout=capture_output,
            stderr=capture_output,
        )
        server = r2.popen(
            ["python3", os.path.join(CWD, "tcp_peer.py")],
            stdin=subprocess.PIPE,
            stdout=output,
            stderr=output,
        )
        observations = []
        try:
            wait_for(lambda: "listening on" in capture_log.read_text())
            wait_for(lambda: "LISTENING" in log.read_text())
            configure("no neighbor 192.0.2.2 shutdown")
            wait_for(lambda: "CONNECTED" in log.read_text())
            wait_for(lambda: state() == ("Connect" if delay else "OpenSent"))
            if delay:
                wait_for(
                    lambda: "(bgp_delayopen_timer)" in r1.vtysh_cmd("show event timers")
                )
            timers = r1.vtysh_cmd("show event timers")
            assert ("(bgp_delayopen_timer)" in timers) == bool(delay), timers
            if manual_stop:
                configure("neighbor 192.0.2.2 shutdown")
                wait_for(lambda: state() == "Idle")
            else:
                before_log = r1.cmd("cat /tmp/bgp-delayopen-fin.log")
                server.stdin.write("close\n")
                server.stdin.flush()
                wait_for(lambda: "FIN" in log.read_text())

                def close_event():
                    new_log = r1.cmd("cat /tmp/bgp-delayopen-fin.log")[
                        len(before_log) :
                    ]
                    return new_log if "TCP_connection_closed (" in new_log else None

                event_log = wait_for(close_event, timeout=3)
                expected_event = "TCP_connection_closed ({}->Active)".format(
                    "Connect" if delay else "OpenSent"
                )
                assert (
                    expected_event in event_log
                ), "DelayOpen FIN did not retain Active: {}".format(event_log)
                (tmp_path / "close-event.log").write_text(event_log)
                expected = "Active"
                wait_for(lambda: state() == expected, timeout=3)
                timers = r1.vtysh_cmd("show event timers")
                assert "(bgp_delayopen_timer)" not in timers, timers
                assert "(bgp_connect_timer)" in timers, timers
                match = re.search(
                    r"\(bgp_connect_timer\)\s+(\d+):(\d+):(\d+\.\d+)", timers
                )
                assert match, timers
                remaining = int(match[1]) * 3600 + int(match[2]) * 60 + float(match[3])
                assert (
                    7 <= remaining <= 10
                ), "ConnectRetry not restarted at initial interval: {}".format(timers)
                # The initial retry interval is ten seconds, not DelayOpen+10.
                start = time.monotonic()
                while time.monotonic() - start < 2:
                    observations.append({"at": time.monotonic(), "state": state()})
                    time.sleep(0.1)
                assert all(row["state"] == "Active" for row in observations)
                assert server.wait(timeout=5) == 0, log.read_text()
            assert r1.cmd("cat /var/run/frr/bgpd.pid").strip() == pid
            (tmp_path / "observations.json").write_text(
                json.dumps(observations, indent=2)
            )
        finally:
            configure("neighbor 192.0.2.2 shutdown")
            if server.poll() is None:
                server.terminate()
            server.wait(timeout=5)
            wait_for(lambda: state() == "Idle")
            # A short native exchange must not pass with a header-only pcap.
            wait_for(
                lambda: captured_fin(
                    tmp_path / "wire.pcap", bytes([192, 0, 2, 1 if manual_stop else 2])
                ),
                timeout=3,
            )
            if capture.poll() is None:
                capture.send_signal(signal.SIGINT)
            capture.wait(timeout=5)
            assert "0 packets dropped by kernel" in capture_log.read_text()
