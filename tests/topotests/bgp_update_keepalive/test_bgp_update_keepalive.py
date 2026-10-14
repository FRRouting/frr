#!/usr/bin/env python
# SPDX-License-Identifier: ISC
# Copyright (c) 2026 Qipeng Ding
"""A completed native UPDATE postpones the next periodic KEEPALIVE."""

import json
import os
import signal
import subprocess
import time
from contextlib import contextmanager

import pytest

from lib import topotest
from lib.topogen import Topogen, get_topogen
from packet_timeline import native_messages

pytestmark = pytest.mark.bgpd
CWD = os.path.dirname(os.path.realpath(__file__))


def build_topo(tgen):
    tgen.add_router("r1")
    tgen.add_router("r2")
    switch = tgen.add_switch("s1")
    switch.add_link(tgen.gears["r1"])
    switch.add_link(tgen.gears["r2"])


def setup_module(mod):
    tgen = Topogen(build_topo, mod.__name__)
    tgen.start_topology()
    for name, router in tgen.routers().items():
        router.load_frr_config(
            os.path.join(CWD, name, "frr.conf"), extra_daemons=["staticd"]
        )
    tgen.start_router()


def teardown_module():
    get_topogen().stop_topology()


def configure(router, *commands):
    reply = router.vtysh_cmd("configure terminal\n" + "\n".join(commands) + "\nend")
    assert "Unknown command" not in reply and "Ambiguous command" not in reply, reply


def established():
    for name, address in [("r1", "192.0.2.11"), ("r2", "192.0.2.10")]:
        row = (
            get_topogen()
            .gears[name]
            .vtysh_cmd("show bgp neighbors " + address + " json", isjson=True)
        )
        if row.get(address, {}).get("bgpState") != "Established":
            return name + " is not Established"
    return None


def wait_until(probe, label, timeout=45):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        result = probe()
        if result:
            return result
        time.sleep(0.1)
    pytest.fail("Timed out waiting for " + label)


def prepare_session(hold_zero=False):
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)
    r1, r2 = tgen.gears["r1"], tgen.gears["r2"]
    configure(r1, "router bgp 65001", "neighbor 192.0.2.11 shutdown")
    timers = "0 0" if hold_zero else "3 9"
    configure(r1, "router bgp 65001", "neighbor 192.0.2.11 timers " + timers)
    configure(r2, "router bgp 65002", "neighbor 192.0.2.10 timers " + timers)
    return r1, r2


@contextmanager
def capture_wire(router, tmp_path):
    path = tmp_path / "wire.pcap"
    log = tmp_path / "capture.log"
    with log.open("w") as output:
        process = router.popen(
            [
                "tcpdump",
                "--immediate-mode",
                "-ni",
                "r2-eth0",
                "-U",
                "-s",
                "0",
                "-w",
                str(path),
                "tcp port 179",
            ],
            stdout=output,
            stderr=output,
        )
        try:
            wait_until(lambda: "listening on" in log.read_text(), "capture readiness")
            yield path, process
        finally:
            if process.poll() is None:
                process.send_signal(signal.SIGINT)
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=5)
    assert process.returncode == 0, log.read_text()


def start_session(r1):
    configure(r1, "router bgp 65001", "no neighbor 192.0.2.11 shutdown")
    wait_until(lambda: established() is None, "both BGP sessions Established")


def advertise(r1, prefix):
    configure(
        r1,
        "ip route " + prefix + " Null0",
        "router bgp 65001",
        "address-family ipv4 unicast",
        "network " + prefix,
    )


def withdraw(r1, prefix):
    configure(
        r1,
        "router bgp 65001",
        "address-family ipv4 unicast",
        "no network " + prefix,
        "exit-address-family",
        "exit",
        "no ip route " + prefix + " Null0",
    )


def route_present(r2, prefix):
    table = r2.vtysh_cmd("show bgp ipv4 unicast json", isjson=True).get("routes", {})
    return any(row.get("valid") is True for row in table.get(prefix, []))


def test_update_restarts_keepalive(tmp_path):
    r1, r2 = prepare_session()
    prefix = "198.51.100.36/32"
    with capture_wire(r2, tmp_path) as (path, capture):
        start_session(r1)
        pid = r1.cmd("cat /var/run/frr/bgpd.pid").strip()

        def keepalives():
            assert capture.poll() is None, "capture stopped before the observation"
            return [
                m
                for m in native_messages(path)
                if m["flow"][0] == "192.0.2.10" and m["type"] == 4
            ]

        controls = wait_until(
            lambda: keepalives() if len(keepalives()) >= 5 else None,
            "five control KEEPALIVEs",
        )
        periods = [b["at"] - a["at"] for a, b in zip(controls[-4:], controls[-3:])]
        assert all(2.7 <= value <= 3.5 for value in periods), periods
        assert not [
            m
            for m in native_messages(path)
            if m["flow"] == controls[-1]["flow"]
            and m["type"] == 2
            and controls[-4]["at"] < m["at"] < controls[-1]["at"]
        ], "Startup UPDATE overlaps control periods"
        anchor = controls[-1]
        # Start halfway into a period, without polling for a 400 ms phase window.
        while time.time() < anchor["at"] + 1.5:
            assert capture.poll() is None
            time.sleep(0.05)
        trigger = time.time()
        advertise(r1, prefix)
        try:

            def update_and_next():
                rows = native_messages(path)
                updates = [
                    m
                    for m in rows
                    if m["flow"] == anchor["flow"]
                    and m["type"] == 2
                    and m["at"] >= trigger
                    and m.get("nlri") == [prefix]
                ]
                following = [
                    m
                    for m in rows
                    if updates
                    and m["flow"] == anchor["flow"]
                    and m["type"] == 4
                    and m["at"] > updates[0]["at"]
                ]
                return (updates[0], following[0]) if following else None

            update, following = wait_until(update_and_next, "UPDATE and next KEEPALIVE")
            previous = [m for m in keepalives() if m["at"] < update["at"]][-1]
            phase = update["at"] - previous["at"]
            gap = following["at"] - update["at"]
            (tmp_path / "observations.json").write_text(
                json.dumps(
                    {
                        "control_periods": periods,
                        "update_phase": phase,
                        "gap": gap,
                        "update": update,
                        "following": following,
                    },
                    indent=2,
                )
            )
            assert 1.0 <= phase <= 2.3, "UPDATE missed the control phase: {}".format(
                phase
            )
            wait_until(lambda: route_present(r2, prefix), "valid received route")
            assert (
                2.7 <= gap <= 3.5
            ), "UPDATE did not restart KeepaliveTimer: gap {}".format(gap)
            assert established() is None
            assert r1.cmd("cat /var/run/frr/bgpd.pid").strip() == pid
        finally:
            withdraw(r1, prefix)


def test_zero_hold_has_no_periodic_keepalives(tmp_path):
    r1, r2 = prepare_session(hold_zero=True)
    prefix = "198.51.100.37/32"
    with capture_wire(r2, tmp_path) as (path, capture):
        start_session(r1)
        for router, address in [(r1, "192.0.2.11"), (r2, "192.0.2.10")]:
            row = router.vtysh_cmd(
                "show bgp neighbors " + address + " json", isjson=True
            )
            assert row[address]["bgpTimerHoldTimeMsecs"] == 0
        time.sleep(1)
        trigger = time.time()
        advertise(r1, prefix)
        try:

            def captured_update():
                assert (
                    capture.poll() is None
                ), "capture stopped during zero-HoldTime control"
                return [
                    m
                    for m in native_messages(path)
                    if m["flow"][0] == "192.0.2.10"
                    and m["type"] == 2
                    and m["at"] >= trigger
                    and m.get("nlri") == [prefix]
                ]

            updates = wait_until(
                captured_update, "zero-HoldTime UPDATE in this capture"
            )
            wait_until(
                lambda: route_present(r2, prefix), "zero-HoldTime valid received route"
            )
            deadline = time.monotonic() + 7
            while time.monotonic() < deadline:
                assert (
                    capture.poll() is None
                ), "capture stopped during zero-HoldTime control"
                time.sleep(0.1)
            assert capture.poll() is None, "capture stopped before observation ended"
            assert not [
                m
                for m in native_messages(path)
                if m["flow"] == updates[0]["flow"]
                and m["type"] == 4
                and m["at"] >= updates[0]["at"]
            ]
            assert established() is None
            (tmp_path / "observations.json").write_text(
                json.dumps(
                    {
                        "captured_updates": len(updates),
                        "observation_seconds": 7,
                        "periodic_keepalives": 0,
                        "capture_alive": True,
                    },
                    indent=2,
                )
            )
        finally:
            withdraw(r1, prefix)
