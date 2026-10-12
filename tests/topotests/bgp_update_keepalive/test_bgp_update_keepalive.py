#!/usr/bin/env python
# SPDX-License-Identifier: ISC
# Copyright (c) 2026 Qipeng Ding
"""A completed native UPDATE postpones the next periodic KEEPALIVE."""

import json
import os
import signal
import subprocess
import time

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


def wait_until(probe, timeout=25):
    deadline = time.monotonic() + timeout
    while True:
        value = probe()
        if value:
            return value
        assert time.monotonic() < deadline, "Timed out waiting for native packet/state"
        time.sleep(0.04)


def test_update_restarts_keepalive(tmp_path):
    tgen = get_topogen()
    assert not tgen.routers_have_failure(), tgen.errors
    r1, r2 = tgen.gears["r1"], tgen.gears["r2"]
    for name, router in tgen.routers().items():
        assert router.cmd(
            "command -v ethtool"
        ).strip(), "ethtool is required for capture checksum controls"
        reply = router.cmd(
            "ethtool -K {}-eth0 tx off tso off gso off gro off".format(name)
        )
        assert "not found" not in reply and "No such device" not in reply, reply
    pcap = tmp_path / "native.pcap"
    logfile = (tmp_path / "capture.log").open("w")
    capture = r2.popen(
        ["tcpdump", "-ni", "r2-eth0", "-U", "-s", "0", "-w", str(pcap), "tcp port 179"],
        stdout=logfile,
        stderr=logfile,
    )
    observations = []
    prefix = "198.51.100.36/32"

    def messages():
        return native_messages(pcap)

    def keepalives():
        return [
            m for m in messages() if m["flow"][0] == "192.0.2.10" and m["type"] == 4
        ]

    def route_present():
        return prefix in r2.vtysh_cmd("show bgp ipv4 unicast json", isjson=True).get(
            "routes", {}
        )

    def session():
        return r1.vtysh_cmd("show bgp neighbors 192.0.2.11 json", isjson=True)[
            "192.0.2.11"
        ]["connectionsEstablished"]

    def run_update_cycle(label):
        before = session()

        def phase():
            rows = keepalives()
            return (
                rows
                if len(rows) >= 5 and 1.5 <= time.time() - rows[-1]["at"] <= 1.9
                else None
            )

        controls = wait_until(phase)
        periods = [b["at"] - a["at"] for a, b in zip(controls[-4:], controls[-3:])]
        assert all(2.7 <= gap <= 3.4 for gap in periods), periods
        assert not [
            m
            for m in messages()
            if m["flow"] == controls[-1]["flow"]
            and m["type"] == 2
            and controls[-4]["at"] < m["at"] < controls[-1]["at"]
        ], "Startup UPDATE overlapped the no-UPDATE control window"
        trigger = time.time()
        configure(
            r1,
            "ip route " + prefix + " Null0",
            "router bgp 65001",
            "address-family ipv4 unicast",
            "network " + prefix,
        )

        def update_and_next():
            rows = messages()
            updates = [
                m
                for m in rows
                if m["flow"][0] == "192.0.2.10"
                and m["type"] == 2
                and m["at"] >= trigger
                and m.get("nlri") == [prefix]
            ]
            after = [
                m
                for m in rows
                if updates
                and m["flow"] == updates[0]["flow"]
                and m["type"] == 4
                and m["at"] > updates[0]["at"]
            ]
            return (updates[0], after[0]) if after else None

        update, after = wait_until(update_and_next)
        wait_until(route_present)
        gap = after["at"] - update["at"]
        observations.append(
            {
                "label": label,
                "control_periods": periods,
                "update": update,
                "next_keepalive": after,
                "gap": gap,
            }
        )
        (tmp_path / "observations.json").write_text(json.dumps(observations, indent=2))
        assert (
            2.7 <= gap <= 3.5
        ), "UPDATE did not restart KeepaliveTimer: gap {}".format(gap)
        assert established() is None and session() == before
        wait_until(phase)
        withdraw_at = time.time()
        configure(
            r1,
            "router bgp 65001",
            "address-family ipv4 unicast",
            "no network " + prefix,
            "exit-address-family",
            "exit",
            "no ip route " + prefix + " Null0",
        )
        wait_until(lambda: not route_present())

        def withdrawal_and_next():
            rows = messages()
            withdrawn = [
                m
                for m in rows
                if m["flow"] == update["flow"]
                and m["type"] == 2
                and m["at"] >= withdraw_at
                and m.get("withdrawn") == [prefix]
            ]
            after = [
                m
                for m in rows
                if withdrawn
                and m["flow"] == update["flow"]
                and m["type"] == 4
                and m["at"] > withdrawn[0]["at"]
            ]
            return (withdrawn[0], after[0]) if after else None

        withdrawal, next_ka = wait_until(withdrawal_and_next)
        gap = next_ka["at"] - withdrawal["at"]
        assert 2.7 <= gap <= 3.5, "Withdrawal UPDATE did not restart timer"
        observations.append({"label": label + "-withdrawal", "gap": gap})
        (tmp_path / "observations.json").write_text(json.dumps(observations, indent=2))

    try:
        wait_until(lambda: "listening on" in (tmp_path / "capture.log").read_text())
        configure(r1, "router bgp 65001", "no neighbor 192.0.2.11 shutdown")
        _, error = topotest.run_and_expect(established, None, count=40, wait=1)
        assert error is None, error
        pids = {
            name: r.cmd("cat /var/run/frr/bgpd.pid").strip()
            for name, r in tgen.routers().items()
        }
        run_update_cycle("first-session")
        capture.send_signal(signal.SIGINT)
        capture.wait(timeout=5)
        # A fresh session must not inherit the previous connection's activity.
        configure(r1, "router bgp 65001", "neighbor 192.0.2.11 shutdown")
        pcap = tmp_path / "reconnected.pcap"
        capture = r2.popen(
            [
                "tcpdump",
                "-ni",
                "r2-eth0",
                "-U",
                "-s",
                "0",
                "-w",
                str(pcap),
                "tcp port 179",
            ],
            stdout=logfile,
            stderr=logfile,
        )
        wait_until(lambda: pcap.exists() and pcap.stat().st_size >= 24)
        configure(r1, "router bgp 65001", "no neighbor 192.0.2.11 shutdown")
        _, error = topotest.run_and_expect(established, None, count=40, wait=1)
        assert error is None, error
        run_update_cycle("reconnected-session")
        # Every later UPDATE must postpone the deadline again.
        burst_prefixes = ["198.51.100.{}/32".format(n) for n in (40, 41, 42)]
        trigger = time.time()
        for item in burst_prefixes:
            configure(
                r1,
                "ip route " + item + " Null0",
                "router bgp 65001",
                "address-family ipv4 unicast",
                "network " + item,
            )
            wait_until(
                lambda: item
                in r2.vtysh_cmd("show bgp ipv4 unicast json", isjson=True).get(
                    "routes", {}
                )
            )
            time.sleep(0.7)

        def burst_and_next():
            rows = messages()
            updates = [
                m
                for m in rows
                if m["flow"][0] == "192.0.2.10"
                and m["type"] == 2
                and m["at"] >= trigger
                and any(p in burst_prefixes for p in m.get("nlri", []))
            ]
            advertised = {p for m in updates for p in m.get("nlri", [])}
            after = [
                m
                for m in rows
                if updates
                and m["flow"] == updates[-1]["flow"]
                and m["type"] == 4
                and m["at"] > updates[-1]["at"]
            ]
            return (
                (updates, after[0])
                if set(burst_prefixes) <= advertised and after
                else None
            )

        updates, next_ka = wait_until(burst_and_next)
        gap = next_ka["at"] - updates[-1]["at"]
        assert 2.7 <= gap <= 3.5, "Later UPDATE did not postpone KeepaliveTimer again"
        assert not [
            m for m in keepalives() if updates[0]["at"] < m["at"] < updates[-1]["at"]
        ]
        for item in burst_prefixes:
            configure(
                r1,
                "router bgp 65001",
                "address-family ipv4 unicast",
                "no network " + item,
                "exit-address-family",
                "exit",
                "no ip route " + item + " Null0",
            )
            wait_until(
                lambda: item
                not in r2.vtysh_cmd("show bgp ipv4 unicast json", isjson=True).get(
                    "routes", {}
                )
            )
        observations.append(
            {"label": "repeated-updates", "updates": updates, "gap_after_last": gap}
        )
        (tmp_path / "observations.json").write_text(json.dumps(observations, indent=2))
        assert {
            name: r.cmd("cat /var/run/frr/bgpd.pid").strip()
            for name, r in tgen.routers().items()
        } == pids

        capture.send_signal(signal.SIGINT)
        capture.wait(timeout=5)
        configure(
            r1,
            "router bgp 65001",
            "neighbor 192.0.2.11 shutdown",
            "neighbor 192.0.2.11 timers 0 0",
        )
        configure(r2, "router bgp 65002", "neighbor 192.0.2.10 timers 0 0")
        pcap = tmp_path / "zero-hold.pcap"
        capture = r2.popen(
            [
                "tcpdump",
                "-ni",
                "r2-eth0",
                "-U",
                "-s",
                "0",
                "-w",
                str(pcap),
                "tcp port 179",
            ],
            stdout=logfile,
            stderr=logfile,
        )
        wait_until(lambda: pcap.exists() and pcap.stat().st_size >= 24)
        configure(r1, "router bgp 65001", "no neighbor 192.0.2.11 shutdown")
        _, error = topotest.run_and_expect(established, None, count=40, wait=1)
        assert error is None, error
        for name, address in [("r1", "192.0.2.11"), ("r2", "192.0.2.10")]:
            neighbor = tgen.gears[name].vtysh_cmd(
                "show bgp neighbors " + address + " json", isjson=True
            )[address]
            assert neighbor["bgpTimerHoldTimeMsecs"] == 0
        time.sleep(1)
        observed_from = time.time()
        configure(
            r1,
            "ip route " + prefix + " Null0",
            "router bgp 65001",
            "address-family ipv4 unicast",
            "network " + prefix,
        )
        wait_until(route_present)

        def zero_hold_updates():
            assert capture.poll() is None, "Zero HoldTime capture stopped early"
            return [
                m
                for m in messages()
                if m["flow"][0] == "192.0.2.10"
                and m["type"] == 2
                and m["at"] >= observed_from
                and m.get("nlri") == [prefix]
            ]

        captured_updates = wait_until(zero_hold_updates)
        observation_deadline = time.monotonic() + 7
        while time.monotonic() < observation_deadline:
            assert capture.poll() is None, "Zero HoldTime capture stopped early"
            time.sleep(0.04)
        assert capture.poll() is None, "Zero HoldTime capture stopped early"
        assert not [
            m for m in keepalives() if m["at"] >= observed_from
        ], "Zero HoldTime started periodic KEEPALIVEs"
        assert established() is None
        configure(
            r1,
            "router bgp 65001",
            "address-family ipv4 unicast",
            "no network " + prefix,
            "exit-address-family",
            "exit",
            "no ip route " + prefix + " Null0",
        )
        wait_until(lambda: not route_present())
        observations.append(
            {
                "label": "zero-hold",
                "periodic_keepalives": 0,
                "captured_updates": len(captured_updates),
                "capture_alive_through_observation": True,
                "observation_seconds": time.time() - observed_from,
            }
        )
        (tmp_path / "observations.json").write_text(json.dumps(observations, indent=2))
    finally:
        if capture.poll() is None:
            capture.send_signal(signal.SIGINT)
            try:
                capture.wait(timeout=5)
            except subprocess.TimeoutExpired:
                capture.kill()
                capture.wait()
        logfile.close()
