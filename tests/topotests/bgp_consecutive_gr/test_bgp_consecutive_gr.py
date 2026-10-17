# SPDX-License-Identifier: ISC
# Copyright (c) 2026 Qipeng Ding
"""Only routes refreshed after the first native restart survive the second."""

import json
import os
import time

import pytest
from lib.topogen import Topogen, get_topogen

pytestmark = [pytest.mark.bgpd]
CWD = os.path.dirname(os.path.realpath(__file__))
OLD = "198.51.100.1/32"
REFRESHED = "198.51.100.2/32"


def build_topo(tgen):
    switch = tgen.add_switch("s1")
    for name in ["r1", "r2"]:
        switch.add_link(tgen.add_router(name))


def setup_module(mod):
    tgen = Topogen(build_topo, mod.__name__)
    tgen.start_topology()
    for name, router in tgen.routers().items():
        router.load_frr_config(os.path.join(CWD, name, "frr.conf"))
    tgen.start_router()


def teardown_module(_mod):
    get_topogen().stop_topology()


def wait_for(predicate, stage, timeout=20):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        value = predicate()
        if value:
            return value
        time.sleep(0.1)
    raise AssertionError(f"Timed out waiting for {stage}")


def test_consecutive_restart(tmp_path):
    tgen = get_topogen()
    assert not tgen.routers_have_failure(), tgen.errors
    r1, r2 = tgen.gears["r1"], tgen.gears["r2"]

    def routes():
        result = r1.vtysh_cmd("show bgp ipv4 unicast json", isjson=True)
        assert "routes" in result, result
        return result["routes"]

    def session():
        return r1.vtysh_cmd("show bgp neighbor 192.0.2.2 json", isjson=True)[
            "192.0.2.2"
        ]

    def established():
        return session()["bgpState"] == "Established"

    def stop_peer():
        r2.net.set_ns_cwd("/")
        peer_pid = r2.cmd("cat /var/run/frr/bgpd.pid").strip()
        assert peer_pid.isdigit(), peer_pid
        assert r2.killDaemons(["bgpd"]) == ""
        wait_for(lambda: not established(), "peer to leave Established")
        return peer_pid

    def start_peer(previous_pid):
        assert r2.startDaemons(["bgpd"]) == ""
        r2.net.set_ns_cwd("/")
        peer_pid = r2.cmd("cat /var/run/frr/bgpd.pid").strip()
        assert peer_pid.isdigit() and peer_pid != previous_pid, peer_pid
        wait_for(established, "BGP session establishment")

    def fresh(table, prefix):
        return (
            prefix in table
            and len(table[prefix]) == 1
            and table[prefix][0].get("valid") is True
            and table[prefix][0].get("stale") is not True
        )

    def stale(table, prefix):
        return (
            prefix in table
            and len(table[prefix]) == 1
            and table[prefix][0].get("stale") is True
        )

    observations = []

    def save(stage):
        observations.append(
            {
                "stage": stage,
                "time": time.monotonic(),
                "routes": routes(),
                "peer": session(),
            }
        )
        (tmp_path / "observations.json").write_text(json.dumps(observations, indent=2))

    wait_for(established, "BGP session establishment")
    wait_for(
        lambda: fresh(routes(), OLD) and fresh(routes(), REFRESHED), "both fresh routes"
    )
    pid = r1.cmd("cat /var/run/frr/bgpd.pid").strip()
    save("baseline")
    previous_pid = stop_peer()
    wait_for(
        lambda: stale(routes(), OLD) and stale(routes(), REFRESHED),
        "both routes to become stale",
    )
    save("first-loss-both-retained")
    reply = r2.cmd(r"sed -i '/network 198.51.100.1\/32/d' /etc/frr/frr.conf")
    assert not reply, reply
    assert OLD not in r2.cmd("cat /etc/frr/frr.conf")
    start_peer(previous_pid)
    wait_for(
        lambda: stale(routes(), OLD) and fresh(routes(), REFRESHED),
        "partial replay without EOR",
    )
    save("first-recovery-partial-replay-no-eor")
    previous_pid = stop_peer()
    save("second-loss-before-adjudication")
    wait_for(
        lambda: stale(routes(), REFRESHED),
        "refreshed route retention after second loss",
    )
    save("second-loss")
    deadline = time.monotonic() + 5
    while OLD in routes() and time.monotonic() < deadline:
        time.sleep(0.1)
    save("second-loss-adjudication")
    assert (
        OLD not in routes()
    ), "preceding GR stale route survived the consecutive restart"
    assert stale(routes(), REFRESHED), "refreshed route lost first-GR retention"
    assert r1.cmd("cat /var/run/frr/bgpd.pid").strip() == pid
    start_peer(previous_pid)
    reply = r2.vtysh_cmd(
        "configure terminal\nrouter bgp 65002\nno bgp graceful-restart disable-eor\naddress-family ipv4 unicast\nnetwork 198.51.100.1/32\nend"
    )
    assert "%" not in reply, reply
    wait_for(
        lambda: fresh(routes(), OLD) and fresh(routes(), REFRESHED), "both fresh routes"
    )
    save("recovered")
