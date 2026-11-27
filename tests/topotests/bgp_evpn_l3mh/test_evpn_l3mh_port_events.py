# SPDX-License-Identifier: ISC
# Copyright (c) 2026 Cisco Systems, Inc.

import time
from pathlib import Path

import pytest

import test_evpn_l3mh as l3mh
from l3mh_netlink import check_probe

pytestmark = l3mh.pytestmark
VID = l3mh.HOST_VID
PORT = "hostbond1"
PROTECTION = "evpn mh bridge-port-protection"
HOLD_SECONDS = 600


def setup_module(module):
    l3mh.setup_module(module, extra_es_peer=True)


def teardown_module(module):
    l3mh.teardown_module(module)


class PortEvents:
    def __init__(self, leaves, family):
        self.leaves = leaves
        self.family = family
        self.owner, self.peer, self.other = leaves
        self.bindings = set()

    def binding(self, number, mac=None, vid=VID, *, family=None):
        family = family or self.family
        ip = f"fd00:45::{number}" if family == "ipv6" else f"45.0.0.{number}"
        entry = (ip, mac or f"02:00:00:00:01:{number:02x}", vid)
        self.bindings.add(entry)
        return entry

    def arp(self, leaf, entry, state="reachable"):
        ip, mac, vid = entry
        leaf.cmd_raises(f"ip neigh replace {ip} lladdr {mac} dev vlan{vid} nud {state}")

    def delete_arp(self, leaf, entry):
        ip, _, vid = entry
        leaf.cmd_raises(f"ip neigh del {ip} dev vlan{vid}")

    def fdb(self, leaf, entry, op="replace"):
        _, mac, vid = entry
        flag = " dynamic" if op == "replace" else ""
        leaf.cmd_raises(f"bridge fdb {op} {mac} dev {PORT} master vlan {vid}{flag}")

    def learn(self, leaf, entry):
        self.fdb(leaf, entry)
        self.arp(leaf, entry)

    def flap(self, state):
        self.owner.cmd_raises(f"ip link set dev {PORT} {state}")
        self.settle()

    def settle(self):
        l3mh._settle(self.leaves)

    def route(self, source, entry, receiver=None):
        ip, mac, vid = entry
        return l3mh._pure_l3_rt2_path(
            receiver or self.other, 65010 + int(source.name[-1]), ip, vid, mac
        )

    def status(self, entry, state=None, leaf=None):
        leaf = leaf or self.owner
        ip, mac, vid = entry
        words = leaf.cmd_raises(f"ip neigh show to {ip} dev vlan{vid}").split()
        if state:
            assert state in words, (leaf.name, entry, words)
            if state != "FAILED" or "lladdr" in words:
                assert mac in words, (leaf.name, entry, words)
        else:
            assert not words, (leaf.name, entry, words)
        return leaf.vtysh_cmd(
            f"show evpn arp-cache vni {l3mh.L3VNI} ip {ip} json", isjson=True
        )

    def pinned(self, entry):
        return l3mh._mac_static_pinned(self.owner, entry[1], entry[2])


@pytest.fixture
def events(request):
    tgen = l3mh.get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    case = PortEvents(
        tuple(tgen.gears[name] for name in ("leaf1", "leaf2", "leaf4")),
        getattr(request, "param", "ipv4"),
    )
    owner = case.owner
    timers = [f"net.ipv4.neigh.vlan{vid}.retrans_time_ms" for vid in (VID, VID + 1)]
    if case.family == "ipv6":
        timers.append(f"net.ipv6.neigh.vlan{VID}.retrans_time_ms")
    original = {}
    try:
        for leaf in case.leaves:
            for timer in timers:
                value = leaf.cmd_raises(f"sysctl -n {timer}").strip()
                original[leaf.name, timer] = value
                leaf.cmd_raises(f"sysctl -qw {timer}=60000")
        owner.vtysh_cmd(
            f"configure terminal\nevpn mh l3-neigh-down-peering-time {HOLD_SECONDS}\n"
            f"interface {PORT}\n {PROTECTION}",
            raises=True,
        )
        yield case
    finally:
        owner.cmd_raises(f"ip link set dev {PORT} up")
        owner.vtysh_cmd(
            f"configure terminal\nno evpn mh l3-neigh-down-peering-time\ninterface {PORT}\n"
            f" no {PROTECTION}",
            raises=True,
        )
        for leaf in case.leaves:
            for ip, mac, vid in case.bindings:
                leaf.run(f"ip neigh del {ip} dev vlan{vid} 2>/dev/null")
                leaf.run(
                    f"bridge fdb del {mac} dev {PORT} master vlan {vid} 2>/dev/null"
                )
            for timer in timers:
                if (leaf.name, timer) in original:
                    leaf.cmd_raises(f"sysctl -qw {timer}={original[leaf.name, timer]}")


def test_peer_ready_and_peer_arriving_while_port_is_down(events):
    owner, peer, _ = events.leaves
    ready, late = (events.binding(i) for i in (101, 102))
    for entry in (ready, late):
        events.learn(owner, entry)
    events.settle()
    events.arp(peer, ready)
    l3mh._relearn_local_fdb(peer, ready[1], leaves=events.leaves)
    events.settle()
    assert events.route(owner, ready) and events.route(peer, ready)
    assert events.route(owner, late)

    log = Path(owner.logdir) / owner.name / "zebra.log"
    offset = log.stat().st_size
    owner.vtysh_cmd("configure terminal\ndebug zebra evpn mh l3vni-neigh", raises=True)
    before_down = time.monotonic()
    try:
        events.flap("down")
        with log.open(encoding="utf-8") as stream:
            stream.seek(offset)
            transitions = stream.read()
        assert (
            f"event down-peering-start next handoff-wait ip {late[0]} " in transitions
        )
        assert (
            f"event down-peering-start next handoff-wait ip {ready[0]} "
            not in transitions
        )
    finally:
        owner.vtysh_cmd(
            "configure terminal\nno debug zebra evpn mh l3vni-neigh", raises=True
        )
    detail = events.status(ready, "PERMANENT")
    assert detail.get("l3mhState") == "peer-sync-protected", detail
    assert detail.get("timerState") == "inactive", detail
    assert events.pinned(ready) and not events.route(owner, ready)
    detail = events.status(late, "PERMANENT")
    assert detail.get("timerState") == "down-peering", detail
    hours, minutes, seconds = (
        int(part) for part in detail["timerRemaining"].split(":")
    )
    remaining = 3600 * hours + 60 * minutes + seconds
    assert (
        HOLD_SECONDS - (time.monotonic() - before_down) - 1 <= remaining <= HOLD_SECONDS
    )
    assert events.pinned(late) and events.route(owner, late)

    events.learn(peer, late)
    events.settle()
    detail = events.status(late, "PERMANENT")
    assert detail.get("l3mhState") == "peer-sync-protected", detail
    assert detail.get("timerState") == "inactive", detail
    assert events.pinned(late) and not events.route(owner, late)
    assert events.route(peer, late)


def test_retained_validation_learning_orders_and_mobility(events):
    owner, peer, _ = events.leaves
    arp_first, mac_first, shared, moved, failed, fallback = (
        events.binding(i) for i in range(103, 109)
    )
    moved_mac = events.binding(110)
    entries = (arp_first, mac_first, shared, moved, failed, fallback, moved_mac)
    sibling = events.binding(109, shared[1])
    new_vlan = events.binding(106, moved[1], VID + 1)
    new_mac = events.binding(110, "02:00:00:00:01:ff")
    for entry in entries:
        events.learn(owner, entry)
    events.settle()

    events.flap("down")
    events.flap("up")
    for entry in entries:
        events.status(entry, "PROBE")
        assert events.route(owner, entry)
        assert not events.pinned(entry)

    events.learn(peer, sibling)
    events.settle()
    events.status(sibling, "PERMANENT")
    assert events.pinned(shared)
    events.arp(owner, arp_first)
    events.fdb(owner, mac_first)
    events.arp(owner, shared)
    events.arp(owner, new_vlan)
    events.arp(owner, new_mac)
    events.learn(peer, fallback)
    events.settle()
    for entry in (arp_first, mac_first):
        detail = events.status(entry, "REACHABLE" if entry == arp_first else "PROBE")
        assert detail.get("l3mhState") == "validation-pending", detail
        assert events.route(owner, entry)
    assert events.status(shared, "REACHABLE").get("l3mhState") == "local-dynamic"
    assert events.pinned(shared) and events.route(owner, shared)
    assert not events.route(owner, moved) and not events.route(owner, new_vlan)
    assert not events.route(owner, moved_mac) and not events.route(owner, new_mac)
    assert events.route(peer, fallback)

    events.fdb(owner, arp_first)
    events.arp(owner, mac_first)
    events.fdb(owner, new_vlan)
    events.fdb(owner, new_mac)
    events.arp(owner, failed, "failed")
    events.arp(owner, fallback, "failed")
    events.arp(owner, moved, "failed")
    events.settle()
    for entry in (arp_first, mac_first, new_vlan, new_mac):
        assert events.status(entry, "REACHABLE").get("l3mhState") == "local-dynamic"
        assert events.route(owner, entry)
    assert not events.route(owner, moved)
    assert not events.route(owner, moved_mac)
    failed_entry = owner.cmd_raises(f"ip neigh show to {failed[0]} dev vlan{VID}")
    assert "FAILED" in failed_entry and not events.pinned(failed), failed_entry
    assert not events.route(owner, failed)
    events.status(fallback, "PERMANENT")
    assert events.pinned(fallback) and not events.route(owner, fallback)


def test_peer_static_validation_shared_mac_and_fallback_changes(events):
    owner, peer, other = events.leaves
    shared, replacement, unbacked, deferred, timeout = (
        events.binding(i) for i in (111, 112, 113, 115, 165)
    )
    sibling = events.binding(114, shared[1])
    entries = (shared, replacement, unbacked, deferred, timeout)
    for entry in entries:
        events.learn(peer, entry)
    events.settle()
    for entry in entries:
        events.status(entry, "PERMANENT")

    events.flap("down")
    events.flap("up")
    for entry in entries:
        events.status(entry, "PROBE")
        assert not events.route(owner, entry)

    events.learn(peer, sibling)
    with check_probe(owner, replacement), check_probe(owner, timeout):
        for entry in (replacement, timeout):
            events.arp(other, entry)
        events.settle()
        for entry in (replacement, timeout):
            events.fdb(other, entry)
        events.settle()
    for entry in (replacement, timeout):
        assert events.route(peer, entry, owner) and events.route(other, entry, owner)
        detail = events.status(entry, "PROBE")
        assert detail.get("peerOrigin") == l3mh.LEAF_LO[other.name], detail
    events.status(sibling, "PERMANENT")
    assert events.pinned(shared)
    events.arp(owner, shared)
    events.arp(owner, deferred)
    with check_probe(owner, replacement), check_probe(owner, timeout):
        for entry in (replacement, timeout):
            events.arp(other, entry, "failed")
        events.arp(peer, unbacked, "failed")
        events.settle()
    events.status(shared, "REACHABLE")
    assert events.route(owner, shared) and events.pinned(shared)
    for entry in (replacement, timeout):
        assert not events.route(other, entry, owner) and events.route(
            peer, entry, owner
        )
        detail = events.status(entry, "PROBE")
        assert detail.get("peerOrigin") == l3mh.LEAF_LO[peer.name], detail
    detail = events.status(unbacked, "PROBE")
    assert not detail.get("peerPresent"), detail

    detail = events.status(deferred, "REACHABLE")
    assert detail.get("l3mhState") == "validation-pending", detail
    assert detail.get("peerOrigin") == l3mh.LEAF_LO[peer.name], detail
    assert not events.route(owner, deferred)
    events.fdb(owner, deferred)
    events.arp(owner, timeout, "failed")
    events.settle()
    assert events.status(deferred, "REACHABLE").get("l3mhState") == "local-dynamic"
    assert events.route(owner, deferred)
    detail = events.status(timeout, "PERMANENT")
    assert detail.get("peerOrigin") == l3mh.LEAF_LO[peer.name], detail
    assert events.pinned(timeout) and not events.route(owner, timeout)

    events.flap("down")
    events.status(unbacked)
    assert not events.pinned(unbacked) and not events.route(owner, unbacked)
    events.status(replacement, "PERMANENT")
    assert events.pinned(replacement) and not events.route(owner, replacement)
