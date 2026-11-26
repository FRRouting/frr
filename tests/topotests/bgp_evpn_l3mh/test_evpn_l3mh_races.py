# SPDX-License-Identifier: ISC
# Copyright (c) 2026 Cisco Systems, Inc.

import configparser
import subprocess
from pathlib import Path
from unittest.mock import patch

import pytest

import test_evpn_l3mh as l3mh
from lib.topogen import TopoRouter
from l3mh_netlink import (
    check_fdb_delete,
    check_probe,
    check_static_fdb,
    has_dynamic_fdb,
    observe_probe,
    watch_binding,
)
from test_evpn_l3mh_aging import send_arp
from test_evpn_l3mh_port_events import PORT, VID, events
from test_evpn_l3mh_three_peers import _es_rd, _per_es_route_targets

pytestmark = l3mh.pytestmark

VTY = """
import socket
import sys

with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connection:
    connection.settimeout(5)
    connection.connect("/var/run/frr/zebra.vty")
    connection.sendall(("show l3mh-test " + sys.argv[1] + "\\0").encode())
    reply = b""
    while len(reply) < 4 or reply[-4:-1] != bytes(3):
        chunk = connection.recv(4096)
        assert chunk, reply
        reply += chunk
    assert reply[-1] == 0, (sys.argv[1], reply)
"""


def setup_module(module):
    settings = configparser.ConfigParser()
    settings.read(Path(__file__).resolve().parents[1] / "pytest.ini")
    binary = Path(settings.get("topogen", "frrdir", fallback="/usr/lib/frr")) / "zebra"
    version = subprocess.check_output([binary, "--version"], text=True)
    if "--enable-dev-build" not in version:
        pytest.skip("L3MH race controls are built with --enable-dev-build")
    original = TopoRouter.load_frr_config

    def load(self, source="frr.conf", daemons=None, extra_daemons=None):
        if self.name in ("leaf1", "leaf2"):
            daemons = [("zebra", "-M l3mh_test"), "bgpd"]
        return original(self, source, daemons, extra_daemons)

    with patch.object(TopoRouter, "load_frr_config", load):
        l3mh.setup_module(module, extra_es_peer=True)


def teardown_module(module):
    l3mh.teardown_module(module)


def control(leaf, command):
    leaf.cmd_raises(["python3", "-c", VTY, command])


def test_peer_rt2_installs_when_local_mac_missing(events):
    owner, peer, _ = events.leaves
    entry = events.binding(244)
    events.learn(owner, entry)
    events.settle()
    assert events.route(owner, entry)
    events.fdb(owner, entry, "del")
    events.settle()
    events.status(entry, "REACHABLE")
    assert not events.route(owner, entry) and not events.pinned(entry)
    events.learn(peer, entry)
    events.settle()
    assert events.route(peer, entry, owner)
    events.status(entry, "PERMANENT")
    assert events.pinned(entry)


def test_peer_rt2_is_cached_during_local_probe_without_mac(events):
    owner, peer, _ = events.leaves
    entry = events.binding(254)
    events.learn(owner, entry)
    events.settle()
    events.fdb(owner, entry, "del")
    events.arp(owner, entry, "probe")
    events.settle()
    assert not events.route(owner, entry)
    events.learn(peer, entry)
    events.settle()
    assert events.route(peer, entry, owner)
    assert events.status(entry, "PROBE")["type"] == "local"
    assert not events.pinned(entry)
    events.arp(owner, entry, "failed")
    events.settle()
    events.status(entry, "PERMANENT")
    assert events.pinned(entry)


def test_early_fdb_and_old_arp_notifications_during_hold(events):
    owner = events.owner
    early, alone = (events.binding(i) for i in (120, 121))
    for entry in (early, alone):
        events.learn(owner, entry)
    events.settle()
    assert events.route(owner, early) and events.route(owner, alone)

    events.fdb(owner, alone, "del")
    events.settle()
    assert not events.route(owner, alone)
    detail = events.status(alone, "REACHABLE")
    assert detail.get("l3mhState") != "handoff-wait", detail

    control(owner, f"early-fdb {early[0]}")
    events.settle()
    assert events.route(owner, early) and events.pinned(early)
    assert events.status(early, "PERMANENT").get("l3mhState") == "handoff-wait"

    control(owner, f"old-arp {early[0]}")
    control(owner, f"arm before-repair {early[0]}")
    owner.cmd_raises(f"ip neigh del {early[0]} dev vlan{VID}")
    events.settle()
    control(owner, "held-create-only before")
    events.status(early)
    control(owner, "release before")
    events.settle()
    entry = events.status(early, "PERMANENT")
    assert entry.get("timerState") == "down-peering", entry
    assert events.route(owner, early) and events.pinned(early)


def test_rt2_withdrawal_and_replacement_rt1_loss_during_queued_probe(events):
    owner, peer, other = events.leaves
    withdrawn, replaced = (events.binding(i) for i in (122, 123))
    failed = events.binding(131)
    events.learn(peer, withdrawn)
    events.learn(peer, failed)
    events.learn(other, replaced)
    events.settle()
    for entry in (withdrawn, replaced, failed):
        events.status(entry, "PERMANENT")

    control(owner, f"old-withdraw {withdrawn[0]}")
    control(owner, f"replacement-loss {replaced[0]} {l3mh.LEAF_LO[peer.name]}")
    events.settle()
    assert not events.status(withdrawn, "PROBE").get("peerPresent")
    detail = events.status(replaced, "PROBE")
    assert detail.get("peerRt1Lost"), detail
    assert detail.get("peerOrigin") == l3mh.LEAF_LO[peer.name], detail
    assert not events.pinned(withdrawn) and not events.pinned(replaced)
    events.status(failed, "PROBE")
    events.arp(owner, failed, "failed")
    events.settle()
    peer.cmd_raises(f"ip neigh del {failed[0]} dev vlan{VID}")
    events.settle()
    failure = owner.cmd_raises(f"ip neigh show to {failed[0]} dev vlan{VID}")
    assert "FAILED" in failure and not events.pinned(failed), failure


def test_failed_static_delete_and_pending_probe_across_reflap(events):
    owner = events.owner
    empty, occupied, reflap = (events.binding(i) for i in (124, 125, 126))
    for entry in (empty, occupied, reflap):
        events.learn(owner, entry)
    events.settle()
    events.flap("down")
    control(owner, f"arm before-delete {empty[0]}")
    control(owner, f"arm after-delete {reflap[0]}")
    events.flap("up")
    control(owner, "held before")
    control(owner, "held after")

    owner.cmd_raises(f"ip neigh del {empty[0]} dev vlan{VID}")
    events.settle()
    control(owner, "fail before")
    events.settle()
    events.status(empty, "PROBE")
    assert not events.pinned(empty) and events.route(owner, empty)

    events.flap("down")
    control(owner, f"arm before-delete {occupied[0]}")
    events.flap("up")
    entry = events.status(reflap, "PERMANENT")
    assert entry.get("l3mhState") == "validation-pending", entry
    assert events.route(owner, reflap)
    control(owner, "fail before")
    control(owner, "release after")
    events.settle()
    events.status(occupied, "PERMANENT")
    assert events.pinned(occupied) and events.route(owner, occupied)
    events.status(reflap, "PROBE")
    assert events.route(owner, reflap)


def test_peer_validation_keeps_static_arp_until_zebra_delete(events):
    owner, peer, _ = events.leaves
    entry = events.binding(154)
    events.learn(peer, entry)
    events.settle()
    events.status(entry, "PERMANENT")
    events.flap("down")
    control(owner, f"arm before-delete {entry[0]}")
    events.flap("up")
    control(owner, "held before")

    send_arp(owner, entry, "host1-eth0")
    events.settle()
    events.status(entry, "PERMANENT")
    assert events.pinned(entry) and not events.route(owner, entry)

    control(owner, "release before")
    events.settle()
    detail = events.status(entry, "PROBE")
    assert detail.get("peerOrigin") == l3mh.LEAF_LO[peer.name], detail
    assert not events.pinned(entry) and not events.route(owner, entry)


@pytest.mark.parametrize("backed", (True, False), ids=("fallback", "unbacked"))
def test_reflap_cancels_held_peer_validation_result(events, backed):
    owner, peer, _ = events.leaves
    entry = events.binding(166 if backed else 167)
    events.learn(peer, entry)
    events.settle()
    events.status(entry, "PERMANENT")
    events.flap("down")
    control(owner, f"arm after-delete {entry[0]}")
    events.flap("up")
    control(owner, "held after")
    detail = events.status(entry)
    assert detail.get("l3mhState") == "validation-pending", detail
    assert detail.get("peerOrigin") == l3mh.LEAF_LO[peer.name], detail
    if not backed:
        events.arp(peer, entry, "failed")
        events.settle()
        assert not events.status(entry).get("peerPresent")

    def check_canceled():
        detail = events.status(entry, "PERMANENT" if backed else None)
        if backed:
            assert detail.get("peerOrigin") == l3mh.LEAF_LO[peer.name], detail
        else:
            assert not detail.get("l3mhState"), detail
        assert events.pinned(entry) is backed
        assert bool(events.route(peer, entry, owner)) is backed
        assert not events.route(owner, entry)

    events.flap("down")
    check_canceled()
    with watch_binding(owner, entry) as changes:
        control(owner, "release after")
        events.settle()
    assert not changes, changes
    check_canceled()


def test_vlan_move_releases_only_its_old_validation_pin(events):
    owner, peer, _ = events.leaves
    old = events.binding(168)
    moved = events.binding(168, old[1], VID + 1)
    sibling = events.binding(169, old[1])
    events.learn(owner, old)
    events.settle()
    events.flap("down")
    control(owner, f"arm before-delete {old[0]}")
    events.flap("up")
    control(owner, "held before")
    detail = events.status(old, "PERMANENT")
    assert detail.get("l3mhState") == "validation-pending", detail
    assert events.pinned(old) and events.route(owner, old)
    events.learn(peer, sibling)
    events.settle()
    events.status(sibling, "PERMANENT")

    with check_static_fdb(owner, old):
        events.arp(owner, moved)
        events.settle()
        assert not events.route(owner, old) and not events.route(owner, moved)
        events.fdb(owner, moved)
        events.settle()
        assert events.route(owner, moved) and has_dynamic_fdb(owner, moved)
        control(owner, "release before")
        events.settle()
    events.status(old)
    events.status(moved, "REACHABLE")
    events.status(sibling, "PERMANENT")
    assert events.pinned(sibling) and events.route(owner, moved)

    events.arp(peer, sibling, "failed")
    events.settle()
    assert not events.pinned(sibling)
    assert has_dynamic_fdb(owner, moved) and events.route(owner, moved)


def test_retained_probe_failure_keeps_pin_for_other_static_ip(events):
    owner, peer, _ = events.leaves
    entry = events.binding(163)
    sibling = events.binding(164, entry[1])
    events.learn(owner, entry)
    events.settle()
    events.flap("down")
    events.status(entry, "PERMANENT")
    assert events.pinned(entry) and events.route(owner, entry)

    control(owner, f"arm before-delete {entry[0]}")
    events.flap("up")
    control(owner, "held before")
    events.learn(peer, sibling)
    events.settle()
    events.status(sibling, "PERMANENT")
    assert events.pinned(sibling) and events.route(peer, sibling)
    detail = events.status(entry, "PERMANENT")
    assert detail.get("l3mhState") == "validation-pending", detail
    assert not detail.get("peerPresent") and events.route(owner, entry)

    with check_fdb_delete(owner, entry):
        with observe_probe(owner, entry):
            control(owner, "release before")
        events.status(entry, "PROBE")
        assert events.route(owner, entry)
        events.arp(owner, entry, "failed")
        events.settle()
        events.status(entry, "FAILED")
        assert not events.route(owner, entry)
        events.delete_arp(owner, entry)
        events.settle()
        events.status(entry)
        assert not events.route(owner, entry)
    events.status(sibling, "PERMANENT")
    assert events.pinned(sibling) and events.route(peer, sibling)


def test_expiry_keeps_mac_pinned_for_other_retained_ip(events):
    owner, peer, _ = events.leaves
    expired = events.binding(159)
    retained = events.binding(160, expired[1])
    events.learn(owner, expired)
    events.arp(owner, retained)
    events.settle()
    assert events.route(owner, expired) and events.route(owner, retained)

    events.flap("down")
    for entry in (expired, retained):
        detail = events.status(entry, "PERMANENT")
        assert detail.get("timerState") == "down-peering", detail
    assert events.pinned(expired)
    version = l3mh._local_rt2_version(owner, retained[0])
    assert version is not None

    assert events.route(owner, expired, peer)
    events.status(expired, "PROBE", peer)
    with check_fdb_delete(owner, retained), check_probe(peer, expired):
        control(owner, f"immediate-expiry {expired[0]}")
        events.settle()
    events.status(expired)
    assert not events.route(owner, expired)
    assert not events.route(owner, expired, peer)
    assert not events.status(expired, "PROBE", peer).get("peerPresent")
    detail = events.status(retained, "PERMANENT")
    assert detail.get("timerState") == "down-peering", detail
    assert events.pinned(retained) and events.route(owner, retained)
    assert l3mh._local_rt2_version(owner, retained[0]) == version

    with check_fdb_delete(owner, retained, deleted=True):
        control(owner, f"immediate-expiry {retained[0]}")
        events.settle()
    events.status(retained)
    assert not events.pinned(retained) and not events.route(owner, retained)

    with check_probe(peer, expired):
        events.flap("up")
    routes = peer.vtysh_cmd("show bgp l2vpn evpn route type 1 json", isjson=True)
    assert _per_es_route_targets(routes, _es_rd(owner))
    assert not events.status(expired, "PROBE", peer).get("peerPresent")


def test_expiry_fdb_delete_completion_preserves_fresh_dynamic_mac(events):
    owner = events.owner
    entry = events.binding(161)
    events.learn(owner, entry)
    events.settle()
    assert events.route(owner, entry)

    control(owner, "immediate-expiry")
    control(owner, f"arm after-mac {entry[1]}")
    events.flap("down")
    control(owner, "held after")
    events.status(entry)
    assert not events.route(owner, entry)
    assert entry[1] not in owner.cmd_raises(f"bridge fdb show dev {PORT}")

    events.flap("up")
    send_arp(owner, entry, "host1-eth0", request=True)
    events.settle()
    assert events.status(entry, "STALE").get("l3mhState") == "local-dynamic"
    version = l3mh._local_rt2_version(owner, entry[0])
    assert version is not None and events.route(owner, entry)
    assert entry[1] in owner.cmd_raises(f"bridge fdb show dev {PORT}")
    assert not events.pinned(entry)
    control(owner, "held after")

    control(owner, "release after")
    events.settle()
    assert events.status(entry, "STALE").get("l3mhState") == "local-dynamic"
    assert l3mh._local_rt2_version(owner, entry[0]) == version
    assert events.route(owner, entry) and not events.pinned(entry)
    assert entry[1] in owner.cmd_raises(f"bridge fdb show dev {PORT}")


@pytest.mark.parametrize(
    "first_learn",
    ("local-first", "peer-first", "peer-first-timeout", "peer-first-while-down"),
)
def test_expiry_completion_after_fresh_binding(events, first_learn):
    owner, peer, _ = events.leaves
    local_first = first_learn == "local-first"
    first = owner if local_first else peer
    codes = {
        "local-first": 127,
        "peer-first": 128,
        "peer-first-timeout": 155,
        "peer-first-while-down": 144,
    }
    entry = events.binding(codes[first_learn])
    events.learn(owner, entry)
    events.settle()
    assert events.route(owner, entry)
    events.status(entry, "PERMANENT", peer)
    rd = _es_rd(owner)

    def peer_rt1():
        routes = peer.vtysh_cmd("show bgp l2vpn evpn route type 1 json", isjson=True)
        return _per_es_route_targets(routes, rd)

    control(owner, "immediate-expiry")
    control(owner, f"arm after-delete {entry[0]}")
    if local_first:
        control(peer, f"arm after-delete {entry[0]}")
    events.flap("down")
    control(owner, "held after")
    assert not events.route(owner, entry)
    assert not peer_rt1()
    events.status(entry)

    if first_learn != "peer-first-while-down":
        events.flap("up")
        assert peer_rt1()
        events.status(entry)
        assert not events.route(owner, entry)
        if local_first:
            # The original RT-2 withdrew before RT-1 was restored. The
            # receiver's old delete must finish before its probe can start.
            assert not events.route(owner, entry, peer)
            control(peer, "held after")
            events.status(entry, leaf=peer)
            control(peer, "release after")
            events.settle()
            events.status(entry, "PROBE", peer)
    if local_first:
        send_arp(owner, entry, "host1-eth0", request=True)
    else:
        events.learn(peer, entry)
    events.settle()
    state = "STALE" if local_first else "PERMANENT"
    events.status(entry, state)
    assert events.route(first, entry)
    control(owner, "release after")
    events.settle()
    events.status(entry, state)
    assert events.route(first, entry)
    assert events.pinned(entry) is not local_first

    if local_first:
        version = l3mh._local_rt2_version(owner, entry[0])
        events.arp(peer, entry)
        l3mh._relearn_local_fdb(peer, entry[1], leaves=events.leaves)
        events.settle()
        assert events.route(peer, entry)
        assert events.status(entry, state).get("l3mhState") == "local-dynamic"
        assert has_dynamic_fdb(owner, entry)
        assert l3mh._local_rt2_version(owner, entry[0]) == version
        return
    if first_learn == "peer-first":
        send_arp(owner, entry, "host1-eth0")
        events.settle()
        events.status(entry, "PERMANENT")
        assert events.pinned(entry) and not events.route(owner, entry)
    assert events.route(peer, entry) and not events.route(owner, entry)
    peer.cmd_raises(f"ip neigh del {entry[0]} dev vlan{VID}")
    events.settle()
    events.status(entry, "PROBE")
    assert not events.pinned(entry) and not events.route(peer, entry)
    if first_learn in ("peer-first-timeout", "peer-first-while-down"):
        events.arp(owner, entry, "failed")
        events.settle()
        failure = owner.cmd_raises(f"ip neigh show to {entry[0]} dev vlan{VID}")
        assert "FAILED" in failure.split() and not events.route(owner, entry), failure
    else:
        send_arp(owner, entry, "host1-eth0")
        events.settle()
        events.status(entry, "REACHABLE")
        assert events.route(owner, entry)


@pytest.mark.parametrize("replace_local", (False, True), ids=("peer", "local"))
def test_old_probe_cleanup_preserves_new_binding(events, replace_local):
    owner, peer, other = events.leaves
    entry = events.binding(145 if replace_local else 146)
    new = owner if replace_local else other
    events.learn(peer, entry)
    events.settle()
    events.status(entry, "PERMANENT")
    control(owner, f"arm after-delete {entry[0]}")
    peer.cmd_raises(f"ip neigh del {entry[0]} dev vlan{VID}")
    events.settle()
    control(owner, "held after")
    events.status(entry)
    if replace_local:
        # The local ARP releases the old static pin. Learn M1 after that
        # delete while the separate neighbor result is still held.
        events.arp(new, entry)
        l3mh._relearn_local_fdb(new, entry[1], leaves=events.leaves)
    else:
        events.learn(new, entry)
    events.settle()
    state = "REACHABLE" if replace_local else "PERMANENT"
    events.status(entry, state)
    assert events.route(new, entry, peer)
    control(owner, "release after")
    events.settle()
    events.status(entry, state)
    assert events.route(new, entry, peer)
    assert events.pinned(entry) is not replace_local
    if replace_local:
        assert entry[1] in owner.cmd_raises(f"bridge fdb show dev {PORT}")
        return

    # This time the old probe has failed before the replacement arrives.
    other.cmd_raises(f"ip neigh del {entry[0]} dev vlan{VID}")
    events.settle()
    events.status(entry, "PROBE")
    events.arp(owner, entry, "failed")
    events.settle()
    failure = owner.cmd_raises(f"ip neigh show to {entry[0]} dev vlan{VID}")
    assert "FAILED" in failure.split(), failure
    events.learn(other, entry)
    events.settle()
    events.status(entry, "PERMANENT")
    assert events.pinned(entry)
    for action in ("stale-failed", "stale-gc"):
        control(owner, f"{action} {entry[0]}")
        events.settle()
        assert (
            events.status(entry, "PERMANENT").get("peerOrigin")
            == l3mh.LEAF_LO[other.name]
        )
        assert events.pinned(entry) and events.route(other, entry, owner)
        assert not events.route(owner, entry)


def test_new_static_user_before_old_fdb_delete_completion(events):
    owner, peer, _ = events.leaves
    old = events.binding(129)
    new = events.binding(130, old[1])
    companion = events.binding(147, old[1])
    events.learn(peer, old)
    events.settle()
    events.status(old, "PERMANENT")
    assert events.pinned(old)
    events.arp(owner, companion)
    events.settle()
    assert events.route(owner, companion)

    control(owner, f"arm before-mac {old[1]}")
    control(owner, f"arm after-mac {old[1]}")
    peer.cmd_raises(f"ip neigh del {old[0]} dev vlan{VID}")
    events.settle()
    control(owner, "held before")
    assert events.pinned(old)
    events.learn(peer, new)
    events.settle()
    events.status(new, "PERMANENT")
    events.status(companion, "REACHABLE")
    control(owner, "held-install before")
    control(owner, "release before")
    events.settle()
    control(owner, "held after")
    assert events.pinned(new)
    control(owner, "release after")
    events.settle()
    events.status(new, "PERMANENT")
    assert events.route(peer, new) and events.pinned(new)
    events.status(companion, "REACHABLE")
    assert events.route(owner, companion)


def test_late_kernel_notification_preserves_current_local_arp(events):
    owner = events.owner
    entry = events.binding(176)
    events.learn(owner, entry)
    events.settle()
    version = l3mh._local_rt2_version(owner, entry[0])
    assert events.route(owner, entry) and version is not None

    for event in ("stale-failed", "stale-gc"):
        control(owner, f"{event} {entry[0]}")
        events.settle()
        events.status(entry, "REACHABLE")
        assert has_dynamic_fdb(owner, entry) and events.route(owner, entry), event
        assert l3mh._local_rt2_version(owner, entry[0]) == version

    events.arp(owner, entry, "failed")
    events.settle()
    assert not events.route(owner, entry)
    send_arp(owner, entry, "host1-eth0", request=True)
    events.settle()
    assert events.route(owner, entry) and has_dynamic_fdb(owner, entry)


@pytest.mark.parametrize("action", ("release", "fail"))
def test_shared_static_pin_must_be_installed_before_local_rt2(events, action):
    owner, peer, _ = events.leaves
    local = events.binding(177 if action == "release" else 179)
    remote = events.binding(178 if action == "release" else 180, local[1])
    events.arp(owner, local)
    events.settle()
    assert not events.route(owner, local) and not events.pinned(local)

    control(owner, f"arm before-pin {local[1]}")
    events.learn(peer, remote)
    events.settle()
    control(owner, "held before")
    assert not events.pinned(local)
    assert not events.route(owner, local)

    control(owner, f"{action} before")
    events.settle()
    assert events.pinned(local) is (action == "release")
    assert bool(events.route(owner, local)) is (action == "release")
    if action == "fail":
        events.fdb(owner, local)
        events.settle()
        events.status(remote, "PERMANENT")
        assert events.route(owner, local) and events.pinned(local)


@pytest.mark.parametrize(
    "withdraw_first", (False, True), ids=("failure-first", "withdraw-first")
)
def test_existing_same_key_survivor_backs_probe_after_rt1_loss(events, withdraw_first):
    owner, selected, survivor = events.leaves
    entry = events.binding(181)
    config = f"configure terminal\ninterface {PORT}\n"
    protection = "evpn mh bridge-port-protection"
    debug = "debug bgp evpn mh l3vni-neigh"
    log = Path(owner.logdir) / owner.name / "bgpd.log"
    origin = l3mh.LEAF_LO[selected.name]
    lookup_log = f"L3MH RT-1 fallback VNI {l3mh.L3VNI} origin {origin}: "
    selected.vtysh_cmd(config + protection, raises=True)
    owner.vtysh_cmd(debug, raises=True)
    try:
        events.learn(survivor, entry)
        events.settle()
        events.arp(selected, entry)
        l3mh._relearn_local_fdb(selected, entry[1], leaves=events.leaves)
        events.settle()
        detail = events.status(entry, "PERMANENT")
        assert detail.get("peerOrigin") == origin, detail
        for leaf in (selected, survivor):
            assert events.route(leaf, entry, owner)

        offset = log.stat().st_size
        selected.vtysh_cmd(config + "no " + protection, raises=True)
        events.settle()
        with log.open() as stream:
            stream.seek(offset)
            lookups = [
                line.split(lookup_log)[1].strip()
                for line in stream
                if lookup_log in line
            ]
        assert lookups == ["1 lookups"], lookups
        events.status(entry, "PROBE")
        assert events.route(selected, entry, owner)
        if withdraw_first:
            with check_probe(owner, entry):
                events.delete_arp(selected, entry)
                events.settle()
            assert not events.route(selected, entry, owner)
            events.status(entry, "PROBE")

        events.arp(owner, entry, "failed")
        events.settle()
        detail = events.status(entry, "PERMANENT")
        assert detail.get("peerOrigin") == l3mh.LEAF_LO[survivor.name], detail
        assert events.pinned(entry) and not events.route(owner, entry)
        if not withdraw_first:
            events.delete_arp(selected, entry)
            events.settle()
            assert (
                events.status(entry, "PERMANENT").get("peerOrigin")
                == l3mh.LEAF_LO[survivor.name]
            )
    finally:
        owner.vtysh_cmd("no " + debug, raises=True)
        selected.vtysh_cmd(config + "no " + protection, raises=True)


def test_retained_rt2_second_spine_copy_stays_ineligible(events):
    owner, receiver, _ = events.leaves
    entry = events.binding(182)
    spine = "192.168.5.1"
    rmap = "L3MH-HOLD-SPINE"
    address_family = "router bgp 65012\n address-family l2vpn evpn\n"

    def configure(commands):
        receiver.vtysh_cmd("configure terminal\n" + commands, raises=True)

    def spines():
        routes = receiver.vtysh_cmd(
            "show bgp l2vpn evpn route detail type macip json", isjson=True
        )
        rd = f"{l3mh.LEAF_LO[owner.name]}:"
        return {
            path["peer"]["peerId"]
            for key, table in routes.items()
            if key.startswith(rd)
            for route in table.values()
            if isinstance(route, dict) and route.get("ip") == entry[0]
            for paths in route["paths"]
            for path in paths
            if path.get("valid")
        }

    configure(
        f"route-map {rmap} deny 10\n match evpn route-type macip\n exit\n"
        f"route-map {rmap} permit 20\n exit\n"
        + address_family
        + f"  neighbor {spine} route-map {rmap} in"
    )
    remove = address_family + f"  no neighbor {spine} route-map {rmap} in"
    try:
        events.learn(owner, entry)
        events.settle()
        events.status(entry, "PERMANENT", receiver)
        assert spines() == {"192.168.2.1"}
        events.flap("down")
        events.status(entry, "PROBE", receiver)
        assert events.route(owner, entry, receiver)
        with check_probe(receiver, entry):
            configure(remove)
            receiver.vtysh_cmd(f"clear bgp l2vpn evpn {spine} soft in", raises=True)
            events.settle()
            assert spines() == {"192.168.2.1", spine}
        events.status(entry, "PROBE", receiver)
        assert not l3mh._mac_static_pinned(receiver, entry[1], VID)

        control(owner, f"immediate-expiry {entry[0]}")
        events.settle()
        assert not spines()
        events.flap("up")
        events.learn(owner, entry)
        events.settle()
        events.status(entry, "PERMANENT", receiver)
    finally:
        configure(remove + f"\n exit-address-family\n exit\nno route-map {rmap}")


def test_stale_pin_success_cannot_validate_deleted_mac(events):
    observer, owner, _ = events.leaves
    speaker = l3mh.get_topogen().gears["leaf3"]
    remote = events.binding(251)
    local = events.binding(252, remote[1])
    events.arp(owner, local)
    events.settle()
    with l3mh._raw_evpn_peer(owner, speaker, remote[1], remote[0]) as send:
        control(owner, f"arm after-pin {remote[1]}")
        send(f"announce 0 {l3mh.L3VNI}")
        events.settle()
        control(owner, "held after")
        assert l3mh._mac_static_pinned(owner, remote[1], remote[2])
        control(owner, f"arm before-pin {remote[1]}")
        events.fdb(owner, remote, "del")
        events.settle()
        control(owner, "held before")
        events.status(remote, "PERMANENT", owner)
        control(owner, "release after")
        events.settle()
        assert not events.route(owner, local, observer)
        assert not has_dynamic_fdb(owner, local)
        assert not l3mh._mac_static_pinned(owner, remote[1], remote[2])
        control(owner, "release before")
        events.settle()
        assert events.route(owner, local, observer)
        assert l3mh._mac_static_pinned(owner, remote[1], remote[2])


def test_loss_of_confirmed_pin_rechecks_dependent_local_rt2(events):
    observer, owner, _ = events.leaves
    speaker = l3mh.get_topogen().gears["leaf3"]
    remote = events.binding(237)
    local = events.binding(238, remote[1])
    events.arp(owner, local)
    events.settle()
    assert not events.route(owner, local, observer)

    # Keep the peer advertisement independent of the local RT-2 withdrawal.
    with l3mh._raw_evpn_peer(owner, speaker, remote[1], remote[0]) as send:
        send(f"announce 0 {l3mh.L3VNI}")
        events.settle()
        events.status(remote, "PERMANENT", owner)
        assert l3mh._mac_static_pinned(owner, remote[1], VID)
        assert events.route(owner, local, observer)
        control(owner, f"arm before-pin {remote[1]}")
        events.fdb(owner, remote, "del")
        events.settle()
        control(owner, "held before")
        events.status(remote, "PERMANENT", owner)
        events.status(local, "REACHABLE", owner)
        assert not l3mh._mac_static_pinned(owner, remote[1], VID)
        assert not has_dynamic_fdb(owner, local)
        assert not events.route(owner, local, observer)
        control(owner, "release before")
        events.settle()
        assert l3mh._mac_static_pinned(owner, remote[1], VID)
        assert events.route(owner, local, observer)