#!/usr/bin/env python
# SPDX-License-Identifier: ISC

# Copyright (c) 2026 Cisco Systems, Inc.

import re
from pathlib import Path

import pytest

import test_evpn_l3mh as l3mh

pytestmark = l3mh.pytestmark

ES_PEERS = ("leaf1", "leaf2", "leaf4")


def setup_module(module):
    l3mh.setup_module(module, extra_es_peer=True)


def teardown_module(module):
    l3mh.teardown_module(module)


def test_three_es_peers_sync_neighbors():
    """Every ES leaf receives a peer binding and a static MAC pin."""
    tgen = l3mh.get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    assert "leaf4" in tgen.gears, "host1's third ES peer is missing"
    peers = [tgen.gears[name] for name in ES_PEERS]
    non_peer = tgen.gears["leaf3"]
    leaves = [*peers, non_peer]
    l3mh._l3mh_knob(non_peer, 65013, True)
    l3mh._settle(leaves)

    for leaf in peers:
        result = l3mh.check_local_es_zebra(leaf, l3mh.ES1_ID)
        assert result is None, result

    # Drive one local learn on each of two peers. Distinct bindings allow
    # all three leaves to exercise receive-side sync in one event round.
    bindings = (
        ("leaf1", 65011, "45.0.0.201", "02:00:00:00:00:c9"),
        ("leaf4", 65014, "45.0.0.202", "02:00:00:00:00:ca"),
    )
    vid = l3mh.HOST_VID
    for owner, _, ip, mac in bindings:
        leaf = tgen.gears[owner]
        leaf.cmd_raises(
            f"bridge fdb replace {mac} dev hostbond1 master vlan {vid} dynamic"
        )
        leaf.cmd_raises(
            f"ip neigh replace {ip} lladdr {mac} dev vlan{vid} nud reachable"
        )

    l3mh._settle(leaves)

    for owner, asn, ip, mac in bindings:
        path = l3mh._pure_l3_rt2_path(non_peer, asn, ip=ip, mac=mac)
        assert path and path.get("esi") == l3mh.ES1_ID, (non_peer.name, ip, path)
        assert not non_peer.cmd_raises(f"ip neigh show to {ip}").strip(), ip
        for leaf in peers:
            if leaf.name == owner:
                continue
            assert l3mh._neigh_synced(leaf, ip), (leaf.name, ip)
            assert l3mh._mac_static_pinned(leaf, mac, vid), (leaf.name, mac)


def _es_rd(leaf):
    es = leaf.vtysh_cmd(f"show bgp l2vpn evpn es {l3mh.ES1_ID} json", isjson=True)
    return es["rd"]


def _per_es_route_targets(routes, rd):
    prefix = f"[4294967295]:[{l3mh.ES1_ID}]"
    return {
        frozenset(
            token
            for token in path.get("extendedCommunity", {}).get("string", "").split()
            if token.startswith("RT:")
        )
        for key, route in routes.get(rd, {}).items()
        if prefix in key
        for paths in route["paths"]
        for path in (paths if isinstance(paths, list) else [paths])
        if path.get("valid")
    }


def test_pure_l3_per_es_rt1_follows_port():
    tgen = l3mh.get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    origin, peer = (tgen.gears[name] for name in ("leaf1", "leaf2"))
    spines = [tgen.gears[name] for name in ("spine1", "spine2")]
    leaves = [tgen.gears[name] for name in (*ES_PEERS, "leaf3")]
    port = "hostbond1"

    def configure(leaf, command):
        leaf.vtysh_cmd(f"configure terminal\ninterface {port}\n {command}", raises=True)

    l3mh._settle(leaves)
    origin_rd, peer_rd = _es_rd(origin), _es_rd(peer)

    def check(origin_up, peer_up, phase):
        l3mh._barrier_round((origin, peer))
        expected_origin = (
            {frozenset((f"RT:65011:{l3mh.L3VNI}",))} if origin_up else set()
        )
        expected_peer = {frozenset((f"RT:65012:{l3mh.L3VNI}",))} if peer_up else set()
        for spine in spines:
            routes = spine.vtysh_cmd(
                "show bgp l2vpn evpn route type 1 json", isjson=True
            )
            actual_origin = _per_es_route_targets(routes, origin_rd)
            actual_peer = _per_es_route_targets(routes, peer_rd)
            assert actual_origin == expected_origin, (phase, spine.name, actual_origin)
            assert actual_peer == expected_peer, (phase, spine.name, actual_peer)

    check(False, False, "protection disabled")
    try:
        for leaf in (origin, peer):
            configure(leaf, "evpn mh bridge-port-protection")
        check(True, True, "protection enabled")

        origin.cmd_raises(f"ip link set dev {port} down")
        check(False, True, "port down")
        origin.cmd_raises(f"ip link set dev {port} up")
        check(True, True, "port restored")

        configure(origin, "evpn mh bypass")
        check(False, True, "bypass enabled")
    finally:
        origin.cmd_raises(f"ip link set dev {port} up")
        configure(origin, "no evpn mh bypass")
        for leaf in (origin, peer):
            configure(leaf, "no evpn mh bridge-port-protection")


def test_protected_port_recovery():
    tgen = l3mh.get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    local, peer = (tgen.gears[name] for name in ("leaf1", "leaf2"))
    leaves = (local, peer)
    vid = l3mh.HOST_VID
    svi = f"vlan{vid}"
    port = "hostbond1"
    success, fallback, lost, lost_failure, retained, fresh = (
        (f"45.0.0.{240 + i}", f"02:00:00:00:00:{0xe0 + i:02x}") for i in range(6)
    )
    synced = (success, fallback, lost, lost_failure)
    bindings = (*synced, retained, fresh)

    def neigh(leaf, binding, state):
        ip, mac = binding
        leaf.cmd_raises(f"ip neigh replace {ip} lladdr {mac} dev {svi} nud {state}")

    def learn(leaf, binding):
        leaf.cmd_raises(
            f"bridge fdb replace {binding[1]} dev {port} master vlan {vid} dynamic"
        )
        neigh(leaf, binding, "reachable")

    def check_nud(binding, expected):
        entry = local.cmd_raises(f"ip neigh show to {binding[0]} dev {svi}")
        assert expected in entry.split(), (binding, entry)

    def route(leaf, asn, binding):
        return l3mh._pure_l3_rt2_path(leaf, asn, ip=binding[0], mac=binding[1])

    def configure(command):
        local.vtysh_cmd(f"configure terminal\n{command}", raises=True)

    def set_port(state):
        local.cmd_raises(f"ip link set dev {port} {state}")

    l3mh._settle(leaves)
    retrans = f"net.ipv4.neigh.{svi}.retrans_time_ms"
    original_retrans = local.cmd_raises(f"sysctl -n {retrans}").strip()
    try:
        configure(f"interface {port}\n evpn mh bridge-port-protection")
        configure("evpn mh l3-neigh-down-peering-time 60")
        local.cmd_raises(f"sysctl -w {retrans}=60000")
        for binding in synced:
            learn(peer, binding)
        learn(local, retained)
        l3mh._settle(leaves)
        for binding in synced:
            check_nud(binding, "PERMANENT")
        assert route(peer, 65011, retained)

        set_port("down")
        l3mh._settle(leaves)
        check_nud(retained, "PERMANENT")
        assert route(peer, 65011, retained)

        set_port("up")
        l3mh._settle(leaves)
        for binding in (*synced, retained):
            check_nud(binding, "PROBE")
        for binding in synced:
            assert route(local, 65012, binding)
            assert not route(peer, 65011, binding)
        assert route(peer, 65011, retained)

        set_port("down")
        l3mh._settle(leaves)
        for binding in (*synced, retained):
            check_nud(binding, "PERMANENT")
        set_port("up")
        l3mh._settle(leaves)
        for binding in (*synced, retained):
            check_nud(binding, "PROBE")

        learn(local, success)
        neigh(local, fallback, "failed")
        for binding in (lost, lost_failure):
            neigh(peer, binding, "failed")
        learn(peer, fresh)
        l3mh._settle(leaves)
        assert route(peer, 65011, success)
        check_nud(fallback, "PERMANENT")
        for binding in (lost, lost_failure):
            check_nud(binding, "PROBE")
            assert not route(local, 65012, binding)
        check_nud(fresh, "PERMANENT")
        assert not route(peer, 65011, fallback)
        assert not route(peer, 65011, fresh)

        neigh(peer, fresh, "failed")
        neigh(local, lost_failure, "failed")
        l3mh._settle(leaves)
        check_nud(fresh, "PROBE")
        check_nud(lost_failure, "FAILED")
        assert not route(peer, 65011, lost_failure)
        for binding in (lost, fresh):
            learn(local, binding)
        l3mh._settle(leaves)
        for binding in (lost, fresh):
            assert route(peer, 65011, binding)
    finally:
        set_port("up")
        configure(f"interface {port}\n no evpn mh bridge-port-protection")
        configure("no evpn mh l3-neigh-down-peering-time")
        local.cmd_raises(f"sysctl -w {retrans}={original_retrans}")
        for leaf in leaves:
            for ip, mac in bindings:
                leaf.run(f"ip neigh del {ip} dev {svi} 2>/dev/null")
                leaf.run(
                    f"bridge fdb del {mac} dev {port} master vlan {vid} 2>/dev/null"
                )


def test_rt2_origin_survives_spine_path_loss_and_changes_on_withdrawal():
    tgen = l3mh.get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    first, receiver, second = (tgen.gears[name] for name in ES_PEERS)
    leaves = (first, receiver, second)
    ip, mac = "45.0.0.205", "02:00:00:00:00:cd"
    vid = l3mh.HOST_VID
    spine1, spine2 = "192.168.2.1", "192.168.5.1"
    rmap = "RT2-ONE-SPINE"
    neighbor = f"show evpn arp-cache vni {l3mh.L3VNI} ip {ip} json"

    def learn(leaf):
        leaf.cmd_raises(
            f"ip neigh replace {ip} lladdr {mac} dev vlan{vid} nud reachable"
        )
        l3mh._relearn_local_fdb(leaf, mac, leaves=leaves)

    def check_origin(leaf):
        entry = receiver.vtysh_cmd(neighbor, isjson=True)
        assert entry.get("peerOrigin") == l3mh.LEAF_LO[leaf.name], entry
        assert l3mh._neigh_synced(receiver, ip)
        assert l3mh._mac_static_pinned(receiver, mac, vid)

    def source_sessions(leaf):
        routes = receiver.vtysh_cmd(
            "show bgp l2vpn evpn route detail type macip json", isjson=True
        )
        rd = f"{l3mh.LEAF_LO[leaf.name]}:"
        return {
            path["peer"]["peerId"]
            for key, table in routes.items()
            if key.startswith(rd)
            for entry in table.values()
            if isinstance(entry, dict) and entry.get("ip") == ip
            for paths in entry["paths"]
            for path in paths
            if path.get("valid")
        }

    def configure(commands):
        receiver.vtysh_cmd(f"configure terminal\n{commands}", raises=True)

    l3mh._settle(leaves)
    learn(first)
    try:
        l3mh._settle(leaves)
        check_origin(first)
        assert {spine1, spine2} <= source_sessions(first)

        learn(second)
        l3mh._settle(leaves)
        check_origin(second)
        assert {spine1, spine2} <= source_sessions(second)

        configure(
            f"route-map {rmap} deny 10\n match evpn route-type macip\n exit\n"
            f"route-map {rmap} permit 20\n exit\n"
            f"router bgp 65012\n address-family l2vpn evpn\n"
            f"  neighbor {spine2} route-map {rmap} in"
        )
        receiver.vtysh_cmd(f"clear bgp l2vpn evpn {spine2} soft in", raises=True)
        l3mh._settle(leaves)
        assert source_sessions(second) == {spine1}
        check_origin(second)

        second.cmd_raises(f"ip neigh del {ip} dev vlan{vid}")
        l3mh._settle(leaves)
        check_origin(first)

        l3mh._l3mh_knob(receiver, 65012, False)
        l3mh._l3mh_knob(receiver, 65012, True)
        l3mh._settle(leaves)
        check_origin(first)
    finally:
        configure(
            f"router bgp 65012\n address-family l2vpn evpn\n"
            f"  no neighbor {spine2} route-map {rmap} in\n exit-address-family\n exit\n"
            f"no route-map {rmap}"
        )
        for leaf in (first, second):
            leaf.run(f"ip neigh del {ip} dev vlan{vid} 2>/dev/null")
            leaf.run(
                f"bridge fdb del {mac} dev hostbond1 master vlan {vid} 2>/dev/null"
            )


def test_rt1_last_path_marks_only_its_origin():
    tgen = l3mh.get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    first, receiver, second = (tgen.gears[name] for name in ES_PEERS)
    leaves = (first, receiver, second)
    vid, vni = l3mh.HOST_VID, l3mh.L3VNI
    bindings = (
        (first, "45.0.0.206", "02:00:00:00:00:ce"),
        (second, "45.0.0.207", "02:00:00:00:00:cf"),
        (first, "45.0.0.220", "02:00:00:00:00:d6"),
    )
    spine = "192.168.4.1"
    bgp = "router bgp 65011\n address-family l2vpn evpn"
    protection = "evpn mh bridge-port-protection"
    svi = f"vlan{vid}"
    timer = f"net.ipv4.neigh.{svi}.retrans_time_ms"
    original_timer = receiver.cmd_raises(f"sysctl -n {timer}").strip()
    log = Path(receiver.logdir) / receiver.name / "zebra.log"

    def configure(leaf, command):
        leaf.vtysh_cmd(f"configure terminal\n{command}", raises=True)

    def rt1_paths(rd):
        routes = receiver.vtysh_cmd(
            "show bgp l2vpn evpn route type 1 json", isjson=True
        )
        key = f"[4294967295]:[{l3mh.ES1_ID}]"
        return sum(
            bool(path.get("valid"))
            for prefix, route in routes.get(rd, {}).items()
            if key in prefix
            for paths in route["paths"]
            for path in (paths if isinstance(paths, list) else [paths])
        )

    def check(first_paths, first_rt1_lost=False):
        l3mh._settle(leaves)
        assert rt1_paths(first_rd) == first_paths
        assert rt1_paths(second_rd) == 2
        entries = []
        for leaf, ip, mac in bindings:
            asn = 65010 + int(leaf.name[-1])
            assert l3mh._pure_l3_rt2_path(receiver, asn, ip=ip, mac=mac)
            entry = receiver.vtysh_cmd(
                f"show evpn arp-cache vni {vni} ip {ip} json", isjson=True
            )
            assert entry.get("peerOrigin") == l3mh.LEAF_LO[leaf.name], entry
            probing = leaf is first and first_rt1_lost
            if probing:
                neigh = receiver.cmd_raises(f"ip neigh show to {ip} dev {svi}")
                assert {mac, "PROBE"} <= set(neigh.split()), neigh
                assert "extern_learn" not in neigh
            else:
                assert l3mh._neigh_synced(receiver, ip)
            assert l3mh._mac_static_pinned(receiver, mac, vid) == (not probing)
            entries.append(entry.get("peerRt1Lost", False))
        return entries

    def backing_messages():
        with log.open(encoding="utf-8") as stream:
            stream.seek(offset)
            return re.findall(
                rf"zebra message\[(ZEBRA_EVPN_BPP_PEER_DEL):{l3mh.VRF}:(\d+)\]",
                stream.read(),
            )

    l3mh._settle(leaves)
    first_rd, second_rd = _es_rd(first), _es_rd(second)
    configure(receiver, "debug zebra packet recv")
    try:
        receiver.cmd_raises(f"sysctl -qw {timer}=60000")
        for leaf in (first, second):
            configure(leaf, f"interface hostbond1\n {protection}")
        for leaf, ip, mac in bindings:
            leaf.cmd_raises(
                f"bridge fdb replace {mac} dev hostbond1 master vlan {vid} dynamic"
            )
            leaf.cmd_raises(
                f"ip neigh replace {ip} lladdr {mac} dev vlan{vid} nud reachable"
            )
        assert check(2) == [False, False, False]
        offset = log.stat().st_size

        configure(
            first,
            "route-map RT1-ONE-SPINE deny 10\n match evpn route-type ead\n exit\n"
            "route-map RT1-ONE-SPINE permit 20\n exit\n"
            f"{bgp}\n  neighbor {spine} route-map RT1-ONE-SPINE out",
        )
        first.vtysh_cmd(f"clear bgp l2vpn evpn {spine} soft out", raises=True)
        assert check(1) == [False, False, False]
        assert backing_messages() == []

        configure(first, f"interface hostbond1\n no {protection}")
        assert check(0, first_rt1_lost=True) == [True, False, True]
        withdrawn = backing_messages()
        assert len(withdrawn) == 1, withdrawn

        configure(first, f"interface hostbond1\n {protection}")
        assert check(1, first_rt1_lost=True) == [True, False, True]
        assert backing_messages() == withdrawn
        assert withdrawn == [("ZEBRA_EVPN_BPP_PEER_DEL", "30")]

        _, ip, mac = bindings[0]
        _, failed_ip, failed_mac = bindings[2]

        def assert_kernel(ip, mac, state):
            l3mh._settle(leaves)
            neigh = receiver.cmd_raises(f"ip neigh show to {ip} dev {svi}")
            assert state in neigh.split(), neigh
            if state != "FAILED":
                assert mac in neigh.split(), neigh
            pinned = state == "PERMANENT"
            assert ("extern_learn" in neigh) == pinned, neigh
            assert l3mh._mac_static_pinned(receiver, mac, vid) == pinned
            assert l3mh._pure_l3_rt2_path(receiver, 65011, ip=ip, mac=mac)

        with l3mh._raw_evpn_peer(receiver, tgen.gears["leaf3"], mac, ip) as send:
            send(f"announce 0 {vni}")
            assert_kernel(ip, mac, "PERMANENT")

            # The original RT-2 is still advertised, even with RT-1 restored.
            send("withdraw")
            assert_kernel(ip, mac, "PROBE")

            receiver.cmd_raises(
                f"ip neigh replace {failed_ip} lladdr {failed_mac} dev {svi} nud failed"
            )
            assert_kernel(failed_ip, failed_mac, "FAILED")

            send(f"announce 0 {vni} ip={failed_ip} mac={failed_mac}")
            assert_kernel(failed_ip, failed_mac, "PERMANENT")
            receiver.cmd_raises(f"ip neigh del {failed_ip} dev {svi}")
            assert_kernel(failed_ip, failed_mac, "PERMANENT")
    finally:
        receiver.cmd_raises(f"sysctl -qw {timer}={original_timer}")
        configure(receiver, "no debug zebra packet recv")
        configure(
            first,
            f"{bgp}\n  no neighbor {spine} route-map RT1-ONE-SPINE out\n"
            " exit-address-family\n exit\nno route-map RT1-ONE-SPINE",
        )
        for leaf in (first, second):
            configure(leaf, f"interface hostbond1\n no {protection}")
        for leaf, ip, mac in bindings:
            leaf.run(f"ip neigh del {ip} dev vlan{vid} 2>/dev/null")
            leaf.run(
                f"bridge fdb del {mac} dev hostbond1 master vlan {vid} 2>/dev/null"
            )


def test_rt1_loss_excludes_rt2_before_import():
    tgen = l3mh.get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    owner, receiver, speaker = (
        tgen.gears[name] for name in ("leaf1", "leaf2", "leaf3")
    )
    leaves = (owner, receiver)
    ip, mac = "45.0.0.221", "02:00:00:00:00:d7"
    vni = l3mh.L3VNI
    origin = l3mh.LEAF_LO[owner.name]
    config = "configure terminal\ninterface hostbond1\n"
    protection = "evpn mh bridge-port-protection"

    try:
        owner.vtysh_cmd(config + protection, raises=True)
        l3mh._settle(leaves)
        with l3mh._raw_evpn_peer(receiver, speaker, mac, ip) as send:
            # Keep a pure-L3 path in the global RIB without a matching import RT.
            send(f"announce-nort 0 {vni} origin={origin}")
            l3mh._settle(leaves)
            assert ip in receiver.vtysh_cmd("show bgp l2vpn evpn route type macip")
            assert not l3mh._neigh_synced(receiver, ip)

            owner.vtysh_cmd(config + "no " + protection, raises=True)
            l3mh._settle(leaves)
            send(f"announce 0 {vni} origin={origin}")
            l3mh._settle(leaves)
            assert l3mh._pure_l3_rt2_path(receiver, 65099, ip=ip, mac=mac)
            assert not l3mh._neigh_synced(receiver, ip)

            send("withdraw")
            l3mh._settle(leaves)
            send(f"announce 0 {vni} origin={origin}")
            l3mh._settle(leaves)
            assert l3mh._neigh_synced(receiver, ip)
    finally:
        owner.vtysh_cmd(config + "no " + protection, raises=True)
        receiver.run(f"ip neigh del {ip} dev vlan{l3mh.HOST_VID} 2>/dev/null")


def test_nud_transitions_do_not_learn_or_delete_l3mh_binding():
    tgen = l3mh.get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    owner, receiver = (tgen.gears[name] for name in ("leaf1", "leaf2"))
    leaves = (owner, receiver)
    ip, mac = "45.0.0.208", "02:00:00:00:00:d0"
    vid = l3mh.HOST_VID
    timer = f"net.ipv4.neigh.vlan{vid}.retrans_time_ms"
    original = owner.cmd_raises(f"sysctl -n {timer}").strip()

    def update(state, lladdr=""):
        owner.cmd_raises(f"ip neigh replace {ip} dev vlan{vid} {lladdr} nud {state}")

    def advertised():
        l3mh._settle(leaves)
        return l3mh._pure_l3_rt2_path(receiver, 65011, ip=ip, mac=mac) is not None

    l3mh._settle(leaves)
    try:
        # Drive failure explicitly so kernel retries cannot race the assertions.
        owner.cmd_raises(f"sysctl -qw {timer}=60000")
        owner.cmd_raises(
            f"bridge fdb replace {mac} dev hostbond1 master vlan {vid} dynamic"
        )
        update("probe", f"lladdr {mac}")
        assert not advertised(), "NUD_PROBE originated an RT-2"
        l3mh._l3mh_knob(owner, 65011, False)
        l3mh._l3mh_knob(owner, 65011, True)
        assert not advertised(), "Replay treated NUD_PROBE as a learn"

        update("reachable", f"lladdr {mac}")
        assert advertised(), "NUD_REACHABLE did not originate the binding"

        update("incomplete")
        assert advertised(), "NUD_INCOMPLETE withdrew the existing RT-2"

        update("failed")
        assert not advertised(), "NUD_FAILED left the local RT-2 advertised"
    finally:
        owner.run(f"ip neigh del {ip} dev vlan{vid} 2>/dev/null")
        owner.run(f"bridge fdb del {mac} dev hostbond1 master vlan {vid} 2>/dev/null")
        owner.cmd_raises(f"sysctl -qw {timer}={original}")


def test_arp_failure_and_gc_require_a_usable_peer_fallback():
    tgen = l3mh.get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    owner, receiver = (tgen.gears[name] for name in ("leaf1", "leaf2"))
    leaves = (owner, receiver)
    fail, idle = "45.0.0.216", "45.0.0.217"
    ips = (fail, idle)
    mac, vid = "02:00:00:00:00:d3", l3mh.HOST_VID
    svi = f"vlan{vid}"
    fdb = f"{mac} dev hostbond1 master vlan {vid}"
    protection = "evpn mh bridge-port-protection"

    def protect(enable):
        command = protection if enable else f"no {protection}"
        owner.vtysh_cmd(
            f"configure terminal\ninterface hostbond1\n {command}", raises=True
        )

    def learn(leaf):
        for ip in ips:
            leaf.cmd_raises(
                f"ip neigh replace {ip} lladdr {mac} dev {svi} nud reachable"
            )

    def age():
        receiver.cmd_raises(
            f"ip neigh replace {fail} lladdr {mac} dev {svi} nud failed"
        )
        receiver.cmd_raises(f"ip neigh del {idle} dev {svi}")
        l3mh._settle(leaves)
        assert all(not l3mh._pure_l3_rt2_path(receiver, 65012, ip=ip) for ip in ips)

    def check_peer_static():
        for ip in ips:
            entry = receiver.cmd_raises(f"ip neigh show to {ip} dev {svi}")
            assert {"PERMANENT", "extern_learn"} <= set(entry.split()), entry
        assert l3mh._mac_static_pinned(receiver, mac, vid)

    try:
        protect(True)
        owner.cmd_raises(f"bridge fdb replace {fdb} dynamic")
        learn(owner)
        l3mh._settle(leaves)
        check_peer_static()

        learn(receiver)
        l3mh._relearn_local_fdb(receiver, mac, leaves=leaves)
        l3mh._settle(leaves)
        assert all(l3mh._pure_l3_rt2_path(receiver, 65012, ip=ip) for ip in ips)
        age()
        check_peer_static()

        learn(receiver)
        l3mh._relearn_local_fdb(receiver, mac, leaves=leaves)
        protect(False)
        l3mh._settle(leaves)
        for ip in ips:
            assert l3mh._pure_l3_rt2_path(receiver, 65011, ip=ip)
            entry = receiver.vtysh_cmd(
                f"show evpn arp-cache vni {l3mh.L3VNI} ip {ip} json", isjson=True
            )
            assert entry.get("peerRt1Lost"), entry

        age()
        failed = receiver.cmd_raises(f"ip neigh show to {fail} dev {svi}")
        assert "FAILED" in failed and "extern_learn" not in failed, failed
        assert not receiver.cmd_raises(f"ip neigh show to {idle} dev {svi}").strip()
        assert not l3mh._mac_static_pinned(receiver, mac, vid)
    finally:
        protect(False)
        for leaf in leaves:
            for ip in ips:
                leaf.run(f"ip neigh del {ip} dev {svi} 2>/dev/null")
            leaf.run(f"bridge fdb del {fdb} 2>/dev/null")


def test_last_static_neighbor_releases_its_vlan_mac_pin():
    tgen = l3mh.get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    owner, receiver = (tgen.gears[name] for name in ("leaf1", "leaf2"))
    leaves = (owner, receiver)
    mac = "02:00:00:00:00:d1"
    vid, other_vid = l3mh.HOST_VID, l3mh.HOST_VID2
    bindings = (("45.0.0.209", vid), ("45.0.0.210", vid), ("45.0.1.209", other_vid))

    def learn(leaf, ip, vlan):
        leaf.cmd_raises(
            f"ip neigh replace {ip} lladdr {mac} dev vlan{vlan} nud reachable"
        )

    def pin_present(vlan):
        return l3mh._mac_static_pinned(receiver, mac, vlan)

    l3mh._settle(leaves)
    try:
        for vlan in (vid, other_vid):
            owner.cmd_raises(
                f"bridge fdb replace {mac} dev hostbond1 master vlan {vlan} dynamic"
            )
        for ip, vlan in bindings:
            learn(owner, ip, vlan)
        l3mh._settle(leaves)
        assert pin_present(vid) and pin_present(other_vid)

        learn(receiver, bindings[0][0], vid)
        l3mh._settle(leaves)
        assert pin_present(vid), "Release of one static ARP removed a shared MAC pin"

        learn(receiver, bindings[1][0], vid)
        l3mh._settle(leaves)
        entries = receiver.cmd_raises("bridge fdb show dev hostbond1")
        assert not any(
            line.startswith(f"{mac} ") and f" vlan {vid} " in f"{line} "
            for line in entries.splitlines()
        ), entries
        assert pin_present(other_vid), "Release removed the same MAC on another VLAN"
        for ip, _ in bindings[:2]:
            entry = receiver.cmd_raises(f"ip neigh show to {ip} dev vlan{vid}")
            assert mac in entry and "extern_learn" not in entry, entry
    finally:
        for leaf in leaves:
            for ip, vlan in bindings:
                leaf.run(f"ip neigh del {ip} dev vlan{vlan} 2>/dev/null")
            for vlan in (vid, other_vid):
                leaf.run(
                    f"bridge fdb del {mac} dev hostbond1 master vlan {vlan} 2>/dev/null"
                )
