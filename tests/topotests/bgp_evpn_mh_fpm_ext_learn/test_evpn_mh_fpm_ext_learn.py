#!/usr/bin/env python
# SPDX-License-Identifier: ISC
"""EVPN MAC synchronization through the SONiC dataplane module."""

import json
import os
import shlex
import socket
import struct
import sys
from contextlib import contextmanager
from pathlib import Path

import pytest

CWD = Path(__file__).resolve().parent
sys.path.append(str(CWD.parent))

from fpm_peer import (
    NDA_DST,
    NDA_LLADDR,
    NDA_NH_ID,
    NDA_SRC_VNI,
    NDA_VLAN,
    NUD_NOARP,
    RTM_DELNEIGH,
    RTM_NEWNEIGH,
    FpmPeer,
    probe_peer_sync,
)
from lib import topotest
from lib.topogen import Topogen

pytestmark = [pytest.mark.bgpd, pytest.mark.evpn, pytest.mark.fpm]

VNI = 1000
VTEPS = {"r1": "192.0.2.1", "r2": "192.0.2.2", "r3": "192.0.2.3"}
ESI = "03:44:38:39:ff:ff:01:00:00:01"


def _expect(check, expected, description):
    reached, result = topotest.run_and_expect(check, expected, count=30, wait=0.5)
    assert reached, f"{description}. Expected {expected!r}, got {result!r}"


def _show(router, daemon, command):
    return json.loads(router.vtysh_cmd(f"{command} json", daemon=daemon, raises=True))


def _configure(router, *commands, daemon=None):
    args = ["vtysh"]
    if daemon:
        args.extend(("-d", daemon))
    for command in ("configure terminal", *commands):
        args.extend(("-c", command))
    router.cmd_raises(shlex.join(args))


def _ifindex(router, dev):
    return json.loads(router.cmd_raises(f"ip -j link show dev {dev}"))[0]["ifindex"]


def _zebra_mac(router, mac):
    return _show(router, "zebra", f"show evpn mac vni {VNI} mac {mac}").get(mac, {})


def _bgp_mac(router, mac):
    routes = _show(router, "bgpd", "show bgp l2vpn evpn route type macip")
    return mac in json.dumps(routes)


def _bgp_neighbor_mac(router, neighbor, mac, direction):
    routes = _show(
        router, "bgpd", f"show bgp l2vpn evpn neighbors {neighbor} {direction}"
    )
    return mac in json.dumps(routes)


def _block_remote_mac_import(router, neighbor):
    _configure(
        router,
        "route-map NO-REMOTE-MACS deny 10",
        "match evpn route-type macip",
        "exit",
        "route-map NO-REMOTE-MACS permit 20",
        "exit",
        "router bgp 65000",
        "address-family l2vpn evpn",
        f"neighbor {neighbor} route-map NO-REMOTE-MACS in",
        daemon="bgpd",
    )


@contextmanager
def _hold_kernel_writes(router):
    command = "zebra test dplane disable install"
    output = router.vtysh_cmd(command, daemon="zebra")
    if "% Unknown command" in output:
        pytest.skip("holding dataplane writes requires an FRR development build")
    assert not output.strip(), output
    try:
        yield
    finally:
        router.vtysh_cmd(f"no {command}", daemon="zebra", raises=True)


def _kernel_macs(router, mac, dev):
    entries = json.loads(router.cmd_raises(f"bridge -j fdb show dev {dev}"))
    return [entry for entry in entries if entry["mac"] == mac]


def _kernel_mac(router, mac, dev):
    return next(iter(_kernel_macs(router, mac, dev)), {})


def _bgp_state(router, neighbor):
    return _show(router, "bgpd", f"show bgp neighbors {neighbor}")[neighbor]["bgpState"]


def _create_vxlan(router):
    for command in (
        f"ip link add vxlan0 type vxlan id {VNI} local {VTEPS[router.name]} "
        "dstport 4789 nolearning",
        "ip link set vxlan0 master br0 up",
        f"bridge vlan add vid {VNI} dev vxlan0 pvid untagged",
    ):
        router.cmd_raises(command)


def _delete_kernel_mac(router, mac, port):
    router.cmd_raises(f"bridge fdb del {mac} dev {port} master vlan {VNI}")


def _send(peer, router, action, mac, port="access0", sticky=False):
    peer.send(action, _ifindex(router, port), mac, VNI, sticky=sticky)


def _assert_local(r1, r2, mac, port="access0", sticky=False):
    def learned():
        entry = _zebra_mac(r1, mac)
        remote = _zebra_mac(r2, mac)
        fdb = _kernel_mac(r1, mac, port)
        return (
            entry.get("type") == "local"
            and entry.get("intf") == port
            and not entry.get("localInactive")
            and entry.get("stickyMac", False) == sticky
            and remote.get("type") == "remote"
            and remote.get("stickyMac", False) == sticky
            and _bgp_mac(r1, mac)
            and _bgp_mac(r2, mac)
            and "extern_learn" in fdb.get("flags", [])
        )

    _expect(learned, True, f"{mac} active on {port} and advertised to the peer")


def _assert_withdrawn(r1, mac, port, r2=None):
    _expect(
        lambda: (
            not _zebra_mac(r1, mac)
            and not _kernel_mac(r1, mac, port)
            and not _bgp_mac(r1, mac)
            and (r2 is None or not _bgp_mac(r2, mac))
        ),
        True,
        f"{mac} removed from kernel, Zebra and BGP",
    )


@contextmanager
def _topology(request, tmp_path, module, *, third_peer=False, external_learn=True):
    names = ("r1", "r2", "r3") if third_peer else ("r1", "r2")
    tgen = Topogen({"s1": tuple(f"{name}:uplink" for name in names)}, request.node.name)
    options = f"--asic-offload=notify_on_offload -M {shlex.quote(str(module))}"
    if external_learn:
        options += " --kernel-mac-ext-learn"
    peers = {}
    try:
        tgen.start_topology()
        r1, r2 = (tgen.gears[name] for name in names[:2])
        for name in names:
            router = tgen.gears[name]
            neighbor_names = names[1:] if router is r1 else ("r1",)
            neighbors = tuple(VTEPS[peer] for peer in neighbor_names)
            for command in (
                "ip link set uplink up",
                "ip link add br0 type bridge vlan_filtering 1 vlan_default_pvid 0",
                "ip link set br0 up",
            ):
                router.cmd_raises(command)
            for port in ("access0", "access1"):
                router.cmd_raises(f"ip link add {port} type dummy")
                router.cmd_raises(f"ip link set {port} master br0 up")
                router.cmd_raises(f"bridge vlan add vid {VNI} dev {port} pvid untagged")
            router.cmd_raises(f"bridge vlan add vid {VNI} dev br0 self")
            _create_vxlan(router)

            peers[name] = FpmPeer(router)
            config = tmp_path / f"{name}.conf"
            config.write_text(
                "evpn mh mac-holdtime 0\n"
                "interface uplink\n"
                f" ip address {VTEPS[name]}/{29 if third_peer else 30}\n"
                "exit\n"
                f"router bgp 65000\n"
                f" bgp router-id {VTEPS[name]}\n"
                + "".join(
                    f" neighbor {address} remote-as 65000\n" for address in neighbors
                )
                + " address-family l2vpn evpn\n"
                + "".join(f"  neighbor {address} activate\n" for address in neighbors)
                + "  advertise-all-vni\n exit-address-family\n"
            )
            router.load_frr_config(str(config), daemons=[("zebra", options), "bgpd"])

        tgen.start_router()
        assert not tgen.routers_have_failure(), tgen.errors
        for name, peer in peers.items():
            _configure(
                tgen.gears[name],
                f"fpm address 127.0.0.1 port {peer.port}",
                daemon="zebra",
            )
            peer.accept()
        _expect(lambda: _bgp_state(r1, VTEPS["r2"]), "Established", "EVPN BGP session")
        _expect(
            lambda: VTEPS["r2"]
            in json.dumps(_show(r1, "zebra", f"show evpn vni {VNI}")),
            True,
            "remote VTEP discovered",
        )
        yield r1, r2, peers
    finally:
        for peer in peers.values():
            peer.close()
        tgen.stop_topology()


@pytest.fixture
def sonic_module():
    module = os.environ.get("FRR_TEST_FPM_SONIC_MODULE")
    if not module:
        pytest.skip("set FRR_TEST_FPM_SONIC_MODULE to a compatible dplane_fpm_sonic.so")
    module = Path(module).resolve()
    assert module.is_file(), f"FPM module not found: {module}"
    return module


@pytest.fixture
def topology(request, tmp_path, sonic_module):
    with _topology(request, tmp_path, sonic_module) as (r1, r2, peers):
        yield r1, r2, peers["r1"], peers["r2"]


def test_fpm_mac_learn_requires_external_mode(request, tmp_path, sonic_module):
    with _topology(request, tmp_path, sonic_module, external_learn=False) as (
        r1,
        r2,
        peers,
    ):
        peer = peers["r1"]
        mac = "02:00:00:40:00:02"
        closes = _show(r1, "zebra", "show fpm counters")["connection-closes"]

        _send(peer, r1, RTM_NEWNEIGH, mac)
        peer.connection.shutdown(socket.SHUT_WR)
        _expect(
            lambda: _show(r1, "zebra", "show fpm counters")["connection-closes"]
            > closes,
            True,
            "FPM processed the input stream through EOF",
        )
        peer.disconnect()
        peer.accept()

        assert not _zebra_mac(r1, mac)
        assert not _kernel_mac(r1, mac, "access0")
        assert not _bgp_mac(r1, mac)
        assert not _bgp_mac(r2, mac)


def test_kernel_can_restore_flood_entry(topology):
    r1, *_ = topology

    def flood_entry():
        fdb = json.loads(r1.cmd_raises("bridge -j fdb show dev vxlan0"))
        return any(
            row["mac"] == "00:00:00:00:00:00" and row.get("dst") == VTEPS["r2"]
            for row in fdb
        )

    _expect(flood_entry, True, "remote IMET route programmed a VXLAN flood entry")
    r1.cmd_raises(f"bridge fdb del 00:00:00:00:00:00 dev vxlan0 self dst {VTEPS['r2']}")
    _expect(flood_entry, True, "kernel flood-list delete caused Zebra to restore it")


def test_local_learn_move_and_age_over_fpm(topology):
    r1, r2, peer, other_peer = topology
    mac = "02:00:00:00:01:01"
    marker = "02:00:00:00:01:09"

    _send(peer, r1, RTM_NEWNEIGH, mac)
    _assert_local(r1, r2, mac)

    _send(peer, r1, RTM_NEWNEIGH, mac)
    _send(peer, r1, RTM_NEWNEIGH, mac, "access1")
    _assert_local(r1, r2, mac, "access1")
    assert not _kernel_mac(r1, mac, "access0")

    # A direct kernel delete is visible in the FDB, but the ASIC still owns
    # the route. The later FPM delete must also work with the FDB already gone.
    _delete_kernel_mac(r1, mac, "access1")
    r1.cmd_raises("ip link set access1 mtu 1400")
    _expect(
        lambda: _show(r1, "zebra", "show interface access1")["access1"]["mtu"],
        1400,
        "link notification following the kernel delete",
    )
    assert _zebra_mac(r1, mac)["intf"] == "access1"
    assert _bgp_mac(r2, mac)
    assert not _kernel_mac(r1, mac, "access1")
    _send(peer, r1, RTM_DELNEIGH, mac, "access1")
    _assert_withdrawn(r1, mac, "access1", r2)

    # A remote MAC is sent after the local FPM operations were processed.
    # Check that no notification for our local MAC preceded it on the wire.
    _send(other_peer, r2, RTM_NEWNEIGH, marker)
    peer.receive(marker, RTM_NEWNEIGH)
    assert all(
        message.attributes.get(NDA_LLADDR) != bytes.fromhex(mac.replace(":", ""))
        for message in peer.messages
    )


def test_remote_type2_update_and_withdraw_over_fpm(topology):
    r1, r2, peer, other_peer = topology
    mac = "02:00:00:00:02:01"

    _send(other_peer, r2, RTM_NEWNEIGH, mac)
    update = peer.receive(mac, RTM_NEWNEIGH)
    assert update.ifindex == _ifindex(r1, "vxlan0")
    assert update.attributes[NDA_DST] == socket.inet_aton(VTEPS["r2"])
    assert update.attributes[NDA_VLAN] == struct.pack("=H", VNI)
    assert update.attributes[NDA_SRC_VNI] == struct.pack("=I", VNI)
    assert NDA_NH_ID not in update.attributes
    assert _zebra_mac(r1, mac)["remoteVtep"] == VTEPS["r2"]
    assert _bgp_mac(r1, mac)
    fdb = _kernel_macs(r1, mac, "vxlan0")
    assert any(entry.get("master") == "br0" for entry in fdb), fdb
    assert any(entry.get("dst") == VTEPS["r2"] for entry in fdb), fdb

    _send(other_peer, r2, RTM_DELNEIGH, mac)
    withdrawal = peer.receive(mac, RTM_DELNEIGH)
    assert withdrawal.attributes[NDA_DST] == update.attributes[NDA_DST]
    _assert_withdrawn(r1, mac, "vxlan0", r2)


@pytest.mark.parametrize("remote_fdb", ["installed", "queued", "missing-self"])
@pytest.mark.parametrize(
    "local_first", [True, False], ids=["learn-first", "withdraw-first"]
)
def test_remote_withdraw_races_local_learn(topology, remote_fdb, local_first):
    r1, r2, peer, other_peer = topology
    mac = "02:00:00:00:0a:01"
    marker = "02:00:00:00:0a:02"
    r1_addr, r2_addr = VTEPS["r1"], VTEPS["r2"]

    # Keep r2's source independent of the mobility update that r1 advertises.
    _block_remote_mac_import(r2, r1_addr)

    def advertise_remote():
        _send(other_peer, r2, RTM_NEWNEIGH, mac)
        _expect(
            lambda: _zebra_mac(r1, mac).get("remoteVtep"),
            r2_addr,
            "Zebra selected the remote VTEP",
        )

    def withdraw_remote():
        _send(other_peer, r2, RTM_DELNEIGH, mac)
        _expect(
            lambda: _bgp_neighbor_mac(r1, r2_addr, mac, "routes"),
            False,
            "BGP removed the remote path",
        )

    def learn_local():
        _send(peer, r1, RTM_NEWNEIGH, mac, "access1")
        _expect(
            lambda: _zebra_mac(r1, mac).get("intf") == "access1"
            and _bgp_neighbor_mac(r1, r2_addr, mac, "advertised-routes"),
            True,
            "Zebra selected the ASIC learn and BGP advertised the local route",
        )

    if remote_fdb != "queued":
        advertise_remote()
        peer.receive(mac, RTM_NEWNEIGH)
        assert any(row.get("dst") == r2_addr for row in _kernel_macs(r1, mac, "vxlan0"))

    with _hold_kernel_writes(r1):
        if remote_fdb == "queued":
            advertise_remote()
        if remote_fdb == "missing-self":
            r1.cmd_raises(f"bridge fdb del {mac} dev vxlan0 self dst {r2_addr}")
            fdb = _kernel_macs(r1, mac, "vxlan0")
            assert any(row.get("master") == "br0" for row in fdb), fdb
            assert all("dst" not in row for row in fdb), fdb
        if local_first:
            learn_local()
            withdraw_remote()
        else:
            withdraw_remote()
            _expect(lambda: _zebra_mac(r1, mac), {}, "Zebra removed the remote path")
            learn_local()

        # Main-thread and BGP state have changed. Previously queued writes
        # still have to run and must leave no stale VXLAN/VTEP entry behind.
        assert not _kernel_mac(r1, mac, "access1")
        assert bool(_kernel_mac(r1, mac, "vxlan0")) == (remote_fdb != "queued")
        _send(other_peer, r2, RTM_NEWNEIGH, marker)
        _expect(
            lambda: _zebra_mac(r1, marker).get("remoteVtep"),
            r2_addr,
            "Zebra queued the dataplane marker after the race",
        )

    peer.receive(marker, RTM_NEWNEIGH)
    remote_updates = [
        message.op
        for message in peer.messages
        if message.attributes.get(NDA_LLADDR) == bytes.fromhex(mac.replace(":", ""))
        and NDA_DST in message.attributes
    ]
    assert remote_updates and remote_updates[0] == RTM_NEWNEIGH, remote_updates
    assert remote_updates[-1] == RTM_DELNEIGH, remote_updates
    assert not _kernel_macs(r1, mac, "vxlan0")
    assert "extern_learn" in _kernel_mac(r1, mac, "access1").get("flags", [])
    assert _zebra_mac(r1, mac).get("intf") == "access1"
    assert _bgp_neighbor_mac(r1, r2_addr, mac, "advertised-routes")

    _send(peer, r1, RTM_DELNEIGH, mac, "access1")
    _assert_withdrawn(r1, mac, "access1", r2)
    assert not _kernel_macs(r1, mac, "vxlan0")


@pytest.mark.parametrize("order", ["add-first", "age-first", "existing-path"])
def test_local_age_races_remote_mac_add(topology, order):
    r1, r2, peer, other_peer = topology
    mac = "02:00:00:00:0c:01"
    marker = "02:00:00:00:0c:02"
    r2_addr = VTEPS["r2"]

    def advertise_remote():
        _send(other_peer, r2, RTM_NEWNEIGH, mac)
        _expect(
            lambda: _zebra_mac(r1, mac).get("remoteVtep"),
            r2_addr,
            "Zebra selected the BGP mobility update",
        )

    if order == "existing-path":
        _block_remote_mac_import(r2, VTEPS["r1"])
        advertise_remote()
        peer.receive(mac, RTM_NEWNEIGH)
        _send(peer, r1, RTM_NEWNEIGH, mac)
        _expect(
            lambda: _bgp_neighbor_mac(r1, r2_addr, mac, "advertised-routes"),
            True,
            "BGP selected and advertised the local MAC over the existing remote path",
        )
        peer.receive(mac, RTM_DELNEIGH)
        assert _bgp_neighbor_mac(r1, r2_addr, mac, "routes")
        assert _kernel_mac(r1, mac, "access0")
    else:
        _send(peer, r1, RTM_NEWNEIGH, mac)
        _assert_local(r1, r2, mac)

    with _hold_kernel_writes(r1):
        if order == "add-first":
            advertise_remote()
            _send(peer, r1, RTM_DELNEIGH, mac)
        else:
            _send(peer, r1, RTM_DELNEIGH, mac)
            if order == "age-first":
                _expect(
                    lambda: not _zebra_mac(r1, mac) and not _bgp_mac(r2, mac),
                    True,
                    "BGP withdrew the local path before the remote MAC appeared",
                )
                advertise_remote()
            else:
                _expect(
                    lambda: _zebra_mac(r1, mac).get("remoteVtep"),
                    r2_addr,
                    "Zebra selected the existing remote path without a new BGP update",
                )

        # Send a duplicate age-out and then a witness on the same FPM stream.
        _send(peer, r1, RTM_DELNEIGH, mac)
        _send(peer, r1, RTM_NEWNEIGH, marker)
        _expect(
            lambda: _zebra_mac(r1, marker).get("intf"),
            "access0",
            "Zebra processed the ASIC age-outs before the witness learn",
        )
        assert _kernel_mac(r1, mac, "access0")
        assert not _kernel_macs(r1, mac, "vxlan0")

    peer.receive(mac, RTM_NEWNEIGH)
    _expect(
        lambda: bool(_kernel_mac(r1, marker, "access0")),
        True,
        "the kernel processed the writes queued after the ASIC age-outs",
    )
    fdb = _kernel_macs(r1, mac, "vxlan0")
    assert any(row.get("dst") == r2_addr for row in fdb), fdb
    assert any(row.get("master") == "br0" for row in fdb), fdb
    assert not _kernel_mac(r1, mac, "access0")
    assert _zebra_mac(r1, mac).get("remoteVtep") == r2_addr
    assert _bgp_neighbor_mac(r1, r2_addr, mac, "routes")
    assert not _bgp_neighbor_mac(r1, r2_addr, mac, "advertised-routes")

    _send(other_peer, r2, RTM_DELNEIGH, mac)
    peer.receive(mac, RTM_DELNEIGH)
    _assert_withdrawn(r1, mac, "vxlan0", r2)


def test_static_replay_on_port_up_and_flush_on_detach(topology):
    r1, r2, peer, _ = topology
    static = "02:00:00:00:03:01"
    dynamic = "02:00:00:00:03:02"
    marker = "02:00:00:00:03:09"

    r1.cmd_raises("ip link set access0 down")
    _expect(
        lambda: "access0 is down"
        in r1.vtysh_cmd("show interface access0", daemon="zebra", raises=True).lower(),
        True,
        "Zebra observed the port going down",
    )
    _send(peer, r1, RTM_NEWNEIGH, static, sticky=True)
    _send(peer, r1, RTM_NEWNEIGH, dynamic)
    # Follow both learns with a learn on the live port on the same FPM
    # socket, then wait for the resulting Type-2 at the BGP peer.
    _send(peer, r1, RTM_NEWNEIGH, marker, "access1")
    _assert_local(r1, r2, marker, "access1")
    for mac in (static, dynamic):
        assert not _zebra_mac(r1, mac)
        assert not _bgp_mac(r2, mac)
        assert not _kernel_mac(r1, mac, "access0")

    r1.cmd_raises("ip link set access0 up")
    _assert_local(r1, r2, static, sticky=True)
    assert not _zebra_mac(r1, dynamic)
    assert not _kernel_mac(r1, dynamic, "access0")
    assert not _bgp_mac(r2, dynamic)

    r1.cmd_raises("ip link set access0 nomaster")
    _assert_withdrawn(r1, static, "access0", r2)
    _assert_local(r1, r2, marker, "access1")


def test_replay_asic_mac_when_vni_is_created(topology):
    r1, r2, peer, _ = topology
    mac = "02:00:00:00:04:01"

    r1.cmd_raises("ip link del vxlan0")
    _expect(
        lambda: _show(r1, "zebra", f"show evpn vni {VNI}").get("vni"),
        None,
        "VNI removed",
    )
    _send(peer, r1, RTM_NEWNEIGH, mac)
    _expect(
        lambda: "extern_learn" in _kernel_mac(r1, mac, "access0").get("flags", []),
        True,
        "ASIC learn reached the kernel while the VNI was absent",
    )
    assert not _bgp_mac(r2, mac)

    # The dataplane read hook must restore the reported MAC without a
    # second FPM learn.
    _create_vxlan(r1)
    _assert_local(r1, r2, mac)


def _set_up_ethernet_segment(r1, *peers):
    for router in (r1, *peers):
        for command in (
            "ip link add es0 type bond mode active-backup",
            "ip link add esmember type dummy",
            "ip link set esmember master es0",
            "ip link set esmember up",
            "ip link set es0 master br0 up",
            f"bridge vlan add vid {VNI} dev es0 pvid untagged",
        ):
            router.cmd_raises(command)
        _configure(
            router,
            "interface es0",
            "evpn mh es-id 1",
            "evpn mh es-sys-mac 44:38:39:ff:ff:01",
        )

    def established():
        output = r1.vtysh_cmd("show evpn es", daemon="zebra", raises=True)
        return all(
            any(
                ESI in line and " up " in line and VTEPS[peer.name] in line
                for line in output.splitlines()
            )
            for peer in peers
        )

    _expect(established, True, "local Ethernet Segment has an operational peer")


@pytest.fixture
def ethernet_segment(topology):
    r1, r2, _, _ = topology
    _set_up_ethernet_segment(r1, r2)
    return topology


def _es_mac(router, mac, *, inactive, peer_active):
    entry = _zebra_mac(router, mac)
    return (
        entry.get("type") == "local"
        and entry.get("intf") == "es0"
        and entry.get("esi") == ESI
        and entry.get("localInactive", False) == inactive
        and entry.get("peerActive", False) == peer_active
    )


def _withdraw_peer(r1, remote):
    _configure(
        remote,
        "router bgp 65000",
        f"neighbor {VTEPS[r1.name]} shutdown",
        daemon="bgpd",
    )
    _expect(
        lambda: _bgp_state(r1, VTEPS[remote.name]) != "Established",
        True,
        "peer BGP session withdrawn",
    )


def test_frr_restart_resynchronizes_local_and_remote_macs(topology):
    r1, r2, peer, other_peer = topology
    local = "02:00:00:00:09:01"
    remote = "02:00:00:00:09:02"

    _send(peer, r1, RTM_NEWNEIGH, local)
    _assert_local(r1, r2, local)
    _send(other_peer, r2, RTM_NEWNEIGH, remote)
    peer.receive(remote, RTM_NEWNEIGH)

    # Keep BGP down during startup to order its replay after FPM connects.
    _withdraw_peer(r1, r2)
    peer.receive(remote, RTM_DELNEIGH)
    r1.stop()
    peer.disconnect()
    r1.start()
    assert not r1.check_router_running()
    _configure(r1, f"fpm address 127.0.0.1 port {peer.port}", daemon="zebra")
    peer.accept()
    _expect(
        lambda: _show(r1, "zebra", f"show evpn vni {VNI}").get("vni"),
        VNI,
        "VNI was rebuilt after the restart",
    )
    assert not _zebra_mac(r1, local)
    assert not _bgp_mac(r1, local)

    # Replay the ASIC's retained entry as fpmsyncd does after a restart.
    _send(peer, r1, RTM_NEWNEIGH, local)
    _configure(
        r2,
        "router bgp 65000",
        f"no neighbor {VTEPS['r1']} shutdown",
        daemon="bgpd",
    )
    _assert_local(r1, r2, local)
    replay = peer.receive(remote, RTM_NEWNEIGH)
    assert replay.attributes[NDA_DST] == socket.inet_aton(VTEPS["r2"])
    assert _zebra_mac(r1, remote)["type"] == "remote"
    assert _bgp_mac(r1, remote)


@pytest.mark.parametrize("first", ["asic-age", "peer-withdraw"])
@pytest.mark.parametrize("learned_first", ["peer", "asic"])
def test_two_source_withdrawal_orders(ethernet_segment, first, learned_first):
    r1, r2, peer, other_peer = ethernet_segment
    mac = "02:00:00:00:05:01"

    if learned_first == "peer":
        _send(other_peer, r2, RTM_NEWNEIGH, mac, "es0")
        _expect(
            lambda: _es_mac(r1, mac, inactive=True, peer_active=True),
            True,
            "only the ES peer owns the MAC",
        )
        _send(peer, r1, RTM_NEWNEIGH, mac, "es0")
    else:
        _send(peer, r1, RTM_NEWNEIGH, mac, "es0")
        _expect(
            lambda: _es_mac(r1, mac, inactive=False, peer_active=False)
            and _es_mac(r2, mac, inactive=True, peer_active=True)
            and bool(_kernel_mac(r1, mac, "es0"))
            and _bgp_mac(r1, mac),
            True,
            "only the ASIC owns the MAC, and the ES peer sees its advertisement",
        )
        _send(other_peer, r2, RTM_NEWNEIGH, mac, "es0")
    _expect(
        lambda: _es_mac(r1, mac, inactive=False, peer_active=True)
        and bool(_kernel_mac(r1, mac, "es0"))
        and _bgp_mac(r1, mac),
        True,
        "both sources own the MAC",
    )

    if first == "asic-age":
        _send(peer, r1, RTM_DELNEIGH, mac, "es0")
        _expect(
            lambda: _es_mac(r1, mac, inactive=True, peer_active=True),
            True,
            "peer-backed entry survives ASIC age-out",
        )
        _withdraw_peer(r1, r2)
    else:
        _withdraw_peer(r1, r2)
        _expect(
            lambda: _es_mac(r1, mac, inactive=False, peer_active=False)
            and bool(_kernel_mac(r1, mac, "es0"))
            and _bgp_mac(r1, mac),
            True,
            "ASIC-backed entry stays active and advertised after peer withdrawal",
        )
        _send(peer, r1, RTM_DELNEIGH, mac, "es0")

    _assert_withdrawn(r1, mac, "es0")


@pytest.mark.parametrize("departing", ["peer", "asic"])
@pytest.mark.parametrize("add_first", [True, False], ids=["add-first", "delete-first"])
def test_es_mac_handoff_with_kernel_writes_pending(
    ethernet_segment, departing, add_first
):
    r1, r2, peer, other_peer = ethernet_segment
    mac = "02:00:00:00:0b:01"
    marker = "02:00:00:00:0b:02"
    r2_addr = VTEPS["r2"]
    sources = {"asic": (r1, peer), "peer": (r2, other_peer)}
    arriving = "asic" if departing == "peer" else "peer"

    def send(source, op):
        router, provider = sources[source]
        _send(provider, router, op, mac, "es0")

    def expect_owner(asic, es_peer):
        _expect(
            lambda: _es_mac(r1, mac, inactive=not asic, peer_active=es_peer)
            and _bgp_neighbor_mac(r1, r2_addr, mac, "advertised-routes"),
            True,
            f"Zebra and BGP reflect ASIC={asic}, ES peer={es_peer}",
        )

    send(departing, RTM_NEWNEIGH)
    expect_owner(departing == "asic", departing == "peer")
    _expect(
        lambda: "extern_learn" in _kernel_mac(r1, mac, "es0").get("flags", []),
        True,
        "the initial owner's bridge FDB entry is installed",
    )

    with _hold_kernel_writes(r1):
        if add_first:
            send(arriving, RTM_NEWNEIGH)
            expect_owner(True, True)
            send(departing, RTM_DELNEIGH)
        else:
            send(departing, RTM_DELNEIGH)
            _expect(
                lambda: not _zebra_mac(r1, mac)
                and not _bgp_neighbor_mac(r1, r2_addr, mac, "advertised-routes"),
                True,
                "Zebra and BGP clear the MAC while neither source is present",
            )
            send(arriving, RTM_NEWNEIGH)
        expect_owner(arriving == "asic", arriving == "peer")

        # The old FDB entry still exists while the control-plane changes are
        # processed. A later FPM frame will order the checks after those writes.
        assert _kernel_mac(r1, mac, "es0")
        _send(other_peer, r2, RTM_NEWNEIGH, marker)
        _expect(
            lambda: _zebra_mac(r1, marker).get("remoteVtep"),
            r2_addr,
            "Zebra queued the dataplane marker after the handoff",
        )

    peer.receive(marker, RTM_NEWNEIGH)
    expect_owner(arriving == "asic", arriving == "peer")
    assert "extern_learn" in _kernel_mac(r1, mac, "es0").get("flags", [])
    assert not _kernel_macs(r1, mac, "vxlan0")

    send(arriving, RTM_DELNEIGH)
    _assert_withdrawn(r1, mac, "es0", r2)
    _send(other_peer, r2, RTM_DELNEIGH, marker)
    peer.receive(marker, RTM_DELNEIGH)
    _withdraw_peer(r1, r2)


@pytest.mark.parametrize("first_peer", ["r2", "r3"])
def test_asic_age_with_two_es_peer_paths(request, tmp_path, sonic_module, first_peer):
    with _topology(request, tmp_path, sonic_module, third_peer=True) as (r1, r2, peers):
        r3 = r1.tgen.gears["r3"]
        _set_up_ethernet_segment(r1, r2, r3)
        mac = "02:00:00:00:0d:01"

        _send(peers["r1"], r1, RTM_NEWNEIGH, mac, "es0")
        _expect(
            lambda: _es_mac(r1, mac, inactive=False, peer_active=False)
            and bool(_kernel_mac(r1, mac, "es0")),
            True,
            "the ASIC owns the MAC before either peer advertises it",
        )
        for remote in (r2, r3):
            _send(peers[remote.name], remote, RTM_NEWNEIGH, mac, "es0")
            _expect(
                lambda: _bgp_neighbor_mac(r1, VTEPS[remote.name], mac, "routes"),
                True,
                f"{remote.name} advertised its independent Type-2 path",
            )
        _expect(
            lambda: _es_mac(r1, mac, inactive=False, peer_active=True),
            True,
            "the ASIC MAC is backed by ES peer paths",
        )

        first, last = (r2, r3) if first_peer == "r2" else (r3, r2)
        with _hold_kernel_writes(r1):
            _send(peers["r1"], r1, RTM_DELNEIGH, mac, "es0")
            _expect(
                lambda: _es_mac(r1, mac, inactive=True, peer_active=True),
                True,
                "the ASIC aged out and the local MAC is peer-backed",
            )
            _withdraw_peer(r1, first)
            _expect(
                lambda: _bgp_neighbor_mac(r1, VTEPS[last.name], mac, "routes")
                and _bgp_neighbor_mac(r1, VTEPS[last.name], mac, "advertised-routes")
                and _es_mac(r1, mac, inactive=True, peer_active=True),
                True,
                "the remaining peer path still backs the local MAC",
            )

        pin = peers["r1"].receive(mac, RTM_NEWNEIGH)
        assert pin.state & NUD_NOARP
        assert pin.ifindex == _ifindex(r1, "es0")
        assert "extern_learn" in _kernel_mac(r1, mac, "es0").get("flags", [])
        assert not _kernel_macs(r1, mac, "vxlan0")

        _withdraw_peer(r1, last)
        _assert_withdrawn(r1, mac, "es0")
        assert not _kernel_macs(r1, mac, "vxlan0")


def test_es_pin_replay_and_withdraw_when_kernel_entry_is_missing(ethernet_segment):
    r1, r2, peer, other_peer = ethernet_segment
    mac = "02:00:00:00:06:01"
    port_index = _ifindex(r1, "es0")
    probe_peer_sync(r1, "es0", port_index, _ifindex(r1, "br0"), VNI)

    _send(other_peer, r2, RTM_NEWNEIGH, mac, "es0")
    pin = peer.receive(mac, RTM_NEWNEIGH)
    assert pin.ifindex == port_index
    assert pin.state & NUD_NOARP
    assert pin.attributes[NDA_VLAN] == struct.pack("=H", VNI)
    assert NDA_DST not in pin.attributes and NDA_NH_ID not in pin.attributes
    assert _es_mac(r1, mac, inactive=True, peer_active=True)
    assert _kernel_mac(r1, mac, "es0")

    peer.disconnect()
    peer.accept()
    assert peer.receive(mac, RTM_NEWNEIGH) == pin

    # The kernel entry is already absent by the time Zebra submits the
    # local delete. The FPM provider must still receive the delete context.
    _delete_kernel_mac(r1, mac, "es0")
    assert not _kernel_mac(r1, mac, "es0")
    _withdraw_peer(r1, r2)
    removal = peer.receive(mac, RTM_DELNEIGH)
    assert removal.ifindex == port_index
    assert removal.attributes[NDA_VLAN] == pin.attributes[NDA_VLAN]
    _assert_withdrawn(r1, mac, "es0")
