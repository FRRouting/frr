#!/usr/bin/env python
# SPDX-License-Identifier: ISC
#
# test_ospf_dup_network_lsa.py
#
# Copyright (c) 2026 ATCorp
#
"""
test_ospf_dup_network_lsa.py
============================

Regression test for the duplicate network-LSA Link State ID problem in
ospfd's SPF (RFC 2328 Section 16.1).

The LSDB is keyed by (Link State ID, Advertising Router), so several
network-LSA copies can share the same Link State ID.  SPF used to take
the first copy in Advertising Router order, so a forged copy with a
lower Advertising Router than the real DR shadowed the real network-LSA:
the reverse-link check then rejected the transit link and the whole
segment vanished from the observer's route table.  The fix selects the
first copy that is not MaxAge and that lists the router as attached.

Topology (all four routers in area 0.0.0.0 on one broadcast segment)

    r1 (DR,       RID 11.11.11.1, 10.211.11.1, priority 200)
    r2 (injector, RID 11.11.11.2, 10.211.11.2, priority 100, BDR)
    r3 (observer, RID 11.11.11.3, 10.211.11.3, priority 50)
    r4 (target,   RID 11.11.11.4, 10.211.11.4, priority 10, lo 198.51.100.11/32)

The real network-LSA has Link State ID 10.211.11.1 (the DR's interface
address).  r2 injects unicast OSPF LS Updates (TTL 1, protocol 89) with
its own source address, so they are processed inside the real r2-r3 /
r2-r1 adjacencies.  Forged copies use Advertising Router 1.0.0.11
(lower than the real 11.11.11.1, so they sort first in the LSDB) or
250.0.0.11 (higher, sorts last).

Test plan
---------

1. test_baseline_full_adjacency_and_routes
     DR election (r1=DR, r2=Backup, r3/r4=DROther), Full adjacencies,
     the real network-LSA on all routers, the transit-dependent route
     198.51.100.11/32 and ping present.

2. test_no_attack_control
     Without injection nothing changes: same network-LSA sequence
     number, no reverse-link-check failures in the logs.

3. test_invalid_checksum_control
     A forged copy with a corrupted LSA checksum is rejected: not
     installed, "LSA checksum error" logged, route retained.

4. test_high_adv_duplicate_control
     A valid forged copy with a HIGHER Advertising Router is installed
     (duplicates are not rejected wholesale) but sorts after the real
     copy, so SPF keeps selecting the real one: route retained.

5. test_low_adv_duplicate_trigger
     A valid forged copy with a LOWER Advertising Router is installed
     and sorts first.  Fixed ospfd keeps selecting the real DR's copy
     (the forged one does not list r3 as attached), so r3 retains the
     route and ping.  Unfixed ospfd loses both.

6. test_dr_maxage_fightback
     Copies with increasing sequence numbers sent to the real DR are
     MaxAge-flushed by it (RFC 2328 Section 12.4.2/13.4 fight-back is
     preserved by the fix).

7. test_recovery
     The forged copy is garbage-collected from the observer's LSDB and
     the adjacencies stay Full.  Fixed ospfd never lost the route;
     unfixed ospfd keeps the stale empty route table because MaxAge
     removal does not schedule a new SPF.
"""

import json
import os
import re
import shlex
import socket
import struct
import time

import pytest

from lib.topogen import Topogen, get_topogen
from lib.topolog import logger

CWD = os.path.dirname(os.path.realpath(__file__))

pytestmark = [pytest.mark.ospfd]

ROUTERS = ("r1", "r2", "r3", "r4")
DR, INJECTOR, OBSERVER, TARGET = ROUTERS
IP_ADDRESSES = {
    DR: "10.211.11.1",
    INJECTOR: "10.211.11.2",
    OBSERVER: "10.211.11.3",
    TARGET: "10.211.11.4",
}
ROUTER_IDS = {
    DR: "11.11.11.1",
    INJECTOR: "11.11.11.2",
    OBSERVER: "11.11.11.3",
    TARGET: "11.11.11.4",
}
LOW_ADV_ROUTER = "1.0.0.11"
HIGH_ADV_ROUTER = "250.0.0.11"
TARGET_IP = "198.51.100.11"
TARGET_PREFIX = TARGET_IP + "/32"
NETWORK_ID = IP_ADDRESSES[DR]
LOW_INVALID_SEQ = 0x80020000
LOW_VALID_SEQ = 0x80020001
HIGH_VALID_SEQ = 0x80010001
DR_UPDATE_COUNT = 3
DR_UPDATE_SPACING = 1.2
MAXAGE_KEY = "MaxAge set to LSA[Type2,id(%s),ar(%s)]" % (NETWORK_ID, LOW_ADV_ROUTER)


def build_topo(tgen):
    for rname in ROUTERS:
        tgen.add_router(rname)
    switch = tgen.add_switch("s1")
    for rname in ROUTERS:
        switch.add_link(tgen.gears[rname])


def setup_module(mod):
    tgen = Topogen(build_topo, mod.__name__)
    tgen.start_topology()
    for rname, router in tgen.routers().items():
        router.load_frr_config(os.path.join(CWD, rname, "frr.conf"))
    tgen.start_router()
    # "debug ospf event" in the config file only sets the config flag
    # (ospf_dump.c: the CONFIG_NODE branch never sets the term flag), so
    # enable it at the enable node like the reproducer does.
    for rname, router in tgen.routers().items():
        out = router.vtysh_cmd("debug ospf event")
        assert (
            "OSPF Event debugging is on" in out
        ), "could not enable OSPF event debugging on %s: %s" % (rname, out)


def teardown_module():
    tgen = get_topogen()
    tgen.stop_topology()


def _failures(tgen):
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)


def _wait_until(func, timeout_s, interval_s=1):
    deadline = time.time() + timeout_s
    while time.time() < deadline:
        if func():
            return True
        time.sleep(interval_s)
    return bool(func())


def _interface(router):
    out = router.vtysh_cmd(
        "show ip ospf interface %s-eth0 json" % router.name, isjson=True
    )
    return out["interfaces"]["%s-eth0" % router.name]


def _neighbors(router):
    out = router.vtysh_cmd("show ip ospf neighbor json", isjson=True)
    return out.get("neighbors", {})


def _neighbor_state(router, peer_rid):
    entries = _neighbors(router).get(peer_rid, [])
    return entries[0].get("converged") if entries else None


def _find_network_lsas(value):
    matches = []
    if isinstance(value, dict):
        if value.get("lsaType") == "network-LSA" and "linkStateId" in value:
            return [value]
        for child in value.values():
            matches.extend(_find_network_lsas(child))
    elif isinstance(value, list):
        for child in value:
            matches.extend(_find_network_lsas(child))
    return matches


def _network_lsas(router):
    out = router.vtysh_cmd("show ip ospf database network json", isjson=True)
    lsas = []
    for lsa in _find_network_lsas(out):
        if lsa.get("linkStateId") != NETWORK_ID:
            continue
        lsas.append(
            {
                "id": lsa.get("linkStateId"),
                "adv_router": lsa.get("advertisingRouter"),
                "age": lsa.get("lsaAge"),
                "seq": lsa.get("lsaSeqNumber"),
                "attached_routers": sorted(lsa.get("attchedRouters", {}).keys()),
            }
        )
    return lsas


def _network_lsa(router, adv_router):
    for lsa in _network_lsas(router):
        if lsa["adv_router"] == adv_router:
            return lsa
    return None


def _network_adv_order(router):
    return [lsa["adv_router"] for lsa in _network_lsas(router)]


def _ospf_route_has(router, ip):
    return ip in router.vtysh_cmd("show ip ospf route json")


def _kernel_route(router, prefix):
    return router.cmd("ip route show %s" % prefix).strip()


def _ping(router, ip):
    rc = router.cmd("ping -c 1 -W 1 %s >/dev/null 2>&1; echo $?" % ip).strip()
    return rc.splitlines()[-1] == "0" if rc else False


def _lsupd_in(router):
    out = router.vtysh_cmd(
        "show ip ospf interface traffic %s-eth0 json" % router.name, isjson=True
    )
    return out["%s-eth0" % router.name].get("lsUpdIn")


def _ospfd_alive(router):
    return bool(router.cmd("pidof ospfd || true").strip())


def _log_path(tgen, router):
    return os.path.join(tgen.logdir, router.name, "ospfd.log")


def _log_offset(tgen, router):
    try:
        return os.path.getsize(_log_path(tgen, router))
    except OSError:
        return 0


def _log_since(tgen, router, offset):
    try:
        with open(_log_path(tgen, router), errors="replace") as fp:
            fp.seek(offset)
            return fp.read()
    except OSError:
        return ""


def _mac(router, ifname):
    return router.cmd("cat /sys/class/net/%s/address" % ifname).strip()


def fletcher_sums(data):
    c0 = 0
    c1 = 0
    for value in data:
        c0 = (c0 + value) % 255
        c1 = (c1 + c0) % 255
    return c0, c1


def fletcher_checksum(lsa):
    data = bytearray(lsa[2:])
    data[14:16] = b"\x00\x00"
    c0, c1 = fletcher_sums(data)
    x = ((len(data) - 14 - 1) * c0 - c1) % 255
    if x == 0:
        x = 255
    y = 510 - c0 - x
    if y > 255:
        y -= 255
    data[14:16] = bytes((x, y))
    if fletcher_sums(data) != (0, 0):
        raise ValueError("invalid generated LSA Fletcher checksum")
    return (x << 8) | y


def internet_checksum(data):
    if len(data) % 2:
        data += b"\x00"
    total = sum(struct.unpack("!%dH" % (len(data) // 2), data))
    total = (total & 0xFFFF) + (total >> 16)
    total = (total & 0xFFFF) + (total >> 16)
    return (~total) & 0xFFFF


def make_update(adv_router, sequence, options, corrupt_lsa=False):
    """One LSU carrying one forged network-LSA copy of the real DR's LSA."""
    lsa = bytearray(
        struct.pack(
            "!HBB4s4sIHH",
            1,
            options,
            2,
            socket.inet_aton(NETWORK_ID),
            socket.inet_aton(adv_router),
            sequence,
            0,
            28,
        )
        + socket.inet_aton("255.255.255.0")
        + socket.inet_aton(adv_router)
    )
    checksum = fletcher_checksum(lsa)
    struct.pack_into("!H", lsa, 16, checksum)
    if corrupt_lsa:
        lsa[16] ^= 0x5A
    packet = bytearray(
        struct.pack(
            "!BBH4s4sHH8sI",
            2,
            4,
            28 + len(lsa),
            socket.inet_aton(ROUTER_IDS[INJECTOR]),
            socket.inet_aton("0.0.0.0"),
            0,
            0,
            b"\x00" * 8,
            1,
        )
        + lsa
    )
    struct.pack_into("!H", packet, 12, internet_checksum(bytes(packet)))
    if internet_checksum(bytes(packet)) != 0:
        raise ValueError("invalid generated OSPF checksum")
    return {
        "src_ip": IP_ADDRESSES[INJECTOR],
        "ospf_hex": bytes(packet).hex(),
        "fields": {
            "lsa_id": NETWORK_ID,
            "adv_router": adv_router,
            "lsa_seq_hex": "0x%08x" % sequence,
            "lsa_seq": sequence,
            "corrupt_lsa_checksum": corrupt_lsa,
        },
    }


def run_phase(tgen, name, packets, dst_router, spacing=0, tail=1.0):
    """Inject packets from r2 at dst_router; verify the packet path."""
    marks = {rname: _log_offset(tgen, tgen.gears[rname]) for rname in ROUTERS}
    before = _lsupd_in(tgen.gears[dst_router.name])
    pcap_path = os.path.join(tgen.logdir, name + ".pcap")
    result_path = os.path.join(tgen.logdir, name + "_result.json")
    cfg = {
        "iface": "%s-eth0" % INJECTOR,
        "src_mac": _mac(tgen.gears[INJECTOR], "%s-eth0" % INJECTOR),
        "packets": packets,
        "spacing": spacing,
        "tail": tail,
        "pcap_path": pcap_path,
        "result_path": result_path,
    }
    config_path = os.path.join(tgen.logdir, name + "_input.json")
    with open(config_path, "w") as fp:
        json.dump(cfg, fp, indent=2, sort_keys=True)
    tgen.gears[INJECTOR].cmd_raises(
        "python3 %s %s"
        % (
            shlex.quote(os.path.join(CWD, "inject_network_lsa.py")),
            shlex.quote(config_path),
        )
    )
    with open(result_path) as fp:
        capture = json.load(fp)
    after = _lsupd_in(tgen.gears[dst_router.name])
    phase = {
        "name": name,
        "capture": capture,
        "lsupd_in_delta": (after or 0) - (before or 0),
        "marks": marks,
    }
    phase["packet_path_verified"] = bool(
        len(capture["injected_events"]) == len(packets)
        and phase["lsupd_in_delta"] >= len(packets)
    )
    logger.info(
        "phase %s: injected=%d/%d lsUpdIn(+%d) on %s pcap=%s",
        name,
        len(capture["injected_events"]),
        len(packets),
        phase["lsupd_in_delta"],
        dst_router.name,
        pcap_path,
    )
    return phase


def _baseline_ready(tgen):
    expected_roles = {
        DR: "DR",
        INJECTOR: "Backup",
        OBSERVER: "DROther",
        TARGET: "DROther",
    }
    for rname, role in expected_roles.items():
        if _interface(tgen.gears[rname]).get("state") != role:
            return False
    for peer in (DR, INJECTOR, OBSERVER):
        if _neighbor_state(tgen.gears[TARGET], ROUTER_IDS[peer]) is None:
            return False
    if _neighbor_state(tgen.gears[OBSERVER], ROUTER_IDS[DR]) != "Full":
        return False
    if _neighbor_state(tgen.gears[OBSERVER], ROUTER_IDS[INJECTOR]) != "Full":
        return False
    for peer in (INJECTOR, OBSERVER, TARGET):
        if _neighbor_state(tgen.gears[DR], ROUTER_IDS[peer]) != "Full":
            return False
    for rname in ROUTERS:
        real = _network_lsa(tgen.gears[rname], ROUTER_IDS[DR])
        if real is None or real["age"] >= 3600:
            return False
        if set(real["attached_routers"]) != set(ROUTER_IDS.values()):
            return False
        if _network_lsa(tgen.gears[rname], LOW_ADV_ROUTER):
            return False
        if _network_lsa(tgen.gears[rname], HIGH_ADV_ROUTER):
            return False
    for rname in (DR, INJECTOR, OBSERVER):
        if not _ospf_route_has(tgen.gears[rname], TARGET_IP):
            return False
        if not _kernel_route(tgen.gears[rname], TARGET_PREFIX):
            return False
    return True


def test_baseline_full_adjacency_and_routes():
    """Baseline: DR election, Full adjacencies, real network-LSA, routes."""
    tgen = get_topogen()
    _failures(tgen)
    assert _wait_until(
        lambda: _baseline_ready(tgen), 150
    ), "baseline did not converge: roles=%s r3-nbrs=%s lsdb-r3=%s" % (
        {r: _interface(tgen.gears[r]).get("state") for r in ROUTERS},
        {
            ROUTER_IDS[p]: _neighbor_state(tgen.gears[OBSERVER], ROUTER_IDS[p])
            for p in (DR, INJECTOR, TARGET)
        },
        _network_lsas(tgen.gears[OBSERVER]),
    )
    assert _ping(
        tgen.gears[OBSERVER], TARGET_IP
    ), "baseline observer ping to the transit-dependent target failed"


def test_no_attack_control():
    """Without injection the observer state must be stable."""
    tgen = get_topogen()
    _failures(tgen)
    marks = {rname: _log_offset(tgen, tgen.gears[rname]) for rname in ROUTERS}
    seq_before = _network_lsa(tgen.gears[OBSERVER], ROUTER_IDS[DR])["seq"]
    time.sleep(2)
    assert _baseline_ready(tgen), "no-attack control: baseline state drifted"
    assert (
        _network_lsa(tgen.gears[OBSERVER], ROUTER_IDS[DR])["seq"] == seq_before
    ), "no-attack control: real network-LSA sequence number changed"
    for rname in ROUTERS:
        text = _log_since(tgen, tgen.gears[rname], marks[rname])
        assert "The LSA doesn't have a link back" not in text, (
            "no-attack control: reverse-link failure logged on %s" % rname
        )
    assert _ping(
        tgen.gears[OBSERVER], TARGET_IP
    ), "no-attack control: observer ping to the target failed"


def test_invalid_checksum_control():
    """A corrupted-checksum forged copy must be rejected cleanly."""
    tgen = get_topogen()
    _failures(tgen)
    options = _real_network_options(tgen)
    packet = make_update(LOW_ADV_ROUTER, LOW_INVALID_SEQ, options, corrupt_lsa=True)
    packet["dst_ip"] = IP_ADDRESSES[OBSERVER]
    packet["dst_mac"] = _mac(tgen.gears[OBSERVER], "%s-eth0" % OBSERVER)
    phase = run_phase(tgen, "invalid_checksum", [packet], tgen.gears[OBSERVER])
    assert phase["packet_path_verified"], (
        "invalid-checksum packet arrival could not be verified: %s" % phase
    )
    time.sleep(2)
    assert (
        _network_lsa(tgen.gears[OBSERVER], LOW_ADV_ROUTER) is None
    ), "invalid-checksum forged copy was installed on the observer"
    assert _ospf_route_has(
        tgen.gears[OBSERVER], TARGET_IP
    ), "invalid-checksum control: observer lost the OSPF route"
    assert _kernel_route(
        tgen.gears[OBSERVER], TARGET_PREFIX
    ), "invalid-checksum control: observer lost the kernel route"
    assert _ping(
        tgen.gears[OBSERVER], TARGET_IP
    ), "invalid-checksum control: observer ping failed"
    text = _log_since(tgen, tgen.gears[OBSERVER], phase["marks"][OBSERVER])
    assert (
        "LSA checksum error" in text
    ), "invalid-checksum control: no LSA checksum error logged on the observer"


def _real_network_options(tgen):
    detail = tgen.gears[OBSERVER].vtysh_cmd(
        "show ip ospf database network %s" % NETWORK_ID
    )
    match = re.search(r"Options:\s*0x([0-9a-fA-F]+)", detail)
    assert match, "cannot read the real network-LSA options: %s" % detail
    return int(match.group(1), 16)


def test_high_adv_duplicate_control():
    """A valid duplicate with a HIGHER adv_router installs but must not win."""
    tgen = get_topogen()
    _failures(tgen)
    options = _real_network_options(tgen)
    packet = make_update(HIGH_ADV_ROUTER, HIGH_VALID_SEQ, options)
    packet["dst_ip"] = IP_ADDRESSES[OBSERVER]
    packet["dst_mac"] = _mac(tgen.gears[OBSERVER], "%s-eth0" % OBSERVER)
    phase = run_phase(tgen, "high_adv_control", [packet], tgen.gears[OBSERVER])
    assert phase["packet_path_verified"], (
        "high-adv_router control packet arrival could not be verified: %s" % phase
    )

    def _installed():
        lsa = _network_lsa(tgen.gears[OBSERVER], HIGH_ADV_ROUTER)
        return lsa is not None and lsa["age"] < 3600

    assert _wait_until(_installed, 15), (
        "valid high-adv_router duplicate was not installed on the observer: %s"
        % _network_lsas(tgen.gears[OBSERVER])
    )
    order = _network_adv_order(tgen.gears[OBSERVER])
    assert order.index(ROUTER_IDS[DR]) < order.index(HIGH_ADV_ROUTER), (
        "high-adv_router duplicate does not sort after the real copy: %s" % order
    )
    assert _ospf_route_has(
        tgen.gears[OBSERVER], TARGET_IP
    ), "high-adv_router control: observer lost the OSPF route"
    assert _kernel_route(
        tgen.gears[OBSERVER], TARGET_PREFIX
    ), "high-adv_router control: observer lost the kernel route"
    text = _log_since(tgen, tgen.gears[OBSERVER], phase["marks"][OBSERVER])
    assert (
        "The LSA doesn't have a link back" not in text
    ), "high-adv_router control: reverse-link failure logged on the observer"
    assert _ping(
        tgen.gears[OBSERVER], TARGET_IP
    ), "high-adv_router control: observer ping failed"


def test_low_adv_duplicate_trigger():
    """A valid duplicate with a LOWER adv_router installs and sorts first.

    Fixed ospfd keeps selecting the real DR's copy for SPF, so the
    observer retains the transit-dependent route.  Unfixed ospfd selects
    the forged copy, the reverse-link check rejects it, and the route
    and ping are lost.
    """
    tgen = get_topogen()
    _failures(tgen)
    options = _real_network_options(tgen)
    packet = make_update(LOW_ADV_ROUTER, LOW_VALID_SEQ, options)
    packet["dst_ip"] = IP_ADDRESSES[OBSERVER]
    packet["dst_mac"] = _mac(tgen.gears[OBSERVER], "%s-eth0" % OBSERVER)
    phase = run_phase(tgen, "low_adv_trigger", [packet], tgen.gears[OBSERVER])
    assert phase["packet_path_verified"], (
        "low-adv_router trigger packet arrival could not be verified: %s" % phase
    )

    def _installed():
        lsa = _network_lsa(tgen.gears[OBSERVER], LOW_ADV_ROUTER)
        return lsa is not None and lsa["age"] < 3600

    assert _wait_until(_installed, 15), (
        "low-adv_router duplicate was not installed on the observer: %s"
        % _network_lsas(tgen.gears[OBSERVER])
    )
    low_lsa = _network_lsa(tgen.gears[OBSERVER], LOW_ADV_ROUTER)
    assert low_lsa["attached_routers"] == [LOW_ADV_ROUTER], (
        "low-adv_router duplicate has unexpected attached routers: %s" % low_lsa
    )
    order = _network_adv_order(tgen.gears[OBSERVER])
    assert (
        LOW_ADV_ROUTER in order
        and ROUTER_IDS[DR] in order
        and HIGH_ADV_ROUTER in order
        and order.index(LOW_ADV_ROUTER)
        < order.index(ROUTER_IDS[DR])
        < order.index(HIGH_ADV_ROUTER)
    ), ("duplicate copies do not sort by (id, adv_router) as expected: %s" % order)

    text = _log_since(tgen, tgen.gears[OBSERVER], phase["marks"][OBSERVER])
    link_back_failures = text.count("The LSA doesn't have a link back")
    skipped = text.count("not used for the transit link")
    logger.info(
        "low-adv trigger: observer log has %d reverse-link failures, "
        "%d skipped-candidate debug lines; lsdb=%s",
        link_back_failures,
        skipped,
        _network_lsas(tgen.gears[OBSERVER]),
    )

    # The fix: the forged copy does not list the observer as attached, so
    # SPF must keep using the real DR's copy and the route must survive.
    assert _ospf_route_has(tgen.gears[OBSERVER], TARGET_IP), (
        "observer lost the OSPF route to %s after the low-adv_router "
        "duplicate was installed (reverse-link failures: %d, lsdb: %s)"
        % (TARGET_IP, link_back_failures, _network_lsas(tgen.gears[OBSERVER]))
    )
    assert _kernel_route(tgen.gears[OBSERVER], TARGET_PREFIX), (
        "observer lost the kernel route to %s after the low-adv_router "
        "duplicate was installed (reverse-link failures: %d)"
        % (TARGET_PREFIX, link_back_failures)
    )
    assert _ping(tgen.gears[OBSERVER], TARGET_IP), (
        "observer ping to %s failed after the low-adv_router duplicate "
        "was installed (reverse-link failures: %d)" % (TARGET_IP, link_back_failures)
    )
    for rname in (DR, INJECTOR):
        assert _ospf_route_has(
            tgen.gears[rname], TARGET_IP
        ), "%s lost the OSPF route to %s" % (rname, TARGET_IP)


def test_dr_maxage_fightback():
    """The real DR must MaxAge-flush the forged copies (fight-back kept)."""
    tgen = get_topogen()
    _failures(tgen)
    options = _real_network_options(tgen)
    packets = []
    expected_sequences = []
    for index in range(DR_UPDATE_COUNT):
        sequence = LOW_VALID_SEQ + 1 + index
        expected_sequences.append(sequence)
        packet = make_update(LOW_ADV_ROUTER, sequence, options)
        packet["dst_ip"] = IP_ADDRESSES[DR]
        packet["dst_mac"] = _mac(tgen.gears[DR], "%s-eth0" % DR)
        packets.append(packet)
    phase = run_phase(
        tgen,
        "dr_response",
        packets,
        tgen.gears[DR],
        spacing=DR_UPDATE_SPACING,
        tail=1.5,
    )
    assert phase["packet_path_verified"], (
        "DR response packet arrival could not be verified: %s" % phase
    )
    flush_events = [
        event
        for event in phase["capture"]["lsa_events"]
        if not event["injected"]
        and event["src"] == IP_ADDRESSES[DR]
        and event["outer_router_id"] == ROUTER_IDS[DR]
        and event["type"] == 2
        and event["id"] == NETWORK_ID
        and event["adv_router"] == LOW_ADV_ROUTER
        and event["age"] == 3600
    ]
    flushed_sequences = sorted({event["seq"] for event in flush_events})
    logger.info(
        "DR fight-back: expected seqs %s, observed MaxAge flush seqs %s",
        expected_sequences,
        flushed_sequences,
    )
    assert set(expected_sequences).issubset(
        set(flushed_sequences)
    ), "DR did not MaxAge-flush every forged copy: expected %s, observed %s" % (
        expected_sequences,
        flushed_sequences,
    )
    text = _log_since(tgen, tgen.gears[DR], phase["marks"][DR])
    maxage_logs = text.count(MAXAGE_KEY)
    assert maxage_logs >= DR_UPDATE_COUNT, "DR logged %d '%s' lines, expected >= %d" % (
        maxage_logs,
        MAXAGE_KEY,
        DR_UPDATE_COUNT,
    )


def test_recovery():
    """The forged copy is GC'd; adjacencies and the route must survive."""
    tgen = get_topogen()
    _failures(tgen)

    def _forged_gone():
        return (
            _network_lsa(tgen.gears[OBSERVER], LOW_ADV_ROUTER) is None
            and _network_lsa(tgen.gears[OBSERVER], ROUTER_IDS[DR]) is not None
        )

    assert _wait_until(_forged_gone, 180, interval_s=3), (
        "forged network-LSA copy was not garbage-collected from the "
        "observer's LSDB: %s" % _network_lsas(tgen.gears[OBSERVER])
    )
    assert (
        _neighbor_state(tgen.gears[OBSERVER], ROUTER_IDS[DR]) == "Full"
    ), "observer lost the Full adjacency to the DR"
    assert (
        _neighbor_state(tgen.gears[OBSERVER], ROUTER_IDS[INJECTOR]) == "Full"
    ), "observer lost the Full adjacency to the injector"
    for peer in (INJECTOR, OBSERVER, TARGET):
        assert _neighbor_state(tgen.gears[DR], ROUTER_IDS[peer]) == "Full", (
            "DR lost the Full adjacency to %s" % peer
        )
    for rname in ROUTERS:
        real = _network_lsa(tgen.gears[rname], ROUTER_IDS[DR])
        assert real is not None and real["age"] < 3600, (
            "real network-LSA missing or MaxAge on %s" % rname
        )
        assert _ospfd_alive(tgen.gears[rname]), "ospfd died on %s" % rname

    # Fixed ospfd never lost the route; unfixed ospfd keeps the stale
    # empty route table because MaxAge removal does not schedule an SPF.
    assert _ospf_route_has(tgen.gears[OBSERVER], TARGET_IP), (
        "observer's OSPF route to %s did not survive the duplicate "
        "network-LSA episode" % TARGET_IP
    )
    assert _kernel_route(tgen.gears[OBSERVER], TARGET_PREFIX), (
        "observer's kernel route to %s did not survive the duplicate "
        "network-LSA episode" % TARGET_PREFIX
    )
    assert _ping(tgen.gears[OBSERVER], TARGET_IP), (
        "observer ping to %s failed after the duplicate network-LSA "
        "episode" % TARGET_IP
    )
