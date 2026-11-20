#!/usr/bin/env python
# SPDX-License-Identifier: ISC

#
# test_ospf_vl_source_check.py
# Part of NetDEF Topology Tests
#

"""
test_ospf_vl_source_check.py: OSPF virtual link association must verify the
packet source address.

ospf_associate_packet_vl() associated any unicast backbone-area packet whose
OSPF Router ID matched a configured virtual-link peer.  The IP source address
was never checked, and the peer Router ID is public knowledge (it is flooded
in Router-LSAs), while virtual-link packets are routable unicast.  Any host
that could route an IP packet to the victim could therefore establish a
virtual-link adjacency from an arbitrary source address and inject arbitrary
LSAs, with the falsified adjacency spanning the whole routing domain.

RFC 2328 Section 15: the virtual neighbor's IP address is calculated from
the routing table entry for the other endpoint (i.e. from its Router-LSA in
the transit area), and OSPF packets sent over the virtual link use that
address.  The fixed code only associates a packet whose source address is
the address the virtual peer is known to use (vl_data->peer_addr, the same
address ospfd itself sends the virtual-link packets to), so the check
follows the transit path instead of pinning a hard-coded address.

Topology (mirrors the original reproducer):

            area 0.0.0.1 (transit)              area 0.0.0.0
   r1 (target) -------------- r2 (peer) -------------------- r3 (observer)
      |  10.213.13.1/24         |  10.213.13.2/24              10.213.14.2/24
      |                         |
   r1-eth1 10.213.14.1/24    r2-eth1 10.213.15.1/24
      |                         |
   (backbone to r3)          h1 (attacker) 10.213.15.2/24
                                default route via r2

The test:
  1. proves the baseline: transit and backbone adjacencies Full, the real
     virtual link Up and Full on both ends, bidirectional routed ping between
     h1 and r1, and captures the legitimate unicast VL traffic on the wire,
  2. removes the real VL on r2 and recreates it on r1, so the target VL is
     up but has no peer (no-attack control),
  3. runs the controls: a Hello with an unconfigured Router ID and a Hello
     with a corrupt checksum must both be rejected without creating a
     neighbor,
  4. attacks: h1 (routed through r2, source 10.213.15.2) runs a rogue VL
     endpoint using the real peer Router ID 13.13.13.1, drives the adjacency
     toward Full and releases one forged Type-5 LSA.  The fixed behavior:
     no Full adjacency from the wrong source, no injected LSA on r1/r3, no
     injected route,
  5. restores the real VL and verifies it re-establishes and floods LSAs
     end to end (new probe prefix on r2 reaches r3 over the VL).

Deviation from the original reproducer: the injected prefix is 10.213.99.0/24
instead of 10.213.15.0/24, because the attack-link subnet 10.213.15.0/24 is
advertised as an intra-area stub route by r2 and would mask the injected
external route.  The adjacency and LSA mechanics are identical.
"""

import json
import os
import shlex
import socket
import struct
import sys
import time

import pytest

CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

# pylint: disable=C0413
from lib import topotest
from lib.topogen import Topogen, get_topogen
from lib.topolog import logger
from scapy.contrib.ospf import OSPF_Hdr
from scapy.layers.inet import IP
from scapy.utils import rdpcap

pytestmark = [pytest.mark.ospfd]

TARGET_RID = "13.13.13.2"
PEER_RID = "13.13.13.1"
OBSERVER_RID = "13.13.13.3"
WRONG_RID = "13.13.13.254"

TARGET_IP = "10.213.13.1"
PEER_IP = "10.213.13.2"
TARGET_BACKBONE_IP = "10.213.14.1"
OBSERVER_IP = "10.213.14.2"
ATTACKER_IP = "10.213.15.2"
PEER_ATTACK_IP = "10.213.15.1"

INJECTED_PREFIX = "10.213.99.0"
INJECTED_PREFIX_LENGTH = INJECTED_PREFIX + "/24"
INJECTED_SEQUENCE = 0x80000001

PROBE_PREFIX = "10.213.0.99/32"
PROBE_HOST = "10.213.0.99"

OSPF_MSG_HELLO = 1
OSPF_MSG_DB_DESC = 2
OSPF_MSG_LS_UPDATE = 4


def build_topo(tgen):
    "Build function"
    for r in ("r1", "r2", "r3"):
        tgen.add_router(r)
    tgen.add_host("h1", ATTACKER_IP + "/24", "via " + PEER_ATTACK_IP)
    switch = tgen.add_switch("s1")
    switch.add_link(tgen.gears["r1"], nodeif="r1-eth0")
    switch.add_link(tgen.gears["r2"], nodeif="r2-eth0")
    switch = tgen.add_switch("s2")
    switch.add_link(tgen.gears["r1"], nodeif="r1-eth1")
    switch.add_link(tgen.gears["r3"], nodeif="r3-eth0")
    switch = tgen.add_switch("s3")
    switch.add_link(tgen.gears["r2"], nodeif="r2-eth1")
    switch.add_link(tgen.gears["h1"], nodeif="h1-eth0")


def setup_module(mod):
    "Sets up the pytest environment"
    tgen = Topogen(build_topo, mod.__name__)
    tgen.start_topology()
    for router in tgen.routers().values():
        router.load_frr_config()
    tgen.start_router()
    # `debug ospf event` from the config file only sets conf_debug_ospf_event
    # in this tree; IS_DEBUG_OSPF_EVENT reads term_debug_ospf_event, which
    # only the enable-node command sets.  Enable it at runtime so the VL
    # association decisions are logged.
    for name in ("r1", "r2", "r3"):
        tgen.gears[name].vtysh_cmd("debug ospf event")


def teardown_module(_mod):
    "Teardown the pytest environment"
    tgen = get_topogen()
    tgen.stop_topology()


#
# State sampling helpers
#


def daemon_json(node, command):
    return get_topogen().gears[node].vtysh_cmd(command, isjson=True)


def neighbor(node, router_id, vlink=None):
    data = daemon_json(node, "show ip ospf neighbor json")
    entries = data.get("neighbors", {}).get(router_id, [])
    if vlink is not None:
        entries = [
            entry
            for entry in entries
            if entry.get("ifaceName", "").split(":", 1)[0] == vlink
        ]
    return entries


def one_full(entries, source_ip=None):
    return bool(
        len(entries) == 1
        and entries[0].get("converged") == "Full"
        and (source_ip is None or entries[0].get("ifaceAddress") == source_ip)
    )


def vlink_name(node):
    data = daemon_json(node, "show ip ospf interface json")
    interfaces = data.get("interfaces", data)
    for name, value in interfaces.items():
        if name.startswith("VLINK") and value.get("networkType") == "VIRTUALLINK":
            return name
    return None


def vlink_snapshot(node):
    name = vlink_name(node)
    if name is None:
        return None
    data = daemon_json(node, "show ip ospf interface json")
    value = data.get("interfaces", data)[name]
    return {
        "name": name,
        "ifUp": value.get("ifUp"),
        "state": value.get("state"),
        "ipAddress": value.get("ipAddress"),
        "vlinkPeer": value.get("vlinkPeer"),
        "area": value.get("area"),
    }


def traffic(node, iface):
    data = daemon_json(node, "show ip ospf interface traffic {} json".format(iface))
    if iface not in data:
        raise RuntimeError(
            "traffic counters absent for {} on {}: {}".format(iface, node, data)
        )
    return data[iface]


def counter_delta(before, after):
    keys = (
        "helloIn",
        "helloOut",
        "dbDescIn",
        "dbDescOut",
        "lsReqIn",
        "lsReqOut",
        "lsUpdIn",
        "lsUpdOut",
        "lsAckIn",
        "lsAckOut",
    )
    return {key: after[key] - before[key] for key in keys}


def find_lsa(node, prefix=INJECTED_PREFIX):
    data = daemon_json(node, "show ip ospf database external {} json".format(prefix))

    def search(value):
        if isinstance(value, dict):
            ls_id = value.get("linkStateId", value.get("lsId"))
            adv_router = value.get("advertisingRouter", value.get("advertisedRouter"))
            sequence = value.get("lsaSeqNumber", value.get("sequenceNumber"))
            if ls_id == prefix and adv_router is not None and sequence is not None:
                return value
            for child in value.values():
                found = search(child)
                if found is not None:
                    return found
        elif isinstance(value, list):
            for child in value:
                found = search(child)
                if found is not None:
                    return found
        return None

    return search(data)


def _ospfd_log_path(node):
    return os.path.join(get_topogen().logdir, node, "ospfd.log")


def ospfd_log_offset(node):
    try:
        return os.path.getsize(_ospfd_log_path(node))
    except FileNotFoundError:
        return 0


def ospfd_log_since(node, offset):
    try:
        with open(_ospfd_log_path(node), errors="replace") as fp:
            fp.seek(offset)
            return fp.read()
    except FileNotFoundError:
        return ""


#
# Wire capture helpers
#


def _wait_until(func, timeout_s=5, interval_s=0.25):
    deadline = time.time() + timeout_s
    while time.time() < deadline:
        if func():
            return True
        time.sleep(interval_s)
    return bool(func())


def _file_ready(path):
    try:
        return os.path.exists(path) and os.path.getsize(path) > 0
    except OSError:
        return False


def _start_capture(node, iface, pcap_path, bpf):
    "Start a scapy sniffer inside the node namespace, writing to the shared rundir."
    err_path = pcap_path + ".err"
    ready_path = pcap_path + ".ready"
    gear = get_topogen().gears[node]
    gear.cmd(
        "rm -f {} {} {}".format(
            shlex.quote(pcap_path),
            shlex.quote(err_path),
            shlex.quote(ready_path),
        )
    )
    pid = gear.cmd(
        "nohup python3 {}/capture_ospf.py --iface {} --pcap {} "
        "--filter {} --ready-file {} </dev/null >{} 2>&1 & echo $!".format(
            shlex.quote(CWD),
            shlex.quote(iface),
            shlex.quote(pcap_path),
            shlex.quote(bpf),
            shlex.quote(ready_path),
            shlex.quote(err_path),
        )
    ).strip()
    if pid:
        pid = pid.splitlines()[-1]
    assert pid.isdigit(), "capture did not start on {} (pid {!r})".format(node, pid)
    assert _wait_until(
        lambda: _file_ready(ready_path)
    ), "capture did not become ready on {}: {}".format(node, err_path)
    return pid


def _stop_capture(node, pid, pcap_path):
    err_path = pcap_path + ".err"
    gear = get_topogen().gears[node]
    gear.cmd("kill -TERM {} >/dev/null 2>&1 || true".format(pid))
    assert _wait_until(
        lambda: gear.cmd("kill -0 {} 2>/dev/null; echo $?".format(pid)).strip() != "0",
        timeout_s=8,
    ), "capture on {} did not stop".format(node)
    assert _wait_until(
        lambda: _file_ready(pcap_path)
    ), "pcap {} missing after stopping capture: {}".format(pcap_path, err_path)


def _count_ospf_packets(pcap_path, src, dst, types=None):
    "Count OSPF packets in a pcap by IP src/dst and optional OSPF types."
    count = 0
    for pkt in rdpcap(pcap_path):
        if not pkt.haslayer(IP):
            continue
        if pkt[IP].src != src or pkt[IP].dst != dst:
            continue
        if pkt[IP].proto != 89:
            continue
        if types is not None:
            hdr = pkt.getlayer(OSPF_Hdr)
            if hdr is None or hdr.type not in types:
                continue
        count += 1
    return count


#
# Raw packet construction (byte-identical to the original reproducer)
#


def internet_checksum(data):
    if len(data) % 2:
        data += b"\x00"
    total = sum(struct.unpack("!{}H".format(len(data) // 2), data))
    total = (total & 0xFFFF) + (total >> 16)
    total = (total & 0xFFFF) + (total >> 16)
    return (~total) & 0xFFFF


def make_hello(router_id, corrupt=False):
    body = (
        socket.inet_aton("0.0.0.0")
        + struct.pack("!HBBI", 10, 0x02, 1, 40)
        + socket.inet_aton("0.0.0.0")
        + socket.inet_aton("0.0.0.0")
        + socket.inet_aton(TARGET_RID)
    )
    packet = bytearray(
        struct.pack(
            "!BBH4s4sHH8s",
            2,
            1,
            24 + len(body),
            socket.inet_aton(router_id),
            socket.inet_aton("0.0.0.0"),
            0,
            0,
            b"\x00" * 8,
        )
        + body
    )
    struct.pack_into("!H", packet, 12, internet_checksum(bytes(packet)))
    if corrupt:
        packet[12] ^= 1
    valid = internet_checksum(bytes(packet)) == 0
    if valid == corrupt:
        raise ValueError("incorrect generated checksum state")
    return bytes(packet)


def send_from_h1(label, payload):
    "Send one raw OSPF packet from h1 toward r1."
    out = (
        get_topogen()
        .gears["h1"]
        .cmd_raises(
            "python3 {}/send_ospf.py h1-eth0 {} {} {}".format(
                CWD, ATTACKER_IP, TARGET_IP, payload.hex()
            )
        )
    )
    assert "sent=1" in out, "{}: scapy send failed: {}".format(label, out)


#
# Baseline / phase conditions
#


def _baseline_ready():
    "None once the real VL and all physical adjacencies are Full."
    target_vlink = vlink_snapshot("r1")
    peer_vlink = vlink_snapshot("r2")
    if not (target_vlink and peer_vlink):
        return "VLINK missing on r1/r2"
    if not (target_vlink["ifUp"] and peer_vlink["ifUp"]):
        return "VLINK not up"
    if target_vlink["ipAddress"] != TARGET_IP or target_vlink["vlinkPeer"] != PEER_IP:
        return "r1 VL addressing wrong: {}".format(target_vlink)
    if peer_vlink["ipAddress"] != PEER_IP or peer_vlink["vlinkPeer"] != TARGET_IP:
        return "r2 VL addressing wrong: {}".format(peer_vlink)
    if not one_full(neighbor("r1", PEER_RID, target_vlink["name"]), PEER_IP):
        return "r1 VL neighbor not Full from {}".format(PEER_IP)
    if not one_full(neighbor("r2", TARGET_RID, peer_vlink["name"]), TARGET_IP):
        return "r2 VL neighbor not Full from {}".format(TARGET_IP)
    if not one_full(neighbor("r1", PEER_RID, "r1-eth0"), PEER_IP):
        return "r1 transit adjacency not Full"
    if not one_full(neighbor("r2", TARGET_RID, "r2-eth0"), TARGET_IP):
        return "r2 transit adjacency not Full"
    if not one_full(neighbor("r1", OBSERVER_RID, "r1-eth1")):
        return "r1 backbone adjacency not Full"
    if not one_full(neighbor("r3", TARGET_RID, "r3-eth0"), TARGET_BACKBONE_IP):
        return "r3 backbone adjacency not Full"
    return None


def _ospfd_alive(node):
    return bool(get_topogen().gears[node].cmd("pidof ospfd || true").strip())


#
# Tests
#


def test_vl_baseline():
    "Baseline: real VL Up/Full, physical adjacencies Full, routed ping, no injected LSA."
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    # Capture the VL bring-up on the wire: the legitimate peer must send
    # unicast OSPF packets from its transit-area address to the target's.
    pcap = os.path.join(tgen.logdir, "baseline_vl_r1eth0.pcap")
    pid = _start_capture("r1", "r1-eth0", pcap, "ip proto 89")
    try:
        _, result = topotest.run_and_expect(_baseline_ready, None, count=90, wait=1)
        assert result is None, "baseline VL not established: {}".format(result)

        attacker_ping = tgen.gears["h1"].cmd("ping -c 2 -W 1 {}".format(TARGET_IP))
        target_ping = tgen.gears["r1"].cmd("ping -c 2 -W 1 {}".format(ATTACKER_IP))
        assert "2 received" in attacker_ping, "h1 cannot ping r1: {}".format(
            attacker_ping
        )
        assert "2 received" in target_ping, "r1 cannot ping h1: {}".format(target_ping)

        assert find_lsa("r1") is None, "injection marker present on r1"
        assert find_lsa("r3") is None, "injection marker present on r3"
    finally:
        _stop_capture("r1", pid, pcap)

    legit = _count_ospf_packets(
        pcap,
        PEER_IP,
        TARGET_IP,
        types={OSPF_MSG_HELLO, OSPF_MSG_DB_DESC, OSPF_MSG_LS_UPDATE},
    )
    logger.info("baseline capture: %d legitimate VL packets on the wire", legit)
    assert (
        legit >= 1
    ), "no legitimate unicast VL traffic from {} to {} captured on r1-eth0".format(
        PEER_IP, TARGET_IP
    )


def test_remove_peer_vl():
    "Remove the real peer VL; the target VL comes back up with no neighbor."
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    tgen.gears["r2"].vtysh_cmd(
        "configure terminal\nrouter ospf\n"
        "no area 0.0.0.1 virtual-link {}\nend".format(TARGET_RID)
    )
    tgen.gears["r1"].vtysh_cmd(
        "configure terminal\nrouter ospf\n"
        "no area 0.0.0.1 virtual-link {0}\n"
        "area 0.0.0.1 virtual-link {0}\nend".format(PEER_RID)
    )

    def _fresh():
        vl = vlink_snapshot("r1")
        if not (
            vl
            and vl["ifUp"]
            and vl["ipAddress"] == TARGET_IP
            and vl["vlinkPeer"] == PEER_IP
        ):
            return "target VL not up correctly: {}".format(vl)
        if neighbor("r1", PEER_RID, vl["name"]):
            return "stale VL neighbor still present"
        if not one_full(neighbor("r1", PEER_RID, "r1-eth0"), PEER_IP):
            return "transit adjacency lost"
        if "area 0.0.0.1 virtual-link {}".format(TARGET_RID) in tgen.gears[
            "r2"
        ].vtysh_cmd("show running-config"):
            return "peer VL config still present"
        if "area 0.0.0.1 virtual-link {}".format(PEER_RID) not in tgen.gears[
            "r1"
        ].vtysh_cmd("show running-config"):
            return "target VL config missing"
        return None

    _, result = topotest.run_and_expect(_fresh, None, count=30, wait=1)
    assert result is None, "fresh target-only VL not established: {}".format(result)

    # No-attack control: without any injected packet the VL must stay
    # neighbor-free and the injected LSA must stay absent.
    time.sleep(2)
    vl = vlink_snapshot("r1")
    assert not neighbor(
        "r1", PEER_RID, vl["name"]
    ), "VL neighbor appeared without any attack"
    assert find_lsa("r1") is None, "injection marker appeared on r1"
    assert find_lsa("r3") is None, "injection marker appeared on r3"


def test_control_wrong_rid():
    "A Hello with an unconfigured Router ID must not be associated with the VL."
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    vl = vlink_snapshot("r1")
    assert vl, "target VL absent"
    before = traffic("r1", vl["name"])
    offset = ospfd_log_offset("r1")
    pcap = os.path.join(tgen.logdir, "control_wrong_rid.pcap")
    pid = _start_capture(
        "r1", "r1-eth0", pcap, "ip proto 89 and src host " + ATTACKER_IP
    )
    try:
        send_from_h1("wrong_rid", make_hello(WRONG_RID))
        time.sleep(1.5)
    finally:
        _stop_capture("r1", pid, pcap)

    captured = _count_ospf_packets(pcap, ATTACKER_IP, TARGET_IP)
    delta = counter_delta(before, traffic("r1", vl["name"]))
    text = ospfd_log_since("r1", offset)
    logger.info(
        "wrong-RID control: captured=%d helloIn_delta=%d", captured, delta["helloIn"]
    )
    assert captured >= 1, "wrong-RID Hello did not reach r1"
    assert delta["helloIn"] == 0, "wrong-RID Hello reached the Hello handler"
    assert not neighbor(
        "r1", WRONG_RID, vl["name"]
    ), "wrong-RID Hello created a VL neighbor"
    assert (
        "couldn't find any VL to associate the packet with" in text
    ), "wrong-RID rejection not logged"


def test_control_bad_checksum():
    "A Hello with the configured peer RID but corrupt checksum must be rejected."
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    vl = vlink_snapshot("r1")
    assert vl, "target VL absent"
    before = traffic("r1", vl["name"])
    pcap = os.path.join(tgen.logdir, "control_bad_checksum.pcap")
    pid = _start_capture(
        "r1", "r1-eth0", pcap, "ip proto 89 and src host " + ATTACKER_IP
    )
    try:
        send_from_h1("bad_checksum", make_hello(PEER_RID, corrupt=True))
        time.sleep(1.5)
    finally:
        _stop_capture("r1", pid, pcap)

    captured = _count_ospf_packets(pcap, ATTACKER_IP, TARGET_IP)
    delta = counter_delta(before, traffic("r1", vl["name"]))
    logger.info(
        "bad-checksum control: captured=%d helloIn_delta=%d",
        captured,
        delta["helloIn"],
    )
    assert captured >= 1, "corrupt-checksum Hello did not reach r1"
    assert delta["helloIn"] == 0, "corrupt-checksum Hello reached the Hello handler"
    assert not neighbor(
        "r1", PEER_RID, vl["name"]
    ), "corrupt-checksum Hello created a VL neighbor"


def test_attack_wrong_source():
    "B13: a rogue VL endpoint from a wrong source address must not come up."
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    vl = vlink_snapshot("r1")
    assert vl, "target VL absent"
    before = traffic("r1", vl["name"])
    offset = ospfd_log_offset("r1")

    trigger_path = os.path.join(tgen.logdir, "allow_lsa_injection.trigger")
    result_path = os.path.join(tgen.logdir, "rogue_capture.json")
    rogue_pcap = os.path.join(tgen.logdir, "rogue_wrong_source.pcap")
    for path in (trigger_path, result_path, rogue_pcap):
        if os.path.exists(path):
            os.unlink(path)

    helper_cfg = {
        "iface": "h1-eth0",
        "attacker_ip": ATTACKER_IP,
        "target_ip": TARGET_IP,
        "target_rid": TARGET_RID,
        "peer_rid": PEER_RID,
        "injected_prefix": INJECTED_PREFIX,
        "injected_sequence": INJECTED_SEQUENCE,
        "trigger_path": trigger_path,
        "duration": 45,
        "pcap_path": rogue_pcap,
        "result_path": result_path,
    }
    r1_pcap = os.path.join(tgen.logdir, "attack_r1eth0.pcap")
    cap_pid = _start_capture(
        "r1", "r1-eth0", r1_pcap, "ip proto 89 and src host " + ATTACKER_IP
    )
    rogue_pid = None
    try:
        rogue_out = (
            tgen.gears["h1"]
            .cmd(
                "nohup python3 {}/rogue_vl.py {} </dev/null >{} 2>&1 & echo $!".format(
                    shlex.quote(CWD),
                    shlex.quote(json.dumps(helper_cfg)),
                    shlex.quote(result_path + ".stdout"),
                )
            )
            .strip()
        )
        rogue_pid = rogue_out.splitlines()[-1] if rogue_out else ""
        assert rogue_pid.isdigit(), "rogue helper did not start: {!r}".format(rogue_out)

        # Watch the VL neighbor table while the rogue drives the state machine.
        started = time.monotonic()
        timeline = []
        last_signature = None
        full_entry = None
        while time.monotonic() - started < 20:
            entries = neighbor("r1", PEER_RID, vl["name"])
            signature = json.dumps(entries, sort_keys=True)
            if signature != last_signature:
                timeline.append(
                    {
                        "elapsed": round(time.monotonic() - started, 3),
                        "entries": entries,
                    }
                )
                last_signature = signature
            if one_full(entries, ATTACKER_IP):
                full_entry = entries[0]
                break
            time.sleep(0.25)

        # Release the forged Type-5 LSA and watch the LSDBs.
        with open(trigger_path, "w") as fp:
            fp.write("release one type-5 LSU\n")
        lsa_seen = {"r1": False, "r3": False}
        route_seen = False
        deadline = time.monotonic() + 20
        while time.monotonic() < deadline:
            for node in ("r1", "r3"):
                lsa = find_lsa(node)
                if (
                    lsa
                    and lsa.get("advertisingRouter") == PEER_RID
                    and int(lsa.get("lsaSeqNumber", "0x0"), 16) == INJECTED_SEQUENCE
                ):
                    lsa_seen[node] = True
            if INJECTED_PREFIX_LENGTH in tgen.gears["r1"].cmd(
                "ip route show {}".format(INJECTED_PREFIX_LENGTH)
            ):
                route_seen = True
            if all(lsa_seen.values()) and route_seen:
                break
            time.sleep(0.25)
    finally:
        if rogue_pid is not None:
            tgen.gears["h1"].cmd(
                "kill -TERM {} >/dev/null 2>&1 || true".format(rogue_pid)
            )
        _stop_capture("r1", cap_pid, r1_pcap)

    _wait_until(lambda: _file_ready(result_path), timeout_s=10)
    captured = _count_ospf_packets(r1_pcap, ATTACKER_IP, TARGET_IP)
    delta = counter_delta(before, traffic("r1", vl["name"]))
    attack_log = ospfd_log_since("r1", offset)
    with open(result_path) as fp:
        rogue_result = json.load(fp)

    logger.info(
        "attack evidence: rogue_packets_at_r1=%d full_entry=%s lsa_seen=%s "
        "route_seen=%s dd_complete=%s",
        captured,
        full_entry,
        lsa_seen,
        route_seen,
        rogue_result.get("dd_complete_observed"),
    )
    interesting = [
        line
        for line in attack_log.splitlines()
        if any(
            needle in line
            for needle in (
                "associating packet",
                "couldn't find any VL",
                ATTACKER_IP,
                PEER_RID,
                INJECTED_PREFIX,
            )
        )
    ]
    logger.info("target ospfd log (attack window):\n%s", "\n".join(interesting[-30:]))

    assert captured >= 1, "rogue packets did not reach r1 (attack did not happen)"
    assert (
        full_entry is None
    ), "B13: wrong-source VL adjacency reached Full from {}: {}".format(
        ATTACKER_IP, full_entry
    )
    assert not any(
        lsa_seen.values()
    ), "B13: forged Type-5 LSA installed (r1={} r3={})".format(
        lsa_seen["r1"], lsa_seen["r3"]
    )
    assert not route_seen, "B13: injected route {} installed on r1".format(
        INJECTED_PREFIX_LENGTH
    )
    assert _ospfd_alive("r1") and _ospfd_alive("r2") and _ospfd_alive("r3")


def test_vl_recovery():
    "With the real VL restored, the adjacency re-establishes and floods LSAs."
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    tgen.gears["r2"].vtysh_cmd(
        "configure terminal\nrouter ospf\n"
        "area 0.0.0.1 virtual-link {}\nend".format(TARGET_RID)
    )

    _, result = topotest.run_and_expect(_baseline_ready, None, count=60, wait=1)
    assert result is None, "real VL did not re-establish: {}".format(result)

    # Flooding over the restored VL: a new area-0 prefix on r2 must reach
    # r3's LSDB/RIB through the backbone (i.e. across the virtual link).
    tgen.gears["r2"].cmd_raises("ip addr add {} dev lo".format(PROBE_PREFIX))

    def _probe_routed():
        # `ip route show` prints host routes without the /32 suffix.
        out = tgen.gears["r3"].cmd("ip route show {}".format(PROBE_PREFIX))
        if PROBE_HOST in out:
            return None
        return "probe prefix not yet routed on r3"

    _, result = topotest.run_and_expect(_probe_routed, None, count=30, wait=1)
    assert result is None, "probe prefix not flooded over the VL: {}".format(result)

    assert _ospfd_alive("r1") and _ospfd_alive("r2") and _ospfd_alive("r3")


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
