#!/usr/bin/env python
# SPDX-License-Identifier: ISC
#
# test_ospf6_hello_linklocal.py
# Part of NetDEF Topology Tests
#
# Copyright (c) 2026
#

r"""
test_ospf6_hello_linklocal.py
=============================

Regression test for OSPFv3 Hello source-address validation in ospf6d.

RFC 5340 Section 2.5 requires that, on all OSPF interfaces except virtual
links, OSPF packets are sent using the interface's link-local unicast
address as the source address (on virtual links a global address MUST be
used).  ospf6d does not implement virtual links, so every Hello it
receives must have a link-local source.  Before the fix,
ospf6_hello_recv() (ospf6d/ospf6_message.c) performed no
IN6_IS_ADDR_LINKLOCAL check on the source: a Hello with a global source
address passed the area/instance/Router-ID checks in
ospf6_rxpacket_examin() and was processed like a legitimate Hello.  It
could:

  * create a neighbor whose stored "link-local" address is a global
    address (ospf6_neighbor_lladdr_set() unconditionally overwrites
    on->linklocal_addr with the packet source), which then became the
    destination of unicast Database Description packets -- with the
    victim's real neighbor sometimes receiving them and resetting the
    adjacency (SeqNumberMismatch), and
  * overwrite the stored address of an existing neighbor, and
  * feed attacker-chosen priority/DR/BDR fields into the DR election and
    LSA re-origination.

The fix drops Hello packets whose IPv6 source is not link-local before
any neighbor lookup/creation or state processing.  Legitimate
link-local Hellos (including configured point-to-point neighbors, whose
configured addresses are link-local per the CLI) are unaffected.
Virtual links need no exception here because ospf6d does not implement
them (a backbone-area packet on a transit-area interface is already
rejected with "Message may be via Virtual Link: not supported").

Topology
--------

    r1 (victim, RID 10.255.77.1, DR on the LAN)
      |
      +-- eth0 --+            +-- eth0 -- r2 (peer, RID 10.255.77.2,
      |           \          /              BDR on the LAN)
      |            +-- s1 --+
      |
      +-- eth1 -- r2          point-to-point, config-neighbors-only
      |                       (configured neighbor = peer link-local)
      |
      +-- eth2 -- r2          plain point-to-point

    eth0: 2001:db8:77::/64, hello-interval 30s, dead-interval 40s
    eth1: 2001:db8:78::/64, hello-interval 10s, dead-interval 40s
    eth2: 2001:db8:79::/64, hello-interval 10s, dead-interval 40s

All triggers are injected from r2's namespace with scapy; the IPv6
source is a global address while every other field (area, instance,
intervals, checksum) is valid.  Each injection is captured on the wire
(pcap under the test logdir); r1's receipt is cross-checked through the
per-interface helloRx counter and the ospf6d log.

Test plan
---------

1. test_adjacency_full
     Baseline: adjacency Full on all three links; r1 is DR and r2 is
     BDR on the LAN.
2. test_global_source_new_rid_rejected
     A Hello with a global source and a new Router-ID must not create a
     neighbor, must not misdeliver unicast DBDesc packets to the global
     address, and must not disturb the real adjacency.
3. test_global_source_existing_rid_ignored
     A Hello with a global source and the real peer's Router-ID must not
     rewrite the neighbor's stored link-local address.
4. test_global_source_phantom_dr_ignored
     A Hello with a global source claiming a phantom DR (priority 255,
     self-DR) must not trigger an election or LSA re-origination.
5. test_legit_linklocal_new_rid_accepted
     A Hello with a link-local source and a new Router-ID is still
     accepted and creates a neighbor (compatibility control).
6. test_p2p_global_source_rejected
     On the plain point-to-point link, a global-source Hello must not
     create a neighbor or disturb the Full adjacency.
7. test_p2p_configured_neighbor_maintained
     The config-neighbors-only point-to-point adjacency (configured
     link-local neighbor) stays Full (p2xp compatibility).
8. test_final_full_convergence
     Roles restored, adjacencies Full, daemons alive, pcaps present.

Note on the invalid-checksum control: unlike ospfd, ospf6d at this
baseline does not verify the OSPF packet header checksum on receive at
all, so a corrupted-checksum Hello is processed like a valid one; the
injected packets here therefore all carry a *correct* checksum, and the
negative controls are the global source address itself plus the
no-injection baseline.
"""

import json
import os
import re
import shlex
import sys
import time
from datetime import datetime

import pytest

from lib.topogen import Topogen, get_topogen
from lib.topolog import logger

CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

pytestmark = [pytest.mark.ospf6d]

R1 = "r1"
R2 = "r2"
LAN_IF = "eth0"
P2P_CFG_IF = "eth1"  # point-to-point, config-neighbors-only
P2P_IF = "eth2"  # plain point-to-point
R1_RID = "10.255.77.1"
R2_RID = "10.255.77.2"
NEW_RID = "10.255.77.99"  # scenario: brand-new neighbor identity
HIJACK_RID = "10.255.77.98"  # scenario: phantom DR candidate
LEGIT_RID = "10.255.77.97"  # compat control: legit link-local new neighbor
P2P_NEW_RID = "10.255.77.95"  # scenario: new identity on the plain p2p link
HIJACK_GUA = "2001:db8:77::99"  # arbitrary global source, not the peer's
HELLO_INTERVAL = 30
DEAD_INTERVAL = 40
P2P_HELLO_INTERVAL = 10
CAPTURE_TAIL = 1.0
ADJACENCY_TIMEOUT = 120

LOG_TS = re.compile(r"^(\d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2}(?:\.\d+)?)")

# Link-local addresses of the config-neighbors-only p2p link, filled in
# during setup so teardown can remove the p2xp neighbor configurations.
P2P_CFG_LL = {}


def build_topo(tgen):
    r1 = tgen.add_router(R1)
    r2 = tgen.add_router(R2)
    s1 = tgen.add_switch("s1")
    tgen.add_link(r1, s1, ifname1=LAN_IF, ifname2="eth0")
    tgen.add_link(r2, s1, ifname1=LAN_IF, ifname2="eth1")
    tgen.add_link(r1, r2, ifname1=P2P_CFG_IF, ifname2=P2P_CFG_IF)
    tgen.add_link(r1, r2, ifname1=P2P_IF, ifname2=P2P_IF)


def setup_module(mod):
    tgen = Topogen(build_topo, mod.__name__)
    tgen.start_topology()

    for router in tgen.routers().values():
        router.load_frr_config()

    tgen.start_router()

    # The config-neighbors-only point-to-point link accepts Hellos only
    # from the explicitly configured neighbor; the configured address is
    # the peer's link-local address (per the CLI), which is assigned by
    # the kernel when the interface comes up, so configure it here.
    r1 = tgen.gears[R1]
    r2 = tgen.gears[R2]
    r1_ll = _linklocal(r1, P2P_CFG_IF)
    r2_ll = _linklocal(r2, P2P_CFG_IF)
    P2P_CFG_LL[R1] = r1_ll
    P2P_CFG_LL[R2] = r2_ll
    r1.vtysh_cmd(
        "configure terminal\ninterface %s\n"
        "ipv6 ospf6 p2p-p2mp config-neighbors-only\n"
        "ipv6 ospf6 neighbor %s\nend" % (P2P_CFG_IF, r2_ll)
    )
    r2.vtysh_cmd(
        "configure terminal\ninterface %s\n"
        "ipv6 ospf6 p2p-p2mp config-neighbors-only\n"
        "ipv6 ospf6 neighbor %s\nend" % (P2P_CFG_IF, r1_ll)
    )


def teardown_module():
    tgen = get_topogen()
    # Remove the p2xp configured neighbors before shutdown: ospf6d does
    # not free the p2xp neighbor config when the interface is deleted
    # (ospf6_interface_delete), so leaving it configured would be
    # reported as a memory leak by the post-shutdown check.  This is a
    # pre-existing ospf6d issue, unrelated to the Hello source check.
    for rname, peer_ll in ((R1, P2P_CFG_LL.get(R2)), (R2, P2P_CFG_LL.get(R1))):
        if not peer_ll:
            continue
        router = tgen.gears[rname]
        router.cmd(
            "vtysh -c 'configure terminal' -c 'interface %s' "
            "-c 'no ipv6 ospf6 neighbor %s' "
            "-c 'no ipv6 ospf6 p2p-p2mp config-neighbors-only' -c 'end'"
            % (P2P_CFG_IF, peer_ll)
        )
    tgen.stop_topology()


def _wait_until(func, timeout=15, interval=0.5):
    deadline = time.time() + timeout
    while time.time() < deadline:
        value = func()
        if value:
            return value
        time.sleep(interval)
    return func()


def _vty_json(router, command):
    return json.loads(router.vtysh_cmd(command))


def _interface_info(router, ifname):
    data = _vty_json(router, "show ipv6 ospf6 interface %s json" % ifname)
    return data.get(ifname, {})


def _neighbor_detail(router):
    """Map (router-id, ifname) -> neighbor detail record."""
    data = _vty_json(router, "show ipv6 ospf6 neighbor detail json")
    result = {}
    for key, value in data.items():
        rid, _, ifname = key.partition("%")
        result[(rid, ifname)] = value
    return result


def _neighbor_state(router, rid, ifname):
    record = _neighbor_detail(router).get((rid, ifname))
    if record is None:
        return None
    return record.get("neighborState")


def _neighbor_lladdr(router, rid, ifname):
    record = _neighbor_detail(router).get((rid, ifname))
    if record is None:
        return None
    return record.get("linkLocalAddress")


def _neighbor_full(router, rid, ifname):
    return str(_neighbor_state(router, rid, ifname) or "").startswith("Full")


def _hello_rx(router, ifname):
    data = _vty_json(router, "show ipv6 ospf6 interface traffic %s json" % ifname)
    return data[ifname]["helloRx"]


def _router_lsa_seq(router):
    data = _vty_json(router, "show ipv6 ospf6 database router self-originated json")
    found = []

    def walk(value):
        if isinstance(value, dict):
            if value.get("advRouter") == R1_RID and "seqNum" in value:
                found.append(value)
            for child in value.values():
                walk(child)
        elif isinstance(value, list):
            for child in value:
                walk(child)

    walk(data)
    if not found:
        raise RuntimeError("r1 router-LSA not found: %s" % data)
    return int(found[0]["seqNum"])


def _iface_mac(node, ifname):
    return node.cmd("cat /sys/class/net/%s/address" % ifname).strip()


def _iface_ifindex(node, ifname):
    return int(node.cmd("cat /sys/class/net/%s/ifindex" % ifname).strip())


def _linklocal(node, ifname):
    out = node.cmd("ip -6 addr show dev %s scope link" % ifname)
    for line in out.splitlines():
        line = line.strip()
        if line.startswith("inet6 "):
            return line.split()[1].split("/")[0]
    raise RuntimeError("no link-local on %s/%s: %s" % (node.name, ifname, out))


def _ospf6d_pid(router):
    return router.cmd("pidof ospf6d || true").strip()


def _log_offset(router):
    path = os.path.join(router.gearlogdir, "ospf6d.out")
    try:
        return os.path.getsize(path)
    except OSError:
        return 0


def _log_since(router, offset):
    path = os.path.join(router.gearlogdir, "ospf6d.out")
    try:
        with open(path, errors="replace") as logf:
            logf.seek(offset)
            return logf.read()
    except OSError:
        return ""


def _interesting_log(text):
    tokens = (
        "NeighborChange",
        "AdjOK",
        "state change",
        "Originate Router-LSA",
        "Originate Network-LSA",
        "non-link-local",
        "SeqNumberMismatch",
    )
    return [line for line in text.splitlines() if any(t in line for t in tokens)]


def _inject(r2, r1, label, ifname, src_ip, packet_rid, priority, dr, bdr,
            count, spacing, tail, hello_interval, dead_interval):
    """Send forged Hellos from r2 and prove they hit the wire.

    Returns the phase dict with the send/capture evidence, r1's
    helloRx delta and the ospf6d log delta for this injection.
    """
    tgen = get_topogen()
    pcap = os.path.join(tgen.logdir, "%s.pcap" % label)
    r2.cmd("rm -f %s" % shlex.quote(pcap))
    hello_before = _hello_rx(r1, ifname)
    offset = _log_offset(r1)
    cmd = (
        "python3 %s/send_hello.py --iface %s --src-mac %s --src-ip %s "
        "--dst-mac %s --dst-ip %s --packet-rid %s --ifindex %d "
        "--neighbors %s --priority %d --dr %s --bdr %s "
        "--hello-interval %d --dead-interval %d "
        "--count %d --spacing %s --tail %s --pcap %s"
        % (
            shlex.quote(CWD),
            shlex.quote(ifname),
            shlex.quote(_iface_mac(r2, ifname)),
            shlex.quote(src_ip),
            shlex.quote(_iface_mac(r1, ifname)),
            shlex.quote(_linklocal(r1, ifname)),
            shlex.quote(packet_rid),
            _iface_ifindex(r2, ifname),
            shlex.quote(R1_RID),
            priority,
            shlex.quote(dr),
            shlex.quote(bdr),
            hello_interval,
            dead_interval,
            count,
            spacing,
            tail,
            shlex.quote(pcap),
        )
    )
    out = r2.cmd_raises(cmd)
    markers = [line for line in out.splitlines() if line.startswith("O6_SEND_JSON=")]
    assert markers, "send_hello.py returned no result for %s: %s" % (label, out)
    send = json.loads(markers[-1].split("=", 1)[1])
    assert send["captured_matching"] == len(
        send["sent"]
    ), "forged Hellos %s were not all captured on the wire: %s" % (label, send)
    hello_delta = _hello_rx(r1, ifname) - hello_before
    log = _log_since(r1, offset)
    phase = {
        "label": label,
        "send": send,
        "hello_in_delta": hello_delta,
        "log": log,
        "interesting_log": _interesting_log(log),
    }
    logger.info(
        "injected %s: packets=%d captured=%d hello_in_delta=%d",
        label,
        len(send["sent"]),
        send["captured_matching"],
        hello_delta,
    )
    for line in phase["interesting_log"][-12:]:
        logger.info("r1 ospf6d: %s", line)
    return phase


def _count_events(text):
    lines = text.splitlines()
    elections = sum(
        "Interface Event" in line and "[NeighborChange]" in line for line in lines
    )
    adjok = sum("*AdjOK?*" in line for line in lines)
    state_changes = sum(
        "Interface state change" in line and (" %s:" % LAN_IF) in line
        for line in lines
    )
    router_refresh = sum("Originate Router-LSA for Area" in line for line in lines)
    network_events = sum(
        ("Originate Network-LSA for Interface %s" % LAN_IF) in line
        for line in lines
    )
    return {
        "elections": elections,
        "adjok": adjok,
        "state_changes": state_changes,
        "router_refresh": router_refresh,
        "network_events": network_events,
    }


def _receipt_verified(phase, count):
    """Prove r1 actually received the injected Hellos.

    On the unpatched build the per-interface helloRx counter advances
    (the Hello reaches neighbor processing).  On the fixed build the
    packet is dropped before that counter, but the new ospf6d log line
    "Hello from non-link-local source ... dropped" records the receipt
    and rejection.  Either proves the trigger reached the daemon.
    """
    if phase["hello_in_delta"] >= count:
        return True
    return any("non-link-local" in line for line in phase["interesting_log"])


def _wait_roles(r1, r1_dr=True, timeout=30):
    def check():
        iface = _interface_info(r1, LAN_IF)
        if r1_dr:
            return (
                iface.get("ospf6InterfaceState") == "DR"
                and iface.get("dr") == R1_RID
                and _neighbor_full(r1, R2_RID, LAN_IF)
            )
        return iface.get("ospf6InterfaceState") != "DR" and iface.get("dr") == R2_RID

    return bool(_wait_until(check, timeout=timeout, interval=0.2))


def _expect_baseline():
    tgen = get_topogen()
    r1 = tgen.gears[R1]
    r2 = tgen.gears[R2]
    assert _wait_roles(
        r1, r1_dr=True, timeout=ADJACENCY_TIMEOUT
    ), "baseline DR/Full not reached: %s" % _interface_info(r1, LAN_IF)
    assert _neighbor_full(r2, R1_RID, LAN_IF), "r2 does not see r1 Full"
    assert _neighbor_full(
        r1, R2_RID, P2P_CFG_IF
    ), "p2p config-neighbors-only adjacency not Full"
    assert _neighbor_full(
        r1, R2_RID, P2P_IF
    ), "plain p2p adjacency not Full"


def test_adjacency_full():
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)
    _expect_baseline()


def test_global_source_new_rid_rejected():
    """A Hello with a global source and a new Router-ID must not create a
    neighbor, must not misdeliver unicast DBDesc packets to the global
    address, and must not disturb the real adjacency."""
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)
    _expect_baseline()
    r1 = tgen.gears[R1]
    r2 = tgen.gears[R2]
    peer_ll = _linklocal(r2, LAN_IF)
    r2_gua = "2001:db8:77::2"
    seq_before = _router_lsa_seq(r1)
    phase = _inject(
        r2, r1, "global_src_new_rid", LAN_IF,
        r2_gua, NEW_RID, 1, R1_RID, R2_RID,
        2, 1.0, CAPTURE_TAIL, HELLO_INTERVAL, DEAD_INTERVAL,
    )
    assert _receipt_verified(
        phase, 2
    ), "global-source Hello was captured on the wire but r1 receipt not verified: %s" % (
        phase["send"],
    )
    assert _neighbor_state(
        r1, NEW_RID, LAN_IF
    ) is None, "global-source Hello created a neighbor: %s" % _neighbor_detail(r1)
    assert not any(
        "SeqNumberMismatch" in line for line in phase["interesting_log"]
    ), "global-source Hello reset the real adjacency: %s" % phase["interesting_log"]
    assert _neighbor_full(
        r1, R2_RID, LAN_IF
    ), "real adjacency disturbed by global-source Hello"
    assert _neighbor_lladdr(r1, R2_RID, LAN_IF) == peer_ll
    assert _router_lsa_seq(r1) == seq_before, "router-LSA sequence moved"


def test_global_source_existing_rid_ignored():
    """A Hello with a global source and the real peer's Router-ID must not
    rewrite the neighbor's stored link-local address."""
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)
    _expect_baseline()
    r1 = tgen.gears[R1]
    r2 = tgen.gears[R2]
    peer_ll = _linklocal(r2, LAN_IF)
    phase = _inject(
        r2, r1, "global_src_existing_rid", LAN_IF,
        HIJACK_GUA, R2_RID, 100, R1_RID, R2_RID,
        2, 1.0, CAPTURE_TAIL, HELLO_INTERVAL, DEAD_INTERVAL,
    )
    assert _receipt_verified(phase, 2), "r1 receipt not verified: %s" % phase["send"]
    assert (
        _neighbor_lladdr(r1, R2_RID, LAN_IF) == peer_ll
    ), "neighbor address rewritten by global-source Hello: %s" % _neighbor_lladdr(
        r1, R2_RID, LAN_IF
    )
    assert _neighbor_full(r1, R2_RID, LAN_IF), "real adjacency disturbed"


def test_global_source_phantom_dr_ignored():
    """A Hello with a global source claiming a phantom DR (priority 255,
    self-DR) must not trigger an election or LSA re-origination."""
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)
    _expect_baseline()
    r1 = tgen.gears[R1]
    r2 = tgen.gears[R2]
    seq_before = _router_lsa_seq(r1)
    phase = _inject(
        r2, r1, "global_src_phantom_dr", LAN_IF,
        "2001:db8:77::2", HIJACK_RID, 255, HIJACK_RID, "0.0.0.0",
        2, 1.0, CAPTURE_TAIL, HELLO_INTERVAL, DEAD_INTERVAL,
    )
    assert _receipt_verified(phase, 2), "r1 receipt not verified: %s" % phase["send"]
    events = _count_events(phase["log"])
    assert events["elections"] == 0, (
        "global-source phantom DR Hello triggered an election: %s"
        % phase["interesting_log"]
    )
    assert events["router_refresh"] == 0, "router-LSA re-originated: %s" % (
        phase["interesting_log"],
    )
    assert _neighbor_state(
        r1, HIJACK_RID, LAN_IF
    ) is None, "phantom DR neighbor created: %s" % _neighbor_detail(r1)
    assert _router_lsa_seq(r1) == seq_before, "router-LSA sequence moved"
    assert _wait_roles(r1, r1_dr=True, timeout=30), "roles changed"


def test_legit_linklocal_new_rid_accepted():
    """A Hello with a link-local source and a new Router-ID is still
    accepted and creates a neighbor (compatibility control)."""
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)
    _expect_baseline()
    r1 = tgen.gears[R1]
    r2 = tgen.gears[R2]
    peer_ll = _linklocal(r2, LAN_IF)
    phase = _inject(
        r2, r1, "legit_linklocal_new_rid", LAN_IF,
        peer_ll, LEGIT_RID, 1, R1_RID, R2_RID,
        1, 1.0, CAPTURE_TAIL, HELLO_INTERVAL, DEAD_INTERVAL,
    )
    assert _receipt_verified(phase, 1), "r1 receipt not verified: %s" % phase["send"]

    def created():
        state = _neighbor_state(r1, LEGIT_RID, LAN_IF)
        return state in ("Twoway", "ExStart", "ExChange", "Loading", "Full")

    assert _wait_until(created, timeout=10, interval=0.5), (
        "legitimate link-local Hello did not create a neighbor: %s"
        % _neighbor_detail(r1)
    )
    assert (
        _neighbor_lladdr(r1, LEGIT_RID, LAN_IF) == peer_ll
    ), "legitimate neighbor address wrong: %s" % _neighbor_lladdr(
        r1, LEGIT_RID, LAN_IF
    )


def test_p2p_global_source_rejected():
    """On the plain point-to-point link, a global-source Hello must not
    create a neighbor or disturb the Full adjacency."""
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)
    _expect_baseline()
    r1 = tgen.gears[R1]
    r2 = tgen.gears[R2]
    peer_ll = _linklocal(r2, P2P_IF)
    phase = _inject(
        r2, r1, "p2p_global_src_new_rid", P2P_IF,
        "2001:db8:79::2", P2P_NEW_RID, 1, "0.0.0.0", "0.0.0.0",
        2, 1.0, CAPTURE_TAIL, P2P_HELLO_INTERVAL, DEAD_INTERVAL,
    )
    assert _receipt_verified(phase, 2), "r1 receipt not verified: %s" % phase["send"]
    assert _neighbor_state(
        r1, P2P_NEW_RID, P2P_IF
    ) is None, "global-source Hello created a p2p neighbor: %s" % _neighbor_detail(r1)
    assert not any(
        "SeqNumberMismatch" in line for line in phase["interesting_log"]
    ), "global-source Hello reset the p2p adjacency: %s" % phase["interesting_log"]
    assert _neighbor_full(
        r1, R2_RID, P2P_IF
    ), "plain p2p adjacency disturbed by global-source Hello"
    assert _neighbor_lladdr(r1, R2_RID, P2P_IF) == peer_ll


def test_p2p_configured_neighbor_maintained():
    """The config-neighbors-only point-to-point adjacency (configured
    link-local neighbor) stays Full (p2xp compatibility)."""
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)
    _expect_baseline()
    r1 = tgen.gears[R1]
    r2 = tgen.gears[R2]
    assert _neighbor_full(
        r1, R2_RID, P2P_CFG_IF
    ), "config-neighbors-only p2p adjacency not Full"
    assert _neighbor_full(
        r2, R1_RID, P2P_CFG_IF
    ), "config-neighbors-only p2p adjacency not Full on r2"


def test_final_full_convergence():
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)
    _expect_baseline()
    r1 = tgen.gears[R1]
    r2 = tgen.gears[R2]
    assert _ospf6d_pid(r1), "ospf6d not running on r1"
    assert _ospf6d_pid(r2), "ospf6d not running on r2"
    pcaps = [name for name in os.listdir(tgen.logdir) if name.endswith(".pcap")]
    assert "global_src_new_rid.pcap" in pcaps, "pcap evidence missing: %s" % pcaps
    assert "p2p_global_src_new_rid.pcap" in pcaps, "pcap evidence missing: %s" % pcaps
