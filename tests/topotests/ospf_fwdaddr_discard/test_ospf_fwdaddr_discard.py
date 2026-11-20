#!/usr/bin/env python
# SPDX-License-Identifier: ISC
#
# test_ospf_fwdaddr_discard.py
# Part of NetDEF Topology Tests
#

"""
test_ospf_fwdaddr_discard.py: an AS-external-LSA forwarding address must not
resolve to an area-range discard route.

RFC 2328 Section 16.4 (3): when the forwarding address is non-zero, the
matching routing table entry "must specify an intra-area or inter-area path;
if no such path exists, do nothing with the LSA and consider the next in the
list".  An ABR installs a discard route into the OSPF routing table for each
configured area range (OSPF_DESTINATION_DISCARD, cost 0, no paths).
ospf_ase_calculate_route() looked the forwarding address up with
route_node_match() but never checked the entry type, so a forwarding address
inside an area range matched the discard entry and produced an external route
with cost 0 + Y and no nexthops, displacing the legitimate external route in
the OSPF table.  zebra rejects the nexthop-less route update, so the RIB and
FIB keep the legitimate path; the bogus route is visible in the OSPF routing
table and to its consumers.

Topology (mirrors the original reproducer):

              area 0.0.0.1 (LAN, 10.210.1.0/24)
   h1 (raw injector, 10.210.1.4) ---+--- r3 (injector identity, 10.210.1.3)
                                     |
                                   r1 (ABR, 10.210.1.2)
                                     |--- area 0.0.0.0, 10.212.0.0/24 --- r2 (ASBR)
                                     |--- area 0.0.0.0, 10.211.0.0/24 --- r4 (observer)

r1 aggregates 10.210.0.0/16 out of area 0.0.0.1 and installs the discard
route.  r2 originates the legitimate Type-5 for 198.51.100.10/32 (E1, metric
50).  h1 injects a forged Type-5 for the same prefix, advertised with r3's
Router ID (r3 is a reachable ASBR in area 0.0.0.1), E1, metric 7, tag 10,
forwarding address 10.210.66.66 inside the discard range.  r3's link is
disabled before the injection so the real r3 cannot fight back; its
Router-LSA stays in the LSDB for the configured dead interval.

Checks:
  1. baseline: adjacencies Full, discard route present, legitimate Type-5
     wins on r1/r4, RIB/FIB consistent, ping works,
  2. control: Type-5 with an unreachable forwarding address outside the
     range (192.0.2.66) is installed in the LSDB but produces no route,
  3. control: Type-5 for 198.51.100.11/32 with the reachable forwarding
     address 10.212.0.1 still produces a route with proper nexthops,
  4. attack: the forged Type-5 stays in the LSDB (flooding untouched) but
     must not produce a route on r1; the legitimate route and RIB/FIB stay,
  5. r4 keeps selecting the injected route through its genuine inter-area
     path to the forwarding address (RFC 2328 16.4 (3) allows it there),
     with OSPF/RIB/FIB consistent and ping working.
"""

import json
import os
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

pytestmark = [pytest.mark.ospfd]

ABR = "r1"
ASBR = "r2"
INJECTOR = "r3"
CORE = "r4"
RAW_HOST = "h1"
ROUTERS = (ABR, ASBR, INJECTOR, CORE)

ABR_RID = "10.255.10.2"
ASBR_RID = "10.255.10.1"
INJECTOR_RID = "10.255.10.3"
CORE_RID = "10.255.10.4"

ABR_AREA1_IP = "10.210.1.2"
INJECTOR_IP = "10.210.1.3"
RAW_HOST_IP = "10.210.1.4"
ABR_ASBR_IP = "10.212.0.2"
ASBR_IP = "10.212.0.1"
ABR_AREA0_IP = "10.211.0.2"

AREA1 = "0.0.0.1"

TARGET = "198.51.100.10"
TARGET_PREFIX = TARGET + "/32"
LEGIT_TARGET = "198.51.100.11"
LEGIT_PREFIX = LEGIT_TARGET + "/32"
RANGE_PREFIX = "10.210.0.0/16"
ATTACK_FWD = "10.210.66.66"
CONTROL_FWD = "192.0.2.66"
LEGIT_FWD = ASBR_IP

LEGIT_METRIC = 50
ATTACK_METRIC = 7
ATTACK_TAG = 10
CONTROL_SEQ = 0x80001001
ATTACK_SEQ = 0x80001002


def build_topo(tgen):
    "Build function"
    for r in ROUTERS:
        tgen.add_router(r)
    tgen.add_host(RAW_HOST, RAW_HOST_IP + "/24", "via " + ABR_AREA1_IP)
    switch = tgen.add_switch("s1")
    switch.add_link(tgen.gears[ABR], nodeif=ABR + "-eth0")
    switch.add_link(tgen.gears[INJECTOR], nodeif=INJECTOR + "-eth0")
    switch.add_link(tgen.gears[RAW_HOST], nodeif=RAW_HOST + "-eth0")
    switch = tgen.add_switch("s2")
    switch.add_link(tgen.gears[ABR], nodeif=ABR + "-eth1")
    switch.add_link(tgen.gears[ASBR], nodeif=ASBR + "-eth0")
    switch = tgen.add_switch("s3")
    switch.add_link(tgen.gears[ABR], nodeif=ABR + "-eth2")
    switch.add_link(tgen.gears[CORE], nodeif=CORE + "-eth0")


def setup_module(mod):
    "Sets up the pytest environment"
    tgen = Topogen(build_topo, mod.__name__)
    tgen.start_topology()
    for router in tgen.routers().values():
        router.load_frr_config()
    tgen.start_router()


def teardown_module(_mod):
    "Teardown the pytest environment"
    tgen = get_topogen()
    tgen.stop_topology()


#
# State sampling helpers
#


def daemon_json(node, command):
    return get_topogen().gears[node].vtysh_cmd(command, isjson=True)


def neighbor_state(node, peer_rid):
    data = daemon_json(node, "show ip ospf neighbor json")
    entries = data.get("neighbors", {}).get(peer_rid, [])
    return entries[0].get("converged") if entries else None


def find_lsa(value, ls_id, adv_router):
    if isinstance(value, dict):
        if (
            value.get("linkStateId") == ls_id
            and value.get("advertisingRouter") == adv_router
            and ("lsaAge" in value or "lsaSeqNumber" in value)
        ):
            return value
        for child in value.values():
            found = find_lsa(child, ls_id, adv_router)
            if found is not None:
                return found
    elif isinstance(value, list):
        for child in value:
            found = find_lsa(child, ls_id, adv_router)
            if found is not None:
                return found
    return None


def external_lsa(node, prefix, adv_router):
    data = daemon_json(node, "show ip ospf database external {} json".format(prefix))
    return find_lsa(data, prefix, adv_router)


def router_lsa(node, rid):
    data = daemon_json(node, "show ip ospf database router {} json".format(rid))
    return find_lsa(data, rid, rid)


def injector_route_ready(node):
    "The injector's router-LSA must carry the ASBR flag and a transit link."
    lsa = router_lsa(node, INJECTOR_RID)
    if lsa is None:
        return False
    if lsa.get("asbr") is not True and not int(lsa.get("flags") or 0) & 0x02:
        return False
    links = lsa.get("routerLinks", {})
    return any(
        link.get("linkType") == "a Transit Network" for link in links.values()
    )


def injected_lsa(node, prefix=TARGET, seq=None, fwd=None):
    lsa = external_lsa(node, prefix, INJECTOR_RID)
    if lsa is None:
        return None
    if lsa.get("lsaAge") is None or int(lsa["lsaAge"]) >= 3600:
        return None
    if seq is not None:
        try:
            lsa_seq = int(str(lsa.get("lsaSeqNumber")), 16)
        except ValueError:
            return None
        if lsa_seq != seq:
            return None
    if fwd is not None and lsa.get("forwardAddress") != fwd:
        return None
    return lsa


def ospf_route(node, prefix):
    data = daemon_json(node, "show ip ospf route json")
    return data.get(prefix)


def route_cost(route):
    return (route or {}).get("cost")


def route_nexthops(route):
    return [entry.get("ip") for entry in (route or {}).get("nexthops", [])]


def rib_entries(node, prefix):
    data = daemon_json(node, "show ip route {} json".format(prefix))
    value = data.get(prefix, [])
    if isinstance(value, list):
        return value
    if isinstance(value, dict):
        return [value]
    return []


def rib_nexthop_ips(entries):
    result = []
    for entry in entries:
        for nexthop in entry.get("nexthops", []):
            if nexthop.get("ip"):
                result.append(nexthop["ip"])
    return result


def kernel_route(node, prefix):
    return get_topogen().gears[node].cmd(
        "ip route show table all {}".format(prefix)
    )


def ls_update_input():
    data = daemon_json(ABR, "show ip ospf interface traffic r1-eth0 json")
    return data["r1-eth0"]["lsUpdIn"]


def zebra_log_offset():
    path = os.path.join(get_topogen().logdir, ABR, "zebra.log")
    try:
        return os.path.getsize(path)
    except FileNotFoundError:
        return 0


def zebra_log_since(offset):
    path = os.path.join(get_topogen().logdir, ABR, "zebra.log")
    try:
        with open(path, errors="replace") as fp:
            fp.seek(offset)
            return fp.read()
    except FileNotFoundError:
        return ""


def ospfd_log_offset():
    path = os.path.join(get_topogen().logdir, ABR, "ospfd.log")
    try:
        return os.path.getsize(path)
    except FileNotFoundError:
        return 0


def ospfd_log_since(offset):
    path = os.path.join(get_topogen().logdir, ABR, "ospfd.log")
    try:
        with open(path, errors="replace") as fp:
            fp.seek(offset)
            return fp.read()
    except FileNotFoundError:
        return ""


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


def fletcher_checksum(lsa):
    data = bytearray(lsa[2:])
    data[14:16] = b"\x00\x00"
    c0 = 0
    c1 = 0
    for value in data:
        c0 = (c0 + value) % 255
        c1 = (c1 + c0) % 255
    x = ((len(data) - 14 - 1) * c0 - c1) % 255
    if x == 0:
        x = 255
    y = 510 - c0 - x
    if y > 255:
        y -= 255
    return (x << 8) | y


def make_external_lsa(target, seq, fwd):
    body = (
        socket.inet_aton("255.255.255.255")
        + bytes((0,))
        + ATTACK_METRIC.to_bytes(3, "big")
        + socket.inet_aton(fwd)
        + ATTACK_TAG.to_bytes(4, "big")
    )
    lsa = bytearray(
        struct.pack(
            "!HBB4s4sIHH",
            1,
            0x02,
            5,
            socket.inet_aton(target),
            socket.inet_aton(INJECTOR_RID),
            seq,
            0,
            36,
        )
        + body
    )
    struct.pack_into("!H", lsa, 16, fletcher_checksum(lsa))
    data = bytearray(lsa[2:])
    c0 = 0
    c1 = 0
    for value in data:
        c0 = (c0 + value) % 255
        c1 = (c1 + c0) % 255
    if (c0, c1) != (0, 0):
        raise ValueError("generated Type-5 Fletcher checksum is invalid")
    return bytes(lsa)


def make_update(target, seq, fwd):
    lsa = make_external_lsa(target, seq, fwd)
    packet = bytearray(
        struct.pack(
            "!BBH4s4sHH8sI",
            2,
            4,
            28 + len(lsa),
            socket.inet_aton(INJECTOR_RID),
            socket.inet_aton(AREA1),
            0,
            0,
            b"\x00" * 8,
            1,
        )
        + lsa
    )
    struct.pack_into("!H", packet, 12, internet_checksum(bytes(packet)))
    if internet_checksum(bytes(packet)) != 0:
        raise ValueError("generated OSPF checksum is invalid")
    return bytes(packet)


def send_update(label, target, seq, fwd):
    "Send one forged Type-5 LSU from h1 toward the ABR; return the lsUpdIn baseline."
    packet = make_update(target, seq, fwd)
    before = ls_update_input()
    out = get_topogen().gears[RAW_HOST].cmd_raises(
        "python3 {}/send_ospf.py {}-eth0 {} {} {}".format(
            CWD, RAW_HOST, INJECTOR_IP, ABR_AREA1_IP, packet.hex()
        )
    )
    assert "sent=1" in out, "{}: scapy send failed: {}".format(label, out)
    logger.info(
        "%s: sent Type-5 id=%s adv=%s seq=0x%08x fwd=%s metric=%d tag=%d",
        label,
        target,
        INJECTOR_RID,
        seq,
        fwd,
        ATTACK_METRIC,
        ATTACK_TAG,
    )
    return before


def ping(node, destination):
    return get_topogen().gears[node].cmd(
        "ping -c 2 -W 1 {}".format(destination)
    )


#
# Baseline / phase conditions
#

BASELINE = {}


def _baseline_ready():
    "None once adjacencies, the discard route and the legitimate route are in place."
    peers = {
        ABR: (ASBR_RID, INJECTOR_RID, CORE_RID),
        ASBR: (ABR_RID,),
        INJECTOR: (ABR_RID,),
        CORE: (ABR_RID,),
    }
    for name, rids in peers.items():
        for rid in rids:
            if neighbor_state(name, rid) != "Full":
                return "{} adjacency to {} not Full".format(name, rid)
    if "This router is an ABR" not in get_topogen().gears[ABR].vtysh_cmd(
        "show ip ospf"
    ):
        return "r1 does not consider itself an ABR"
    # The injector must be a reachable ASBR: its router-LSA needs the ASBR
    # flag and a transit link to the area-1 LAN.  The transit link only
    # appears once the DR election has completed and the adjacency is Full;
    # before that the LSA describes a stub link and SPF cannot reach r3.
    if not injector_route_ready(ABR):
        return "r3 router-LSA lacks ASBR flag or transit link on r1"
    discard = ospf_route(ABR, RANGE_PREFIX)
    if (discard or {}).get("routeType") != "D IA":
        return "discard route {} missing on r1: {}".format(RANGE_PREFIX, discard)
    kernel_range = kernel_route(ABR, RANGE_PREFIX)
    if not any(
        token in kernel_range for token in ("blackhole", "unreachable", "prohibit")
    ):
        return "discard route not in r1 kernel FIB: {}".format(kernel_range)
    legit = external_lsa(ABR, TARGET, ASBR_RID)
    if legit is None or int(legit.get("lsaAge", 3600)) >= 3600:
        return "legitimate Type-5 from r2 missing on r1"
    if legit.get("forwardAddress") != "0.0.0.0":
        return "legitimate Type-5 has unexpected forwarding address"
    if injected_lsa(ABR) is not None:
        return "injected Type-5 already present on r1"
    if injected_lsa(CORE) is not None:
        return "injected Type-5 already present on r4"
    abr_route = ospf_route(ABR, TARGET_PREFIX)
    if (abr_route or {}).get("routeType") != "N E1":
        return "r1 route to {} missing: {}".format(TARGET_PREFIX, abr_route)
    if route_cost(abr_route) <= LEGIT_METRIC:
        return "r1 route to {} cost {} not above {}".format(
            TARGET_PREFIX, route_cost(abr_route), LEGIT_METRIC
        )
    if ASBR_IP not in route_nexthops(abr_route):
        return "r1 route to {} not via {}: {}".format(
            TARGET_PREFIX, ASBR_IP, route_nexthops(abr_route)
        )
    core_route = ospf_route(CORE, TARGET_PREFIX)
    if (core_route or {}).get("routeType") != "N E1":
        return "r4 route to {} missing: {}".format(TARGET_PREFIX, core_route)
    if route_cost(core_route) <= LEGIT_METRIC:
        return "r4 route to {} cost {} not above {}".format(
            TARGET_PREFIX, route_cost(core_route), LEGIT_METRIC
        )
    if ABR_AREA0_IP not in route_nexthops(core_route):
        return "r4 route to {} not via {}: {}".format(
            TARGET_PREFIX, ABR_AREA0_IP, route_nexthops(core_route)
        )
    return None


#
# Tests
#


def test_baseline():
    "Baseline: adjacencies Full, discard route present, legitimate route installed."
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    _, result = topotest.run_and_expect(_baseline_ready, None, count=120, wait=1)
    assert result is None, "baseline not established: {}".format(result)

    BASELINE["abr_cost"] = route_cost(ospf_route(ABR, TARGET_PREFIX))
    BASELINE["core_cost"] = route_cost(ospf_route(CORE, TARGET_PREFIX))
    logger.info(
        "baseline OSPF costs: r1=%s r4=%s", BASELINE["abr_cost"], BASELINE["core_cost"]
    )

    rib = rib_entries(ABR, TARGET_PREFIX)
    assert ASBR_IP in rib_nexthop_ips(rib), "r1 RIB route not via r2: {}".format(rib)
    assert all(entry.get("installed") for entry in rib), "r1 RIB route not installed"
    kernel = kernel_route(ABR, TARGET_PREFIX)
    assert ASBR_IP in kernel, "r1 kernel FIB route not via r2: {}".format(kernel)

    core_rib = rib_entries(CORE, TARGET_PREFIX)
    assert ABR_AREA0_IP in rib_nexthop_ips(
        core_rib
    ), "r4 RIB route not via r1: {}".format(core_rib)
    core_kernel = kernel_route(CORE, TARGET_PREFIX)
    assert ABR_AREA0_IP in core_kernel, "r4 kernel FIB route not via r1: {}".format(
        core_kernel
    )

    for node in (ABR, CORE):
        out = ping(node, TARGET)
        assert "2 received" in out, "ping {} -> {} failed: {}".format(
            node, TARGET, out
        )


def test_isolate_injector():
    "Disable r3's link; the ABR keeps its state inside the dead interval."
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    tgen.gears[INJECTOR].link_enable(INJECTOR + "-eth0", enabled=False)
    time.sleep(2)

    assert neighbor_state(ABR, INJECTOR_RID) == "Full", "r1 lost r3 adjacency"
    assert neighbor_state(ABR, ASBR_RID) == "Full", "r1 lost r2 adjacency"
    assert neighbor_state(ABR, CORE_RID) == "Full", "r1 lost r4 adjacency"
    abr_route = ospf_route(ABR, TARGET_PREFIX)
    assert route_cost(abr_route) == BASELINE["abr_cost"], "r1 route changed on r3 isolation"
    out = ping(ABR, TARGET)
    assert "2 received" in out, "ping r1 -> {} failed after r3 isolation".format(TARGET)


def test_control_unreachable_forward_address():
    "A Type-5 whose forwarding address is outside the range must not produce a route."
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    before = send_update("unreachable-fwd control", TARGET, CONTROL_SEQ, CONTROL_FWD)

    def _installed():
        if injected_lsa(ABR, TARGET, seq=CONTROL_SEQ, fwd=CONTROL_FWD) is None:
            return "control Type-5 not in r1 LSDB"
        if ls_update_input() <= before:
            return "control LSU not counted on r1-eth0"
        return None

    _, result = topotest.run_and_expect(_installed, None, count=20, wait=0.5)
    assert result is None, "unreachable-fwd control not processed: {}".format(result)

    # Settle the incremental ASE calculation before declaring no effect.
    time.sleep(3)
    abr_route = ospf_route(ABR, TARGET_PREFIX)
    assert route_cost(abr_route) == BASELINE["abr_cost"], (
        "unreachable forwarding address changed r1 route: cost {} nexthops {}".format(
            route_cost(abr_route), route_nexthops(abr_route)
        )
    )
    assert ASBR_IP in route_nexthops(abr_route), "r1 route lost its nexthop"
    out = ping(ABR, TARGET)
    assert "2 received" in out, "ping r1 -> {} failed after control".format(TARGET)


def test_legit_forward_address_control():
    "A Type-5 with a reachable forwarding address must still produce a route."
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    send_update("reachable-fwd control", LEGIT_TARGET, CONTROL_SEQ, LEGIT_FWD)

    def _routed():
        if injected_lsa(ABR, LEGIT_TARGET, seq=CONTROL_SEQ, fwd=LEGIT_FWD) is None:
            return "reachable-fwd control Type-5 not in r1 LSDB"
        route = ospf_route(ABR, LEGIT_PREFIX)
        if (route or {}).get("routeType") != "N E1":
            return "reachable-fwd control route missing on r1: {}".format(route)
        if route_nexthops(route) != [LEGIT_FWD]:
            return "reachable-fwd control route nexthops {} != {}".format(
                route_nexthops(route), [LEGIT_FWD]
            )
        if route_cost(route) <= ATTACK_METRIC:
            return "reachable-fwd control route cost {} has no X component".format(
                route_cost(route)
            )
        return None

    _, result = topotest.run_and_expect(_routed, None, count=20, wait=0.5)
    assert result is None, "reachable-fwd control not routed: {}".format(result)

    rib = rib_entries(ABR, LEGIT_PREFIX)
    assert LEGIT_FWD in rib_nexthop_ips(rib), "control route not in r1 RIB: {}".format(
        rib
    )
    assert all(entry.get("installed") for entry in rib), "control route not installed"
    kernel = kernel_route(ABR, LEGIT_PREFIX)
    assert LEGIT_FWD in kernel, "control route not in r1 kernel FIB: {}".format(kernel)


def test_attack_discard_forward_address():
    "B10: a forwarding address resolving only to the discard route must not produce a route."
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    zebra_mark = zebra_log_offset()
    ospfd_mark = ospfd_log_offset()
    before = send_update("discard-fwd attack", TARGET, ATTACK_SEQ, ATTACK_FWD)

    def _installed():
        if injected_lsa(ABR, TARGET, seq=ATTACK_SEQ, fwd=ATTACK_FWD) is None:
            return "attack Type-5 not in r1 LSDB"
        if ls_update_input() <= before:
            return "attack LSU not counted on r1-eth0"
        return None

    _, result = topotest.run_and_expect(_installed, None, count=20, wait=0.5)
    assert result is None, "attack Type-5 not processed: {}".format(result)

    # The LSA stays in the LSDB; flooding is untouched.
    assert injected_lsa(ABR, TARGET, seq=ATTACK_SEQ, fwd=ATTACK_FWD) is not None
    assert injected_lsa(CORE, TARGET, seq=ATTACK_SEQ, fwd=ATTACK_FWD) is not None, (
        "attack Type-5 not flooded to r4"
    )

    # Let the incremental ASE calculation (1s timer) settle before reading
    # the route table, so an unfixed ospfd has already installed the bogus
    # route when the assertion runs.
    time.sleep(5)
    route = ospf_route(ABR, TARGET_PREFIX)
    assert route_cost(route) == BASELINE["abr_cost"] and route_nexthops(route) == [
        ASBR_IP
    ], (
        "B10: discard-resolved forwarding address produced a route on r1: "
        "cost {} (baseline {}) nexthops {}".format(
            route_cost(route), BASELINE["abr_cost"], route_nexthops(route)
        )
    )

    # OSPF, zebra RIB and kernel FIB stay consistent with the legitimate route.
    rib = rib_entries(ABR, TARGET_PREFIX)
    assert rib_nexthop_ips(rib) == [ASBR_IP], "r1 RIB changed: {}".format(rib)
    assert all(entry.get("installed") for entry in rib)
    kernel = kernel_route(ABR, TARGET_PREFIX)
    assert ASBR_IP in kernel, "r1 kernel FIB changed: {}".format(kernel)
    zebra_log = zebra_log_since(zebra_mark)
    assert "received a route without nexthops" not in zebra_log, (
        "zebra rejected a nexthop-less route update: {}".format(zebra_log[-400:])
    )
    ospfd_log = ospfd_log_since(ospfd_mark)
    assert "Forwarding address resolves to a discard route" in ospfd_log, (
        "ospfd did not log the discard forwarding-address skip"
    )

    out = ping(ABR, TARGET)
    assert "2 received" in out, "ping r1 -> {} failed after attack".format(TARGET)

    # r4 has a genuine inter-area path to the forwarding address, so it
    # legitimately selects the injected route; its OSPF, RIB and FIB agree.
    def _core_selected():
        route = ospf_route(CORE, TARGET_PREFIX)
        if (route or {}).get("routeType") != "N E1":
            return "r4 route missing"
        if route_nexthops(route) != [ABR_AREA0_IP]:
            return "r4 route nexthops {}".format(route_nexthops(route))
        if route_cost(route) >= BASELINE["core_cost"]:
            return "r4 did not select the injected route: cost {} baseline {}".format(
                route_cost(route), BASELINE["core_cost"]
            )
        return None

    _, result = topotest.run_and_expect(_core_selected, None, count=20, wait=0.5)
    assert result is None, "r4 injected-route state wrong: {}".format(result)
    core_rib = rib_entries(CORE, TARGET_PREFIX)
    assert ABR_AREA0_IP in rib_nexthop_ips(core_rib), "r4 RIB wrong: {}".format(
        core_rib
    )
    out = ping(CORE, TARGET)
    assert "2 received" in out, "ping r4 -> {} failed after attack".format(TARGET)


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
