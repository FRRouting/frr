#!/usr/bin/env python
# SPDX-License-Identifier: ISC

# Copyright 2026 RouteViews
# Authored by Anton Berezin <tobez@tobez.org>
#

"""
test_bgp_bmp_timestamps.py: BMP per-peer header timestamps.

    +----------+            +----------+               +----------+
    |          |            |          |               |          |
    |  bmp1ts  |------------|   r1ts   |---------------|   r2ts   |
    |          |            |          |               |          |
    +----------+            +----------+               +----------+

r1ts additionally has a configured neighbor at an unreachable address
(192.168.0.66) whose session can never establish.

Checks:

* peer-state (Peer Up/Down) messages for a peer that has never established
  since bgpd start must carry a per-peer header timestamp of 0 -- RFC 7854
  section 4.2 "time unavailable" -- not a wall-clock time fabricated from
  the peer's zero monotonic uptime (which decodes to the machine's boot
  time);
* the live Peer Up at the moment of establishment must carry the
  establish time: a real timestamp on the first establish (not 0), and
  the NEW session's establish time on a re-establish (not the previous
  session's disconnect time, which is what a stale peer uptime yields);
* a pre-policy route-monitoring message for a re-announcement of an
  already-known prefix (same prefix, changed attribute) must carry the
  reception time of the re-announcement, not the time the prefix was
  first received.
* pre-policy route-monitoring timestamps must carry genuine
  microsecond precision: the microsecond components of updates
  received seconds apart must differ, not all sit at the boot-constant
  sub-second offset that monotime_to_realtime() fabricates from a
  seconds-only monotonic timestamp.
"""

import os
import sys
import pytest
from datetime import datetime
from itertools import combinations

# Save the Current Working Directory to find configuration files.
CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join("../"))
sys.path.append(os.path.join("../lib/"))

# pylint: disable=C0413
# Import topogen and topotest helpers
from lib import topotest
from .bgpbmp import BMPSequenceContext, bmp_update_seq, get_bmp_messages
from lib.topogen import Topogen, get_topogen
from lib.topolog import logger

pytestmark = [pytest.mark.bgpd]

WATCHED_PREFIX = "203.0.113.1/32"
NEVER_ESTABLISHED_PEER = "192.168.0.66"

bmp_seq_context = BMPSequenceContext()


def build_topo(tgen):
    tgen.add_router("r1ts")
    tgen.add_router("r2ts")
    tgen.add_bmp_server("bmp1ts", ip="192.0.2.10", defaultRoute="via 192.0.2.1")

    switch = tgen.add_switch("s1")
    switch.add_link(tgen.gears["r1ts"])
    switch.add_link(tgen.gears["bmp1ts"])

    tgen.add_link(tgen.gears["r1ts"], tgen.gears["r2ts"], "r1ts-eth1", "r2ts-eth0")


def setup_module(mod):
    tgen = Topogen(build_topo, mod.__name__)
    tgen.start_topology()

    for router in tgen.routers().values():
        router.load_frr_config(
            daemons=["zebra", ("bgpd", "-M bmp")],
        )

    tgen.start_router()

    logger.info("starting BMP servers")
    for bmp_name, server in tgen.get_bmp_servers().items():
        server.start(log_file=os.path.join(tgen.logdir, bmp_name, "bmp.log"))


def teardown_module(_mod):
    tgen = get_topogen()
    tgen.stop_topology()


def _bmp_log_file():
    tgen = get_topogen()
    return os.path.join(tgen.logdir, "bmp1ts", "bmp.log")


def _parse_bmp_timestamp(value):
    """
    Parse the per-peer header timestamp string logged by the test BMP
    collector (str(datetime.fromtimestamp(...))) back into a datetime.
    """
    return datetime.fromisoformat(value)


def _route_messages(policy, bmp_log_type, prefix):
    """
    Return the new BMP route-monitoring messages (seq beyond the recorded
    baseline) matching the given policy, message type and prefix.
    """
    tgen = get_topogen()
    baseline = bmp_seq_context.get_seq()
    messages = get_bmp_messages(tgen.gears["bmp1ts"], _bmp_log_file())
    return [
        m
        for m in messages
        if m.get("seq", 0) > baseline
        and m.get("policy") == policy
        and m.get("bmp_log_type") == bmp_log_type
        and m.get("ip_prefix") == prefix
    ]


def _peer_state_messages(peer_ip, bmp_log_type, min_seq=0):
    """
    Return the peer-state messages of the given type logged for the given
    peer beyond the given sequence number, oldest first.
    """
    tgen = get_topogen()
    messages = get_bmp_messages(tgen.gears["bmp1ts"], _bmp_log_file())
    return sorted(
        (
            m
            for m in messages
            if m.get("peer_ip") == peer_ip
            and m.get("bmp_log_type") == bmp_log_type
            and m.get("seq", 0) > min_seq
        ),
        key=lambda m: m["seq"],
    )


def _never_established_peer_state_messages():
    """
    Return the peer-state (Peer Up/Down) messages logged for the neighbor
    that can never establish, oldest first.
    """
    return sorted(
        _peer_state_messages(NEVER_ESTABLISHED_PEER, "peer up")
        + _peer_state_messages(NEVER_ESTABLISHED_PEER, "peer down"),
        key=lambda m: m["seq"],
    )


def test_bmp_server_logging():
    """
    Wait for the BMP collector to start logging (session established).
    """

    def check_for_log_file():
        tgen = get_topogen()
        output = tgen.gears["bmp1ts"].run(
            "ls {}".format(os.path.join(tgen.logdir, "bmp1ts"))
        )
        return "bmp.log" in output

    success, _ = topotest.run_and_expect(check_for_log_file, True, count=30, wait=1)
    assert success, "The BMP server is not logging"


def test_peerstate_timestamp_never_established():
    """
    When the BMP session starts, bgpd dumps the state of every configured
    peer; a peer that has never established is reported with a Peer Down
    message.  Per RFC 7854 section 4.2 its per-peer header timestamp must
    be 0 ("time unavailable"), since there is no session whose reception
    time could be reported.
    """
    tgen = get_topogen()

    def _peer_state_seen():
        if _never_established_peer_state_messages():
            return True
        return "no peer-state message for {} logged yet".format(NEVER_ESTABLISHED_PEER)

    success, res = topotest.run_and_expect(_peer_state_seen, True, count=60, wait=1)
    assert success, (
        "bgpd never sent a peer-state message for the never-established "
        "neighbor {}: {}".format(NEVER_ESTABLISHED_PEER, res)
    )

    msg = _never_established_peer_state_messages()[0]
    timestamp = _parse_bmp_timestamp(msg["timestamp"])
    epoch = datetime.fromtimestamp(0)
    assert timestamp == epoch, (
        "the peer-state message (seq {}) for the never-established neighbor "
        "{} must carry timestamp 0 ('time unavailable', decoding to {}), "
        "but carries {} -- bgpd converted the peer's zero monotonic uptime "
        "to wall clock, fabricating the machine's boot time".format(
            msg["seq"], NEVER_ESTABLISHED_PEER, epoch, timestamp
        )
    )


def test_peerup_timestamp_first_establish():
    """
    Enable the r2ts neighbor (configured shut down) while the BMP session
    is already up.  The live Peer Up for the first establishment since
    bgpd start must carry the establish time.  With a stale peer uptime
    (still 0 when the peer_status_changed hook fires) the message carries
    a zero 'time unavailable' timestamp instead.
    """
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    bmp_update_seq(tgen.gears["bmp1ts"], _bmp_log_file(), bmp_seq_context)
    baseline = bmp_seq_context.get_seq()

    tgen.gears["r1ts"].vtysh_cmd(
        "configure terminal\n"
        "router bgp 65501\n"
        " no neighbor 192.168.0.2 shutdown\n"
    )

    def _established():
        out = tgen.gears["r1ts"].vtysh_cmd(
            "show bgp neighbors 192.168.0.2 json", isjson=True
        )
        state = out.get("192.168.0.2", {}).get("bgpState")
        if state == "Established":
            return True
        return "session state is {}".format(state)

    success, res = topotest.run_and_expect(_established, True, count=60, wait=1)
    assert success, "r1ts--r2ts BGP session did not establish: {}".format(res)

    def _peer_up_seen():
        if _peer_state_messages("192.168.0.2", "peer up", baseline):
            return True
        return "no live peer up for 192.168.0.2 logged yet"

    success, res = topotest.run_and_expect(_peer_up_seen, True, count=30, wait=1)
    assert (
        success
    ), "no live Peer Up for 192.168.0.2 after enabling the neighbor: " "{}".format(res)

    msg = _peer_state_messages("192.168.0.2", "peer up", baseline)[0]
    timestamp = _parse_bmp_timestamp(msg["timestamp"])
    epoch = datetime.fromtimestamp(0)
    assert timestamp != epoch, (
        "the live Peer Up (seq {}) for the first establishment of "
        "192.168.0.2 must carry the establish time, but carries the zero "
        "'time unavailable' timestamp -- peer->uptime was still 0 when "
        "the peer_status_changed hook fired".format(msg["seq"])
    )

    out = tgen.gears["r1ts"].vtysh_cmd(
        "show bgp neighbors 192.168.0.2 json", isjson=True
    )
    established_epoch = out["192.168.0.2"]["bgpTimerUpEstablishedEpoch"]
    delta = abs((timestamp - datetime.fromtimestamp(established_epoch)).total_seconds())
    assert delta <= 2.0, (
        "the live Peer Up (seq {}) timestamp {} does not match bgpd's own "
        "establish epoch {} (delta {:.1f}s)".format(
            msg["seq"],
            timestamp,
            datetime.fromtimestamp(established_epoch),
            delta,
        )
    )


def test_peerup_timestamp_reestablish():
    """
    Hard-clear the established r2ts session and let it re-establish.  The
    live Peer Up for the re-establishment must carry the NEW session's
    establish time.  With a stale peer uptime the message instead carries
    the previous session's disconnect time -- bit-identical to the Peer
    Down timestamp, since both come from the same uptime stamp written by
    bgp_stop().  The session's 5s delayopen timer guarantees the two
    events are >= 5s apart; both r1ts and r2ts run `timers delayopen
    5`, so neither side's OPEN is sent early.  A >= 2s assertion
    threshold is safe at the 1-second BMP timestamp granularity.
    """
    tgen = get_topogen()

    out = tgen.gears["r1ts"].vtysh_cmd(
        "show bgp neighbors 192.168.0.2 json", isjson=True
    )
    assert (
        out.get("192.168.0.2", {}).get("bgpState") == "Established"
    ), "test precondition: the r1ts--r2ts session must be established"
    epoch_before = out["192.168.0.2"]["bgpTimerUpEstablishedEpoch"]

    bmp_update_seq(tgen.gears["bmp1ts"], _bmp_log_file(), bmp_seq_context)
    baseline = bmp_seq_context.get_seq()

    tgen.gears["r1ts"].vtysh_cmd("clear bgp 192.168.0.2")

    def _peer_down_seen():
        if _peer_state_messages("192.168.0.2", "peer down", baseline):
            return True
        return "no peer down for 192.168.0.2 logged yet"

    success, res = topotest.run_and_expect(_peer_down_seen, True, count=30, wait=1)
    assert (
        success
    ), "no Peer Down for 192.168.0.2 after clearing the session: " "{}".format(res)
    down_msg = _peer_state_messages("192.168.0.2", "peer down", baseline)[0]
    down_timestamp = _parse_bmp_timestamp(down_msg["timestamp"])

    # Established-epoch-differs idiom (precedent:
    # bgp_evpn_rt5/test_bgp_evpn.py): plain state polling can pass before
    # the old session is torn down; the epoch only changes when a NEW
    # session establishes.
    def _reestablished():
        out = tgen.gears["r1ts"].vtysh_cmd(
            "show bgp neighbors 192.168.0.2 json", isjson=True
        )
        state = out.get("192.168.0.2", {}).get("bgpState")
        if state != "Established":
            return "session state is {}".format(state)
        if out["192.168.0.2"]["bgpTimerUpEstablishedEpoch"] == epoch_before:
            return "established epoch not changed yet"
        return True

    success, res = topotest.run_and_expect(_reestablished, True, count=60, wait=1)
    assert success, "r1ts--r2ts session did not re-establish: {}".format(res)

    def _peer_up_seen():
        if _peer_state_messages("192.168.0.2", "peer up", down_msg["seq"]):
            return True
        return "no peer up for 192.168.0.2 logged yet"

    success, res = topotest.run_and_expect(_peer_up_seen, True, count=30, wait=1)
    assert success, (
        "no live Peer Up for 192.168.0.2 after the session cleared and "
        "re-established: {}".format(res)
    )

    up_msg = _peer_state_messages("192.168.0.2", "peer up", down_msg["seq"])[0]
    up_timestamp = _parse_bmp_timestamp(up_msg["timestamp"])

    delta = (up_timestamp - down_timestamp).total_seconds()
    assert delta >= 2.0, (
        "the live Peer Up (seq {}) for the re-establishment of 192.168.0.2 "
        "must carry the new session's establish time, >= 5s after the "
        "disconnect (5s delayopen), but carries {} vs Peer Down (seq {}) "
        "at {} (delta {:.6f}s) -- peer->uptime still held the previous "
        "session's disconnect time when the peer_status_changed hook "
        "fired".format(
            up_msg["seq"],
            up_timestamp,
            down_msg["seq"],
            down_timestamp,
            delta,
        )
    )


def test_prepolicy_reannouncement_timestamp():
    """
    Announce a prefix from r2ts with a route-map attaching a community,
    record the timestamp of its pre-policy update, then change ONLY the
    route-map contents (a different community).  Route-map update
    processing runs after the route-map delay timer (5s), guaranteeing a
    measurable wall-clock gap between the two receptions, and re-advertises
    the prefix as an implicit-replace UPDATE -- no withdraw -- so r1ts
    modifies its existing Adj-RIB-In entry in place.  The new pre-policy
    update must carry the reception time of the re-announcement, not the
    frozen timestamp of the original announcement.
    """
    tgen = get_topogen()

    bmp_update_seq(tgen.gears["bmp1ts"], _bmp_log_file(), bmp_seq_context)

    # Initial announcement, community 65502:11 attached from the start.
    tgen.gears["r2ts"].vtysh_cmd(
        "configure terminal\n"
        "route-map RM-TS permit 10\n"
        " set community 65502:11\n"
        "exit\n"
        "router bgp 65502\n"
        " address-family ipv4 unicast\n"
        "  network {} route-map RM-TS\n".format(WATCHED_PREFIX)
    )

    def _first_update_seen():
        if [
            m
            for m in _route_messages("pre-policy", "update", WATCHED_PREFIX)
            if m.get("communities") == "65502:11"
        ]:
            return True
        return "initial pre-policy update not logged yet"

    success, res = topotest.run_and_expect(_first_update_seen, True, count=30, wait=1)
    assert (
        success
    ), "no pre-policy update for the initial announcement of {}: " "{}".format(
        WATCHED_PREFIX, res
    )

    first = [
        m
        for m in _route_messages("pre-policy", "update", WATCHED_PREFIX)
        if m.get("communities") == "65502:11"
    ][0]
    first_timestamp = _parse_bmp_timestamp(first["timestamp"])

    # Change only the route-map contents: r2ts re-advertises the
    # already-known prefix with the new community as an implicit-replace
    # UPDATE (no withdraw).  bgpd processes the route-map change only
    # after the route-map delay timer (pinned to 5s in the r2ts config),
    # so the re-announcement reaches r1ts >= 5 seconds after the initial
    # announcement -- a measurable wall-clock gap between the two
    # receptions.
    tgen.gears["r2ts"].vtysh_cmd(
        "configure terminal\n" "route-map RM-TS permit 10\n" " set community 65502:77\n"
    )

    def _second_update_seen():
        if [
            m
            for m in _route_messages("pre-policy", "update", WATCHED_PREFIX)
            if m["seq"] > first["seq"] and m.get("communities") == "65502:77"
        ]:
            return True
        return "re-announcement pre-policy update not logged yet"

    success, res = topotest.run_and_expect(_second_update_seen, True, count=60, wait=1)
    assert success, (
        "no pre-policy update carrying community 65502:77 for the "
        "re-announcement of {}: {}".format(WATCHED_PREFIX, res)
    )

    # Scenario self-check: the re-announcement must have modified the
    # existing Adj-RIB-In entry in place.  A pre-policy withdraw in between
    # would mean the entry was deleted and re-created (fresh timestamp even
    # under buggy code), i.e. the test would not exercise the right path.
    withdraws = _route_messages("pre-policy", "withdraw", WATCHED_PREFIX)
    assert not withdraws, (
        "test scenario broken: pre-policy withdraw(s) logged for {} "
        "between the two announcements, so the Adj-RIB-In entry was "
        "re-created instead of modified in place: {}".format(WATCHED_PREFIX, withdraws)
    )

    second = [
        m
        for m in _route_messages("pre-policy", "update", WATCHED_PREFIX)
        if m["seq"] > first["seq"] and m.get("communities") == "65502:77"
    ][0]
    second_timestamp = _parse_bmp_timestamp(second["timestamp"])

    delta = (second_timestamp - first_timestamp).total_seconds()
    assert delta >= 2.0, (
        "the pre-policy update for the re-announced {} (seq {}) must carry "
        "the re-announcement's reception time: initial update (seq {}) at "
        "{}, re-announcement at {}, delta {:.6f}s despite the 5s "
        "route-map delay-timer gap -- bgpd reused the Adj-RIB-In entry's "
        "original reception time".format(
            WATCHED_PREFIX,
            second["seq"],
            first["seq"],
            first_timestamp,
            second_timestamp,
            delta,
        )
    )


def test_prepolicy_microsecond_timestamps():
    """
    The previous subtest left WATCHED_PREFIX announced through
    route-map RM-TS (community 65502:77) and produced two pre-policy
    updates >= 5s apart.  Drive three further re-announcements by
    changing only the route-map community, each spaced by the 5s
    route-map delay timer, and collect the microsecond component of
    all five updates' timestamps.  Genuine reception times of events
    seconds apart have effectively random microseconds; the fabricated
    ones are the boot-constant CLOCK_REALTIME-CLOCK_MONOTONIC
    sub-second offset, identical (within ~20us of clock-read jitter)
    for every message.  Assert the samples spread out: maximum
    pairwise circular distance above 100us -- 5x the observed jitter
    cluster, with a ~1e-8 false-failure probability on fixed code.
    """
    tgen = get_topogen()

    # Deliberately no bmp_update_seq() here: the baseline set at the
    # start of the previous subtest keeps its two updates visible.
    def _update_with_community(community, min_seq):
        msgs = [
            m
            for m in _route_messages("pre-policy", "update", WATCHED_PREFIX)
            if m["seq"] > min_seq and m.get("communities") == community
        ]
        return msgs[0] if msgs else None

    samples = {}
    last_seq = 0

    # The two updates the previous subtest already verified.
    for community in ("65502:11", "65502:77"):
        msg = _update_with_community(community, last_seq)
        assert msg, (
            "pre-policy update with community {} from the previous "
            "subtest not found in the BMP log".format(community)
        )
        samples[community] = _parse_bmp_timestamp(msg["timestamp"]).microsecond
        last_seq = msg["seq"]

    # Three more re-announcements, each an in-place attribute change
    # spaced by the 5s route-map delay timer.
    for community in ("65502:101", "65502:102", "65502:103"):
        tgen.gears["r2ts"].vtysh_cmd(
            "configure terminal\n"
            "route-map RM-TS permit 10\n"
            " set community {}\n".format(community)
        )

        def _update_seen():
            if _update_with_community(community, last_seq):
                return True
            return "pre-policy update with community {} not logged yet".format(
                community
            )

        success, res = topotest.run_and_expect(_update_seen, True, count=60, wait=1)
        assert success, (
            "no pre-policy update carrying community {} for the "
            "re-announcement of {}: {}".format(community, WATCHED_PREFIX, res)
        )
        msg = _update_with_community(community, last_seq)
        samples[community] = _parse_bmp_timestamp(msg["timestamp"]).microsecond
        last_seq = msg["seq"]

    def _circular_distance(a, b):
        d = abs(a - b)
        return min(d, 1000000 - d)

    max_spread = max(
        _circular_distance(a, b) for a, b in combinations(samples.values(), 2)
    )
    assert max_spread > 100, (
        "the microsecond components of {} pre-policy updates received "
        "seconds apart all sit within {}us of each other ({}) -- bgpd "
        "fabricated them from the boot-constant sub-second offset "
        "between CLOCK_REALTIME and CLOCK_MONOTONIC instead of "
        "carrying the genuine reception time".format(len(samples), max_spread, samples)
    )


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
