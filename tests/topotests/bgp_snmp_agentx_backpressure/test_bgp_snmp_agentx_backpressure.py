#!/usr/bin/env python
# SPDX-License-Identifier: GPL-2.0-or-later
#
# bgpd AgentX notification backpressure, observed with "show agentx status".
#
# peer1 is one ExaBGP process, started with TopoExaBGP.start() like the
# other ExaBGP topotests. exabgp_scale.py writes its config: one neighbor
# block per session. Each block has its own local-address, taken from
# 10.1.0.1 upward, and its own destination on r1, taken from 10.2.0.1
# upward. ExaBGP rejects a second block only when the peer address, local
# address, both AS numbers, and router-id are all the same, so either
# address may be shared as long as the other differs. This test varies
# both. r1 accepts the source addresses with "bgp listen range". The
# default dynamic-neighbor limit is 100, so the limit is raised to the
# session count.
#
# Both gears have 10.0.0.0/8 on the one link between them, so each
# session is directly connected eBGP. No ebgp-multihop and no
# disable-connected-check: those are for a peer that is not on the
# attached subnet.
#
# Bringing a session up queues one bgpEstablished trap, and only when the
# previous state was OpenConfirm. "clear bgp *" drops every Established
# session and queues one bgpBackwardTransition trap per session. ExaBGP
# reconnects; a SYN that arrives before the dynamic peer has been deleted
# is rejected ("not fully closed down yet") and retried, and the new
# session queues bgpEstablished again.
#
# The AgentX queue sends 16 notifications every 10 ms, so 500
# notifications leave the queue in about 320 ms. A vtysh process started
# after clear usually finds the queue empty. clear and the following
# "show agentx status json" therefore share one vtysh session: vtysh
# waits for the reply to each line before sending the next, and the show
# is sent as soon as clear's reply has been read. pendingNotifications
# is sampled while the drain is still walking the burst. The later
# sample must show pendingNotifications 0, droppedNotifications
# unchanged, and the kernel send buffer back to idle. The traps were
# handed to snmpd with send_v2trap. They were not discarded, which is
# the only other way the queue shrinks.
#
# Knobs:
#   FRR_AGENTX_BGP_NEIGHBORS   sessions to bring up (default 500). The
#                              drain window above scales with this. 500
#                              notifications take about 320 ms, which is
#                              longer than the gap between the clear reply
#                              and the next command in the same vtysh.

import ipaddress
import json
import os
import sys

import pytest

CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

# pylint: disable=C0413
from lib import exabgp_scale
from lib import topotest
from lib.topogen import Topogen, TopoRouter, get_topogen
from lib.topolog import logger

pytestmark = [pytest.mark.bgpd, pytest.mark.snmp]

NEIGHBORS = int(os.environ.get("FRR_AGENTX_BGP_NEIGHBORS", "500"))
DUT_ASN = 65001
PEER_ASN = 65002
# Shared L2 prefix. Source and destination hosts below are on-link.
LINK_PREFIXLEN = 8
DUT_ADDR = "10.0.0.1"
PEER = "peer1"
PEER_ADDR = "10.0.0.2"
# ExaBGP local-address values. This is the dynamic-neighbor listen range.
SRC_BASE = ipaddress.IPv4Address("10.1.0.1")
LISTEN_PREFIX = "10.1.0.0/16"
# ExaBGP neighbor destinations, one per session, installed on r1.
DST_BASE = ipaddress.IPv4Address("10.2.0.1")
# After snmpd is reading, this much leftover in the kernel buffer is the
# AgentX session itself. A burst of notifications leaves far more than
# this queued until snmpd has read them.
QUEUED_IDLE = 8192
# Default listen backlog is too small for every session to SYN at once.
# The neighbor GC knobs are not set: a fresh netns on this kernel has no
# /proc/sys/net/ipv4/neigh/default/gc_thresh*, and 500 ARP entries sit
# under the default gc_thresh2 of 512.
_ACCEPT_SYSCTL = "sysctl -w net.core.somaxconn=4096 net.ipv4.tcp_max_syn_backlog=4096"


def build_topo(tgen):
    r1 = tgen.add_router("r1")
    peer = tgen.add_exabgp_peer(
        PEER,
        ip="{}/{}".format(PEER_ADDR, LINK_PREFIXLEN),
        defaultRoute="via {}".format(DUT_ADDR),
    )

    switch = tgen.add_switch("s1")
    switch.add_link(r1)
    switch.add_link(peer)


def _sessions():
    "One (source, destination) pair per ExaBGP neighbor stanza."
    sources = []
    destinations = []
    for offset in range(NEIGHBORS):
        sources.append(str(SRC_BASE + offset))
        destinations.append(str(DST_BASE + offset))
    network = ipaddress.ip_network(LISTEN_PREFIX)
    outside = [src for src in sources if ipaddress.ip_address(src) not in network]
    if outside:
        raise RuntimeError(
            "{} sources fall outside {}: {}".format(
                len(outside), LISTEN_PREFIX, outside[:4]
            )
        )
    return sources, destinations


def _bgpd_conf():
    return """!
route-map RM-DYN permit 10
!
router bgp {asn}
 no bgp ebgp-requires-policy
 no bgp default ipv4-unicast
 bgp router-id {router_id}
 bgp listen limit {limit}
 neighbor DYN peer-group
 neighbor DYN remote-as {peer_asn}
 neighbor DYN timers 60 180
 no neighbor DYN capability extended-nexthop
 !
 address-family ipv4 unicast
  neighbor DYN activate
  neighbor DYN route-map RM-DYN in
  neighbor DYN route-map RM-DYN out
 exit-address-family
 bgp listen range {prefix} peer-group DYN
!
agentx
!
""".format(
        asn=DUT_ASN,
        router_id=DUT_ADDR,
        limit=NEIGHBORS,
        peer_asn=PEER_ASN,
        prefix=LISTEN_PREFIX,
    )


def _zebra_conf(iface, primary, extras):
    lines = [
        "!",
        "interface {}".format(iface),
        " ip address {}/{}".format(primary, LINK_PREFIXLEN),
    ]
    for addr in extras:
        lines.append(" ip address {}/32".format(addr))
    lines.extend(["!", ""])
    return "\n".join(lines)


def _exabgp_conf(sources, destinations):
    return "".join(
        exabgp_scale.neighbor_block(
            peer_address=dst,
            local_address=src,
            local_as=PEER_ASN,
            peer_as=DUT_ASN,
        )
        for src, dst in zip(sources, destinations)
    )


def _write(path, text):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="ascii") as handle:
        handle.write(text)
    return path


def setup_module(mod):
    if os.system("which snmpd") != 0:
        pytest.skip("SNMP not installed - skipping")
    if NEIGHBORS < 1 or NEIGHBORS > 65535:
        pytest.skip(
            "FRR_AGENTX_BGP_NEIGHBORS {} is outside bgp listen limit".format(NEIGHBORS)
        )

    sources, destinations = _sessions()
    tgen = Topogen(build_topo, mod.__name__)
    tgen.start_topology()

    r1 = tgen.gears["r1"]
    peer = tgen.gears[PEER]
    r1.load_config(
        TopoRouter.RD_ZEBRA,
        _write(
            os.path.join(tgen.logdir, "r1", "zebra.conf"),
            _zebra_conf("r1-eth0", DUT_ADDR, destinations),
        ),
    )
    r1.load_config(
        TopoRouter.RD_BGP,
        _write(os.path.join(tgen.logdir, "r1", "bgpd.conf"), _bgpd_conf()),
        "-M snmp",
    )
    r1.load_config(
        TopoRouter.RD_SNMP,
        os.path.join(CWD, "r1/snmpd.conf"),
        "-Le -Ivacm_conf,usmConf,iquery -V -DAgentX",
    )
    tgen.start_router()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    # Raise the accept queue before the sessions connect. A failure here
    # is reported and the test continues: the SYNs are then retried inside
    # the establish wait below.
    for gear in (r1, peer):
        gear.cmd(_ACCEPT_SYSCTL)

    exabgp_scale.add_addresses(peer, "{}-eth0".format(PEER), sources)
    peer.start(
        exabgp_scale.write_peer_dir(peer, _exabgp_conf(sources, destinations)),
        os.path.join(CWD, "exabgp.env"),
    )


def teardown_module(mod):
    tgen = get_topogen()
    if tgen is not None:
        tgen.stop_topology()


def _peer_counts(router):
    """Return (established, dynamic) for the IPv4 unicast summary.

    "show bgp ipv4 unicast summary json" puts peers on the top object,
    unlike "show bgp summary json", which nests them under ipv4Unicast.
    state is the FSM state. dynamicPeer is set only for a dynamic neighbor.
    """
    raw = router.vtysh_cmd("show bgp ipv4 unicast summary json")
    try:
        output = json.loads(raw)
    except json.JSONDecodeError:
        return "show bgp ipv4 unicast summary json: {}".format(raw)
    peers = output.get("peers") or {}
    established = 0
    dynamic = 0
    for peer in peers.values():
        if not isinstance(peer, dict):
            continue
        if peer.get("state") == "Established":
            established += 1
        if peer.get("dynamicPeer") is True:
            dynamic += 1
    return established, dynamic


def _agentx_bgpd(router):
    raw = router.vtysh_cmd("show agentx status json")
    try:
        output = json.loads(raw)
    except json.JSONDecodeError:
        return "show agentx status json: {}".format(raw)
    return _bgpd_status(output, raw)


def _bgpd_status(output, raw):
    """Return bgpd's AgentX object.

    vtysh wraps one object per daemon, {"bgpd": {...}}, including when
    invoked with -d bgpd. A command that reached bgpd directly already
    has pendingNotifications or moduleLoaded on the top object.
    """
    if not isinstance(output, dict):
        return "show agentx status json: {}".format(raw)
    if "pendingNotifications" in output or "moduleLoaded" in output:
        return output
    bgpd = output.get("bgpd")
    if not isinstance(bgpd, dict):
        return "bgpd missing from show agentx status: {}".format(raw)
    return bgpd


def _json_objects(text):
    """Each JSON object in a multi-command vtysh transcript.

    pretty_output prints the command line and then the daemon's reply, so
    the two "show agentx status json" lines produce two objects. A failed
    parse skips one character and tries again, so a command echo cannot
    hide the following object.
    """
    decoder = json.JSONDecoder()
    found = []
    idx = 0
    while True:
        start = text.find("{", idx)
        if start < 0:
            break
        try:
            obj, end = decoder.raw_decode(text[start:])
        except json.JSONDecodeError:
            idx = start + 1
            continue
        found.append(obj)
        idx = start + end
    return found


def _require_module(router):
    status = _agentx_bgpd(router)
    assert isinstance(status, dict), status
    assert status.get("moduleLoaded") is True, status
    assert status.get("enabled") is True, status
    return status


def _idle(status, dropped):
    "None when every trap has been sent and the master session is still up."
    if not isinstance(status, dict):
        return status
    if status.get("moduleLoaded") is not True:
        return "SNMP module not loaded: {}".format(status)
    if status.get("enabled") is not True:
        return "agentx not enabled: {}".format(status)
    if status.get("connected") is not True:
        return "master session down: {}".format(status)
    pending = status.get("pendingNotifications")
    if pending != 0:
        return "pendingNotifications {}".format(pending)
    if status.get("droppedNotifications") != dropped:
        return "droppedNotifications {} (baseline {})".format(
            status.get("droppedNotifications"), dropped
        )
    queued = status.get("socketSendQueued", 0)
    if queued > QUEUED_IDLE:
        return "socketSendQueued {} still above {}".format(queued, QUEUED_IDLE)
    return None


def _neighbors_up(r1):
    counts = _peer_counts(r1)
    if not isinstance(counts, tuple):
        return counts
    established, dynamic = counts
    if established != NEIGHBORS or dynamic != NEIGHBORS:
        return "established {} dynamic {}, want {}".format(
            established, dynamic, NEIGHBORS
        )
    return None


def test_clear_bgp_agentx_traps_sent():
    """500 dynamic neighbors, clear bgp *, traps reach snmpd."""
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]
    _require_module(r1)

    logger.info("waiting for %s dynamic neighbors to reach Established", NEIGHBORS)

    def _up():
        return _neighbors_up(r1)

    _, result = topotest.run_and_expect(_up, None, count=90, wait=1)
    assert result is None, "{}\n{}".format(
        result, exabgp_scale.log_tail(tgen.gears[PEER])
    )

    logger.info("waiting for the session-up traps to drain to snmpd")

    def _startup_drained():
        return _idle(_agentx_bgpd(r1), 0)

    _, result = topotest.run_and_expect(_startup_drained, None, count=30, wait=1)
    assert result is None, "startup traps did not drain: {}".format(result)

    baseline = _agentx_bgpd(r1)
    assert isinstance(baseline, dict), baseline
    baseline_dropped = baseline["droppedNotifications"]

    # One bgpd vtysh session, default pretty_output. vtysh sends one line
    # and waits for that reply before sending the next, so bgpd runs the
    # clear, queues one bgpBackwardTransition per Established session, and
    # the following show reads the queue while the 16-per-10ms drain is
    # in progress. -d bgpd does not query the other daemons first. The
    # second show is a second sample of the same burst.
    logger.info("clear bgp * and read show agentx status in the same session")
    output = r1.vtysh_multicmd(
        "clear bgp *\nshow agentx status json\nshow agentx status json\n",
        daemon="bgpd",
    )
    samples = []
    for obj in _json_objects(output):
        status = _bgpd_status(obj, output)
        if isinstance(status, dict):
            samples.append(status)

    logger.info(
        "show agentx status immediately after clear: %s",
        [
            {
                "pending": status.get("pendingNotifications"),
                "queued": status.get("socketSendQueued"),
                "dropped": status.get("droppedNotifications"),
                "connected": status.get("connected"),
            }
            for status in samples
        ],
    )
    assert samples, "show agentx status json missing after clear:\n{}".format(output)
    peak_pending = max(status.get("pendingNotifications", 0) for status in samples)
    for status in samples:
        assert status.get("connected") is True, status
        assert status.get("droppedNotifications") == baseline_dropped, status
    assert peak_pending > 0, (
        "clear bgp * did not leave traps queued for snmpd "
        "(pending peak {}). show agentx status output:\n{}".format(peak_pending, output)
    )

    logger.info(
        "waiting for %s queued traps to be sent and the neighbors to return",
        peak_pending,
    )

    def _settled():
        neighbor = _neighbors_up(r1)
        if neighbor is not None:
            return neighbor
        return _idle(_agentx_bgpd(r1), baseline_dropped)

    _, result = topotest.run_and_expect(_settled, None, count=90, wait=1)
    if result is not None:
        text = r1.vtysh_cmd("show agentx status")
        pytest.fail(
            "{}\n{}\n{}".format(result, text, exabgp_scale.log_tail(tgen.gears[PEER]))
        )

    done = _agentx_bgpd(r1)
    logger.info(
        "show agentx status after the burst: pending=%s dropped=%s "
        "socketSendQueued=%s connected=%s",
        done.get("pendingNotifications"),
        done.get("droppedNotifications"),
        done.get("socketSendQueued"),
        done.get("connected"),
    )
    if tgen.routers_have_failure():
        pytest.fail(tgen.errors)


def test_memory_leak():
    "Run the memory leak test and report results."
    tgen = get_topogen()
    if not tgen or not tgen.is_memleak_enabled():
        pytest.skip("Memory leak test/report is disabled")

    tgen.report_memory_leaks()


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
