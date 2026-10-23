#!/usr/bin/env python
# SPDX-License-Identifier: ISC

#
# Copyright (c) 2026 by Nexthop AI
# Authored by Srinivasan Koona Lokabiraman <srinivasan@nexthop.ai>
#

"""
SendHoldTimer (RFC 9687) expiry must tear the session down.

The peer is a hand-written speaker (stalledpeer.py) that completes the
handshake and then keeps sending KEEPALIVEs without ever reading. r1 runs
bgpd with a 4 KB socket send buffer (-s 4096, plus tcp_wmem capped at 4 KB,
since bgpd raises SO_SNDBUF to its -s value) and has 10000 routes to send, so
its output stalls right after Established. With a 3 second hold time the
SendHoldTimer fires after 6 seconds without progress.

The session must then leave Established. Counting the drop alone is not
enough: a peer that is stopped without the FSM advancing stays "Established"
with no socket and no ConnectRetry timer, and never recovers.
"""

import json
import os
import shutil
import subprocess
import sys

import pytest

CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

# pylint: disable=C0413
from lib import topotest
from lib.topogen import Topogen, get_topogen
from lib.topolog import logger

pytestmark = [pytest.mark.bgpd, pytest.mark.sharpd]

PEER_NAME = "peer1"
PEER_IP = "10.0.0.2"
PEER_SCRIPT = os.path.join(CWD, "stalledpeer.py")
ROUTE_COUNT = 10000

peer_proc = None


def build_topo(tgen):
    r1 = tgen.add_router("r1")

    switch = tgen.add_switch("s1")
    switch.add_link(r1)

    peer = tgen.add_host(PEER_NAME, "%s/24" % PEER_IP, "via 10.0.0.1")
    switch.add_link(peer)


def setup_module(mod):
    tgen = Topogen(build_topo, mod.__name__)
    tgen.start_topology()

    router = tgen.gears["r1"]
    # Both limits are needed: bgpd sets SO_SNDBUF to its -s value, and the
    # kernel default would otherwise still leave room for every UPDATE.
    router.run("sysctl -w net.ipv4.tcp_wmem='4096 4096 4096'")
    router.load_frr_config(
        os.path.join(CWD, "r1/frr.conf"),
        daemons=["zebra", ("bgpd", "-s 4096"), "sharpd"],
    )
    router.start()


def teardown_module(mod):
    if peer_proc and peer_proc.poll() is None:
        peer_proc.terminate()
        try:
            peer_proc.communicate(timeout=10)
        except subprocess.TimeoutExpired:
            peer_proc.kill()

    tgen = get_topogen()
    tgen.stop_topology()

    shutil.rmtree(os.path.join(CWD, "__pycache__"), ignore_errors=True)


def _neighbor(router):
    output = json.loads(router.vtysh_cmd("show bgp neighbors %s json" % PEER_IP))
    return output.get(PEER_IP, {})


def test_routes_to_send():
    "r1 has ROUTE_COUNT routes in BGP to send to the peer."
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]
    r1.vtysh_cmd(
        "sharp install routes 172.16.0.0 nexthop 10.0.0.2 {}".format(ROUTE_COUNT)
    )

    def _rib_count():
        output = json.loads(r1.vtysh_cmd("show bgp ipv4 unicast summary json"))
        count = output.get("ipv4Unicast", output).get("ribCount", -1)
        return None if count == ROUTE_COUNT else count

    _, result = topotest.run_and_expect(_rib_count, None, count=60, wait=1)
    assert result is None, "BGP has {} routes, expected {}".format(result, ROUTE_COUNT)


def test_send_hold_timer_tears_session_down():
    "A stalled session is dropped and leaves Established."
    global peer_proc

    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]
    peer_proc = tgen.gears[PEER_NAME].popen(["python3", PEER_SCRIPT])

    def _established():
        state = _neighbor(r1).get("bgpState", "")
        return None if state == "Established" else state

    _, result = topotest.run_and_expect(_established, None, count=60, wait=1)
    assert result is None, "session never came up (state {})".format(result)

    # The SendHoldTimer firing drops the session in both the broken and the
    # fixed case, so wait for that first. Require the specific notification
    # reason too, not just any drop, so an unrelated disconnect (e.g. the
    # receive-side HoldTimer) can't satisfy this.
    def _dropped():
        neighbor = _neighbor(r1)
        dropped = neighbor.get("connectionsDropped", 0)
        reason = neighbor.get("lastNotificationReason", "")
        if dropped >= 1 and reason == "Send Hold Timer Expired":
            return None
        return "dropped={} reason={!r}".format(dropped, reason)

    _, result = topotest.run_and_expect(_dropped, None, count=60, wait=1)
    assert result is None, "the SendHoldTimer never dropped the session ({})".format(
        result
    )

    def _left_established():
        neighbor = _neighbor(r1)
        state = neighbor.get("bgpState", "")
        if not state:
            return "no bgpState in response yet"
        if state != "Established":
            return None
        return "state {}, last reset: {}".format(state, neighbor.get("lastResetDueTo"))

    _, result = topotest.run_and_expect(_left_established, None, count=15, wait=1)
    if peer_proc.poll() is not None:
        for line in peer_proc.communicate()[1].splitlines():
            logger.info(line)
    assert result is None, (
        "the session was dropped but stayed Established ({}): the peer is "
        "wedged and will never reconnect".format(result)
    )


def test_memory_leak():
    "Run the memory leak test and report results."
    tgen = get_topogen()
    if not tgen.is_memleak_enabled():
        pytest.skip("Memory leak test/report is disabled")

    tgen.report_memory_leaks()


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
