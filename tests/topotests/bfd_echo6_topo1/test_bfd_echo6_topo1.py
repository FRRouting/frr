#!/usr/bin/env python
# SPDX-License-Identifier: ISC
#
# test_bfd_echo6_topo1.py
#
# Copyright (c) 2026 by Abdul Wasey
#

"""
test_bfd_echo6_topo1.py: IPv6 BFD echo must be sourced from the session's
local address.

r1 carries two global addresses from the same prefix on the link.  The
session local-address is marked deprecated with preferred_lft 0, so RFC
6724 rule 3 makes the kernel's default source selection pick the decoy
instead.  The address stays valid and bindable; only the default choice
moves.

bfdd reflects an IPv6 echo only when the received {source, destination}
pair maps to a known session, so echoes that go out with the decoy as
their source are dropped by r2 and r1's echo detection expires.  With the
fix in place the echo is sourced from the session local-address and the
reflection comes back.

Echo mode is enabled on both routers because bfdd opens the per-VRF IPv6
echo socket only when some session uses echo; without it r2 never reaches
the reflection path.  Only r1's echoes are asserted on, and r2's echoes
do not contribute to r1's echo input counter, which counts only packets
that reach the discriminator demux.

See FRRouting/frr#22875.
"""

import os
import sys
from functools import partial

import pytest

CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

# pylint: disable=C0413
from lib import topotest
from lib.topogen import Topogen, TopoRouter, get_topogen
from lib.topolog import logger

pytestmark = [pytest.mark.bfdd]

R1_ADDR = "2001:db8:1::1"
R1_DECOY = "2001:db8:1::5"
R2_ADDR = "2001:db8:1::2"
PREFIXLEN = 64

# Echo detection is detect-multiplier * echo transmit-interval, i.e. 300ms
# with the configuration used here.  A broken echo source takes the session
# down far inside this window.
STABILITY_SECS = 20


def build_topo(tgen):
    "Two routers on a single link."
    for routern in range(1, 3):
        tgen.add_router("r{}".format(routern))

    switch = tgen.add_switch("s1")
    switch.add_link(tgen.gears["r1"])
    switch.add_link(tgen.gears["r2"])


def _wait_dad(tgen):
    """
    Block until duplicate address detection has finished.

    A tentative address is not eligible as a source, so deprecating the
    local address has no effect until DAD has finished and both of r1's
    addresses are usable.
    """

    def _tentative():
        for rname in ("r1", "r2"):
            router = tgen.gears[rname]
            out = router.run("ip -6 addr show dev {}-eth0".format(rname))
            if "tentative" in out:
                return "{} still has a tentative address".format(rname)
        return None

    _, result = topotest.run_and_expect(_tentative, None, count=20, wait=1)
    assert result is None, result


def _restart_sessions(tgen):
    """
    Re-create the BFD sessions after the addresses are usable.

    bfdd binds the session socket to the configured local-address, and it
    starts before zebra has finished installing addresses, so the initial
    bind fails.  Bouncing the peer once the interface is settled makes the
    daemon retry against an address that now exists.
    """
    for rname, peer in (("r1", R2_ADDR), ("r2", R1_ADDR)):
        router = tgen.gears[rname]
        local = R1_ADDR if rname == "r1" else R2_ADDR
        ifname = "{}-eth0".format(rname)
        router.vtysh_cmd(
            "configure terminal\nbfd\n"
            "peer {} local-address {} interface {}\n"
            "shutdown\nno shutdown\nend".format(peer, local, ifname)
        )


def _deprecate_local(tgen):
    """
    Make the session local-address a deprecated source candidate.

    RFC 6724 rule 3 prefers non-deprecated addresses, so the kernel picks
    the decoy for anything it sends without an explicit source.  The
    address stays valid and bfdd can still bind it; it is only the default
    source selection that moves away from it, which is exactly the
    condition this test needs.
    """
    r1 = tgen.gears["r1"]
    cmd = "ip -6 addr change {}/{} dev r1-eth0 preferred_lft 0".format(
        R1_ADDR, PREFIXLEN
    )
    output = r1.run(cmd)
    logger.info("r1: {} -> {!r}".format(cmd, output))


def setup_module(mod):
    tgen = Topogen(build_topo, mod.__name__)
    tgen.start_topology()

    for rname, router in tgen.routers().items():
        router.load_config(
            TopoRouter.RD_ZEBRA, os.path.join(CWD, "{}/zebra.conf".format(rname))
        )
        router.load_config(
            TopoRouter.RD_BFD, os.path.join(CWD, "{}/bfdd.conf".format(rname))
        )

    tgen.start_router()

    _wait_dad(tgen)

    _deprecate_local(tgen)

    _restart_sessions(tgen)


def teardown_module(_mod):
    tgen = get_topogen()
    tgen.stop_topology()


def _peer_entry(entries, peer):
    for entry in entries:
        if entry.get("peer") == peer:
            return entry
    return None


def _check_peer(router, peer, expected):
    output = router.vtysh_cmd("show bfd peers json", isjson=True)
    entry = _peer_entry(output, peer)
    if entry is None:
        return "peer {} not found on {}".format(peer, router.name)
    return topotest.json_cmp(entry, expected)


def _check_echo_input(router, peer):
    output = router.vtysh_cmd("show bfd peers counters json", isjson=True)
    entry = _peer_entry(output, peer)
    if entry is None:
        return "peer {} not found on {}".format(peer, router.name)
    received = entry.get("echo-packet-input", 0)
    if received == 0:
        return "no echo packets reflected back to {}".format(router.name)
    return None


def _session_down(router, peer):
    "Cumulative down-event count for a peer, or -1 if the session is absent."
    counters = router.vtysh_cmd("show bfd peers counters json", isjson=True)
    entry = _peer_entry(counters, peer)
    assert entry is not None, "peer {} not found on {}".format(peer, router.name)
    return entry.get("session-down", 0)


def test_source_address_selection():
    """
    Precondition: the kernel must pick the decoy as the echo source.

    Without this the session would come up for the wrong reason and the test
    would pass vacuously against unfixed code.
    """
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]
    output = r1.run("ip -6 route get {}".format(R2_ADDR))
    logger.info("r1 ip -6 route get {}: {}".format(R2_ADDR, output))

    assert "src {} ".format(R1_DECOY) in output, (
        "kernel did not select {} as the source towards {}; "
        "the echo source address bug cannot be reproduced".format(R1_DECOY, R2_ADDR)
    )


def test_bfd_echo6_session_up():
    "Both ends must reach up."
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    for router, peer in ((tgen.gears["r1"], R2_ADDR), (tgen.gears["r2"], R1_ADDR)):
        test_func = partial(_check_peer, router, peer, {"status": "up"})
        _, result = topotest.run_and_expect(test_func, None, count=32, wait=1)
        assert result is None, "{} did not reach up with {}".format(router.name, peer)


def test_bfd_echo6_reflection():
    "r1 must receive its own echoes back, which means r2 reflected them."
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]
    test_func = partial(_check_echo_input, r1, R2_ADDR)
    _, result = topotest.run_and_expect(test_func, None, count=16, wait=1)
    assert result is None, (
        "r1 sent IPv6 echoes but received none back: r2 dropped them because "
        "they were not sourced from the session local address"
    )


def test_bfd_echo6_stability():
    "The session must survive echo detection."
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    pairs = ((tgen.gears["r1"], R2_ADDR), (tgen.gears["r2"], R1_ADDR))

    # A flapping session spends most of its time up, so sampling the state
    # once can miss it.  Count down events across the window instead: the
    # session is bounced during setup, so only the delta is meaningful.
    before = {router.name: _session_down(router, peer) for router, peer in pairs}

    topotest.sleep(STABILITY_SECS, "waiting for echo detection to expire or not")

    expected = {"status": "up", "diagnostic": "ok"}
    for router, peer in pairs:
        result = _check_peer(router, peer, expected)
        assert result is None, "{} lost the session with {}".format(router.name, peer)

    for router, peer in pairs:
        flaps = _session_down(router, peer) - before[router.name]
        assert flaps == 0, (
            "{} recorded {} down events with {} while idle: echo detection "
            "is expiring".format(router.name, flaps, peer)
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
