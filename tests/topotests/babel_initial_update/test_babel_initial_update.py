#!/usr/bin/env python
# SPDX-License-Identifier: ISC

#
# test_babel_initial_update.py
#
# Copyright (c) 2026 by
# Evelyn0828
#

"""
test_babel_initial_update.py: enabling a Babel interface on a running daemon
must schedule an initial broadcast Update covering all current xroutes.

babeld's interface_recalculate() gates its initial send_update() on
``if (rc > 0)`` where rc is the return value of the immediately preceding
setsockopt(IPV6_JOIN_GROUP).  setsockopt(2) returns 0 or -1, and the error
case has already returned, so the branch is unreachable: an interface enabled
after babel_initial_noise() has run (``network <iface>`` on a running daemon)
never schedules the initial Update, and the peer only learns the prefixes at
the first periodic update one update-interval later.

Topology:

    r1-eth1 (stub 10.1.1.0/24)      r1-eth3 (stub 10.2.2.0/24)
       |                                 |
    [ r1 ] --- r1-eth0 --- sw1 --- r2-eth0 --- [ r2 ]
       |
    r1-eth2 --- sw3 --- r2-eth1

Link A (r1-eth0/r2-eth0) is enabled in the startup configuration and carries
the control prefix 10.1.1.0/24; an outbound distribute-list on r1-eth0 keeps
the trigger prefix 10.2.2.0/24 off link A.  The trigger is ``network
r1-eth2``: enabling the trigger link must promptly put an Update carrying
10.2.2.0/24 on the wire, which a packet capture on r1-eth2 asserts directly.
On the unfixed code the first Update on link B only comes with the periodic
update (update-interval 20s, i.e. no earlier than 3/4 * 20s = 15s after the
enable); the fixed code sends it within a few seconds.  Afterwards r2-eth1
is enabled as well and r2 must learn the prefix end-to-end.

Two details the test deliberately relies on:

* r2-eth1 stays disabled until the wire assertion is done.  An already
  adjacent peer would send a wildcard request as soon as the new neighbour
  association forms (its reach becomes 1100), and the daemon honours that
  request with a full route dump - on unfixed code too, whenever its main
  loop is awake - which hides the missing initial Update.

* The distribute-list on r1-eth0 is applied at runtime via vtysh, not from
  the configuration file.  A distribute-list read from the file is silently
  lost: babel_distribute_update() runs while the configuration is being
  read, before zebra has told babeld about the interface, so if_lookup_by_
  name() fails and the filter is never attached to the babel interface.
"""

import contextlib
import ipaddress
import os
import select
import sys
import time
import subprocess
import pytest
from functools import partial
from scapy.all import UDP, rdpcap

pytestmark = [pytest.mark.babeld]

CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

# pylint: disable=C0413
from lib import topotest
from lib.topogen import Topogen, TopoRouter, get_topogen
from lib.topolog import logger

PREFIX_CONTROL = "10.1.1.0/24"
PREFIX_TRIGGER = "10.2.2.0/24"

# On unfixed code the first possible re-advertisement of PREFIX_TRIGGER is
# the periodic update, due no earlier than 3/4 * 20s = 15s after the enable;
# the initial Update on fixed code is flushed within ~5s.  10s separates the
# two with margin on both sides.
RELEARN_DEADLINE = 10.0


def build_topo(tgen):
    tgen.add_router("r1")
    tgen.add_router("r2")

    # Babel link A: r1-eth0 <-> r2-eth0
    sw1 = tgen.add_switch("sw1")
    sw1.add_link(tgen.gears["r1"])
    sw1.add_link(tgen.gears["r2"])

    # Stub 1 on r1 carrying the control prefix: r1-eth1
    sw2 = tgen.add_switch("sw2")
    sw2.add_link(tgen.gears["r1"])

    # Babel link B (trigger link): r1-eth2 <-> r2-eth1
    sw3 = tgen.add_switch("sw3")
    sw3.add_link(tgen.gears["r1"])
    sw3.add_link(tgen.gears["r2"])

    # Stub 2 on r1 carrying the trigger prefix: r1-eth3
    sw4 = tgen.add_switch("sw4")
    sw4.add_link(tgen.gears["r1"])


def setup_module(module):
    tgen = Topogen(build_topo, module.__name__)
    tgen.start_topology()

    for rname, router in tgen.routers().items():
        router.load_config(
            TopoRouter.RD_ZEBRA, os.path.join(CWD, "{}/zebra.conf".format(rname))
        )
        router.load_config(
            TopoRouter.RD_BABEL, os.path.join(CWD, "{}/babeld.conf".format(rname))
        )

    tgen.start_router()


def teardown_module(_mod):
    tgen = get_topogen()
    tgen.stop_topology()


def _forwarding_nexthops(router, prefix):
    """Return the list of active forwarding nexthops for prefix on router.

    A retracted/unreachable route stays in the RIB with a reject ("unreachable")
    nexthop and no gateway, so it is not counted here.
    """
    output = router.vtysh_cmd("show ip route {} json".format(prefix), isjson=True)
    if not output or prefix not in output:
        return []
    fwd = []
    for entry in output[prefix]:
        if entry.get("protocol") != "babel":
            continue
        for nh in entry.get("nexthops", []):
            if nh.get("unreachable") or nh.get("reject") or nh.get("blackhole"):
                continue
            if nh.get("ip"):
                fwd.append(nh)
    return fwd


def _prefix_reachable(router, prefix):
    "Return None when prefix is installed via babel with a forwarding nexthop."
    if _forwarding_nexthops(router, prefix):
        return None
    return "{} is not reachable via babel on {}".format(prefix, router.name)


def _prefix_unreachable(router, prefix):
    "Return None when prefix has no babel forwarding nexthop left."
    if _forwarding_nexthops(router, prefix):
        return "{} is still reachable via babel on {}".format(prefix, router.name)
    return None


@contextlib.contextmanager
def _capture(router, ifname, pcap):
    logfile = pcap + ".log"
    with open(logfile, "w") as log:
        capture = router.popen(
            ["python3", os.path.join(CWD, "capture_babel.py"),
             "--iface", ifname, "--pcap", pcap],
            stdout=subprocess.PIPE,
            stderr=log,
            text=True,
        )
        try:
            readable, _, _ = select.select([capture.stdout], [], [], 10)
            if not readable or capture.stdout.readline().strip() != "ready":
                raise RuntimeError("Babel capture did not start; see {}".format(logfile))
            yield
        finally:
            if capture.poll() is None:
                capture.terminate()
            try:
                status = capture.wait(timeout=5)
            except subprocess.TimeoutExpired:
                capture.kill()
                capture.wait()
                raise RuntimeError("Babel capture did not stop; see {}".format(logfile))
            finally:
                capture.stdout.close()
            if status != 0:
                raise RuntimeError("Babel capture exited with {}; see {}".format(status, logfile))



def _babel_update_prefixes(payload):
    """Decode IPv4 Update TLVs, including per-packet prefix compression."""
    if len(payload) < 4 or payload[:2] != b"\x2a\x02":
        return []
    length = int.from_bytes(payload[2:4], "big")
    if length > len(payload) - 4:
        return []
    body = payload[4:4 + length]
    previous = b""
    prefixes = []
    offset = 0
    while offset < len(body):
        kind = body[offset]
        if kind == 0:
            offset += 1
            continue
        if offset + 2 > len(body):
            return []
        size = body[offset + 1]
        value = body[offset + 2:offset + 2 + size]
        if len(value) != size:
            return []
        offset += 2 + size
        if kind != 8:
            continue
        if size < 10:
            return []
        ae, flags, plen, omitted = value[:4]
        if ae != 1:
            continue
        octets = (plen + 7) // 8
        if plen > 32 or omitted > octets or size < 10 + octets - omitted:
            return []
        if omitted and not previous:
            return []
        address = (previous[:omitted] if omitted else b"") + value[10:10 + octets - omitted]
        address = address.ljust(4, b"\x00")
        if flags & 0x80:
            previous = address
        prefixes.append(str(ipaddress.IPv4Network((int.from_bytes(address, "big"), plen), strict=False)))
    return prefixes


def _capture_has_update(path, prefix):
    for packet in rdpcap(path):
        if UDP not in packet:
            continue
        udp = packet[UDP]
        if 6696 in (udp.sport, udp.dport):
            if prefix in _babel_update_prefixes(bytes(udp.payload)):
                return True
    return False


def test_converge_protocols():
    "Wait for Babel adjacency on link A between r1 and r2."
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    for rname, ifname in [("r1", "r1-eth0"), ("r2", "r2-eth0")]:
        router = tgen.gears[rname]

        def check_convergence(router=router, ifname=ifname):
            output = router.vtysh_cmd("show babel neighbor")
            if "dev {}".format(ifname) not in output:
                return "{} has no babel neighbor on {} yet".format(router.name, ifname)
            return None

        _, result = topotest.run_and_expect(check_convergence, None, count=60, wait=1)
        assert result is None, "{} failed to establish babel neighbor on {}".format(
            rname, ifname
        )


def test_route_learned_at_startup():
    "r2 must learn the control prefix 10.1.1.0/24 from r1 via Babel on link A."
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]
    r2 = tgen.gears["r2"]
    _, result = topotest.run_and_expect(
        partial(_prefix_reachable, r2, PREFIX_CONTROL), None, count=60, wait=1
    )
    assert result is None, "r2 did not learn a reachable {} via babel".format(
        PREFIX_CONTROL
    )

    # With no filter applied yet, the trigger prefix reaches r2 over link A
    # like any other redistributed prefix.  Wait until it is really there, so
    # the retraction below proves the distribute-list took effect.
    _, result = topotest.run_and_expect(
        partial(_prefix_reachable, r2, PREFIX_TRIGGER), None, count=30, wait=1
    )
    assert result is None, "r2 never learned a reachable {} via link A".format(
        PREFIX_TRIGGER
    )

    logger.info(
        "Applying outbound distribute-list denying {} on r1-eth0".format(PREFIX_TRIGGER)
    )
    r1.vtysh_cmd(
        "configure terminal\n"
        "router babel\n"
        "distribute-list prefix DENY_STUB2 out r1-eth0\n"
    )

    # The filter change retracts 10.2.2.0/24 from r2; from now on the prefix
    # must stay off link A, so anything r2 learns later came over link B.
    _, result = topotest.run_and_expect(
        partial(_prefix_unreachable, r2, PREFIX_TRIGGER), None, count=30, wait=1
    )
    assert result is None, "r2 still has a reachable {} after outbound deny".format(
        PREFIX_TRIGGER
    )


def test_initial_update_on_enable():
    """Enabling r1-eth2 must promptly put an Update carrying 10.2.2.0/24 on
    the wire, without waiting for the first periodic update; once r2-eth1 is
    enabled too, r2 must learn the prefix end-to-end."""
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]
    r2 = tgen.gears["r2"]
    _, result = topotest.run_and_expect(
        partial(_prefix_unreachable, r2, PREFIX_TRIGGER), None, count=10, wait=1
    )
    assert result is None, "r2 has a reachable {} before the trigger".format(
        PREFIX_TRIGGER
    )

    capture = os.path.join(tgen.logdir, "r1-eth2.pcap")
    with _capture(r1, "r1-eth2", capture):
        logger.info("Enabling babel on r1-eth2 (trigger link)")
        t0 = time.monotonic()
        r1.vtysh_cmd("configure terminal\nrouter babel\nnetwork r1-eth2\n")

        deadline = t0 + RELEARN_DEADLINE
        seen = False
        while time.monotonic() < deadline:
            if _capture_has_update(capture, PREFIX_TRIGGER):
                seen = True
                break
            time.sleep(0.5)
        elapsed = time.monotonic() - t0
        logger.info(
            "Update for {} on r1-eth2 after enabling r1-eth2: {} ({:.1f}s)".format(
                PREFIX_TRIGGER, "seen" if seen else "not seen", elapsed
            )
        )

        assert seen, (
            "no Update carrying {} appeared on r1-eth2 within {:.0f}s after the "
            "enable; on unfixed code the prefix only comes with the first "
            "periodic update (>= 15s, interval 20s)".format(
                PREFIX_TRIGGER, RELEARN_DEADLINE
            )
        )

        # End-to-end: with r2-eth1 enabled as well, r2 must actually install
        # the prefix.  On the fixed build the wildcard request r2 sends on the
        # new association is suppressed (r1-eth2's last_update_time is fresh),
        # so r2 may learn the prefix from the periodic update instead.
        logger.info("Enabling babel on r2-eth1")
        r2.vtysh_cmd("configure terminal\nrouter babel\nnetwork r2-eth1\n")
        _, result = topotest.run_and_expect(
            partial(_prefix_reachable, r2, PREFIX_TRIGGER), None, count=60, wait=1
        )
        assert result is None, (
            "r2 did not learn a reachable {} via babel after r2-eth1 was "
            "enabled".format(PREFIX_TRIGGER)
        )


def test_shutdown_check_stderr():
    if os.environ.get("TOPOTESTS_CHECK_STDERR") is None:
        pytest.skip("Skipping test for Stderr output and memory leaks")

    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    for router in tgen.routers().values():
        router.stop()
        for daemon in ["babeld", "zebra"]:
            log = tgen.net[router.name].getStdErr(daemon)
            if log:
                logger.error("{} {} StdErr Log:\n{}".format(router.name, daemon, log))


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
