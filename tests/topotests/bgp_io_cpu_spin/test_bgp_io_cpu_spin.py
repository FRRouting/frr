#!/usr/bin/env python
# SPDX-License-Identifier: ISC

#
# test_bgp_io_cpu_spin.py
# Part of FRR Topology Tests
#

"""
test_bgp_io_cpu_spin.py:

Stress test that verifies the BGP I/O thread does not spin when the
peer input queue is full.

Before the fix in commit 1cfa5013c ("bgpd: fix I/O thread spinning
when peer input queue is full"), when a peer's input queue reached
bm->inq_limit the I/O thread entered a tight spin loop.
bgp_process_reads() unconditionally re-armed the read event even when
read_ibuf_work() returned -ENOMEM (queue full). Since the socket
remained readable, epoll fired again immediately and the cycle
repeated with no useful work done.

This test uses a raw BGP speaker (bgp_sender.py) to send 10000 routes
as fast as possible -- all UPDATE messages are pre-built and sent via
non-blocking I/O for maximum TCP throughput. Each UPDATE carries a
15-ASN AS_PATH, making the total data (~740 KB) well exceed the
ibuf_work ring buffer (~96 KB), so the socket remains readable while
the input queue is full. Without the fix, the I/O thread re-arms
reads and spins on every queue-full event, producing ~152K wasted
bgp_process_reads invocations.

r2 also applies a heavy inbound route-map (SLOW_IMPORT) that matches
against a 100-entry as-path access-list (each entry is a regex
evaluated via regexec() on the 15-ASN path string) and sets multiple
community attributes. This slows down the main thread's
bgp_process_packet() processing, keeping the input queue full longer
and amplifying spin detection.

After convergence, the test parses `show event cpu` on r2 and checks
that bgp_process_reads was invoked a reasonable number of times.

Topology:

  peer1 (raw BGP, AS 65001) ---- eBGP ---- r2 (FRR, AS 65002)
  192.168.1.1/24                             192.168.1.2/24

peer1 announces 10000 /32 routes, each in a separate UPDATE message.
r2 has `bgp input-queue-limit 100` and a heavy inbound route-map.
"""

import os
import sys
import json
import pytest
import functools

CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

# pylint: disable=C0413
from lib import topotest
from lib.topogen import Topogen, TopoRouter, get_topogen
from lib.topolog import logger

pytestmark = [pytest.mark.bgpd]

# Number of routes announced by bgp_sender.py.
# Must exceed ibuf_work capacity (~96 KB / ~74 bytes per UPDATE ≈ 1300)
# so that the TCP socket remains readable while the input queue is full.
# More routes = longer socket-readable phase = more spin accumulation.
ROUTE_COUNT = 10000

# Upper bound for bgp_process_reads invocations.
# With the fix, each invocation does useful work (read + parse + queue),
# so the call count stays roughly proportional to ROUTE_COUNT (~9K observed).
# A 3x multiplier provides headroom for legitimate overhead (keepalives,
# session setup, slow CI machines) while still catching the spin bug
# which produces ~152K calls.
MAX_READ_CALLS = ROUTE_COUNT * 3


def build_topo(tgen):
    """Create the topology: 1 FRR router + 1 host peer via 1 switch."""
    tgen.add_router("r2")
    peer1 = tgen.add_exabgp_peer(
        "peer1", ip="192.168.1.1/24", defaultRoute="via 192.168.1.2"
    )

    switch = tgen.add_switch("s1")
    switch.add_link(tgen.gears["r2"])
    switch.add_link(peer1)


def setup_module(mod):
    tgen = Topogen(build_topo, mod.__name__)
    tgen.start_topology()

    # Configure and start r2 (FRR)
    router = tgen.gears["r2"]
    router.load_config(TopoRouter.RD_ZEBRA, os.path.join(CWD, "r2/zebra.conf"))
    router.load_config(TopoRouter.RD_BGP, os.path.join(CWD, "r2/bgpd.conf"))
    router.start()

    # Start raw BGP sender on peer1 in background.
    # We use a raw BGP speaker instead of ExaBGP because it can blast
    # pre-built UPDATE messages at maximum speed via non-blocking I/O,
    # creating the TCP buffer pressure needed to trigger the spin bug.
    peer = tgen.gears["peer1"]
    sender = os.path.join(CWD, "peer1/bgp_sender.py")
    log_dir = os.path.join(peer.logdir, peer.name)
    peer.cmd("chmod 777 {}".format(log_dir))
    log_file = os.path.join(log_dir, "bgp_sender.log")
    peer.cmd(
        "python3 {} 192.168.1.2 65001 65002 {} > {} 2>&1 &".format(
            sender, ROUTE_COUNT, log_file
        )
    )
    logger.info("bgp_sender started on peer1")


def teardown_module(mod):
    tgen = get_topogen()

    # Shut down the BGP neighbor and wait for route cleanup so that
    # bgpd can free all memory before the topology is torn down.
    # Without this, --memleaks flags the 20000 routes still in the
    # deletion work queue when bgpd receives SIGTERM.
    tgen.gears["r2"].vtysh_cmd(
        "configure terminal\nrouter bgp 65002\nneighbor 192.168.1.1 shutdown"
    )

    def _check_routes_cleared():
        output = json.loads(
            tgen.gears["r2"].vtysh_cmd("show bgp ipv4 unicast summary json")
        )
        expected = {
            "peers": {
                "192.168.1.1": {
                    "pfxRcd": 0,
                }
            }
        }
        return topotest.json_cmp(output, expected)

    test_func = functools.partial(_check_routes_cleared)
    success, _ = topotest.run_and_expect(test_func, None, count=60, wait=1)
    if not success:
        logger.info("Routes did not clear before teardown")

    tgen.stop_topology()


def parse_event_cpu(output, funcname):
    """
    Parse `show event cpu` output and return the Invoked count for the
    given function name.

    The output format is:
      Active Runtime(ms) Invoked Avg_uSec Max_uSecs ...  Type  Event
         1      0.123     456      ...                    R     bgp_process_reads

    Returns the total Invoked count across all pthread sections, or 0
    if the function is not found.
    """
    total = 0
    for line in output.splitlines():
        if funcname in line:
            fields = line.split()
            if len(fields) >= 3:
                try:
                    total += int(fields[2])
                except ValueError:
                    pass
    return total


def test_bgp_convergence():
    """Verify eBGP session between peer1 and r2 reaches Established state."""
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    def _bgp_converge():
        output = json.loads(
            tgen.gears["r2"].vtysh_cmd("show bgp ipv4 unicast summary json")
        )
        expected = {
            "peers": {
                "192.168.1.1": {
                    "state": "Established",
                }
            }
        }
        return topotest.json_cmp(output, expected)

    test_func = functools.partial(_bgp_converge)
    success, result = topotest.run_and_expect(test_func, None, count=60, wait=1)
    assert success is True, "BGP session not Established on r2: {}".format(result)


def test_bgp_routes_converge():
    """
    Wait for all routes to be received on r2. This must succeed
    for the CPU spin test to be meaningful -- it proves the back-pressure
    mechanism (block reads, drain queue, re-arm) actually works.
    """
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    def _check_routes():
        output = json.loads(
            tgen.gears["r2"].vtysh_cmd("show bgp ipv4 unicast summary json")
        )
        expected = {
            "peers": {
                "192.168.1.1": {
                    "pfxRcd": ROUTE_COUNT,
                    "state": "Established",
                }
            }
        }
        return topotest.json_cmp(output, expected)

    test_func = functools.partial(_check_routes)
    success, result = topotest.run_and_expect(test_func, None, count=200, wait=1)

    if not success:
        # Dump diagnostic info
        peer = tgen.gears["peer1"]
        log_dir = os.path.join(peer.logdir, peer.name)
        log_file = os.path.join(log_dir, "bgp_sender.log")
        sender_log = peer.cmd(
            "cat {} 2>/dev/null || echo 'no log file'".format(log_file)
        )
        logger.info("bgp_sender.py log:\n%s", sender_log)

        neigh = tgen.gears["r2"].vtysh_cmd("show bgp neighbor 192.168.1.1")
        logger.info("show bgp neighbor 192.168.1.1:\n%s", neigh)

    assert success is True, "r2 did not receive all {} routes: {}".format(
        ROUTE_COUNT, result
    )


def test_bgp_io_thread_not_spinning():
    """
    After all routes have converged, check that the I/O thread did not
    spin by examining the `show event cpu` call count for
    bgp_process_reads.

    Without the fix, the I/O thread re-arms the read event even when
    the input queue is full. With input-queue-limit 100 and 10000
    individual UPDATE messages sent at maximum speed, the total data
    (~740 KB) exceeds the ibuf_work ring buffer (~96 KB). This means
    the socket remains readable while the queue is full, causing
    bgp_process_reads to be invoked ~152K times in tight spin loops
    with no useful work.

    With the fix, reads are blocked when the queue is full and only
    re-armed once the main thread drains below the limit. The call
    count stays below ROUTE_COUNT.
    """
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    # Ensure the input queue has drained so we measure the final count.
    def _check_inq_drained():
        output = json.loads(
            tgen.gears["r2"].vtysh_cmd("show bgp ipv4 unicast summary json")
        )
        expected = {
            "peers": {
                "192.168.1.1": {
                    "inq": 0,
                }
            }
        }
        return topotest.json_cmp(output, expected)

    test_func = functools.partial(_check_inq_drained)
    success, result = topotest.run_and_expect(test_func, None, count=30, wait=1)
    assert success is True, "Input queue on r2 did not drain to 0: {}".format(result)

    # Grab the event CPU stats from r2's bgpd.
    output = tgen.gears["r2"].vtysh_cmd("show event cpu R")
    logger.info("show event cpu R output:\n%s", output)

    read_calls = parse_event_cpu(output, "bgp_process_reads")
    logger.info(
        "bgp_process_reads invocations: %d (limit: %d)", read_calls, MAX_READ_CALLS
    )

    assert read_calls > 0, (
        "bgp_process_reads not found in 'show event cpu R' output; "
        "cannot verify I/O thread behavior"
    )

    assert read_calls <= MAX_READ_CALLS, (
        "bgp_process_reads invoked {} times (limit {}). "
        "This indicates the I/O thread is spinning when the input queue "
        "is full instead of blocking until the main thread drains it.".format(
            read_calls, MAX_READ_CALLS
        )
    )


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
