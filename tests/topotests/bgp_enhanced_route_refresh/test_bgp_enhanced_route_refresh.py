#!/usr/bin/env python
# SPDX-License-Identifier: ISC
#
# Copyright (c) 2026 NVIDIA Corporation
#               Rajasekar Raja
#

"""
Enhanced route refresh (RFC 7313) over one session carrying IPv4 and IPv6.

r2 asks r1 for a refresh, and r1 answers each address family with a BoRR,
its routes and an EoRR. The markers must not make r2 send anything back,
and each address family must be tracked on its own when both are refreshed
at the same time.

Which markers were ignored or rejected is not visible in any show command,
so the second test reads r2's bgpd.log, written under
`debug bgp neighbor-events`.
"""

import functools
import os
import sys
import time

import pytest

CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

# pylint: disable=C0413
from lib import topotest
from lib.topogen import Topogen, get_topogen
from lib.topolog import logger

pytestmark = [pytest.mark.bgpd]

R1 = "192.168.1.1"


def build_topo(tgen):
    for rname in ["r1", "r2"]:
        tgen.add_router(rname)

    switch = tgen.add_switch("s1")
    switch.add_link(tgen.gears["r1"])
    switch.add_link(tgen.gears["r2"])


def setup_module(mod):
    tgen = Topogen(build_topo, mod.__name__)
    tgen.start_topology()

    for rname, router in tgen.routers().items():
        router.load_frr_config(os.path.join(CWD, "{}/frr.conf".format(rname)))

    tgen.start_router()


def teardown_module(mod):
    tgen = get_topogen()
    tgen.stop_topology()


def _stats_towards_r1(r2):
    output = r2.vtysh_cmd("show bgp neighbor {} json".format(R1), isjson=True)
    return output[R1]["messageStats"]


def _r2_log(tgen):
    with open(os.path.join(tgen.logdir, "r2", "bgpd.log")) as logfile:
        return logfile.read()


def _wait_updates_settled(r2):
    last = [None]

    def _check():
        sent = _stats_towards_r1(r2)["updatesSent"]
        settled = sent == last[0]
        last[0] = sent
        return settled

    success, _ = topotest.run_and_expect(_check, True, count=30, wait=1)
    assert success, "r2 kept sending UPDATEs to r1"
    return last[0]


def _wait_refresh_received(r2, count):
    def _check():
        received = _stats_towards_r1(r2)["routeRefreshRecv"]
        if received < count:
            return "{} route-refresh messages received, want {}".format(received, count)
        return None

    _, result = topotest.run_and_expect(_check, None, count=30, wait=1)
    assert result is None, result


def _check_markers_logged(tgen, log_start, expected):
    """None once every expected line, or a rejected marker, is logged."""
    lines = _r2_log(tgen)[log_start:].splitlines()
    if any("whereas" in line for line in lines):
        return None
    missing = [text for text in expected if not any(text in line for line in lines)]
    if missing:
        return "missing from r2's bgpd.log: {}".format(missing)
    return None


def test_bgp_converge():
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    peer_prefixes = {
        "r1": {"ipv4": "10.0.0.2/32", "ipv6": "2001:db8::2/128"},
        "r2": {"ipv4": "10.0.0.1/32", "ipv6": "2001:db8::1/128"},
    }

    for rname, prefixes in peer_prefixes.items():
        router = tgen.gears[rname]
        for family, prefix in prefixes.items():
            expected = {"routes": {prefix: [{"valid": True}]}}
            test_func = functools.partial(
                topotest.router_json_cmp,
                router,
                "show bgp {} unicast json".format(family),
                expected,
            )
            _, result = topotest.run_and_expect(test_func, None, count=30, wait=1)
            assert result is None, "{} did not learn {}".format(rname, prefix)


def test_bgp_markers_do_not_trigger_updates():
    """
    A soft inbound clear only asks r1 to re-send its routes. r1's BoRR and
    EoRR must not make r2 send its own routes back to r1.
    """
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r2 = tgen.gears["r2"]
    updates_sent = _wait_updates_settled(r2)
    refresh_recv = _stats_towards_r1(r2)["routeRefreshRecv"]

    r2.vtysh_cmd("clear bgp ipv4 unicast {} soft in".format(R1))
    _wait_refresh_received(r2, refresh_recv + 2)

    # An announce caused by a marker would leave within a few hundred ms.
    for _ in range(3):
        time.sleep(1)
        sent = _stats_towards_r1(r2)["updatesSent"]
        assert (
            sent == updates_sent
        ), "r2 sent {} UPDATE(s) to r1 after receiving BoRR/EoRR".format(
            sent - updates_sent
        )


def test_bgp_dual_af_refresh():
    """
    Refresh IPv4 and IPv6 at the same time. Each address family must get
    its own BoRR to EoRR handling, with no marker ignored or rejected.

    Refreshes that do not overlap would pass even with one timer shared by
    all families, so a run only counts if both BoRRs arrive before either
    EoRR. r1 sends a BoRR as soon as it gets the request, but its EoRR only
    after the announce delay, so the two refreshes normally overlap. That
    order is not guaranteed, so the clear is repeated until it holds.
    """
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r2 = tgen.gears["r2"]

    expected = []
    for family in ["IPv4", "IPv6"]:
        expected.append(
            "rcvd route-refresh (BoRR) for {}/unicast, triggering timer".format(family)
        )
        expected.append(
            "rcvd route-refresh (EoRR) for {}/unicast, stopping BoRR timer".format(
                family
            )
        )

    attempts = 5
    for attempt in range(1, attempts + 1):
        log_start = len(_r2_log(tgen))
        refresh_recv = _stats_towards_r1(r2)["routeRefreshRecv"]

        r2.vtysh_cmd("clear bgp {} soft in".format(R1))
        _wait_refresh_received(r2, refresh_recv + 4)

        test_func = functools.partial(_check_markers_logged, tgen, log_start, expected)
        _, result = topotest.run_and_expect(test_func, None, count=15, wait=1)
        assert result is None, result

        lines = _r2_log(tgen)[log_start:].splitlines()
        rejected = [line for line in lines if "whereas" in line]
        assert not rejected, "marker ignored or rejected: {}".format(rejected[0])

        borr = [
            i for i, line in enumerate(lines) if "rcvd route-refresh (BoRR)" in line
        ]
        eorr = [
            i for i, line in enumerate(lines) if "rcvd route-refresh (EoRR)" in line
        ]
        if max(borr) < min(eorr):
            return

        logger.info(
            "attempt %d: the two refreshes did not overlap, clearing again", attempt
        )

    assert False, "the two refreshes did not overlap in {} attempts".format(attempts)


def test_memory_leak():
    "Run the memory leak test and report results."
    tgen = get_topogen()
    if not tgen.is_memleak_enabled():
        pytest.skip("Memory leak test/report is disabled")

    tgen.report_memory_leaks()


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
