#!/usr/bin/env python
# SPDX-License-Identifier: ISC

#
# test_rip_triggered_update_scan.py
# Part of NetDEF Topology Tests
#

"""
test_rip_triggered_update_scan.py: RIP triggered updates must not scan the
full routing table once per output point.

A single route change (same from/next-hop, metric or tag alternation)
schedules a triggered update.  RFC 2453 section 3.10 only requires
advertising the changed routes, but the unmodified daemon walks the whole
RIP table in rip_output_process() once per output point (every non-passive
interface plus every static neighbor) and applies the output filter to
every route before the changed-route check, and rip_clear_changed_flag()
walks the table again - O(N x M + N) work for K changed routes.

Topology:
    r2-eth0 10.0.12.2/24 --- s1 --- r1-eth0 10.0.12.1/24
    r1-eth1 10.0.13.1/24 --- s2 --- r3-eth0 10.0.13.2/24

r1 holds 64 loopback /24 routes and logs every per-route RIPv1 mask check
("RIPv1 mask check ... considered for output / made it through", two lines
per route per output point) under `debug rip packet`.  r2 originates
192.168.100.0/24 and re-advertises it with an alternating offset-list
metric; every change triggers an update on r1.  On the unmodified daemon
one triggered round logs ~2 x 67 x 2 mask-check lines; with the fix only
the changed route is visited (~2 x 1 x 2 lines).  The test fails when one
triggered round logs more than SCAN_LINE_LIMIT mask-check lines.

Wire behaviour is asserted at the same time: the triggered update must
still carry the changed route to r3, output filters must still apply to
changed routes, merged changes must converge, and periodic updates must
keep working (initial convergence depends on them).

Beyond the scan bound the suite covers the lifecycle edges of the
changed-route set: two distinct routes merged into one round (K=2),
ECMP routes changing (per-nexthop rinfos), a poisoned route going
through garbage collection, and tearing the RIP instance down while a
merged round is still pending.
"""

import functools
import json
import os
import sys
import time

import pytest

CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

# pylint: disable=C0413
from lib import topotest
from lib.topogen import Topogen, get_topogen

pytestmark = [pytest.mark.ripd]

TARGET = "192.168.100.0/24"
TARGET2 = "192.168.101.0/24"
DUMMY = "10.250.0.0/24"
LO_NETS = ["10.100.{}.0/24".format(i) for i in range(64)]
MASK_CHECK = "RIPv1 mask check"
TRIGGERED = "triggered update!"
# A triggered round visits each changed route once per output point and
# logs two mask-check lines per visit (2 output points, up to 3 changed
# routes -> 4-12 lines); allow margin.  The unmodified daemon logs
# hundreds.
SCAN_LINE_LIMIT = 16
# r2 advertises the target with offset metric 1 or 2; each RIP hop adds
# one to the installed metric, so r3 sees offset + 3.
R3_METRIC = {1: 4, 2: 5}
# The second target is redistributed at the default metric 1, so r3
# sees it at metric 3.
R3_METRIC2 = 3


def setup_module(mod):
    topodef = {"s1": ("r1", "r2"), "s2": ("r1", "r3")}
    tgen = Topogen(topodef, mod.__name__)
    tgen.start_topology()

    # Explicit daemon list and absolute config paths: the config-file
    # grep inference enables every daemon on platforms where the
    # in-router grep misbehaves (tripping the LDP/MPLS availability
    # gate), and the relative-path fallback depends on the node's view
    # of the host filesystem.
    for name, router in tgen.routers().items():
        router.load_frr_config(
            source=os.path.join(CWD, name, "frr.conf"),
            daemons=["zebra", "ripd"],
        )

    tgen.start_router()


def teardown_module():
    tgen = get_topogen()
    tgen.stop_topology()


def ripd_log_lines(marker=0):
    path = os.path.join(get_topogen().logdir, "r1", "ripd.log")
    with open(path) as logf:
        return logf.readlines()[marker:]


def ripd_log_marker():
    return len(ripd_log_lines())


def triggered_round_scan_lines(marker):
    """Per-route mask-check lines logged by the first triggered update
    round that starts at or after `marker`.  One round runs synchronously,
    so its lines are contiguous up to the next round or a periodic
    update."""
    count = 0
    started = False
    for line in ripd_log_lines(marker):
        if TRIGGERED in line:
            if started:
                break
            started = True
            continue
        if not started:
            continue
        if "update timer fire!" in line:
            break
        if MASK_CHECK in line:
            count += 1
    return count, started


def triggered_rounds(marker):
    return [l for l in ripd_log_lines(marker) if TRIGGERED in l]


def flap_target(offset):
    """Change the metric r2 advertises for the target."""
    get_topogen().gears["r2"].vtysh_cmd(
        "configure terminal\n"
        "router rip\n"
        "offset-list FLAP out {} r2-eth0\n"
        "end".format(offset)
    )


def second_route_config(remove=False):
    """Originate (or withdraw) the second target on r2."""
    cmd = "no ip route {} Null0" if remove else "ip route {} Null0"
    get_topogen().gears["r2"].vtysh_cmd(
        "configure terminal\n{}\nend".format(cmd.format(TARGET2))
    )


def toggle_dummy(add):
    """Add/remove a dummy static on r2 so r2 sends a triggered update
    immediately instead of waiting for its 5s periodic timer."""
    if add:
        cmd = "ip route {} Null0".format(DUMMY)
    else:
        cmd = "no ip route {} Null0".format(DUMMY)
    get_topogen().gears["r2"].vtysh_cmd(
        "configure terminal\n{}\nend".format(cmd)
    )


def route_metric(prefix, node="r3"):
    router = get_topogen().gears[node]
    routes = route_json(router, "show ip route json")
    if routes is None:
        return None
    route = routes.get(prefix)
    if not route:
        return None
    return route[0]["metric"]


def r3_target_metric():
    return route_metric(TARGET)


def r1_target_nexthops():
    r1 = get_topogen().gears["r1"]
    routes = route_json(r1, "show ip route {} json".format(TARGET))
    if routes is None:
        return None
    route = routes.get(TARGET)
    if not route:
        return None
    return sorted(nh["ip"] for nh in route[0]["nexthops"])


def wait_triggered_round(marker):
    """Wait until a triggered update round is logged at or after
    `marker`."""

    def _one_round():
        lines = ripd_log_lines(marker)
        return None if any(TRIGGERED in l for l in lines) else "not yet"

    _, result = topotest.run_and_expect(_one_round, None, count=30, wait=1)
    assert result is None, "no triggered update on r1"


def route_json(router, command):
    """Parse the first JSON value from a vtysh response, tolerating
    shell noise (e.g. locale warnings) around the payload."""
    out = router.vtysh_cmd(command)
    start = out.find("{")
    if start < 0:
        return None
    try:
        return json.JSONDecoder().raw_decode(out, start)[0]
    except json.JSONDecodeError:
        return None


def settle_changed_flags():
    """Flush startup changes and wait for each dummy transition on r3.

    An unrelated pending round can satisfy a log-only wait before r1 has
    learned the dummy. Waiting for r3 proves the corresponding update was
    processed and forwarded before reversing it.
    """
    toggle_dummy(False)
    _, result = topotest.run_and_expect(
        lambda: route_metric(DUMMY, node="r1") in (None, 16),
        True, count=30, wait=1
    )
    assert result is True, "previous dummy route still reachable on r1"
    for add in (True, False):
        marker = ripd_log_marker()
        toggle_dummy(add)
        if add:
            # After r1 instance teardown, r3 may retain an old dummy.
            # Require fresh learning and output processing on r1 first.
            _, result = topotest.run_and_expect(
                functools.partial(route_metric, DUMMY, node="r1"),
                2, count=30, wait=1,
            )
            assert result == 2, "r1 did not learn the dummy route"
            _, result = topotest.run_and_expect(
                lambda: any(
                    "{}, {} considered for output".format(MASK_CHECK, DUMMY) in line
                    for line in ripd_log_lines(marker)
                ),
                True, count=30, wait=1,
            )
            assert result is True, "r1 did not process the dummy for output"
        if add:
            expected = R3_METRIC2
            check = functools.partial(route_metric, DUMMY)
        else:
            expected = True
            check = lambda: route_metric(DUMMY) in (None, 16)
        _, result = topotest.run_and_expect(check, expected, count=30, wait=1)
        assert result == expected, "dummy {} did not reach r3".format(
            "addition" if add else "withdrawal"
        )
        wait_triggered_round(marker)


def wait_r3_metric(offset):
    test_func = functools.partial(r3_target_metric)
    _, result = topotest.run_and_expect(
        test_func, R3_METRIC[offset], count=40, wait=1
    )
    assert result == R3_METRIC[offset], (
        "r3 metric for {} did not become {}".format(TARGET, R3_METRIC[offset])
    )


def normalize_target():
    """Bring the target back to offset 1 (a no-op when it is already
    there, so tests can call it unconditionally)."""
    flap_target(1)
    wait_r3_metric(1)


def flap_and_expect_scan(offset):
    """Flap the target metric, wait until r3 installs it, then check the
    scan size of the triggered round on r1."""
    marker = ripd_log_marker()
    flap_target(offset)
    wait_r3_metric(offset)
    scan, started = triggered_round_scan_lines(marker)
    assert started, "no triggered update logged on r1"
    assert scan <= SCAN_LINE_LIMIT, (
        "one triggered update for 1 changed route scanned the full table: "
        "{} per-route mask-check lines (limit {})".format(
            scan, SCAN_LINE_LIMIT
        )
    )
    return scan


def test_convergence():
    "All 64 loopback routes and the target reach r3 via RIP."
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    def _routes_present():
        r3 = tgen.gears["r3"]
        routes = route_json(r3, "show ip route json")
        if routes is None:
            return "no route json yet"
        missing = [n for n in LO_NETS + [TARGET] if n not in routes]
        return missing if missing else None

    _, result = topotest.run_and_expect(_routes_present, None, count=90, wait=1)
    assert result is None, "r3 is missing RIP routes: {}".format(result)


def test_triggered_update_scan_bounded():
    "One route change must not walk the whole table per output point."
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    settle_changed_flags()
    for offset in (2, 1):
        scan = flap_and_expect_scan(offset)
        assert scan > 0, (
            "no per-route mask-check lines logged at all; "
            "debug rip packet not effective"
        )


def test_triggered_update_merge():
    "Changes in quick succession still converge; every round stays bounded."
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    settle_changed_flags()
    marker = ripd_log_marker()
    # First change: r2's periodic timer is too slow, so it is pushed out
    # immediately by toggling a dummy static on r2.
    flap_target(2)
    toggle_dummy(True)
    wait_triggered_round(marker)
    # Wait until the first round actually reached r3 (metric 5), so the
    # next wait cannot be satisfied by the pre-flap metric.
    wait_r3_metric(2)

    # Second change right behind the first: converges to the last metric
    # through a follow-up round (merged into the 1-5s interval when it
    # has not expired yet).
    flap_target(1)
    toggle_dummy(False)
    wait_r3_metric(1)

    rounds = triggered_rounds(marker)
    assert len(rounds) >= 2, (
        "expected an immediate and a follow-up triggered update, got {}".format(
            len(rounds)
        )
    )
    # The last (merged) round must also stay scan-bounded.
    lines = ripd_log_lines(marker)
    last_started_at = max(
        i for i, l in enumerate(lines) if TRIGGERED in l
    )
    scan, _ = triggered_round_scan_lines(marker + last_started_at)
    assert scan <= SCAN_LINE_LIMIT, (
        "merged triggered update scanned the full table: {} lines".format(scan)
    )


def test_triggered_update_output_filter():
    "Output filters must still apply to changed routes."
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    # Make sure r3 has converged with the target route first.
    wait_r3_metric(1)

    r1 = tgen.gears["r1"]

    # Deny the target on r1-eth1: the changed route must be filtered and
    # r3 must keep the old metric.
    r1.vtysh_cmd(
        "configure terminal\n"
        "ip prefix-list BLOCK seq 5 deny {}\n"
        "ip prefix-list BLOCK seq 10 permit 0.0.0.0/0 le 32\n"
        "router rip\n"
        "distribute-list prefix BLOCK out r1-eth1\n"
        "end".format(TARGET)
    )
    marker = ripd_log_marker()
    flap_target(2)
    # A previous dummy withdrawal may still be pending; it must not
    # acknowledge this target metric change before r2 advertises it.
    _, result = topotest.run_and_expect(
        functools.partial(route_metric, TARGET, node="r1"),
        R3_METRIC[2] - 1, count=30, wait=1,
    )
    assert result == R3_METRIC[2] - 1, "r1 did not process the target metric change"
    _, result = topotest.run_and_expect(
        lambda: any(
            "{}, {} considered for output".format(MASK_CHECK, TARGET) in line
            for line in ripd_log_lines(marker)
        ),
        True, count=30, wait=1,
    )
    assert result is True, "r1 did not process the changed target for output"
    wait_triggered_round(marker)
    assert r3_target_metric() == R3_METRIC[1], (
        "r3 metric changed although the changed route is filtered on r1"
    )

    # Remove the filter: the next flaps must reach r3 again.
    r1.vtysh_cmd(
        "configure terminal\n"
        "router rip\n"
        "no distribute-list prefix BLOCK out r1-eth1\n"
        "end"
    )
    # flap back to offset 1; the round must happen even though r3's
    # metric does not change (it was never updated to offset 2).
    marker = ripd_log_marker()
    flap_target(1)
    wait_triggered_round(marker)
    # flap to offset 2: r3 must now receive metric 5 again, and the
    # round must stay scan-bounded.
    flap_and_expect_scan(2)


def test_triggered_update_multi_route_merge():
    "Two distinct routes changed in one merge window: one bounded round."
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    settle_changed_flags()

    # r2 originates a second prefix at the default redistribute metric.
    second_route_config()
    try:
        _, result = topotest.run_and_expect(
            functools.partial(route_metric, TARGET2), R3_METRIC2,
            count=40, wait=1,
        )
        assert result == R3_METRIC2, (
            "r3 did not learn {} at metric {}".format(TARGET2, R3_METRIC2)
        )

        # First change: immediate round (pushed out by the dummy static).
        marker = ripd_log_marker()
        flap_target(2)
        toggle_dummy(True)
        wait_triggered_round(marker)
        wait_r3_metric(2)

        # Two distinct route changes inside the merge window: the
        # target's metric and the second route's withdrawal (the dummy
        # withdrawal rides along).  The commands are sent one by one
        # within the window; r2's and r1's merge timers each group them
        # into a single update/round.
        marker = ripd_log_marker()
        flap_target(1)
        second_route_config(remove=True)
        toggle_dummy(False)
        wait_r3_metric(1)

        def _second_gone():
            routes = route_json(get_topogen().gears["r3"],
                                "show ip route json")
            if routes is None:
                return "no route json yet"
            return None if TARGET2 not in routes else "still present"

        _, result = topotest.run_and_expect(_second_gone, None,
                                            count=40, wait=1)
        assert result is None, (
            "r3 did not drop {} after withdrawal".format(TARGET2)
        )

        # Check every triggered round that follows, not just the last
        # one: each round must stay scan-bounded, and the two route
        # changes must ride in a single merged round.  Per-route rounds
        # (one route each, 4 mask-check lines) would also satisfy a
        # cross-round total of 8, so require one round to visit both
        # changed routes (>= 8 lines; the dummy withdrawal rides along
        # in the same round).
        lines = ripd_log_lines(marker)
        starts = [i for i, l in enumerate(lines) if TRIGGERED in l]
        assert starts, "no triggered update logged on r1"
        merged = 0
        for start in starts:
            scan, _ = triggered_round_scan_lines(marker + start)
            assert scan <= SCAN_LINE_LIMIT, (
                "triggered round for 2 changed routes scanned the full "
                "table: {} mask-check lines (limit {})".format(
                    scan, SCAN_LINE_LIMIT
                )
            )
            merged = max(merged, scan)
        assert merged >= 8, (
            "no single triggered round scanned both changed routes; "
            "largest round logged {} mask-check lines".format(merged)
        )
    finally:
        # Withdraw the second route again (a no-op when the test
        # already withdrew it).
        second_route_config(remove=True)

    assert tgen.net["r1"].checkRouterRunning() == ""


def test_triggered_update_ecmp():
    "ECMP routes: a per-nexthop change still triggers a bounded update."
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    settle_changed_flags()
    # Earlier tests may have left the target at another offset; both r2
    # and r3 must advertise it with metric 2 on the wire for ECMP.
    normalize_target()
    r1 = tgen.gears["r1"]
    r3 = tgen.gears["r3"]

    # r3 originates the same prefix with the same metric as r2 (static
    # metric 1 + offset 1 = 2 on the wire), so r1 forms an ECMP pair.
    # allow-ecmp must be committed before r3's first advertisement
    # arrives, otherwise the second path is rejected on arrival.
    # Keep rip-only and non-rip commands in separate vtysh sessions.
    r1.vtysh_cmd("configure terminal\nrouter rip\nallow-ecmp 2\nend")
    r3.vtysh_cmd(
        "configure terminal\n"
        "ip route {} Null0\n"
        "access-list ECMP permit 192.168.100.0 0.0.0.255\n"
        "end".format(TARGET)
    )
    r3.vtysh_cmd(
        "configure terminal\n"
        "router rip\n"
        "redistribute static\n"
        "offset-list ECMP out 1 r3-eth0\n"
        "end"
    )

    try:
        both = ["10.0.12.2", "10.0.13.2"]
        _, result = topotest.run_and_expect(
            r1_target_nexthops, both, count=30, wait=1
        )
        assert result == both, "r1 did not form ECMP for {}: {}".format(
            TARGET, result
        )

        # Raise r2's metric: the pair collapses to the r3 path; the
        # triggered round must stay scan-bounded.  r1's own RIB is
        # updated before the round is logged, so wait for it.
        marker = ripd_log_marker()
        flap_target(2)
        _, result = topotest.run_and_expect(
            r1_target_nexthops, ["10.0.13.2"], count=30, wait=1
        )
        assert result == ["10.0.13.2"], (
            "r1 did not fall back to the r3 path: {}".format(result)
        )
        wait_triggered_round(marker)
        scan, _ = triggered_round_scan_lines(marker)
        assert scan <= SCAN_LINE_LIMIT, (
            "triggered update for an ECMP metric change scanned the full "
            "table: {} mask-check lines (limit {})".format(scan,
                                                           SCAN_LINE_LIMIT)
        )

        # Back to equal metrics: ECMP reforms, still bounded.
        marker = ripd_log_marker()
        flap_target(1)
        _, result = topotest.run_and_expect(r1_target_nexthops, both,
                                            count=30, wait=1)
        assert result == both, "r1 did not reform ECMP for {}: {}".format(
            TARGET, result
        )
        wait_triggered_round(marker)
        scan, _ = triggered_round_scan_lines(marker)
        assert scan <= SCAN_LINE_LIMIT, (
            "triggered update for the ECMP reform scanned the full table: "
            "{} mask-check lines (limit {})".format(scan, SCAN_LINE_LIMIT)
        )
    finally:
        # Withdraw r3's copy and disable ECMP again.
        r3.vtysh_cmd(
            "configure terminal\n"
            "router rip\n"
            "no redistribute static\n"
            "no offset-list ECMP out 1 r3-eth0\n"
            "end"
        )
        r3.vtysh_cmd(
            "configure terminal\n"
            "no ip route {} Null0\n"
            "no access-list ECMP\n"
            "end".format(TARGET)
        )
        r1.vtysh_cmd("configure terminal\nrouter rip\nno allow-ecmp\nend")
    assert tgen.net["r1"].checkRouterRunning() == ""


def test_triggered_update_gc():
    "A poisoned route is advertised, garbage-collected, and re-learned."
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    settle_changed_flags()
    normalize_target()

    # Short garbage timer on r1 and r3 so the poisoned route is freed
    # within the test.
    for r in ("r1", "r3"):
        tgen.gears[r].vtysh_cmd(
            "configure terminal\nrouter rip\ntimers basic 600 3600 5\nend"
        )

    try:
        # Poison the target: offset 15 + redistributed metric 1 = 16.
        marker = ripd_log_marker()
        flap_target(15)

        def _r1_route_gone():
            routes = route_json(get_topogen().gears["r1"], "show ip route json")
            if routes is None:
                return "no route json yet"
            return None if TARGET not in routes else "still present"

        _, result = topotest.run_and_expect(_r1_route_gone, None,
                                            count=30, wait=1)
        assert result is None, "r1 still installs the poisoned route"

        # The poison round must stay scan-bounded (it advertises the
        # poison).  A merge timer armed by an earlier round can defer
        # it by up to 5 seconds.
        wait_triggered_round(marker)
        scan, _ = triggered_round_scan_lines(marker)
        assert scan <= SCAN_LINE_LIMIT, (
            "triggered update for the poison scanned the full table: {} "
            "mask-check lines (limit {})".format(scan, SCAN_LINE_LIMIT)
        )

        # After the garbage timer the rinfo is gone from the RIP table.
        time.sleep(7)

        def _r1_rip_gone():
            out = get_topogen().gears["r1"].vtysh_cmd("show ip rip")
            return None if TARGET not in out else "still in rip table"

        _, result = topotest.run_and_expect(_r1_rip_gone, None,
                                            count=15, wait=1)
        assert result is None, "poisoned route not garbage-collected on r1"

        # Re-learn the route: the next triggered round is bounded again.
        marker = ripd_log_marker()
        flap_target(1)
        wait_r3_metric(1)
        scan, started = triggered_round_scan_lines(marker)
        assert started, "no triggered update logged on r1 after re-learning"
        assert scan <= SCAN_LINE_LIMIT, (
            "triggered update after garbage collection scanned the full "
            "table: {} mask-check lines (limit {})".format(scan,
                                                           SCAN_LINE_LIMIT)
        )
    finally:
        # Restore the garbage timer.
        for r in ("r1", "r3"):
            tgen.gears[r].vtysh_cmd(
                "configure terminal\nrouter rip\n"
                "timers basic 600 3600 2400\nend"
            )
    assert tgen.net["r1"].checkRouterRunning() == ""


def test_triggered_update_instance_teardown():
    "Instance teardown with a change pending, then re-create and reuse."
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    settle_changed_flags()
    normalize_target()

    # One round now, one change pending inside the merge window, then
    # remove the whole instance before the merged round can fire.
    marker = ripd_log_marker()
    flap_target(2)
    toggle_dummy(True)
    wait_triggered_round(marker)
    wait_r3_metric(2)
    flap_target(1)
    r1 = tgen.gears["r1"]
    r1.vtysh_cmd("configure terminal\nno router rip\nend")

    # Any pending merge timer must not fire into the destroyed instance.
    time.sleep(6)
    assert tgen.net["r1"].checkRouterRunning() == "", (
        "ripd died after removing the RIP instance"
    )

    # Re-create the instance and verify triggered updates work again.
    r1.vtysh_multicmd([
        "configure terminal",
        "router rip",
        "network 10.0.12.0/24",
        "network 10.0.13.0/24",
        "redistribute connected",
        "timers basic 600 3600 2400",
        "end",
    ])
    settle_changed_flags()
    flap_and_expect_scan(2)
    flap_target(1)
    wait_r3_metric(1)
    assert tgen.net["r1"].checkRouterRunning() == ""


if __name__ == "__main__":
    args = ["-s", CWD] + sys.argv[1:]
    sys.exit(pytest.main(args))
