#!/usr/bin/env python
# SPDX-License-Identifier: ISC

#
# test_static_bfd_admin_down.py
# Part of NetDEF Topology Tests
#
# Copyright (c) 2025 Nvidia, Inc.
# Sougata Barik
#

"""
test_static_bfd_admin_down.py:

Verify that static routes monitored by BFD are NOT removed and re-added
when a BFD session transitions through Admin Down -> Down -> Up.

Prior to the fix, when a BFD profile was shut down (admin down) and then
re-enabled (no shutdown), the BFD session would transition:
    Admin Down -> Down -> Up
During the transient Down state, staticd would incorrectly remove the
route and then re-add it on Up, causing unnecessary route churn.

After the fix, staticd uses a hold-down timer when BFD transitions from
Admin Down to Down:
  - On ADMIN_DOWN -> DOWN: a hold-down timer is started instead of
    immediately removing the route.
  - If BFD reaches UP before the timer fires, the timer is cancelled
    and no route churn occurs.
  - If the timer expires (peer genuinely unreachable), the route is removed.

The test enables "debug static bfd" and verifies the correct code path
by checking staticd's log for diagnostic messages:
  - WITH fix: "starting hold-down timer" + "cancelling admin-down hold-down timer"
  - WITHOUT fix (BUG): "next hop is down, remove it from RIB" during the
    admin down cycle

Topology:

    r1 -------- r2
     .1  s1  .2
  192.168.1.0/24

r1: static routes to 10.10.10.0/24 (IPv4) and fd00::/64 (IPv6)
    with next-hop via r2, tracked by BFD with a profile.
r2: BFD peer with matching profile, loopback with destination prefixes.

BFD session states on r1 (``show bfd peers json``): ``up``, ``down`` (session
down), ``shutdown`` (local administrative down / admin down).

There are three states and six directed transitions between *distinct* states
(each state can transition to the other two). Those six edges are covered by
``test_state_transition_up_to_down``, ``test_state_transition_up_to_admin_down``,
``test_state_transition_down_to_up``, ``test_state_transition_down_to_admin_down``,
``test_state_transition_admin_down_to_up``, and ``test_state_transition_admin_down_to_down``.

Additional scenarios (multi-hop paths, staticd log checks, unreachable peer,
hold-down cancelled when profile shutdown is re-applied) are in the other
tests in this module.
"""

import os
import sys
import time
import functools
import pytest

pytestmark = [pytest.mark.staticd, pytest.mark.bfdd]

CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

from lib import topotest
from lib.topogen import Topogen, TopoRouter, get_topogen
from lib.topolog import logger
from lib.common_config import step
from munet.watchlog import WatchLog


def build_topo(tgen):
    for routern in range(1, 3):
        tgen.add_router("r{}".format(routern))

    switch = tgen.add_switch("s1")
    switch.add_link(tgen.gears["r1"])
    switch.add_link(tgen.gears["r2"])


def setup_module(mod):
    tgen = Topogen(build_topo, mod.__name__)
    tgen.start_topology()

    for _, (rname, router) in enumerate(tgen.routers().items(), 1):
        router.load_frr_config(
            os.path.join(CWD, "{}/frr.conf".format(rname)),
            [
                (TopoRouter.RD_ZEBRA, None),
                (TopoRouter.RD_MGMTD, None),
                (TopoRouter.RD_BFD, None),
                (TopoRouter.RD_STATIC, None),
            ],
        )

    tgen.start_router()

    r1 = tgen.gears["r1"]
    r1.vtysh_cmd("debug static bfd", daemon="staticd")


def teardown_module(_mod):
    tgen = get_topogen()
    tgen.stop_topology()


def _check_bfd_up(router, peer_ip):
    output = router.vtysh_cmd("show bfd peers json", isjson=True)
    for peer in output:
        if peer.get("peer") == peer_ip and peer.get("status") == "up":
            return None
    return "BFD peer {} not up".format(peer_ip)


def _check_bfd_status(router, peer_ip, expected_status):
    output = router.vtysh_cmd("show bfd peers json", isjson=True)
    for peer in output:
        if peer.get("peer") == peer_ip:
            if peer.get("status") == expected_status:
                return None
            return "BFD peer {} status is '{}', expected '{}'".format(
                peer_ip, peer.get("status"), expected_status
            )
    return "BFD peer {} not found".format(peer_ip)


def _check_route_installed(router, prefix, cmd):
    output = router.vtysh_cmd(cmd, isjson=True)
    if prefix not in output:
        return "Route {} not in output".format(prefix)
    for entry in output[prefix]:
        if entry.get("installed"):
            for nh in entry.get("nexthops", []):
                if nh.get("fib") and nh.get("active"):
                    return None
    return "Route {} not installed in FIB".format(prefix)


def _check_route_not_installed(router, prefix, cmd):
    output = router.vtysh_cmd(cmd, isjson=True)
    if prefix not in output:
        return None
    for entry in output[prefix]:
        if not entry.get("installed"):
            continue
        for nh in entry.get("nexthops", []):
            if nh.get("fib") and nh.get("active"):
                return "Route {} still installed in FIB".format(prefix)
    return None


def _ensure_link_up_bfd_up_and_routes(r1, r2):
    """Restore link, clear BFD admin shutdown, wait for UP and routes on r1."""
    r2.link_enable("r2-eth0", enabled=True)
    r1.vtysh_cmd(
        """
configure terminal
bfd
 profile admin-test
  no shutdown
 exit
 peer 192.168.1.2 interface r1-eth0
  no shutdown
 exit
 peer fc00::2 interface r1-eth0
  no shutdown
 exit
exit
"""
    )
    for peer_ip in ["192.168.1.2", "fc00::2"]:
        test_func = functools.partial(_check_bfd_up, r1, peer_ip)
        _, res = topotest.run_and_expect(test_func, None, count=60, wait=1)
        assert res is None, "BFD peer {} not up after link restore".format(peer_ip)
    test_func = functools.partial(
        _check_route_installed, r1, "10.10.10.0/24", "show ip route 10.10.10.0/24 json"
    )
    _, res = topotest.run_and_expect(test_func, None, count=30, wait=1)
    assert res is None, "IPv4 static route not installed"
    test_func = functools.partial(
        _check_route_installed, r1, "fd00::/64", "show ipv6 route fd00::/64 json"
    )
    _, res = topotest.run_and_expect(test_func, None, count=30, wait=1)
    assert res is None, "IPv6 static route not installed"


def test_bfd_convergence():
    """Verify BFD peers come up on both routers."""
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    step("Waiting for BFD peers to come up")
    r1 = tgen.gears["r1"]

    for peer_ip in ["192.168.1.2", "fc00::2"]:
        test_func = functools.partial(_check_bfd_up, r1, peer_ip)
        _, res = topotest.run_and_expect(test_func, None, count=30, wait=1)
        assert res is None, "BFD peer {} did not come up on r1".format(peer_ip)


def test_static_routes_installed():
    """Verify static routes are installed when BFD is up."""
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    step("Verify static routes are installed")
    r1 = tgen.gears["r1"]

    test_func = functools.partial(
        _check_route_installed, r1, "10.10.10.0/24", "show ip route 10.10.10.0/24 json"
    )
    _, res = topotest.run_and_expect(test_func, None, count=30, wait=1)
    assert res is None, "IPv4 static route not installed"

    test_func = functools.partial(
        _check_route_installed, r1, "fd00::/64", "show ipv6 route fd00::/64 json"
    )
    _, res = topotest.run_and_expect(test_func, None, count=30, wait=1)
    assert res is None, "IPv6 static route not installed"


def test_bfd_profile_admin_down_no_route_churn():
    """
    Core test: verify via debug logs that routes are not churned during
    the BFD admin down -> down -> up transition.

    1. Snapshot the staticd log.
    2. Shutdown BFD profile -> admin down.
    3. Re-enable profile -> Admin Down -> Down -> Up transition.
    4. Check staticd debug log for the correct code path:
       - PASS: "BFD transitioning from Admin Down to Down, keeping route"
       - FAIL: "next hop is down, remove it from RIB" (route churn)
    """
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]

    step("Create WatchLog for staticd and snapshot current position")
    staticd_log = WatchLog(r1.net.rundir / "staticd.log")
    staticd_log.snapshot()

    step("Shutdown BFD profile on r1 to trigger admin down")
    r1.vtysh_cmd(
        """
configure terminal
bfd
 profile admin-test
  shutdown
 exit
exit
"""
    )

    step("Verify BFD sessions enter shutdown state")
    for peer_ip in ["192.168.1.2", "fc00::2"]:
        test_func = functools.partial(_check_bfd_status, r1, peer_ip, "shutdown")
        _, res = topotest.run_and_expect(test_func, None, count=10, wait=1)
        assert res is None, "BFD peer {} did not enter shutdown on r1".format(peer_ip)

    step("Verify static routes remain installed during admin down")
    test_func = functools.partial(
        _check_route_installed, r1, "10.10.10.0/24", "show ip route 10.10.10.0/24 json"
    )
    _, res = topotest.run_and_expect(test_func, None, count=5, wait=1)
    assert res is None, "IPv4 static route removed during admin down"

    step("Re-enable BFD profile (no shutdown) -> triggers Admin Down -> Down -> Up")
    r1.vtysh_cmd(
        """
configure terminal
bfd
 profile admin-test
  no shutdown
 exit
exit
"""
    )

    step("Wait for BFD sessions to come back up")
    for peer_ip in ["192.168.1.2", "fc00::2"]:
        test_func = functools.partial(_check_bfd_up, r1, peer_ip)
        _, res = topotest.run_and_expect(test_func, None, count=30, wait=1)
        assert res is None, "BFD peer {} did not come back up on r1".format(peer_ip)

    step("Verify static routes are still installed after recovery")
    test_func = functools.partial(
        _check_route_installed, r1, "10.10.10.0/24", "show ip route 10.10.10.0/24 json"
    )
    _, res = topotest.run_and_expect(test_func, None, count=5, wait=1)
    assert res is None, "IPv4 static route not installed after BFD recovery"

    test_func = functools.partial(
        _check_route_installed, r1, "fd00::/64", "show ipv6 route fd00::/64 json"
    )
    _, res = topotest.run_and_expect(test_func, None, count=5, wait=1)
    assert res is None, "IPv6 static route not installed after BFD recovery"

    step("Check staticd debug log to verify no route churn occurred")
    time.sleep(1)
    staticd_log.update_content()
    log_content = staticd_log.from_mark(staticd_log.last_snap_mark)
    logger.info("staticd log content after admin down cycle:\n%s", log_content)

    assert "BFD transitioning from Admin Down to Down, starting hold-down timer" in log_content, (
        "Expected debug message 'BFD transitioning from Admin Down to Down, "
        "starting hold-down timer' not found in staticd log. The fix may not be applied."
    )
    assert "cancelling admin-down hold-down timer" in log_content, (
        "Expected debug message 'cancelling admin-down hold-down timer' "
        "not found in staticd log. BFD should have come up and cancelled the timer."
    )
    assert "next hop is down, remove it from RIB" not in log_content, (
        "Found 'next hop is down, remove it from RIB' in staticd log during "
        "admin down cycle. This indicates route churn - the fix is NOT working."
    )
    assert "admin-down hold-down expired" not in log_content, (
        "Hold-down timer expired during normal admin-down cycle. "
        "BFD should have come up before the timer fired."
    )

    logger.info(
        "SUCCESS: staticd debug log confirms routes were NOT removed during "
        "admin down -> down -> up transition"
    )


def test_bfd_peer_shutdown_no_route_churn():
    """
    Same log-based verification using per-peer shutdown instead of profile.
    """
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]

    step("Snapshot staticd log before peer shutdown cycle")
    staticd_log = WatchLog(r1.net.rundir / "staticd.log")
    staticd_log.snapshot()

    step("Shutdown BFD peers directly on r1")
    r1.vtysh_cmd(
        """
configure terminal
bfd
 peer 192.168.1.2 interface r1-eth0
  shutdown
 exit
 peer fc00::2 interface r1-eth0
  shutdown
 exit
exit
"""
    )

    step("Verify BFD sessions enter shutdown state")
    for peer_ip in ["192.168.1.2", "fc00::2"]:
        test_func = functools.partial(_check_bfd_status, r1, peer_ip, "shutdown")
        _, res = topotest.run_and_expect(test_func, None, count=10, wait=1)
        assert res is None, "BFD peer {} did not enter shutdown on r1".format(peer_ip)

    step("Re-enable BFD peers on r1")
    r1.vtysh_cmd(
        """
configure terminal
bfd
 peer 192.168.1.2 interface r1-eth0
  no shutdown
 exit
 peer fc00::2 interface r1-eth0
  no shutdown
 exit
exit
"""
    )

    step("Wait for BFD peers to come back up")
    for peer_ip in ["192.168.1.2", "fc00::2"]:
        test_func = functools.partial(_check_bfd_up, r1, peer_ip)
        _, res = topotest.run_and_expect(test_func, None, count=30, wait=1)
        assert res is None, "BFD peer {} did not come back up".format(peer_ip)

    step("Check staticd debug log for no route churn during peer shutdown cycle")
    time.sleep(1)
    staticd_log.update_content()
    log_content = staticd_log.from_mark(staticd_log.last_snap_mark)
    logger.info("staticd log content after peer shutdown cycle:\n%s", log_content)

    assert "BFD transitioning from Admin Down to Down, starting hold-down timer" in log_content, (
        "Expected 'BFD transitioning from Admin Down to Down, starting hold-down timer' "
        "not found in staticd log during peer shutdown cycle."
    )
    assert "cancelling admin-down hold-down timer" in log_content, (
        "Expected 'cancelling admin-down hold-down timer' not found in "
        "staticd log. BFD should have come up and cancelled the timer."
    )
    assert "next hop is down, remove it from RIB" not in log_content, (
        "Found 'next hop is down, remove it from RIB' during peer shutdown "
        "cycle. Route churn detected - fix is NOT working."
    )

    logger.info("SUCCESS: No route churn during per-peer shutdown cycle")


def test_admin_down_with_peer_unreachable():
    """
    Verify that routes are removed when the peer is genuinely unreachable
    after admin-down is lifted.

    Scenario:
      1. BFD is UP, routes installed.
      2. Admin-down BFD profile -> BSS_ADMIN_DOWN, routes stay (correct).
      3. While admin-down, remote peer becomes unreachable (link down on r2).
      4. Lift admin-down -> BFD transitions ADMIN_DOWN -> DOWN.
      5. A hold-down timer starts (BFD_ADMIN_HOLDDOWN_SEC = 5s).
      6. BFD stays DOWN because peer is unreachable (no UP follows).
      7. Hold-down timer expires -> routes are removed.

    This ensures that the admin-down optimization does not leave stale
    routes when the peer is genuinely unreachable.
    """
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]
    r2 = tgen.gears["r2"]

    step("Ensure BFD is up and routes are installed before test")
    for peer_ip in ["192.168.1.2", "fc00::2"]:
        test_func = functools.partial(_check_bfd_up, r1, peer_ip)
        _, res = topotest.run_and_expect(test_func, None, count=30, wait=1)
        assert res is None, "BFD peer {} not up before test".format(peer_ip)

    step("Admin-down BFD profile on r1")
    r1.vtysh_cmd(
        """
configure terminal
bfd
 profile admin-test
  shutdown
 exit
exit
"""
    )

    step("Verify BFD sessions enter shutdown state")
    for peer_ip in ["192.168.1.2", "fc00::2"]:
        test_func = functools.partial(_check_bfd_status, r1, peer_ip, "shutdown")
        _, res = topotest.run_and_expect(test_func, None, count=10, wait=1)
        assert res is None, "BFD peer {} did not enter shutdown".format(peer_ip)

    step("While admin-down, bring r2-eth0 down (peer becomes unreachable)")
    r2.link_enable("r2-eth0", enabled=False)
    time.sleep(2)

    step("Lift admin-down -> BFD transitions ADMIN_DOWN -> DOWN (peer unreachable)")
    r1.vtysh_cmd(
        """
configure terminal
bfd
 profile admin-test
  no shutdown
 exit
exit
"""
    )

    step("Verify BFD sessions go to down state (not up, peer is unreachable)")
    for peer_ip in ["192.168.1.2", "fc00::2"]:
        test_func = functools.partial(_check_bfd_status, r1, peer_ip, "down")
        _, res = topotest.run_and_expect(test_func, None, count=30, wait=1)
        assert res is None, "BFD peer {} did not reach down state".format(peer_ip)

    step("Verify static routes are removed (peer is genuinely unreachable)")
    test_func = functools.partial(
        _check_route_not_installed,
        r1,
        "10.10.10.0/24",
        "show ip route 10.10.10.0/24 json",
    )
    _, res = topotest.run_and_expect(test_func, None, count=30, wait=1)
    assert res is None, (
        "IPv4 static route still installed after admin-down lifted with "
        "unreachable peer — stale route detected"
    )

    test_func = functools.partial(
        _check_route_not_installed,
        r1,
        "fd00::/64",
        "show ipv6 route fd00::/64 json",
    )
    _, res = topotest.run_and_expect(test_func, None, count=30, wait=1)
    assert res is None, (
        "IPv6 static route still installed after admin-down lifted with "
        "unreachable peer — stale route detected"
    )

    step("Restore: bring r2-eth0 back up")
    r2.link_enable("r2-eth0", enabled=True)

    step("Wait for BFD to recover and routes to be re-installed")
    for peer_ip in ["192.168.1.2", "fc00::2"]:
        test_func = functools.partial(_check_bfd_up, r1, peer_ip)
        _, res = topotest.run_and_expect(test_func, None, count=60, wait=1)
        assert res is None, "BFD peer {} did not recover after restore".format(peer_ip)

    test_func = functools.partial(
        _check_route_installed,
        r1,
        "10.10.10.0/24",
        "show ip route 10.10.10.0/24 json",
    )
    _, res = topotest.run_and_expect(test_func, None, count=30, wait=1)
    assert res is None, "IPv4 route not restored after peer recovery"

    test_func = functools.partial(
        _check_route_installed, r1, "fd00::/64", "show ipv6 route fd00::/64 json"
    )
    _, res = topotest.run_and_expect(test_func, None, count=30, wait=1)
    assert res is None, "IPv6 route not restored after peer recovery"


def test_holddown_cancelled_when_profile_shutdown_reapplied():
    """
    Re-applying BFD profile shutdown after ``no shutdown`` must cancel any
    pending admin-down hold-down timer. Otherwise a stale timer could fire
    while the session is administratively down again and wrongly withdraw the
    static route.

    Sequence: UP + routes -> profile ``shutdown`` -> ``no shutdown`` (may arm
    hold-down on Admin Down -> Down) -> profile ``shutdown`` again -> wait past
    hold-down duration -> routes must remain installed.

    Often BFD reaches Up before the second ``shutdown``; the hold-down is then
    cancelled on Up, not on re-admin-down. The log check allows either path.
    """
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]

    step("Baseline: link up, BFD up, routes installed")
    _ensure_link_up_bfd_up_and_routes(r1, tgen.gears["r2"])

    staticd_log = WatchLog(r1.net.rundir / "staticd.log")
    staticd_log.snapshot()

    step("Profile shutdown: admin-down, routes stay installed")
    r1.vtysh_cmd(
        """
configure terminal
bfd
 profile admin-test
  shutdown
 exit
exit
"""
    )
    for peer_ip in ["192.168.1.2", "fc00::2"]:
        test_func = functools.partial(_check_bfd_status, r1, peer_ip, "shutdown")
        _, res = topotest.run_and_expect(test_func, None, count=10, wait=1)
        assert res is None, "BFD peer {} not shutdown".format(peer_ip)
    for prefix, cmd in [
        ("10.10.10.0/24", "show ip route 10.10.10.0/24 json"),
        ("fd00::/64", "show ipv6 route fd00::/64 json"),
    ]:
        test_func = functools.partial(_check_route_installed, r1, prefix, cmd)
        _, res = topotest.run_and_expect(test_func, None, count=5, wait=1)
        assert res is None, "Route {} missing during admin-down".format(prefix)

    step("no shutdown then re-apply shutdown before hold-down can expire")
    r1.vtysh_cmd(
        """
configure terminal
bfd
 profile admin-test
  no shutdown
 exit
exit
"""
    )
    # Allow time for Admin Down -> Down and hold-down timer arm (BFD_ADMIN_HOLDDOWN_SEC is 5s).
    time.sleep(2)
    r1.vtysh_cmd(
        """
configure terminal
bfd
 profile admin-test
  shutdown
 exit
exit
"""
    )
    for peer_ip in ["192.168.1.2", "fc00::2"]:
        test_func = functools.partial(_check_bfd_status, r1, peer_ip, "shutdown")
        _, res = topotest.run_and_expect(test_func, None, count=10, wait=1)
        assert res is None, "BFD peer {} not shutdown after re-apply".format(peer_ip)

    step("Wait past hold-down window while session remains admin-down")
    time.sleep(7)

    step("Routes must still be installed (stale hold-down must not withdraw)")
    for prefix, cmd in [
        ("10.10.10.0/24", "show ip route 10.10.10.0/24 json"),
        ("fd00::/64", "show ipv6 route fd00::/64 json"),
    ]:
        test_func = functools.partial(_check_route_installed, r1, prefix, cmd)
        _, res = topotest.run_and_expect(test_func, None, count=10, wait=1)
        assert res is None, "Route {} wrongly withdrawn after stale timer window".format(prefix)

    step("Verify staticd log: timer cancelled on re-admin-down, no spurious expiry removal")
    time.sleep(1)
    staticd_log.update_content()
    log_content = staticd_log.from_mark(staticd_log.last_snap_mark)
    logger.info("staticd log (hold-down cancel on re-shutdown):\n%s", log_content)

    assert (
        "admin-down hold-down expired, peer unreachable, removing route" not in log_content
    ), "Hold-down expiry should not remove route while re-asserting admin-down (timer must be cancelled)"

    if "BFD transitioning from Admin Down to Down, starting hold-down timer" in log_content:
        # Hold-down may be cleared by BFD Up before the second ``shutdown`` (typical), or still
        # pending and cleared on re-admin-down. Both are valid; expiry must never run while wrong.
        holddown_cleared = (
            "BFD admin-down, cancelling pending admin-down hold-down timer" in log_content
            or "BFD up, cancelling admin-down hold-down timer" in log_content
        )
        assert holddown_cleared, (
            "When hold-down was armed, it must be cancelled (via BFD up or re-applying admin-down) "
            "before hold-down expiry can remove the route — see staticd log"
        )


def test_bfd_real_failure_removes_routes():
    """
    Verify that a real BFD failure (link down) still correctly removes
    static routes. This ensures the fix does not break normal BFD behavior.
    """
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]
    r2 = tgen.gears["r2"]

    step("Ensure link up and BFD not administratively shut down (earlier tests may leave profile shutdown)")
    _ensure_link_up_bfd_up_and_routes(r1, r2)

    step("Bring r2-eth0 down to simulate real BFD failure")
    tgen.gears["r2"].link_enable("r2-eth0", enabled=False)

    step("Verify BFD peers go down on r1")
    for peer_ip in ["192.168.1.2", "fc00::2"]:
        test_func = functools.partial(_check_bfd_status, r1, peer_ip, "down")
        _, res = topotest.run_and_expect(test_func, None, count=30, wait=1)
        assert res is None, "BFD peer {} did not go down on r1".format(peer_ip)

    step("Verify static routes are removed (real failure)")
    test_func = functools.partial(
        _check_route_not_installed, r1, "10.10.10.0/24", "show ip route 10.10.10.0/24 json"
    )
    _, res = topotest.run_and_expect(test_func, None, count=30, wait=1)
    assert res is None, "IPv4 static route not removed after real BFD failure"

    test_func = functools.partial(
        _check_route_not_installed, r1, "fd00::/64", "show ipv6 route fd00::/64 json"
    )
    _, res = topotest.run_and_expect(test_func, None, count=30, wait=1)
    assert res is None, "IPv6 static route not removed after real BFD failure"


def test_bfd_recovery_restores_routes():
    """
    Bring link back up -> BFD recovers -> static routes re-installed.
    """
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]

    step("Bring r2-eth0 back up")
    tgen.gears["r2"].link_enable("r2-eth0", enabled=True)

    step("Verify BFD peers come back up")
    for peer_ip in ["192.168.1.2", "fc00::2"]:
        test_func = functools.partial(_check_bfd_up, r1, peer_ip)
        _, res = topotest.run_and_expect(test_func, None, count=60, wait=1)
        assert res is None, "BFD peer {} did not recover on r1".format(peer_ip)

    step("Verify static routes are re-installed after recovery")
    test_func = functools.partial(
        _check_route_installed, r1, "10.10.10.0/24", "show ip route 10.10.10.0/24 json"
    )
    _, res = topotest.run_and_expect(test_func, None, count=30, wait=1)
    assert res is None, "IPv4 static route not restored after BFD recovery"

    test_func = functools.partial(
        _check_route_installed, r1, "fd00::/64", "show ipv6 route fd00::/64 json"
    )
    _, res = topotest.run_and_expect(test_func, None, count=30, wait=1)
    assert res is None, "IPv6 static route not restored after BFD recovery"


def test_transition_up_down_then_admin_down_then_admin_up():
    """
    Transition chain: UP -> DOWN (real link failure) -> ADMIN DOWN (profile
    shutdown) -> ADMIN UP (no shutdown) -> UP.

    Ensures staticd recovers correctly when a BFD profile is cleared after a
    prior forwarding failure: routes were already withdrawn (path_down) before
    admin-down.

    The admin-down hold-down timer (and its debug lines) only runs when
    ``previous_state == Admin Down`` and the next hop is *not* already
    ``path_down``. Here the link failure left ``path_down`` true; the
    ``BSS_ADMIN_DOWN`` handler does not clear it, so Admin Down -> Down uses
    the normal Down path—no "starting hold-down timer" log—while BFD and
    routes still recover after ``no shutdown``.
    """
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]
    r2 = tgen.gears["r2"]

    step("Baseline: link up, BFD up, routes installed")
    _ensure_link_up_bfd_up_and_routes(r1, r2)

    staticd_log = WatchLog(r1.net.rundir / "staticd.log")
    staticd_log.snapshot()

    step("UP -> DOWN: remote link failure removes routes")
    r2.link_enable("r2-eth0", enabled=False)
    for peer_ip in ["192.168.1.2", "fc00::2"]:
        test_func = functools.partial(_check_bfd_status, r1, peer_ip, "down")
        _, res = topotest.run_and_expect(test_func, None, count=30, wait=1)
        assert res is None, "BFD peer {} did not go down".format(peer_ip)
    test_func = functools.partial(
        _check_route_not_installed, r1, "10.10.10.0/24", "show ip route 10.10.10.0/24 json"
    )
    _, res = topotest.run_and_expect(test_func, None, count=30, wait=1)
    assert res is None, "IPv4 route should be withdrawn after BFD down"
    test_func = functools.partial(
        _check_route_not_installed, r1, "fd00::/64", "show ipv6 route fd00::/64 json"
    )
    _, res = topotest.run_and_expect(test_func, None, count=30, wait=1)
    assert res is None, "IPv6 route should be withdrawn after BFD down"

    step("DOWN -> ADMIN DOWN: profile shutdown while session is already down")
    r1.vtysh_cmd(
        """
configure terminal
bfd
 profile admin-test
  shutdown
 exit
exit
"""
    )
    for peer_ip in ["192.168.1.2", "fc00::2"]:
        test_func = functools.partial(_check_bfd_status, r1, peer_ip, "shutdown")
        _, res = topotest.run_and_expect(test_func, None, count=10, wait=1)
        assert res is None, "BFD peer {} not in shutdown after profile shutdown".format(peer_ip)

    step("Restore forwarding while still administratively shut down")
    r2.link_enable("r2-eth0", enabled=True)
    time.sleep(2)

    step("ADMIN DOWN -> ADMIN UP: no shutdown; expect UP and routes installed")
    r1.vtysh_cmd(
        """
configure terminal
bfd
 profile admin-test
  no shutdown
 exit
exit
"""
    )
    for peer_ip in ["192.168.1.2", "fc00::2"]:
        test_func = functools.partial(_check_bfd_up, r1, peer_ip)
        _, res = topotest.run_and_expect(test_func, None, count=60, wait=1)
        assert res is None, "BFD peer {} did not come up after admin up".format(peer_ip)
    test_func = functools.partial(
        _check_route_installed, r1, "10.10.10.0/24", "show ip route 10.10.10.0/24 json"
    )
    _, res = topotest.run_and_expect(test_func, None, count=30, wait=1)
    assert res is None, "IPv4 static route not installed after recovery chain"
    test_func = functools.partial(
        _check_route_installed, r1, "fd00::/64", "show ipv6 route fd00::/64 json"
    )
    _, res = topotest.run_and_expect(test_func, None, count=30, wait=1)
    assert res is None, "IPv6 static route not installed after recovery chain"

    step("Verify staticd log: no admin hold-down when path was already down before admin-down")
    time.sleep(1)
    staticd_log.update_content()
    log_content = staticd_log.from_mark(staticd_log.last_snap_mark)
    logger.info("staticd log (up->down->admin cycle):\n%s", log_content)

    assert "BFD transitioning from Admin Down to Down, starting hold-down timer" not in log_content, (
        "Admin hold-down should not start when next hop was already path_down before profile shutdown"
    )
    assert "cancelling admin-down hold-down timer" not in log_content, (
        "No admin hold-down timer should run in this scenario"
    )
    assert "admin-down hold-down expired" not in log_content
    assert "state: 2, previous_state: 8, path_down: 1" in log_content, (
        "Expected Admin Down -> Down with path_down still set (normal Down branch)"
    )
    assert log_content.count("next hop is up, add it to RIB") >= 2, (
        "Expected both BFD-monitored nexthops reinstalled after admin up"
    )


def test_transition_down_up_then_profile_admin_cycle():
    """
    Transition chain: DOWN -> UP (recover from link failure), then
    ADMIN DOWN -> … -> UP (profile shutdown / no shutdown).

    Covers the case where a normal BFD failure/recovery happens first; the
    subsequent administrative BFD cycle must still avoid static route churn.
    """
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]
    r2 = tgen.gears["r2"]

    step("Ensure starting state: link up, BFD up")
    _ensure_link_up_bfd_up_and_routes(r1, r2)

    step("DOWN -> UP: link failure then recovery before admin BFD cycle")
    r2.link_enable("r2-eth0", enabled=False)
    for peer_ip in ["192.168.1.2", "fc00::2"]:
        test_func = functools.partial(_check_bfd_status, r1, peer_ip, "down")
        _, res = topotest.run_and_expect(test_func, None, count=30, wait=1)
        assert res is None, "BFD peer {} did not go down".format(peer_ip)
    test_func = functools.partial(
        _check_route_not_installed, r1, "10.10.10.0/24", "show ip route 10.10.10.0/24 json"
    )
    _, res = topotest.run_and_expect(test_func, None, count=30, wait=1)
    assert res is None, "IPv4 route should be gone while BFD down"
    r2.link_enable("r2-eth0", enabled=True)
    for peer_ip in ["192.168.1.2", "fc00::2"]:
        test_func = functools.partial(_check_bfd_up, r1, peer_ip)
        _, res = topotest.run_and_expect(test_func, None, count=60, wait=1)
        assert res is None, "BFD peer {} did not recover".format(peer_ip)
    test_func = functools.partial(
        _check_route_installed, r1, "10.10.10.0/24", "show ip route 10.10.10.0/24 json"
    )
    _, res = topotest.run_and_expect(test_func, None, count=30, wait=1)
    assert res is None, "IPv4 route not back after DOWN->UP"
    test_func = functools.partial(
        _check_route_installed, r1, "fd00::/64", "show ipv6 route fd00::/64 json"
    )
    _, res = topotest.run_and_expect(test_func, None, count=30, wait=1)
    assert res is None, "IPv6 route not back after DOWN->UP"

    staticd_log = WatchLog(r1.net.rundir / "staticd.log")
    staticd_log.snapshot()

    step("Profile shutdown then no shutdown (ADMIN DOWN -> UP) after prior failure cycle")
    r1.vtysh_cmd(
        """
configure terminal
bfd
 profile admin-test
  shutdown
 exit
exit
"""
    )
    for peer_ip in ["192.168.1.2", "fc00::2"]:
        test_func = functools.partial(_check_bfd_status, r1, peer_ip, "shutdown")
        _, res = topotest.run_and_expect(test_func, None, count=10, wait=1)
        assert res is None, "BFD peer {} not shutdown".format(peer_ip)

    test_func = functools.partial(
        _check_route_installed, r1, "10.10.10.0/24", "show ip route 10.10.10.0/24 json"
    )
    _, res = topotest.run_and_expect(test_func, None, count=5, wait=1)
    assert res is None, "IPv4 route should stay installed during admin down"

    r1.vtysh_cmd(
        """
configure terminal
bfd
 profile admin-test
  no shutdown
 exit
exit
"""
    )
    for peer_ip in ["192.168.1.2", "fc00::2"]:
        test_func = functools.partial(_check_bfd_up, r1, peer_ip)
        _, res = topotest.run_and_expect(test_func, None, count=60, wait=1)
        assert res is None, "BFD peer {} did not come up".format(peer_ip)
    test_func = functools.partial(
        _check_route_installed, r1, "10.10.10.0/24", "show ip route 10.10.10.0/24 json"
    )
    _, res = topotest.run_and_expect(test_func, None, count=5, wait=1)
    assert res is None, "IPv4 route missing after admin cycle"
    test_func = functools.partial(
        _check_route_installed, r1, "fd00::/64", "show ipv6 route fd00::/64 json"
    )
    _, res = topotest.run_and_expect(test_func, None, count=5, wait=1)
    assert res is None, "IPv6 route missing after admin cycle"

    time.sleep(1)
    staticd_log.update_content()
    log_content = staticd_log.from_mark(staticd_log.last_snap_mark)
    logger.info("staticd log (down-up then admin cycle):\n%s", log_content)

    assert "BFD transitioning from Admin Down to Down, starting hold-down timer" in log_content
    assert "cancelling admin-down hold-down timer" in log_content
    assert "next hop is down, remove it from RIB" not in log_content
    assert "admin-down hold-down expired" not in log_content


def test_state_transition_up_to_down():
    """
    Directed transition: UP -> DOWN (session loss from forwarding failure).

    Trigger: disable r2 facing link; expect BFD ``down`` and tracked static
    routes withdrawn.
    """
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]
    r2 = tgen.gears["r2"]
    _ensure_link_up_bfd_up_and_routes(r1, r2)

    step("UP -> DOWN")
    r2.link_enable("r2-eth0", enabled=False)
    for peer_ip in ["192.168.1.2", "fc00::2"]:
        test_func = functools.partial(_check_bfd_status, r1, peer_ip, "down")
        _, res = topotest.run_and_expect(test_func, None, count=30, wait=1)
        assert res is None, "BFD peer {} not down".format(peer_ip)
    test_func = functools.partial(
        _check_route_not_installed, r1, "10.10.10.0/24", "show ip route 10.10.10.0/24 json"
    )
    _, res = topotest.run_and_expect(test_func, None, count=30, wait=1)
    assert res is None, "IPv4 route should be withdrawn when BFD is down"
    test_func = functools.partial(
        _check_route_not_installed, r1, "fd00::/64", "show ipv6 route fd00::/64 json"
    )
    _, res = topotest.run_and_expect(test_func, None, count=30, wait=1)
    assert res is None, "IPv6 route should be withdrawn when BFD is down"

    _ensure_link_up_bfd_up_and_routes(r1, r2)


def test_state_transition_up_to_admin_down():
    """
    Directed transition: UP -> shutdown (local administrative BFD shutdown).

    Trigger: ``bfd profile admin-test shutdown``; expect ``shutdown`` status
    while static routes remain installed (admin-down does not withdraw alone).
    """
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]
    r2 = tgen.gears["r2"]
    _ensure_link_up_bfd_up_and_routes(r1, r2)

    step("UP -> shutdown (admin down)")
    r1.vtysh_cmd(
        """
configure terminal
bfd
 profile admin-test
  shutdown
 exit
exit
"""
    )
    for peer_ip in ["192.168.1.2", "fc00::2"]:
        test_func = functools.partial(_check_bfd_status, r1, peer_ip, "shutdown")
        _, res = topotest.run_and_expect(test_func, None, count=10, wait=1)
        assert res is None, "BFD peer {} not shutdown".format(peer_ip)
    test_func = functools.partial(
        _check_route_installed, r1, "10.10.10.0/24", "show ip route 10.10.10.0/24 json"
    )
    _, res = topotest.run_and_expect(test_func, None, count=5, wait=1)
    assert res is None, "IPv4 route should remain during admin down"

    r1.vtysh_cmd(
        """
configure terminal
bfd
 profile admin-test
  no shutdown
 exit
exit
"""
    )
    for peer_ip in ["192.168.1.2", "fc00::2"]:
        test_func = functools.partial(_check_bfd_up, r1, peer_ip)
        _, res = topotest.run_and_expect(test_func, None, count=60, wait=1)
        assert res is None, "BFD peer {} did not return to up".format(peer_ip)


def test_state_transition_down_to_up():
    """
    Directed transition: DOWN -> UP (recovery after forwarding failure).

    Start from DOWN (link down), restore link; expect ``up`` and routes
    installed.
    """
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]
    r2 = tgen.gears["r2"]
    _ensure_link_up_bfd_up_and_routes(r1, r2)

    step("Reach DOWN first")
    r2.link_enable("r2-eth0", enabled=False)
    for peer_ip in ["192.168.1.2", "fc00::2"]:
        test_func = functools.partial(_check_bfd_status, r1, peer_ip, "down")
        _, res = topotest.run_and_expect(test_func, None, count=30, wait=1)
        assert res is None, "BFD peer {} not down".format(peer_ip)

    step("DOWN -> UP")
    r2.link_enable("r2-eth0", enabled=True)
    for peer_ip in ["192.168.1.2", "fc00::2"]:
        test_func = functools.partial(_check_bfd_up, r1, peer_ip)
        _, res = topotest.run_and_expect(test_func, None, count=60, wait=1)
        assert res is None, "BFD peer {} not up".format(peer_ip)
    test_func = functools.partial(
        _check_route_installed, r1, "10.10.10.0/24", "show ip route 10.10.10.0/24 json"
    )
    _, res = topotest.run_and_expect(test_func, None, count=30, wait=1)
    assert res is None, "IPv4 route not installed after DOWN->UP"
    test_func = functools.partial(
        _check_route_installed, r1, "fd00::/64", "show ipv6 route fd00::/64 json"
    )
    _, res = topotest.run_and_expect(test_func, None, count=30, wait=1)
    assert res is None, "IPv6 route not installed after DOWN->UP"


def test_state_transition_down_to_admin_down():
    """
    Directed transition: DOWN -> shutdown (admin down while session already down).

    Start from DOWN (link failure), apply profile shutdown; expect ``shutdown``.
    """
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]
    r2 = tgen.gears["r2"]
    _ensure_link_up_bfd_up_and_routes(r1, r2)

    r2.link_enable("r2-eth0", enabled=False)
    for peer_ip in ["192.168.1.2", "fc00::2"]:
        test_func = functools.partial(_check_bfd_status, r1, peer_ip, "down")
        _, res = topotest.run_and_expect(test_func, None, count=30, wait=1)
        assert res is None, "BFD peer {} not down".format(peer_ip)

    step("DOWN -> shutdown (admin down)")
    r1.vtysh_cmd(
        """
configure terminal
bfd
 profile admin-test
  shutdown
 exit
exit
"""
    )
    for peer_ip in ["192.168.1.2", "fc00::2"]:
        test_func = functools.partial(_check_bfd_status, r1, peer_ip, "shutdown")
        _, res = topotest.run_and_expect(test_func, None, count=10, wait=1)
        assert res is None, "BFD peer {} not shutdown".format(peer_ip)

    r1.vtysh_cmd(
        """
configure terminal
bfd
 profile admin-test
  no shutdown
 exit
exit
"""
    )
    r2.link_enable("r2-eth0", enabled=True)
    for peer_ip in ["192.168.1.2", "fc00::2"]:
        test_func = functools.partial(_check_bfd_up, r1, peer_ip)
        _, res = topotest.run_and_expect(test_func, None, count=60, wait=1)
        assert res is None, "BFD peer {} not up after cleanup".format(peer_ip)


def test_state_transition_admin_down_to_up():
    """
    Directed transition: shutdown -> UP (``no shutdown`` with path usable).

    Trigger: profile ``no shutdown`` after admin down; expect ``up`` and routes.
    """
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]
    r2 = tgen.gears["r2"]
    _ensure_link_up_bfd_up_and_routes(r1, r2)

    r1.vtysh_cmd(
        """
configure terminal
bfd
 profile admin-test
  shutdown
 exit
exit
"""
    )
    for peer_ip in ["192.168.1.2", "fc00::2"]:
        test_func = functools.partial(_check_bfd_status, r1, peer_ip, "shutdown")
        _, res = topotest.run_and_expect(test_func, None, count=10, wait=1)
        assert res is None, "BFD peer {} not shutdown".format(peer_ip)

    step("shutdown -> UP (admin up)")
    r1.vtysh_cmd(
        """
configure terminal
bfd
 profile admin-test
  no shutdown
 exit
exit
"""
    )
    for peer_ip in ["192.168.1.2", "fc00::2"]:
        test_func = functools.partial(_check_bfd_up, r1, peer_ip)
        _, res = topotest.run_and_expect(test_func, None, count=60, wait=1)
        assert res is None, "BFD peer {} not up".format(peer_ip)
    test_func = functools.partial(
        _check_route_installed, r1, "10.10.10.0/24", "show ip route 10.10.10.0/24 json"
    )
    _, res = topotest.run_and_expect(test_func, None, count=30, wait=1)
    assert res is None, "IPv4 route not installed after admin up"
    test_func = functools.partial(
        _check_route_installed, r1, "fd00::/64", "show ipv6 route fd00::/64 json"
    )
    _, res = topotest.run_and_expect(test_func, None, count=30, wait=1)
    assert res is None, "IPv6 route not installed after admin up"


def test_state_transition_admin_down_to_down():
    """
    Directed transition: shutdown -> DOWN (lift admin while peer is unreachable).

    Admin down, break forwarding, ``no shutdown``; BFD stays ``down`` until
    forwarding returns.
    """
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]
    r2 = tgen.gears["r2"]
    _ensure_link_up_bfd_up_and_routes(r1, r2)

    r1.vtysh_cmd(
        """
configure terminal
bfd
 profile admin-test
  shutdown
 exit
exit
"""
    )
    for peer_ip in ["192.168.1.2", "fc00::2"]:
        test_func = functools.partial(_check_bfd_status, r1, peer_ip, "shutdown")
        _, res = topotest.run_and_expect(test_func, None, count=10, wait=1)
        assert res is None, "BFD peer {} not shutdown".format(peer_ip)

    step("shutdown -> DOWN (unreachable peer after no shutdown)")
    r2.link_enable("r2-eth0", enabled=False)
    time.sleep(2)

    r1.vtysh_cmd(
        """
configure terminal
bfd
 profile admin-test
  no shutdown
 exit
exit
"""
    )
    for peer_ip in ["192.168.1.2", "fc00::2"]:
        test_func = functools.partial(_check_bfd_status, r1, peer_ip, "down")
        _, res = topotest.run_and_expect(test_func, None, count=30, wait=1)
        assert res is None, "BFD peer {} not down".format(peer_ip)

    r2.link_enable("r2-eth0", enabled=True)
    for peer_ip in ["192.168.1.2", "fc00::2"]:
        test_func = functools.partial(_check_bfd_up, r1, peer_ip)
        _, res = topotest.run_and_expect(test_func, None, count=60, wait=1)
        assert res is None, "BFD peer {} not up after link restore".format(peer_ip)


def test_memory_leak():
    """Run the memory leak test and report results."""
    tgen = get_topogen()
    if not tgen.is_memleak_enabled():
        pytest.skip("Memory leak test/report is disabled")

    tgen.report_memory_leaks()


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
