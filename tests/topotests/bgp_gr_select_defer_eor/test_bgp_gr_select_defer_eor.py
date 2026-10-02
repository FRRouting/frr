#!/usr/bin/env python
# SPDX-License-Identifier: ISC

# Copyright (c) 2026 Nvidia Inc.
#                    Donald Sharp

"""
Best-path must run when End-of-RIB arrives, including on a second deferral.

r1 is the graceful-restart speaker. r2 originates 102.0.20.1/32. r3 learns
that prefix only from r1.

The first config load starts selection deferral while the startup timer is
running. End-of-RIB from r3 finishes that cycle and sets select_defer_over.
That flag is never cleared. r2 is held shutdown so its prefix is not
learned during this cycle.

Helpers advertise the R bit while their own startup timer runs. They are
shut and unshut first; their restart-time is 1s, so that timer expires
before r2 is allowed to connect and the new OPEN has no R bit.

`bgp shutdown` / `no bgp shutdown` on r1 re-arms r1's startup timer for
the configured 3600s and lets r3 finish the first cycle. A later
`vtysh -f` load sends XFRR_end_configuration, which runs
peer_unshut_after_cfg() and starts another selection-deferral timer.
A plain configure-terminal session does not. That function does not
look at select_defer_over. The test waits until the timer is visible,
then unshuts r2. Routes learned while it is running stay unselected,
because End-of-RIB skips bgp_gr_check_path_select() once
select_defer_over is set.

select-defer-time is 3600s so a busy CI host cannot pass by waiting the
timer out. The post-EOR check is 120s.
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
from lib.topogen import Topogen, get_topogen
from lib.common_config import step

pytestmark = [pytest.mark.bgpd]

PREFIX = "102.0.20.1/32"
R2_NEIGHBOR = "192.168.12.2"
R3_NEIGHBOR = "192.168.13.3"
HELPERS = (("r2", R2_NEIGHBOR, 65002), ("r3", R3_NEIGHBOR, 65003))
# 40 * 3s = 120s. Above run_and_expect's 15s floor, and far below the
# 3600s select-defer-time configured on r1.
POLL_COUNT = 40
POLL_WAIT = 3


def build_topo(tgen):
    for routern in range(1, 4):
        tgen.add_router("r{}".format(routern))

    switch = tgen.add_switch("s1")
    switch.add_link(tgen.gears["r1"])
    switch.add_link(tgen.gears["r2"])

    switch = tgen.add_switch("s2")
    switch.add_link(tgen.gears["r1"])
    switch.add_link(tgen.gears["r3"])


def setup_module(mod):
    tgen = Topogen(build_topo, mod.__name__)
    tgen.start_topology()

    for rname, router in tgen.routers().items():
        router.load_frr_config(os.path.join(CWD, "{}/frr.conf".format(rname)))

    tgen.start_router()


def teardown_module(mod):
    tgen = get_topogen()
    tgen.stop_topology()


def _bgp_json(router, cmd):
    raw = router.vtysh_cmd(cmd)
    try:
        return json.loads(raw)
    except json.JSONDecodeError:
        return {"_parse_error": raw.strip()}


def _neighbor(router, neighbor):
    data = _bgp_json(router, "show bgp ipv4 neighbor {} json".format(neighbor))
    return data.get(neighbor, data)


def _gr(entry):
    return entry.get("gracefulRestartInfo", {})


def _deferral_remaining(router, neighbor):
    timers = _gr(_neighbor(router, neighbor)).get("ipv4Unicast", {}).get("timers", {})
    return timers.get("selectionDeferralTimerRemaining")


def _eor_received(router, neighbor):
    return _gr(_neighbor(router, neighbor)).get("endOfRibRecv", {}).get(
        "ipv4Unicast"
    ) is True


def _path_is_best(path):
    # Prefix detail JSON uses {"overall": true}. Table JSON uses a boolean.
    best = path.get("bestpath")
    if best is True:
        return True
    if isinstance(best, dict):
        return best.get("overall") is True
    return False


def _prefix_best(router):
    data = _bgp_json(router, "show bgp ipv4 unicast {} json".format(PREFIX))
    paths = data.get("paths") or []
    if not paths:
        return False, data
    return _path_is_best(paths[0]), paths[0]


def _set_shutdown(router, asn, shut):
    router.vtysh_cmd(
        """
        configure terminal
        router bgp {}
         {}bgp shutdown
        """.format(asn, "" if shut else "no ")
    )


def test_second_deferral_selects_bestpath_on_eor():
    """End-of-RIB must end a deferral timer started after the first cycle."""
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]
    r3 = tgen.gears["r3"]

    step("Re-arm helper startup timers for their configured 1s restart-time")
    for name, _peer, asn in HELPERS:
        _set_shutdown(tgen.gears[name], asn, True)
        _set_shutdown(tgen.gears[name], asn, False)

    def _first_deferral_done():
        if not _eor_received(r1, R3_NEIGHBOR):
            return "r1 has not received IPv4 End-of-RIB from r3"
        remaining = _deferral_remaining(r1, R3_NEIGHBOR)
        if remaining is not None:
            return "first deferral timer still running ({}s left)".format(
                remaining
            )
        return None

    step("Wait for the first selection deferral to finish on End-of-RIB")
    test_func = functools.partial(_first_deferral_done)
    _, result = topotest.run_and_expect(
        test_func, None, count=POLL_COUNT, wait=POLL_WAIT
    )
    assert result is None, "First GR deferral did not finish: {}".format(
        result
    )

    step("Re-arm r1's startup timer and let r3 finish the first cycle")
    _set_shutdown(r1, 65001, True)
    _set_shutdown(r1, 65001, False)

    def _first_cycle_after_rearm():
        entry = _neighbor(r1, R3_NEIGHBOR)
        if entry.get("bgpState") != "Established":
            return "r1-r3 is {}".format(entry.get("bgpState"))
        if not _gr(entry).get("endOfRibRecv", {}).get("ipv4Unicast"):
            return "IPv4 End-of-RIB not received from r3 after re-arm"
        remaining = _deferral_remaining(r1, R3_NEIGHBOR)
        if remaining is not None:
            return "deferral timer still running after r3 End-of-RIB ({}s)".format(
                remaining
            )
        return None

    test_func = functools.partial(_first_cycle_after_rearm)
    _, result = topotest.run_and_expect(
        test_func, None, count=POLL_COUNT, wait=POLL_WAIT
    )
    assert result is None, "First cycle did not finish after re-arm: {}".format(
        result
    )

    # peer_unshut_after_cfg() runs only from XFRR_end_configuration,
    # which vtysh -f emits. A configure-terminal session does not.
    # r3 is already up, so this load does not open a new session.
    step("Load config through vtysh -f while the startup timer is running")
    r1.vtysh_multicmd(
        """
        router bgp 65001
         bgp graceful-restart select-defer-time 3600
        """,
        pretty_output=False,
    )

    def _second_timer_running():
        entry = _neighbor(r1, R3_NEIGHBOR)
        if entry.get("bgpState") != "Established":
            return "r1-r3 is {}".format(entry.get("bgpState"))
        remaining = _deferral_remaining(r1, R3_NEIGHBOR)
        if remaining is None:
            return "second selection-deferral timer is not running"
        return None

    step("Wait until the second selection-deferral timer is running")
    test_func = functools.partial(_second_timer_running)
    _, result = topotest.run_and_expect(
        test_func, None, count=POLL_COUNT, wait=POLL_WAIT
    )
    assert result is None, "Second deferral timer did not start: {}".format(
        result
    )

    step("Unshut r2 so its prefix arrives during the second deferral")
    r1.vtysh_cmd(
        """
        configure terminal
        router bgp 65001
         no neighbor 192.168.12.2 shutdown
        """
    )

    def _eor_from_r2():
        entry = _neighbor(r1, R2_NEIGHBOR)
        state = entry.get("bgpState")
        if state != "Established":
            return "r1-r2 is {}".format(state)
        if _gr(entry).get("rBit") is True:
            tgen.gears["r2"].vtysh_cmd("clear bgp *")
            return "r2 is still advertising the R bit"
        if not _gr(entry).get("endOfRibRecv", {}).get("ipv4Unicast"):
            return "IPv4 End-of-RIB not received from r2"
        return None

    step("Wait for r2's End-of-RIB")
    test_func = functools.partial(_eor_from_r2)
    _, result = topotest.run_and_expect(
        test_func, None, count=POLL_COUNT, wait=POLL_WAIT
    )
    assert result is None, "r2 did not send End-of-RIB: {}".format(result)

    def _bestpath_after_eor():
        if not _eor_received(r1, R2_NEIGHBOR):
            return "IPv4 End-of-RIB from r2 went away"
        best, path = _prefix_best(r1)
        remaining = _deferral_remaining(r1, R2_NEIGHBOR)
        if not best:
            return (
                "{} not best after End-of-RIB (valid={}, "
                "deferralRemaining={})".format(
                    PREFIX, path.get("valid"), remaining
                )
            )
        best, path = _prefix_best(r3)
        if not best:
            return "r3 has not learned {} after End-of-RIB ({})".format(
                PREFIX, path
            )
        if remaining is not None:
            return "selection deferral still running ({}s left)".format(
                remaining
            )
        return None

    step("Best-path must run without waiting out select-defer-time")
    test_func = functools.partial(_bestpath_after_eor)
    _, result = topotest.run_and_expect(
        test_func, None, count=POLL_COUNT, wait=POLL_WAIT
    )
    assert result is None, "Selection stayed deferred after End-of-RIB: {}".format(
        result
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
