#!/usr/bin/env python
# SPDX-License-Identifier: ISC
#
# test_frr_reload_vrf_scale.py
#
# Copyright (c) 2026 by Nvidia, Inc.
#
"""
frr-reload.py VRF knob apply/rollback correctness + scale.

This suite drives tools/frr-reload.py "--reload" (the real apply path that
contains the per-VRF batch-delete logic) to prove that:

  1. Every command that can live under "vrf NAME" (see vrf_knobs.py, derived
     from the install_element(VRF_NODE, ...) sites) applies cleanly and shows
     up in running-config, and rolls back cleanly (round-trips).

  2. At scale (many VRFs), unsetting all VRF knobs in one reload takes the
     batch "vtysh -f" delete path - not the per-line "vtysh -c" path that
     caused the reload timeouts - and completes well within a time budget.

  3. When the batch "vtysh -f" fails, frr-reload falls back to per-line deletes
     and the config still converges (see test_batch_delete_fallback).

No PIM/EVPN adjacency is required here: these tests verify that frr-reload
computes and applies the correct add/delete deltas and that no daemon crashes.
End-to-end dataplane (host traffic through the VRF, PIM multicast) is covered by
the companion dataplane test.

Scale knobs (override via env):
  FRR_RELOAD_VRF_SCALE       number of VRFs for the all-knob scale test (150)
  FRR_RELOAD_VRF_BIG         number of VRFs for the big static-route test (150)
  FRR_RELOAD_VRF_ROUTES      static routes per VRF for the big test (200)
  FRR_RELOAD_VRF_FALLBACK    number of VRFs for the batch-failure test (2)
  FRR_RELOAD_VRF_TIMEOUT     reload budget in seconds; defaults to 120 (the
                             TimeoutSec in tools/frr.service)
"""

import os
import sys

import pytest

CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, ".."))

from lib.topogen import Topogen
from lib.topolog import logger

import vrf_knobs as K
import frr_reload_lib as R

pytestmark = [pytest.mark.bgpd, pytest.mark.pimd, pytest.mark.staticd]

SCALE_N = int(os.environ.get("FRR_RELOAD_VRF_SCALE", "150"))
BIG_N = int(os.environ.get("FRR_RELOAD_VRF_BIG", "150"))
ROUTES_PER_VRF = int(os.environ.get("FRR_RELOAD_VRF_ROUTES", "200"))
# Kept deliberately small: the fallback test drives the per-line delete path.
FALLBACK_N = int(os.environ.get("FRR_RELOAD_VRF_FALLBACK", "2"))

# The reload budget is the ceiling systemd enforces on ExecReload (frr-reload):
# TimeoutSec in tools/frr.service (currently 2m -> 120s). A reload that crosses
# this in the field is killed mid-flight. We assert it on the rollback/delete
# reloads - the path this fix changes and the field pain point (scaled VRF
# rollback) - to catch a regression back to the per-line "vtysh -c" behaviour
# (minutes at scale). Apply reloads are pure additions (always batched) and are
# only logged, not budget-asserted. Override with FRR_RELOAD_VRF_TIMEOUT if a
# contended CI sandbox needs headroom.
RELOAD_TIMEOUT = float(os.environ.get("FRR_RELOAD_VRF_TIMEOUT", "120"))

# Knob set used for the "all knobs" tests. Everything in the catalog.
ALL = K.ALL_KNOBS
# Daemon names for load_frr_config (strings, not RD_* ints — bare ints are
# unpacked as (daemon, param) tuples and raise TypeError).
NEEDED_DAEMONS = ["zebra", "staticd", "bgpd", "pimd", "pim6d"]


def _conf_path(tgen, rname="r1"):
    d = os.path.join(tgen.logdir, rname)
    os.makedirs(d, exist_ok=True)
    return os.path.join(d, "gen-frr.conf")


def _base_lines(n):
    """Base config: hostname, global prereqs, and n empty vrf stanzas."""
    lines = ["hostname r1", "!"]
    lines += K.global_prereqs()
    lines.append("!")
    for i in range(1, n + 1):
        lines.append("vrf {}".format(K.vrf_name(i)))
        lines.append("exit-vrf")
        lines.append("!")
    return lines


def _full_lines(n, knobs, routes_v4=0, routes_v6=0):
    """Base config plus n vrf stanzas populated with `knobs` (+ static routes)."""
    lines = ["hostname r1", "!"]
    lines += K.global_prereqs()
    lines.append("!")
    for i in range(1, n + 1):
        if routes_v4 or routes_v6:
            lines += K.vrf_stanza_scale_routes(i, routes_v4, routes_v6, knobs)
        else:
            lines += K.vrf_stanza(i, knobs)
    return lines


def _assert_daemons_healthy(tgen):
    for rname, router in tgen.routers().items():
        status = router.check_router_running()
        assert status == "", "router {} unhealthy after reload: {}".format(
            rname, status
        )


@pytest.fixture(scope="module")
def tgen(request):
    """Single router with SCALE_N kernel VRFs; config driven via frr-reload."""

    def build(tg):
        tg.add_router("r1")
        # A couple of switches so r1 has interfaces (not required by the knobs,
        # but keeps the node realistic and lets the dataplane test share shape).
        for s in range(1, 3):
            sw = tg.add_switch("sw{}".format(s))
            sw.add_link(tg.gears["r1"])

    tg = Topogen(build, request.module.__name__)
    tg.start_topology()

    r1 = tg.gears["r1"]

    # Create the kernel VRFs up front so both individual and scale tests can use
    # any index up to BIG_N.
    nvrfs = max(SCALE_N, BIG_N)
    logger.info("creating %d kernel VRFs on r1", nvrfs)
    for i in range(1, nvrfs + 1):
        r1.net.add_l3vrf(K.vrf_name(i), str(K.vrf_table_id(i)))

    # Start with the base config (empty vrf stanzas + prereqs).
    base_path = os.path.join(CWD, "r1")
    os.makedirs(base_path, exist_ok=True)
    startup = os.path.join(base_path, "frr.conf")
    with open(startup, "w", encoding="ascii") as fh:
        fh.write("\n".join(_base_lines(nvrfs)) + "\n")

    r1.load_frr_config(startup, daemons=NEEDED_DAEMONS)
    tg.start_router()

    yield tg
    tg.stop_topology()


def test_individual_knob_roundtrip(tgen):
    """Each VRF knob, one at a time on a single VRF: apply -> verify present,
    rollback -> verify absent, and confirm the delete used the batch path."""
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]
    conf = _conf_path(tgen)
    base = _base_lines(SCALE_N)

    for knob in ALL:
        # apply just this knob on vrf1
        full = _inject_knob(_base_lines(SCALE_N), 1, knob)

        logger.info("individual knob: %s", knob["id"])
        R.apply_and_verify(r1, conf, full)
        R.assert_lines_present(r1, knob["lines"](1))
        _assert_daemons_healthy(tgen)

        # rollback to base -> the single vrf line is deleted via the batch path
        res = R.apply_and_verify(r1, conf, base, expect_vrf_batch=True)
        R.assert_lines_absent(r1, knob["lines"](1))
        _assert_daemons_healthy(tgen)
        logger.info(
            "knob %s round-trip ok (rollback %.2fs, batch=%s)",
            knob["id"],
            res.elapsed,
            res.vrf_batch_attempted,
        )


def test_all_knobs_one_vrf(tgen):
    """All knobs together on a single VRF: apply, verify, rollback, verify."""
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]
    conf = _conf_path(tgen)
    base = _base_lines(SCALE_N)

    full = _inject_knob_all(_base_lines(SCALE_N), 1, ALL)
    R.apply_and_verify(r1, conf, full)
    R.assert_lines_present(r1, K.expected_running_lines(1, ALL))
    _assert_daemons_healthy(tgen)

    res = R.apply_and_verify(r1, conf, base, expect_vrf_batch=True)
    R.assert_lines_absent(r1, K.expected_running_lines(1, ALL))
    _assert_daemons_healthy(tgen)
    logger.info("all-knobs one-vrf rollback %.2fs", res.elapsed)


def test_batch_delete_fallback(tgen):
    """Negative path: make the batch "vtysh -f" fail and confirm frr-reload
    falls back to per-line deletes and still converges.

    Deliberately tiny. The fallback is the per-line "vtysh -c" path that
    batching exists to avoid, so this uses FALLBACK_N VRFs and only the
    zebra/static knobs - a handful of deletes, which stays comfortably inside
    the reload budget even though every one of them is its own vtysh run.
    """
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]
    conf = _conf_path(tgen)
    knobs = K.ZEBRA_KNOBS + K.STATIC_KNOBS
    base = _base_lines(SCALE_N)

    full = base
    for i in range(1, FALLBACK_N + 1):
        full = _inject_knob_all(full, i, knobs)

    # Apply through the real vtysh.
    R.apply_and_verify(r1, conf, full)
    for i in range(1, FALLBACK_N + 1):
        R.assert_lines_present(r1, K.expected_running_lines(i, knobs))
    _assert_daemons_healthy(tgen)

    # Roll back with a vtysh that rejects the batch file. The batch applies
    # nothing, so every knob below has to be removed by the fallback - which is
    # the property worth testing, not just that the warning got logged.
    bindir = R.make_failing_batch_vtysh(
        r1, os.path.join(tgen.logdir, "r1", "shim-bin")
    )
    res = R.apply_and_verify(
        r1,
        conf,
        base,
        expect_vrf_batch="fallback",
        max_seconds=RELOAD_TIMEOUT,
        extra_args=["--bindir", bindir],
    )
    for i in range(1, FALLBACK_N + 1):
        R.assert_lines_absent(r1, K.expected_running_lines(i, knobs))
    _assert_daemons_healthy(tgen)
    logger.info(
        "FALLBACK: %d VRFs x %d knobs unset via the per-line path in %.2fs",
        FALLBACK_N,
        len(knobs),
        res.elapsed,
    )


def test_scale_all_knobs(tgen):
    """SCALE_N VRFs, all knobs each: apply, then unset everything in one reload
    and confirm it takes the batch delete path within budget."""
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]
    conf = _conf_path(tgen)
    base = _base_lines(SCALE_N)
    full = _full_lines(SCALE_N, ALL)

    logger.info("scale apply: %d VRFs x %d knobs", SCALE_N, len(ALL))
    # Apply is pure additions (always batched); it is not the delete path the
    # fix touches, so log its time for visibility but don't budget-assert it.
    res = R.apply_and_verify(r1, conf, full)
    logger.info("scale apply of %d VRFs took %.2fs", SCALE_N, res.elapsed)
    # Spot-check a few VRFs rather than all N.
    sample_vrfs = (1, max(1, SCALE_N // 2), SCALE_N)
    for i in dict.fromkeys(sample_vrfs):
        R.assert_lines_present(r1, K.expected_running_lines(i, ALL))
    _assert_daemons_healthy(tgen)

    logger.info("scale rollback: unset all %d VRFs in one reload", SCALE_N)
    res = R.apply_and_verify(
        r1, conf, base, expect_vrf_batch=True, max_seconds=RELOAD_TIMEOUT
    )
    for i in dict.fromkeys(sample_vrfs):
        R.assert_lines_absent(r1, K.expected_running_lines(i, ALL))
    _assert_daemons_healthy(tgen)
    logger.info(
        "SCALE ROLLBACK: %d VRFs unset in %.2fs (batch path)", SCALE_N, res.elapsed
    )


def test_scale_big_static_routes(tgen):
    """BIG_N VRFs with ROUTES_PER_VRF static routes + zebra knobs each; unset in
    one reload. This is the closest analogue to the field rollback scenario."""
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]
    conf = _conf_path(tgen)

    # Use zebra + static knobs at big scale (the field case: L3VNI + lots of
    # static routes). PIM at BIG_N would multiply daemon work without adding
    # signal to the reload-batch measurement.
    knobs = K.ZEBRA_KNOBS + K.STATIC_KNOBS
    base = _base_lines(BIG_N)
    full = _full_lines(BIG_N, knobs, routes_v4=ROUTES_PER_VRF)

    logger.info(
        "big apply: %d VRFs x (%d knobs + %d static routes)",
        BIG_N,
        len(knobs),
        ROUTES_PER_VRF,
    )
    # Apply is pure additions (always batched); it is not the delete path the
    # fix touches, so log its time for visibility but don't budget-assert it.
    res = R.apply_and_verify(r1, conf, full)
    logger.info(
        "big apply of %d VRFs (%d routes each) took %.2fs",
        BIG_N,
        ROUTES_PER_VRF,
        res.elapsed,
    )
    _assert_daemons_healthy(tgen)

    logger.info("big rollback: unset all %d VRFs in one reload", BIG_N)
    res = R.apply_and_verify(
        r1, conf, base, expect_vrf_batch=True, max_seconds=RELOAD_TIMEOUT
    )
    _assert_daemons_healthy(tgen)
    logger.info(
        "BIG ROLLBACK: %d VRFs (%d routes each) unset in %.2fs (batch path)",
        BIG_N,
        ROUTES_PER_VRF,
        res.elapsed,
    )


# ---------------------------------------------------------------------------
# helpers to splice knob lines into a base config's vrf stanza
# ---------------------------------------------------------------------------


def _inject_knob(lines, i, knob):
    return _inject_knob_all(lines, i, [knob])


def _inject_knob_all(lines, i, knobs):
    """Return a copy of `lines` with `knobs` inserted into vrf i's stanza."""
    marker = "vrf {}".format(K.vrf_name(i))
    out = []
    j = 0
    while j < len(lines):
        out.append(lines[j])
        if lines[j] == marker:
            # next line is "exit-vrf"; inject before it
            for kn in knobs:
                for ln in kn["lines"](i):
                    out.append(" " + ln)
        j += 1
    return out


if __name__ == "__main__":
    args = ["-s", "-v"] + sys.argv[1:]
    sys.exit(pytest.main(args))
