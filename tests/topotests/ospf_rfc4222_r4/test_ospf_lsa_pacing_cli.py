#!/usr/bin/env python
# -*- coding: utf-8 eval: (blacken-mode 1) -*-
# SPDX-License-Identifier: ISC
#
# test_ospf_lsa_pacing_cli.py
# Part of NetDEF Topology Tests
#
# Copyright (c) 2026 by
# Network Device Education Foundation, Inc. ("NetDEF")
#

"""
test_ospf_lsa_pacing_cli.py: Test OSPF RFC4222/R4 LSA Gap Pacing CLI

Tests LSA gap pacing configuration persistence and functionality:
1. Enable / disable
2. Each sub-parameter set and removed via no-form
3. Config persistence via write memory
4. Config persistence across interface flap
5. Config persistence across ospfd restart
6. Input validation (min > max, low >= high rejected)
7. Default values not written to running-config
8. All parameters combined
"""

import pytest
import time

from lib.topogen import Topogen


pytestmark = [pytest.mark.ospfd]


def build_topo(tgen):
    r1 = tgen.add_router("r1")
    r2 = tgen.add_router("r2")

    tgen.add_link(r1, r2, ifname1="eth1", ifname2="eth1")


@pytest.fixture(scope="function")
def tgen(request):
    tgen = Topogen(build_topo, request.module.__name__)
    tgen.start_topology()

    router_list = tgen.routers()

    for _, router in router_list.items():
        router.load_frr_config("frr.conf")

    tgen.start_router()

    yield tgen

    tgen.stop_topology()


# ---------------------------------------------------------------------------
# Enable / disable
# ---------------------------------------------------------------------------

def test_lsa_pacing_enable(tgen):
    """Test that ip ospf lsa-pacing appears in running-config after enable."""

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]

    r1.vtysh_cmd(
        "configure terminal\n"
        "interface eth1\n"
        "ip ospf lsa-pacing\n"
        "end"
    )

    running_config = r1.vtysh_cmd("show running-config")

    assert "ip ospf lsa-pacing" in running_config, \
        "ip ospf lsa-pacing not in running config after enable"


def test_lsa_pacing_disable(tgen):
    """Test that no ip ospf lsa-pacing removes it from running-config."""

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]

    r1.vtysh_cmd(
        "configure terminal\n"
        "interface eth1\n"
        "ip ospf lsa-pacing\n"
        "end"
    )

    r1.vtysh_cmd(
        "configure terminal\n"
        "interface eth1\n"
        "no ip ospf lsa-pacing\n"
        "end"
    )

    running_config = r1.vtysh_cmd("show running-config")

    assert "ip ospf lsa-pacing" not in running_config, \
        "ip ospf lsa-pacing still in running config after disable"


# ---------------------------------------------------------------------------
# Sub-parameter: initial-gap
# ---------------------------------------------------------------------------

def test_lsa_pacing_initial_gap(tgen):
    """Test initial-gap set and removed."""

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]

    r1.vtysh_cmd(
        "configure terminal\n"
        "interface eth1\n"
        "ip ospf lsa-pacing\n"
        "ip ospf lsa-pacing initial-gap 50\n"
        "end"
    )

    running_config = r1.vtysh_cmd("show running-config")

    assert "ip ospf lsa-pacing initial-gap 50" in running_config, \
        "initial-gap 50 not in running config"

    r1.vtysh_cmd(
        "configure terminal\n"
        "interface eth1\n"
        "no ip ospf lsa-pacing initial-gap\n"
        "end"
    )

    running_config = r1.vtysh_cmd("show running-config")

    assert "initial-gap" not in running_config, \
        "initial-gap still present after removal"


def test_lsa_pacing_initial_gap_before_minmax(tgen):
    """initial-gap > default max (1000) set BEFORE min-gap/max-gap.

    Before the fix the VTY handler silently clamped to OSPF_GAP_MAX_MS_DEFAULT
    (1000) because max-gap was not yet configured.  After the fix, the value is
    accepted as-is and stored; rejection only occurs when explicit min/max are
    already set and the value falls outside them.
    """

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]

    r1.vtysh_cmd(
        "configure terminal\n"
        "interface eth1\n"
        "ip ospf lsa-pacing\n"
        "ip ospf lsa-pacing initial-gap 2000\n"
        "ip ospf lsa-pacing min-gap 200 max-gap 2000\n"
        "end"
    )

    running_config = r1.vtysh_cmd("show running-config")

    assert "ip ospf lsa-pacing initial-gap 2000" in running_config, \
        "initial-gap 2000 was silently clamped — ordering bug not fixed"


def test_lsa_pacing_initial_gap_after_minmax(tgen):
    """initial-gap set AFTER min-gap/max-gap — value within bounds accepted."""

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]

    r1.vtysh_cmd(
        "configure terminal\n"
        "interface eth1\n"
        "ip ospf lsa-pacing\n"
        "ip ospf lsa-pacing min-gap 200 max-gap 2000\n"
        "ip ospf lsa-pacing initial-gap 1500\n"
        "end"
    )

    running_config = r1.vtysh_cmd("show running-config")

    assert "ip ospf lsa-pacing initial-gap 1500" in running_config, \
        "initial-gap 1500 (within configured min/max) not accepted"


def test_lsa_pacing_initial_gap_at_boundaries(tgen):
    """initial-gap equal to min-gap and max-gap boundaries is accepted."""

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]

    # At min boundary
    r1.vtysh_cmd(
        "configure terminal\n"
        "interface eth1\n"
        "ip ospf lsa-pacing\n"
        "ip ospf lsa-pacing min-gap 100 max-gap 500\n"
        "ip ospf lsa-pacing initial-gap 100\n"
        "end"
    )
    running_config = r1.vtysh_cmd("show running-config")
    assert "ip ospf lsa-pacing initial-gap 100" in running_config, \
        "initial-gap equal to min-gap not accepted"

    # At max boundary
    r1.vtysh_cmd(
        "configure terminal\n"
        "interface eth1\n"
        "ip ospf lsa-pacing initial-gap 500\n"
        "end"
    )
    running_config = r1.vtysh_cmd("show running-config")
    assert "ip ospf lsa-pacing initial-gap 500" in running_config, \
        "initial-gap equal to max-gap not accepted"


def test_lsa_pacing_initial_gap_rejected_below_min(tgen):
    """initial-gap below configured min-gap is rejected with an error."""

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]

    r1.vtysh_cmd(
        "configure terminal\n"
        "interface eth1\n"
        "ip ospf lsa-pacing\n"
        "ip ospf lsa-pacing min-gap 200 max-gap 1000\n"
        "end"
    )

    r1.vtysh_cmd(
        "configure terminal\n"
        "interface eth1\n"
        "ip ospf lsa-pacing initial-gap 50\n"
        "end"
    )

    running_config = r1.vtysh_cmd("show running-config")
    assert "ip ospf lsa-pacing initial-gap 50" not in running_config, \
        "initial-gap below min-gap was accepted — validation broken"


def test_lsa_pacing_initial_gap_rejected_above_max(tgen):
    """initial-gap above configured max-gap is rejected with an error."""

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]

    r1.vtysh_cmd(
        "configure terminal\n"
        "interface eth1\n"
        "ip ospf lsa-pacing\n"
        "ip ospf lsa-pacing min-gap 100 max-gap 500\n"
        "end"
    )

    r1.vtysh_cmd(
        "configure terminal\n"
        "interface eth1\n"
        "ip ospf lsa-pacing initial-gap 2000\n"
        "end"
    )

    running_config = r1.vtysh_cmd("show running-config")
    assert "ip ospf lsa-pacing initial-gap 2000" not in running_config, \
        "initial-gap above max-gap was accepted — validation broken"


def test_lsa_pacing_minmax_clamps_existing_initial_gap(tgen):
    """When min-gap/max-gap is set after initial-gap, initial-gap is clamped.

    If initial-gap 2000 is set first (no min/max configured yet), then
    min-gap 100 max-gap 500 is applied, the min-max handler clamps the
    stored initial-gap to max-gap (500).
    """

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]

    r1.vtysh_cmd(
        "configure terminal\n"
        "interface eth1\n"
        "ip ospf lsa-pacing\n"
        "ip ospf lsa-pacing initial-gap 2000\n"
        "ip ospf lsa-pacing min-gap 100 max-gap 500\n"
        "end"
    )

    running_config = r1.vtysh_cmd("show running-config")

    # initial-gap 2000 must be clamped to max-gap 500 by the min-max handler
    assert "ip ospf lsa-pacing initial-gap 2000" not in running_config, \
        "initial-gap was not clamped when min-gap/max-gap set below it"
    assert "ip ospf lsa-pacing initial-gap 500" in running_config, \
        "initial-gap not clamped to max-gap=500"


# ---------------------------------------------------------------------------
# Sub-parameter: min-gap / max-gap
# ---------------------------------------------------------------------------

def test_lsa_pacing_min_max_gap(tgen):
    """Test min-gap/max-gap set and removed."""

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]

    r1.vtysh_cmd(
        "configure terminal\n"
        "interface eth1\n"
        "ip ospf lsa-pacing\n"
        "ip ospf lsa-pacing min-gap 5 max-gap 500\n"
        "end"
    )

    running_config = r1.vtysh_cmd("show running-config")

    assert "ip ospf lsa-pacing min-gap 5 max-gap 500" in running_config, \
        "min-gap/max-gap not in running config"

    r1.vtysh_cmd(
        "configure terminal\n"
        "interface eth1\n"
        "no ip ospf lsa-pacing min-gap 5 max-gap 500\n"
        "end"
    )

    running_config = r1.vtysh_cmd("show running-config")

    assert "min-gap" not in running_config, "min-gap still present after removal"
    assert "max-gap" not in running_config, "max-gap still present after removal"


# ---------------------------------------------------------------------------
# Sub-parameter: factor
# ---------------------------------------------------------------------------

def test_lsa_pacing_factor(tgen):
    """Test factor set and removed."""

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]

    r1.vtysh_cmd(
        "configure terminal\n"
        "interface eth1\n"
        "ip ospf lsa-pacing\n"
        "ip ospf lsa-pacing factor 2\n"
        "end"
    )

    running_config = r1.vtysh_cmd("show running-config")

    assert "ip ospf lsa-pacing factor 2" in running_config, \
        "factor 2 not in running config"

    r1.vtysh_cmd(
        "configure terminal\n"
        "interface eth1\n"
        "no ip ospf lsa-pacing factor\n"
        "end"
    )

    running_config = r1.vtysh_cmd("show running-config")

    assert "lsa-pacing factor" not in running_config, \
        "factor still present after removal"


# ---------------------------------------------------------------------------
# Sub-parameter: adjust-interval
# ---------------------------------------------------------------------------

def test_lsa_pacing_adjust_interval(tgen):
    """Test adjust-interval set and removed."""

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]

    r1.vtysh_cmd(
        "configure terminal\n"
        "interface eth1\n"
        "ip ospf lsa-pacing\n"
        "ip ospf lsa-pacing adjust-interval 200\n"
        "end"
    )

    running_config = r1.vtysh_cmd("show running-config")

    assert "ip ospf lsa-pacing adjust-interval 200" in running_config, \
        "adjust-interval 200 not in running config"

    r1.vtysh_cmd(
        "configure terminal\n"
        "interface eth1\n"
        "no ip ospf lsa-pacing adjust-interval\n"
        "end"
    )

    running_config = r1.vtysh_cmd("show running-config")

    assert "adjust-interval" not in running_config, \
        "adjust-interval still present after removal"


# ---------------------------------------------------------------------------
# Sub-parameter: watermarks
# ---------------------------------------------------------------------------

def test_lsa_pacing_watermarks(tgen):
    """Test low-watermark/high-watermark set and removed."""

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]

    r1.vtysh_cmd(
        "configure terminal\n"
        "interface eth1\n"
        "ip ospf lsa-pacing\n"
        "ip ospf lsa-pacing low-watermark 10 high-watermark 50\n"
        "end"
    )

    running_config = r1.vtysh_cmd("show running-config")

    assert "ip ospf lsa-pacing low-watermark 10 high-watermark 50" in running_config, \
        "watermarks not in running config"

    r1.vtysh_cmd(
        "configure terminal\n"
        "interface eth1\n"
        "no ip ospf lsa-pacing low-watermark 10 high-watermark 50\n"
        "end"
    )

    running_config = r1.vtysh_cmd("show running-config")

    assert "low-watermark" not in running_config, \
        "low-watermark still present after removal"
    assert "high-watermark" not in running_config, \
        "high-watermark still present after removal"


# ---------------------------------------------------------------------------
# Sub-parameter: max-lsas-per-update
# ---------------------------------------------------------------------------

def test_lsa_pacing_max_lsas(tgen):
    """Test max-lsas-per-update set and removed."""

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]

    r1.vtysh_cmd(
        "configure terminal\n"
        "interface eth1\n"
        "ip ospf lsa-pacing\n"
        "ip ospf lsa-pacing max-lsas-per-update 20\n"
        "end"
    )

    running_config = r1.vtysh_cmd("show running-config")

    assert "ip ospf lsa-pacing max-lsas-per-update 20" in running_config, \
        "max-lsas-per-update 20 not in running config"

    r1.vtysh_cmd(
        "configure terminal\n"
        "interface eth1\n"
        "no ip ospf lsa-pacing max-lsas-per-update\n"
        "end"
    )

    running_config = r1.vtysh_cmd("show running-config")

    assert "max-lsas-per-update" not in running_config, \
        "max-lsas-per-update still present after removal"


# ---------------------------------------------------------------------------
# Validation
# ---------------------------------------------------------------------------

def test_lsa_pacing_validation_min_max(tgen):
    """min-gap must be <= max-gap; router must reject min > max."""

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]

    r1.vtysh_cmd(
        "configure terminal\n"
        "interface eth1\n"
        "ip ospf lsa-pacing min-gap 1000 max-gap 5\n"
        "end"
    )

    running_config = r1.vtysh_cmd("show running-config")

    assert "min-gap 1000" not in running_config, \
        "Router accepted min-gap > max-gap — validation broken"


def test_lsa_pacing_validation_watermarks(tgen):
    """low-watermark must be < high-watermark; router must reject low >= high."""

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]

    r1.vtysh_cmd(
        "configure terminal\n"
        "interface eth1\n"
        "ip ospf lsa-pacing low-watermark 50 high-watermark 50\n"
        "end"
    )

    running_config = r1.vtysh_cmd("show running-config")

    assert "low-watermark 50 high-watermark 50" not in running_config, \
        "Router accepted low-watermark == high-watermark — validation broken"


# ---------------------------------------------------------------------------
# Default values not written to running-config
# ---------------------------------------------------------------------------

def test_lsa_pacing_defaults(tgen):
    """Enable pacing without sub-params: only the enable line is written."""

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]

    r1.vtysh_cmd(
        "configure terminal\n"
        "interface eth1\n"
        "ip ospf lsa-pacing\n"
        "end"
    )

    running_config = r1.vtysh_cmd("show running-config")

    assert "ip ospf lsa-pacing" in running_config, \
        "ip ospf lsa-pacing not in running config"
    assert "initial-gap" not in running_config, \
        "Default initial-gap should not appear in running config"
    assert "min-gap" not in running_config, \
        "Default min-gap should not appear in running config"
    assert "factor" not in running_config, \
        "Default factor should not appear in running config"
    assert "adjust-interval" not in running_config, \
        "Default adjust-interval should not appear in running config"
    assert "watermark" not in running_config, \
        "Default watermarks should not appear in running config"
    assert "max-lsas-per-update" not in running_config, \
        "Default max-lsas-per-update should not appear in running config"


# ---------------------------------------------------------------------------
# Write memory persistence
# ---------------------------------------------------------------------------

def test_lsa_pacing_config_persistence(tgen):
    """Configure all params, write memory, verify saved to ospfd.conf."""

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]

    r1.vtysh_cmd(
        "configure terminal\n"
        "interface eth1\n"
        "ip ospf lsa-pacing\n"
        "ip ospf lsa-pacing initial-gap 25\n"
        "ip ospf lsa-pacing min-gap 8 max-gap 800\n"
        "ip ospf lsa-pacing factor 4\n"
        "ip ospf lsa-pacing adjust-interval 150\n"
        "ip ospf lsa-pacing low-watermark 3 high-watermark 15\n"
        "ip ospf lsa-pacing max-lsas-per-update 40\n"
        "end"
    )

    r1.vtysh_cmd("write memory")

    saved = r1.run("cat /etc/frr/frr.conf")

    assert "ip ospf lsa-pacing" in saved, \
        "ip ospf lsa-pacing not saved to ospfd.conf"
    assert "ip ospf lsa-pacing initial-gap 25" in saved, \
        "initial-gap not saved"
    assert "ip ospf lsa-pacing min-gap 8 max-gap 800" in saved, \
        "min-gap/max-gap not saved"
    assert "ip ospf lsa-pacing factor 4" in saved, \
        "factor not saved"
    assert "ip ospf lsa-pacing adjust-interval 150" in saved, \
        "adjust-interval not saved"
    assert "ip ospf lsa-pacing low-watermark 3 high-watermark 15" in saved, \
        "watermarks not saved"
    assert "ip ospf lsa-pacing max-lsas-per-update 40" in saved, \
        "max-lsas-per-update not saved"


# ---------------------------------------------------------------------------
# Interface flap
# ---------------------------------------------------------------------------

def test_lsa_pacing_interface_flap(tgen):
    """Config survives interface shutdown / no shutdown."""

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]

    r1.vtysh_cmd(
        "configure terminal\n"
        "interface eth1\n"
        "ip ospf lsa-pacing\n"
        "ip ospf lsa-pacing min-gap 8 max-gap 800\n"
        "end"
    )

    r1.vtysh_cmd(
        "configure terminal\n"
        "interface eth1\n"
        "shutdown\n"
        "end"
    )
    time.sleep(2)

    r1.vtysh_cmd(
        "configure terminal\n"
        "interface eth1\n"
        "no shutdown\n"
        "end"
    )
    time.sleep(2)

    running_config = r1.vtysh_cmd("show running-config")

    assert "ip ospf lsa-pacing min-gap 8 max-gap 800" in running_config, \
        "min-gap/max-gap lost after interface flap"


# ---------------------------------------------------------------------------
# ospfd restart
# ---------------------------------------------------------------------------

def test_lsa_pacing_frr_restart(tgen):
    """Config persists across ospfd kill/restart."""

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]

    r1.vtysh_cmd(
        "configure terminal\n"
        "interface eth1\n"
        "ip ospf lsa-pacing\n"
        "ip ospf lsa-pacing initial-gap 25\n"
        "ip ospf lsa-pacing min-gap 8 max-gap 800\n"
        "ip ospf lsa-pacing factor 4\n"
        "ip ospf lsa-pacing adjust-interval 150\n"
        "ip ospf lsa-pacing low-watermark 3 high-watermark 15\n"
        "ip ospf lsa-pacing max-lsas-per-update 40\n"
        "end"
    )

    r1.vtysh_cmd("write memory")

    r1.killDaemons(["ospfd"])
    time.sleep(2)
    r1.startDaemons(["ospfd"])
    time.sleep(2)
    r1.run("vtysh -f /etc/frr/frr.conf")
    time.sleep(3)

    running_config = r1.vtysh_cmd("show running-config")

    assert "ip ospf lsa-pacing" in running_config, \
        "ip ospf lsa-pacing lost after restart"
    assert "ip ospf lsa-pacing initial-gap 25" in running_config, \
        "initial-gap lost after restart"
    assert "ip ospf lsa-pacing min-gap 8 max-gap 800" in running_config, \
        "min-gap/max-gap lost after restart"
    assert "ip ospf lsa-pacing factor 4" in running_config, \
        "factor lost after restart"
    assert "ip ospf lsa-pacing adjust-interval 150" in running_config, \
        "adjust-interval lost after restart"
    assert "ip ospf lsa-pacing low-watermark 3 high-watermark 15" in running_config, \
        "watermarks lost after restart"
    assert "ip ospf lsa-pacing max-lsas-per-update 40" in running_config, \
        "max-lsas-per-update lost after restart"


# ---------------------------------------------------------------------------
# All parameters combined
# ---------------------------------------------------------------------------

def test_lsa_pacing_all_params(tgen):
    """Set every parameter and verify all appear in running-config."""

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]

    r1.vtysh_cmd(
        "configure terminal\n"
        "interface eth1\n"
        "ip ospf lsa-pacing\n"
        "ip ospf lsa-pacing initial-gap 25\n"
        "ip ospf lsa-pacing min-gap 20 max-gap 1000\n"
        "ip ospf lsa-pacing factor 2\n"
        "ip ospf lsa-pacing adjust-interval 300\n"
        "ip ospf lsa-pacing low-watermark 5 high-watermark 20\n"
        "ip ospf lsa-pacing max-lsas-per-update 15\n"
        "end"
    )

    running_config = r1.vtysh_cmd("show running-config")

    assert "ip ospf lsa-pacing" in running_config
    assert "ip ospf lsa-pacing initial-gap 25" in running_config
    assert "ip ospf lsa-pacing min-gap 20 max-gap 1000" in running_config
    assert "ip ospf lsa-pacing factor 2" in running_config
    assert "ip ospf lsa-pacing adjust-interval 300" in running_config
    assert "ip ospf lsa-pacing low-watermark 5 high-watermark 20" in running_config
    assert "ip ospf lsa-pacing max-lsas-per-update 15" in running_config


if __name__ == "__main__":
    import sys

    sys.exit(pytest.main(["-s", __file__]))
