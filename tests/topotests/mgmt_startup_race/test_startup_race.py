#!/usr/bin/env python
# SPDX-License-Identifier: ISC
#
# Copyright (c) 2026, Palo Alto Networks, Inc.
# Enke Chen <enchen@paloaltonetworks.com>
#
"""
Test for startup race: CLI commands vs mgmtd sending initial config.

When staticd connects to mgmtd, mgmtd sends the initial config to staticd
while holding the running DS lock. CLI commands arriving during this
window fail to acquire the lock. Without the fix, these commands were
silently dropped.

This race condition is scale-related: mgmtd must hold the lock long
enough for CLI commands to arrive. The route count (INIT_ROUTE_COUNT)
may need adjustment on different systems.

This test delays starting staticd until after mgmtd is running and the
config is loaded. If staticd were started together with mgmtd, a much
higher route count would be needed to trigger the race, since mgmtd
would start sending config before CLI commands could be sent.

This test reproduces the race:
1. Load N routes into mgmtd config (more routes = longer lock hold time)
2. Start staticd after mgmtd (mgmtd sends config, holds running DS lock)
3. Immediately send CLI route commands (race with config send)
4. Verify ALL routes are present (config + CLI-added)

Without the fix, CLI-added routes are dropped with "could not lock running DS".
With the fix, CLI commits retry until the lock is released.

To verify the race was triggered, check mgmtd.log for lock failure:
    grep "Lock.*failed" /tmp/topotests/mgmt_startup_race.../r1/mgmtd.log
    -> "Locking for DS 1 failed, Err: 'Lock already taken...'"
This confirms the CLI command hit the lock held while mgmtd was sending
config to staticd, and the fix's retry logic handled it.
"""

import json
import logging
import os
import shutil
import time

import pytest
from lib.common_config import retry, step
from lib.topogen import Topogen, TopoRouter
from munet.base import Timeout

CWD = os.path.dirname(os.path.realpath(__file__))

pytestmark = [pytest.mark.staticd, pytest.mark.mgmtd]

# Routes in initial config - more routes means mgmtd holds the running
# DS lock longer while sending config, increasing the race window.
INIT_ROUTE_COUNT = 300

# Routes to add via CLI during race window, with non-default distance to verify
# the value isn't corrupted by UAF (distance is a stack local in the CLI handler)
CLI_ROUTES = [
    "192.168.1.0/24",
    "192.168.2.0/24",
    "192.168.3.0/24",
    "192.168.4.0/24",
    "192.168.5.0/24",
]
CLI_ROUTE_DISTANCE = 55

# Delay (ms) after starting staticd to let mgmtd grab the lock first
RACE_DELAY_MS = 50


def generate_conf_with_routes(srcpath, dstpath, count):
    """Copy source config and append generated routes."""
    shutil.copy(srcpath, dstpath)
    with open(dstpath, "a", encoding="ascii") as f:
        for i in range(count):
            x = i // 256
            y = i % 256
            f.write(f"ip route 10.{x}.{y}.0/24 101.0.0.2\n")


@pytest.fixture(scope="module")
def tgen(request):
    """Setup/Teardown the environment and provide tgen argument to tests"""

    topodef = {
        "s1": ("r1",),
    }

    tgen = Topogen(topodef, request.module.__name__)
    tgen.start_topology()

    # Generate config with routes, then load it.
    router = tgen.gears["r1"]
    srcconf = os.path.join(CWD, "{}/frr.conf".format("r1"))
    dstconf = os.path.join(router.gearlogdir, "frr.conf")
    generate_conf_with_routes(srcconf, dstconf, INIT_ROUTE_COUNT)
    router.load_frr_config(dstconf)

    # Disable staticd - start it manually to control timing and trigger
    # the race condition.
    router.net.daemons["staticd"] = 0

    tgen.start_router()
    yield tgen
    tgen.stop_topology()


@retry(retry_timeout=120)
def check_route_count(router, expected):
    """Wait for expected number of static routes in zebra."""
    output = json.loads(router.vtysh_cmd("show ip route static json"))
    count = len(output)
    assert count >= expected, f"Expected {expected} routes, got {count}"
    return count


@retry(retry_timeout=30)
def check_route_present(router, prefix, expected_distance=None):
    """Check if a route is present in zebra with expected distance."""
    output = json.loads(router.vtysh_cmd(f"show ip route {prefix} json"))
    assert prefix in output, f"Route {prefix} not found"
    if expected_distance is not None:
        route_info = output[prefix][0]
        actual_distance = route_info.get("distance")
        assert actual_distance == expected_distance, (
            f"Route {prefix} distance mismatch: expected {expected_distance}, "
            f"got {actual_distance}"
        )


def test_startup_race(tgen):
    """Test that CLI routes are not dropped during init push race."""
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.routers()["r1"]

    step("Verify no static routes present before staticd starts")
    output = json.loads(r1.vtysh_cmd("show ip route static json"))
    assert len(output) == 0, f"Expected 0 routes, got {len(output)}"

    step(f"Starting staticd (will push {INIT_ROUTE_COUNT} routes)")
    t = Timeout(0)
    r1.startDaemons(["staticd"])

    # Let mgmtd grab the running DS lock first
    time.sleep(RACE_DELAY_MS / 1000.0)

    step("Adding CLI routes (racing with config send)")
    for prefix in CLI_ROUTES:
        r1.net.cmd_nostatus(
            f"vtysh -c 'config t' -c 'ip route {prefix} 101.0.0.2 {CLI_ROUTE_DISTANCE}'"
        )
    logging.info("CLI routes sent after %ss", t.elapsed())

    step("Waiting for all routes to be installed")
    expected = INIT_ROUTE_COUNT + len(CLI_ROUTES)
    actual = check_route_count(r1, expected)
    logging.info("All %d routes installed after %ss", actual, t.elapsed())

    step("Verifying CLI-added routes are present with correct distance")
    for prefix in CLI_ROUTES:
        check_route_present(r1, prefix, expected_distance=CLI_ROUTE_DISTANCE)
    logging.info("All %d CLI routes present with distance %d", len(CLI_ROUTES), CLI_ROUTE_DISTANCE)
