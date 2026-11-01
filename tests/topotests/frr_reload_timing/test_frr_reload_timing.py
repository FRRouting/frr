#!/usr/bin/env python
# SPDX-License-Identifier: ISC

#
# Copyright (c) 2026, Palo Alto Networks, Inc.
# Enke Chen <enchen@paloaltonetworks.com>
#

"""
Test frr-reload.py --timing flag for per-phase timing instrumentation.

This test verifies that frr-reload.py correctly outputs timing information
for major reload phases when the --timing flag is specified.

Phases measured:
- show-running + mark: vtysh show running + mark mode processing
- load_from_file: mark_file + parsing target config file
- running-config line split/strip: text processing of running config
- load_contexts: parsing into context objects
- compare_context_objects: diff computation
- apply adds/deletes: vtysh -f execution
"""

import os
import re
import sys

import pytest

from lib.topogen import Topogen, get_topogen

CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

pytestmark = [pytest.mark.staticd]

ROUTE_COUNT = 100


def get_reload_script(tgen):
    """Get the frr-reload.py path from tgen config."""
    frrdir = tgen.config.get(tgen.CONFIG_SECTION, "frrdir")
    return os.path.join(frrdir, "frr-reload.py")


def setup_module(mod):
    topodef = {"s1": ("r1",)}
    tgen = Topogen(topodef, mod.__name__)
    tgen.start_topology()
    for _, router in tgen.routers().items():
        router.load_frr_config(os.path.join(CWD, "r1/zebra.conf"))
    tgen.start_router()


def teardown_module(mod):
    get_topogen().stop_topology()


def _build_static_routes_conf(n_routes):
    """Build a complete config with base config plus n static routes."""
    # Start with base config
    base = open(os.path.join(CWD, "r1/zebra.conf")).read()
    # Add static routes
    routes = []
    for i in range(n_routes):
        routes.append(f"ip route 10.{i // 256}.{i % 256}.0/24 10.254.0.2")
    routes.append("!")
    return base + "\n".join(routes) + "\n"


def test_frr_reload_timing_adds():
    """
    Verify that frr-reload.py --timing outputs timing for adding routes.

    Expected TIMING lines:
    - show-running + mark
    - running-config line split/strip
    - load_contexts
    - compare_context_objects
    - apply adds
    """
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]
    conf_dir = tgen.logdir

    conf_file = os.path.join(conf_dir, "static_routes.conf")

    with open(conf_file, "w") as f:
        f.write(_build_static_routes_conf(ROUTE_COUNT))

    # Run frr-reload.py with --timing (cmd_raises checks exit status)
    reload_script = get_reload_script(tgen)
    cmd = f"python3 {reload_script} --reload --timing {conf_file}"
    output = r1.cmd_raises(cmd)

    # Verify expected TIMING lines are present
    assert "TIMING: show-running + mark:" in output, \
        f"Missing 'show-running + mark' timing in output:\n{output}"

    assert "TIMING: running-config line split/strip:" in output, \
        f"Missing 'running-config line split/strip' timing in output:\n{output}"

    assert "TIMING: load_contexts" in output, \
        f"Missing 'load_contexts' timing in output:\n{output}"

    assert "TIMING: pass 0 compare_context_objects:" in output, \
        f"Missing 'compare_context_objects' timing in output:\n{output}"

    assert "TIMING: pass 0 apply adds" in output, \
        f"Missing 'apply adds' timing in output:\n{output}"

    # Extract and print timing for reference
    timing_lines = [line for line in output.splitlines() if "TIMING:" in line]
    print("\n=== Timing output (adding {} routes) ===".format(ROUTE_COUNT))
    for line in timing_lines:
        print(line)


def test_frr_reload_timing_deletes():
    """
    Verify that frr-reload.py --timing outputs timing for deleting routes.

    This test first adds routes, then reloads with base config to delete them.
    """
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]
    conf_dir = tgen.logdir

    # First, add routes
    routes_conf = os.path.join(conf_dir, "routes_to_delete.conf")
    with open(routes_conf, "w") as f:
        f.write(_build_static_routes_conf(ROUTE_COUNT))

    reload_script = get_reload_script(tgen)
    r1.cmd_raises(f"python3 {reload_script} --reload {routes_conf}")

    # Now reload with base config (no routes) to trigger deletes
    base_conf = os.path.join(conf_dir, "base.conf")
    with open(base_conf, "w") as f:
        f.write(open(os.path.join(CWD, "r1/zebra.conf")).read())

    # Run frr-reload.py with --timing to delete routes (cmd_raises checks exit status)
    cmd = f"python3 {reload_script} --reload --timing {base_conf}"
    output = r1.cmd_raises(cmd)

    # Verify expected TIMING lines are present
    assert "TIMING: show-running + mark:" in output, \
        f"Missing 'show-running + mark' timing in output:\n{output}"

    assert "TIMING: pass 0 compare_context_objects:" in output, \
        f"Missing 'compare_context_objects' timing in output:\n{output}"

    assert "TIMING: pass 0 apply deletes" in output, \
        f"Missing 'apply deletes' timing in output:\n{output}"

    # Verify routes are being deleted (del= should be at least ROUTE_COUNT)
    del_match = re.search(r"compare_context_objects:.*del=(\d+)", output)
    assert del_match, f"Missing del= count in compare_context_objects output:\n{output}"
    del_count = int(del_match.group(1))
    assert del_count >= ROUTE_COUNT, \
        f"Expected del >= {ROUTE_COUNT}, got del={del_count} in output:\n{output}"

    # Extract and print timing for reference
    timing_lines = [line for line in output.splitlines() if "TIMING:" in line]
    print("\n=== Timing output (deleting {} routes) ===".format(ROUTE_COUNT))
    for line in timing_lines:
        print(line)
