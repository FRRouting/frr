#!/usr/bin/env python
# SPDX-License-Identifier: ISC

#
# Copyright (c) 2026, Palo Alto Networks, Inc.
# Enke Chen <enchen@paloaltonetworks.com>
#

"""
Test MPLS label stack configuration for static routes via CLI.

MPLS_MAX_LABELS is 16.  This test verifies that an 8-label stack (well
within the limit) is accepted via the CLI and appears correctly in both
running-config and the RIB.

The gRPC test in tests/lib/test_grpc.cpp exercises the NB_EV_VALIDATE
guard against >16 labels; this topotest complements it by confirming
that valid label stacks work end-to-end through the CLI path.
"""

import functools
import json
import os
import sys

import pytest

from lib import topotest
from lib.topogen import Topogen, get_topogen

CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

pytestmark = [pytest.mark.staticd]

PREFIX = "10.88.0.0/24"
NH = "192.0.2.2"

# 8 labels — well within MPLS_MAX_LABELS (16)
LABELS_8 = "/".join(str(100 + i) for i in range(8))


def setup_module(mod):
    topodef = {"s1": ("r1",)}
    tgen = Topogen(topodef, mod.__name__)
    tgen.start_topology()

    for _, router in tgen.routers().items():
        router.load_frr_config(os.path.join(CWD, "r1/frr.conf"))

    tgen.start_router()


def teardown_module(mod):
    tgen = get_topogen()
    tgen.stop_topology()


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _running_has_labels(router, prefix, label_str):
    """Return True if running-config for prefix contains label_str."""
    output = router.vtysh_cmd("show running-config")
    for line in output.splitlines():
        if f"ip route {prefix}" in line and f"label {label_str}" in line:
            return True
    return False


def _route_installed(router, prefix):
    """Return True if prefix appears in the RIB."""
    output = router.vtysh_cmd(f"show ip route {prefix} json")
    data = json.loads(output)
    return bool(data.get(prefix))


def _route_has_labels(router, prefix, expected_labels):
    """Return True if the RIB entry for prefix has the expected label stack."""
    output = router.vtysh_cmd(f"show ip route {prefix} json")
    data = json.loads(output)
    entries = data.get(prefix, [])
    for entry in entries:
        for nh in entry.get("nexthops", []):
            labels = nh.get("labels", [])
            if labels == expected_labels:
                return True
    return False


def _check_route_with_labels(router, prefix, expected_labels):
    """Return None if route has expected labels, else error string."""
    if not _route_installed(router, prefix):
        return "route not installed"
    if not _route_has_labels(router, prefix, expected_labels):
        return "labels mismatch"
    return None


# ---------------------------------------------------------------------------
# Test: 8-label stack accepted via CLI
# ---------------------------------------------------------------------------


def test_label_stack_8_labels():
    """An 8-label stack must be installed correctly via CLI."""
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]

    # Configure route with 8 labels
    output = r1.vtysh_cmd(
        f"configure terminal\nip route {PREFIX} {NH} label {LABELS_8}\n"
    )

    # Should not be rejected
    assert "% Configuration failed" not in output, (
        f"8-label stack unexpectedly rejected: {output!r}"
    )
    assert "% Exceeded" not in output, (
        f"8-label stack hit change limit: {output!r}"
    )

    # Expected labels as integers for RIB comparison
    expected_labels = [100 + i for i in range(8)]

    # Wait for route to be installed with correct labels
    test_func = functools.partial(
        _check_route_with_labels, r1, PREFIX, expected_labels
    )
    _, result = topotest.run_and_expect(test_func, None, count=15, wait=1)
    assert result is None, f"Route not installed with 8-label stack: {result}"

    # Verify labels appear in running-config
    assert _running_has_labels(r1, PREFIX, LABELS_8), (
        "8-label stack not found in running-config"
    )

    # Clean up
    r1.vtysh_cmd(f"configure terminal\nno ip route {PREFIX} {NH}\n")

    # Verify cleanup
    test_func = functools.partial(_route_installed, r1, PREFIX)
    _, result = topotest.run_and_expect(
        lambda: None if not _route_installed(r1, PREFIX) else "still installed",
        None,
        count=15,
        wait=1,
    )


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
