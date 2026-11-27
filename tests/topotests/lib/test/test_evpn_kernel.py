# SPDX-License-Identifier: ISC
"""Tests for vxlan_nh_fdb_probe_reason()."""

import os
import sys

CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../../"))

# pylint: disable=C0413
from lib.evpn import vxlan_nh_fdb_probe_reason  # noqa: E402
import pytest  # noqa: E402

RELEASE = "7.0.0-41-generic"


def test_rejecting_kernel_skips():
    output = "Error: A nexthop fdb cannot be dynamic.\n"
    reason = vxlan_nh_fdb_probe_reason(2, output, RELEASE)
    assert reason is not None
    assert RELEASE in reason


@pytest.mark.parametrize(
    "rc, output",
    [
        # Entry accepted: kernel before the reject, or with its correction.
        (0, ""),
        # Probe failing for another reason: the test keeps its own checks.
        (1, "unshare: unshare failed: Operation not permitted\n"),
        (2, "Error: Unknown device type.\n"),
        (255, 'Object "nexthop" is unknown, try "ip help".\n'),
        (1, None),
    ],
)
def test_other_results_run(rc, output):
    assert vxlan_nh_fdb_probe_reason(rc, output, RELEASE) is None
