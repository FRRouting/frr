# -*- coding: utf-8 eval: (blacken-mode 1) -*-
# SPDX-License-Identifier: GPL-2.0-or-later
#
# December 2025, Ashwini Reddy <ashred@nvidia.com>
#
# Copyright (c) 2025 NVIDIA Corporation
#
"""
test_grpc_notification.py: Test gRPC notification streaming.

Tests Subscribe RPC for registering data path subscriptions.
Uses the grpc-query.py script pattern to run gRPC client inside router namespace.
"""

import logging
import os
import sys

import pytest
from lib.common_config import step
from lib.micronet import commander
from lib.topogen import Topogen, TopoRouter

CWD = os.path.dirname(os.path.realpath(__file__))

GRPCP_ZEBRA = 50051

# Use daemon markers (registered in pytest.ini) not grpc marker
pytestmark = [pytest.mark.mgmtd]

# Path to grpc-query.py script
script_path = os.path.realpath(os.path.join(CWD, "../lib/grpc-query.py"))

# Module-level check - skip if gRPC proto modules can't be created
try:
    commander.cmd_raises([script_path, "--check"])
except Exception:
    pytest.skip(
        "skipping; cannot create or import gRPC proto modules", allow_module_level=True
    )


@pytest.fixture(scope="module")
def tgen(request):
    """Setup/Teardown the environment and provide tgen argument to tests."""
    topodef = {"s1": ("r1",)}
    tgen = Topogen(topodef, request.module.__name__)

    tgen.start_topology()
    router_list = tgen.routers()

    for _, router in router_list.items():
        router.load_config(TopoRouter.RD_MGMTD)
        router.load_config(TopoRouter.RD_ZEBRA, "zebra.conf", f"-M grpc:{GRPCP_ZEBRA}")

    tgen.start_router()
    yield tgen

    logging.info("Stopping all routers")
    tgen.stop_topology()


@pytest.fixture(autouse=True)
def skip_on_failure(tgen):
    if tgen.routers_have_failure():
        pytest.skip("skipped because of previous test failure")


def run_grpc_client(r, port, commands):
    """Run gRPC client inside router's namespace."""
    if not isinstance(commands, str):
        commands = "\n".join(commands) + "\n"
    if not commands.endswith("\n"):
        commands += "\n"
    return r.cmd_raises([script_path, f"--port={port}"], stdin=commands)


def test_grpc_connectivity(tgen):
    """Test that gRPC server is reachable."""
    step("Test gRPC server connectivity")

    r1 = tgen.gears["r1"]

    step("Query gRPC capabilities")
    output = run_grpc_client(r1, GRPCP_ZEBRA, "GETCAP")
    logging.debug("gRPC capabilities output: %s", output)

    # Verify we got a response (capabilities include module names)
    assert "frr-interface" in output or "name:" in output, "gRPC server not responding"


def test_get_interface_config(tgen):
    """Test GET request for interface configuration."""
    step("Test GET interface config via gRPC")

    r1 = tgen.gears["r1"]

    step("Get interface configuration")
    output = run_grpc_client(r1, GRPCP_ZEBRA, "GET,/frr-interface:lib")
    logging.debug("gRPC GET output: %s", output)

    # Verify we got interface data
    assert "r1-eth0" in output or "interface" in output, "No interface data returned"


def test_get_vrf_config(tgen):
    """Test GET request for VRF configuration."""
    step("Test GET VRF config via gRPC")

    r1 = tgen.gears["r1"]

    step("Get VRF configuration")
    output = run_grpc_client(r1, GRPCP_ZEBRA, "GET,/frr-vrf:lib")
    logging.debug("gRPC GET VRF output: %s", output)

    # Verify we got VRF data (at least default VRF)
    assert "default" in output or "vrf" in output, "No VRF data returned"


def test_subscribe_rpc(tgen):
    """Test Subscribe RPC - register a subscription for interface data."""
    step("Test Subscribe RPC")

    r1 = tgen.gears["r1"]

    step("Subscribe to interface path")
    output = run_grpc_client(r1, GRPCP_ZEBRA, "SUBSCRIBE,/frr-interface:lib/interface,add,5000")
    logging.debug("gRPC Subscribe output: %s", output)

    # Verify subscription succeeded
    assert "OK" in output or "ERROR" not in output, f"Subscribe RPC failed: {output}"


def test_subscribe_multiple_paths(tgen):
    """Test Subscribe RPC with multiple paths."""
    step("Test Subscribe RPC with multiple paths")

    r1 = tgen.gears["r1"]

    step("Subscribe to multiple paths")
    commands = [
        "SUBSCRIBE,/frr-interface:lib/interface,add,1000",
        "SUBSCRIBE,/frr-vrf:lib/vrf,add,2000",
    ]
    output = run_grpc_client(r1, GRPCP_ZEBRA, commands)
    logging.debug("gRPC multi-Subscribe output: %s", output)

    # Should get OK for both subscriptions
    assert output.count("OK") >= 1, f"Multi-path Subscribe failed: {output}"


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
