#!/usr/bin/env python
# SPDX-License-Identifier: ISC

#
# Copyright (c) 2026, Palo Alto Networks, Inc.
# Enke Chen <enchen@paloaltonetworks.com>
#
"""
test_grpc_bgp_health.py: Test gRPC health check for BGP daemon instances.

This test verifies both the gRPC handler health ("gRPC-handler") and
BGP instance health ("bgp-default"):
1. Wait for "gRPC-handler" to be SERVING (gRPC server ready)
2. Verify "bgp-default" returns NOT_FOUND (no BGP config yet)
3. Configure "router bgp" via vtysh
4. Verify "bgp-default" returns SERVING
5. Delete the BGP instance
6. Verify "bgp-default" returns NOT_SERVING
7. Verify startup replay: instance configured before gRPC ready shows SERVING
"""

import glob
import logging
import os
import sys
import time

import pytest
from lib.common_config import step
from lib.topogen import Topogen, TopoRouter
from lib.topotest import run_and_expect
from functools import partial

CWD = os.path.dirname(os.path.realpath(__file__))

GRPCP_BGPD_R1 = 50051
GRPCP_BGPD_R2 = 50052

pytestmark = [
    pytest.mark.bgpd,
]

script_path = os.path.realpath(os.path.join(CWD, "../lib/grpc-query.py"))


def _frr_grpc_module_available():
    """True when the FRR northbound gRPC module (grpc.so) is installed."""
    patterns = (
        "/usr/lib/*/frr/modules/grpc.so",
        "/usr/lib/frr/modules/grpc.so",
        "/usr/lib64/*/frr/modules/grpc.so",
        "/usr/lib64/frr/modules/grpc.so",
        "/usr/local/lib/*/frr/modules/grpc.so",
        "/usr/local/lib/frr/modules/grpc.so",
    )
    for pattern in patterns:
        for path in glob.glob(pattern):
            if os.path.isfile(path):
                return True

    frr_root = os.path.realpath(os.path.join(CWD, "../../.."))
    for base in (frr_root, os.environ.get("FRR_BUILD_DIR")):
        if not base:
            continue
        for rel in ("lib/.libs/grpc.so", "lib/grpc.so"):
            if os.path.isfile(os.path.join(base, rel)):
                return True
    return False


try:
    import grpc  # noqa: F401
    import grpc_tools  # noqa: F401
except ImportError:
    pytest.skip("skipping; gRPC modules not installed", allow_module_level=True)

if not _frr_grpc_module_available():
    pytest.skip(
        "skipping; FRR gRPC northbound module not installed "
        "(install frr-grpc or build with --enable-grpc)",
        allow_module_level=True,
    )


@pytest.fixture(scope="module")
def tgen(request):
    "Setup/Teardown the environment and provide tgen argument to tests"
    # r1: no BGP config at startup (tests dynamic creation)
    # r2: BGP config loaded at startup (tests startup replay hook)
    topodef = {"s1": ("r1", "r2")}
    tgen = Topogen(topodef, request.module.__name__)

    tgen.start_topology()

    # r1: frr.conf has no BGP config - tests dynamic instance creation
    r1 = tgen.gears["r1"]
    r1.load_frr_config(
        os.path.join(CWD, "r1/frr.conf"),
        daemons=[
            (TopoRouter.RD_ZEBRA, ""),
            (TopoRouter.RD_BGP, f"-M grpc:{GRPCP_BGPD_R1}"),
        ],
    )

    # r2: frr.conf has BGP config - tests startup replay hook
    r2 = tgen.gears["r2"]
    r2.load_frr_config(
        os.path.join(CWD, "r2/frr.conf"),
        daemons=[
            (TopoRouter.RD_ZEBRA, ""),
            (TopoRouter.RD_BGP, f"-M grpc:{GRPCP_BGPD_R2}"),
        ],
    )

    tgen.start_router()
    yield tgen

    logging.info("Stopping all routers (no assert on error)")
    tgen.stop_topology()


@pytest.fixture(autouse=True)
def skip_on_failure(tgen):
    if tgen.routers_have_failure():
        pytest.skip("skipped because of previous test failure")


def run_grpc_client(r, port, commands):
    if not isinstance(commands, str):
        commands = "\n".join(commands) + "\n"
    if not commands.endswith("\n"):
        commands += "\n"
    return r.cmd_raises([script_path, f"--port={port}"], stdin=commands)


def check_grpc_health_serving(r, port, service):
    """Check if gRPC service is SERVING. Returns None on success, error string on failure."""
    try:
        output = run_grpc_client(r, port, f"HEALTH,{service}")
        if ": SERVING" in output:
            return None
        return f"not SERVING: {output}"
    except Exception as e:
        return str(e)


def wait_for_grpc_ready(r, port, service, count=60, wait=0.5):
    """Poll until the gRPC service reports SERVING, using run_and_expect."""
    test_func = partial(check_grpc_health_serving, r, port, service)
    success, result = run_and_expect(test_func, None, count=count, wait=wait)
    assert success, f"gRPC service '{service}' did not become SERVING: {result}"
    # Return actual output for logging
    return run_grpc_client(r, port, f"HEALTH,{service}")


def test_bgp_health_check_lifecycle(tgen):
    """Test BGP instance health check through create/delete lifecycle.

    Verifies that:
    1. Before BGP config: "bgp-default" returns SERVICE_UNKNOWN or NOT_SERVING
    2. After "router bgp": "bgp-default" returns SERVING
    3. After "no router bgp": "bgp-default" returns NOT_SERVING
    """
    r1 = tgen.gears["r1"]

    step("Wait for gRPC server to be ready")
    # Poll for gRPC handler to become SERVING (bounded timeout)
    wait_for_grpc_ready(r1, GRPCP_BGPD_R1, "gRPC-handler")

    step("Check health status of 'bgp-default' before BGP config")
    output = run_grpc_client(r1, GRPCP_BGPD_R1, "HEALTH,bgp-default")
    logging.info("grpc health check (before config) output: %s", output)
    # Before any BGP config, bgp-default should not be serving.
    # NOT_FOUND means the service was never registered (expected).
    # NOT_SERVING means explicitly set to not serving.
    # SERVICE_UNKNOWN means the service name is not recognized.
    assert (
        "NOT_SERVING" in output
        or "SERVICE_UNKNOWN" in output
        or "NOT_FOUND" in output
    ), f"Expected NOT_SERVING, SERVICE_UNKNOWN, or NOT_FOUND before config, got: {output}"

    step("Configure 'router bgp 65001'")
    r1.vtysh_cmd(
        """
        configure terminal
        router bgp 65001
        exit
        """
    )

    step("Check health status of 'bgp-default' after BGP config")
    # Poll for bgp-default to become SERVING
    output = wait_for_grpc_ready(r1, GRPCP_BGPD_R1, "bgp-default")
    logging.info("grpc health check (after config) output: %s", output)
    # After BGP config, bgp-default should be serving
    # Use ": SERVING" to avoid matching "NOT_SERVING"
    assert ": SERVING" in output, f"Expected SERVING after config, got: {output}"

    step("Delete BGP instance with 'no router bgp 65001'")
    r1.vtysh_cmd(
        """
        configure terminal
        no router bgp 65001
        exit
        """
    )

    step("Check health status of 'bgp-default' after BGP deletion")
    # Deletion is synchronous, status should be updated immediately
    output = run_grpc_client(r1, GRPCP_BGPD_R1, "HEALTH,bgp-default")
    logging.info("grpc health check (after delete) output: %s", output)
    # After deletion, bgp-default should not be serving
    assert "NOT_SERVING" in output, f"Expected NOT_SERVING after delete, got: {output}"


def test_bgp_health_check_recreate(tgen):
    """Test that BGP health check works correctly on instance recreation.

    Creates a new BGP instance after deletion to verify health transitions.
    """
    r1 = tgen.gears["r1"]

    step("Recreate BGP instance with 'router bgp 65002'")
    r1.vtysh_cmd(
        """
        configure terminal
        router bgp 65002
        exit
        """
    )

    step("Check health status after recreation")
    # Poll for bgp-default to become SERVING
    output = wait_for_grpc_ready(r1, GRPCP_BGPD_R1, "bgp-default")
    logging.info("grpc health check (after recreate) output: %s", output)
    # Use ": SERVING" to avoid matching "NOT_SERVING"
    assert ": SERVING" in output, f"Expected SERVING after recreate, got: {output}"

    step("Cleanup - delete BGP instance")
    r1.vtysh_cmd(
        """
        configure terminal
        no router bgp 65002
        exit
        """
    )


def test_bgp_health_check_startup_replay(tgen):
    """Test that BGP instances created before gRPC ready are published via replay hook.

    r2 has BGP config loaded at startup. The bgp_grpc_server_ready() hook should
    publish the health status for instances that existed before gRPC started.
    This verifies the startup replay mechanism works correctly.
    """
    r2 = tgen.gears["r2"]

    step("Wait for gRPC server on r2 to be ready")
    wait_for_grpc_ready(r2, GRPCP_BGPD_R2, "gRPC-handler")

    step("Check that bgp-default is SERVING (created at startup, before gRPC ready)")
    # This tests the bgp_grpc_server_ready() hook that replays health status
    # for instances that existed before gRPC started
    output = wait_for_grpc_ready(r2, GRPCP_BGPD_R2, "bgp-default")
    logging.info("grpc health check (startup replay) output: %s", output)
    assert ": SERVING" in output, f"Expected SERVING for startup instance, got: {output}"


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
