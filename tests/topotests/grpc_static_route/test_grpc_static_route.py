#!/usr/bin/env python
# SPDX-License-Identifier: ISC

#
# Copyright (c) 2026, Palo Alto Networks, Inc.
# Enke Chen <enchen@paloaltonetworks.com>
#

"""
Test gRPC COMMIT and DELETE operations with static routes.

This test verifies that:
1. Static routes can be created via gRPC COMMIT (NB_OP_CREATE)
2. Static routes can be modified via gRPC COMMIT (NB_OP_MODIFY)
3. Static routes can be deleted via gRPC DELETE (NB_OP_DESTROY)
"""

import glob
import json
import logging
import os
import sys

import pytest
from lib.common_config import step
from lib.topogen import Topogen, TopoRouter
from lib.topotest import json_cmp

CWD = os.path.dirname(os.path.realpath(__file__))

GRPCP_ZEBRA = 50051
GRPCP_STATICD = 50052

pytestmark = [
    pytest.mark.staticd,
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
    pytest.skip(
        "skipping; gRPC modules not installed", allow_module_level=True
    )

if not _frr_grpc_module_available():
    pytest.skip(
        "skipping; FRR gRPC northbound module not installed "
        "(install frr-grpc or build with --enable-grpc)",
        allow_module_level=True,
    )


@pytest.fixture(scope="module")
def tgen(request):
    "Setup/Teardown the environment and provide tgen argument to tests"
    topodef = {"s1": ("r1", "r2")}
    tgen = Topogen(topodef, request.module.__name__)

    tgen.start_topology()
    router_list = tgen.routers()

    for rname, router in router_list.items():
        router.load_config(TopoRouter.RD_ZEBRA, "zebra.conf", f"-M grpc:{GRPCP_ZEBRA}")
        router.load_config(TopoRouter.RD_STATIC, "", f"-M grpc:{GRPCP_STATICD}")

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


def test_grpc_commit_static_route(tgen):
    step("Add static route via gRPC COMMIT")
    r1 = tgen.gears["r1"]

    xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol[type='frr-staticd:staticd'][name='staticd'][vrf='default']/frr-staticd:staticd/route-list[prefix='10.0.0.0/24'][src-prefix='::/0'][afi-safi='frr-routing:ipv4-unicast']/path-list[table-id='0'][nh-type='ip4-ifindex'][vrf='default'][gateway='192.168.1.2'][interface='r1-eth0']"
    value = ""

    output = run_grpc_client(r1, GRPCP_STATICD, f"COMMIT,{xpath}:::{value}")
    logging.debug("grpc COMMIT output: %s", output)
    assert "COMMIT OK" in output

    step("Verify static route is installed")
    output = r1.vtysh_cmd("show ip route json")
    routes = json.loads(output)

    expected = {
        "10.0.0.0/24": [
            {
                "protocol": "static",
                "nexthops": [
                    {
                        "ip": "192.168.1.2",
                        "interfaceName": "r1-eth0",
                    }
                ],
            }
        ]
    }
    result = json_cmp(routes, expected, exact=False)
    assert result is None, f"Static route not found: {result}"


def test_grpc_modify_static_route(tgen):
    step("Modify static route metric via gRPC COMMIT")
    r1 = tgen.gears["r1"]

    xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol[type='frr-staticd:staticd'][name='staticd'][vrf='default']/frr-staticd:staticd/route-list[prefix='10.0.0.0/24'][src-prefix='::/0'][afi-safi='frr-routing:ipv4-unicast']/path-list[table-id='0'][nh-type='ip4-ifindex'][vrf='default'][gateway='192.168.1.2'][interface='r1-eth0']/metric"
    value = "100"

    output = run_grpc_client(r1, GRPCP_STATICD, f"COMMIT,{xpath}:::{value}")
    logging.debug("grpc COMMIT (modify) output: %s", output)
    assert "COMMIT OK" in output

    step("Verify static route still exists with metric")
    output = r1.vtysh_cmd("show ip route json")
    routes = json.loads(output)

    expected = {
        "10.0.0.0/24": [
            {
                "protocol": "static",
                "metric": 100,
                "nexthops": [
                    {
                        "ip": "192.168.1.2",
                        "interfaceName": "r1-eth0",
                    }
                ],
            }
        ]
    }
    result = json_cmp(routes, expected, exact=False)
    assert result is None, f"Static route with metric not found: {result}"


def test_grpc_delete_static_route(tgen):
    step("Delete static route via gRPC DELETE")
    r1 = tgen.gears["r1"]

    xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol[type='frr-staticd:staticd'][name='staticd'][vrf='default']/frr-staticd:staticd/route-list[prefix='10.0.0.0/24'][src-prefix='::/0'][afi-safi='frr-routing:ipv4-unicast']"

    output = run_grpc_client(r1, GRPCP_STATICD, f"DELETE,{xpath}")
    logging.debug("grpc DELETE output: %s", output)
    assert "DELETE OK" in output

    step("Verify static route is removed")
    output = r1.vtysh_cmd("show ip route json")
    routes = json.loads(output)

    assert "10.0.0.0/24" not in routes, "Static route still present after DELETE"


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
