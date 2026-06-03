# SPDX-License-Identifier: ISC
# -*- coding: utf-8 eval: (blacken-mode 1) -*-
#
# Copyright (C) 2026  Eric Parsonage
#

"""
Test mgmtd gRPC Get and Execute access to backend daemons.
"""

import glob
import json
import os

import pytest
from lib.common_config import retry, step
from lib.micronet import commander
from lib.topogen import Topogen, TopoRouter
from lib.topotest import json_cmp

CWD = os.path.dirname(os.path.realpath(__file__))
GRPCP_MGMTD = 50057
script_path = os.path.realpath(os.path.join(CWD, "../lib/grpc-query.py"))

pytestmark = [pytest.mark.ripd, pytest.mark.mgmtd]


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

try:
    commander.cmd_raises([script_path, "--check"])
except Exception:
    pytest.skip(
        "skipping; cannot create or import gRPC proto modules",
        allow_module_level=True,
    )


@pytest.fixture(scope="module")
def tgen(request):
    "Setup/Teardown the environment and provide tgen argument to tests"

    topodef = {"s1": ("r1", "r2")}
    tgen = Topogen(topodef, request.module.__name__)
    tgen.start_topology()

    for rname, router in tgen.routers().items():
        router.load_frr_config("frr.conf")
        if rname == "r1":
            mgmtd_options = f"-M grpc:{GRPCP_MGMTD}"
        else:
            mgmtd_options = ""
        router.load_config(TopoRouter.RD_MGMTD, "", mgmtd_options)

    tgen.start_router()
    yield tgen
    tgen.stop_topology()


@pytest.fixture(autouse=True)
def skip_on_failure(tgen):
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)


@retry(retry_timeout=30)
def check_ripd_rpc_registered(r1):
    out = r1.vtysh_cmd("show mgmt backend-yang-xpath-registry")
    return None if "rpc: /frr-ripd: ripd" in out else "missing ripd RPC backend"


@retry(retry_timeout=60)
def check_rip_route_present(r1):
    out = r1.vtysh_cmd("show ip rip")
    return None if "203.0.113.0/24" in out else "missing learned RIP route"


@retry(retry_timeout=10)
def check_rip_route_absent(r1):
    out = r1.vtysh_cmd("show ip rip")
    return None if "203.0.113.0/24" not in out else "learned RIP route still present"


def run_grpc_client(r, commands, extra_args=None):
    if not isinstance(commands, str):
        commands = "\n".join(commands) + "\n"
    if not commands.endswith("\n"):
        commands += "\n"
    args = [script_path, f"--port={GRPCP_MGMTD}"]
    if extra_args:
        args.extend(extra_args)
    return r.cmd_raises(args, stdin=commands)


def run_grpc_client_status(r, commands, port=GRPCP_MGMTD):
    if not commands.endswith("\n"):
        commands += "\n"
    return r.net.cmd_status([script_path, f"--port={port}"], stdin=commands)


def test_capabilities_via_mgmtd_grpc(tgen):
    r1 = tgen.gears["r1"]

    step("Read gRPC capabilities through mgmtd")
    output = run_grpc_client(r1, "GETCAP")
    for module in ("frr-backend", "frr-interface", "frr-ripd"):
        assert f'name: "{module}"' in output
    assert "supported_encodings: JSON" in output
    assert "supported_encodings: XML" in output


def test_get_config_via_mgmtd_grpc(tgen):
    r1 = tgen.gears["r1"]

    step("Read interface config repeatedly through mgmtd gRPC")
    for _ in range(5):
        output = run_grpc_client(r1, "GET-CONFIG,/frr-interface:lib")
        out_json = json.loads(output)
        expect = json.loads(
            """{
  "frr-interface:lib": {
    "interface": [
      {
        "name": "r1-eth0",
        "frr-zebra:zebra": {
          "ipv4-addrs": [
            {
              "ip": "192.0.2.1",
              "prefix-length": 24
            }
          ]
        }
      }
    ]
  }
}"""
        )
        result = json_cmp(out_json, expect, exact=False)
        assert result is None

    step("Read interface config repeatedly in one gRPC client session")
    commands = ["GET-CONFIG,/frr-interface:lib" for _ in range(10)]
    output = run_grpc_client(r1, commands)
    assert output.count('"frr-interface:lib"') == len(commands)

    step("Read interface config with the response path field")
    output = run_grpc_client(r1, "GET-CONFIG-WITH-PATH,/frr-interface:lib")
    path, data = output.split("\n", 1)
    assert path == "/frr-interface:lib"
    assert '"frr-interface:lib"' in data

    step("Read the whole running datastore through mgmtd gRPC")
    output = run_grpc_client(r1, "GET-CONFIG,/")
    out_json = json.loads(output)
    assert isinstance(out_json, dict)
    assert "frr-interface:lib" in out_json
    assert "frr-ripd:ripd" in out_json

    step("Read the whole running datastore through mgmtd gRPC without a path")
    no_path_json = json.loads(run_grpc_client(r1, "GET-CONFIG"))
    assert json_cmp(no_path_json, out_json, exact=True) is None

    try:
        step("Read daemon-owned RIP config after changing it through vtysh")
        r1.vtysh_cmd(
            "configure terminal\n"
            "router rip\n"
            "default-metric 7\n"
            "end\n"
        )

        output = run_grpc_client(
            r1,
            "GET-CONFIG,/frr-ripd:ripd/instance[vrf='default']",
        )
        out_json = json.loads(output)
        expect = json.loads(
            """{
  "frr-ripd:instance": [
    {
      "vrf": "default",
      "default-metric": 7
    }
  ]
}"""
        )

        result = json_cmp(out_json, expect, exact=False)
        assert result is None
    finally:
        r1.vtysh_cmd(
            "configure terminal\n"
            "router rip\n"
            "no default-metric\n"
            "end\n"
        )


def test_get_config_xml_via_mgmtd_grpc(tgen):
    r1 = tgen.gears["r1"]

    step("Read interface config as XML through mgmtd gRPC")
    output = run_grpc_client(
        r1, "GET-CONFIG,/frr-interface:lib", extra_args=["--xml"]
    )
    assert "<interface" in output
    assert "r1-eth0" in output
    assert "192.0.2.1" in output


def test_get_state_and_all_via_mgmtd_grpc(tgen):
    r1 = tgen.gears["r1"]

    step("Read operational backend state through mgmtd gRPC")
    output = run_grpc_client(r1, "GET-STATE,/frr-backend:clients")
    out_json = json.loads(output)
    assert "frr-backend:clients" in out_json
    assert "client" in out_json["frr-backend:clients"]

    step("Read combined config and state through mgmtd gRPC")
    output = run_grpc_client(r1, "GET,/frr-backend:clients")
    out_json = json.loads(output)
    assert isinstance(out_json, dict)
    assert "frr-backend:clients" in out_json
    assert "client" in out_json["frr-backend:clients"]

    step("Do not warn when GET-ALL falls through from config to state")
    with open(os.path.join(tgen.logdir, "r1", "mgmtd.log"), encoding="utf-8") as log:
        assert (
            "failed to fetch config path /frr-backend:clients" not in log.read()
        )


def test_get_rejects_missing_paths_via_mgmtd_grpc(tgen):
    r1 = tgen.gears["r1"]

    step("Reject a missing config path")
    rc, stdout, stderr = run_grpc_client_status(
        r1, "GET-CONFIG,/frr-interface:missing"
    )
    assert rc != 0
    assert "INVALID_ARGUMENT" in stdout + stderr

    step("Reject a missing state path")
    rc, stdout, stderr = run_grpc_client_status(
        r1, "GET-STATE,/frr-interface:missing"
    )
    assert rc != 0
    assert "INVALID_ARGUMENT" in stdout + stderr

    step("Reject a missing mixed config/state path")
    rc, stdout, stderr = run_grpc_client_status(r1, "GET,/frr-interface:missing")
    assert rc != 0
    output = stdout + stderr
    assert "INVALID_ARGUMENT" in output
    assert "Data path not found" in output


def test_execute_rpc_via_mgmtd_grpc(tgen):
    r1 = tgen.gears["r1"]

    assert check_ripd_rpc_registered(r1) is None
    assert check_rip_route_present(r1) is None

    output = run_grpc_client(r1, "EXEC,/frr-ripd:clear-rip-route")
    assert "output" not in output
    assert check_rip_route_absent(r1) is None


def test_execute_cancel_keeps_listener_available(tgen):
    r1 = tgen.gears["r1"]

    assert check_ripd_rpc_registered(r1) is None

    step("Cancel a gRPC Execute call")
    output = run_grpc_client(
        r1, "EXEC-CANCEL,/frr-ripd:clear-rip-route,0,5"
    ).strip()
    assert output in {"CANCELLED", "OK"}

    step("Execute still accepts a later request")
    output = run_grpc_client(r1, "EXEC,/frr-ripd:clear-rip-route")
    assert "output" not in output


def test_concurrent_execute_rpc_via_mgmtd_grpc(tgen):
    r1 = tgen.gears["r1"]

    assert check_ripd_rpc_registered(r1) is None

    step("Run concurrent gRPC Execute requests through mgmtd")
    output = run_grpc_client(
        r1, "EXEC-CONCURRENT,/frr-ripd:clear-rip-route,5,5"
    )
    results = json.loads(output)
    assert results == ["OK"] * 5


def test_execute_rejects_unknown_rpc_via_mgmtd_grpc(tgen):
    r1 = tgen.gears["r1"]

    rc, stdout, stderr = run_grpc_client_status(
        r1, "EXEC,/frr-ripd:no-such-rpc"
    )
    assert rc != 0
    assert "INVALID_ARGUMENT" in stdout + stderr
