# -*- coding: utf-8 eval: (blacken-mode 1) -*-
# SPDX-License-Identifier: GPL-2.0-or-later
#
# February 21 2022, Christian Hopps <chopps@labn.net>
#
# Copyright (c) 2022, LabN Consulting, L.L.C.
#
"""
test_basic_grpc.py: Test Basic gRPC.
"""

import json
import logging
import os
import re
import sys

import pytest
from lib.common_config import step
from lib.micronet import commander
from lib.topogen import Topogen, TopoRouter
from lib.topotest import json_cmp, run_and_expect

CWD = os.path.dirname(os.path.realpath(__file__))

GRPCP = 50051

pytestmark = [
    pytest.mark.mgmtd,
    # pytest.mark.bfdd,
    # pytest.mark.isisd,
    # pytest.mark.ospfd,
    # pytest.mark.pimd,
    pytest.mark.staticd,
]

script_path = os.path.realpath(os.path.join(CWD, "../lib/grpc-query.py"))

try:
    commander.cmd_raises([script_path, "--check"])
except Exception:
    pytest.skip(
        "skipping; cannot create or import gRPC proto modules", allow_module_level=True
    )


@pytest.fixture(scope="module")
def tgen(request):
    "Setup/Teardown the environment and provide tgen argument to tests"
    topodef = {"s1": ("r1",)}
    tgen = Topogen(topodef, request.module.__name__)

    tgen.start_topology()
    router_list = tgen.routers()

    for _, router in router_list.items():
        router.load_frr_config(
            "frr.conf", extra_daemons=[("mgmtd", f"-M grpc:{GRPCP}")]
        )

    tgen.start_router()
    yield tgen

    logging.info("Stopping all routers (no assert on error)")
    tgen.stop_topology()


# Let's not do this so we catch errors
# Fixture that executes before each test
@pytest.fixture(autouse=True)
def skip_on_failure(tgen):
    if tgen.routers_have_failure():
        pytest.skip("skipped because of previous test failure")


# ===================
# The tests functions
# ===================


def run_grpc_client(r, port, commands):
    if not isinstance(commands, str):
        commands = "\n".join(commands) + "\n"
    if not commands.endswith("\n"):
        commands += "\n"
    return r.cmd_raises([script_path, "--verbose", f"--port={port}"], stdin=commands)


def test_capabilities(tgen):
    r1 = tgen.gears["r1"]
    output = run_grpc_client(r1, GRPCP, "GETCAP")
    logging.debug("grpc output: %s", output)

    modules = sorted(re.findall('name: "([^"]+)"', output))
    required = [
        "frr-backend",
        "frr-host",
        "frr-interface",
        "frr-logging",
        "frr-routing",
        "frr-staticd",
        "frr-vrf",
        "ietf-srv6-types",
        "ietf-syslog-types",
    ]
    missing = set(required) - set(modules)
    assert not missing, f"GETCAP missing required modules: {missing}"

    encodings = sorted(re.findall("supported_encodings: (.*)", output))
    assert "JSON" in encodings and "XML" in encodings


def test_get_config(tgen):
    nrepeat = 5
    r1 = tgen.gears["r1"]

    step("'GET' interface config and state 10 times, once per invocation")

    for i in range(0, nrepeat):
        output = run_grpc_client(r1, GRPCP, "GET-CONFIG,/frr-interface:lib")
        logging.debug("[iteration %s]: grpc GET output: %s", i, output)

    step(f"'GET' YANG {nrepeat} times in one invocation")
    commands = ["GET-CONFIG,/frr-interface:lib" for _ in range(0, 10)]
    output = run_grpc_client(r1, GRPCP, commands)
    logging.debug("grpc GET*{%d} output: %s", nrepeat, output)

    output = run_grpc_client(r1, GRPCP, commands[0])
    out_json = json.loads(output)
    expect = json.loads("""{
  "frr-interface:lib": {
    "interface": [
      {
        "name": "r1-eth0",
        "frr-zebra:zebra": {
          "ipv4-addrs": [
            {
              "ip": "192.168.1.1",
              "prefix-length": 24
            }
          ]
        }
      }
    ]
  }
} """)
    result = json_cmp(out_json, expect, exact=False)
    assert result is None


def test_get_vrf_config(tgen):
    r1 = tgen.gears["r1"]

    step("'GET' VRF config and state")

    output = run_grpc_client(r1, GRPCP, "GET,/frr-backend:clients/client/name")
    logging.debug("grpc GET /frr-backend:clients/client/name output: %s", output)
    out_json = json.loads(output)

    expect = json.loads("""{
  "frr-backend:clients": {
    "client": [
      {
        "name": "mgmtd"
      },
      {
        "name": "staticd"
      },
      {
        "name": "zebra"
      }
    ]
  }
}
    """)
    result = json_cmp(out_json, expect, exact=False)
    assert result is None


def test_shutdown_checks(tgen):
    # Start a process rnuning that will fetch bunches of data then shut the routers down
    # and check for cores.
    nrepeat = 100
    r1 = tgen.gears["r1"]
    commands = ["GET,/frr-interface:lib" for _ in range(0, nrepeat)]
    p = r1.popen([script_path, f"--port={GRPCP}"] + commands)
    import time

    time.sleep(1)
    try:
        for r in tgen.routers().values():
            r.net.stopRouter(False)
            r.net.checkRouterCores()
    finally:
        if p:
            p.terminate()
            p.wait()


# Memory leak test template
# Not compatible with the shutdown check above
def _test_memory_leak(tgen):
    "Run the memory leak test and report results."

    if not tgen.is_memleak_enabled():
        pytest.skip("Memory leak test/report is disabled")

    tgen.report_memory_leaks()


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
