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
from lib.topolog import logger
from lib.topotest import json_cmp

CWD = os.path.dirname(os.path.realpath(__file__))

GRPCP_ZEBRA = 50051
GRPCP_STATICD = 50052
GRPCP_BFDD = 50053
GRPCP_ISISD = 50054
GRPCP_OSPFD = 50055
GRPCP_PIMD = 50056
GRPCP_MGMTD = 50057

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
    topodef = {"s1": ("r1", "r2")}
    tgen = Topogen(topodef, request.module.__name__)

    tgen.start_topology()
    router_list = tgen.routers()

    for rname, router in router_list.items():
        router.load_config(TopoRouter.RD_ZEBRA, "zebra.conf", f"-M grpc:{GRPCP_ZEBRA}")
        router.load_config(TopoRouter.RD_STATIC, "", f"-M grpc:{GRPCP_STATICD}")
        # router.load_config(TopoRouter.RD_BFDD, "", f"-M grpc:{GRPCP_BFDD}")
        # router.load_config(TopoRouter.RD_ISIS, None, f"-M grpc:{GRPCP_ISISD}")
        # router.load_config(TopoRouter.RD_OSPF, None, f"-M grpc:{GRPCP_OSPFD}")
        # router.load_config(TopoRouter.RD_PIM, None, f"-M grpc:{GRPCP_PIMD}")

        # This doesn't work yet...
        # router.load_config(TopoRouter.RD_MGMTD, "", f"-M grpc:{GRPCP_MGMTD}")

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
    return r.cmd_raises([script_path, f"--port={port}"], stdin=commands)


def test_connectivity(tgen):
    tgen.gears["r1"].cmd_raises("ping -c1 192.168.1.2")


def test_capabilities(tgen):
    r1 = tgen.gears["r1"]
    output = run_grpc_client(r1, GRPCP_STATICD, "GETCAP")
    logging.debug("grpc output: %s", output)

    modules = sorted(re.findall('name: "([^"]+)"', output))
    expected = ["frr-interface", "frr-routing", "frr-staticd", "frr-vrf"]
    assert modules == expected

    encodings = sorted(re.findall("supported_encodings: (.*)", output))
    expected = ["JSON", "XML"]
    assert encodings == expected


def test_get_config(tgen):
    nrepeat = 5
    r1 = tgen.gears["r1"]

    step("'GET' interface config and state 10 times, once per invocation")

    for i in range(0, nrepeat):
        output = run_grpc_client(r1, GRPCP_ZEBRA, "GET-CONFIG,/frr-interface:lib")
        logging.debug("[iteration %s]: grpc GET output: %s", i, output)

    step(f"'GET' YANG {nrepeat} times in one invocation")
    commands = ["GET-CONFIG,/frr-interface:lib" for _ in range(0, 10)]
    output = run_grpc_client(r1, GRPCP_ZEBRA, commands)
    logging.debug("grpc GET*{%d} output: %s", nrepeat, output)

    output = run_grpc_client(r1, GRPCP_ZEBRA, commands[0])
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
              "ip": "192.168.1.1",
              "prefix-length": 24
            }
          ],
          "evpn-mh": {},
          "ipv6-router-advertisements": {}
        }
      }
    ]
  },
  "frr-zebra:zebra": {
    "import-kernel-table": {}
  }
} """
    )
    result = json_cmp(out_json, expect, exact=True)
    assert result is None


def test_get_vrf_config(tgen):
    r1 = tgen.gears["r1"]

    step("'GET' VRF config and state")

    output = run_grpc_client(r1, GRPCP_STATICD, "GET,/frr-vrf:lib")
    logging.debug("grpc GET /frr-vrf:lib output: %s", output)
    out_json = json.loads(output)
    expect = json.loads(
        """{
  "frr-vrf:lib": {
    "vrf": [
      {
        "name": "default",
        "state": {
          "id": 0,
          "active": true
        }
      }
    ]
  }
}
    """
    )
    result = json_cmp(out_json, expect, exact=True)
    assert result is None


def test_shutdown_checks(tgen):
    # Start a process rnuning that will fetch bunches of data then shut the routers down
    # and check for cores.
    nrepeat = 100
    r1 = tgen.gears["r1"]
    commands = ["GET,/frr-interface:lib" for _ in range(0, nrepeat)]
    p = r1.popen([script_path, f"--port={GRPCP_ZEBRA}"] + commands)
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
