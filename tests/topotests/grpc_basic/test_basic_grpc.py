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

import logging
import os
import sys

import pytest

from lib.common_config import step
from lib.micronet import commander
from lib.topogen import Topogen, TopoRouter
from lib.topolog import logger

CWD = os.path.dirname(os.path.realpath(__file__))

GRPCP_ZEBRA = 50051
GRPCP_STATICD = 50052
GRPCP_BFDD = 50053
GRPCP_ISISD = 50054
GRPCP_OSPFD = 50055
GRPCP_PIMD = 50056

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
        router.load_config(TopoRouter.RD_STATIC, None, f"-M grpc:{GRPCP_STATICD}")
        # router.load_config(TopoRouter.RD_BFD, None, f"-M grpc:{GRPCP_BFDD}")
        # router.load_config(TopoRouter.RD_ISIS, None, f"-M grpc:{GRPCP_ISISD}")
        # router.load_config(TopoRouter.RD_OSPF, None, f"-M grpc:{GRPCP_OSPFD}")
        # router.load_config(TopoRouter.RD_PIM, None, f"-M grpc:{GRPCP_PIMD}")

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
    r1 = tgen.gears["r1"]
    output = r1.cmd_raises("ping -c1 192.168.1.2")
    logging.info("ping output: %s", output)


def test_capabilities(tgen):
    r1 = tgen.gears["r1"]
    output = run_grpc_client(r1, GRPCP_ZEBRA, "GETCAP")
    logging.info("grpc output: %s", output)


def test_get_config(tgen):
    nrepeat = 5
    r1 = tgen.gears["r1"]

    step("'GET' interface config 10 times, once per invocation")

    for i in range(0, nrepeat):
        output = run_grpc_client(r1, GRPCP_ZEBRA, "GET,/frr-interface:lib")
        logging.info("[iteration %s]: grpc GET output: %s", i, output)

    step(f"'GET' YANG {nrepeat} times in one invocation")
    commands = ["GET,/frr-interface:lib" for _ in range(0, 10)]
    output = run_grpc_client(r1, GRPCP_ZEBRA, commands)
    logging.info("grpc GET*{%d} output: %s", nrepeat, output)


def test_get_vrf_config(tgen):
    r1 = tgen.gears["r1"]

    step("'GET' get VRF config")

    output = run_grpc_client(r1, GRPCP_ZEBRA, "GET,/frr-vrf:lib")
    logging.info("grpc GET /frr-vrf:lib output: %s", output)


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
