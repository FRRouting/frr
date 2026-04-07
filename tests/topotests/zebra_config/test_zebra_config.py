# -*- coding: utf-8 eval: (blacken-mode 1) -*-
#
# April 7 2026, Christian Hopps <chopps@labn.net>
#
# Copyright (c) 2026, LabN Consulting, L.L.C.
#
#
"""
Test zebra config. Expand as we go.
"""
import ipaddress
import logging
import os
import re
from pathlib import Path

import pytest
from lib import topotest
from lib.common_config import retry, step
from lib.topogen import Topogen, TopoRouter

pytestmark = [pytest.mark.staticd, pytest.mark.mgmtd]


@pytest.fixture(scope="module")
def tgen(request):
    "Setup/Teardown the environment and provide tgen argument to tests"

    topodef = {"s1": ("r1",)}

    tgen = Topogen(topodef, request.module.__name__)
    tgen.start_topology()

    for router in tgen.routers().values():
        router.load_frr_config("frr.conf")

    tgen.start_router()
    yield tgen
    tgen.stop_topology()


@pytest.fixture(scope="module")
def r1(tgen):
    return tgen.gears["r1"].net


@pytest.fixture(scope="module")
def confdir():
    return Path(os.environ["PYTEST_TOPOTEST_SCRIPTDIR"]) / "r1"


@pytest.fixture(autouse=True, scope="function")
def cleanup_config(r1):
    yield

    r1.cmd_nostatus("vtysh -c 'conf t' -c 'no allow-external-route-update'")
    r1.cmd_nostatus("vtysh -c 'conf t' -c 'no router-id 1.2.3.4'")
    r1.cmd_nostatus("vtysh -c 'conf t' -c 'no ip table range 2 3'")
    r1.cmd_nostatus("vtysh -c 'conf t' -c 'no ip import-table 10'")
    r1.cmd_nostatus("vtysh -c 'conf t' -c 'no ipv6 import-table 10 mrib'")
    r1.cmd_nostatus(
        "vtysh -c 'conf t' -c 'no ip import-table 11 route-map IMPORT-FILTER'"
    )
    r1.cmd_nostatus(
        "vtysh -c 'conf t' -c 'no ipv6 import-table 11 mrib route-map IMPORT-FILTER'"
    )
    r1.cmd_nostatus("vtysh -c 'conf t' -c 'no route-map IMPORT-FILTER'")
    r1.cmd_nostatus("vtysh -c 'conf t' -c 'no zebra work-queue'")
    r1.cmd_nostatus("vtysh -c 'conf t' -c 'no zebra zapi-packets'")
    r1.cmd_nostatus("vtysh -c 'conf t' -c 'no zebra dplane limit'")
    expect_show_running(
        r1,
        absent=[
            "ip table range 2 3",
            "ip import-table 10",
            "ipv6 import-table 10 mrib",
            "ip import-table 11 route-map IMPORT-FILTER",
            "ipv6 import-table 11 mrib route-map IMPORT-FILTER",
            "route-map IMPORT-FILTER permit 10",
            "zebra work-queue",
            "zebra zapi-packets",
            "zebra dplane limit",
        ],
    )


def check_show_running(r1, present=None, absent=None):
    showrun = r1.cmd_nostatus("vtysh -c 'show running'")

    for entry in present or []:
        if entry not in showrun:
            return f"Missing '{entry}' in show running:\n{showrun}"

    for entry in absent or []:
        if entry in showrun:
            return f"Unexpected '{entry}' in show running:\n{showrun}"

    return None


def expect_show_running(r1, present=None, absent=None):
    test_func = lambda: check_show_running(r1, present=present, absent=absent)
    _, result = topotest.run_and_expect(test_func, None, count=20, wait=1)
    assert result is None, result


def test_zebra_import_table_file(r1, confdir):
    conf = "import-table-zebra.conf"
    step(f"load {conf} file with vtysh -f ")
    output = r1.cmd_nostatus(f"vtysh -f {confdir / conf}")
    print(output)

    expect_show_running(
        r1,
        present=["ip import-table 10", "ipv6 import-table 10 mrib"],
        absent=["route-map IMPORT-FILTER"],
    )


def test_zebra_import_table_route_map_file(r1, confdir):
    conf = "import-table-route-map-zebra.conf"
    step(f"load {conf} file with vtysh -f ")
    output = r1.cmd_nostatus(f"vtysh -f {confdir / conf}")
    print(output)

    expect_show_running(
        r1,
        present=[
            "route-map IMPORT-FILTER permit 10",
            "ip import-table 11 route-map IMPORT-FILTER",
            "ipv6 import-table 11 mrib route-map IMPORT-FILTER",
        ],
    )


def test_zebra_mgmt_frontend_smoke(r1):
    step("Configure mgmt-fronted zebra smoke commands")
    r1.cmd_nostatus(
        "vtysh -c 'conf t' -c 'zebra work-queue 123' "
        "-c 'zebra zapi-packets 456' -c 'zebra dplane limit 789'"
    )

    expect_show_running(
        r1,
        present=[
            "zebra work-queue 123",
            "zebra zapi-packets 456",
            "zebra dplane limit 789",
        ],
    )

    step("Remove mgmt-fronted zebra smoke commands")
    r1.cmd_nostatus(
        "vtysh -c 'conf t' -c 'no zebra work-queue' "
        "-c 'no zebra zapi-packets' -c 'no zebra dplane limit'"
    )

    expect_show_running(
        r1,
        absent=[
            "zebra work-queue",
            "zebra zapi-packets",
            "zebra dplane limit",
        ],
    )
