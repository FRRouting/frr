# -*- coding: utf-8 eval: (blacken-mode 1) -*-
# SPDX-License-Identifier: ISC
#
# April 22 2026, Christian Hopps <chopps@labn.net>
#
# Copyright (c) 2026, LabN Consulting, L.L.C.
#

"""
Test that backend informational messages are returned to the frontend on commit.
Tests both the edit reply path (mgmt edit) and the commit reply path (CLI command).
"""
import os

import pytest
from lib.common_config import retry
from lib.topogen import Topogen

pytestmark = [pytest.mark.mgmtd]

CWD = os.path.dirname(os.path.realpath(__file__))
BE_CLIENT = "/usr/lib/frr/mgmtd_testc"


@pytest.fixture(scope="module")
def tgen(request):
    "Setup/Teardown the environment and provide tgen argument to tests"

    topodef = {"s1": ("r1",)}

    tgen = Topogen(topodef, request.module.__name__)
    tgen.start_topology()

    router_list = tgen.routers()
    for router in router_list.values():
        router.load_frr_config()

    tgen.start_router()
    yield tgen
    tgen.stop_topology()


@retry(retry_timeout=30)
def check_client_connect(r1):
    out = r1.vtysh_cmd("show mgmt backend-adapter all")
    return None if "mgmtd-testc" in out else "missing mgmtd-testc"


def _start_be_client(r1):
    """Start backend test client and wait for it to connect."""
    rc, _, _ = r1.net.cmd_status(BE_CLIENT + " --help")
    if rc:
        pytest.skip("No mgmtd_testc")

    p = r1.net.popen(
        [BE_CLIENT, "--timeout", "20", "--log", "file:mgmtd_testc.log"],
    )

    res = check_client_connect(r1)
    assert res is None, "mgmtd_testc did not connect"
    return p


def _check_info_output(out, client_name, value):
    """Verify the output contains info message from backend."""
    assert "Configuration applied with notes:" in out, (
        f"Expected 'Configuration applied with notes:' in output, got: {out!r}"
    )
    assert f"{client_name}:" in out, (
        f"Expected '{client_name}:' in output, got: {out!r}"
    )
    assert value in out, f"Expected '{value}' in output, got: {out!r}"


def test_edit_reply_info(tgen):
    """Test info messages via the edit reply path (mgmt edit command)."""
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]
    p = _start_be_client(r1)

    try:
        xpath = "/frr-test-config:frr-test-config"
        data = '{"frr-test-config:frr-test-config":{"test-value":"edit-test"}}'
        out = r1.net.cmd_raises(
            f"vtysh -c 'conf term' -c 'mgmt edit replace {xpath} lock commit {data}'"
        )
    finally:
        p.kill()

    _check_info_output(out, "MGMTD-TESTC", "edit-test")


def test_commit_reply_info(tgen):
    """Test info messages via the commit reply path (CLI config command)."""
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]
    p = _start_be_client(r1)

    try:
        out = r1.vtysh_cmd("conf\nmgmt test-config-value commit-test")
    finally:
        p.kill()

    _check_info_output(out, "MGMTD-TESTC", "commit-test")
