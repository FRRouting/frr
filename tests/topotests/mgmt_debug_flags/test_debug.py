#!/usr/bin/env python
# -*- coding: utf-8 eval: (blacken-mode 1) -*-
# SPDX-License-Identifier: ISC
#
# Copyright (c) 2021, LabN Consulting, L.L.C.
# Copyright (c) 2019-2020 by
# Donatas Abraitis <donatas.abraitis@gmail.com>
#
# noqa: E501
#
"""
Test static route functionality
"""
import pytest
from lib.common_config import step
from lib.topogen import Topogen
from munet.watchlog import WatchLog

pytestmark = [pytest.mark.staticd, pytest.mark.mgmtd]


@pytest.fixture(scope="module")
def tgen(request):
    "Setup/Teardown the environment and provide tgen argument to tests"

    topodef = {"s1": ("r1",)}
    tgen = Topogen(topodef, request.module.__name__)
    tgen.start_topology()

    for rname, router in tgen.routers().items():
        router.load_frr_config("frr.conf")

    tgen.start_router()
    yield tgen
    tgen.stop_topology()


def test_client_debug_enable(tgen):
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]

    # Start watching log files
    watch_mgmtd_log = WatchLog(r1.net.rundir / "mgmtd.log")
    watch_staticd_log = WatchLog(r1.net.rundir / "staticd.log")

    def __test_debug(r1, on):
        watch_mgmtd_log.snapshot()
        watch_staticd_log.snapshot()

        # Add ip route and remove look for debug.
        r1.vtysh_cmd("conf t\nip route 11.11.11.11/32 1.1.1.2")
        r1.vtysh_cmd("conf t\nno ip route 11.11.11.11/32 1.1.1.2")

        new_mgmt_logs = watch_mgmtd_log.snapshot()
        new_be_logs = watch_staticd_log.snapshot()

        fe_cl_msg = "Sending SET_CONFIG_REQ"
        fe_ad_msg = "Got SETCFG_REQ"
        be_ad_msg = "Sending CFGDATA_CREATE_REQ"
        be_cl_msg = "Got CFG_APPLY_REQ"

        if on:
            assert fe_cl_msg in new_mgmt_logs
            assert fe_ad_msg in new_mgmt_logs
            assert be_ad_msg in new_mgmt_logs
            assert be_cl_msg in new_be_logs
        else:
            assert fe_cl_msg not in new_mgmt_logs
            assert fe_ad_msg not in new_mgmt_logs
            assert be_ad_msg not in new_mgmt_logs
            assert be_cl_msg not in new_be_logs

    step("test debug off")
    __test_debug(r1, False)

    # Turn it on
    step("tests debug on")
    r1.vtysh_cmd("debug mgmt client frontend")
    r1.vtysh_cmd("debug mgmt client backend")
    r1.vtysh_cmd("debug mgmt backend frontend")
    __test_debug(r1, True)

    # Turn it off
    step("tests debug off")
    r1.vtysh_cmd("no debug mgmt client frontend")
    r1.vtysh_cmd("no debug mgmt client backend")
    r1.vtysh_cmd("no debug mgmt backend frontend")
    __test_debug(r1, False)

    # Configure it on
    step("tests debug on")
    r1.vtysh_cmd("conf t\ndebug mgmt client frontend")
    r1.vtysh_cmd("conf t\ndebug mgmt client backend")
    r1.vtysh_cmd("conf t\ndebug mgmt backend frontend")
    __test_debug(r1, True)

    # Configure it off
    step("tests debug off")
    r1.vtysh_cmd("conf t\nno debug mgmt client frontend")
    r1.vtysh_cmd("conf t\nno debug mgmt client backend")
    r1.vtysh_cmd("conf t\nno debug mgmt backend frontend")
    __test_debug(r1, False)

    # Turn it on
    step("tests debug on")
    r1.vtysh_cmd("debug mgmt client frontend")
    r1.vtysh_cmd("debug mgmt client backend")
    r1.vtysh_cmd("debug mgmt backend frontend")
    __test_debug(r1, True)
    # Configure it on
    step("tests debug on")
    r1.vtysh_cmd("conf t\ndebug mgmt client frontend")
    r1.vtysh_cmd("conf t\ndebug mgmt client backend")
    r1.vtysh_cmd("conf t\ndebug mgmt backend frontend")
    __test_debug(r1, True)
    # Turn it off
    step("tests debug on")
    r1.vtysh_cmd("no debug mgmt client frontend")
    r1.vtysh_cmd("no debug mgmt client backend")
    r1.vtysh_cmd("no debug mgmt backend frontend")
    __test_debug(r1, True)
    # Configure it off
    step("tests debug off")
    r1.vtysh_cmd("conf t\nno debug mgmt client frontend")
    r1.vtysh_cmd("conf t\nno debug mgmt client backend")
    r1.vtysh_cmd("conf t\nno debug mgmt backend frontend")
    __test_debug(r1, False)
