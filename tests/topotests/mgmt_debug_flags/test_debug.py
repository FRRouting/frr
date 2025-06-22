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
import time

import pytest
from lib.common_config import step
from lib.topogen import Topogen
from munet.testing.util import retry
from munet.watchlog import WatchLog

pytestmark = [pytest.mark.staticd, pytest.mark.mgmtd]


@pytest.fixture(scope="module")
def tgen(request):
    "Setup/Teardown the environment and provide tgen argument to tests"

    topodef = {"s1": ("r1",)}
    tgen = Topogen(topodef, request.module.__name__)
    tgen.start_topology()

    for _, router in tgen.routers().items():
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
        time.sleep(1)

        @retry(retry_timeout=10, retry_sleep=0.25)
        def __scan_log(log, items):
            log.update_content()
            content = log.from_mark(log.last_snap_mark)
            for item in items:
                if item not in content:
                    return f"{item} not found in {log.path}:{content}"

        def __scan_log_notfound(log, items, delay=2):
            time.sleep(delay)
            log.update_content()
            content = log.from_mark(log.last_snap_mark)
            for item in items:
                if item in content:
                    return f"{item} found in {log.path}:{content}"

        watch_mgmtd_log.snapshot()
        watch_staticd_log.snapshot()

        # Add ip route and look for debug.
        r1.vtysh_cmd("conf t\nip route 11.11.11.11/32 1.1.1.2")
        try:
            fe_cl_msg = "Sending COMMIT "
            fe_ad_msg = "Got COMMIT "
            be_ad_msg = "Sending CFG_REQ"
            be_cl_msg = "Got CFG_APPLY_REQ"

            if on:
                error = __scan_log(watch_mgmtd_log, [fe_cl_msg, fe_ad_msg, be_ad_msg])
                assert not error, error
                error = __scan_log(watch_staticd_log, [be_cl_msg])
                assert not error, error
            else:
                error = __scan_log_notfound(
                    watch_mgmtd_log, [fe_cl_msg, fe_ad_msg, be_ad_msg]
                )
                assert not error, error
                error = __scan_log_notfound(watch_staticd_log, [be_cl_msg])
                assert not error, error
        finally:
            # Remove ip route to cleanup
            r1.vtysh_cmd("conf t\nno ip route 11.11.11.11/32 1.1.1.2")

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
