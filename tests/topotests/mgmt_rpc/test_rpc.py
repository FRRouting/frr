# -*- coding: utf-8 eval: (blacken-mode 1) -*-
# SPDX-License-Identifier: ISC
#
# March 21 2024, Igor Ryzhov <iryzhov@nfware.com>
#
# Copyright (c) 2024, NFWare Inc.
#

"""
Test YANG Notifications
"""
import json
import os
import threading

import pytest
from lib.common_config import retry
from lib.topogen import Topogen
from lib.topotest import json_cmp

pytestmark = [pytest.mark.ripd, pytest.mark.mgmtd]

CWD = os.path.dirname(os.path.realpath(__file__))


@pytest.fixture(scope="module")
def tgen(request):
    "Setup/Teardown the environment and provide tgen argument to tests"

    topodef = {"s1": ("r1",)}

    tgen = Topogen(topodef, request.module.__name__)
    tgen.start_topology()

    router_list = tgen.routers()
    for _, router in router_list.items():
        router.load_frr_config("frr.conf")

    tgen.start_router()
    yield tgen
    tgen.stop_topology()


# Verify the backend test client has connected
@retry(retry_timeout=10)
def check_client_connect(r1):
    out = r1.vtysh_cmd("show mgmt backend-adapter all")
    assert "mgmtd-testc" in out


def test_backend_rpc(tgen):
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]

    # Run the backend test client which registers to handle the `clear ip rip` command.
    be_client_path = "/usr/lib/frr/mgmtd_testc"
    rc, _, _ = r1.net.cmd_status(be_client_path + " --help")

    if rc:
        pytest.skip("No mgmtd_testc")

    out = []

    def run_testc():
        output = r1.net.cmd_raises(
            be_client_path + " --timeout 10 --log file:mgmt_testc.log"
        )
        out.append(json.loads(output))

    t = threading.Thread(target=run_testc)
    t.start()

    # We need to wait for mgmtd_testc to connect before issuing the command.
    res = check_client_connect(r1)
    assert res is None

    r1.vtysh_cmd("clear ip rip vrf testname")

    t.join()

    jsout = out[0]

    expected = {"frr-ripd:clear-rip-route": {"vrf": "testname"}}
    result = json_cmp(jsout, expected)
    assert result is None
