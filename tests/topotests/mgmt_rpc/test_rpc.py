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
    for rname, router in router_list.items():
        router.load_frr_config("frr.conf")

    tgen.start_router()
    yield tgen
    tgen.stop_topology()


def test_backend_rpc(tgen):
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]

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

    r1.vtysh_cmd("clear ip rip vrf testname")

    t.join()

    jsout = out[0]

    expected = {"frr-ripd:clear-rip-route": {"vrf": "testname"}}
    result = json_cmp(jsout, expected)
    assert result is None
