# -*- coding: utf-8 eval: (blacken-mode 1) -*-
# SPDX-License-Identifier: ISC
#
# September 18 2025, Christian Hopps <chopps@labn.net>
#
# Copyright (c) 2025, LabN Consulting, L.L.C.
#
"""
Test backend daemon config validation failure
"""
import pytest
from lib.common_config import step
from lib.topogen import Topogen

pytestmark = [pytest.mark.staticd]


@pytest.fixture(scope="module")
def tgen(request):
    "Setup/Teardown the environment and provide tgen argument to tests"

    topodef = {"net1": ("r1:eth0",)}
    tgen = Topogen(topodef, request.module.__name__)
    tgen.start_topology()

    router_list = tgen.routers()
    for _, router in router_list.items():
        router.load_frr_config("frr.conf")

    tgen.start_router()
    yield tgen
    tgen.stop_topology()


def test_backend_config_validation_fail(tgen):
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"].net

    step("Configure too long interface name", reset=True)
    bad_config = "interface long-interface-name-exceeding-16-chars"
    try:
        r1.cmd_raises(f"vtysh -c conf -c '{bad_config}' -c end")
    except Exception:
        pass
    else:
        pytest.fail("Expected failure on too long interface name")
