#!/usr/bin/env python
# SPDX-License-Identifier: ISC
# -*- coding: utf-8 eval: (blacken-mode 1) -*-
#
# September 17 2024, Christian Hopps <chopps@labn.net>
#
# Copyright (c) 2024, LabN Consulting, L.L.C.
#

import json
import pytest
from lib.topogen import Topogen

pytestmark = [pytest.mark.staticd, pytest.mark.mgmtd]


@pytest.fixture(scope="module")
def tgen(request):
    "Setup/Teardown the environment and provide tgen argument to tests"

    topodef = {"s1": ("r1",)}

    tgen = Topogen(topodef, request.module.__name__)
    tgen.start_topology()

    router_list = tgen.routers()
    for rname, router in router_list.items():
        router.load_frr_config("frr-yanglib.conf")

    tgen.start_router()
    yield tgen
    tgen.stop_topology()


def test_yang_lib(tgen):
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"].net
    output = r1.cmd_nostatus(
        "vtysh -c 'show mgmt get-data /ietf-yang-library:yang-library'"
    )
    ret = json.loads(output)
    loaded_modules = ret['ietf-yang-library:yang-library']['module-set'][0]['module']
    assert len(loaded_modules) > 10, "Modules missing from yang-library"
