# -*- coding: utf-8 eval: (blacken-mode 1) -*-
# SPDX-License-Identifier: ISC
#
# May 2 2023, Christian Hopps <chopps@labn.net>
#
# Copyright (c) 2023, LabN Consulting, L.L.C.
#

"""
Verify routes present when staticd (backend client) is started after it's startup
config, contained inside a unified configuration file, is present during launch.
"""
import pytest
from lib.topogen import Topogen
from util import _test_staticd_late_start

pytestmark = [pytest.mark.staticd, pytest.mark.mgmtd]


@pytest.fixture(scope="module")
def tgen(request):
    "Setup/Teardown the environment and provide tgen argument to tests"

    topodef = {
        "s1": ("r4",),
    }

    tgen = Topogen(topodef, request.module.__name__)
    tgen.start_topology()

    # configure mgmtd using current mgmtd config file
    tgen.gears["r4"].load_frr_config("frr.conf")

    # Explicit disable staticd now..
    tgen.gears["r4"].net.daemons["staticd"] = 0

    tgen.start_router()
    yield tgen
    tgen.stop_topology()


def test_staticd_late_start(tgen):
    return _test_staticd_late_start(tgen, tgen.routers()["r4"])
