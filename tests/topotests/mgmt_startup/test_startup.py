# -*- coding: utf-8 eval: (blacken-mode 1) -*-
# SPDX-License-Identifier: ISC
#
# May 2 2023, Christian Hopps <chopps@labn.net>
#
# Copyright (c) 2023, LabN Consulting, L.L.C.
#
"""
Test static route functionality using old or new configuration files.

User compat:

 - mgmtd split config will first look to `/etc/frr/zebra.conf`
   then `/etc/frr/staticd.conf` and finally `/etc/frr/mgmtd.conf`

 - When new components are converted to mgmtd their split config should be
   added here too.

Topotest compat:

  - `mgmtd.conf` is copied to `/etc/frr/` for use by mgmtd when implicit load,
    or explicit load no config specified.

  - `staticd.conf` is copied to `/etc/frr/` for use by mgmtd when staticd
    is explicit load implict config, and explicit config.

"""

import ipaddress
import re
import time

import pytest
from lib.common_config import create_static_routes, retry, step, verify_rib
from lib.topogen import Topogen, TopoRouter
from lib.topolog import logger

# pytestmark = [pytest.mark.staticd, pytest.mark.mgmtd]
pytestmark = [pytest.mark.staticd]


@pytest.fixture(scope="module")
def tgen(request):
    "Setup/Teardown the environment and provide tgen argument to tests"

    topodef = {
        "s1": ("r1",),
    }

    tgen = Topogen(topodef, request.module.__name__)
    tgen.start_topology()

    # configure mgmtd using current mgmtd config file
    tgen.gears["r1"].load_config(TopoRouter.RD_ZEBRA, "zebra.conf")
    tgen.gears["r1"].load_config(TopoRouter.RD_MGMTD)

    # Explicit disable staticd now..
    tgen.gears["r1"].net.daemons["staticd"] = 0

    tgen.start_router()
    yield tgen
    tgen.stop_topology()


@retry(retry_timeout=3, initial_wait=0.1)
def check_kernel(r1, prefix, expected=True):
    net = ipaddress.ip_network(prefix)
    if net.version == 6:
        kernel = r1.net.cmd_nostatus("ip -6 route show", warn=not expected)
    else:
        kernel = r1.net.cmd_nostatus("ip -4 route show", warn=not expected)

    logger.debug("checking kernel routing table:\n%s", kernel)
    route = f"{str(net)}(?: nhid [0-9]+)?.*proto (static|196)"
    m = re.search(route, kernel)
    if expected and not m:
        return f"Failed to find \n'{route}'\n in \n'{kernel}'"
    elif not expected and m:
        return f"Failed found \n'{route}'\n in \n'{kernel}'"
    return None


def test_staticd_late_start(tgen):
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    # for x in ["r1"]:
    #     tgen.gears[x].net.cmd_nostatus(
    #         "vtysh -c 'debug mgmt client frontend' "
    #         "-c 'debug mgmt client backend' "
    #         "-c 'debug mgmt backend frontend datastore transaction'"
    #     )

    r1 = tgen.routers()["r1"]

    step("Verifying startup route is not present w/o staticd running")
    result = check_kernel(r1, "12.0.0.0/24", expected=False)
    assert result is not None

    step("Configure another static route verify is not present w/o staticd running")
    r1.net.cmd_nostatus("vtysh -c 'config t' -c 'ip route 12.1.0.0/24 101.0.0.2'")
    result = check_kernel(r1, "12.0.0.0/24", expected=False)
    assert result is not None
    result = check_kernel(r1, "12.1.0.0/24", expected=False)
    assert result is not None

    step("Starting staticd")
    r1.startDaemons(["staticd"])

    step("Verifying both routes are present")
    result = check_kernel(r1, "12.0.0.0/24")
    assert result is None
    result = check_kernel(r1, "12.1.0.0/24")
    assert result is None
