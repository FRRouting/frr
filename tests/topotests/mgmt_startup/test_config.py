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

import pytest
from lib.common_config import retry, step
from lib.topogen import Topogen, TopoRouter
from lib.topolog import logger

# pytestmark = [pytest.mark.staticd, pytest.mark.mgmtd]
pytestmark = [pytest.mark.staticd]


@pytest.fixture(scope="module")
def tgen(request):
    "Setup/Teardown the environment and provide tgen argument to tests"

    topodef = {
        "s1": ("r1", "r2", "r3"),
    }

    tgen = Topogen(topodef, request.module.__name__)
    tgen.start_topology()

    # configure mgmtd using current mgmtd config file
    tgen.gears["r1"].load_config(TopoRouter.RD_ZEBRA, "zebra.conf")
    tgen.gears["r1"].load_config(TopoRouter.RD_MGMTD, "mgmtd.conf")

    # user/topotest compat:
    # configure mgmtd using old staticd config file, with explicity staticd
    # load.
    tgen.gears["r2"].load_config(TopoRouter.RD_ZEBRA, "zebra.conf")
    tgen.gears["r2"].load_config(TopoRouter.RD_STATIC, "staticd.conf")

    # user compat:
    # configure mgmtd using backup config file `zebra.conf`
    tgen.gears["r3"].load_config(TopoRouter.RD_ZEBRA, "zebra.conf")

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

    for x in ["r1", "r2", "r3"]:
        tgen.gears[x].net.cmd_nostatus(
            "vtysh -c 'debug mgmt client frontend' "
            "-c 'debug mgmt client backend' "
            "-c 'debug mgmt backend frontend datastore transaction'"
        )

    r1 = tgen.routers()["r1"]
    r2 = tgen.routers()["r2"]
    r3 = tgen.routers()["r3"]

    step("Verifying routes are present on r1")
    result = check_kernel(r1, "12.0.0.0/24")
    assert result is None
    result = check_kernel(r1, "13.0.0.0/24")
    assert result is None

    step("Verifying routes are present on r2")
    result = check_kernel(r2, "11.0.0.0/24")
    assert result is None
    result = check_kernel(r2, "13.0.0.0/24")
    assert result is None

    step("Verifying routes are present on r3")
    result = check_kernel(r3, "11.0.0.0/24")
    assert result is None
    result = check_kernel(r3, "12.0.0.0/24")
    assert result is None
