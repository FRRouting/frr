# -*- coding: utf-8 eval: (blacken-mode 1) -*-
# SPDX-License-Identifier: ISC
#
# July 13 2023, Christian Hopps <chopps@labn.net>
#
# Copyright (c) 2023, LabN Consulting, L.L.C.
#
"""
Test mgmtd regressions

"""
import logging
import re
import time

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

    tgen.gears["r1"].load_frr_config("frr2.conf")
    tgen.gears["r1"].net.add_l3vrf("red", 10)
    tgen.gears["r1"].net.attach_iface_to_l3vrf("r1-eth0", "red")

    tgen.start_router()
    yield tgen
    tgen.stop_topology()


def check_locked(r1g):
    # This was another regression but was not related to mgmtd being broken, but rather
    # underlying messaging. The connections from mgmtd to daemons cycled, and the new
    # sockets had same fd's but when written to the receiver never got the data. So the
    # 10m timerout timer was running with the datastore locked.
    time.sleep(2)
    output = r1g.vtysh_multicmd(
        """
        conf t
            int r1-eth0
        end
        """
    )
    assert "could not lock" not in output


def test_regression_disconnect_after_abort(tgen):
    r1g = tgen.gears["r1"]
    r1 = r1g.net

    step("Config an active VRF")
    output = r1g.vtysh_multicmd(
        """
        show vrf
        conf t
        vrf red
        router-id 1.1.1.1
        exit-vrf
        end
        """
    )

    wl = WatchLog(r1.rundir / "frr.log")

    wl.snapshot()

    step('Try to un-config an active vrf (i.e., "no vrf"), verify failure')
    output = r1g.vtysh_multicmd(
        """
        show vrf
        conf t
            no vrf red
        end
        """
    )
    assert "Only inactive VRFs can be deleted" in output

    logged = wl.snapshot()

    step("Check that no clients disconnected due to config validation failure")
    matches = re.findall(r"disconnect.*client.*(zebra|static)", logged)
    assert not matches, f"Found clients {matches} disconnected after validation failure"

    step("Verify TXN_REQ delete sent to all subscribed clients")
    regex = r"([-0-9A-Z_]+): \[[-0-9A-Z]*\] BE-CLIENT:.*Ignoring TXN_DELETE"
    matches = re.findall(regex, logged)
    assert (
        len(matches) == 2
    ), f"Wrong number of clients (2 != {len(matches)}) received TXN_REQ delete"

    step("Checking for still locked regression")
    check_locked(r1g)
