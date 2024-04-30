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
import pytest
from lib.topogen import Topogen

pytestmark = [pytest.mark.staticd, pytest.mark.mgmtd]


@pytest.fixture(scope="module")
def tgen(request):
    "Setup/Teardown the environment and provide tgen argument to tests"

    topodef = {"s1": ("r1",)}
    tgen = Topogen(topodef, request.module.__name__)
    tgen.start_topology()
    tgen.gears["r1"].load_frr_config("frr.conf")
    tgen.start_router()
    yield tgen
    tgen.stop_topology()


def test_regression_issue_13920(tgen):
    """Issue #13920

    ubuntu2204# conf t
    ubuntu2204(config)# ip route 3.2.4.0/24 6.5.5.11 loop3
    ubuntu2204(config)# nexthop-group nh2
    ubuntu2204(config-nh-group)# nexthop 6.5.5.12
    ubuntu2204(config-nh-group)# exi
    ubuntu2204(config)# ip route 3.22.4.0/24 6.5.5.12
    crash
    """

    r1 = tgen.gears["r1"]
    r1.vtysh_multicmd(
        """
    conf t
    nexthop-group nh2
    exit
    ip route 3.22.4.0/24 6.5.5.12
    """
    )
    output = r1.net.checkRouterCores()
    assert not output.strip()


def test_regression_pullreq_15423(tgen):
    r1 = tgen.gears["r1"]
    r1.vtysh_multicmd(
        """
    conf t
    access-list test seq 1 permit ip any 10.10.10.0 0.0.0.255
    """
    )

    output = r1.vtysh_multicmd(
        """
    conf terminal file-lock
    mgmt delete-config /frr-filter:lib/access-list[name='test'][type='ipv4']/entry[sequence='1']/destination-network
    mgmt commit apply
    end
    """
    )
    assert "No changes found" not in output
