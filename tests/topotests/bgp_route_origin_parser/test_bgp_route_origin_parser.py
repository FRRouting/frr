#!/usr/bin/env python
# SPDX-License-Identifier: GPL-2.0-or-later
#
# April 03 2023, Trey Aspelund <taspelund@nvidia.com>
#
# Copyright (C) 2023 NVIDIA Corporation
#
# Test if the CLI parser for RT/SoO ecoms correctly
# constrain user input to valid 4-byte ASN values.
#

import os
import sys
import pytest
import functools

CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

# pylint: disable=C0413
from lib import topotest
from lib.topogen import Topogen, TopoRouter, get_topogen
from lib.common_config import step

pytestmark = [pytest.mark.bgpd]


def build_topo(tgen):
    tgen.add_router("pe1")


def setup_module(mod):
    tgen = Topogen(build_topo, mod.__name__)
    tgen.start_topology()
    pe1 = tgen.gears["pe1"]
    pe1.load_config(TopoRouter.RD_BGP, os.path.join(CWD, "pe1/bgpd.conf"))
    tgen.start_router()


def teardown_module(mod):
    tgen = get_topogen()
    tgen.stop_topology()


def test_bgp_route_origin_parser():
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    pe1 = tgen.gears["pe1"]

    def _invalid_soo_accepted():
        pe1.vtysh_cmd(
            """
        configure terminal
        router bgp 65001
         address-family ipv4 unicast
          neighbor 192.168.2.1 soo 4294967296:65
        """
        )
        run_cfg = pe1.vtysh_cmd("show run")
        return "soo" in run_cfg

    def _max_soo_accepted():
        pe1.vtysh_cmd(
            """
        configure terminal
        router bgp 65001
         address-family ipv4 unicast
          neighbor 192.168.2.1 soo 4294967295:65
            """
        )
        run_cfg = pe1.vtysh_cmd("show run")
        return "soo 4294967295:65" in run_cfg

    def _invalid_rt_accepted():
        pe1.vtysh_cmd(
            """
        configure terminal
        router bgp 65001
         address-family ipv4 unicast
          rt vpn both 4294967296:65
        """
        )
        run_cfg = pe1.vtysh_cmd("show run")
        return "rt vpn" in run_cfg

    def _max_rt_accepted():
        pe1.vtysh_cmd(
            """
        configure terminal
        router bgp 65001
         address-family ipv4 unicast
          rt vpn both 4294967295:65
            """
        )
        run_cfg = pe1.vtysh_cmd("show run")
        return "rt vpn both 4294967295:65" in run_cfg

    step(
        "Configure invalid 4-byte value SoO (4294967296:65), this should not be accepted"
    )
    test_func = functools.partial(_invalid_soo_accepted)
    _, result = topotest.run_and_expect(test_func, False, count=30, wait=0.5)
    assert result is False, "invalid 4-byte value of SoO accepted"

    step("Configure max 4-byte value SoO (4294967295:65), this should be accepted")
    test_func = functools.partial(_max_soo_accepted)
    _, result = topotest.run_and_expect(test_func, True, count=30, wait=0.5)
    assert result is True, "max 4-byte value of SoO not accepted"

    step(
        "Configure invalid 4-byte value RT (4294967296:65), this should not be accepted"
    )
    test_func = functools.partial(_invalid_rt_accepted)
    _, result = topotest.run_and_expect(test_func, False, count=30, wait=0.5)
    assert result is False, "invalid 4-byte value of RT accepted"

    step("Configure max 4-byte value RT (4294967295:65), this should be accepted")
    test_func = functools.partial(_max_rt_accepted)
    _, result = topotest.run_and_expect(test_func, True, count=30, wait=0.5)
    assert result is True, "max 4-byte value of RT not accepted"


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
