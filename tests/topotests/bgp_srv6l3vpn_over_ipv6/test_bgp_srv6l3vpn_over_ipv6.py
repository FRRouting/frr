#!/usr/bin/env python
# SPDX-License-Identifier: ISC

#
# Part of NetDEF Topology Tests
#
# Copyright (c) 2018, LabN Consulting, L.L.C.
# Authored by Lou Berger <lberger@labn.net>
#

import os
import re
import sys
import json
import functools
import pytest

CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

# pylint: disable=C0413
# Import topogen and topotest helpers
from lib import topotest
from lib.topogen import Topogen, TopoRouter, get_topogen
from lib.topolog import logger
from lib.common_config import required_linux_kernel_version

pytestmark = [pytest.mark.bgpd]


def build_topo(tgen):
    tgen.add_router("r1")
    tgen.add_router("r2")
    tgen.add_router("r3")

    tgen.add_router("c11")
    tgen.add_router("c12")
    tgen.add_router("c21")
    tgen.add_router("c22")
    tgen.add_router("c31")
    tgen.add_router("c32")

    tgen.add_link(tgen.gears["r1"], tgen.gears["r2"], "eth0", "eth0")
    tgen.add_link(tgen.gears["r1"], tgen.gears["r3"], "eth1", "eth0")
    tgen.add_link(tgen.gears["r1"], tgen.gears["c11"], "eth2", "eth0")
    tgen.add_link(tgen.gears["r1"], tgen.gears["c12"], "eth3", "eth0")
    tgen.add_link(tgen.gears["r2"], tgen.gears["c21"], "eth1", "eth0")
    tgen.add_link(tgen.gears["r2"], tgen.gears["c22"], "eth2", "eth0")
    tgen.add_link(tgen.gears["r3"], tgen.gears["c31"], "eth1", "eth0")
    tgen.add_link(tgen.gears["r3"], tgen.gears["c32"], "eth2", "eth0")


def setup_module(mod):
    result = required_linux_kernel_version("5.15")
    if result is not True:
        pytest.skip("Kernel requirements are not met")

    tgen = Topogen(build_topo, mod.__name__)
    tgen.start_topology()

    for rname, router in tgen.routers().items():
        router.load_config(
            TopoRouter.RD_ZEBRA, os.path.join(CWD, "{}/zebra.conf".format(rname))
        )
        router.load_config(
            TopoRouter.RD_STATIC, os.path.join(CWD, "{}/staticd.conf".format(rname))
        )
        router.load_config(
            TopoRouter.RD_BGP, os.path.join(CWD, "{}/bgpd.conf".format(rname))
        )

    tgen.gears["r1"].run("sysctl net.vrf.strict_mode=1")
    tgen.gears["r1"].run("ip link add vrf10 type vrf table 10")
    tgen.gears["r1"].run("ip link set vrf10 up")
    tgen.gears["r1"].run("ip link add vrf20 type vrf table 20")
    tgen.gears["r1"].run("ip link set vrf20 up")
    tgen.gears["r1"].run("ip link set eth2 master vrf10")
    tgen.gears["r1"].run("ip link set eth3 master vrf20")

    tgen.gears["r2"].run("sysctl net.vrf.strict_mode=1")
    tgen.gears["r2"].run("ip link add vrf10 type vrf table 10")
    tgen.gears["r2"].run("ip link set vrf10 up")
    tgen.gears["r2"].run("ip link add vrf20 type vrf table 20")
    tgen.gears["r2"].run("ip link set vrf20 up")
    tgen.gears["r2"].run("ip link set eth1 master vrf10")
    tgen.gears["r2"].run("ip link set eth2 master vrf20")

    tgen.gears["r3"].run("sysctl net.vrf.strict_mode=1")
    tgen.gears["r3"].run("ip link add vrf10 type vrf table 10")
    tgen.gears["r3"].run("ip link set vrf10 up")
    tgen.gears["r3"].run("ip link add vrf20 type vrf table 20")
    tgen.gears["r3"].run("ip link set vrf20 up")
    tgen.gears["r3"].run("ip link set eth1 master vrf10")
    tgen.gears["r3"].run("ip link set eth2 master vrf20")

    tgen.start_router()


def teardown_module(mod):
    tgen = get_topogen()
    tgen.stop_topology()


def check_ping4(name, dest_addr, expected):
    def _check(name, dest_addr, match):
        tgen = get_topogen()
        output = tgen.gears[name].run("ping {} -c 1 -w 1".format(dest_addr))
        logger.info(output)
        if match not in output:
            return "ping fail"

    match = ", {} packet loss".format("0%" if expected else "100%")
    logger.info("[+] check {} {} {}".format(name, dest_addr, match))
    tgen = get_topogen()
    func = functools.partial(_check, name, dest_addr, match)
    success, result = topotest.run_and_expect(func, None, count=10, wait=1)
    assert result is None, "Failed"


def test_ping():
    tgen = get_topogen()

    check_ping4("c11", "192.168.2.1", True)
    check_ping4("c11", "192.168.3.1", True)
    check_ping4("c12", "192.168.2.1", True)
    check_ping4("c12", "192.168.3.1", True)
    check_ping4("c21", "192.168.3.1", True)
    check_ping4("c22", "192.168.3.1", True)


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
