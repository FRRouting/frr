#!/usr/bin/env python
# SPDX-License-Identifier: ISC

#
# Part of NetDEF Topology Tests
#
# Copyright 2021 by LINE Corporation, Hiroki Shirokura <hiroki.shirokura@linecorp.com>
# Copyright 2023 6WIND S.A.

"""
test_isis_sr_flex_algo_topo2.py:

[+] Flex-Algos 128
[+] Flex-Algos 129
[+] Flex-Algos 130 include-any blue

            +--------+                  +--------+
            |        |                  |        |
            |  RT1   |------------------|  RT2   |
            |        |                  |        |
            +--------+                  +--------+
           /     |    \\                     |    \\
          /      |     \\                    |     \\
+--------+       |      \\                   |      \\
|        |       |       +--------+          |       +--------+
|  RT0   |       |       |        |          |       |        |
|        |       |       |  RT4   |------------------|  RT3   |
+--------+       |       |        |          |       |        |
          \\     |       +--------+          |       +--------+
           \\    |           |               |            |    \\
            +--------+       |          +--------+        |     \\
            |        |       |          |        |        |      +--------+
            |  RT5   |-------|----------|  RT6   |        |      |        |
            |        |       |          |        |        |      |  RT9   |
            +--------+       |          +--------+        |      |        |
                      \\     |                    \\      |      +--------+
                       \\    |                     \\     |     /
                        \\   |                      \\    |    /
                         +--------+                  +--------+
                         |        |                  |        |
                         |  RT8   |------------------|  RT7   |
                         |        |                  |        |
                         +--------+                  +--------+
"""

import os
import sys
import pytest
import json
import time
from functools import partial

# Save the Current Working Directory to find configuration files.
CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

# pylint: disable=C0413
# Import topogen and topotest helpers
from lib import topotest
from lib.topogen import Topogen, TopoRouter, get_topogen
from lib.topolog import logger


pytestmark = [pytest.mark.isisd]


def build_topo(tgen):
    "Build function"

    routers = []
    for i in range(0, 10):
        rt = tgen.add_router("rt{}".format(i))
        rt.run("sysctl -w net.ipv4.fib_multipath_hash_policy=1")

    def connect_routers(tgen, left_idx, right_idx):
        left = "rt{}".format(left_idx)
        right = "rt{}".format(right_idx)
        switch = tgen.add_switch("s-{}-{}".format(left, right))
        switch.add_link(tgen.gears[left], nodeif="eth-{}".format(right))
        switch.add_link(tgen.gears[right], nodeif="eth-{}".format(left))
        l_addr = "52:54:00:{}:{}:{}".format(left_idx, right_idx, left_idx)
        tgen.gears[left].run("ip link set eth-{} down".format(right))
        tgen.gears[left].run("ip link set eth-{} address {}".format(right, l_addr))
        tgen.gears[left].run("ip link set eth-{} up".format(right))
        tgen.gears[left].run("sysctl -w net.mpls.conf.eth-{}.input=1".format(right))
        r_addr = "52:54:00:{}:{}:{}".format(left_idx, right_idx, right_idx)
        tgen.gears[right].run("ip link set eth-{} down".format(left))
        tgen.gears[right].run("ip link set eth-{} address {}".format(left, r_addr))
        tgen.gears[right].run("ip link set eth-{} up".format(left))
        tgen.gears[right].run("sysctl -w net.mpls.conf.eth-{}.input=1".format(left))

    connect_routers(tgen, 0, 1)
    connect_routers(tgen, 0, 5)
    connect_routers(tgen, 1, 2)
    connect_routers(tgen, 1, 4)
    connect_routers(tgen, 1, 5)
    connect_routers(tgen, 2, 3)
    connect_routers(tgen, 2, 6)
    connect_routers(tgen, 3, 4)
    connect_routers(tgen, 3, 7)
    connect_routers(tgen, 3, 9)
    connect_routers(tgen, 4, 8)
    connect_routers(tgen, 5, 6)
    connect_routers(tgen, 5, 8)
    connect_routers(tgen, 6, 7)
    connect_routers(tgen, 7, 8)
    connect_routers(tgen, 7, 9)


def setup_module(mod):
    "Sets up the pytest environment"
    tgen = Topogen(build_topo, mod.__name__)
    frrdir = tgen.config.get(tgen.CONFIG_SECTION, "frrdir")
    if not os.path.isfile(os.path.join(frrdir, "pathd")):
        pytest.skip("pathd daemon wasn't built")
    tgen.start_topology()
    router_list = tgen.routers()

    # For all registered routers, load the zebra configuration file
    for rname, router in router_list.items():
        router.load_config(
            TopoRouter.RD_ZEBRA, os.path.join(CWD, "{}/zebra.conf".format(rname))
        )
        router.load_config(
            TopoRouter.RD_ISIS, os.path.join(CWD, "{}/isisd.conf".format(rname))
        )
        if rname in ["rt0", "rt9"]:
            router.load_config(
                TopoRouter.RD_BGP, os.path.join(CWD, "{}/bgpd.conf".format(rname))
            )
            router.load_config(
                TopoRouter.RD_PATH, os.path.join(CWD, "{}/pathd.conf".format(rname))
            )
            router.run("ip link add dum0 type dummy")
            router.run("ip link set dum0 up")
            if rname == "rt0":
                router.run("ip addr add 10.255.0.1/24 dev dum0")
            elif rname == "rt9":
                router.run("ip addr add 10.255.9.1/24 dev dum0")
    tgen.start_router()


def teardown_module(mod):
    "Teardown the pytest environment"
    tgen = get_topogen()
    tgen.stop_topology()


def setup_testcase(msg):
    logger.info(msg)
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)
    return tgen


def open_json_file(filename):
    try:
        with open(filename, "r") as f:
            return json.load(f)
    except IOError:
        assert False, "Could not read file {}".format(filename)


def check_rib(name, cmd, expected_file):
    def _check(name, cmd, expected_file):
        logger.info("polling")
        tgen = get_topogen()
        router = tgen.gears[name]
        output = json.loads(router.vtysh_cmd(cmd))
        expected = open_json_file("{}/{}".format(CWD, expected_file))
        return topotest.json_cmp(output, expected)

    logger.info('[+] check {} "{}" {}'.format(name, cmd, expected_file))
    tgen = get_topogen()
    func = partial(_check, name, cmd, expected_file)
    success, result = topotest.run_and_expect(func, None, count=120, wait=0.5)
    assert result is None, "Failed"


def test_rib():
    check_rib("rt0", "show mpls table json", "rt0/step1/route.json")
    check_rib("rt1", "show mpls table json", "rt1/step1/route.json")
    check_rib("rt2", "show mpls table json", "rt2/step1/route.json")
    check_rib("rt3", "show mpls table json", "rt3/step1/route.json")
    check_rib("rt4", "show mpls table json", "rt4/step1/route.json")
    check_rib("rt5", "show mpls table json", "rt5/step1/route.json")
    check_rib("rt6", "show mpls table json", "rt6/step1/route.json")
    check_rib("rt7", "show mpls table json", "rt7/step1/route.json")
    check_rib("rt8", "show mpls table json", "rt8/step1/route.json")
    check_rib("rt9", "show mpls table json", "rt9/step1/route.json")


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
