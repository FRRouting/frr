#!/usr/bin/env python
# SPDX-License-Identifier: ISC

# Copyright (c) 2022, LINE Corporation
# Authored by Ryoga Saito <ryoga.saito@linecorp.com>
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
    tgen.add_router("pe1")
    tgen.add_router("ce1")

    tgen.add_link(tgen.gears["pe1"], tgen.gears["ce1"], "eth0", "eth0")


def setup_module(mod):
    tgen = Topogen(build_topo, mod.__name__)
    tgen.start_topology()

    for rname, router in tgen.routers().items():
        router.load_config(
            TopoRouter.RD_ZEBRA, os.path.join(CWD, "{}/zebra.conf".format(rname))
        )
        router.load_config(
            TopoRouter.RD_BGP, os.path.join(CWD, "{}/bgpd.conf".format(rname))
        )

    tgen.gears["pe1"].run("ip link add vrf10 type vrf table 10")
    tgen.gears["pe1"].run("ip link set vrf10 up")
    tgen.gears["pe1"].run("ip link add vrf20 type vrf table 20")
    tgen.gears["pe1"].run("ip link set vrf20 up")
    tgen.gears["pe1"].run("ip link set eth0 master vrf10")

    tgen.start_router()


def teardown_module(mod):
    tgen = get_topogen()
    tgen.stop_topology()


def open_json_file(path):
    try:
        with open(path, "r") as f:
            return json.load(f)
    except IOError:
        assert False, "Could not read file {}".format(path)


def check_vrf10_rib(output):
    expected = open_json_file("%s/pe1/results/vrf10_ipv4_unicast.json" % CWD)
    actual = json.loads(output)
    return topotest.json_cmp(actual, expected)


def check_default_vpn_rib(output):
    expected = open_json_file("%s/pe1/results/default_ipv4_vpn.json" % CWD)
    actual = json.loads(output)
    return topotest.json_cmp(actual, expected)


def check_vrf20_rib(output):
    expected = open_json_file("%s/pe1/results/vrf20_ipv4_unicast.json" % CWD)
    actual = json.loads(output)
    return topotest.json_cmp(actual, expected)


def check(name, command, checker):
    tgen = get_topogen()
    router = tgen.gears[name]

    def _check():
        try:
            return checker(router.vtysh_cmd(command))
        except:
            return False

    logger.info('[+] check {} "{}"'.format(name, command))
    _, result = topotest.run_and_expect(_check, None, count=10, wait=0.5)
    assert result is None, "Failed"


def test_rib():
    check("pe1", "show bgp vrf vrf10 ipv4 unicast json", check_vrf10_rib)
    check("pe1", "show bgp ipv4 vpn json", check_default_vpn_rib)
    check("pe1", "show bgp vrf vrf20 ipv4 unicast json", check_vrf20_rib)


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
