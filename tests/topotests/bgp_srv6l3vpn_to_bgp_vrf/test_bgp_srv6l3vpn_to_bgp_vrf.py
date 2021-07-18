#!/usr/bin/env python

#
# Part of NetDEF Topology Tests
#
# Copyright (c) 2018, LabN Consulting, L.L.C.
# Authored by Lou Berger <lberger@labn.net>
#
# Permission to use, copy, modify, and/or distribute this software
# for any purpose with or without fee is hereby granted, provided
# that the above copyright notice and this permission notice appear
# in all copies.
#
# THE SOFTWARE IS PROVIDED "AS IS" AND NETDEF DISCLAIMS ALL WARRANTIES
# WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
# MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL NETDEF BE LIABLE FOR
# ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY
# DAMAGES WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS,
# WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS
# ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE
# OF THIS SOFTWARE.
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
from lib.micronet_compat import Topo


class Topology(Topo):
    """
      CE1     CE3      CE5
    (eth0)  (eth0)   (eth0)
      :2      :2      :2
       |       |       |
     2001:   2001:   2001:
     1::/64  3::/64  5::/64
       |       |       |
      :1      :1      :1
   +-(eth1)--(eth2)---(eth3)-+
   |     \   /          |    |
   |    (vrf10)     (vrf20)  |
   |             R1          |
   +----------(eth0)---------+
                :1
                |
            2001::/64
                |
                :2
              (eth0)
    +----------(eth0)--------------+
    |            R2                |
    |   (vrf10)       (vrf20)      |
    |     /           /     \      |
    +-(eth1)-----(eth2)-----(eth3)-+
        :1         :1          :1
         |          |           |
      +------+   +------+   +------+
     /  2001: \ /  2001: \ /  2001: \
     \ 2::/64 / \ 4::/64 / \ 6::/64 /
      +------+   +------+   +------+
         |           |          |
        :2          :2         :2
      (eth0)      (eth0)      (eth0)
        CE2         CE4         CE6
    """
    def build(self, *_args, **_opts):
        tgen = get_topogen(self)
        tgen.add_router("r1")
        tgen.add_router("r2")
        tgen.add_router("ce1")
        tgen.add_router("ce2")
        tgen.add_router("ce3")
        tgen.add_router("ce4")
        tgen.add_router("ce5")
        tgen.add_router("ce6")

        tgen.add_link(tgen.gears["r1"], tgen.gears["r2"], "eth0", "eth0")
        tgen.add_link(tgen.gears["ce1"], tgen.gears["r1"], "eth0", "eth1")
        tgen.add_link(tgen.gears["ce2"], tgen.gears["r2"], "eth0", "eth1")
        tgen.add_link(tgen.gears["ce3"], tgen.gears["r1"], "eth0", "eth2")
        tgen.add_link(tgen.gears["ce4"], tgen.gears["r2"], "eth0", "eth2")
        tgen.add_link(tgen.gears["ce5"], tgen.gears["r1"], "eth0", "eth3")
        tgen.add_link(tgen.gears["ce6"], tgen.gears["r2"], "eth0", "eth3")


def setup_module(mod):
    result = required_linux_kernel_version("4.15")
    if result is not True:
        pytest.skip("Kernel requirements are not met")

    tgen = Topogen(Topology, mod.__name__)
    tgen.start_topology()
    router_list = tgen.routers()
    for rname, router in tgen.routers().items():
        router.run("/bin/bash {}/{}/setup.sh".format(CWD, rname))
        router.load_config(TopoRouter.RD_ZEBRA,
                           os.path.join(CWD, '{}/zebra.conf'.format(rname)))
        router.load_config(TopoRouter.RD_BGP,
                           os.path.join(CWD, '{}/bgpd.conf'.format(rname)))

    tgen.gears["r1"].run("ip link add vrf10 type vrf table 10")
    tgen.gears["r1"].run("ip link set vrf10 up")
    tgen.gears["r1"].run("ip link add vrf20 type vrf table 20")
    tgen.gears["r1"].run("ip link set vrf20 up")
    tgen.gears["r1"].run("ip link set eth1 master vrf10")
    tgen.gears["r1"].run("ip link set eth2 master vrf10")
    tgen.gears["r1"].run("ip link set eth3 master vrf20")

    tgen.gears["r2"].run("ip link add vrf10 type vrf table 10")
    tgen.gears["r2"].run("ip link set vrf10 up")
    tgen.gears["r2"].run("ip link add vrf20 type vrf table 20")
    tgen.gears["r2"].run("ip link set vrf20 up")
    tgen.gears["r2"].run("ip link set eth1 master vrf10")
    tgen.gears["r2"].run("ip link set eth2 master vrf20")
    tgen.gears["r2"].run("ip link set eth3 master vrf20")
    tgen.start_router()


def teardown_module(mod):
    tgen = get_topogen()
    tgen.stop_topology()


def open_json_file(filename):
    try:
        with open(filename, "r") as f:
            return json.load(f)
    except IOError:
        assert False, "Could not read file {}".format(filename)


def test_rib():
    def _check(name, cmd, expected_file):
        logger.info("polling")
        tgen = get_topogen()
        router = tgen.gears[name]
        output = json.loads(router.vtysh_cmd(cmd))
        expected = open_json_file("{}/{}".format(CWD, expected_file))
        return topotest.json_cmp(output, expected)

    def check(name, cmd, expected_file):
        logger.info("[+] check {} \"{}\" {}".format(name, cmd, expected_file))
        tgen = get_topogen()
        func = functools.partial(_check, name, cmd, expected_file)
        success, result = topotest.run_and_expect(func, None, count=10, wait=0.5)
        assert result is None, 'Failed'

    check("r1", "show bgp ipv6 vpn json", "r1/vpnv6_rib.json")
    check("r2", "show bgp ipv6 vpn json", "r2/vpnv6_rib.json")
    check("r1", "show ipv6 route vrf vrf10 json", "r1/vrf10_rib.json")
    check("r1", "show ipv6 route vrf vrf20 json", "r1/vrf20_rib.json")
    check("r2", "show ipv6 route vrf vrf10 json", "r2/vrf10_rib.json")
    check("r2", "show ipv6 route vrf vrf20 json", "r2/vrf20_rib.json")
    check("ce1", "show ipv6 route json", "ce1/ipv6_rib.json")
    check("ce2", "show ipv6 route json", "ce2/ipv6_rib.json")
    check("ce3", "show ipv6 route json", "ce3/ipv6_rib.json")
    check("ce4", "show ipv6 route json", "ce4/ipv6_rib.json")
    check("ce5", "show ipv6 route json", "ce5/ipv6_rib.json")
    check("ce6", "show ipv6 route json", "ce6/ipv6_rib.json")


def test_ping():
    def _check(name, dest_addr, match):
        tgen = get_topogen()
        output = tgen.gears[name].run("ping6 {} -c 1 -w 1".format(dest_addr))
        logger.info(output)
        assert match in output, "ping fail"

    def check(name, dest_addr, match):
        logger.info("[+] check {} {} {}".format(name, dest_addr, match))
        tgen = get_topogen()
        func = functools.partial(_check, name, dest_addr, match)
        success, result = topotest.run_and_expect(func, None, count=10, wait=0.5)
        assert result is None, 'Failed'

    check("ce1", "2001:2::2", " 0% packet loss")
    check("ce1", "2001:3::2", " 0% packet loss")
    check("ce1", "2001:4::2", " 100% packet loss")
    check("ce1", "2001:5::2", " 100% packet loss")
    check("ce1", "2001:6::2", " 100% packet loss")
    check("ce4", "2001:1::2", " 100% packet loss")
    check("ce4", "2001:2::2", " 100% packet loss")
    check("ce4", "2001:3::2", " 100% packet loss")
    check("ce4", "2001:5::2", " 0% packet loss")
    check("ce4", "2001:6::2", " 0% packet loss")


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
