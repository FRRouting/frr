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
import sys
import json
import functools
import pytest
from time import sleep

CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

# pylint: disable=C0413
# Import topogen and topotest helpers
from lib import topotest
from lib.topogen import Topogen, TopoRouter, get_topogen
from lib.topolog import logger
from lib.common_config import required_linux_kernel_version

pytestmark = [pytest.mark.bgpd, pytest.mark.isisd]


def build_topo(tgen):
    """
      H11         H12                                                                                                     H41           H42
    (h11r1)     (h12r1)                                                                                                 (h41r4)       (h42r4)
       |           |                                                                                                       |             |
    4444::1     4444::3                                                                                                 4444::2       4444::4
    /128        /128                                                                                                    /128          /128
    10.0.1.1    10.0.1.3                                                                                                10.0.1.2      10.0.1.4
    /32         /32                                                                                                     /32           /32
       |           |                                                                                                       |             |
   +-(r1h11)----(r1h12)---------+              +---------------+              +---------------+              +----------(r4h41)-------(r4h42)--+
   |    |          |            |              |               |              |               |              |             |             |     |
   | (vrf10)    (vrf20)       (r1r2)---------(r2r1)          (r2r3)---------(r3r2)          (r3r4)---------(r4r3)        (vrf10)      (vrf20)  |
   | fe80::1    fe80::2         |              |       R2      |              |       R3      |              |           fe80::1      fe80::2  |
   | /128       /128            |              |  fcff:0:2::1  |              |  fcff:0:3::1  |              |           /128         /128     |
   | 169.254.   169.254.        |              |               |              |               |              |           169.254.     169.254. |
   | 0.1/16     0.2/16          |              |               |              |               |              |           0.1/16       0.2/16   |
   |        R1 fcff:0:1::1      |              |               |              |               |              |          R4 fcff:0:4::1         |
   +-(r1r6)-------(r1r5)--------+              +---------------+              +---------------+              +-(r4r5)-------(r4r6)-------------+
        \            \                                                                                           /            /
         \            \                                                                                         /            /
          \            \                                                                                       /            /
           \            \                                  +--------------------+                             /            /
            \            \                                 |         R5         |                            /            /
             \            \                                |                    |                           /            /
              \            ------------------------------(r5r1)              (r5r4)-------------------------            /
               \                                           |     fcff:0:5::1    |                                      /
                \                                          |                    |                                     /
                 \                                         +--------------------+                                    /
                  \                                                                                                 /
                   \                                       +--------------------+                                  /
                    \                                      |         R6         |                                 /
                     \                                     |                    |                                /
                      -----------------------------------(r6r1)               (r6r4)-----------------------------
                                                           |     fcff:0:6::1    |
                                                           |                    |
                                                           +--------------------+

    Dockerfile additions:
          vim
          tmux
          tcpdump
          traceroute
    """
    tgen.add_router("r1")
    tgen.add_router("r2")
    tgen.add_router("r3")
    tgen.add_router("r4")
    tgen.add_router("r5")
    tgen.add_router("r6")
    tgen.add_router("h11")
    tgen.add_router("h12")
    tgen.add_router("h41")
    tgen.add_router("h42")

    # r1
    tgen.add_link(tgen.gears["r1"], tgen.gears["r2"], "r1r2", "r2r1")
    tgen.add_link(tgen.gears["r1"], tgen.gears["r5"], "r1r5", "r5r1")
    tgen.add_link(tgen.gears["r1"], tgen.gears["r6"], "r1r6", "r6r1")

    # r2
    tgen.add_link(tgen.gears["r2"], tgen.gears["r3"], "r2r3", "r3r2")
    tgen.add_link(tgen.gears["r2"], tgen.gears["r4"], "r2r5", "r5r2")

    # r3
    tgen.add_link(tgen.gears["r3"], tgen.gears["r4"], "r3r4", "r4r3")

    # r4
    tgen.add_link(tgen.gears["r4"], tgen.gears["r5"], "r4r5", "r5r4")
    tgen.add_link(tgen.gears["r4"], tgen.gears["r6"], "r4r6", "r6r4")

    # r1 connected hosts
    tgen.add_link(tgen.gears["h11"], tgen.gears["r1"], "h11r1", "r1h11")
    tgen.add_link(tgen.gears["h12"], tgen.gears["r1"], "h12r1", "r1h12")

    # r4 connected hosts
    tgen.add_link(tgen.gears["h41"], tgen.gears["r4"], "h41r4", "r4h41")
    tgen.add_link(tgen.gears["h42"], tgen.gears["r4"], "h42r4", "r4h42")


def setup_module(mod):
    result = required_linux_kernel_version("4.15")
    if result is not True:
        pytest.skip("Kernel requirements are not met")

    tgen = Topogen(build_topo, mod.__name__)
    tgen.start_topology()
    
    tgen.gears["r1"].run("sysctl net.vrf.strict_mode=1")
    tgen.gears["r1"].run("ip link add vrf10 type vrf table 10")
    tgen.gears["r1"].run("ip link set vrf10 up")
    tgen.gears["r1"].run("ip link add vrf20 type vrf table 20")
    tgen.gears["r1"].run("ip link set vrf20 up")
    tgen.gears["r1"].run("ip link set r1h11 master vrf10")
    tgen.gears["r1"].run("ip link set r1h12 master vrf20")
    tgen.gears["r1"].run("ip route add table 10 10.0.1.1/32 dev r1h11")
    tgen.gears["r1"].run("ip -6 route add table 10 4444::1/128 dev r1h11")
    tgen.gears["r1"].run("ip route add table 20 10.0.1.3/32 dev r1h12")
    tgen.gears["r1"].run("ip -6 route add table 20 4444::3/128 dev r1h12")

    tgen.gears["r4"].run("sysctl net.vrf.strict_mode=1")
    tgen.gears["r4"].run("ip link add vrf10 type vrf table 10")
    tgen.gears["r4"].run("ip link set vrf10 up")
    tgen.gears["r4"].run("ip link add vrf20 type vrf table 20")
    tgen.gears["r4"].run("ip link set vrf20 up")
    tgen.gears["r4"].run("ip link set r4h41 master vrf10")
    tgen.gears["r4"].run("ip link set r4h42 master vrf20")
    tgen.gears["r4"].run("ip route add table 10 10.0.1.2/32 dev r4h41")
    tgen.gears["r4"].run("ip -6 route add table 10 4444::2/128 dev r4h41")
    tgen.gears["r4"].run("ip route add table 20 10.0.1.4/32 dev r4h42")
    tgen.gears["r4"].run("ip -6 route add table 20 4444::4/128 dev r4h42")

    tgen.gears["h11"].run("ip route add 169.254.0.1 dev h11r1")
    tgen.gears["h11"].run("ip route add 10.0.1.0/24 via 169.254.0.1 dev h11r1")
    tgen.gears["h11"].run("ip -6 route add 4444::/64 via fe80::1 dev h11r1")
    tgen.gears["h41"].run("ip route add 169.254.0.1 dev h41r4")
    tgen.gears["h41"].run("ip route add 10.0.1.0/24 via 169.254.0.1 dev h41r4")
    tgen.gears["h41"].run("ip -6 route add 4444::/64 via fe80::1 dev h41r4")

    tgen.gears["h12"].run("ip route add 169.254.0.2 dev h12r1")
    tgen.gears["h12"].run("ip route add 10.0.1.0/24 via 169.254.0.2 dev h12r1")
    tgen.gears["h12"].run("ip -6 route add 4444::/64 via fe80::2 dev h12r1")
    tgen.gears["h42"].run("ip route add 169.254.0.2 dev h42r4")
    tgen.gears["h42"].run("ip route add 10.0.1.0/24 via 169.254.0.2 dev h42r4")
    tgen.gears["h42"].run("ip -6 route add 4444::/64 via fe80::2 dev h42r4")

    router_list = tgen.routers()
    for rname, router in tgen.routers().items():
        router.load_config(
            TopoRouter.RD_ZEBRA, os.path.join(CWD, "{}/zebra.conf".format(rname))
        )
        router.load_config(
            TopoRouter.RD_BGP, os.path.join(CWD, "{}/bgpd.conf".format(rname))
        )
        router.load_config(
            TopoRouter.RD_ISIS, os.path.join(CWD, "{}/isisd.conf".format(rname))
        )

    tgen.start_router()

    # FOR DEVELOPER:
    # If you want to stop some specific line and start interactive shell,
    # please use tgen.mininet_cli() to start it.


def teardown_module(mod):
    tgen = get_topogen()
    tgen.stop_topology()


def open_json_file(filename):
    try:
        with open(filename, "r") as f:
            return json.load(f)
    except IOError:
        assert False, "Could not read file {}".format(filename)


def check_ping(name, dest_addr, iface, expect_connected):
    def _check(name, dest_addr, iface, match):
        tgen = get_topogen()
        cmd = ""
        if ":" in dest_addr:
            if iface:
                cmd = "ping6 -I {} {} -c 1 -w 1".format(iface, dest_addr)
            else:
                cmd = "ping6 {} -c 1 -w 1".format(dest_addr)
        else:
            if iface:
                cmd = "ping -I {} {} -c 1 -w 1".format(iface, dest_addr)
            else:
                cmd = "ping {} -c 1 -w 1".format(dest_addr)
        output = tgen.gears[name].run(cmd)
        logger.info(output)
        if match not in output:
            return "ping fail"

    match = ", {} packet loss".format("0%" if expect_connected else "100%")
    logger.info("[+] check name={} dest_addr={} iface={} match={}".format(name, dest_addr, iface, match))
    tgen = get_topogen()
    func = functools.partial(_check, name, dest_addr, iface, match)
    success, result = topotest.run_and_expect(func, None, count=10, wait=1)
    assert result is None, "Failed"

def check_setup_completed(rname, match):
    count = 0
    tgen = get_topogen()
    while count < 60:
        res = tgen.gears[rname].run("ip -6 route")
        logger.info("count-{} result {}".format(count, res))
        if match in res:
            return True
        count += 1
        sleep(1)
    return False


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
    func = functools.partial(_check, name, cmd, expected_file)
    success, result = topotest.run_and_expect(func, None, count=10, wait=0.5)
    assert result is None, "Failed"


def check_kernel_v6_state(rname, dest_addr, vrfname, matchlist):
    count = 0
    tgen = get_topogen()
    while count < 60:
        res = tgen.gears[rname].run('ip -6 route show vrf {} | grep -A 2 "{}"'.format(vrfname, dest_addr))
        logger.info("count-{} result {}".format(count, res))
        if res:
            for match in matchlist:
                if not (match in res):
                    return False
            return True
        count += 1
        sleep(1)
    return False

def test_topology():
    logger.info("Check h11 connectivity")
    check_ping("h11", "169.254.0.1", "h11r1", True)
    check_ping("h11", "169.254.0.2", "h11r1", False)
    check_ping("h11", "fe80::1", "h11r1", True)
    check_ping("h11", "fe80::2", "h11r1", False)

    logger.info("Check h12 connectivity")
    check_ping("h12", "169.254.0.2", "h12r1", True)
    check_ping("h12", "169.254.0.1", "h12r1", False)
    check_ping("h12", "fe80::2", "h12r1", True)
    check_ping("h12", "fe80::1", "h12r1", False)

    logger.info("Check h41 connectivity")
    check_ping("h41", "169.254.0.1", "h41r4", True)
    check_ping("h41", "169.254.0.2", "h41r4", False)
    check_ping("h41", "fe80::1", "h41r4", True)
    check_ping("h41", "fe80::2", "h41r4", False)

    logger.info("Check h42 connectivity")
    check_ping("h42", "169.254.0.1", "h42r4", False)
    check_ping("h42", "169.254.0.2", "h42r4", True)
    check_ping("h42", "fe80::1", "h42r4", False)
    check_ping("h42", "fe80::2", "h42r4", True)

    logger.info("Check r1-r2 connectivity")
    if not check_setup_completed("r1", "fcff:0:2::/48"):
        assert False, "r1 doesn't contains route to fcff:0:2::/48"
    if not check_setup_completed("r2", "fcff:0:1::/48"):
        assert False, "r1 doesn't contains route to fcff:0:1::/48"
    check_ping("r1", "fcff:0:2::1", "r1r2", True)
    check_ping("r2", "fcff:0:1::1", "r2r1", True)

    logger.info("Check r2-r3 connectivity")
    if not check_setup_completed("r2", "fcff:0:3::/48"):
        assert False, "r2 doesn't contains route to fcff:0:3::/48"
    if not check_setup_completed("r3", "fcff:0:2::/48"):
        assert False, "r3 doesn't contains route to fcff:0:2::/48"
    check_ping("r2", "fcff:0:3::1", "r2r3", True)
    check_ping("r3", "fcff:0:2::1", "r3r2", True)

    logger.info("Check r3-r4 connectivity")
    if not check_setup_completed("r3", "fcff:0:4::/48"):
        assert False, "r3 doesn't contains route to fcff:0:4::/48"
    if not check_setup_completed("r4", "fcff:0:3::/48"):
        assert False, "r4 doesn't contains route to fcff:0:3::/48"
    check_ping("r3", "fcff:0:4::1", "r3r4", True)
    check_ping("r4", "fcff:0:3::1", "r4r3", True)

    logger.info("Check r4-r5 connectivity")
    if not check_setup_completed("r4", "fcff:0:5::/48"):
        assert False, "r4 doesn't contains route to fcff:0:5::/48"
    if not check_setup_completed("r5", "fcff:0:4::/48"):
        assert False, "r5 doesn't contains route to fcff:0:4::/48"
    check_ping("r4", "fcff:0:5::1", "r4r5", True)
    check_ping("r5", "fcff:0:4::1", "r5r4", True)

    logger.info("Check r5-r1 connectivity")
    if not check_setup_completed("r5", "fcff:0:1::/48"):
        assert False, "r5 doesn't contains route to fcff:0:1::/48"
    if not check_setup_completed("r1", "fcff:0:5::/48"):
        assert False, "r1 doesn't contains route to fcff:0:5::/48"
    check_ping("r5", "fcff:0:1::1", "r5r1", True)
    check_ping("r1", "fcff:0:5::1", "r1r5", True)

    logger.info("Check r4-r6 connectivity")
    if not check_setup_completed("r4", "fcff:0:6::/48"):
        assert False, "r4 doesn't contains route to fcff:0:6::/48"
    if not check_setup_completed("r6", "fcff:0:4::/48"):
        assert False, "r6 doesn't contains route to fcff:0:4::/48"
    check_ping("r4", "fcff:0:6::1", "r4r6", True)
    check_ping("r6", "fcff:0:4::1", "r6r4", True)

    logger.info("Check r6-r1 connectivity")
    if not check_setup_completed("r6", "fcff:0:1::/48"):
        assert False, "r6 doesn't contains route to fcff:0:1::/48"
    if not check_setup_completed("r1", "fcff:0:6::/48"):
        assert False, "r1 doesn't contains route to fcff:0:6::/48"
    check_ping("r6", "fcff:0:1::1", "r6r1", True)
    check_ping("r1", "fcff:0:6::1", "r1r6", True)

def test_kernel_state():
    logger.info("Check r1 kernel state (vrf10)")
    if not check_kernel_v6_state("r1", "4444::2", "vrf10", ["fcff:0:4:2::","encap seg6","r1r6", "r1r5"]):
        assert False, "r1 doesn't contains ipv6 route to 4444::2 in vrf vrf10"
    logger.info("Check r4 kernel state (vrf10)")
    if not check_kernel_v6_state("r4", "4444::1", "vrf10", ["fcff:0:1:2::","encap seg6","r4r6", "r4r5"]):
        assert False, "r4 doesn't contains ipv6 route to 4444::1 in vrf vrf10"

    logger.info("Check h11-h41 connectivity")
    check_ping("h11", "4444::2", None, True)
    check_ping("h11", "4444::4", None, False)
    check_ping("h11", "4444::3", None, False)
    check_ping("h11", "10.0.1.2", None, True)
    check_ping("h11", "10.0.1.3", None, False)
    check_ping("h11", "10.0.1.4", None, False)

    logger.info("Check h41-h11 connectivity")
    check_ping("h41", "4444::1", None, True)
    check_ping("h41", "4444::4", None, False)
    check_ping("h41", "4444::3", None, False)
    check_ping("h41", "10.0.1.1", None, True)
    check_ping("h41", "10.0.1.3", None, False)
    check_ping("h41", "10.0.1.4", None, False)

    logger.info("Check r1 kernel state (vrf20)")
    if not check_kernel_v6_state("r1", "4444::4", "vrf20", ["fcff:0:4:4::","encap seg6","r1r6", "r1r5"]):
        assert False, "r1 doesn't contains ipv6 route to 4444::4 in vrf vrf20"
    logger.info("Check r4 kernel state (vrf20)")
    if not check_kernel_v6_state("r4", "4444::3", "vrf20", ["fcff:0:1:4::","encap seg6","r4r6", "r4r5"]):
        assert False, "r4 doesn't contains ipv6 route to 4444::3 in vrf vrf20"

    logger.info("Check h12-h42 connectivity")
    check_ping("h12", "4444::2", None, False)
    check_ping("h12", "4444::4", None, True)
    check_ping("h12", "4444::1", None, False)
    check_ping("h12", "10.0.1.4", None, True)
    check_ping("h12", "10.0.1.2", None, False)
    check_ping("h12", "10.0.1.1", None, False)

    logger.info("Check h42-h12 connectivity")
    check_ping("h42", "4444::3", None, True)
    check_ping("h42", "4444::1", None, False)
    check_ping("h42", "4444::2", None, False)
    check_ping("h42", "10.0.1.3", None, True)
    check_ping("h42", "10.0.1.1", None, False)
    check_ping("h42", "10.0.1.2", None, False)


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
