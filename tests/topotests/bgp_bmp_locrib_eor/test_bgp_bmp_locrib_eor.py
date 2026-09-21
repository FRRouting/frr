#!/usr/bin/env python
# SPDX-License-Identifier: ISC
#
# Copyright (c) 2026 by
# Kyle Qi <kyle@nexthop.ai>
#
# BMP Loc-RIB End-of-RIB is sent once per AFI/SAFI.
#
#   +------+          +------+          +------+
#   | BMP1 |----s1----|  R1  |----------|  R2  |
#   +------+          +------+          +------+
#
# R1 has two eBGP sessions to R2 (IPv4 and IPv6 transport), both negotiating
# IPv4 unicast and neither negotiating IPv6 unicast. R1 monitors IPv4 and IPv6
# unicast pre-policy, post-policy and loc-rib. The initial table dump must carry
# exactly one Loc-RIB End-of-RIB per monitored AFI/SAFI, regardless of how many
# peers negotiated it (two for IPv4, zero for IPv6). Pre- and post-policy
# End-of-RIBs remain per negotiated peer.

import functools
import json
import os
import sys

import pytest

CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))
sys.path.append(os.path.join(CWD, "../lib/"))

# pylint: disable=C0413
from lib import topotest
from lib.topogen import Topogen, TopoRouter, get_topogen
from lib.topolog import logger

pytestmark = [pytest.mark.bgpd]

# configured only once BGP is up, so the initial dump sees negotiated peers
BMP_TARGET_CFG = """
configure terminal
router bgp 65501
 bmp targets bmp1
  bmp monitor ipv4 unicast pre-policy
  bmp monitor ipv6 unicast pre-policy
  bmp monitor ipv4 unicast post-policy
  bmp monitor ipv6 unicast post-policy
  bmp monitor ipv4 unicast loc-rib
  bmp monitor ipv6 unicast loc-rib
  bmp connect 192.0.2.10 port 1789 min-retry 100 max-retry 10000
 exit
exit
"""


def build_topo(tgen):
    tgen.add_router("r1")
    tgen.add_router("r2")
    tgen.add_bmp_server("bmp1", ip="192.0.2.10", defaultRoute="via 192.0.2.1")

    switch = tgen.add_switch("s1")
    switch.add_link(tgen.gears["r1"])
    switch.add_link(tgen.gears["bmp1"])

    tgen.add_link(tgen.gears["r1"], tgen.gears["r2"], "r1-eth1", "r2-eth0")


def setup_module(mod):
    tgen = Topogen(build_topo, mod.__name__)
    tgen.start_topology()

    for rname, router in tgen.routers().items():
        logger.info("Loading router %s" % rname)
        router.load_frr_config(
            os.path.join(CWD, "{}/frr.conf".format(rname)),
            [(TopoRouter.RD_ZEBRA, None), (TopoRouter.RD_BGP, "-M bmp")],
        )

    tgen.start_router()

    logger.info("starting BMP servers")
    for bmp_name, server in tgen.get_bmp_servers().items():
        server.start(log_file=os.path.join(tgen.logdir, bmp_name, "bmp.log"))


def teardown_module(_mod):
    get_topogen().stop_topology()


def test_bgp_convergence():
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    expected = {
        "peers": {
            "192.168.0.2": {"state": "Established"},
            "192:168::2": {"state": "Established"},
        }
    }
    test_func = functools.partial(
        topotest.router_json_cmp,
        tgen.gears["r1"],
        "show bgp ipv4 unicast summary json",
        expected,
    )
    _, result = topotest.run_and_expect(test_func, None, count=60, wait=1)
    assert result is None, "r1: both IPv4 unicast sessions did not establish"


def _eor_counts(bmp1, log_file):
    """Count End-of-RIBs in the BMP log per (policy, afi, safi)."""
    counts = {}
    for line in bmp1.run("cat {}".format(log_file)).splitlines():
        try:
            msg = json.loads(line)
        except ValueError:
            continue
        # an EoR is a route monitoring message without any prefix
        if msg.get("bmp_log_type") not in ("update", "withdraw"):
            continue
        if "ip_prefix" in msg:
            continue
        # IPv4 unicast EoR has no MP_UNREACH_NLRI, hence no afi/safi
        key = "{} {}/{}".format(msg["policy"], msg.get("afi", 1), msg.get("safi", 1))
        counts[key] = counts.get(key, 0) + 1
    return counts


def test_bmp_locrib_eor_once_per_afi_safi():
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    tgen.gears["r1"].vtysh_cmd(BMP_TARGET_CFG)

    bmp1 = tgen.gears["bmp1"]
    log_file = os.path.join(tgen.logdir, "bmp1", "bmp.log")

    # IPv6 is dumped after IPv4, so its Loc-RIB EoR closes the initial dump
    expected = {
        "rib-in-pre-policy 1/1": 2,
        "rib-in-post-policy 1/1": 2,
        "loc-rib 1/1": 1,
        "loc-rib 2/1": 1,
    }

    def _check():
        counts = _eor_counts(bmp1, log_file)
        logger.info("BMP End-of-RIB counts: {}".format(counts))
        return counts

    _, counts = topotest.run_and_expect(_check, expected, count=30, wait=1)
    assert (
        counts == expected
    ), "unexpected BMP End-of-RIB counts: got {}, expected {}".format(counts, expected)


if __name__ == "__main__":
    sys.exit(pytest.main(["-s"] + sys.argv[1:]))
