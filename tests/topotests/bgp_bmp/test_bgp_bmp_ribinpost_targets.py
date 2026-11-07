#!/usr/bin/env python
# SPDX-License-Identifier: ISC

#
# Copyright 2026 by 6WIND S.A.
#

"""
test_bgp_bmp_ribinpost_targets.py: Adj-RIB-In post-policy with two targets.

    +---------+
    | bmp1rp  |---+
    +---------+   |     +----------+              +----------+
                  +-----|   r1rp   |--------------|   r2rp   |
    +---------+   |     +----------+              +----------+
    | bmp2rp  |---+
    +---------+

r1rp has two bmp targets, bmp1 and bmp2, both monitoring the ipv4 unicast
Adj-RIB-In post-policy, and connected to bmp1rp and bmp2rp. A prefix is
announced then withdrawn by r2rp once both BMP sessions are up: both
collectors must receive the post-policy update and withdraw.
"""

import os
import sys
import pytest

# Save the Current Working Directory to find configuration files.
CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join("../"))
sys.path.append(os.path.join("../lib/"))

# pylint: disable=C0413
# Import topogen and topotest helpers
from .bgpbmp import get_bmp_messages
from lib.common_config import retry
from lib.topogen import Topogen, get_topogen

pytestmark = [pytest.mark.bgpd]

PREFIX = "172.31.0.1/32"
BMP_COLLECTORS = ["bmp1rp", "bmp2rp"]


def build_topo(tgen):
    tgen.add_router("r1rp")
    tgen.add_router("r2rp")

    tgen.add_bmp_server("bmp1rp", ip="192.0.2.10", defaultRoute="via 192.0.2.1")
    tgen.add_bmp_server(
        "bmp2rp", ip="192.0.2.20", defaultRoute="via 192.0.2.1", port=1790
    )

    switch = tgen.add_switch("s1")
    switch.add_link(tgen.gears["r1rp"])
    switch.add_link(tgen.gears["bmp1rp"])
    switch.add_link(tgen.gears["bmp2rp"])

    tgen.add_link(tgen.gears["r1rp"], tgen.gears["r2rp"], "r1rp-eth1", "r2rp-eth0")


def setup_module(mod):
    tgen = Topogen(build_topo, mod.__name__)
    tgen.start_topology()

    for router in tgen.routers().values():
        router.load_frr_config(
            daemons=["zebra", ("bgpd", "-M bmp")],
        )

    tgen.start_router()

    for bmp_name, server in tgen.get_bmp_servers().items():
        server.start(log_file=os.path.join(tgen.logdir, bmp_name, "bmp.log"))


def teardown_module(_mod):
    tgen = get_topogen()
    tgen.stop_topology()


def bmp_messages(bmp_name):
    tgen = get_topogen()
    bmp_log_file = os.path.join(tgen.logdir, bmp_name, "bmp.log")
    return get_bmp_messages(tgen.gears[bmp_name], bmp_log_file)


def test_bmp_peer_up():
    """
    Wait for the peer up of r2rp on both collectors.
    """
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    @retry(retry_timeout=60)
    def check_peer_up(bmp_name):
        for message in bmp_messages(bmp_name):
            if (
                message.get("bmp_log_type") == "peer up"
                and message.get("peer_ip") == "192.168.0.2"
            ):
                return True
        return "{}: no peer up received for 192.168.0.2".format(bmp_name)

    for bmp_name in BMP_COLLECTORS:
        result = check_peer_up(bmp_name)
        assert result is True, result


def test_bmp_ribinpost_update_withdraw():
    """
    Announce then withdraw a prefix from r2rp, and check that both
    collectors receive the post-policy update and withdraw.
    """
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    @retry(retry_timeout=30)
    def check_prefix(bmp_name, bmp_log_type):
        for message in bmp_messages(bmp_name):
            if (
                message.get("bmp_log_type") == bmp_log_type
                and message.get("policy") == "rib-in-post-policy"
                and message.get("ip_prefix") == PREFIX
            ):
                return True
        return "{}: no post-policy {} received for {}".format(
            bmp_name, bmp_log_type, PREFIX
        )

    tgen.gears["r2rp"].vtysh_cmd(
        """
        configure terminal
         router bgp 65502
          address-family ipv4 unicast
           network {}
        """.format(
            PREFIX
        )
    )
    for bmp_name in BMP_COLLECTORS:
        result = check_prefix(bmp_name, "update")
        assert result is True, result

    tgen.gears["r2rp"].vtysh_cmd(
        """
        configure terminal
         router bgp 65502
          address-family ipv4 unicast
           no network {}
        """.format(
            PREFIX
        )
    )
    for bmp_name in BMP_COLLECTORS:
        result = check_prefix(bmp_name, "withdraw")
        assert result is True, result


def test_memory_leak():
    "Run the memory leak test and report results."
    tgen = get_topogen()
    if not tgen.is_memleak_enabled():
        pytest.skip("Memory leak test/report is disabled")

    tgen.report_memory_leaks()


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
