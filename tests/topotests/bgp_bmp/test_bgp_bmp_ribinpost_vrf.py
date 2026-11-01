#!/usr/bin/env python
# SPDX-License-Identifier: ISC

#
# Copyright 2026 by 6WIND S.A.
#

"""
test_bgp_bmp_ribinpost_vrf.py: Adj-RIB-In post-policy of a BGP instance
that is not imported.

    +---------+     +----------+              +----------+
    | bmp1rv  |-----|   r1rv   |--------------|   r2rv   |
    +---------+     +----------+              +----------+
                         |
                         | vrf1
                         |                    +----------+
                         +--------------------|   r3rv   |
                                              +----------+

The default BGP instance of r1rv has a bmp target monitoring the ipv4
unicast Adj-RIB-In post-policy, without 'bmp import-vrf-view'. r3rv is
a peer of the vrf1 BGP instance of r1rv: bmp1rv must receive no message
for the prefix announced by r3rv.
"""

import os
import sys
import json
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

DEFAULT_PEER = "192.168.0.2"
VRF_PEER = "192.168.1.3"
DEFAULT_PREFIX = "172.31.0.1/32"
VRF_PREFIX = "172.31.1.1/32"


def build_topo(tgen):
    tgen.add_router("r1rv")
    tgen.add_router("r2rv")
    tgen.add_router("r3rv")

    tgen.add_bmp_server("bmp1rv", ip="192.0.2.10", defaultRoute="via 192.0.2.1")

    switch = tgen.add_switch("s1")
    switch.add_link(tgen.gears["r1rv"])
    switch.add_link(tgen.gears["bmp1rv"])

    tgen.add_link(tgen.gears["r1rv"], tgen.gears["r2rv"], "r1rv-eth1", "r2rv-eth0")
    tgen.add_link(tgen.gears["r1rv"], tgen.gears["r3rv"], "r1rv-eth2", "r3rv-eth0")


def setup_module(mod):
    tgen = Topogen(build_topo, mod.__name__)
    tgen.start_topology()

    tgen.net["r1rv"].cmd(
        """
ip link add vrf1 type vrf table 10
ip link set vrf1 up
ip link set r1rv-eth2 master vrf1
"""
    )

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


def bmp_messages():
    tgen = get_topogen()
    bmp_log_file = os.path.join(tgen.logdir, "bmp1rv", "bmp.log")
    return get_bmp_messages(tgen.gears["bmp1rv"], bmp_log_file)


def announce(router, asn, prefix):
    tgen = get_topogen()
    tgen.gears[router].vtysh_cmd(
        """
        configure terminal
         router bgp {}
          address-family ipv4 unicast
           network {}
        """.format(
            asn, prefix
        )
    )


def test_bmp_peer_up():
    """
    Wait for the peer up of r2rv on bmp1rv.
    """
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    @retry(retry_timeout=60)
    def check_peer_up():
        for message in bmp_messages():
            if (
                message.get("bmp_log_type") == "peer up"
                and message.get("peer_ip") == DEFAULT_PEER
            ):
                return True
        return "no peer up received for {}".format(DEFAULT_PEER)

    result = check_peer_up()
    assert result is True, result


def test_bmp_ribinpost_vrf_not_imported():
    """
    Announce a prefix from r3rv in vrf1, then a prefix from r2rv in the
    default instance. Once the post-policy update of the default instance
    prefix is received, check that no message was received for the vrf1
    prefix or peer.
    """
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    @retry(retry_timeout=60)
    def check_vrf_bestpath():
        output = json.loads(
            tgen.gears["r1rv"].vtysh_cmd(
                "show bgp vrf vrf1 ipv4 unicast {} json".format(VRF_PREFIX)
            )
        )
        for path in output.get("paths", []):
            if path.get("bestpath", {}).get("overall"):
                return True
        return "{} not selected in vrf1: {}".format(VRF_PREFIX, output)

    @retry(retry_timeout=30)
    def check_default_update():
        for message in bmp_messages():
            if (
                message.get("bmp_log_type") == "update"
                and message.get("policy") == "rib-in-post-policy"
                and message.get("ip_prefix") == DEFAULT_PREFIX
            ):
                return True
        return "no post-policy update received for {}".format(DEFAULT_PREFIX)

    announce("r3rv", 65503, VRF_PREFIX)
    result = check_vrf_bestpath()
    assert result is True, result

    announce("r2rv", 65502, DEFAULT_PREFIX)
    result = check_default_update()
    assert result is True, result

    leaked = [
        message
        for message in bmp_messages()
        if message.get("ip_prefix") == VRF_PREFIX or message.get("peer_ip") == VRF_PEER
    ]
    assert not leaked, "bmp1rv received messages of the vrf1 instance: {}".format(
        leaked
    )


def test_memory_leak():
    "Run the memory leak test and report results."
    tgen = get_topogen()
    if not tgen.is_memleak_enabled():
        pytest.skip("Memory leak test/report is disabled")

    tgen.report_memory_leaks()


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
