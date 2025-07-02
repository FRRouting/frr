#!/usr/bin/env python
# SPDX-License-Identifier: ISC

# Copyright 2023 6WIND S.A.
# Authored by Farid Mihoub <farid.mihoub@6wind.com>
#

"""
test_bgp_bmp.py: Test BGP BMP functionalities

    +------+            +------+               +------+
    |      |            |      |               |      |
    | BMP1 |------------|  R1  |---------------|  R2  |
    |      |            |      |               |      |
    +------+            +------+               +------+

Setup two routers R1 and R2 with one link configured with IPv4 and
IPv6 addresses.
Configure BGP in R1 and R2 to exchange prefixes from
the latter to the first router.
Setup a link between R1 and the BMP server, activate the BMP feature in R1
and ensure the monitored BGP sessions logs are well present on the BMP server.
"""

from functools import partial
import json
import os
import pytest
import sys

# Save the Current Working Directory to find configuration files.
CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join("../"))
sys.path.append(os.path.join("../lib/"))

# pylint: disable=C0413
# Import topogen and topotest helpers
from lib import topotest
from lib.bgp import verify_bgp_convergence_from_running_config
from lib.bgp import bgp_configure_prefixes
from .bgpbmp import (
    bmp_check_for_prefixes,
    bmp_check_for_peer_message,
    bmp_update_seq,
    _test_prefixes,
    ADJ_IN_PRE_POLICY,
    ADJ_IN_POST_POLICY,
    LOC_RIB,
    ADJ_OUT_PRE_POLICY,
    ADJ_OUT_POST_POLICY,
)
from lib.topogen import Topogen, TopoRouter, get_topogen
from lib.topolog import logger

pytestmark = [pytest.mark.bgpd]

TEST_PREFIXES = ["172.31.0.15/32", "2001::1111/128"]

DEBUG_PCAP = False


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

    if DEBUG_PCAP:
        pcap_file = os.path.join(tgen.logdir, "r1/bmp.pcap")
        tgen.gears["r1"].run(
            "tcpdump -nni r1-eth0 -s 0 -w {} &".format(pcap_file), stdout=None
        )

    tgen.net["r2"].cmd(
        """
ip link add vrf1 type vrf table 10
ip link set vrf1 up
"""
    )

    for _, (rname, router) in enumerate(tgen.routers().items(), 1):
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
    tgen = get_topogen()
    tgen.stop_topology()


def test_bgp_convergence():
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    result = verify_bgp_convergence_from_running_config(tgen, dut="r1")
    assert result is True, "BGP is not converging"


def test_bmp_server_logging():
    """
    Assert the logging of the bmp server.
    """

    def check_for_log_file():
        tgen = get_topogen()
        output = tgen.gears["bmp1"].run(
            "ls {}".format(os.path.join(tgen.logdir, "bmp1"))
        )
        if "bmp.log" not in output:
            return False
        return True

    success, _ = topotest.run_and_expect(check_for_log_file, True, count=30, wait=1)
    assert success, "The BMP server is not logging"


def test_peer_up():
    """
    Checking for BMP peers up messages
    """

    tgen = get_topogen()
    peers = ["192.168.0.2", "192:168::2", "0.0.0.0"]

    logger.info("checking for BMP peers up messages")

    test_func = partial(
        bmp_check_for_peer_message,
        peers,
        "peer up",
        tgen.gears["bmp1"],
        os.path.join(tgen.logdir, "bmp1", "bmp.log"),
    )
    success, _ = topotest.run_and_expect(test_func, True, count=30, wait=1)
    assert success, "Checking the updated prefixes has been failed !."


def test_bmp_bgp_unicast():
    """
    Add/withdraw bgp unicast prefixes and check the bmp logs.
    """

    args = [TEST_PREFIXES, "r2", "r1", "bmp1", CWD, None, None, 65502, "unicast", 1]

    logger.info("*** Unicast prefixes rib-in pre-policy logging ***")
    _test_prefixes(ADJ_IN_PRE_POLICY, *args)
    logger.info("*** Unicast prefixes rib-in post-policy logging ***")
    _test_prefixes(ADJ_IN_POST_POLICY, *args)
    logger.info("*** Unicast prefixes loc-rib logging ***")
    _test_prefixes(LOC_RIB, *args)
    logger.info("*** Unicast prefixes rib-out pre-policy logging ***")
    _test_prefixes(ADJ_OUT_PRE_POLICY, *args)
    logger.info("*** Unicast prefixes rib-out post-policy logging ***")
    _test_prefixes(ADJ_OUT_POST_POLICY, *args)


def test_bmp_bgp_vpn():
    # check for the prefixes in the BMP server logging file

    args = [TEST_PREFIXES, "r2", "r1", "bmp1", CWD, "vrf1", None, 65502, "vpn", 2]

    logger.info("***** VPN prefixes rib-in pre-policy logging *****")
    _test_prefixes(ADJ_IN_PRE_POLICY, *args)
    logger.info("***** VPN prefixes rib-in post-policy logging *****")
    _test_prefixes(ADJ_IN_POST_POLICY, *args)
    logger.info("***** VPN prefixes loc-rib logging *****")
    _test_prefixes(LOC_RIB, *args)




def test_peer_down():
    """
    Checking for BMP peers down messages
    """
    tgen = get_topogen()

    tgen.gears["r2"].vtysh_cmd("clear bgp *")

    peers = ["192.168.0.2", "192:168::2"]

    logger.info("checking for BMP peers down messages")

    test_func = partial(
        bmp_check_for_peer_message,
        peers,
        "peer down",
        tgen.gears["bmp1"],
        os.path.join(tgen.logdir, "bmp1", "bmp.log"),
    )
    success, _ = topotest.run_and_expect(test_func, True, count=30, wait=1)
    assert success, "Checking the updated prefixes has been failed !."


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
