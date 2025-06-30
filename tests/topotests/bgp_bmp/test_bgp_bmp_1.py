#!/usr/bin/env python
# SPDX-License-Identifier: ISC

# Copyright 2023 6WIND S.A.
# Authored by Farid Mihoub <farid.mihoub@6wind.com>
#

"""
test_bgp_bmp.py: Test BGP BMP functionalities

    +------+            +------+               +------+
    |      |            |      |               |      |
    | BMP1 |------------|  R1  |-------+-------|  R2  |
    |      |            |      |       |       |      |
    +------+            +------+       |       +------+
                            |          |
                            |          |       +------+
                            |          |       |      |
                        +------+       +-------|  R3  |
                        |      |               | ecmp |
                        |  R4  |               +------+
                        |      |
                        +------+

Setup three routers R1 and R3 with one link configured with IPv4 and
IPv6 addresses.
Configure BGP to exchange prefixes from R2 and R3 to R1.
R3 is only used in the multi-path test, it announces the same as R2 to R1 to
have the R2 prefixes be ECMP paths in R1.
R4 is in addpath tx test where R2 and R3ecmp announce the same prefixes to R1.
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
    BMPSequenceContext,
    bmp_check_for_addpath,
    bmp_check_for_prefixes,
    bmp_check_for_peer_message,
    bmp_update_seq,
    ADJ_IN_PRE_POLICY,
    ADJ_IN_POST_POLICY,
    LOC_RIB,
    ADJ_OUT_PRE_POLICY,
    ADJ_OUT_POST_POLICY,
    _test_prefixes,
)
from lib.topogen import Topogen, TopoRouter, get_topogen
from lib.topolog import logger

pytestmark = [pytest.mark.bgpd]

TEST_PREFIXES = ["172.31.0.15/32", "2001::1111/128"]

DEBUG_PCAP = False

# Create a sequence context for this test run
bmp_seq_context = BMPSequenceContext()


def build_topo(tgen):
    tgen.add_router("r1")
    tgen.add_router("r2")
    tgen.add_router("r3ecmp")
    tgen.add_router("r4")
    tgen.add_bmp_server("bmp1", ip="192.0.2.10", defaultRoute="via 192.0.2.1")

    switch = tgen.add_switch("s1")
    switch.add_link(tgen.gears["r1"])
    switch.add_link(tgen.gears["bmp1"])

    switch = tgen.add_switch("s2")
    switch.add_link(tgen.gears["r1"], nodeif="r1-eth1")
    switch.add_link(tgen.gears["r2"], nodeif="r2-eth0")
    switch.add_link(tgen.gears["r3ecmp"], nodeif="r3ecmp-eth0")

    switch = tgen.add_switch("s3")
    switch.add_link(tgen.gears["r1"], nodeif="r1-eth2")
    switch.add_link(tgen.gears["r4"], nodeif="r4-eth0")


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
        bmp_seq_context,
    )
    success, _ = topotest.run_and_expect(test_func, True, count=30, wait=1)
    assert success, "Checking the updated prefixes has been failed !."


def test_bmp_bgp_unicast():
    """
    Add/withdraw bgp unicast prefixes and check the bmp logs.
    """

    args = [
        TEST_PREFIXES,
        "r2",
        "r1",
        "bmp1",
        CWD,
        bmp_seq_context,
        None,
        None,
        65502,
        "unicast",
        1,
    ]

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

    args = [
        TEST_PREFIXES,
        "r2",
        "r1",
        "bmp1",
        CWD,
        bmp_seq_context,
        "vrf1",
        None,
        65502,
        "vpn",
        2,
    ]

    logger.info("***** VPN prefixes rib-in pre-policy logging *****")
    _test_prefixes(ADJ_IN_PRE_POLICY, *args)
    logger.info("***** VPN prefixes rib-in post-policy logging *****")
    _test_prefixes(ADJ_IN_POST_POLICY, *args)
    logger.info("***** VPN prefixes loc-rib logging *****")
    _test_prefixes(LOC_RIB, *args)


def multipath_unicast_prefixes(policy, step, vrf=None):
    """
    Setup the BMP  monitor policy, Add and withdraw ipv4/v6 prefixes.
    Check if the previous actions are logged in the BMP server with the right
    message type and the right policy.
    Make R3 announce the prefixes, then R2 so its paths are ECMP
    Finally, withdraw on R3 to clean up
    """
    tgen = get_topogen()

    MULTIPATH_TEST_PREFIXES = ["10.1.1.0/31", "172.16.3.0/31"]

    bgp_configure_prefixes(
        tgen.gears["r3ecmp"],
        65502,
        "unicast",
        MULTIPATH_TEST_PREFIXES,
        vrf,
        update=True,
    )

    _test_prefixes(
        policy,
        MULTIPATH_TEST_PREFIXES,
        "r2",
        "r1",
        "bmp1",
        CWD,
        bmp_seq_context,
        vrf,
        None,
        65502,
        "unicast",
        3,
    )

    bgp_configure_prefixes(
        tgen.gears["r3ecmp"],
        65502,
        "unicast",
        MULTIPATH_TEST_PREFIXES,
        vrf,
        update=False,
    )


def test_bmp_bgp_multipath():
    """
    Test the ECMP feature of BMP i.e. when the loc-rib installs multiple paths
    """

    logger.info("*** Multipath unicast prefixes loc-rib logging ***")
    multipath_unicast_prefixes(LOC_RIB, step=3)


def test_addpath_id_unicast():
    """
    Test the unicast addpath bmp log.
    Configure the same ipv4/6 prefix on R2 and R3ecmp that is redistributed to R1
    , and redistribute it to R4. Check [R2, R3ecm] -> R1 -> R4 addpath bmp log.
    """

    logger.info("*** Activating peering with R4 with addpath tx enabled")
    tgen = get_topogen()
    tgen.gears["r1"].vtysh_cmd(
        """
        configure terminal
        router bgp 65501
         neighbor 192.169.0.4 remote-as 65501
         neighbor 192:169::4 remote-as 65501
        address-family ipv4 unicast
         neighbor 192.169.0.4 addpath-tx-all-paths
         no neighbor 192:169::4 activate
        exit-address-family
        address-family ipv6 unicast
         neighbor 192:169::4 activate
         neighbor 192:169::4 addpath-tx-all-paths
        """
    )
    tgen.gears["r2"].vtysh_cmd(
        """
        configure terminal
        router bgp 65502
        address-family ipv4 unicast
         neighbor 192.168.0.1 addpath-tx-all-paths
        exit-address-family
        address-family ipv6 unicast
         neighbor 192:168::1 addpath-tx-all-paths
        """
    )
    tgen.gears["r3ecmp"].vtysh_cmd(
        """
        configure terminal
        router bgp 65502
        address-family ipv4 unicast
         neighbor 192.168.0.1 addpath-tx-all-paths
        exit-address-family
        address-family ipv6 unicast
         neighbor 192:168::1 addpath-tx-all-paths
        """
    )

    bgp_configure_prefixes(
        tgen.gears["r3ecmp"],
        65502,
        "unicast",
        ["172.17.7.7/32", "fd00:7:7:7::7/128"],
        None,
        update=True,
    )

    bgp_configure_prefixes(
        tgen.gears["r2"],
        65502,
        "unicast",
        ["172.17.7.7/32", "fd00:7:7:7::7/128"],
        None,
        update=True,
    )

    logger.info("*** [R2, R3ecmp] -> R1 -> R4, check rib-in-pre-policy logging ***")
    test_func = partial(
        bmp_check_for_addpath,
        ["172.17.7.7/32", "fd00:7:7:7::7/128"],
        "rib-in-pre-policy",
        tgen.gears["bmp1"],
        os.path.join(tgen.logdir, "bmp1/bmp.log"),
        [("192.168.0.2", "192.168.0.3"), ("192:168::2", "192:168::3")],
        None,
        bmp_seq_context,
        id_per_prefix=False,
    )
    success, ret = topotest.run_and_expect_type(test_func, dict, count=30, wait=1)
    assert success, "bmp addpath rib-in-pre-policy failed for : %s" % ret

    logger.info("*** [R2, R3ecmp] -> R1 -> R4, check rib-in-post-policy logging ***")
    test_func = partial(
        bmp_check_for_addpath,
        ["172.17.7.7/32", "fd00:7:7:7::7/128"],
        "rib-in-post-policy",
        tgen.gears["bmp1"],
        os.path.join(tgen.logdir, "bmp1/bmp.log"),
        [("192.168.0.2", "192.168.0.3"), ("192:168::2", "192:168::3")],
        None,
        bmp_seq_context,
        id_per_prefix=False,
    )
    success, ret = topotest.run_and_expect_type(test_func, dict, count=30, wait=1)
    assert success, "bmp addpath rib-in-post-policy failed for : %s" % ret

    logger.info("*** [R2, R3ecmp] -> R1 -> R4, check loc-rib logging ***")
    test_func = partial(
        bmp_check_for_addpath,
        ["172.17.7.7/32", "fd00:7:7:7::7/128"],
        "loc-rib",
        tgen.gears["bmp1"],
        os.path.join(tgen.logdir, "bmp1/bmp.log"),
        [("192.168.0.2", "192.168.0.3"), ("192:168::2", "192:168::3")],
        None,
        bmp_seq_context,
        id_per_prefix=False,
    )
    success, ret = topotest.run_and_expect_type(test_func, dict, count=30, wait=1)
    assert success, "bmp addpath loc-rib-policy failed for : %s" % ret

    logger.info("*** [R2, R3ecmp] -> R1 -> R4, check rib-out-pre-policy logging ***")
    test_func = partial(
        bmp_check_for_addpath,
        ["172.17.7.7/32", "fd00:7:7:7::7/128"],
        "rib-out-pre-policy",
        tgen.gears["bmp1"],
        os.path.join(tgen.logdir, "bmp1/bmp.log"),
        [("192.168.0.2", "192.168.0.3"), ("192:168::2", "192:168::3")],
        "192.169.0.4",
        bmp_seq_context,
    )
    success, ret = topotest.run_and_expect_type(test_func, dict, count=30, wait=1)
    assert success, "bmp addpath rib-out-pre-policy failed for : %s" % ret

    logger.info("*** [R2, R3ecmp] -> R1 -> R4, check rib-out-post-policy logging ***")
    test_func = partial(
        bmp_check_for_addpath,
        ["172.17.7.7/32", "fd00:7:7:7::7/128"],
        "rib-out-post-policy",
        tgen.gears["bmp1"],
        os.path.join(tgen.logdir, "bmp1/bmp.log"),
        [("192.168.0.2", "192.168.0.3"), ("192:168::2", "192:168::3")],
        "192.169.0.4",
        bmp_seq_context,
    )
    success, ret = topotest.run_and_expect_type(test_func, dict, count=30, wait=1)
    assert success, "bmp addpath rib-out-post-policy failed for %s" % ret


def test_addpath_id_vpn():
    """
    Test the vpn addpath bmp log.
    Activate vpn addpath on [R3ecmp, R2] -> R1 and R1 -> R4.
    Check [R2, R3ecm] -> R1 -> R4 addpath bmp log.
    """

    logger.info("*** Activating [R2, R3ecmp] -> R1 -> R4 vpn addpath peering ***")
    tgen = get_topogen()
    tgen.gears["r1"].vtysh_cmd(
        """
        configure terminal
        router bgp 65501
        bmp target bmp1
         bmp monitor ipv4 vpn rib-out pre-policy
         bmp monitor ipv4 vpn rib-out post-policy
         bmp monitor ipv6 vpn rib-out pre-policy
         bmp monitor ipv6 vpn rib-out post-policy
        exit
        address-family ipv4 vpn
         neighbor 192.168.0.3 activate
         neighbor 192.168.0.3 soft-reconfiguration inbound
         neighbor 192.169.0.4 activate
         neighbor 192.169.0.4 soft-reconfiguration inbound
         neighbor 192.169.0.4 addpath-tx-all-paths
        exit-address-family
        address-family ipv6 vpn
         neighbor 192:168::3 activate
         neighbor 192:168::3 soft-reconfiguration inbound
         neighbor 192:169::4 activate
         neighbor 192:169::4 addpath-tx-all-paths
        exit-address-family
        """
    )
    tgen.gears["r4"].vtysh_cmd(
        """
        configure terminal
        router bgp 65501
        address-family ipv4 vpn
         neighbor 192.169.0.1 activate
        exit-address-family
        address-family ipv6 vpn
         neighbor 192:169::1 activate
        exit-address-family
        """
    )
    tgen.gears["r2"].vtysh_cmd(
        """
        configure terminal
        router bgp 65502
        address-family ipv4 vpn
         neighbor 192.168.0.1 addpath-tx-all-paths
        exit-address-family
        address-family ipv6 vpn
         neighbor 192:168::1 addpath-tx-all-paths
        exit-address-family
        address-family ipv4 unicast
         export vpn
         rd vpn export 65502:2
         rt vpn expor 65502:22
        exit-address-family
        address-family ipv6 unicast
         export vpn
         rd vpn export 65502:2
         rt vpn expor 65502:22
        exit-address-family
        """
    )
    tgen.gears["r3ecmp"].vtysh_cmd(
        """
        configure terminal
        router bgp 65502
        address-family ipv4 vpn
         neighbor 192.168.0.1 activate
         neighbor 192.168.0.1 addpath-tx-all-paths
        exit-address-family
        address-family ipv6 vpn
         neighbor 192:168::1 activate
         neighbor 192:168::1 addpath-tx-all-paths
        exit-address-family
        address-family ipv4 unicast
         export vpn
         rd vpn export 65502:3
         rt vpn expor 65502:33
        exit-address-family
        address-family ipv6 unicast
         export vpn
         rd vpn export 65502:3
         rt vpn expor 65502:33
        exit-address-family
        """
    )

    logger.info("*** [R2, R3ecmp] -> R1 -> R4, check rib-in-pre-policy logging ***")
    test_func = partial(
        bmp_check_for_addpath,
        ["172.17.7.7/32", "fd00:7:7:7::7/128"],
        "rib-in-pre-policy",
        tgen.gears["bmp1"],
        os.path.join(tgen.logdir, "bmp1/bmp.log"),
        [("192.168.0.2", "192.168.0.3"), ("192:168::2", "192:168::3")],
        None,
        bmp_seq_context,
        id_per_prefix=False,
        safi=128,
    )
    success, ret = topotest.run_and_expect_type(test_func, dict, count=30, wait=1)
    assert success, "bmp addpath rib-in-pre-policy failed for : %s" % ret

    logger.info("*** [R2, R3ecmp] -> R1 -> R4, check rib-in-post-policy logging ***")
    test_func = partial(
        bmp_check_for_addpath,
        ["172.17.7.7/32", "fd00:7:7:7::7/128"],
        "rib-in-post-policy",
        tgen.gears["bmp1"],
        os.path.join(tgen.logdir, "bmp1/bmp.log"),
        [("192.168.0.2", "192.168.0.3"), ("192:168::2", "192:168::3")],
        None,
        bmp_seq_context,
        id_per_prefix=False,
        safi=128,
    )
    success, ret = topotest.run_and_expect_type(test_func, dict, count=30, wait=1)
    assert success, "bmp addpath rib-in-post-policy failed for : %s" % ret

    logger.info("*** [R2, R3ecmp] -> R1 -> R4, check loc-rib logging ***")
    test_func = partial(
        bmp_check_for_addpath,
        ["172.17.7.7/32", "fd00:7:7:7::7/128"],
        "loc-rib",
        tgen.gears["bmp1"],
        os.path.join(tgen.logdir, "bmp1/bmp.log"),
        [("192.168.0.2", "192.168.0.3"), ("192:168::2", "192:168::3")],
        None,
        bmp_seq_context,
        id_per_prefix=False,
        safi=128,
    )
    success, ret = topotest.run_and_expect_type(test_func, dict, count=30, wait=1)
    assert success, "bmp addpath loc-rib-policy failed for : %s" % ret

    logger.info("*** [R2, R3ecmp] -> R1 -> R4, check rib-out-pre-policy logging ***")
    test_func = partial(
        bmp_check_for_addpath,
        ["172.17.7.7/32", "fd00:7:7:7::7/128"],
        "rib-out-pre-policy",
        tgen.gears["bmp1"],
        os.path.join(tgen.logdir, "bmp1/bmp.log"),
        [("192.168.0.2", "192.168.0.3"), ("192:168::2", "192:168::3")],
        "192.169.0.4",
        bmp_seq_context,
        safi=128,
    )
    success, ret = topotest.run_and_expect_type(test_func, dict, count=30, wait=1)
    assert success, "bmp vpn addpath rib-out-pre-policy failed for %s" % ret

    logger.info("*** [R2, R3ecmp] -> R1 -> R4, check rib-out-post-policy logging ***")
    test_func = partial(
        bmp_check_for_addpath,
        ["172.17.7.7/32", "fd00:7:7:7::7/128"],
        "rib-out-post-policy",
        tgen.gears["bmp1"],
        os.path.join(tgen.logdir, "bmp1/bmp.log"),
        [("192.168.0.2", "192.168.0.3"), ("192:168::2", "192:168::3")],
        "192.169.0.4",
        bmp_seq_context,
        safi=128,
    )
    success, ret = topotest.run_and_expect_type(test_func, dict, count=30, wait=1)
    assert success, "bmp vpn addpath rib-out-post-policy failed for %s" % ret


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
        bmp_seq_context,
    )
    success, _ = topotest.run_and_expect(test_func, True, count=30, wait=1)
    assert success, "Checking the updated prefixes has been failed !."


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
