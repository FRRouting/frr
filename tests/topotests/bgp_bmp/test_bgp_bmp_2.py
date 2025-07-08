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
import platform
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
    bmp_reset_seq,
    BMPSequenceContext,
)


from lib.topogen import Topogen, TopoRouter, get_topogen
from lib.topolog import logger

pytestmark = [pytest.mark.bgpd]

PRE_POLICY = "pre-policy"
POST_POLICY = "post-policy"
LOC_RIB = "loc-rib"

UPDATE_EXPECTED_JSON = False
DEBUG_PCAP = False

# Create a global BMP sequence context for this test module
bmp_seq_context = BMPSequenceContext()


def build_topo(tgen):
    tgen.add_router("r1vrf")
    tgen.add_router("r2vrf")
    tgen.add_bmp_server("bmp1vrf", ip="192.0.2.10", defaultRoute="via 192.0.2.1")

    switch = tgen.add_switch("s1")
    switch.add_link(tgen.gears["r1vrf"])
    switch.add_link(tgen.gears["bmp1vrf"])

    tgen.add_link(tgen.gears["r1vrf"], tgen.gears["r2vrf"], "r1vrf-eth1", "r2vrf-eth0")


def setup_module(mod):
    tgen = Topogen(build_topo, mod.__name__)
    tgen.start_topology()

    tgen.net["r1vrf"].cmd(
        """
ip link add vrf1 type vrf table 10
ip link set vrf1 up
ip link set r1vrf-eth1 master vrf1
"""
    )
    bmp_reset_seq(bmp_seq_context)
    if DEBUG_PCAP:
        pcap_file = os.path.join(tgen.logdir, "r1vrf/bmp.pcap")
        tgen.gears["r1vrf"].run(
            "tcpdump -nni r1vrf-eth0 -s 0 -w {} &".format(pcap_file), stdout=None
        )

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
    tgen = get_topogen()
    tgen.stop_topology()


def test_bgp_convergence():
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    result = verify_bgp_convergence_from_running_config(tgen, dut="r1vrf")
    assert result is True, "BGP is not converging"


def _test_prefixes(policy, step=1):
    """
    Setup the BMP  monitor policy, Add and withdraw ipv4/v6 prefixes.
    Check if the previous actions are logged in the BMP server with the right
    message type and the right policy.
    """
    tgen = get_topogen()

    prefixes = ["172.31.0.15/32", "2111::1111/128"]

    for type in ("update", "withdraw"):
        bmp_update_seq(
            tgen.gears["bmp1vrf"],
            os.path.join(tgen.logdir, "bmp1vrf", "bmp.log"),
            bmp_seq_context,
        )

        # add prefixes
        bgp_configure_prefixes(
            tgen.gears["r2vrf"], 65502, "unicast", prefixes, update=(type == "update")
        )

        logger.info(f"checking for prefixes {type}")

        for ipver in [4, 6]:
            if UPDATE_EXPECTED_JSON:
                continue
            ref_file = "{}/r1vrf/show-bgp-ipv{}-{}-step{}.json".format(
                CWD, ipver, type, step
            )
            expected = json.loads(open(ref_file).read())

            test_func = partial(
                topotest.router_json_cmp,
                tgen.gears["r1vrf"],
                f"show bgp vrf vrf1 ipv{ipver} json",
                expected,
            )
            _, res = topotest.run_and_expect(test_func, None, count=30, wait=1)
            assertmsg = f"r1vrf: BGP IPv{ipver} convergence failed"
            assert res is None, assertmsg

        # check
        test_func = partial(
            bmp_check_for_prefixes,
            prefixes,
            type,
            policy,
            step,
            tgen.gears["bmp1vrf"],
            os.path.join(tgen.logdir, "bmp1vrf"),
            tgen.gears["r1vrf"],
            f"{CWD}/bmp1vrf",
            UPDATE_EXPECTED_JSON,
            LOC_RIB,
            bmp_seq_context,
        )
        success, res = topotest.run_and_expect(test_func, None, count=30, wait=1)
        assert success, "Checking the updated prefixes has failed ! %s" % res


def test_bmp_server_logging():
    """
    Assert the logging of the bmp server.
    """

    def check_for_log_file():
        tgen = get_topogen()
        output = tgen.gears["bmp1vrf"].run(
            "ls {}".format(os.path.join(tgen.logdir, "bmp1vrf"))
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
        tgen.gears["bmp1vrf"],
        os.path.join(tgen.logdir, "bmp1vrf", "bmp.log"),
        bmp_seq_context,
        is_rd_instance=True,
    )
    success, _ = topotest.run_and_expect(test_func, True, count=30, wait=1)
    assert success, "Checking the updated prefixes has been failed !."


def test_bmp_bgp_unicast():
    """
    Add/withdraw bgp unicast prefixes and check the bmp logs.
    """
    logger.info("*** Unicast prefixes pre-policy logging ***")
    _test_prefixes(PRE_POLICY)
    logger.info("*** Unicast prefixes post-policy logging ***")
    _test_prefixes(POST_POLICY)
    logger.info("*** Unicast prefixes loc-rib logging ***")
    _test_prefixes(LOC_RIB)


def test_peer_down():
    """
    Checking for BMP peers down messages
    """
    tgen = get_topogen()

    tgen.gears["r2vrf"].vtysh_cmd("clear bgp *")

    peers = ["192.168.0.2", "192:168::2"]

    logger.info("checking for BMP peers down messages")

    test_func = partial(
        bmp_check_for_peer_message,
        peers,
        "peer down",
        tgen.gears["bmp1vrf"],
        os.path.join(tgen.logdir, "bmp1vrf", "bmp.log"),
        bmp_seq_context,
        is_rd_instance=True,
    )
    success, _ = topotest.run_and_expect(test_func, True, count=30, wait=1)
    assert success, "Checking the updated prefixes has been failed !."


def test_bgp_instance_flapping():
    """
    Checking for BGP loc-rib up messages
    """
    tgen = get_topogen()

    # create flapping at BMP
    tgen.net["r1vrf"].cmd("ip link set dev vrf1 down")

    peers = ["0.0.0.0"]
    logger.info("checking for BMP peer down LOC-RIB message.")
    test_func = partial(
        bmp_check_for_peer_message,
        peers,
        "peer down",
        tgen.gears["bmp1vrf"],
        os.path.join(tgen.logdir, "bmp1vrf", "bmp.log"),
        bmp_seq_context,
        is_rd_instance=True,
    )
    success, _ = topotest.run_and_expect(test_func, True, count=30, wait=1)
    assert success, "Checking the BMP peer down LOC-RIB message failed !."

    tgen.net["r1vrf"].cmd("ip link set dev vrf1 up")

    logger.info("checking for BMP peer up LOC-RIB message.")
    test_func = partial(
        bmp_check_for_peer_message,
        peers,
        "peer up",
        tgen.gears["bmp1vrf"],
        os.path.join(tgen.logdir, "bmp1vrf", "bmp.log"),
        bmp_seq_context,
        is_rd_instance=True,
    )
    success, _ = topotest.run_and_expect(test_func, True, count=30, wait=1)
    assert success, "Checking the BMP peer up LOC-RIB message failed !."


def test_bgp_routerid_changed():
    """
    Checking for BGP loc-rib up messages with new router-id
    """
    tgen = get_topogen()

    tgen.gears["r1vrf"].vtysh_cmd(
        """
        configure terminal
        router bgp 65501 vrf vrf1
        bgp router-id 192.168.1.77
        """
    )

    peers = ["0.0.0.0"]

    logger.info(
        "checking for BMP peer down LOC-RIB message with router-id set to 192.168.0.1."
    )
    test_func = partial(
        bmp_check_for_peer_message,
        peers,
        "peer down",
        tgen.gears["bmp1vrf"],
        os.path.join(tgen.logdir, "bmp1vrf", "bmp.log"),
        bmp_seq_context,
        is_rd_instance=True,
    )
    success, _ = topotest.run_and_expect(test_func, True, count=30, wait=1)
    assert (
        success
    ), "Checking the BMP peer down LOC-RIB message with router-id set to 192.168.0.1 failed !."

    logger.info(
        "checking for BMP peer up LOC-RIB message with router-id set to 192.168.1.77."
    )
    test_func = partial(
        bmp_check_for_peer_message,
        peers,
        "peer up",
        tgen.gears["bmp1vrf"],
        os.path.join(tgen.logdir, "bmp1vrf", "bmp.log"),
        bmp_seq_context,
        is_rd_instance=True,
        peer_bgp_id="192.168.1.77",
    )
    success, _ = topotest.run_and_expect(test_func, True, count=30, wait=1)
    assert (
        success
    ), "Checking the BMP peer up LOC-RIB message with router-id set to 192.168.1.77 failed !."


def test_reconfigure_route_distinguisher_vrf1():
    """
    Checking for BMP peers down messages
    """
    tgen = get_topogen()

    bmp_update_seq(
        tgen.gears["bmp1vrf"],
        os.path.join(tgen.logdir, "bmp1vrf", "bmp.log"),
        bmp_seq_context,
    )
    peers = ["0.0.0.0"]

    tgen.gears["r1vrf"].vtysh_cmd(
        """
        configure terminal
        router bgp 65501 vrf vrf1
        address-family ipv4 unicast
        rd vpn export 666:22
        exit-address-family
        address-family ipv6 unicast
        rd vpn export 666:22
        """
    )
    logger.info(
        "checking for BMP peer down LOC-RIB message with route-distinguisher set to 444:1"
    )
    test_func = partial(
        bmp_check_for_peer_message,
        peers,
        "peer down",
        tgen.gears["bmp1vrf"],
        os.path.join(tgen.logdir, "bmp1vrf", "bmp.log"),
        bmp_seq_context,
        is_rd_instance=True,
        peer_distinguisher="444:1",
    )
    success, _ = topotest.run_and_expect(test_func, True, count=30, wait=1)
    assert (
        success
    ), "Checking the BMP peer down LOC-RIB message with route-distinguisher set to 444:1 failed !."

    logger.info(
        "checking for BMP peer up LOC-RIB messages with route-distinguisher set to 666:22"
    )
    test_func = partial(
        bmp_check_for_peer_message,
        peers,
        "peer up",
        tgen.gears["bmp1vrf"],
        os.path.join(tgen.logdir, "bmp1vrf", "bmp.log"),
        bmp_seq_context,
        is_rd_instance=True,
        peer_bgp_id="192.168.1.77",
        peer_distinguisher="666:22",
    )
    success, _ = topotest.run_and_expect(test_func, True, count=30, wait=1)
    assert (
        success
    ), "Checking the BMP peer up LOC-RIB message with route-distinguisher set to 666:22 failed !."

    logger.info(
        "checking for BMP peer up messages with route-distinguisher set to 666:22"
    )
    peers = ["192.168.0.2", "192:168::2"]
    test_func = partial(
        bmp_check_for_peer_message,
        peers,
        "peer up",
        tgen.gears["bmp1vrf"],
        os.path.join(tgen.logdir, "bmp1vrf", "bmp.log"),
        bmp_seq_context,
        is_rd_instance=True,
        peer_distinguisher="666:22",
    )
    success, _ = topotest.run_and_expect(test_func, True, count=30, wait=1)
    assert (
        success
    ), "Checking the BMP peer up messages with route-distinguisher set to 666:22 failed !."


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
