#!/usr/bin/env python
# SPDX-License-Identifier: ISC

# Copyright 2024 6WIND S.A.
#

"""
test_bgp_bmp.py_3: Test BGP BMP functionalities

    +------+            +------+               +------+
    |      |            |      |               |      |
    | BMP1 |------+-----|  R1  |---------------|  R2  |
    |      |      |     |      |               |      |
    +------+      |     +--+---+               +------+
                  |        |
    +------+      |     +--+---+
    |      |      |     |      |
    | BMP2 |------+     |  R3  |
    |      |            |      |
    +------+            +------+

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
    bmp_display_seq,
    bmp_get_seq,
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

SEQ_BACKUP = 0


def build_topo(tgen):
    tgen.add_router("r1import")
    tgen.add_router("r2")
    tgen.add_router("r3")  # CPE behind r1

    tgen.add_bmp_server("bmp1import", ip="192.0.2.10", defaultRoute="via 192.0.2.1")
    tgen.add_bmp_server(
        "bmp2import", ip="192.0.2.20", defaultRoute="via 192.0.2.1", port=1790
    )

    switch = tgen.add_switch("s1")
    switch.add_link(tgen.gears["r1import"])
    switch.add_link(tgen.gears["bmp1import"])
    switch.add_link(tgen.gears["bmp2import"])

    tgen.add_link(tgen.gears["r1import"], tgen.gears["r2"], "r1import-eth1", "r2-eth0")
    tgen.add_link(tgen.gears["r1import"], tgen.gears["r3"], "r1import-eth2", "r3-eth0")


def setup_module(mod):
    tgen = Topogen(build_topo, mod.__name__)
    tgen.start_topology()

    tgen.net["r1import"].cmd(
        """
ip link add vrf1 type vrf table 10
ip link set vrf1 up
ip link set r1import-eth2 master vrf1
        """
    )

    bmp_reset_seq(bmp_seq_context)
    if DEBUG_PCAP:
        tgen.gears["r1import"].run("rm /tmp/bmp.pcap")
        tgen.gears["r1import"].run(
            "tcpdump -nni r1import-eth0 -s 0 -w /tmp/bmp.pcap &", stdout=None
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

    result = verify_bgp_convergence_from_running_config(tgen, dut="r1import")
    assert result is True, "BGP is not converging"


def _test_prefixes_syncro(policy, vrf=None, step=1, bmp_name="bmp1import"):
    """
    Check that the given policy has syncronised the previously received BGP
    updates.
    """
    tgen = get_topogen()

    prefixes = ["172.31.0.77/32", "2001::1125/128"]
    # check
    test_func = partial(
        bmp_check_for_prefixes,
        prefixes,
        "update",
        policy,
        step,
        tgen.gears[bmp_name],
        os.path.join(tgen.logdir, bmp_name),
        tgen.gears["r1import"],
        f"{CWD}/{bmp_name}",
        UPDATE_EXPECTED_JSON,
        LOC_RIB,
        bmp_seq_context,
    )
    success, res = topotest.run_and_expect(test_func, None, count=30, wait=1)
    assert success, "Checking the updated prefixes has failed ! %s" % res


def _test_prefixes(policy, vrf=None, step=0):
    """
    Setup the BMP  monitor policy, Add and withdraw ipv4/v6 prefixes.
    Check if the previous actions are logged in the BMP server with the right
    message type and the right policy.
    """
    tgen = get_topogen()

    safi = "vpn" if vrf else "unicast"

    prefixes = ["172.31.0.77/32", "2001::1125/128"]

    for type in ("update", "withdraw"):
        bmp_update_seq(
            tgen.gears["bmp1import"],
            os.path.join(tgen.logdir, "bmp1import", "bmp.log"),
            bmp_seq_context,
        )

        bgp_configure_prefixes(
            tgen.gears["r3"],
            65501,
            "unicast",
            prefixes,
            vrf=None,
            update=(type == "update"),
        )

        logger.info(f"checking for prefixes {type}")

        for ipver in [4, 6]:
            if UPDATE_EXPECTED_JSON:
                continue
            ref_file = "{}/r1import/show-bgp-{}-ipv{}-{}-step{}.json".format(
                CWD, vrf, ipver, type, step
            )
            expected = json.loads(open(ref_file).read())

            test_func = partial(
                topotest.router_json_cmp,
                tgen.gears["r1import"],
                f"show bgp vrf {vrf} ipv{ipver} json",
                expected,
            )
            _, res = topotest.run_and_expect(test_func, None, count=30, wait=1)
            assertmsg = f"r1: BGP IPv{ipver} convergence failed"
            assert res is None, assertmsg

        # check
        test_func = partial(
            bmp_check_for_prefixes,
            prefixes,
            type,
            policy,
            step,
            tgen.gears["bmp1import"],
            os.path.join(tgen.logdir, "bmp1import"),
            tgen.gears["r1import"],
            f"{CWD}/bmp1import",
            UPDATE_EXPECTED_JSON,
            LOC_RIB,
            bmp_seq_context,
        )
        success, res = topotest.run_and_expect(test_func, None, count=30, wait=1)
        assert success, "Checking the updated prefixes has failed ! %s" % res


def _test_peer_up(check_locrib=True, bmp_name="bmp1import"):
    """
    Checking for BMP peers up messages
    """

    tgen = get_topogen()
    if check_locrib:
        peers = ["0.0.0.0", "192.168.1.3", "192:167::3"]
    else:
        peers = ["192.168.1.3", "192:167::3"]

    logger.info("checking for BMP peers up messages")

    test_func = partial(
        bmp_check_for_peer_message,
        peers,
        "peer up",
        tgen.gears[bmp_name],
        os.path.join(tgen.logdir, bmp_name, "bmp.log"),
        bmp_seq_context,
        is_rd_instance=True,
    )
    success, _ = topotest.run_and_expect(test_func, True, count=30, wait=1)
    assert success, "Checking the updated prefixes has been failed !."


def test_bmp_server_logging():
    """
    Assert the logging of the bmp server.
    """

    def check_for_log_file():
        tgen = get_topogen()
        output = tgen.gears["bmp1import"].run(
            "ls {}".format(os.path.join(tgen.logdir, "bmp1import"))
        )
        if "bmp.log" not in output:
            return False
        return True

    success, _ = topotest.run_and_expect(check_for_log_file, True, count=30, wait=1)
    assert success, "The BMP server is not logging"


def test_bmp_peer_up_start():
    _test_peer_up()


def test_bmp_bgp_unicast():
    """
    Add/withdraw bgp unicast prefixes and check the bmp logs.
    """
    logger.info("*** Unicast prefixes pre-policy logging ***")
    _test_prefixes(PRE_POLICY, vrf="vrf1", step=1)
    logger.info("*** Unicast prefixes post-policy logging ***")
    _test_prefixes(POST_POLICY, vrf="vrf1", step=1)
    logger.info("*** Unicast prefixes loc-rib logging ***")
    _test_prefixes(LOC_RIB, vrf="vrf1", step=1)


def _test_r1import_update_networks(update=True):
    """
    Populate R3 with networks
    """
    tgen = get_topogen()

    prefixes = ["172.31.0.77/32", "2001::1125/128"]
    bgp_configure_prefixes(
        tgen.gears["r3"],
        65501,
        "unicast",
        prefixes,
        vrf=None,
        update=update,
    )


def test_r1import_add_networks():
    _test_r1import_update_networks()


def test_bmp_collector_bmp2_connect():
    """
    Check that BMP client reconnected to BMP collector
    """
    tgen = get_topogen()

    tgen.gears["r1import"].vtysh_cmd(
        """
        configure terminal
        router bgp 65501
        bmp targets bmp1
        bmp connect 192.0.2.20 port 1790 min-retry 100 max-retry 10000
        """
    )

    def _bmp_check_bmp_state(router, bmp_collector, state):
        output = router.cmd(
            f'vtysh -c "show bmp" 2>/dev/null | grep {bmp_collector} | grep {state}'
        )
        if output == "":
            return "not good"
        return True

    logger.info("Checking that BMP collector 192.0.2.20 is in Up state.")
    test_func = partial(
        _bmp_check_bmp_state, tgen.gears["r1import"], "192.0.2.20:1790", "Up"
    )
    success, _ = topotest.run_and_expect(test_func, True, count=15, wait=1)
    assert success, "Checking that BMP collector 192.0.2.20 is in Up state, has failed."


def test_bmp2_peer_up_start():
    global SEQ_BACKUP
    SEQ_BACKUP = bmp_get_seq(bmp_seq_context)
    bmp_reset_seq(bmp_seq_context)
    _test_peer_up(bmp_name="bmp2import")


def test_bmp2_bgp_unicast():
    """
    Check the bmp logs.
    """
    logger.info("*** Unicast prefixes pre-policy logging ***")
    _test_prefixes_syncro(PRE_POLICY, vrf="vrf1", bmp_name="bmp2import")
    logger.info("*** Unicast prefixes post-policy logging ***")
    _test_prefixes_syncro(POST_POLICY, vrf="vrf1", bmp_name="bmp2import")
    logger.info("*** Unicast prefixes loc-rib logging ***")
    _test_prefixes_syncro(LOC_RIB, vrf="vrf1", bmp_name="bmp2import")

    bmp_reset_seq(bmp_seq_context, seq_param=SEQ_BACKUP)


def test_r1import_del_networks():
    _test_r1import_update_networks(update=False)


def test_peer_down():
    """
    Checking for BMP peers down messages
    """
    tgen = get_topogen()

    tgen.gears["r3"].vtysh_cmd("clear bgp *")

    peers = ["192.168.1.3", "192:167::3"]

    logger.info("checking for BMP peers down messages")

    test_func = partial(
        bmp_check_for_peer_message,
        peers,
        "peer down",
        tgen.gears["bmp1import"],
        os.path.join(tgen.logdir, "bmp1import", "bmp.log"),
        bmp_seq_context,
    )
    success, _ = topotest.run_and_expect(test_func, True, count=30, wait=1)
    assert success, "Checking the updated prefixes has been failed !."


def test_reconfigure_prefixes():
    """
    Reconfigured BGP networks from R3. Check for BGP VRF update messages
    """

    tgen = get_topogen()

    prefixes = ["172.31.0.77/32", "2001::1125/128"]
    bgp_configure_prefixes(
        tgen.gears["r3"],
        65501,
        "unicast",
        prefixes,
        vrf=None,
        update=True,
    )

    for ipver in [4, 6]:
        ref_file = "{}/r1import/show-bgp-{}-ipv{}-{}-step{}.json".format(
            CWD, "vrf1", ipver, "update", 1
        )
        expected = json.loads(open(ref_file).read())

        test_func = partial(
            topotest.router_json_cmp,
            tgen.gears["r1import"],
            f"show bgp vrf vrf1 ipv{ipver} json",
            expected,
        )
        _, res = topotest.run_and_expect(test_func, None, count=30, wait=1)
        assertmsg = f"r1: BGP IPv{ipver} convergence failed"
        assert res is None, assertmsg


def test_monitor_syncro():
    """
    Checking for BMP peers down messages
    """
    tgen = get_topogen()

    tgen.gears["r1import"].vtysh_cmd(
        """
        configure terminal
        router bgp 65501
        bmp targets bmp1
        bmp import-vrf-view vrf1
        """
    )

    logger.info("*** Unicast prefixes pre-policy logging ***")
    _test_prefixes_syncro(PRE_POLICY, vrf="vrf1")
    logger.info("*** Unicast prefixes post-policy logging ***")
    _test_prefixes_syncro(POST_POLICY, vrf="vrf1")
    logger.info("*** Unicast prefixes loc-rib logging ***")
    _test_prefixes_syncro(LOC_RIB, vrf="vrf1")


def test_reconfigure_route_distinguisher_vrf1():
    """
    Checking for BMP peers down messages
    """
    tgen = get_topogen()

    bmp_update_seq(
        tgen.gears["bmp1import"],
        os.path.join(tgen.logdir, "bmp1import", "bmp.log"),
        bmp_seq_context,
    )
    peers = ["0.0.0.0"]

    tgen.gears["r1import"].vtysh_cmd(
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
        "Checking for BMP peer down LOC-RIB message with route-distinguisher set to 444:1"
    )
    test_func = partial(
        bmp_check_for_peer_message,
        peers,
        "peer down",
        tgen.gears["bmp1import"],
        os.path.join(tgen.logdir, "bmp1import", "bmp.log"),
        bmp_seq_context,
        is_rd_instance=True,
        peer_distinguisher="444:1",
    )
    success, _ = topotest.run_and_expect(test_func, True, count=30, wait=1)
    assert (
        success
    ), "Checking the BMP peer down LOC-RIB message with route-distinguisher set to 444:1 failed !."

    logger.info(
        "Checking for BMP peer up LOC-RIB messages with route-distinguisher set to 666:22"
    )
    test_func = partial(
        bmp_check_for_peer_message,
        peers,
        "peer up",
        tgen.gears["bmp1import"],
        os.path.join(tgen.logdir, "bmp1import", "bmp.log"),
        bmp_seq_context,
        is_rd_instance=True,
        peer_distinguisher="666:22",
    )
    success, _ = topotest.run_and_expect(test_func, True, count=30, wait=1)
    assert (
        success
    ), "Checking the BMP peer up LOC-RIB message with route-distinguisher set to 666:22 failed !."

    logger.info(
        "Checking for BMP peer up messages with route-distinguisher set to 666:22"
    )
    peers = ["192.168.1.3", "192:167::3"]
    test_func = partial(
        bmp_check_for_peer_message,
        peers,
        "peer up",
        tgen.gears["bmp1import"],
        os.path.join(tgen.logdir, "bmp1import", "bmp.log"),
        bmp_seq_context,
        is_rd_instance=True,
        peer_distinguisher="666:22",
    )
    success, _ = topotest.run_and_expect(test_func, True, count=30, wait=1)
    assert (
        success
    ), "Checking the BMP peer up messages with route-distinguisher set to 666:22 failed !."

    logger.info("*** Unicast prefixes pre-policy logging ***")
    _test_prefixes_syncro(PRE_POLICY, vrf="vrf1", step=2)
    logger.info("*** Unicast prefixes post-policy logging ***")
    _test_prefixes_syncro(POST_POLICY, vrf="vrf1", step=2)
    logger.info("*** Unicast prefixes loc-rib logging ***")
    _test_prefixes_syncro(LOC_RIB, vrf="vrf1", step=2)


def test_bgp_routerid_changed():
    """
    Checking for BGP loc-rib up messages with new router-id
    """
    tgen = get_topogen()

    tgen.gears["r1import"].vtysh_cmd(
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
        tgen.gears["bmp1import"],
        os.path.join(tgen.logdir, "bmp1import", "bmp.log"),
        bmp_seq_context,
        is_rd_instance=True,
        peer_bgp_id="192.168.0.1",
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
        tgen.gears["bmp1import"],
        os.path.join(tgen.logdir, "bmp1import", "bmp.log"),
        bmp_seq_context,
        is_rd_instance=True,
        peer_bgp_id="192.168.1.77",
        bgp_open_as=65501,
        bgp_open_bgp_id="192.168.1.77",
    )
    success, _ = topotest.run_and_expect(test_func, True, count=30, wait=1)
    assert (
        success
    ), "Checking the BMP peer up LOC-RIB message with router-id set to 192.168.1.77 failed !."


def test_bgp_instance_flapping():
    """
    Checking for BGP loc-rib up messages
    """
    tgen = get_topogen()

    # create flapping at BMP
    # note: only peer up are handled at BMP level today
    tgen.net["r1import"].cmd("ip link set dev vrf1 down")

    peers = ["0.0.0.0"]

    logger.info("checking for BMP peer down LOC-RIB message.")
    test_func = partial(
        bmp_check_for_peer_message,
        peers,
        "peer down",
        tgen.gears["bmp1import"],
        os.path.join(tgen.logdir, "bmp1import", "bmp.log"),
        bmp_seq_context,
        is_rd_instance=True,
    )
    success, _ = topotest.run_and_expect(test_func, True, count=30, wait=1)
    assert success, "Checking the BMP peer down LOC-RIB message failed !."

    tgen.net["r1import"].cmd("ip link set dev vrf1 up")

    logger.info("checking for BMP peer up LOC-RIB message.")
    test_func = partial(
        bmp_check_for_peer_message,
        peers,
        "peer up",
        tgen.gears["bmp1import"],
        os.path.join(tgen.logdir, "bmp1import", "bmp.log"),
        bmp_seq_context,
        is_rd_instance=True,
    )
    success, _ = topotest.run_and_expect(test_func, True, count=30, wait=1)
    assert success, "Checking the BMP peer up LOC-RIB message failed !."


def test_peer_up_after_flush():
    """
    Checking for BMP peers down messages
    """
    _test_peer_up(check_locrib=False)


def test_peer_down_locrib():
    """
    Checking for BMP peers down loc-rib messages
    """
    tgen = get_topogen()

    tgen.gears["r1import"].vtysh_cmd(
        """
        configure terminal
        router bgp 65501
        bmp targets bmp1
        no bmp import-vrf-view vrf1
        """
    )

    peers = ["0.0.0.0"]

    logger.info("checking for BMP peers down messages")

    test_func = partial(
        bmp_check_for_peer_message,
        peers,
        "peer down",
        tgen.gears["bmp1import"],
        os.path.join(tgen.logdir, "bmp1import", "bmp.log"),
        bmp_seq_context,
    )
    success, _ = topotest.run_and_expect(test_func, True, count=30, wait=1)
    assert success, "Checking the BMP peer down message has failed !."


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
