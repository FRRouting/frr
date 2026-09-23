#!/usr/bin/env python
# SPDX-License-Identifier: ISC

"""
test_bgp_bmp_open_collision.py: BMP Peer Up after a BGP connection collision

    +------+            +------+               +-------+
    |      |            |      |               |       |
    | BMP1 |------------|  R1  |---------------| PEER1 |
    |      |            |      |               |       |
    +------+            +------+               +-------+

PEER1 is a scripted BGP speaker that lets R1's outgoing connection reach
Established while a second, incoming connection from PEER1 is still waiting
in OpenSent. R1 resolves the collision in favour of its own connection.

The Peer Up notification R1 then sends to BMP1 must carry the OPEN messages
exchanged on the surviving connection, not a placeholder taken from the
connection that lost. The check asserts on the decoded OPENs in the
collector's JSON log.
"""

from functools import partial
import os
import pytest
import sys

CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join("../"))
sys.path.append(os.path.join("../lib/"))

# pylint: disable=C0413
from lib import topotest
from .bgpbmp import get_bmp_messages
from lib.topogen import Topogen, TopoRouter, get_topogen
from lib.topolog import logger

pytestmark = [pytest.mark.bgpd]

R1_AS = 65501
PEER_AS = 65502
R1_ID = "192.168.0.1"
PEER_IP = "192.168.0.2"
# Lower than R1_ID so that R1 keeps its own outgoing connection on collision.
PEER_ID = "10.0.0.2"


def build_topo(tgen):
    tgen.add_router("r1col")
    tgen.add_bmp_server("bmp1col", ip="192.0.2.10", defaultRoute="via 192.0.2.1")
    tgen.add_host("peer1", ip=PEER_IP + "/24", defaultRoute="via " + R1_ID)

    switch = tgen.add_switch("s1")
    switch.add_link(tgen.gears["r1col"])
    switch.add_link(tgen.gears["bmp1col"])

    switch = tgen.add_switch("s2")
    switch.add_link(tgen.gears["r1col"])
    switch.add_link(tgen.gears["peer1"])


def setup_module(mod):
    tgen = Topogen(build_topo, mod.__name__)
    tgen.start_topology()

    for rname, router in tgen.routers().items():
        router.load_frr_config(
            os.path.join(CWD, "{}/frr.conf".format(rname)),
            [(TopoRouter.RD_ZEBRA, None), (TopoRouter.RD_BGP, "-M bmp")],
        )

    tgen.start_router()

    for bmp_name, server in tgen.get_bmp_servers().items():
        server.start(log_file=os.path.join(tgen.logdir, bmp_name, "bmp.log"))

    peer_log = os.path.join(tgen.logdir, "peer1", "peer.log")
    tgen.gears["peer1"].run("mkdir -p {}".format(os.path.dirname(peer_log)))
    tgen.gears["peer1"].run(
        "python3 {}/peer1/bgp_collision_peer.py --local {} --router {} --asn {} "
        "--bgp-id {} > {} 2>&1 &".format(
            CWD, PEER_IP, R1_ID, PEER_AS, PEER_ID, peer_log
        ),
        stdout=None,
    )


def teardown_module(_mod):
    tgen = get_topogen()
    tgen.stop_topology()


def _peer_established():
    tgen = get_topogen()
    output = tgen.gears["r1col"].vtysh_cmd(
        "show bgp neighbors {} json".format(PEER_IP), isjson=True
    )
    return output.get(PEER_IP, {}).get("bgpState")


def test_collision_established():
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    success, state = topotest.run_and_expect(
        _peer_established, "Established", count=60, wait=1
    )
    assert success, "BGP session with the scripted peer not Established: {}".format(
        state
    )


def _peer_up_with_real_opens():
    tgen = get_topogen()
    log_file = os.path.join(tgen.logdir, "bmp1col", "bmp.log")
    for m in get_bmp_messages(tgen.gears["bmp1col"], log_file):
        if m.get("bmp_log_type") != "peer up" or m.get("peer_ip") != PEER_IP:
            continue
        open_tx = m.get("open_tx", {})
        open_rx = m.get("open_rx", {})
        return {
            "tx_as": open_tx.get("my_as"),
            "tx_id": open_tx.get("bgp_id"),
            "rx_as": open_rx.get("my_as"),
            "rx_id": open_rx.get("bgp_id"),
        }
    return None


def test_peer_up_carries_winner_opens():
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    expected = {"tx_as": R1_AS, "tx_id": R1_ID, "rx_as": PEER_AS, "rx_id": PEER_ID}
    success, result = topotest.run_and_expect(
        _peer_up_with_real_opens, expected, count=30, wait=1
    )
    assert (
        success
    ), "BMP Peer Up does not carry the surviving connection's OPENs: {}".format(result)


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
