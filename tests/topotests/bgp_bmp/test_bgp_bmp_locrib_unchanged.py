#!/usr/bin/env python
# SPDX-License-Identifier: ISC

#
# Copyright 2026 by 6WIND S.A.
#

"""
test_bgp_bmp_locrib_unchanged.py: BMP loc-rib when the best path is
unchanged.

    +---------+     +----------+              +----------+
    | bmp1lr  |-----|   r1lr   |--------------|   r2lr   |
    +---------+     +----------+              +----------+

r1lr has a bmp target monitoring the ipv4 unicast loc-rib. When the best
paths of r1lr are computed again and the same path is selected, no
loc-rib route monitoring message must be sent for the prefix.
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

PEER = "192.168.0.2"
WATCHED_PREFIX = "203.0.113.1/32"
SENTINEL_PREFIX_BEFORE = "203.0.113.2/32"
SENTINEL_PREFIX_AFTER = "203.0.113.3/32"


def build_topo(tgen):
    tgen.add_router("r1lr")
    tgen.add_router("r2lr")

    tgen.add_bmp_server("bmp1lr", ip="192.0.2.10", defaultRoute="via 192.0.2.1")

    switch = tgen.add_switch("s1")
    switch.add_link(tgen.gears["r1lr"])
    switch.add_link(tgen.gears["bmp1lr"])

    tgen.add_link(tgen.gears["r1lr"], tgen.gears["r2lr"], "r1lr-eth1", "r2lr-eth0")


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


def bmp_messages():
    tgen = get_topogen()
    bmp_log_file = os.path.join(tgen.logdir, "bmp1lr", "bmp.log")
    return get_bmp_messages(tgen.gears["bmp1lr"], bmp_log_file)


@retry(retry_timeout=30)
def check_locrib_update(prefix, min_seq=0):
    for message in bmp_messages():
        if (
            message.get("seq", 0) > min_seq
            and message.get("policy") == "loc-rib"
            and message.get("bmp_log_type") == "update"
            and message.get("ip_prefix") == prefix
        ):
            return message
    return "no loc-rib update for {} after seq {}".format(prefix, min_seq)


def announce(prefix):
    """
    Announce a prefix from r2lr, and return the sequence number of its
    loc-rib update.
    """
    tgen = get_topogen()
    tgen.gears["r2lr"].vtysh_cmd(
        """
        configure terminal
         router bgp 65502
          address-family ipv4 unicast
           network {}
        """.format(
            prefix
        )
    )
    message = check_locrib_update(prefix)
    assert not isinstance(message, str), message
    return message["seq"]


def test_bmp_peer_up():
    """
    Wait for the peer up of r2lr on bmp1lr.
    """
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    @retry(retry_timeout=60)
    def check_peer_up():
        for message in bmp_messages():
            if (
                message.get("bmp_log_type") == "peer up"
                and message.get("peer_ip") == PEER
            ):
                return True
        return "no peer up received for {}".format(PEER)

    result = check_peer_up()
    assert result is True, result


def test_bmp_locrib_best_path_unchanged():
    """
    Recompute the best paths of r1lr without changing them, by setting then
    unsetting 'bgp always-compare-med': the selected path of the watched
    prefix is the same, so no loc-rib update must be sent for it.
    A sentinel prefix is announced from r2lr before and after the
    recomputation: the loc-rib messages logged between both sentinel
    updates are the ones queued by the recomputation.
    """
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    announce(WATCHED_PREFIX)
    seq_before = announce(SENTINEL_PREFIX_BEFORE)

    tgen.gears["r1lr"].vtysh_cmd(
        """
        configure terminal
         router bgp 65501
          bgp always-compare-med
          no bgp always-compare-med
        """
    )

    seq_after = announce(SENTINEL_PREFIX_AFTER)

    spurious = [
        message
        for message in bmp_messages()
        if seq_before < message.get("seq", 0) < seq_after
        and message.get("policy") == "loc-rib"
        and message.get("ip_prefix") == WATCHED_PREFIX
    ]
    assert (
        not spurious
    ), "loc-rib message(s) sent for {} while its best path is unchanged: " "{}".format(
        WATCHED_PREFIX, spurious
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
