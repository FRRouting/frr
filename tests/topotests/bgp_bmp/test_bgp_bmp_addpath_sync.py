#!/usr/bin/env python
# SPDX-License-Identifier: ISC

# Copyright 2026 6WIND S.A.
#

"""
test_bgp_bmp_addpath_sync.py: BMP initial sync of add-path paths.

                                                       +----------+
                                                  +----|   r3ap   |
    +----------+     +----------+     +----------+|    +----------+
    |  bmp1ap  |-----|   r1ap   |-----|   r2ap   |+
    +----------+     +----------+     +----------+|    +----------+
                                                  +----|   r4ap   |
                                                       +----------+

r3ap and r4ap announce 172.31.0.1/32 to r2ap, which sends both paths to
r1ap with add-path. r1ap has a BMP target without connection.

Checks:

* when the BMP collector connects after r1ap received both paths, the
  initial table synchronization sends both add-path IDs of r2ap in the
  adj-rib-in pre-policy and post-policy, and every selected path in the
  loc-rib.
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
from lib.common_config import retry
from .bgpbmp import get_bmp_messages
from lib.topogen import Topogen, get_topogen
from lib.topolog import logger

pytestmark = [pytest.mark.bgpd]

PREFIX = "172.31.0.1/32"
PEER = "192.168.0.2"


def build_topo(tgen):
    for rname in ("r1ap", "r2ap", "r3ap", "r4ap"):
        tgen.add_router(rname)
    tgen.add_bmp_server("bmp1ap", ip="192.0.2.10", defaultRoute="via 192.0.2.1")

    switch = tgen.add_switch("s1")
    switch.add_link(tgen.gears["r1ap"])
    switch.add_link(tgen.gears["bmp1ap"])

    tgen.add_link(tgen.gears["r1ap"], tgen.gears["r2ap"], "r1ap-eth1", "r2ap-eth0")
    tgen.add_link(tgen.gears["r2ap"], tgen.gears["r3ap"], "r2ap-eth1", "r3ap-eth0")
    tgen.add_link(tgen.gears["r2ap"], tgen.gears["r4ap"], "r2ap-eth2", "r4ap-eth0")


def setup_module(mod):
    tgen = Topogen(build_topo, mod.__name__)
    tgen.start_topology()

    for router in tgen.routers().values():
        router.load_frr_config(
            daemons=["zebra", ("bgpd", "-M bmp")],
        )

    tgen.start_router()

    logger.info("starting BMP servers")
    for bmp_name, server in tgen.get_bmp_servers().items():
        server.start(log_file=os.path.join(tgen.logdir, bmp_name, "bmp.log"))


def teardown_module(_mod):
    tgen = get_topogen()
    tgen.stop_topology()


def test_bgp_addpath_paths_received():
    """
    r1ap receives two paths for the prefix from r2ap, with different
    add-path IDs.
    """
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    @retry(retry_timeout=60)
    def check_two_paths():
        output = json.loads(
            tgen.gears["r1ap"].vtysh_cmd(
                "show bgp ipv4 unicast {} json".format(PREFIX)
            )
        )
        paths = [
            p
            for p in output.get("paths", [])
            if p.get("peer", {}).get("peerId") == PEER
        ]
        if len(paths) != 2:
            return "{} paths from {} for {}, 2 expected".format(
                len(paths), PEER, PREFIX
            )
        return True

    result = check_two_paths()
    assert result is True, result


def test_bmp_sync_addpath_paths():
    """
    Connect the BMP collector after the paths were received: the initial
    table synchronization must send all the add-path IDs of r2ap.
    """
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1ap = tgen.gears["r1ap"]
    log_file = os.path.join(tgen.logdir, "bmp1ap", "bmp.log")

    output = json.loads(
        r1ap.vtysh_cmd("show bgp ipv4 unicast {} json".format(PREFIX))
    )
    selected = [
        p
        for p in output.get("paths", [])
        if p.get("bestpath", {}).get("overall") or p.get("multipath")
    ]

    r1ap.vtysh_cmd(
        """
        configure terminal
         router bgp 65501
          bmp targets bmp1
           bmp connect 192.0.2.10 port 1789 min-retry 100 max-retry 10000
        """
    )

    @retry(retry_timeout=30)
    def check_log_file():
        output = tgen.gears["bmp1ap"].run(
            "ls {}".format(os.path.join(tgen.logdir, "bmp1ap"))
        )
        if "bmp.log" in output:
            return True
        return "bmp1ap is not logging"

    result = check_log_file()
    assert result is True, result

    @retry(retry_timeout=60)
    def check_sync_path_ids(policy, expected):
        path_ids = set()
        for m in get_bmp_messages(tgen.gears["bmp1ap"], log_file):
            if (
                m.get("policy") != policy
                or m.get("bmp_log_type") != "update"
                or m.get("ip_prefix") != PREFIX
            ):
                continue
            if policy != "loc-rib" and m.get("peer_ip") != PEER:
                continue
            path_ids.add(m.get("path_id"))
        if len(path_ids) != expected:
            return "{} {} path IDs logged for {}: {}, {} expected".format(
                len(path_ids), policy, PREFIX, path_ids, expected
            )
        return True

    for policy, expected in (
        ("pre-policy", 2),
        ("post-policy", 2),
        ("loc-rib", len(selected)),
    ):
        result = check_sync_path_ids(policy, expected)
        assert result is True, result


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
