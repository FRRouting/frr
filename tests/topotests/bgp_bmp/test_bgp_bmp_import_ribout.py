#!/usr/bin/env python
# SPDX-License-Identifier: ISC

# Copyright 2026 6WIND S.A.
#

"""
test_bgp_bmp_import_ribout.py: BMP adj-rib-out of an imported BGP instance.

    +----------+            +----------+    vrf1     +----------+
    |  bmp1ri  |------------|   r1ri   |-------------|   r2ri   |
    +----------+            +----------+             +----------+

The BMP target of the default BGP instance of r1ri imports the vrf1 BGP
instance, and monitors the adj-rib-out pre-policy and post-policy. The
vrf1 instance advertises its networks to r2ri. The BMP target has no
connection at startup.

Checks:

* when the BMP collector connects, the initial table synchronization
  sends the adj-rib-out of vrf1 towards r2ri;
* a network added afterwards in vrf1 is sent as an adj-rib-out update
  towards r2ri.
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

SYNC_PREFIX = "172.31.0.1/32"
LIVE_PREFIX = "172.31.0.2/32"
PEER = "192.168.1.2"


def build_topo(tgen):
    tgen.add_router("r1ri")
    tgen.add_router("r2ri")
    tgen.add_bmp_server("bmp1ri", ip="192.0.2.10", defaultRoute="via 192.0.2.1")

    switch = tgen.add_switch("s1")
    switch.add_link(tgen.gears["r1ri"])
    switch.add_link(tgen.gears["bmp1ri"])

    tgen.add_link(tgen.gears["r1ri"], tgen.gears["r2ri"], "r1ri-eth1", "r2ri-eth0")


def setup_module(mod):
    tgen = Topogen(build_topo, mod.__name__)
    tgen.start_topology()

    tgen.net["r1ri"].cmd(
        """
ip link add vrf1 type vrf table 10
ip link set vrf1 up
ip link set r1ri-eth1 master vrf1
"""
    )

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


@retry(retry_timeout=60)
def check_prefix_advertised(prefix):
    tgen = get_topogen()
    output = json.loads(
        tgen.gears["r2ri"].vtysh_cmd("show bgp ipv4 unicast {} json".format(prefix))
    )
    if not output.get("paths"):
        return "{} not received by r2ri".format(prefix)
    return True


@retry(retry_timeout=60)
def check_ribout_update(prefix, policy):
    tgen = get_topogen()
    log_file = os.path.join(tgen.logdir, "bmp1ri", "bmp.log")
    for m in get_bmp_messages(tgen.gears["bmp1ri"], log_file):
        if (
            m.get("policy") == policy
            and m.get("bmp_log_type") == "update"
            and m.get("ip_prefix") == prefix
            and m.get("peer_ip") == PEER
        ):
            return True
    return "no {} rib-out update for {} towards {}".format(policy, prefix, PEER)


def test_vrf_prefix_advertised():
    """
    The vrf1 instance of r1ri advertises its network to r2ri.
    """
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    result = check_prefix_advertised(SYNC_PREFIX)
    assert result is True, result


def test_bmp_sync_imported_ribout():
    """
    Connect the BMP collector: the initial table synchronization must send
    the adj-rib-out of the imported vrf1 instance.
    """
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    tgen.gears["r1ri"].vtysh_cmd(
        """
        configure terminal
         router bgp 65501
          bmp targets bmp1
           bmp connect 192.0.2.10 port 1789 min-retry 100 max-retry 10000
        """
    )

    @retry(retry_timeout=30)
    def check_log_file():
        output = tgen.gears["bmp1ri"].run(
            "ls {}".format(os.path.join(tgen.logdir, "bmp1ri"))
        )
        if "bmp.log" in output:
            return True
        return "bmp1ri is not logging"

    result = check_log_file()
    assert result is True, result

    for policy in ("pre-policy", "post-policy"):
        result = check_ribout_update(SYNC_PREFIX, policy)
        assert result is True, result


def test_bmp_imported_ribout_update():
    """
    Add a network in vrf1: its adj-rib-out update towards r2ri must be sent.
    """
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    tgen.gears["r1ri"].vtysh_cmd(
        """
        configure terminal
         router bgp 65501 vrf vrf1
          address-family ipv4 unicast
           network {}
        """.format(
            LIVE_PREFIX
        )
    )

    result = check_prefix_advertised(LIVE_PREFIX)
    assert result is True, result

    for policy in ("pre-policy", "post-policy"):
        result = check_ribout_update(LIVE_PREFIX, policy)
        assert result is True, result


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
