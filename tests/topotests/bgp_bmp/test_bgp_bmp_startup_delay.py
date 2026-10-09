#!/usr/bin/env python
# SPDX-License-Identifier: ISC

# Copyright 2026 6WIND S.A.
#

"""
test_bgp_bmp_startup_delay.py: BMP startup delay per BGP instance.

    +----------+                 +----------+   default    +----------+
    |  bmp1sd  |-----+-----------|   r1sd   |--------------|   r2sd   |
    +----------+     |           |          |              +----------+
    +----------+     |           |          |   vrf1       +----------+
    |  bmp2sd  |-----+           |          |--------------|   r3sd   |
    +----------+                 +----------+              +----------+

The default BGP instance of r1sd sends BMP to bmp1sd without startup
delay. The vrf1 BGP instance sends BMP to bmp2sd, with a startup delay
longer than the test.

Checks:

* once the startup delay of the default instance is over, the BMP
  session of vrf1 stays in startup wait, and bmp2sd receives no
  peer-state message for the vrf1 peer, even when that peer flaps.
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

DEFAULT_PEER = "192.168.0.2"
VRF_PEER = "192.168.1.3"
BMP2_SESSION = "192.0.2.20:1790"


def build_topo(tgen):
    tgen.add_router("r1sd")
    tgen.add_router("r2sd")
    tgen.add_router("r3sd")
    tgen.add_bmp_server("bmp1sd", ip="192.0.2.10", defaultRoute="via 192.0.2.1")
    tgen.add_bmp_server(
        "bmp2sd", ip="192.0.2.20", defaultRoute="via 192.0.2.1", port=1790
    )

    switch = tgen.add_switch("s1")
    switch.add_link(tgen.gears["r1sd"])
    switch.add_link(tgen.gears["bmp1sd"])
    switch.add_link(tgen.gears["bmp2sd"])

    tgen.add_link(tgen.gears["r1sd"], tgen.gears["r2sd"], "r1sd-eth1", "r2sd-eth0")
    tgen.add_link(tgen.gears["r1sd"], tgen.gears["r3sd"], "r1sd-eth2", "r3sd-eth0")


def setup_module(mod):
    tgen = Topogen(build_topo, mod.__name__)
    tgen.start_topology()

    tgen.net["r1sd"].cmd(
        """
ip link add vrf1 type vrf table 10
ip link set vrf1 up
ip link set r1sd-eth2 master vrf1
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


def peer_state_messages(bmp_name, peer_ip):
    tgen = get_topogen()
    log_file = os.path.join(tgen.logdir, bmp_name, "bmp.log")
    messages = get_bmp_messages(tgen.gears[bmp_name], log_file)
    return [
        m
        for m in messages
        if m.get("peer_ip") == peer_ip
        and m.get("bmp_log_type") in ("peer up", "peer down")
    ]


def test_bmp_server_logging():
    """
    Wait for both BMP collectors to start logging (session established).
    """
    tgen = get_topogen()

    @retry(retry_timeout=30)
    def check_log_file(bmp_name):
        output = tgen.gears[bmp_name].run(
            "ls {}".format(os.path.join(tgen.logdir, bmp_name))
        )
        if "bmp.log" in output:
            return True
        return "{} is not logging".format(bmp_name)

    for bmp_name in ("bmp1sd", "bmp2sd"):
        result = check_log_file(bmp_name)
        assert result is True, result


def test_bmp_default_instance_started():
    """
    The default instance has no startup delay: bmp1sd receives the Peer Up
    of the default instance peer.
    """
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    @retry(retry_timeout=60)
    def check_peer_up(bmp_name, peer_ip):
        for m in peer_state_messages(bmp_name, peer_ip):
            if m["bmp_log_type"] == "peer up":
                return True
        return "no Peer Up for {} logged by {}".format(peer_ip, bmp_name)

    result = check_peer_up("bmp1sd", DEFAULT_PEER)
    assert result is True, result


def test_bmp_vrf_instance_startup_wait():
    """
    Flap the vrf1 peer while the vrf1 BMP session is in startup wait:
    bmp2sd must not receive any peer-state message for that peer.
    """
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1sd = tgen.gears["r1sd"]

    def check_bmp2_startup_wait():
        output = r1sd.vtysh_cmd("show bmp")
        for line in output.splitlines():
            if BMP2_SESSION in line and "Startup-Wait" in line:
                return True
        return "BMP session {} not in Startup-Wait:\n{}".format(BMP2_SESSION, output)

    @retry(retry_timeout=60)
    def check_vrf_peer_established(min_dropped):
        output = json.loads(
            r1sd.vtysh_cmd("show bgp vrf vrf1 neighbors {} json".format(VRF_PEER))
        )
        peer = output.get(VRF_PEER, {})
        if peer.get("bgpState") != "Established":
            return "{} not established".format(VRF_PEER)
        if peer.get("connectionsDropped", 0) < min_dropped:
            return "{} did not flap yet".format(VRF_PEER)
        return True

    result = check_vrf_peer_established(0)
    assert result is True, result

    output = json.loads(
        r1sd.vtysh_cmd("show bgp vrf vrf1 neighbors {} json".format(VRF_PEER))
    )
    dropped = output[VRF_PEER].get("connectionsDropped", 0)

    r1sd.vtysh_cmd("clear bgp vrf vrf1 {}".format(VRF_PEER))

    result = check_vrf_peer_established(dropped + 1)
    assert result is True, result

    result = check_bmp2_startup_wait()
    assert result is True, result

    messages = peer_state_messages("bmp2sd", VRF_PEER)
    assert not messages, (
        "bmp2sd received peer-state messages for {} while the vrf1 BMP "
        "session is in startup wait: {}".format(VRF_PEER, messages)
    )


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
