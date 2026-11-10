#!/usr/bin/env python
# SPDX-License-Identifier: ISC
#
# test_bfd_dplane_echo_socket_topo1.py
#
# Copyright (c) 2026 by Abdul Wasey
#

"""
With a data plane, bfdd must not open the BFD echo port.

bfdd opens no BFD sockets when it uses a data plane: the data plane sends
and receives control and echo packets. The echo sockets were an exception,
opened whenever echo-mode was set on a session whose VRF was already known.
Whether bfdd held the port then depended on the order in which the
configuration and the interfaces arrived, and so did whether a peer's IPv6
echo was returned by bfdd or refused with port unreachable.

The listener stands in for a data plane.
"""

import os
import sys
from functools import partial

import pytest

CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

# pylint: disable=C0413
from lib import topotest
from lib.topogen import Topogen, TopoRouter, get_topogen

pytestmark = [pytest.mark.bfdd]

DPLANE_PORT = 50700
PEERS = {
    "10.0.1.2": "peer 10.0.1.2 local-address 10.0.1.1 interface r1-eth0",
    "fd00:1::2": "peer fd00:1::2 local-address fd00:1::1 interface r1-eth0",
}


def build_topo(tgen):
    "Build function"
    tgen.add_router("r1")
    switch = tgen.add_switch("s1")
    switch.add_link(tgen.gears["r1"])


def setup_module(mod):
    tgen = Topogen(build_topo, mod.__name__)
    tgen.start_topology()

    router = tgen.gears["r1"]

    # bfdd connects to the listener as a client, so it starts first.
    router.load_frr_config(
        daemons=[
            (TopoRouter.RD_BFD_DPLANE_LISTENER, "-p {}".format(DPLANE_PORT)),
            (TopoRouter.RD_ZEBRA, None),
            (
                TopoRouter.RD_BFD,
                "--dplaneaddr ipv4c:127.0.0.1:{}".format(DPLANE_PORT),
            ),
        ],
    )

    tgen.start_router()


def teardown_module(_mod):
    tgen = get_topogen()
    tgen.stop_topology()


def _echo_sockets(router):
    "bfdd's UDP sockets on the echo port, as ss prints them."
    out = router.cmd("ss -Hulpn sport = :3785")
    return [line for line in out.splitlines() if "bfdd" in line]


def _echo_tx(router, peer):
    "The peer's echo transmit interval: 0 when echo-mode is off."
    for entry in router.vtysh_cmd("show bfd peers json", isjson=True):
        if entry.get("peer") == peer:
            return entry.get("echo-transmit-interval")
    return None


def _all_up(router):
    peers = router.vtysh_cmd("show bfd peers json", isjson=True)
    down = [p["peer"] for p in peers if p.get("status") != "up"]
    if len(peers) != len(PEERS) or down:
        return "not up: {}".format(down or peers)
    return None


def test_sessions_up():
    "The listener takes both sessions."
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    router = tgen.gears["r1"]
    _, result = topotest.run_and_expect(
        partial(_all_up, router), None, count=30, wait=1
    )
    assert result is None, result


def test_no_echo_socket_from_config():
    "echo-mode from the startup configuration opens no socket."
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    router = tgen.gears["r1"]
    found = _echo_sockets(router)
    assert not found, "bfdd holds the echo port: {}".format(found)


def test_no_echo_socket_when_set_at_runtime():
    "echo-mode set from vtysh opens no socket either."
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    router = tgen.gears["r1"]
    for peer, config in PEERS.items():
        router.vtysh_cmd(
            "configure terminal\nbfd\n{}\nno echo-mode\nend".format(config)
        )
        assert _echo_tx(router, peer) == 0, "echo-mode is still on for {}".format(peer)
        router.vtysh_cmd("configure terminal\nbfd\n{}\necho-mode\nend".format(config))
        assert _echo_tx(router, peer), "echo-mode did not come back for {}".format(peer)

    found = _echo_sockets(router)
    assert not found, "bfdd holds the echo port: {}".format(found)

    _, result = topotest.run_and_expect(
        partial(_all_up, router), None, count=10, wait=1
    )
    assert result is None, result


def test_memory_leak():
    "Run the memory leak test and report results."
    tgen = get_topogen()
    if not tgen.is_memleak_enabled():
        pytest.skip("Memory leak test/report is disabled")
    tgen.report_memory_leaks()


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
