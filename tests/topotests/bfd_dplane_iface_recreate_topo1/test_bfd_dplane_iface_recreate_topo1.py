#!/usr/bin/env python
# SPDX-License-Identifier: ISC
#
# test_bfd_dplane_iface_recreate_topo1.py
#
# Copyright (c) 2026 by Abdul Wasey
#

"""
Test that a data plane session gets its interface back when the
interface, or the VRF it is in, is deleted and created again.

A data plane places a single hop session by its interface. When the
interface or VRF comes back, bfdd has to tell the data plane which one
the session runs on, and keep sending it in later session updates.
"""

import os
import re
import sys
import time

import pytest

CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

# pylint: disable=C0413
from lib import topotest
from lib.topogen import Topogen, TopoRouter, get_topogen

pytestmark = [pytest.mark.bfdd]

DPLANE_PORT = 50700
PEER_DEFAULT = "10.0.2.100"
PEER_VRF = "10.0.3.100"


def build_topo(tgen):
    "Build function"
    tgen.add_router("r1")
    switch = tgen.add_switch("s1")
    switch.add_link(tgen.gears["r1"])


def _add_dum0(router):
    router.run("ip link add dum0 type dummy && ip link set dum0 up")


def _add_cust1(router):
    router.run(
        "ip link add cust1 type vrf table 10 && ip link set cust1 up"
        " && ip link set dum1 master cust1"
    )


def setup_module(mod):
    tgen = Topogen(build_topo, mod.__name__)
    tgen.start_topology()

    router = tgen.gears["r1"]
    _add_dum0(router)
    router.run("ip link add dum1 type dummy && ip link set dum1 up")
    _add_cust1(router)

    dump_file = os.path.join(router.gearlogdir, "bfd_dplane.data")
    # bfdd connects to the listener as a client, so the listener has to
    # be accepting before bfdd starts.
    router.load_frr_config(
        daemons=[
            (
                TopoRouter.RD_BFD_DPLANE_LISTENER,
                "-p {} -z {}".format(DPLANE_PORT, dump_file),
            ),
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


def _listener_dump(router):
    "Ask the listener to write its state out, and return it."
    pid_file = os.path.join(router.gearlogdir, "bfd_dplane_listener.pid")
    dump_file = os.path.join(router.gearlogdir, "bfd_dplane.data")

    try:
        with open(pid_file) as f:
            pid = f.read().strip()
    except FileNotFoundError:
        return ""

    router.run("kill -SIGUSR1 {}".format(pid))
    time.sleep(0.2)

    try:
        with open(dump_file) as f:
            return f.read()
    except FileNotFoundError:
        return ""


def _interfaces(router):
    "lid -> (ifindex, ifname) from the listener's dump."
    return {
        int(m.group(1)): (int(m.group(2)), m.group(3))
        for m in re.finditer(
            r"^  interface: lid (\d+) ifindex (\d+) ifname (\S+)$",
            _listener_dump(router),
            re.M,
        )
    }


def _lid(router, peer):
    for p in router.vtysh_cmd("show bfd peers json", isjson=True):
        if p["peer"] == peer:
            return p["id"]
    return None


def _ifindex(router, ifname):
    return int(router.run("ip -o link show {}".format(ifname)).split(":")[0])


def _expect_interface(router, peer, ifname, what):
    lid = _lid(router, peer)
    assert lid is not None, "no session for {}".format(peer)
    want = (_ifindex(router, ifname), ifname)

    def _got():
        return _interfaces(router).get(lid)

    _, result = topotest.run_and_expect(_got, want, count=20, wait=0.5)
    assert result == want, "{}: the data plane has {} for {}, not {}".format(
        what, result, peer, want
    )


def _update(router, peer, vrf, mult):
    "Change the session so that bfdd sends it to the data plane again."
    router.vtysh_cmd(
        "configure terminal\nbfd\npeer {} interface {}{}\ndetect-multiplier {}".format(
            peer,
            "dum1" if vrf else "dum0",
            " vrf cust1" if vrf else "",
            mult,
        )
    )


def test_sessions_reach_the_data_plane():
    "Both sessions arrive with the interface they run on."
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    router = tgen.gears["r1"]

    def _registered():
        return len(_interfaces(router))

    _, result = topotest.run_and_expect(_registered, 2, count=30, wait=1)
    assert result == 2, "the data plane received {} of 2 sessions".format(result)

    _expect_interface(router, PEER_DEFAULT, "dum0", "at start")
    _expect_interface(router, PEER_VRF, "dum1", "at start")


def test_interface_created_again():
    "A session gets the new interface, and keeps it in later updates."
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    router = tgen.gears["r1"]
    old = _ifindex(router, "dum0")
    router.run("ip link del dum0")
    time.sleep(2)
    _add_dum0(router)
    assert _ifindex(router, "dum0") != old, "dum0 came back with its old ifindex"

    _expect_interface(router, PEER_DEFAULT, "dum0", "interface created again")
    _update(router, PEER_DEFAULT, False, 4)
    time.sleep(2)
    _expect_interface(router, PEER_DEFAULT, "dum0", "update after that")


def test_vrf_created_again():
    "A session in a VRF that comes back keeps its interface in later updates."
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    router = tgen.gears["r1"]
    router.run("ip link del cust1")
    time.sleep(2)
    _add_cust1(router)

    _expect_interface(router, PEER_VRF, "dum1", "VRF created again")
    _update(router, PEER_VRF, True, 4)
    time.sleep(2)
    _expect_interface(router, PEER_VRF, "dum1", "update after that")


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
