#!/usr/bin/env python
# SPDX-License-Identifier: ISC
#
# test_bfd_dplane_late_connect_topo1.py
#
# Copyright (c) 2026 by Abdul Wasey
#

"""
Test that a data plane connecting after bfdd has its sessions running
in software is given each session's interface.

bfdd starts with a data plane address but nothing listening there, so
it runs its sessions itself. When the data plane listener starts, bfdd
moves them to it, and the single hop session has to arrive with the
interface it is configured on.
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
SINGLE_HOP = "10.0.1.100"
MULTIHOP = "10.0.9.100"


def build_topo(tgen):
    "Build function"
    tgen.add_router("r1")
    switch = tgen.add_switch("s1")
    switch.add_link(tgen.gears["r1"])


def setup_module(mod):
    tgen = Topogen(build_topo, mod.__name__)
    tgen.start_topology()

    router = tgen.gears["r1"]

    # No listener yet: bfdd retries the connection and meanwhile runs
    # the sessions in software.
    router.load_frr_config(
        daemons=[
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
    router = tgen.gears["r1"]
    pid_file = os.path.join(router.gearlogdir, "bfd_dplane_listener.pid")
    if os.path.exists(pid_file):
        with open(pid_file) as f:
            router.run("kill {}".format(f.read().strip()))
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


def _interfaces(dump):
    "lid -> (ifindex, ifname) from the listener's dump."
    return {
        int(m.group(1)): (int(m.group(2)), m.group(3))
        for m in re.finditer(
            r"^  interface: lid (\d+) ifindex (\d+) ifname (\S+)$", dump, re.M
        )
    }


def test_sessions_run_in_software_first():
    "With no data plane to connect to, bfdd holds the sessions itself."
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    router = tgen.gears["r1"]

    def _count():
        peers = router.vtysh_cmd("show bfd peers json", isjson=True)
        return len(peers) if peers else 0

    _, result = topotest.run_and_expect(_count, 2, count=30, wait=1)
    assert result == 2, "bfdd has {} of 2 sessions".format(result)


def test_late_data_plane_gets_the_interface():
    "The sessions reach the data plane with the interface they run on."
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    router = tgen.gears["r1"]
    dump_file = os.path.join(router.gearlogdir, "bfd_dplane.data")
    # The daemon keeps no inherited output open, or run() waits on it.
    router.run(
        "{} -d -p {} -z {} </dev/null >/dev/null 2>&1".format(
            os.path.join(router.net.daemondir, "bfd_dplane_listener"),
            DPLANE_PORT,
            dump_file,
        )
    )

    def _registered():
        return len(_interfaces(_listener_dump(router)))

    # bfdd retries its data plane connection every few seconds.
    _, result = topotest.run_and_expect(_registered, 2, count=30, wait=1)
    assert result == 2, "the data plane received {} of 2 sessions".format(result)

    ifaces = _interfaces(_listener_dump(router))
    lids = {
        p["peer"]: p["id"] for p in router.vtysh_cmd("show bfd peers json", isjson=True)
    }
    ifindex = int(router.run("ip -o link show r1-eth0").split(":")[0])

    assert ifaces[lids[SINGLE_HOP]] == (ifindex, "r1-eth0"), (
        "the single hop session arrived with ifindex {} ifname {}, "
        "not {} r1-eth0".format(*ifaces[lids[SINGLE_HOP]], ifindex)
    )
    # A multihop session is not tied to an interface.
    assert ifaces[lids[MULTIHOP]] == (0, "-"), ifaces[lids[MULTIHOP]]


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
