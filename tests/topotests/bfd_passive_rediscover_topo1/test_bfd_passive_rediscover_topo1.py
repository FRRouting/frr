#!/usr/bin/env python
# SPDX-License-Identifier: ISC
#
# test_bfd_passive_rediscover_topo1.py
#
# Copyright (c) 2026 by Abdul Wasey
#

"""
test_bfd_passive_rediscover_topo1.py: a passive session must come back up
after its peer kept a stale discriminator.

r1 is passive, r2 active. r1 goes AdminDown and keeps saying so for a few
packets, as RFC 5880 Section 6.8.16 recommends, then deletes the session and
creates it again, which gives it a new discriminator. r2 took the old one
from those AdminDown packets while it was already Down.

RFC 5880 Section 6.8.1 zeroes bfd.RemoteDiscr once a Detection Time passes
without a valid packet. Until it is zero, r2 keeps sending the old value, r1
discards every packet as naming no session, and being passive r1 never
speaks first, so neither side recovers.
"""

import os
import sys
from functools import partial

import pytest

CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

# pylint: disable=C0413
from lib import topotest
from lib.topogen import Topogen, get_topogen

pytestmark = [pytest.mark.bfdd]

R1_ADDR = "192.168.1.1"
R2_ADDR = "192.168.1.2"
R1_PEER = "peer {} local-address {} interface r1-eth0".format(R2_ADDR, R1_ADDR)


def build_topo(tgen):
    "Two routers on a single link."
    for routern in range(1, 3):
        tgen.add_router("r{}".format(routern))

    switch = tgen.add_switch("s1")
    switch.add_link(tgen.gears["r1"])
    switch.add_link(tgen.gears["r2"])


def setup_module(mod):
    tgen = Topogen(build_topo, mod.__name__)
    tgen.start_topology()

    for rname, router in tgen.routers().items():
        router.load_frr_config(os.path.join(CWD, "{}/frr.conf".format(rname)))

    tgen.start_router()


def teardown_module(_mod):
    tgen = get_topogen()
    tgen.stop_topology()


def _peer(router, peer):
    for entry in router.vtysh_cmd("show bfd peers json", isjson=True):
        if entry.get("peer") == peer:
            return entry
    return None


def _check_up(router, peer, remote_id=None):
    entry = _peer(router, peer)
    if entry is None:
        return "peer {} not found on {}".format(peer, router.name)
    expected = {"status": "up"}
    if remote_id is not None:
        expected["remote-id"] = remote_id
    return topotest.json_cmp(entry, expected)


def _expect_up(router, peer, count=30, remote_id=None):
    test_func = partial(_check_up, router, peer, remote_id)
    _, result = topotest.run_and_expect(test_func, None, count=count, wait=1)
    assert result is None, "{} peer {} is not up: {}".format(router.name, peer, result)


def test_bfd_up():
    "The passive session comes up."
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    _expect_up(tgen.gears["r1"], R2_ADDR)
    _expect_up(tgen.gears["r2"], R1_ADDR)


def test_passive_rediscover():
    "After AdminDown and a new discriminator, the passive session recovers."
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]
    r2 = tgen.gears["r2"]
    old_id = _peer(r1, R2_ADDR)["id"]
    r2_id = _peer(r2, R1_ADDR)["id"]

    r1.vtysh_cmd("configure terminal\nbfd\n{}\nshutdown\nend".format(R1_PEER))

    # bfdd sends one AdminDown; send the rest a Detection Time would carry.
    r1.cmd(
        "python3 {} {} {} {} {} 2".format(
            os.path.join(CWD, "admindown.py"), R1_ADDR, R2_ADDR, old_id, r2_id
        )
    )

    # A new session, so a new discriminator.
    r1.vtysh_cmd("configure terminal\nbfd\nno {}\nend".format(R1_PEER))
    r1.vtysh_cmd("configure terminal\nbfd\n{}\npassive-mode\nend".format(R1_PEER))
    new_id = _peer(r1, R2_ADDR)["id"]
    assert new_id != old_id, "the recreated session kept its discriminator"

    _expect_up(r1, R2_ADDR)
    _expect_up(r2, R1_ADDR, remote_id=new_id)


def test_memory_leak():
    "Run the memory leak test and report results."
    tgen = get_topogen()
    if not tgen.is_memleak_enabled():
        pytest.skip("Memory leak test/report is disabled")
    tgen.report_memory_leaks()


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
