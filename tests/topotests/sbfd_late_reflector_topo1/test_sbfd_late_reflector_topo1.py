#!/usr/bin/env python
# SPDX-License-Identifier: ISC
#
# test_sbfd_late_reflector_topo1.py
#
# Copyright (c) 2026 by Abdul Wasey
#

"""
Test that an S-BFD initiator keeps its remote discriminator while no
reflector answers.

RFC 7880 Section 7.3.2: an SBFDInitiator sends the configured S-BFD
discriminator of the remote entity as Your Discriminator. It is
configuration, not learned from the reflector, so a Detection Time
without an answer must not clear it.

r1 runs an initiator towards r2 from the start. r2 configures its
reflector only after r1's Detection Time has passed, and again after r1
restarts the session with "shutdown" and "no shutdown" while no
reflector answers.
"""

import os
import sys
import time

import pytest

CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

# pylint: disable=C0413
from lib import topotest
from lib.topogen import Topogen, TopoRouter, get_topogen

pytestmark = [pytest.mark.bfdd]

REMOTE_DISCR = 456
REFLECTOR = "sbfd reflector source-address 2001::20 discriminator {}".format(
    REMOTE_DISCR
)
PEER = (
    "peer 2001::20 bfd-mode sbfd-init bfd-name r2 multihop "
    "local-address 2001::10 remote-discr {}".format(REMOTE_DISCR)
)
# Longer than the initiator's Detection Time: 900 ms at its default interval,
# 3 s at the slow interval it falls back to once Down.
NO_ANSWER = 5


def build_topo(tgen):
    "Build function"
    tgen.add_router("r1")
    tgen.add_router("r2")
    switch = tgen.add_switch("s1")
    switch.add_link(tgen.gears["r1"])
    switch.add_link(tgen.gears["r2"])


def setup_module(mod):
    tgen = Topogen(build_topo, mod.__name__)
    tgen.start_topology()

    for rname, router in tgen.routers().items():
        router.load_frr_config(
            os.path.join(CWD, "{}/frr.conf".format(rname)),
            [(TopoRouter.RD_ZEBRA, None), (TopoRouter.RD_BFD, None)],
        )

    tgen.start_router()


def teardown_module(_mod):
    tgen = get_topogen()
    tgen.stop_topology()


def _initiator(router):
    "The initiator's state and remote discriminator."
    for peer in router.vtysh_cmd("show bfd peers json", isjson=True):
        if peer.get("peer") == "2001::20":
            return peer["status"], peer["remote-id"]
    return None


def _reflector(router, enable):
    cmd = REFLECTOR if enable else "no sbfd reflector"
    router.vtysh_cmd("configure terminal\nbfd\n{}".format(cmd))


def _expect(router, status):
    want = (status, REMOTE_DISCR)
    _, result = topotest.run_and_expect(
        lambda: _initiator(router), want, count=20, wait=0.5
    )
    assert result == want, "initiator is {}, expected {}".format(result, want)


def test_reflector_after_detection_time():
    "A reflector configured late still brings the initiator up."
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1, r2 = tgen.gears["r1"], tgen.gears["r2"]
    time.sleep(NO_ANSWER)
    _expect(r1, "down")
    _reflector(r2, True)
    _expect(r1, "up")


def test_no_shutdown_without_reflector():
    "Restarting the session through shutdown keeps the discriminator."
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1, r2 = tgen.gears["r1"], tgen.gears["r2"]
    _reflector(r2, False)
    _expect(r1, "down")
    r1.vtysh_cmd("configure terminal\nbfd\n{}\nshutdown".format(PEER))
    r1.vtysh_cmd("configure terminal\nbfd\n{}\nno shutdown".format(PEER))
    time.sleep(NO_ANSWER)
    _expect(r1, "down")
    _reflector(r2, True)
    _expect(r1, "up")


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
