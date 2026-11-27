#!/usr/bin/env python
# SPDX-License-Identifier: ISC

#
# test_bgp_yang_shutdown_msg.py
#
# Copyright (c) 2026 by Nvidia Corporation
# Donald Sharp
#

"""
A shutdown message must be on the cease notification. The message leaf
is applied after enable, so enable has to read it from the candidate.
"""

import json
import os
import sys
import pytest

CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

# pylint: disable=C0413
from lib import topotest
from lib.topogen import Topogen, get_topogen

pytestmark = [pytest.mark.bgpd]


def build_topo(tgen):
    for name in ("r1", "r2"):
        tgen.add_router(name)

    switch = tgen.add_switch("s1")
    switch.add_link(tgen.gears["r1"])
    switch.add_link(tgen.gears["r2"])


def setup_module(mod):
    tgen = Topogen(build_topo, mod.__name__)
    tgen.start_topology()

    for router in tgen.routers().values():
        router.load_frr_config()

    tgen.start_router()


def teardown_module(mod):
    tgen = get_topogen()
    tgen.stop_topology()


def _established(router, peer):
    out = router.vtysh_cmd("show bgp neighbors %s" % peer)
    return "BGP state = Established" in out


def _shutdown_description(router, peer):
    raw = router.vtysh_cmd("show bgp neighbors %s json" % peer)
    try:
        data = json.loads(raw)
    except json.JSONDecodeError:
        return ""
    if peer in data and isinstance(data[peer], dict):
        data = data[peer]
    return data.get("lastShutdownDescription", "")


def test_shutdown_message_is_in_the_notification():
    "Established peer receives the shutdown message"
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]
    r2 = tgen.gears["r2"]

    ok, result = topotest.run_and_expect(
        lambda: _established(r1, "192.0.2.2"), True, count=20, wait=1
    )
    assert ok, result

    r1.vtysh_multicmd(
        """
router bgp 65001
 neighbor 192.0.2.2 shutdown message maintenance
""",
        pretty_output=False,
        raises=True,
    )

    ok, result = topotest.run_and_expect(
        lambda: _shutdown_description(r2, "192.0.2.1"), "maintenance", count=20, wait=1
    )
    assert ok, result


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
