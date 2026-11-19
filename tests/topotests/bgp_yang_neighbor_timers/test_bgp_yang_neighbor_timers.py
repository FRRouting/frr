#!/usr/bin/env python
# SPDX-License-Identifier: ISC

#
# test_bgp_yang_neighbor_timers.py
#
# Copyright (c) 2026 by Nvidia Corporation
# Donald Sharp
#

"""
"no neighbor X timers" must drop the per-neighbor override so the peer
follows "timers bgp", including across a bgpd restart.
"""

import os
import sys
import subprocess
import pytest

CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

# pylint: disable=C0413
from lib import topotest
from lib.common_config import kill_router_daemons, start_router_daemons
from lib.topogen import Topogen, get_topogen

pytestmark = [pytest.mark.bgpd]


def build_topo(tgen):
    tgen.add_router("r1")


def setup_module(mod):
    tgen = Topogen(build_topo, mod.__name__)
    tgen.start_topology()

    for router in tgen.routers().values():
        router.load_frr_config()

    tgen.start_router()


def teardown_module(mod):
    tgen = get_topogen()
    tgen.stop_topology()


def _configured_follows_bgp(router):
    detail = router.vtysh_cmd("show bgp neighbors 192.0.2.2")
    assert "Configured hold time is 30 seconds, keepalive interval is 10 seconds" in detail


def test_no_neighbor_timers_follows_bgp_timers():
    "Clearing neighbor timers inherits timers bgp, including after restart"
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]
    r1.vtysh_multicmd(
        """
router bgp 65000
 timers bgp 10 30
 neighbor 192.0.2.2 timers 20 60
""",
        pretty_output=False,
        raises=True,
    )

    running = r1.vtysh_cmd("show running-config")
    assert "timers bgp 10 30" in running
    assert "neighbor 192.0.2.2 timers 20 60" in running
    detail = r1.vtysh_cmd("show bgp neighbors 192.0.2.2")
    assert "Configured hold time is 60 seconds, keepalive interval is 20 seconds" in detail

    r1.vtysh_multicmd(
        """
router bgp 65000
 no neighbor 192.0.2.2 timers
""",
        pretty_output=False,
        raises=True,
    )

    running = r1.vtysh_cmd("show running-config")
    assert "timers bgp 10 30" in running
    assert "neighbor 192.0.2.2 timers" not in running
    _configured_follows_bgp(r1)

    # The restart reloads frr.conf, so save what was configured above.
    r1.vtysh_cmd("write memory")

    kill_router_daemons(tgen, "r1", ["bgpd"])
    start_router_daemons(tgen, "r1", ["bgpd"])

    def _restored():
        running = r1.vtysh_cmd("show running-config")
        if "timers bgp 10 30" not in running:
            return "timers bgp 10 30 missing after restart"
        if "neighbor 192.0.2.2 timers" in running:
            return "neighbor timers override came back after restart"
        return None

    ok, result = topotest.run_and_expect(_restored, None, count=30, wait=1)
    assert ok, result

    def _follows_bgp():
        try:
            _configured_follows_bgp(r1)
        except AssertionError as err:
            return str(err)
        return None

    ok, result = topotest.run_and_expect(_follows_bgp, None, count=30, wait=1)
    assert ok, result


def test_hold_time_one_is_rejected():
    "Hold time 1 or 2 is rejected with the classic message"
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]
    with pytest.raises(subprocess.CalledProcessError) as err:
        r1.vtysh_multicmd(
            """
router bgp 65000
 neighbor 192.0.2.2 timers 10 1
""",
            pretty_output=False,
            raises=True,
        )

    output = getattr(err.value, "output", b"") or b""
    if isinstance(output, bytes):
        output = output.decode(errors="replace")
    stderr = getattr(err.value, "stderr", b"") or b""
    if isinstance(stderr, bytes):
        stderr = stderr.decode(errors="replace")
    text = output + stderr
    assert "hold time value must be either 0 or at least 3" in text

    running = r1.vtysh_cmd("show running-config")
    assert "neighbor 192.0.2.2 timers 10 1" not in running


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
