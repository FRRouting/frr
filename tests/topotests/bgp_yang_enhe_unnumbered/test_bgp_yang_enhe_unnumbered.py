#!/usr/bin/env python
# SPDX-License-Identifier: ISC

#
# test_bgp_yang_enhe_unnumbered.py
#
# Copyright (c) 2026 by Nvidia Corporation
# Donald Sharp
#

"""
An unnumbered neighbor cannot turn extended-nexthop off.
"""

import os
import sys
import subprocess
import pytest

CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

# pylint: disable=C0413
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


def test_unnumbered_extended_nexthop_stays_on():
    "no capability extended-nexthop is rejected on an interface neighbor"
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]
    with pytest.raises(subprocess.CalledProcessError) as err:
        r1.vtysh_multicmd(
            """
router bgp 65000
 no neighbor eth0 capability extended-nexthop
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
    assert "cannot have capability extended-nexthop turned off" in output + stderr

    running = r1.vtysh_cmd("show running-config")
    assert "no neighbor eth0 capability extended-nexthop" not in running
    assert "neighbor eth0 interface" in running


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
