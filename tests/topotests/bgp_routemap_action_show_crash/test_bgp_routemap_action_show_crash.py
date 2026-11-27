#!/usr/bin/env python
# SPDX-License-Identifier: GPL-2.0-or-later
"""
route_map_action_show() reads "extcommunity-color" without checking it
exists. The leaf isn't mandatory, so "set extcommunity color bogus" (fails
the color-list pattern) leaves the set-action entry committed without its
value, and the next display/save aborts bgpd.
"""

import os
import sys

import pytest

CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

from lib.topogen import Topogen, get_topogen

RMAP = "RM_CRASH"


def build_topo(tgen):
    tgen.add_router("r1")


def setup_module(mod):
    tgen = Topogen(build_topo, mod.__name__)
    tgen.start_topology()
    for rname, router in tgen.routers().items():
        router.load_frr_config(os.path.join(CWD, "{}/frr.conf".format(rname)))
    tgen.start_router()


def teardown_module(mod):
    get_topogen().stop_topology()


def test_routemap_action_show_dangling_leaf_no_crash():
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]

    # "bogus" fails the color-list pattern: the set-action entry is
    # created, but the extcommunity-color leaf modify is rejected.
    out = r1.vtysh_multicmd(
        """
    configure terminal
    route-map {} permit 10
    set extcommunity color bogus
    """.format(
            RMAP
        )
    )
    assert "failed to edit configuration" in out.lower(), (
        "expected the extcommunity-color modify to be rejected: %s" % out
    )

    # still commits despite the rejected leaf: not mandatory in the YANG model
    assert "configuration failed" not in out.lower(), (
        "commit was rejected, dangling entry not created: %s" % out
    )

    # before the fix, this walk dereferences the missing leaf and aborts
    r1.vtysh_cmd("write memory")

    output = r1.net.checkRouterCores()
    assert not output.strip(), "bgpd crashed: {}".format(output)

    out = r1.vtysh_cmd("show version")
    assert "FRRouting" in out


if __name__ == "__main__":
    sys.exit(pytest.main([__file__]))
