#!/usr/bin/env python
# SPDX-License-Identifier: ISC

"""
Test that withdrawing the route behind 'default-information originate' (without
'always') withdraws the originated default and logs no error.

isis_redist_delete() hands a removed default back to isis_redist_add() as the
synthetic DEFAULT_ROUTE (ZEBRA_ROUTE_MAX) origin, whose debug message must not
look it up as a zebra route type.
"""

import functools
import json
import os
import sys

import pytest

CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

# pylint: disable=C0413
from lib import topotest
from lib.common_config import step
from lib.topogen import Topogen, get_topogen

pytestmark = [pytest.mark.isisd, pytest.mark.staticd]


def build_topo(tgen):
    """r1 originates a default into IS-IS for r2."""
    for router in ("r1", "r2"):
        tgen.add_router(router)

    switch = tgen.add_switch("s1")
    switch.add_link(tgen.gears["r1"])
    switch.add_link(tgen.gears["r2"])


def setup_module(mod):
    tgen = Topogen(build_topo, mod.__name__)
    tgen.start_topology()

    for router in tgen.routers().values():
        router.load_frr_config()

    tgen.start_router()


def teardown_module():
    get_topogen().stop_topology()


def _isis_default(router, present):
    routes = json.loads(router.vtysh_cmd("show ip route 0.0.0.0/0 json"))
    found = any(
        route.get("protocol") == "isis" and route.get("selected", False)
        for route in routes.get("0.0.0.0/0", [])
    )
    if found == present:
        return None
    return "IS-IS default {}: {}".format(
        "missing" if present else "still present", routes
    )


def test_default_originated():
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    step("r2 learns the default r1 originates from its static default")
    test_func = functools.partial(_isis_default, tgen.gears["r2"], True)
    _, result = topotest.run_and_expect(test_func, None, count=60, wait=1)
    assert result is None, result


def test_default_withdrawn_without_error():
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]

    step("Remove r1's static default: r2 loses the IS-IS default")
    r1.vtysh_cmd("configure terminal\nno ip route 0.0.0.0/0 blackhole")
    test_func = functools.partial(_isis_default, tgen.gears["r2"], False)
    _, result = topotest.run_and_expect(test_func, None, count=60, wait=1)
    assert result is None, result

    step("r1's isisd logged no unknown zebra route type")
    with open(os.path.join(tgen.logdir, "r1", "isisd.log")) as f:
        errors = [line for line in f if "unknown zebra route type" in line]
    assert not errors, "isisd logged: {}".format(errors)


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
