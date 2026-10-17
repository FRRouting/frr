#!/usr/bin/env python
# SPDX-License-Identifier: ISC

"""
Test that "show isis neighbor json" lists every neighbor of a LAN.

    r1 --+-- r2
         |
         r3

Each router has two neighbors on its only circuit, at both levels.
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
from lib.topogen import Topogen, get_topogen

pytestmark = [pytest.mark.isisd]

ROUTERS = ("r1", "r2", "r3")


def build_topo(tgen):
    switch = tgen.add_switch("s1")
    for router in ROUTERS:
        switch.add_link(tgen.add_router(router))


def setup_module(mod):
    tgen = Topogen(build_topo, mod.__name__)
    tgen.start_topology()

    for router in tgen.routers().values():
        router.load_frr_config()

    tgen.start_router()


def teardown_module():
    get_topogen().stop_topology()


def _neighbors(router, command):
    """{(neighbor, level)} of the adjacencies that are Up, from the JSON"""
    output = json.loads(router.vtysh_cmd(command + " json"))
    rv = set()
    for area in output["areas"]:
        for circuit in area["circuits"]:
            if "adj" not in circuit:
                continue
            # the detail output nests the state under the interface
            if isinstance(circuit["interface"], dict):
                state = circuit["interface"]["state"]
            else:
                state = circuit["state"]
            if state == "Up":
                rv.add((circuit["adj"], circuit["level"]))
    return rv


def _check(router, command, expected):
    got = _neighbors(router, command)
    if got != expected:
        return "{} '{}': {}, expected {}".format(router.name, command, got, expected)
    return None


def test_lan_neighbors():
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    for name in ROUTERS:
        others = {other for other in ROUTERS if other != name}
        expected = {(other, level) for other in others for level in (1, 2)}
        for command in ("show isis neighbor", "show isis neighbor detail"):
            test_func = functools.partial(_check, tgen.gears[name], command, expected)
            _, result = topotest.run_and_expect(test_func, None, count=60, wait=1)
            assert result is None, result


def test_lan_neighbor_by_name():
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]
    expected = {("r3", 1), ("r3", 2)}
    test_func = functools.partial(_check, r1, "show isis neighbor r3", expected)
    _, result = topotest.run_and_expect(test_func, None, count=30, wait=1)
    assert result is None, result


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
