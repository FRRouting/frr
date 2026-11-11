#!/usr/bin/env python
# SPDX-License-Identifier: ISC

# Copyright (c) 2026 by
# Donatas Abraitis <donatas@opensourcerouting.org>
#

"""
Malformed extended community values must be rejected before they are
committed.

For route-map `set extcommunity rt|soo|nt|color` and for
`bgp extcommunity-list standard`, submit malformed values and check that:

- the command fails (non-zero vtysh exit status and an error message),
- the running configuration is unchanged,
- an existing rule of the same kind is not replaced, and no rule is
  added to an entry that had none (checked against the installed
  route-map rules, not just the configuration text).
"""

import difflib
import functools
import json
import os
import shlex
import sys

import pytest

CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

# pylint: disable=C0413
from lib import topotest
from lib.topogen import Topogen, get_topogen

pytestmark = [pytest.mark.bgpd]

# Installed rules for route-map rmap from r1/frr.conf (sorted, as
# _set_clauses() returns them).
EXPECTED_SET_CLAUSES = {
    10: [
        "extcommunity color 01:100",
        "extcommunity nt 192.168.1.1:0",
        "extcommunity rt 65001:1",
        "extcommunity soo 65001:2",
    ],
    20: [],
}

# The rt, soo and nt values are plain strings in the YANG model, so only
# the northbound validation callback can reject them. The color value
# matches the YANG color-list pattern (it is read as "01:100" followed by
# "01:5"), so it also gets as far as the validation callback.
MALFORMED_SET_VALUES = [
    ("rt", "1.2.3"),
    ("rt", "100"),
    ("rt", "65001:192.168.1.1"),
    ("soo", "1.2.3"),
    ("soo", "100"),
    ("nt", "65001:100"),
    ("nt", "65001:192.168.1.1"),
    ("nt", "1.2:3"),
    ("nt", "4200000000:1"),
    ("nt", "192.168.1.1:5"),
    ("nt", "192.168.1.1"),
    ("color", "01:10001:5"),
]

MALFORMED_EXTCOMMUNITY_LIST_VALUES = [
    "nt 65001:100",
    "nt 65001:192.168.1.1",
    "nt 1.2:3",
    "nt 192.168.1.1:5",
    "nt 192.168.1.1",
    "rt 100",
    "soo 1.2.3",
]


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


def _vtysh_config(router, *commands):
    """
    Run configuration commands and return (exit status, stdout + stderr).

    TopoRouter.vtysh_cmd() drops both stderr and the exit status, which are
    exactly what is checked here, so call vtysh directly.
    """
    cmd = "vtysh -c 'configure terminal'"
    for command in commands:
        cmd += " -c {}".format(shlex.quote(command))

    rc, stdout, stderr = router.net.cmd_status(cmd, warn=False)

    return rc, stdout + stderr


def _running_config(router):
    return router.vtysh_cmd("show running-config")


def _set_clauses(router):
    output = router.vtysh_cmd("show route-map rmap json", daemon="bgpd")
    try:
        rules = json.loads(output)["bgpd"]["rmap"]["rules"]
    except (ValueError, KeyError):
        return {"unexpected output": output}

    return {rule["sequenceNumber"]: sorted(rule["setClauses"]) for rule in rules}


def _check_unchanged(router, baseline_config, what):
    config = _running_config(router)
    if config != baseline_config:
        diff = "\n".join(
            difflib.unified_diff(
                baseline_config.splitlines(),
                config.splitlines(),
                "before",
                "after",
                lineterm="",
            )
        )
        pytest.fail("{} changed the running configuration:\n{}".format(what, diff))

    set_clauses = _set_clauses(router)
    assert (
        set_clauses == EXPECTED_SET_CLAUSES
    ), "{} changed the installed route-map rules: {}".format(what, set_clauses)


def test_bgp_extcommunity_initial_config():
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]

    def _check_loaded():
        set_clauses = _set_clauses(r1)
        if set_clauses != EXPECTED_SET_CLAUSES:
            return "route-map rules not installed yet: {}".format(set_clauses)

        config = _running_config(r1)
        if (
            "bgp extcommunity-list standard nt-list seq 5 permit nt 192.168.1.1:0"
            not in config
        ):
            return "extcommunity-list not configured yet"

        return None

    test_func = functools.partial(_check_loaded)
    _, result = topotest.run_and_expect(test_func, None, count=30, wait=1)
    assert result is None, "Initial configuration not loaded: {}".format(result)


@pytest.mark.parametrize("seq", [10, 20], ids=["existing-rule", "no-rule"])
@pytest.mark.parametrize(
    "kind,value",
    MALFORMED_SET_VALUES,
    ids=["{}-{}".format(k, v) for k, v in MALFORMED_SET_VALUES],
)
def test_bgp_route_map_set_extcommunity_malformed(kind, value, seq):
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]
    baseline = _running_config(r1)
    what = "'set extcommunity {} {}' in route-map rmap permit {}".format(
        kind, value, seq
    )

    rc, output = _vtysh_config(
        r1,
        "route-map rmap permit {}".format(seq),
        "set extcommunity {} {}".format(kind, value),
    )

    assert rc != 0, "{} was accepted (exit status 0):\n{}".format(what, output)
    assert (
        "Malformed extcommunity {} value".format(kind) in output
    ), "{} was not rejected by validation:\n{}".format(what, output)

    _check_unchanged(r1, baseline, what)


@pytest.mark.parametrize("value", MALFORMED_EXTCOMMUNITY_LIST_VALUES)
def test_bgp_extcommunity_list_malformed(value):
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]
    baseline = _running_config(r1)
    what = "'bgp extcommunity-list standard nt-list permit {}'".format(value)

    rc, output = _vtysh_config(
        r1, "bgp extcommunity-list standard nt-list permit {}".format(value)
    )

    assert rc != 0, "{} was accepted (exit status 0):\n{}".format(what, output)
    assert (
        "Malformed community-list value" in output
    ), "{} was not rejected:\n{}".format(what, output)

    _check_unchanged(r1, baseline, what)


def test_bgp_extcommunity_valid_config_still_accepted():
    """
    Make sure the validation does not reject the well-formed values, which
    would make every negative test above pass trivially.
    """
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]

    rc, output = _vtysh_config(
        r1,
        "route-map rmap permit 20",
        "set extcommunity rt 192.168.1.1:100",
        "set extcommunity soo 65001:200",
        "set extcommunity nt 10.0.0.1:0 10.0.0.2:0",
        "set extcommunity color 00:300",
        "exit",
        "bgp extcommunity-list standard nt-list seq 10 permit nt 10.0.0.1:0",
    )
    assert rc == 0, "Valid configuration was rejected:\n{}".format(output)

    assert _set_clauses(r1)[20] == [
        "extcommunity color 00:300",
        "extcommunity nt 10.0.0.1:0 10.0.0.2:0",
        "extcommunity rt 192.168.1.1:100",
        "extcommunity soo 65001:200",
    ]
    assert (
        "bgp extcommunity-list standard nt-list seq 10 permit nt 10.0.0.1:0"
        in _running_config(r1)
    )


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
