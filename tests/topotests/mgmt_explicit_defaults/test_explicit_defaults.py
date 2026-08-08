# -*- coding: utf-8 eval: (blacken-mode 1) -*-
# SPDX-License-Identifier: ISC
#
# Copyright (C) 2026 Robin Christ for partimus GmbH
#

"""
Test RFC 7950 default-leaf strictness in the northbound/mgmtd stack.

A leaf explicitly set to its schema default value is configuration in its
own right (RFC 7950 7.6.1): it must survive the commit (not collapse into
"no changes"), be stored explicitly in the running datastore, and be
emitted by "show running-config" and saved configurations. A leaf whose
default merely applies implicitly must NOT be emitted (except in the
with-defaults view).

Exercised with ripd, whose frr-ripd model carries plain YANG defaults
(default-metric 1, timers basic 30/180/120).
"""

import json
import os

import pytest
from lib.topogen import Topogen

pytestmark = [pytest.mark.mgmtd, pytest.mark.ripd]

CWD = os.path.dirname(os.path.realpath(__file__))


@pytest.fixture(scope="module")
def tgen(request):
    "Setup/Teardown the environment and provide tgen argument to tests"

    topodef = {"s1": ("r1",)}

    tgen = Topogen(topodef, request.module.__name__)
    tgen.start_topology()

    router_list = tgen.routers()
    for router in router_list.values():
        router.load_frr_config()

    tgen.start_router()
    yield tgen
    tgen.stop_topology()


def _rip_block(r1, args=""):
    out = r1.vtysh_cmd("show running-config %s" % args)
    lines = out.splitlines()
    try:
        start = next(i for i, l in enumerate(lines) if l.startswith("router rip"))
    except StopIteration:
        return []
    block = []
    for line in lines[start:]:
        block.append(line)
        if line.strip() in ("exit", "!") and len(block) > 1:
            break
    return block


def test_explicit_defaults_survive_load(tgen):
    "Explicitly configured default values must appear in show running-config."
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)
    r1 = tgen.gears["r1"]

    block = _rip_block(r1)
    assert " default-metric 1" in block, "explicit default-metric 1 lost: %s" % block
    assert " timers basic 30 180 120" in block, (
        "explicit timers basic 30 180 120 lost: %s" % block
    )


def test_implicit_default_not_emitted(tgen):
    "Removing the config line must return the leaf to (non-emitted) default."
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)
    r1 = tgen.gears["r1"]

    r1.vtysh_cmd("conf t\nrouter rip\nno default-metric\n")
    block = _rip_block(r1)
    assert not any("default-metric" in l for l in block), (
        "implicit default-metric emitted: %s" % block
    )


def test_explicit_set_to_default_commits(tgen):
    """Setting a leaf to its default value on a running system is a real
    commit (previously collapsed into 'no changes') and must re-appear."""
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)
    r1 = tgen.gears["r1"]

    r1.vtysh_cmd("conf t\nrouter rip\ndefault-metric 1\n")
    block = _rip_block(r1)
    assert " default-metric 1" in block, (
        "explicit set-to-default did not commit/emit: %s" % block
    )


def test_with_defaults_view(tgen):
    """The as-configured view must contain only explicitly configured leaves;
    the with-defaults (effective) view materializes the implicit defaults."""
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)
    r1 = tgen.gears["r1"]

    r1.vtysh_cmd("conf t\nrouter rip\nno timers basic\n")
    block = _rip_block(r1)
    assert not any("timers basic" in l for l in block), (
        "implicit timers emitted in plain view: %s" % block
    )

    cmd = "show mgmt get-data /frr-ripd:ripd datastore running only-config %sjson"
    plain = json.loads(r1.vtysh_cmd(cmd % ""))
    effective = json.loads(r1.vtysh_cmd(cmd % "with-defaults all "))

    plain_inst = plain["frr-ripd:ripd"]["instance"][0]
    effective_inst = effective["frr-ripd:ripd"]["instance"][0]

    assert "timers" not in plain_inst, (
        "implicit timers in as-configured data: %s" % plain_inst
    )
    assert plain_inst.get("default-metric") == 1, (
        "explicit default-metric missing from as-configured data: %s" % plain_inst
    )
    assert effective_inst.get("timers", {}).get("update-interval") == 30, (
        "implicit timers missing from effective data: %s" % effective_inst
    )

    # The CLI rendering of both views, from mgmtd (which owns the
    # datastore); vtysh's grammar requires the trailing daemon name.
    plain_cli = r1.vtysh_cmd("show configuration running mgmtd")
    effective_cli = r1.vtysh_cmd("show configuration running with-defaults mgmtd")
    assert " default-metric 1" in plain_cli.splitlines(), (
        "explicit default-metric missing from plain CLI view"
    )
    assert not any(
        "timers basic" in l for l in plain_cli.splitlines()
    ), "implicit timers in plain CLI view"
    assert " timers basic 30 180 120" in effective_cli.splitlines(), (
        "implicit timers missing from with-defaults CLI view"
    )


def test_explicit_default_round_trips_restart(tgen):
    "An explicitly configured default survives write memory and a restart."
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)
    r1 = tgen.gears["r1"]

    r1.vtysh_cmd("conf t\nrouter rip\ndefault-metric 1\n")
    r1.vtysh_cmd("write memory")

    saved = r1.cmd("cat /etc/frr/frr.conf")
    assert " default-metric 1" in saved.splitlines(), (
        "explicit default-metric missing from saved config:\n%s" % saved
    )
    assert not any(
        l.strip().startswith("timers basic") for l in saved.splitlines()
    ), "implicit timers leaked into saved config:\n%s" % saved


if __name__ == "__main__":
    args = ["-s"] + [__file__]
    ret = pytest.main(args)
    exit(ret)
