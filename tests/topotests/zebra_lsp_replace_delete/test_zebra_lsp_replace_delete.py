#!/usr/bin/env python
# SPDX-License-Identifier: ISC
#
# test_zebra_lsp_replace_delete.py
#
# Copyright (c) 2026 by Andrei-Alexandru Bleortu
#

"""
An LSP that a client replaces and then deletes, in two messages that zebra
reads together, is removed from zebra and from the kernel.

A replace removes every NHLFE of the client's type and adds those of the
message back. The re-add is queued in the meta-queue; if the removal is not,
a delete that follows the replace is applied before the re-add, which then
installs the LSP again. isisd does this when a prefix loses its SID right
after a route update.
"""

import os
import sys
import json
from functools import partial
import pytest

CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

# pylint: disable=C0413
from lib import topotest
from lib.common_config import step
from lib.topogen import Topogen, get_topogen

pytestmark = [pytest.mark.sharpd]

LABEL = 777


def build_topo(tgen):
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
            os.path.join(CWD, "{}/frr.conf".format(rname)), extra_daemons=["sharpd"]
        )

    tgen.start_router()


def teardown_module(_mod):
    tgen = get_topogen()
    tgen.stop_topology()


def _check_lsp(router, present):
    "The LSP is in zebra and in the kernel, or in neither."
    table = json.loads(router.vtysh_cmd("show mpls table json"))
    kernel = router.cmd("ip -f mpls route show {}".format(LABEL)).strip()
    if (str(LABEL) in table) != present or bool(kernel) != present:
        return "label {}: zebra {}, kernel {!r}".format(LABEL, list(table), kernel)
    return None


def _install(router):
    "Install the LSP, once sharpd has the nexthop of its nexthop-group."
    output = router.vtysh_cmd("sharp lsp {} nexthop-group A".format(LABEL))
    if output.strip():
        return output.strip()
    return _check_lsp(router, True)


def _expect(func, *args):
    test_func = partial(func, *args)
    _, result = topotest.run_and_expect(test_func, None, count=20, wait=0.5)
    assert result is None, result


def test_lsp_replace_then_delete():
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)
    if not tgen.hasmpls:
        pytest.skip("MPLS is not available")
    r1 = tgen.gears["r1"]

    step("sharpd installs the LSP")
    _expect(_install, r1)

    for attempt in range(5):
        step("A replace and a delete in one burst remove it ({})".format(attempt))
        r1.vtysh_cmd("""
            sharp lsp update {0} nexthop-group A
            sharp remove lsp {0}
            """.format(LABEL))
        _expect(_check_lsp, r1, False)
        _expect(_install, r1)


def test_memory_leak():
    "Run the memory leak test and report results."
    tgen = get_topogen()
    if not tgen.is_memleak_enabled():
        pytest.skip("Memory leak test/report is disabled")

    tgen.report_memory_leaks()


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
