# SPDX-License-Identifier: ISC
# -*- coding: utf-8 eval: (blacken-mode 1) -*-
#
# Copyright (c) 2026, Reinaldo Saraiva
#
"""
Test observability hook for route-map match list-name references.

The `list-name` leaf of a route-map match condition does not reject commits
with unresolved references -- partial configuration is a first-class FRR
workflow. Instead, mgmtd emits an informational log line so declarative
controllers (NETCONF/gNMI) can surface the drift without tailing runtime
DENY traces.

This test locks down four properties:

  - happy path (v4 condition + v4 prefix-list) commits without the warning;
  - same-batch create-and-reference (list and match defined in the same
    vtysh batch) commits without the warning, because NB_EV_VALIDATE runs
    over the merged candidate tree;
  - dangling reference (non-existent list) commits, running-config retains
    the match, and the warning appears in the log;
  - cross-family reference (v4 condition -> v6 list, or v6 -> v4) commits,
    running-config retains the match, and the warning appears in the log.
"""
import os
import re
import sys

import pytest

from lib.topogen import Topogen

pytestmark = [pytest.mark.staticd, pytest.mark.mgmtd]

WARN_PATTERN = re.compile(
    r"route-map match \S+ references (access|prefix)-list '\S+' \(type ipv[46]\) "
    r"that does not exist in candidate config"
)


@pytest.fixture(scope="module")
def tgen(request):
    topodef = {"s1": ("r1",)}
    tgen = Topogen(topodef, request.module.__name__)
    tgen.start_topology()
    tgen.gears["r1"].load_frr_config("frr.conf")
    tgen.start_router()
    yield tgen
    tgen.stop_topology()


def _vtysh_config(router, cmds):
    """Run a config sequence and assert mgmtd accepted it.

    The `"end"` token is silently stripped by `vtysh -f` (see
    `vtysh_config_from_file`); batched edits commit atomically at end-of-file
    via the `XFRR_start_configuration` / `XFRR_end_configuration` protocol, so
    `NB_EV_VALIDATE` sees the merged candidate tree regardless of how many
    statements appear in `cmds`.
    """
    output = router.vtysh_multicmd(
        "\n".join(["configure terminal", *cmds, "end"]),
        pretty_output=False,
    )
    # Child daemons (zebra/staticd) emit noise like
    # "% Unknown command[4]: configure terminal" and
    # "Configuration file[...] processing failure: 2" because mgmtd owns
    # config reception -- these are not commit failures. The real signal is
    # the mgmtd marker "% Configuration failed." or "commit failed session-id".
    for marker in ("% Configuration failed.", "commit failed session-id"):
        assert marker not in output, (
            f"mgmtd rejected the commit (marker={marker!r}):\n{output}"
        )
    return output


def _zebra_log(router):
    """Return current contents of the zebra log file.

    The route-map northbound callbacks run in the zebra backend (mgmtd
    delegates the frr-route-map module), so the observability log line
    lands in zebra.log rather than mgmtd.log.
    """
    logdir = router.logdir
    candidates = [
        os.path.join(logdir, router.name, "zebra.log"),
        os.path.join(logdir, "zebra.log"),
    ]
    for path in candidates:
        if os.path.exists(path):
            with open(path) as fh:
                return fh.read()
    raise AssertionError(f"zebra.log not found in {candidates}")


def _warn_count(router):
    return len(WARN_PATTERN.findall(_zebra_log(router)))


def _running_config(router):
    return router.vtysh_cmd("show running-config")


def test_matching_family_accepted_no_warning(tgen):
    """Happy path: v4 condition + v4 prefix-list commits, no warning."""
    r1 = tgen.gears["r1"]
    before = _warn_count(r1)
    _vtysh_config(
        r1,
        [
            "ip prefix-list pl-v4 seq 5 permit 10.0.0.0/8",
            "route-map rm-happy permit 10",
            " match ip address prefix-list pl-v4",
            " exit",
        ],
    )
    running = _running_config(r1)
    assert "match ip address prefix-list pl-v4" in running
    after = _warn_count(r1)
    assert after == before, (
        f"expected no new unresolved-ref warning; delta={after - before}"
    )


def test_cross_family_commits_with_warning(tgen):
    """v4 condition referencing v6 prefix-list: commits, warning in log."""
    r1 = tgen.gears["r1"]
    before = _warn_count(r1)
    _vtysh_config(r1, ["ipv6 prefix-list pl-v6-only seq 5 permit 2001:db8::/32"])
    _vtysh_config(
        r1,
        [
            "route-map rm-cross-v4 permit 10",
            " match ip address prefix-list pl-v6-only",
            " exit",
        ],
    )
    running = _running_config(r1)
    assert "match ip address prefix-list pl-v6-only" in running
    after = _warn_count(r1)
    assert after > before, (
        f"expected unresolved-ref warning; delta={after - before}, log tail:\n"
        f"{_zebra_log(r1)[-2000:]}"
    )


def test_same_transaction_create_and_reference_no_warning(tgen):
    """Same-batch create-and-reference: no warning (candidate tree has the list)."""
    r1 = tgen.gears["r1"]
    before = _warn_count(r1)
    _vtysh_config(
        r1,
        [
            "ip prefix-list pl-samebatch seq 5 permit 10.20.0.0/16",
            "route-map rm-samebatch permit 10",
            " match ip address prefix-list pl-samebatch",
            " exit",
        ],
    )
    running = _running_config(r1)
    assert "match ip address prefix-list pl-samebatch" in running
    after = _warn_count(r1)
    assert after == before, (
        f"expected no new unresolved-ref warning (list created in same batch); "
        f"delta={after - before}, log tail:\n{_zebra_log(r1)[-2000:]}"
    )


def test_dangling_reference_commits_with_warning(tgen):
    """Reference to non-existent list: commits, warning in log."""
    r1 = tgen.gears["r1"]
    before = _warn_count(r1)
    _vtysh_config(
        r1,
        [
            "route-map rm-dangling permit 10",
            " match ip address prefix-list pl-does-not-exist",
            " exit",
        ],
    )
    running = _running_config(r1)
    assert "match ip address prefix-list pl-does-not-exist" in running
    after = _warn_count(r1)
    assert after > before, (
        f"expected unresolved-ref warning; delta={after - before}, log tail:\n"
        f"{_zebra_log(r1)[-2000:]}"
    )


if __name__ == "__main__":
    sys.exit(pytest.main(sys.argv[1:] + [__file__]))
