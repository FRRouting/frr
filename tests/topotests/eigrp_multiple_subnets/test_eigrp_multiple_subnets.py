#!/usr/bin/env python
# SPDX-License-Identifier: ISC

#
# test_eigrp_multiple_subnets.py
#
# Copyright (c) 2026 by
# Lee Clements
#

"""
test_eigrp_multiple_subnets.py: EIGRP on an interface carrying several
connected subnets.

r1 and r2 share one segment and both run EIGRP on 10.0.1.0/24 and
10.0.2.0/24.  r1 additionally holds a second address inside 10.0.1.0/24,
which must not produce a second advertisement of that prefix.
"""

import os
import re
import sys
import functools
import pytest

pytestmark = [pytest.mark.eigrpd]

CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

# pylint: disable=C0413
from lib import topotest
from lib.topogen import Topogen, get_topogen


def build_topo(tgen):
    for name in ("r1", "r2"):
        tgen.add_router(name)

    switch = tgen.add_switch("s1")
    switch.add_link(tgen.gears["r1"])
    switch.add_link(tgen.gears["r2"])


def setup_module(module):
    tgen = Topogen(build_topo, module.__name__)
    tgen.start_topology()

    for router in tgen.routers().values():
        router.load_frr_config(daemons=["zebra", "eigrpd"])

    tgen.start_router()


def teardown_module(_mod):
    tgen = get_topogen()
    tgen.stop_topology()


def connected_prefixes(node):
    """
    Parse the Connected entries out of 'show ip eigrp topology'.

    Returns {prefix: {"successors": int, "fd": str}}.  The table renders each
    entry as a pair of lines:

        P  10.0.1.0/24, 1 successors, FD is 28160, serno: 0
               via Connected, r1-eth0

    Raises if the output is not a topology table at all, so that a vtysh
    error or a renamed command fails the test rather than quietly looking
    like an empty table.
    """
    output = topotest.normalize_text(node.vtysh_cmd("show ip eigrp topology"))

    if "EIGRP Topology Table" not in output:
        raise AssertionError(
            "'show ip eigrp topology' produced no topology table: %r" % output
        )

    lines = output.splitlines()
    result = {}

    for idx, line in enumerate(lines):
        match = re.match(r"^[PA]\s+(\S+), (\d+) successors, FD is (\d+)", line)
        if not match:
            continue

        if idx + 1 >= len(lines) or "via Connected" not in lines[idx + 1]:
            continue

        result[match.group(1)] = {
            "successors": int(match.group(2)),
            "fd": match.group(3),
        }

    return result


def successor_counts(node):
    return {p: v["successors"] for p, v in connected_prefixes(node).items()}


def test_premise_all_addresses_installed():
    "All three addresses must really be on r1-eth0, or the rest proves nothing."
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    output = tgen.gears["r1"].vtysh_cmd("show interface r1-eth0")

    for address in ("10.0.1.1/24", "10.0.1.3/24", "10.0.2.1/24"):
        assert address in output, (
            "%s is not configured on r1-eth0; the topology this test needs "
            "was never set up" % address
        )


def test_every_connected_subnet_is_advertised():
    "Both subnets on the interface must be advertised, once each."
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    expected = {"10.0.1.0/24": 1, "10.0.2.0/24": 1}

    test_func = functools.partial(successor_counts, tgen.gears["r1"])
    _, result = topotest.run_and_expect(test_func, expected, count=30, wait=1)

    assert result == expected, (
        "r1 did not advertise both connected subnets of one interface; got %r"
        % (result,)
    )


def test_same_subnet_second_address_shares_the_entry():
    "10.0.1.3/24 shares a subnet with 10.0.1.1/24 and must add no successor."
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    prefixes = successor_counts(tgen.gears["r1"])

    assert prefixes.get("10.0.1.0/24") == 1, (
        "10.0.1.0/24 has %r successors, expected 1 -- a second address in the "
        "same subnet produced its own advertisement"
        % (prefixes.get("10.0.1.0/24"),)
    )


def test_adjacency_forms_over_the_segment():
    "An interface with several subnets must still peer."
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    def _peer_present():
        output = tgen.gears["r1"].vtysh_cmd("show ip eigrp neighbors")
        return "10.0.1.2" in output or "10.0.2.2" in output

    _, result = topotest.run_and_expect(_peer_present, True, count=60, wait=1)

    assert result is True, (
        "r1 never formed an adjacency with r2:\n%s"
        % tgen.gears["r1"].vtysh_cmd("show ip eigrp neighbors")
    )


def test_bandwidth_change_refreshes_the_advertised_metric():
    "Reconfiguring bandwidth must update the metric, not be swallowed."
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]
    before = connected_prefixes(r1)
    assert before.get("10.0.1.0/24"), "10.0.1.0/24 is not advertised yet"
    before_fd = before["10.0.1.0/24"]["fd"]

    # Changing bandwidth resets the interface.  eigrp_if_down() leaves the
    # connected entry in the topology table, so bringing it back up has to
    # refresh that entry -- skipping it would silently discard this change.
    r1.vtysh_cmd(
        """
        configure terminal
          interface r1-eth0
            eigrp bandwidth 5000
        """
    )

    def _fd_changed():
        current = connected_prefixes(r1).get("10.0.1.0/24")
        return current is not None and current["fd"] != before_fd

    _, result = topotest.run_and_expect(_fd_changed, True, count=30, wait=1)

    assert result is True, (
        "FD for 10.0.1.0/24 stayed at %s after `eigrp bandwidth 5000`; the "
        "reconfiguration was not applied to the advertised metric" % before_fd
    )

    # And it must still be advertised exactly once.
    assert successor_counts(r1).get("10.0.1.0/24") == 1, (
        "the reset left 10.0.1.0/24 with a duplicate successor"
    )


def test_source_address_follows_the_advertised_subnets():
    """
    Dropping a subnet must move the packet source into one still advertised.

    Both routers hold 10.0.1.x first, so before this the interface speaks from
    10.0.1.0/24.  Once neither advertises that subnet any more, each has to
    speak from 10.0.2.0/24 instead -- a peer only accepts a source inside a
    subnet it runs on, so leaving the source where it was silently ends the
    adjacency.
    """
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    for name in ("r1", "r2"):
        tgen.gears[name].vtysh_cmd(
            """
            configure terminal
              router eigrp 1
                no network 10.0.1.0/24
            """
        )

    def _only_second_subnet():
        return sorted(successor_counts(tgen.gears["r1"]))

    _, result = topotest.run_and_expect(
        _only_second_subnet, ["10.0.2.0/24"], count=30, wait=1
    )
    assert result == ["10.0.2.0/24"], (
        "r1 still advertises a subnet it was told to drop; got %r" % (result,)
    )

    def _peer_still_present():
        output = tgen.gears["r1"].vtysh_cmd("show ip eigrp neighbors")
        return "10.0.2.2" in output

    _, result = topotest.run_and_expect(_peer_still_present, True, count=60, wait=1)

    assert result is True, (
        "r1 lost its adjacency after 10.0.1.0/24 was withdrawn -- it is still "
        "sourcing packets from a subnet it no longer advertises:\n%s"
        % tgen.gears["r1"].vtysh_cmd("show ip eigrp neighbors")
    )


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
