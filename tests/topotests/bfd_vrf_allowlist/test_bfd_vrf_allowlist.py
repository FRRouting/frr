# SPDX-License-Identifier: ISC
# -*- coding: utf-8 eval: (blacken-mode 1) -*-
#
# Copyright (C) 2026  Nevoa Solutions Ltda.

"""
Test the bfdd --vrfs allowlist.

r1 runs bfdd with "--vrfs=default": the default VRF is on the allowlist,
so its BFD sockets must open and a single-hop session to r2 must come
up.  With the inverted typesafe-hash comparator (bfd_perm_vrfs_hash_cmp
returning strmatch) the allowlist lookup never matched and bfdd opened
no socket in any VRF.
"""

import os
import re
import sys

import json

import pytest
from lib.topogen import Topogen, TopoRouter, get_topogen
from lib.topotest import run_and_expect

# Save the Current Working Directory to find configuration files.
CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

pytestmark = [pytest.mark.bfdd]

# BFD well-known single-hop UDP port
BFD_SINGLE_HOP_PORT = 3784


def setup_module(mod):
    "Sets up the pytest environment"

    topodef = {
        "s1": ("r1", "r2"),
    }
    tgen = Topogen(topodef, mod.__name__)
    tgen.start_topology()

    router_list = tgen.routers()
    for rname, router in router_list.items():
        router.load_config(
            TopoRouter.RD_ZEBRA, os.path.join(CWD, "{}/zebra.conf".format(rname))
        )
        options = "--vrfs=default" if rname == "r1" else None
        router.load_config(
            TopoRouter.RD_BFD, os.path.join(CWD, "{}/bfdd.conf".format(rname)), options
        )

    # Initialize all routers.
    tgen.start_router()


def teardown_module(_mod):
    "Teardown the pytest environment: stop topologies and free resources."
    tgen = get_topogen()
    # Remove the peers so bfdd exits without live sessions: a live
    # session at exit makes the daemon print memstats, which the
    # teardown memory-leak check would flag.
    for rname, peer in (("r1", "192.168.0.2"), ("r2", "192.168.0.1")):
        if rname in tgen.gears:
            tgen.gears[rname].vtysh_cmd(
                f"""
configure terminal
bfd
 no peer {peer}
 !
!
"""
            )
    tgen.stop_topology()


def bfd_socket_count(router, port):
    """Count the number of UDP sockets bound to the given port."""
    output = router.cmd("ss -ulpn sport = :{}".format(port))
    count = 0
    for line in output.strip().splitlines():
        if re.search(r":{}(?!\d)".format(port), line):
            count += 1
    return count


def _peer_status(router, peer):
    "Return the remote peer status from 'show bfd peers json'."
    output = router.vtysh_cmd("show bfd peers json", isjson=False)
    try:
        entries = json.loads(output)
    except json.JSONDecodeError:
        return None
    for entry in entries:
        if entry.get("peer") == peer:
            return entry.get("status")
    return None


def test_allowlisted_vrf_serves_bfd():
    "A VRF on the --vrfs allowlist must open its sockets and run sessions."

    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]
    r2 = tgen.gears["r2"]

    r1.vtysh_cmd(
        """
configure terminal
bfd
 peer 192.168.0.2
  no shutdown
 !
!
"""
    )
    r2.vtysh_cmd(
        """
configure terminal
bfd
 peer 192.168.0.1
  no shutdown
 !
!
"""
    )

    # The allowlisted default VRF must open the single-hop socket.
    ok, ret = run_and_expect(
        lambda: None if bfd_socket_count(r1, BFD_SINGLE_HOP_PORT) > 0 else "no socket",
        None,
        count=30,
        wait=1,
    )
    assert ok, "r1 has no BFD single-hop socket (--vrfs=default): {}".format(ret)

    # And the session must establish.
    ok, ret = run_and_expect(
        lambda: None if _peer_status(r1, "192.168.0.2") == "up" else "session down",
        None,
        count=30,
        wait=2,
    )
    assert ok, "r1 BFD session did not come up: {}".format(ret)
    ok, ret = run_and_expect(
        lambda: None if _peer_status(r2, "192.168.0.1") == "up" else "session down",
        None,
        count=30,
        wait=2,
    )
    assert ok, "r2 BFD session did not come up: {}".format(ret)
