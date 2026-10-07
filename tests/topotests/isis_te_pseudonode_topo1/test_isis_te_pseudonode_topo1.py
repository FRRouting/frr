#!/usr/bin/env python
# SPDX-License-Identifier: ISC
#
# Copyright (c) 2026 by Nvidia, Inc
#                       Donald Sharp
"""
test_isis_te_pseudonode_topo1.py

A LAN pseudonode LSP must not be applied to the real router's TED vertex.
The TED is keyed by the 6-byte sysid, so isis_te_parse_lsp() and
isis_te_delete_lsp() have to ignore r2.XX-00 instead of treating it as
r2.00-00.

    r1 ---- LAN 10.0.1.0/24 ---- r2 ---- P2P 10.0.2.0/24 ---- r3
                                 DIS

r2 is pinned as DIS and originates the only pseudonode. Its point-to-point
adjacency to r3 is advertised with Local/Remote IP (10.0.2.2 -> 10.0.2.3).
r3 is not on the LAN, so its reverse edge must survive both steps below;
only r2's edge is exposed to the pseudonode.

Setup conditions are waited on with run_and_expect(). The two checks that
cover the bug itself are single-shot: polling them would let a later
r2.00-00 refresh reparse the node LSP, restore the edge, and hide the
collision.
"""

import os
import re
import sys
from functools import partial

import pytest

CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

# pylint: disable=C0413
from lib import topotest
from lib.topogen import Topogen, get_topogen
from lib.topolog import logger

pytestmark = [pytest.mark.isisd]

R2_SYSID = "0000.0000.0002"
R2_EDGE = "10.0.2.2"
R2_EDGE_REMOTE = "10.0.2.3"
R3_EDGE = "10.0.2.3"
# Toggled to force r2 to reoriginate its node LSP without touching the LAN.
_r2_loop_metric = {"value": 20}


def build_topo(tgen):
    "Build function"

    for router in ["r1", "r2", "r3"]:
        tgen.add_router(router)

    lan = tgen.add_switch("s1")
    lan.add_link(tgen.gears["r1"], nodeif="eth-lan")
    lan.add_link(tgen.gears["r2"], nodeif="eth-lan")

    p2p = tgen.add_switch("s2")
    p2p.add_link(tgen.gears["r2"], nodeif="eth-p2p")
    p2p.add_link(tgen.gears["r3"], nodeif="eth-p2p")


def setup_module(module):
    "Sets up the pytest environment"

    tgen = Topogen(build_topo, module.__name__)
    tgen.start_topology()

    for router in tgen.routers().values():
        router.load_frr_config()

    tgen.start_router()


def teardown_module():
    "Teardown the pytest environment"
    get_topogen().stop_topology()


def vtysh_cfg(rname, *lines):
    args = " ".join('-c "{}"'.format(line) for line in ("conf t",) + lines)
    get_topogen().net[rname].cmd("vtysh {}".format(args))


def router_out(rname, command):
    return get_topogen().gears[rname].vtysh_cmd(command, isjson=False)


def isis_state(rname):
    return "{}\n{}".format(
        router_out(rname, "show isis database"),
        router_out(rname, "show isis mpls-te database"),
    )


def lsdb_has_pseudonode(rname, hostname, sysid):
    "True when hostname/sysid has an LSP whose pseudonode id is not 00."
    db = router_out(rname, "show isis database")
    pattern = re.compile(
        r"(?:^|\s)(?:{}|{})\.([0-9A-Fa-f]{{2}})-00(?:\s|$)".format(
            re.escape(hostname), re.escape(sysid)
        ),
        re.M,
    )
    return any(pseudo != "00" for pseudo in pattern.findall(db))


def lsdb_has_node_lsp(rname, hostname, sysid):
    db = router_out(rname, "show isis database")
    return "{}.00-00".format(hostname) in db or "{}.00-00".format(sysid) in db


def ted_has_ipv4_edge(rname, local, remote):
    """
    True when the TED edge keyed by local has that remote address.

    The brief edge line only prints the key. The remote address is under
    "detail".
    """
    out = router_out(rname, "show isis mpls-te database edge {} detail".format(local))
    if "No edge found" in out or "MPLS-TE is disabled" in out:
        return False
    return (
        "Local IPv4 address: {}".format(local) in out
        and "Remote IPv4 address: {}".format(remote) in out
    )


def ted_has_vertex(rname, name):
    out = router_out(rname, "show isis mpls-te database vertex {}".format(name))
    return "No vertex found" not in out and name in out


def check_pseudonode_present(rname, hostname, sysid):
    "None once rname's LSDB holds a pseudonode LSP from hostname/sysid."
    if lsdb_has_pseudonode(rname, hostname, sysid):
        return None
    return router_out(rname, "show isis database")


def check_pseudonode_gone(rname, hostname, sysid):
    "None once hostname/sysid's pseudonode LSP has left rname's LSDB."
    if not lsdb_has_pseudonode(rname, hostname, sysid):
        return None
    return router_out(rname, "show isis database")


def check_ted_ipv4_edge(rname, local, remote):
    "None once rname's TED holds the edge local -> remote."
    if ted_has_ipv4_edge(rname, local, remote):
        return None
    return router_out(rname, "show isis mpls-te database detail")


def force_r2_node_lsp_refresh():
    """
    Change r2's loopback metric so r2.00-00 is reoriginated. The resulting
    LSP_UPD reparses only the node LSP, which puts the P2P edge back after
    a pseudonode collision has removed it.
    """
    _r2_loop_metric["value"] = 50 if _r2_loop_metric["value"] == 20 else 20
    vtysh_cfg("r2", "interface lo", "isis metric {}".format(_r2_loop_metric["value"]))


def ensure_r2_is_dis_with_p2p_edge():
    "r2 is DIS, and r1's TED has r2's point-to-point edge."
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    vtysh_cfg("r1", "interface eth-lan", "isis priority 64")
    vtysh_cfg("r2", "interface eth-lan", "isis priority 127")

    test_func = partial(check_pseudonode_present, "r1", "r2", R2_SYSID)
    _, result = topotest.run_and_expect(test_func, None, count=60, wait=1)
    assert (
        result is None
    ), "r2 never became DIS, no r2 pseudonode LSP in r1's LSDB:\n{}".format(result)

    if not ted_has_ipv4_edge("r1", R2_EDGE, R2_EDGE_REMOTE):
        logger.info("r2 P2P edge missing from r1 TED; refreshing r2.00-00")
        force_r2_node_lsp_refresh()

    test_func = partial(check_ted_ipv4_edge, "r1", R2_EDGE, R2_EDGE_REMOTE)
    _, result = topotest.run_and_expect(test_func, None, count=60, wait=1)
    assert result is None, "r1 TED never learned r2's P2P edge {} -> {}:\n{}".format(
        R2_EDGE, R2_EDGE_REMOTE, result
    )


def rebuild_r1_ted():
    "Drop and re-enable MPLS-TE so isis_te_init_ted() walks the whole LSDB."
    vtysh_cfg("r1", "router isis 1", "no mpls-te")
    vtysh_cfg(
        "r1",
        "router isis 1",
        "mpls-te on",
        "mpls-te router-address 1.1.1.1",
    )


def assert_r2_p2p_survives(reason):
    """
    Single-shot: run_and_expect() here would let the next r2.00-00 refresh
    put the edge back before the loop gave up, hiding the bug.
    """
    edge = ted_has_ipv4_edge("r1", R2_EDGE, R2_EDGE_REMOTE)
    vertex = ted_has_vertex("r1", "r2")

    assert edge and vertex, (
        "{}\n"
        "r2 vertex in TED: {}\n"
        "r2 P2P edge {} -> {} in TED: {}\n"
        "r3 P2P edge {} -> {} in TED: {}\n"
        "r2.00-00 still in LSDB: {}\n"
        "{}".format(
            reason,
            vertex,
            R2_EDGE,
            R2_EDGE_REMOTE,
            edge,
            R3_EDGE,
            R2_EDGE,
            ted_has_ipv4_edge("r1", R3_EDGE, R2_EDGE),
            lsdb_has_node_lsp("r1", "r2", R2_SYSID),
            isis_state("r1"),
        )
    )


def test_ted_rebuild_keeps_dis_p2p_edge():
    """
    Rebuilding the TED from an LSDB that contains the DIS pseudonode must
    keep the DIS router's point-to-point edges.

    isis_te_init_ted() walks the LSDB in LSP-ID order, so r2.00-00 is parsed
    before r2.XX-00. Parsing the pseudonode finds that same vertex, marks its
    edges ORPHAN, and ls_vertex_clean() deletes them: the pseudonode has no
    Local/Remote IP sub-TLVs.
    """
    logger.info("TED rebuild must keep r2's P2P edge while r2's PSN is in the LSDB")
    ensure_r2_is_dis_with_p2p_edge()
    rebuild_r1_ted()
    assert_r2_p2p_survives(
        "rebuilding r1's TED from an LSDB that still contains r2's LAN "
        "pseudonode dropped r2's point-to-point edge"
    )


def test_ted_keeps_dis_p2p_edge_after_pseudonode_purge():
    """
    Purging the DIS pseudonode must not delete the real router's TED vertex.

    A receiver ages a purged pseudonode out after ZERO_AGE_LIFETIME (60s) and
    lsp_destroy() sends LSP_DEL. isis_te_delete_lsp() copies only the 6-byte
    sysid, so that delete removes r2.00-00's vertex and its outgoing edges.
    The node LSP itself stays in the LSDB and is not reparsed.
    """
    logger.info("Purging r2's pseudonode must leave r2's TED vertex and P2P edge")
    ensure_r2_is_dis_with_p2p_edge()

    # Hand the LAN to r1. r2 resigns and purges r2.XX-00.
    vtysh_cfg("r2", "interface eth-lan", "isis priority 0")
    vtysh_cfg("r1", "interface eth-lan", "isis priority 127")

    logger.info("waiting for r1 to age out r2's pseudonode LSP")
    test_func = partial(check_pseudonode_gone, "r1", "r2", R2_SYSID)
    _, result = topotest.run_and_expect(test_func, None, count=90, wait=1)
    assert (
        result is None
    ), "r2's pseudonode LSP never aged out of r1's LSDB:\n{}".format(result)

    assert_r2_p2p_survives(
        "r1 deleted r2's TED vertex when r2's LAN pseudonode LSP aged out"
    )
