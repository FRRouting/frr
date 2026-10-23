#!/usr/bin/env python
# SPDX-License-Identifier: ISC
#
# test_isis_srv6_locator_state.py
# Part of NetDEF Topology Tests
#
# Copyright (c) 2026 by Bing Shui <bingshui@smail.nju.edu.cn>

"""
test_isis_srv6_locator_state.py
===============================

Regression for the IS-IS SRv6 Locator de-duplication flag leaking across
Locator entries of the same LSP.

isis_spf_process_lsp() used to initialize loc_is_in_ipv6_reach once at
function entry.  Inside the SRv6 Locator TLV loop the flag is set when a
Locator prefix also appears in an IPv6 Prefix Reachability TLV of the
same LSP (allowed by RFC 9352 section 5), and it was never reset: once
any Locator matched, every later Locator of the same LSP - including
later fragments, since the fragment loop re-enters the TLV processing
without resetting it - skipped process_N().  A Locator advertised only
in the SRv6 Locator TLV therefore contributed no IS-IS route.

Topology
--------

    r1 (FRR isisd victim) ----eth1---- r2 (scapy fake peer + injector)

r2 impersonates router 0000.0000.0002: it mirrors r1's IIH to form a
real point-to-point adjacency (RFC 5303 3-way state INIT/UP with r1 as
neighbor) and then injects crafted L1 LSPs.  The crafted LSPs carry an
IPv6 Prefix Reachability TLV (236) and an SRv6 Locator TLV (27), both
MTID 0, algorithm 0 (SR_ALGORITHM_SPF); r1 runs metric-style wide
(newmetric), which the IPv6 reachability and SRv6 Locator processing
requires.

Scenarios
---------

1. test_adjacency
     Baseline: the point-to-point adjacency to the fake peer reaches Up.
2. test_locator_after_reach_match
     TLV236 += A, TLV27 = [A, B].  Both locators must be routed; the
     unpatched SPF silently skips B.
3. test_reverse_order_control
     TLV236 += A, TLV27 = [B, A].  Both locators are routed on any
     version: the skip is order-dependent state residue, not a generic
     failure to process the SRv6 Locator TLV.
4. test_locators_without_reach_control
     TLV27 = [A, B], no locator in TLV236.  Both locators are routed on
     any version: legitimate multiple locators keep working.
5. test_dedup_control
     TLV236 += A, TLV27 = [A].  Exactly A is routed on any version: the
     intended RFC 9352 section 5 de-duplication is preserved.
6. test_fragment_locator
     frag0: TLV236 += A, TLV27 = [A]; frag1: TLV27 = [B].  Both locators
     must be routed; unpatched the flag survives the fragment loop and B
     is skipped.
"""

import json
import os
import sys
import time

import pytest

CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

# pylint: disable=C0413
from lib.topogen import Topogen, TopoRouter, get_topogen
from lib.topolog import logger


pytestmark = [pytest.mark.isisd]

RUNTIME = "/tmp/isis-srv6-locator-state"
TARGET_SYSID = "0000.0000.0001"
FAKE_SYSID = "0000.0000.0002"
LOCATOR_A = "2001:db8:100::/64"
LOCATOR_B = "2001:db8:200::/64"
LSP_LIFETIME = 600

_seqno = 0x10


def build_topo(tgen):
    "Build function"
    tgen.add_router("r1")
    tgen.add_host("r2", "10.213.12.2/24", "via 10.213.12.1")
    tgen.add_link(tgen.gears["r1"], tgen.gears["r2"])


def setup_module(mod):
    "Sets up the pytest environment"
    tgen = Topogen(build_topo, mod.__name__)
    tgen.start_topology()

    r1 = tgen.gears["r1"]
    r1.load_config(TopoRouter.RD_ZEBRA, os.path.join(CWD, "r1/zebra.conf"))
    r1.load_config(TopoRouter.RD_ISIS, os.path.join(CWD, "r1/isisd.conf"))

    tgen.start_router()

    os.makedirs(os.path.join(RUNTIME, "spool"), exist_ok=True)
    cfg = {
        "iface": "r2-eth0",
        "target_sysid": TARGET_SYSID.replace(".", ""),
        "fake_sysid": FAKE_SYSID.replace(".", ""),
        "stop_file": os.path.join(RUNTIME, "peer.stop"),
        "spool_dir": os.path.join(RUNTIME, "spool"),
        "events_path": os.path.join(RUNTIME, "peer_events.jsonl"),
        "template_path": os.path.join(RUNTIME, "peer_iih_template.hex"),
    }
    with open(os.path.join(RUNTIME, "peer_input.json"), "w") as fp:
        json.dump(cfg, fp)
    for stale in (cfg["stop_file"], cfg["events_path"], cfg["template_path"],
                  os.path.join(RUNTIME, "peer.out")):
        if os.path.exists(stale):
            os.remove(stale)
    for stale in os.listdir(os.path.join(RUNTIME, "spool")):
        os.remove(os.path.join(RUNTIME, "spool", stale))
    r2 = tgen.gears["r2"]
    r2.cmd("ip link set r2-eth0 up")
    r2.cmd(
        "nohup python3 {}/peer_helper.py {} > {} 2>&1 &".format(
            CWD, os.path.join(RUNTIME, "peer_input.json"),
            os.path.join(RUNTIME, "peer.out")
        )
    )


def teardown_module():
    "Teardown the pytest environment"
    tgen = get_topogen()
    with open(os.path.join(RUNTIME, "peer.stop"), "w") as fp:
        fp.write("stop\n")
    time.sleep(2)
    tgen.stop_topology()


def peer_ready():
    "True once the fake peer captured the r1 IIH template."
    try:
        with open(os.path.join(RUNTIME, "peer.out")) as fp:
            return "IIH_TEMPLATE" in fp.read()
    except FileNotFoundError:
        return False


def adjacency_up(tgen):
    r1 = tgen.gears["r1"]
    out = r1.vtysh_cmd("show isis neighbor")
    return FAKE_SYSID in out and "Up" in out


def wait_adjacency(tgen, timeout=90):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if adjacency_up(tgen):
            return True
        time.sleep(1)
    return False


def peer_inject(tgen, name, frames):
    "Send one injection job (<=2 PDUs) to the fake peer."
    global _seqno
    _seqno += 0x10
    spool = os.path.join(RUNTIME, "spool")
    for stale in os.listdir(spool):
        os.remove(os.path.join(spool, stale))
    frames = [dict(f, seqno=_seqno, lifetime=LSP_LIFETIME) for f in frames]
    job = {"name": name, "spacing": 0.4, "frames": frames}
    with open(os.path.join(spool, "job_{}.json".format(name)), "w") as fp:
        json.dump(job, fp)
    done_path = os.path.join(spool, "job_{}.done".format(name))
    deadline = time.monotonic() + 30
    while time.monotonic() < deadline:
        if os.path.exists(done_path):
            with open(done_path) as fp:
                return json.load(fp)
        time.sleep(0.3)
    raise RuntimeError("peer helper did not finish injection {}".format(name))


def rib6_routes(tgen):
    r1 = tgen.gears["r1"]
    return json.loads(r1.vtysh_cmd("show ipv6 route isis json"))


def isis_routes(tgen):
    r1 = tgen.gears["r1"]
    return json.loads(r1.vtysh_cmd("show isis route json"))


def _json_has_prefix(value, prefix):
    if isinstance(value, dict):
        for key, child in value.items():
            if key == prefix:
                return True
            if key == "prefix" and child == prefix:
                return True
            if _json_has_prefix(child, prefix):
                return True
    elif isinstance(value, list):
        for child in value:
            if _json_has_prefix(child, prefix):
                return True
    return False


def wait_routes(tgen, want, timeout=30):
    """Poll until `show ipv6 route isis json` matches want ({prefix: bool})."""
    deadline = time.monotonic() + timeout
    routes = {}
    while time.monotonic() < deadline:
        routes = rib6_routes(tgen)
        if all((prefix in routes) == expected for prefix, expected in want.items()):
            return routes
        time.sleep(1)
    return routes


def check_routes(tgen, name, want):
    routes = wait_routes(tgen, want)
    isis = isis_routes(tgen)
    for prefix, expected in want.items():
        assert (prefix in routes) == expected, (
            "{}: RIB route {} expected {}: {}".format(
                name, prefix, expected, json.dumps(routes, indent=2)
            )
        )
        assert _json_has_prefix(isis, prefix) == expected, (
            "{}: IS-IS route {} expected {}: {}".format(
                name, prefix, expected, json.dumps(isis, indent=2)
            )
        )


def test_adjacency():
    "Baseline: the point-to-point adjacency to the fake peer reaches Up."
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)
    if not wait_adjacency(tgen):
        r1 = tgen.gears["r1"]
        logger.info("DIAG isis interface: %s", r1.vtysh_cmd("show isis interface detail"))
        logger.info("DIAG ip interface: %s", r1.vtysh_cmd("show ip interface r1-eth0"))
        logger.info("DIAG ipv6 interface: %s", r1.vtysh_cmd("show ipv6 interface r1-eth0"))
        logger.info("DIAG neighbor: %s", r1.vtysh_cmd("show isis neighbor detail"))
        pytest.fail("adjacency to the fake peer did not come up")
    assert peer_ready()


def test_locator_after_reach_match():
    "TLV236 += A, TLV27 = [A, B]: both locators must be routed."
    tgen = get_topogen()
    peer_inject(tgen, "ab_attack",
                [{"reach": [LOCATOR_A], "locators": [LOCATOR_A, LOCATOR_B]}])
    check_routes(tgen, "ab_attack",
                 {LOCATOR_A: True, LOCATOR_B: True})


def test_reverse_order_control():
    "TLV236 += A, TLV27 = [B, A]: both locators routed on any version."
    tgen = get_topogen()
    peer_inject(tgen, "ba_order_control",
                [{"reach": [LOCATOR_A], "locators": [LOCATOR_B, LOCATOR_A]}])
    check_routes(tgen, "ba_order_control",
                 {LOCATOR_A: True, LOCATOR_B: True})


def test_locators_without_reach_control():
    "TLV27 = [A, B] without reach match: both routed on any version."
    tgen = get_topogen()
    peer_inject(tgen, "only_control",
                [{"reach": [], "locators": [LOCATOR_A, LOCATOR_B]}])
    check_routes(tgen, "only_control",
                 {LOCATOR_A: True, LOCATOR_B: True})


def test_dedup_control():
    "TLV236 += A, TLV27 = [A]: exactly A routed on any version."
    tgen = get_topogen()
    peer_inject(tgen, "dedup_control",
                [{"reach": [LOCATOR_A], "locators": [LOCATOR_A]}])
    check_routes(tgen, "dedup_control",
                 {LOCATOR_A: True, LOCATOR_B: False})


def test_fragment_locator():
    "frag0 carries A in reach+locator, frag1 carries B: both routed."
    tgen = get_topogen()
    peer_inject(tgen, "fragment_attack",
                [{"frag": 0, "reach": [LOCATOR_A], "locators": [LOCATOR_A]},
                 {"frag": 1, "reach": [], "locators": [LOCATOR_B]}])
    check_routes(tgen, "fragment_attack",
                 {LOCATOR_A: True, LOCATOR_B: True})


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    ret = pytest.main(args)
    sys.exit(ret)
