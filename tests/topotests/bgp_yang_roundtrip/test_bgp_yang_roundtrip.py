#!/usr/bin/env python
# SPDX-License-Identifier: ISC

"""
General BGP YANG config round-trip test (P1-02: A2-01, A2-02).

Loads a config covering every peer shape (numbered IPv4/IPv6, link-local
with local-interface, unnumbered, unnumbered v6only, typed and untyped
peer-groups, and members with inherited or overriding remote-as), saves
show running-config to a file, restarts bgpd with that saved file, and
verifies show running-config and show bgp neighbors json match before and
after restart.
"""

import json
import os
import sys
import pytest

CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

# pylint: disable=C0413
from lib import topotest
from lib.topogen import Topogen, TopoRouter, get_topogen

pytestmark = [pytest.mark.bgpd]


def build_topo(tgen):
    r1 = tgen.add_router("r1")
    switch = tgen.add_switch("s1")
    switch.add_link(r1)


def setup_module(mod):
    tgen = Topogen(build_topo, mod.__name__)
    tgen.start_topology()
    for router in tgen.routers().values():
        router.load_frr_config()
    tgen.start_router()


def teardown_module(mod):
    tgen = get_topogen()
    tgen.stop_topology()


def _bgp_config_block(run_cfg):
    lines = run_cfg.splitlines()
    start = next(
        (i for i, line in enumerate(lines) if line.startswith("router bgp")), None
    )
    assert start is not None, f"No router bgp block in:\n{run_cfg}"
    return "\n".join(lines[start:])


def _peer_summary_fields(nbrs_json):
    data = json.loads(nbrs_json)
    out = {}
    for key, val in data.items():
        if not isinstance(val, dict):
            continue
        out[key] = {
            "remoteAs": val.get("remoteAs"),
            "peerGroup": val.get("peerGroup"),
            "bgpNeighborAddr": val.get("bgpNeighborAddr"),
            "nbrExternalLink": val.get("nbrExternalLink"),
        }
    return out


def test_roundtrip_all_peer_shapes():
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]

    run_before = r1.vtysh_cmd("show running-config")
    bgp_before = _bgp_config_block(run_before)
    nbrs_before = _peer_summary_fields(r1.vtysh_cmd("show bgp neighbors json"))

    # Sanity checks for A2-01 and A2-02 formatting
    assert "neighbor fe80::2 remote-as external" in bgp_before
    assert bgp_before.index("neighbor fe80::2 remote-as external") < bgp_before.index(
        "neighbor fe80::2 interface r1-eth0"
    )
    assert (
        "neighbor swp3 interface peer-group PG_UNTYPED\n neighbor swp3 remote-as external"
        in bgp_before
    )
    assert (
        "neighbor swp4 interface v6only peer-group PG_ASN\n neighbor swp4 remote-as 65006"
        in bgp_before
    )

    saved_path = os.path.join(r1.logdir, "r1", "saved_frr.conf")
    os.makedirs(os.path.dirname(saved_path), exist_ok=True)
    with open(saved_path, "w") as f:
        f.write(
            "\n".join(
                line
                for line in run_before.splitlines()
                if not line.startswith(("Building configuration", "Current configuration"))
            )
            + "\n"
        )

    # Restart bgpd from the saved config only; in unified-config mode
    # startDaemons() replays /etc/frr/frr.conf into the restarted daemon.
    r1.killDaemons(["bgpd"])
    r1.load_config(TopoRouter.RD_FRR, saved_path)
    r1.startDaemons(["bgpd"])

    run_after = r1.vtysh_cmd("show running-config")
    bgp_after = _bgp_config_block(run_after)
    nbrs_after = _peer_summary_fields(r1.vtysh_cmd("show bgp neighbors json"))

    assert bgp_before == bgp_after, (
        f"Running-config changed after round-trip!\n"
        f"--- BEFORE ---\n{bgp_before}\n--- AFTER ---\n{bgp_after}"
    )
    assert nbrs_before == nbrs_after, (
        f"Neighbor state changed after round-trip!\n"
        f"--- BEFORE ---\n{nbrs_before}\n--- AFTER ---\n{nbrs_after}"
    )


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
