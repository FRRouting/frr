#!/usr/bin/env python
# SPDX-License-Identifier: ISC
#
# Copyright (c) 2026 by FRRouting / topology test authors
#
"""
Description: dynamic BGP + MD5 in a non-default VRF on the DUT while also
peering in the default VRF (switch3). Expected failure mode is that switch1
does not show the vrf1 dynamic neighbor as Established in
``show bgp vrf all summary`` while the default-VRF session may be up.

Topology :
  switch1 (DUT) -- vrf1 -- switch2
  switch1 -------- default -- switch3

Each router uses a single integrated ``switchN/frr.conf`` (zebra + BGP; on the
DUT, default BGP instance before VRF BGP). Config is loaded with
``load_frr_config()`` (standard topotest unified ``frr.conf`` path).
"""

import functools
import json
import os
import platform
import re
import sys
import time

import pytest

CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

# pylint: disable=C0413
from lib import topotest
from lib.checkping import check_ping
from lib.topogen import Topogen, get_topogen

pytestmark = [pytest.mark.bgpd]

VRF_NAME = "vrf1"
VRF_TABLE_S1 = 11001
VRF_TABLE_S2 = 11002
PEER_S2 = "10.10.12.2"
PEER_S3 = "10.10.13.2"
DUT_ADDR_VRF1 = "10.10.12.1"


def build_topo(tgen):
    s1 = tgen.add_router("switch1")
    s2 = tgen.add_router("switch2")
    s3 = tgen.add_router("switch3")
    tgen.add_link(s1, s2)
    tgen.add_link(s1, s3)


def _peer_state_vrf_all_summary(summary, vrf, addr):
    """Return BGP FSM state string for addr under vrf (handles dynamic * prefix)."""
    if not isinstance(summary, dict):
        return None
    try:
        peers = summary[vrf]["ipv4Unicast"]["peers"]
    except (KeyError, TypeError):
        return None
    if not isinstance(peers, dict):
        return None
    for key in (addr, "*{}".format(addr)):
        ent = peers.get(key)
        if isinstance(ent, dict):
            return ent.get("state")
    for key, ent in peers.items():
        if isinstance(ent, dict) and key.lstrip("*") == addr:
            return ent.get("state")
    return None


def _extract_running_config_block(config, header_line):
    """Return the `router bgp ...` stanza starting at header_line, or a short note."""
    if not config or header_line not in config:
        return "(block start {!r} not found in running-config)".format(header_line)
    i = config.index(header_line)
    rest = config[i:]
    m = re.search(r"\nrouter ", rest[1:])
    if m:
        return rest[: m.start() + 1].strip()
    return rest.strip()[:8000]


def _failure_md5_diagnostic_bundle(dut, peer, vrf_name):
    """
    Commands to separate:
      - switch2 NHT / eBGP-connected (not the original MD5/listener issue)
      - TCP :179 not ESTAB (often MD5 mismatch or no accept)
      - Listeners OK on DUT but no dynamic peer (DUT accept / MD5 on listen socket)
    """
    parts = []

    def _add(title, text):
        parts.append("=== {} ===\n{}".format(title, (text or "").rstrip() or "(empty)"))

    _add(
        "switch1: show bgp vrf all summary json",
        dut.vtysh_cmd("show bgp vrf all summary json"),
    )
    _add("switch1: show bgp listeners", dut.vtysh_cmd("show bgp listeners"))
    _add(
        "switch1: show bgp vrf {} ipv4 unicast summary json".format(vrf_name),
        dut.vtysh_cmd("show bgp vrf {} ipv4 unicast summary json".format(vrf_name)),
    )
    _add(
        "switch1: show bgp vrf {} neighbors".format(vrf_name),
        dut.vtysh_cmd("show bgp vrf {} neighbors".format(vrf_name)),
    )
    _add(
        "switch1: show ip route vrf {} json".format(vrf_name),
        dut.vtysh_cmd("show ip route vrf {} json".format(vrf_name)),
    )
    _add(
        "switch1: ss tcp (vrf {}, lines mentioning :179)".format(vrf_name),
        dut.cmd(
            "ip vrf exec {} ss -tn 2>/dev/null | grep -E ':179|State' | head -80".format(
                vrf_name
            )
        ),
    )
    rc1 = dut.vtysh_cmd("show running-config")
    _add(
        "switch1: running-config (BGP vrf instance only)",
        _extract_running_config_block(rc1, "router bgp 65001 vrf {}".format(vrf_name)),
    )

    _add(
        "switch2: show bgp vrf {} neighbors {}".format(vrf_name, DUT_ADDR_VRF1),
        peer.vtysh_cmd("show bgp vrf {} neighbors {}".format(vrf_name, DUT_ADDR_VRF1)),
    )
    _add(
        "switch2: show bgp vrf {} ipv4 unicast summary json".format(vrf_name),
        peer.vtysh_cmd("show bgp vrf {} ipv4 unicast summary json".format(vrf_name)),
    )
    _add(
        "switch2: show ip route vrf {} json".format(vrf_name),
        peer.vtysh_cmd("show ip route vrf {} json".format(vrf_name)),
    )
    _add(
        "switch2: ss tcp (vrf {}, lines mentioning :179)".format(vrf_name),
        peer.cmd(
            "ip vrf exec {} ss -tn 2>/dev/null | grep -E ':179|State' | head -80".format(
                vrf_name
            )
        ),
    )
    rc2 = peer.vtysh_cmd("show running-config")
    _add(
        "switch2: running-config (BGP vrf instance only)",
        _extract_running_config_block(rc2, "router bgp 65002 vrf {}".format(vrf_name)),
    )

    parts.append(
        "=== how to read (original issue = DUT vrf1 dynamic + MD5 listen) ===\n"
        "- switch2: 'No path to specified Neighbor' / Opens 0 / Nexthop 0.0.0.0 → "
        "peer-side NHT or eBGP-connected check; fix switch2 config before blaming "
        "DUT MD5 listen.\n"
        "- switch1: vrf1 listeners on 0.0.0.0:179 but 'No BGP neighbors' and ss "
        "shows no ESTAB to :179 → TCP+MD5 not completing (typical MD5 listen / "
        "accept path).\n"
        "- switch2 Established to 10.10.12.1 but switch1 vrf1 still empty → "
        "focus on DUT dynamic neighbor creation / vrf1 instance."
    )
    return "\n\n".join(parts)


def setup_module(mod):
    tgen = Topogen(build_topo, mod.__name__)
    tgen.start_topology()

    s1 = tgen.gears["switch1"]
    s2 = tgen.gears["switch2"]
    s3 = tgen.gears["switch3"]

    s1.cmd_raises("ip link add {} type vrf table {}".format(VRF_NAME, VRF_TABLE_S1))
    s1.cmd_raises("ip link set up dev {}".format(VRF_NAME))
    s1.cmd_raises("ip link set switch1-eth0 master {}".format(VRF_NAME))
    s1.cmd_raises("ip link set up dev switch1-eth0")
    s1.cmd_raises("ip link set up dev switch1-eth1")

    s2.cmd_raises("ip link add {} type vrf table {}".format(VRF_NAME, VRF_TABLE_S2))
    s2.cmd_raises("ip link set up dev {}".format(VRF_NAME))
    s2.cmd_raises("ip link set switch2-eth0 master {}".format(VRF_NAME))
    s2.cmd_raises("ip link set up dev switch2-eth0")

    s3.cmd_raises("ip link set up dev switch3-eth0")

    for r in (s1, s2, s3):
        r.cmd_raises("sysctl -w net.ipv4.tcp_l3mdev_accept=1")

    for rname, router in tgen.routers().items():
        router.load_frr_config(os.path.join(CWD, rname, "frr.conf"))

    tgen.start_router()

    check_ping("switch2", DUT_ADDR_VRF1, True, 30, 1, vrf=VRF_NAME)
    check_ping("switch3", "10.10.13.1", True, 10, 1)


def teardown_module(mod):
    tgen = get_topogen()
    tgen.stop_topology()


def test_bgp_vrf_dynamic_md5_listen_late():
    """
    1. DUT switch1: dynamic BGP listen range in vrf1 (MD5 peergroup1).
    2. switch2: BGP toward switch1 in vrf1 (MD5 peergroup1).
    3. switch3: BGP toward switch1 in default VRF (MD5 peergroup2).
    4. On switch1, ``show bgp vrf all summary``: vrf1 neighbor switch2 must be
       Established (dynamic). Known product issue: this stays down while default
       may be up.
    """
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    if topotest.version_cmp(platform.release(), "5.3") < 0:
        pytest.skip("Kernel < 5.3 (tcp_l3mdev_accept / VRF TCP)")

    dut = tgen.gears["switch1"]
    s2 = tgen.gears["switch2"]

    def _check():
        try:
            summary = json.loads(dut.vtysh_cmd("show bgp vrf all summary json"))
        except (json.JSONDecodeError, TypeError, ValueError):
            return {"err": "bad json", "raw": None}

        def_v = _peer_state_vrf_all_summary(summary, "default", PEER_S3)
        v1_v = _peer_state_vrf_all_summary(summary, VRF_NAME, PEER_S2)

        if def_v == "Established" and v1_v == "Established":
            return None
        return {
            "default_peer_{}".format(PEER_S3): def_v,
            "vrf1_peer_{}".format(PEER_S2): v1_v,
            "summary_keys": sorted(summary.keys()) if isinstance(summary, dict) else [],
        }

    ok, last = topotest.run_and_expect(
        functools.partial(_check), None, count=60, wait=1
    )
    if ok:
        assert last is None
        return

    bundle = _failure_md5_diagnostic_bundle(dut, s2, VRF_NAME)
    assert False, (
        "Expected switch1: default->{} and vrf1->{} Established "
        "(show bgp vrf all summary json). Last poll: {}.\n"
        "Goal: reproduce DUT vrf1 dynamic listen + peer-group MD5; use the "
        "bundle below to see if switch2 is still stuck at NHT (not MD5) vs "
        "TCP:179/accept on switch1.\n"
        "If you patched bgpd, ensure the topotest runs that rebuilt binary "
        "(e.g. install to /usr/lib/frr).\n\n{}".format(
            PEER_S3,
            PEER_S2,
            json.dumps(last, indent=2),
            bundle,
        )
    )


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
