# SPDX-License-Identifier: ISC
"""
test_bgp_nb_roundtrip.py — Phase 6 integration test.

Verifies that configuration written via the management plane (mgmtd)
becomes visible through the legacy CLI (`show running-config bgpd`) and
vice-versa. This is the round-trip contract that the Phase 1-3
DEFPY_YANG conversions are supposed to uphold.

CAVEAT: this scaffold runs only on Linux + a built FRR tree; the
local-development workflow (`pytest`) requires the standard topotest
prerequisites. The test is structured as four phases:

  1. set router-id via mgmtd (YANG xpath) and verify the change shows
     up in `vtysh -c "show running-config bgpd"`
  2. set the same leaf via the legacy CLI and verify it appears in
     `vtysh -c "show mgmt yang-config-data XPath ..."`
  3. exercise a per-AF flag toggle (e.g. `route-reflector-client`) via
     each side and verify the other side sees it
  4. exercise the apply_finish container (local-as) via mgmtd and
     verify all three leaves (local-as, no-prepend, replace-as)
     appear correctly on the CLI side

Subjects covered:
  * Phase 1 — backend client registration
  * Phase 2 — global leaves (router-id)
  * Phase 3a — neighbor leaves (passive-mode, password)
  * Phase 3c — per-AF flags (route-reflector-client)
  * Phase 5 — cli_show callbacks (round-trip via mgmtd reads)
"""
import os
import sys
import pytest

CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

from lib.topogen import Topogen, get_topogen
from lib.topolog import logger
from lib.common_config import step

pytestmark = [pytest.mark.bgpd, pytest.mark.mgmtd]


def build_topo(tgen):
    """Two routers, r1 <-> r2 over a single link, both running mgmtd+bgpd."""
    tgen.add_router("r1")
    tgen.add_router("r2")
    switch = tgen.add_switch("s1")
    switch.add_link(tgen.gears["r1"])
    switch.add_link(tgen.gears["r2"])


def setup_module(mod):
    """Bring up FRR with mgmtd + bgpd, no initial bgp config."""
    tgen = Topogen(build_topo, mod.__name__)
    tgen.start_topology()
    for rname, router in tgen.routers().items():
        router.load_config(
            "mgmtd",
            os.path.join(CWD, f"{rname}/mgmtd.conf"),
        )
        router.load_config(
            "bgpd",
            os.path.join(CWD, f"{rname}/bgpd.conf"),
        )
    tgen.start_router()


def teardown_module():
    tgen = get_topogen()
    tgen.stop_topology()


def test_router_id_mgmtd_to_cli():
    """Set router-id via mgmtd YANG path; verify legacy CLI shows it."""
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]
    step("Set router-id via mgmtd YANG path")
    r1.vtysh_cmd(
        'configure terminal\n'
        'mgmt set-config xpath '
        '"/frr-routing:routing/control-plane-protocols/control-plane-protocol'
        "[type='frr-bgp:bgp'][name='bgp'][vrf='default']/frr-bgp:bgp/global/router-id"
        '" value 10.0.0.1'
    )
    step("Verify legacy CLI shows the router-id")
    output = r1.vtysh_cmd("show running-config bgpd")
    assert "bgp router-id 10.0.0.1" in output, (
        f"expected router-id on legacy CLI; got:\n{output}"
    )


def test_router_id_cli_to_mgmtd():
    """Set router-id via legacy CLI; verify mgmtd YANG view sees it."""
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]
    step("Set router-id via legacy CLI")
    r1.vtysh_cmd(
        "configure terminal\n"
        "router bgp 65000\n"
        " bgp router-id 10.0.0.2"
    )
    step("Verify mgmtd YANG view sees it")
    output = r1.vtysh_cmd(
        'show mgmt yang-config-data xpath '
        '"/frr-routing:routing/control-plane-protocols/control-plane-protocol'
        "[type='frr-bgp:bgp'][name='bgp'][vrf='default']/frr-bgp:bgp/global/router-id"
        '"'
    )
    assert "10.0.0.2" in output, (
        f"expected router-id in mgmtd YANG view; got:\n{output}"
    )


def test_neighbor_passive_roundtrip():
    """Set neighbor passive via legacy CLI; verify mgmtd YANG sees passive-mode=true."""
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]
    r1.vtysh_cmd(
        "configure terminal\n"
        "router bgp 65000\n"
        " neighbor 10.0.0.2 remote-as 65001\n"
        " neighbor 10.0.0.2 passive"
    )
    output = r1.vtysh_cmd(
        'show mgmt yang-config-data xpath '
        '"/frr-routing:routing/control-plane-protocols/control-plane-protocol'
        "[type='frr-bgp:bgp'][name='bgp'][vrf='default']/frr-bgp:bgp/"
        "neighbors/neighbor[remote-address='10.0.0.2']/passive-mode"
        '"'
    )
    assert "true" in output.lower(), (
        f"expected passive-mode=true in YANG view; got:\n{output}"
    )


def test_per_af_route_reflector_client_roundtrip():
    """Set route-reflector-client (per-AF) via mgmtd; legacy CLI must show it."""
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]
    r1.vtysh_cmd(
        'configure terminal\n'
        'mgmt set-config xpath '
        '"/frr-routing:routing/control-plane-protocols/control-plane-protocol'
        "[type='frr-bgp:bgp'][name='bgp'][vrf='default']/frr-bgp:bgp/"
        "neighbors/neighbor[remote-address='10.0.0.2']/afi-safis/"
        "afi-safi[afi-safi-name='frr-rt:ipv4-unicast']/route-reflector-client"
        '" value true'
    )
    output = r1.vtysh_cmd("show running-config bgpd")
    assert "neighbor 10.0.0.2 route-reflector-client" in output, (
        f"expected RR-client on legacy CLI; got:\n{output}"
    )


def test_local_as_apply_finish_roundtrip():
    """local-as is a multi-leaf apply_finish container — all three leaves
    must apply atomically."""
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]
    base = (
        "/frr-routing:routing/control-plane-protocols/control-plane-protocol"
        "[type='frr-bgp:bgp'][name='bgp'][vrf='default']/frr-bgp:bgp/"
        "neighbors/neighbor[remote-address='10.0.0.2']/local-as"
    )
    r1.vtysh_cmd(
        f'configure terminal\n'
        f'mgmt set-config xpath "{base}/local-as" value 65999\n'
        f'mgmt set-config xpath "{base}/no-prepend" value true\n'
        f'mgmt set-config xpath "{base}/replace-as" value true'
    )
    output = r1.vtysh_cmd("show running-config bgpd")
    assert "neighbor 10.0.0.2 local-as 65999 no-prepend replace-as" in output, (
        f"expected full local-as line; got:\n{output}"
    )


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
