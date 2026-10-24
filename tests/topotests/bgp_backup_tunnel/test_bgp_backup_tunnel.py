#!/usr/bin/env python
# SPDX-License-Identifier: ISC

"""
Test the "install backup-path ... tunnel-only" backup selection variant.

R1 (AS 65001) learns 192.168.199.0/24 from three peers:

|----------------------     R2          -------- 192.168.199.0/24
|    10.16.2.0/24       RID 10.255.255.2         (primary: weighted in
|                        AS 65002                 on R1)
|
|    10.16.3.0/24
R1 --------------------     R3          -------- 192.168.199.0/24
AS 65001                 RID 10.255.255.3        (plain-IP backup
|                        AS 65003                 candidate)
|
|----------------------     R4          -------- 192.168.199.0/24
     10.16.4.0/24       RID 10.255.255.4         (tunnel-resolved backup
                         AS 65001 (iBGP)          candidate: nexthop
                                                  4.4.4.4 resolves on R1
                                                  over a static SRv6
                                                  seg6 route)

R2's path is made primary via an inbound weight. R3's path (eBGP) sorts
ahead of R4's path (iBGP, equal AS path length after prepend), so without
"tunnel-only" the plain-IP path via R3 is selected as the backup. With
"tunnel-only", R3's candidate is rejected (nexthop not tunnel-resolved)
and R4's SRv6-resolved path becomes the backup.
"""

import os
import sys
import json
import pytest
import functools

from lib.common_config import step
from lib.topogen import Topogen, get_topogen
from lib import topotest

CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

pytestmark = [pytest.mark.bgpd, pytest.mark.staticd]

PREFIX = "192.168.199.0/24"
PLAIN_BACKUP_NH = "10.16.3.3"
TUNNEL_BACKUP_NH = "4.4.4.4"
SEG6_ROUTE = "ip route 4.4.4.4/32 10.16.4.4 r1-eth2 segments fc00:0:4::1"
PLAIN_ROUTE = "ip route 4.4.4.4/32 10.16.4.4 r1-eth2"
MPLS_ROUTE = "ip route 4.4.4.4/32 10.16.4.4 r1-eth2 label 16100"
GRE_ROUTE = "ip route 4.4.4.4/32 gre1"


def build_topo(tgen):
    for routern in range(1, 5):
        tgen.add_router("r{}".format(routern))

    switch = tgen.add_switch("s1")
    switch.add_link(tgen.gears["r1"])
    switch.add_link(tgen.gears["r2"])

    switch = tgen.add_switch("s2")
    switch.add_link(tgen.gears["r1"])
    switch.add_link(tgen.gears["r3"])

    switch = tgen.add_switch("s3")
    switch.add_link(tgen.gears["r1"])
    switch.add_link(tgen.gears["r4"])

    # Stub switches for the announced 192.168.199.0/24 networks
    switch = tgen.add_switch("s4")
    switch.add_link(tgen.gears["r2"])

    switch = tgen.add_switch("s5")
    switch.add_link(tgen.gears["r3"])

    switch = tgen.add_switch("s6")
    switch.add_link(tgen.gears["r4"])


def setup_module(mod):
    tgen = Topogen(build_topo, mod.__name__)
    tgen.start_topology()

    for rname, router in tgen.routers().items():
        if rname == "r1":
            router.load_frr_config(
                os.path.join(CWD, "{}/frr.conf".format(rname)),
                extra_daemons=["staticd"],
            )
        else:
            router.load_frr_config(os.path.join(CWD, "{}/frr.conf".format(rname)))

    tgen.start_router()


def teardown_module(mod):
    tgen = get_topogen()
    tgen.stop_topology()


def _r1_af_config(r1, lines):
    cmd = "configure terminal\nrouter bgp 65001\naddress-family ipv4 unicast\n"
    cmd += "\n".join(lines)
    cmd += "\nend"
    r1.vtysh_cmd(cmd)


def _bgp_backup_state(r1):
    """Return {nexthop-ip: has-tunnelResolved-bool} for paths flagged backup."""
    output = json.loads(
        r1.vtysh_cmd("show bgp ipv4 unicast {} json".format(PREFIX))
    )
    state = {}
    for path in output.get("paths", []):
        if not path.get("backup"):
            continue
        for nh in path.get("nexthops", []):
            state[nh.get("ip")] = bool(path.get("tunnelResolved"))
    return state


def _expect_backup_state(r1, expected, msg):
    def _check():
        state = _bgp_backup_state(r1)
        if state != expected:
            return "backup state {} != expected {}".format(state, expected)
        return None

    test_func = functools.partial(_check)
    success, result = topotest.run_and_expect(test_func, None, count=60, wait=1)
    assert success, "{}: {}".format(msg, result)


def _expect_paths(r1, count):
    def _check():
        output = json.loads(
            r1.vtysh_cmd("show bgp ipv4 unicast {} json".format(PREFIX))
        )
        if output.get("pathCount") != count:
            return "expected {} paths, got {}".format(
                count, output.get("pathCount")
            )
        return None

    test_func = functools.partial(_check)
    success, result = topotest.run_and_expect(test_func, None, count=60, wait=1)
    assert success, "paths for {} did not converge: {}".format(PREFIX, result)


def test_backup_plain_selected_without_tunnel_only():
    """Baseline: plain 'install backup-path' may pick a plain-IP backup."""
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]

    step("Waiting for all three paths for {}".format(PREFIX))
    _expect_paths(r1, 3)

    step("Without tunnel-only, the plain-IP path via R3 is the backup")
    _expect_backup_state(
        r1,
        {PLAIN_BACKUP_NH: False},
        "plain install backup-path should select the R3 path",
    )


def test_backup_tunnel_only_selects_tunnel_resolved():
    """tunnel-only skips the plain-IP candidate for the SRv6-resolved one."""
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]

    step("Enable install backup-path tunnel-only")
    _r1_af_config(r1, ["install backup-path tunnel-only"])

    step("The SRv6-resolved path via R4 becomes the backup")
    _expect_backup_state(
        r1,
        {TUNNEL_BACKUP_NH: True},
        "tunnel-only should select the SRv6-resolved R4 path",
    )

    step("The detail view marks the backup tunnel-resolved")
    output = r1.vtysh_cmd("show bgp ipv4 unicast {}".format(PREFIX))
    assert ", backup (tunnel-resolved)" in output, (
        "expected ', backup (tunnel-resolved)' in: {}".format(output)
    )

    step("show bgp nexthop reports the tunnel-resolution verdict per nexthop")
    output = json.loads(r1.vtysh_cmd("show bgp nexthop json"))
    nhs = output.get("ipv4", {})
    assert nhs.get(TUNNEL_BACKUP_NH, {}).get("tunnelResolved") is True, (
        "expected tunnelResolved=true for {}: {}".format(TUNNEL_BACKUP_NH, nhs)
    )
    assert nhs.get(TUNNEL_BACKUP_NH, {}).get("tunnelKind") == "srv6", (
        "expected tunnelKind=srv6 for {}: {}".format(TUNNEL_BACKUP_NH, nhs)
    )
    assert nhs.get(PLAIN_BACKUP_NH, {}).get("tunnelResolved") is False, (
        "expected tunnelResolved=false for {}: {}".format(PLAIN_BACKUP_NH, nhs)
    )

    step("The RIB carries the backup nexthop")

    def _check_rib_backup():
        output = json.loads(
            r1.vtysh_cmd("show ip route {} json".format(PREFIX))
        )
        routes = output.get(PREFIX, [])
        for route in routes:
            if route.get("protocol") != "bgp":
                continue
            backups = route.get("backupNexthops", [])
            if any(nh.get("ip") == TUNNEL_BACKUP_NH for nh in backups):
                return None
            return "no backup nexthop {} in {}".format(
                TUNNEL_BACKUP_NH, backups
            )
        return "no bgp route for {}".format(PREFIX)

    test_func = functools.partial(_check_rib_backup)
    success, result = topotest.run_and_expect(test_func, None, count=60, wait=1)
    assert success, "RIB backup nexthop missing: {}".format(result)


def test_backup_follows_resolution_changes():
    """Degrading the backup NH resolution to plain drops the backup."""
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]

    step("Replace the seg6 static route with a plain static route")
    r1.vtysh_cmd(
        "configure terminal\nno {}\n{}\nend".format(SEG6_ROUTE, PLAIN_ROUTE)
    )

    step("With no tunnel-resolved candidate left, there is no backup")
    _expect_backup_state(
        r1, {}, "no backup should survive a non-tunnel resolution"
    )

    step("Restore the seg6 static route")
    r1.vtysh_cmd(
        "configure terminal\nno {}\n{}\nend".format(PLAIN_ROUTE, SEG6_ROUTE)
    )

    step("The SRv6-resolved backup returns")
    _expect_backup_state(
        r1,
        {TUNNEL_BACKUP_NH: True},
        "backup should return once the nexthop tunnels again",
    )


def test_backup_mpls_resolved_leg():
    """A nexthop resolved over a labeled static route counts as a tunnel."""
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]

    # Order-independent: don't rely on a previous test leaving tunnel-only set.
    _r1_af_config(r1, ["install backup-path tunnel-only"])

    step("Replace the seg6 static route with a labeled static route")
    r1.vtysh_cmd(
        "configure terminal\nno {}\n{}\nend".format(SEG6_ROUTE, MPLS_ROUTE)
    )
    try:
        step("The MPLS-resolved path via R4 is the backup under tunnel-only")
        _expect_backup_state(
            r1,
            {TUNNEL_BACKUP_NH: True},
            "an MPLS label stack on the resolved leg should qualify as a tunnel",
        )

        step("show bgp nexthop reports the mpls tunnel kind")

        def _check_mpls_kind():
            output = json.loads(r1.vtysh_cmd("show bgp nexthop json"))
            nh = output.get("ipv4", {}).get(TUNNEL_BACKUP_NH, {})
            if nh.get("tunnelResolved") is not True:
                return "tunnelResolved not true for {}: {}".format(
                    TUNNEL_BACKUP_NH, nh
                )
            if nh.get("tunnelKind") != "mpls":
                return "tunnelKind {} != mpls for {}".format(
                    nh.get("tunnelKind"), TUNNEL_BACKUP_NH
                )
            return None

        test_func = functools.partial(_check_mpls_kind)
        success, result = topotest.run_and_expect(test_func, None, count=60, wait=1)
        assert success, "mpls tunnel kind not reported: {}".format(result)
    finally:
        step("Restore the seg6 static route")
        r1.vtysh_cmd(
            "configure terminal\nno {}\n{}\nend".format(MPLS_ROUTE, SEG6_ROUTE)
        )
    _expect_backup_state(
        r1,
        {TUNNEL_BACKUP_NH: True},
        "backup should remain once the nexthop is SRv6-resolved again",
    )


def test_backup_gre_interface_leg():
    """A nexthop egressing a GRE netdev counts as a tunnel (tunnel-if)."""
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]

    # Order-independent: don't rely on a previous test leaving tunnel-only set.
    _r1_af_config(r1, ["install backup-path tunnel-only"])

    step("Create a GRE tunnel interface on r1")
    out = r1.run(
        "ip tunnel add gre1 mode gre local 10.16.4.1 remote 10.16.4.4 ttl 64"
    )
    if "not supported" in out.lower() or "operation not" in out.lower():
        pytest.skip("GRE tunnels not supported by this kernel: {}".format(out))
    r1.run("ip link set gre1 up")

    try:
        step("Route the backup nexthop out of the GRE interface")
        r1.vtysh_cmd(
            "configure terminal\nno {}\n{}\nend".format(SEG6_ROUTE, GRE_ROUTE)
        )

        step("The GRE-resolved path via R4 is the backup under tunnel-only")
        _expect_backup_state(
            r1,
            {TUNNEL_BACKUP_NH: True},
            "a GRE egress interface on the resolved leg should qualify as a tunnel",
        )

        step("show bgp nexthop reports the tunnel-if kind")

        def _check_gre_kind():
            output = json.loads(r1.vtysh_cmd("show bgp nexthop json"))
            nh = output.get("ipv4", {}).get(TUNNEL_BACKUP_NH, {})
            if nh.get("tunnelResolved") is not True:
                return "tunnelResolved not true for {}: {}".format(
                    TUNNEL_BACKUP_NH, nh
                )
            if nh.get("tunnelKind") != "tunnel-if":
                return "tunnelKind {} != tunnel-if for {}".format(
                    nh.get("tunnelKind"), TUNNEL_BACKUP_NH
                )
            return None

        test_func = functools.partial(_check_gre_kind)
        success, result = topotest.run_and_expect(test_func, None, count=60, wait=1)
        assert success, "tunnel-if kind not reported: {}".format(result)
    finally:
        step("Restore the seg6 static route and remove the GRE interface")
        r1.vtysh_cmd(
            "configure terminal\nno {}\n{}\nend".format(GRE_ROUTE, SEG6_ROUTE)
        )
        r1.run("ip link del gre1")
    _expect_backup_state(
        r1,
        {TUNNEL_BACKUP_NH: True},
        "backup should remain once the nexthop is SRv6-resolved again",
    )


def test_backup_variant_transitions():
    """CLI variants transition cleanly and round-trip in the config."""
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]

    step("install backup-path ecmp tunnel-only keeps the tunnel backup")
    _r1_af_config(r1, ["install backup-path ecmp tunnel-only"])
    _expect_backup_state(
        r1,
        {TUNNEL_BACKUP_NH: True},
        "ecmp tunnel-only should keep the SRv6-resolved backup",
    )
    output = r1.vtysh_cmd("show running-config")
    assert "install backup-path ecmp tunnel-only" in output, (
        "running-config does not round-trip 'install backup-path ecmp "
        "tunnel-only': {}".format(output)
    )

    step("Dropping tunnel-only reverts to the plain-IP backup")
    _r1_af_config(r1, ["install backup-path"])
    _expect_backup_state(
        r1,
        {PLAIN_BACKUP_NH: False},
        "plain install backup-path should reselect the R3 path",
    )
    output = r1.vtysh_cmd("show running-config")
    assert "install backup-path\n" in output, (
        "running-config does not round-trip 'install backup-path': "
        "{}".format(output)
    )
    assert "tunnel-only" not in output, (
        "running-config still carries tunnel-only: {}".format(output)
    )

    step("no install backup-path flushes every backup")
    _r1_af_config(r1, ["no install backup-path"])
    _expect_backup_state(r1, {}, "disable should flush all backups")
    output = r1.vtysh_cmd("show running-config")
    assert "install backup-path" not in output, (
        "running-config still carries install backup-path: {}".format(output)
    )


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
