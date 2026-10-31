#!/usr/bin/env python
# SPDX-License-Identifier: ISC

"""
Test "install backup-path tunnel-only" with an RFC 9252 backup candidate.

R1 (PE, AS 65001) learns 192.168.199.0/24 in vrf10 from three sources:

                       10.16.2.0/24 (vrf10)
R1 ------------------------------------------ R2 (CE, AS 65002)
|                                                primary: weighted in on R1
|                      10.16.3.0/24 (vrf10)
R1 ------------------------------------------ R3 (CE, AS 65003)
|                                                plain-IP backup candidate
|                      10.16.4.0/24 (default VRF)
R1 ------------------------------------------ R4 (remote PE, AS 65001, iBGP)
                                                 VPNv4-over-SRv6: the route
                                                 carries an SRv6 service SID
                                                 in the BGP Prefix-SID
                                                 attribute (RFC 9252) and is
                                                 imported into vrf10

Without "tunnel-only" the plain-IP CE path via R3 is the backup. With
"tunnel-only", R3's candidate is rejected (nexthop not tunnel-resolved) and
the VPN-imported path — tunnel-by-construction through its RFC 9252 service
SID — becomes the backup.
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

pytestmark = [pytest.mark.bgpd]

PREFIX = "192.168.199.0/24"
PLAIN_BACKUP_NH = "10.16.3.3"
VPN_BACKUP_NH = "10.16.4.4"


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

    # vrf10 on the two PEs; CE-facing links on r1 and the stub on r4
    tgen.gears["r1"].run("ip link add vrf10 type vrf table 10")
    tgen.gears["r1"].run("ip link set vrf10 up")
    tgen.gears["r1"].run("ip link set r1-eth0 master vrf10")
    tgen.gears["r1"].run("ip link set r1-eth1 master vrf10")

    tgen.gears["r4"].run("ip link add vrf10 type vrf table 10")
    tgen.gears["r4"].run("ip link set vrf10 up")
    tgen.gears["r4"].run("ip link set r4-eth1 master vrf10")

    for rname, router in tgen.routers().items():
        router.load_frr_config(os.path.join(CWD, "{}/frr.conf".format(rname)))

    tgen.start_router()


def teardown_module(mod):
    tgen = get_topogen()
    tgen.stop_topology()


def _r1_vrf_af_config(r1, lines):
    cmd = "configure terminal\nrouter bgp 65001 vrf vrf10\naddress-family ipv4 unicast\n"
    cmd += "\n".join(lines)
    cmd += "\nend"
    r1.vtysh_cmd(cmd)


def _bgp_backup_state(r1):
    """Return {nexthop-ip: has-tunnelResolved-bool} for paths flagged backup."""
    output = json.loads(
        r1.vtysh_cmd(
            "show bgp vrf vrf10 ipv4 unicast {} json".format(PREFIX)
        )
    )
    state = {}
    for path in output.get("paths", []):
        if not path.get("backup"):
            continue
        for nh in path.get("nexthops", []):
            state[nh.get("ip")] = bool(path.get("tunnelResolved"))
    return state


def _path_dump(r1):
    output = json.loads(
        r1.vtysh_cmd(
            "show bgp vrf vrf10 ipv4 unicast {} json".format(PREFIX)
        )
    )
    dump = []
    for path in output.get("paths", []):
        dump.append(
            {
                "nhs": [nh.get("ip") for nh in path.get("nexthops", [])],
                "valid": path.get("valid"),
                "best": bool(path.get("bestpath")),
                "backup": bool(path.get("backup")),
                "tunnelResolved": bool(path.get("tunnelResolved")),
            }
        )
    return dump


def _expect_backup_state(r1, expected, msg):
    def _check():
        state = _bgp_backup_state(r1)
        if state != expected:
            return "backup state {} != expected {} (paths: {})".format(
                state, expected, _path_dump(r1)
            )
        return None

    test_func = functools.partial(_check)
    success, result = topotest.run_and_expect(test_func, None, count=60, wait=1)
    assert success, "{}: {}".format(msg, result)


def test_vpn_backup_candidate_converges():
    """All three paths (two CE, one VPN-imported) are present in vrf10."""
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]

    step("Waiting for all three paths for {} in vrf10".format(PREFIX))

    def _check_paths():
        output = json.loads(
            r1.vtysh_cmd(
                "show bgp vrf vrf10 ipv4 unicast {} json".format(PREFIX)
            )
        )
        if output.get("pathCount") != 3:
            return "expected 3 paths, got {}".format(output.get("pathCount"))
        return None

    test_func = functools.partial(_check_paths)
    success, result = topotest.run_and_expect(test_func, None, count=60, wait=1)
    assert success, "paths did not converge: {}".format(result)

    step("Without tunnel-only, the plain-IP CE path via R3 is the backup")
    _expect_backup_state(
        r1,
        {PLAIN_BACKUP_NH: False},
        "plain install backup-path should select the R3 path",
    )


def test_vpn_backup_selected_with_tunnel_only():
    """tunnel-only selects the RFC 9252 VPN-imported path as the backup."""
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]

    step("Enable install backup-path tunnel-only in vrf10")
    _r1_vrf_af_config(r1, ["install backup-path tunnel-only"])

    step("The VPN-imported SRv6-service-SID path becomes the backup")
    _expect_backup_state(
        r1,
        {VPN_BACKUP_NH: True},
        "tunnel-only should select the RFC 9252 VPN-imported path",
    )

    step("The detail view marks the backup tunnel-resolved")
    output = r1.vtysh_cmd(
        "show bgp vrf vrf10 ipv4 unicast {}".format(PREFIX)
    )
    assert ", backup (tunnel-resolved)" in output, (
        "expected ', backup (tunnel-resolved)' in: {}".format(output)
    )

    step("The vrf10 RIB carries the VPN backup nexthop")

    def _check_rib_backup():
        output = json.loads(
            r1.vtysh_cmd("show ip route vrf vrf10 {} json".format(PREFIX))
        )
        routes = output.get(PREFIX, [])
        for route in routes:
            if route.get("protocol") != "bgp":
                continue
            backups = route.get("backupNexthops", [])
            if any(nh.get("ip") == VPN_BACKUP_NH for nh in backups):
                return None
            return "no backup nexthop {} in {}".format(VPN_BACKUP_NH, backups)
        return "no bgp route for {} in vrf10".format(PREFIX)

    test_func = functools.partial(_check_rib_backup)
    success, result = topotest.run_and_expect(test_func, None, count=60, wait=1)
    assert success, "vrf10 RIB backup nexthop missing: {}".format(result)


def test_vpn_backup_disable_flush():
    """no install backup-path flushes the VPN backup."""
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]

    step("no install backup-path flushes every backup")
    _r1_vrf_af_config(r1, ["no install backup-path"])
    _expect_backup_state(r1, {}, "disable should flush all backups")


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
