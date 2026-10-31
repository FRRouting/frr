#!/usr/bin/env python
# SPDX-License-Identifier: ISC

# Copyright (c) 2025, 
# Dawid Kopec <dkopec@akamai.com>
#
# Regression test for the bug in zebra/zebra_nhg.c nexthop_set_resolved():
# when performing recursive nexthop resolution for an IPv4 route whose NH
# resolves through an SRv6 VPN route, zebra was installing the route with
# MPLS encapsulation instead of SRv6 seg6 encapsulation.
#
# Root cause: nh_srv6 from the resolved nexthop (newhop) was not being copied
# to the new resolved_hop — only the parent nexthop's nh_srv6 was propagated.
# The fix adds a newhop->nh_srv6 copy block in nexthop_set_resolved(), mirroring
# the existing MPLS label propagation logic.

import functools
import json
import os
import sys

import pytest

CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

from lib import topotest
from lib.topogen import Topogen, TopoRouter, get_topogen
from lib.topolog import logger
from lib.common_config import required_linux_kernel_version

pytestmark = [pytest.mark.bgpd]

#
# Topology
#
#   r1 ---[eth0-eth0]--- r2
#
# r2 exports 2600:1000::101/128 from vrf test1 as an IPv6 VPN route with an
# SRv6 SID (from locator 2001:db8:3::/48).  r1 imports this into its own
# vrf test1, giving it a nexthop with nh_srv6 set.
#
# r1 also has a static IPv4 route for 198.0.0.150/32 → 2600:1000::101 inside
# vrf test1.  That nexthop has nh_srv6 = NULL (plain static, no SRv6 SID).
#
# When zebra resolves the static route it performs a recursive lookup:
#   198.0.0.150/32 → NH 2600:1000::101 → 2600:1000::101/128 (SRv6 VPN)
#
# nexthop_set_resolved() is called with:
#   nexthop  = static route NH  (nh_srv6 = NULL)
#   newhop   = FIB nexthop of 2600:1000::101/128 (nh_srv6 = SID)
#
# Before the fix: newhop->nh_srv6 was silently dropped and the kernel
# received an MPLS label instead.
# After the fix:  newhop->nh_srv6 is copied and the kernel installs the
# route with encap seg6.
#

# SRv6 SID allocated by r2 for 2600:1000::101/128:
#   locator  2001:db8:3::/48  block-len 32  node-len 16  func-bits 16
#   sid vpn export 1  →  function 1 placed at bits 48-63 → 0x0001
#   SID = 2001:0db8:0003:0001:: = 2001:db8:3:1::
EXPECTED_SID = "2001:db8:3:1::"


def build_topo(tgen):
    tgen.add_router("r1")
    tgen.add_router("r2")
    tgen.add_link(tgen.gears["r1"], tgen.gears["r2"], "eth0", "eth0")


def setup_module(mod):
    result = required_linux_kernel_version("5.15")
    if result is not True:
        pytest.skip("Kernel 5.15+ required for SRv6")

    tgen = Topogen(build_topo, mod.__name__)
    tgen.start_topology()

    for rname, router in tgen.routers().items():
        router.load_frr_config(os.path.join(CWD, "{}/frr.conf".format(rname)))

    # VRFs must exist before FRR starts so that interface-in-vrf assignments
    # and VPN route import tables are set up correctly at daemon init.
    for rname in ("r1", "r2"):
        tgen.gears[rname].run("sysctl -w net.vrf.strict_mode=1")
        tgen.gears[rname].run("ip link add test1 type vrf table 10")
        tgen.gears[rname].run("ip link set test1 up")

    tgen.start_router()


def teardown_module(mod):
    tgen = get_topogen()
    tgen.stop_topology()


def open_json_file(path):
    try:
        with open(path) as f:
            return json.load(f)
    except OSError:
        assert False, "Could not read file {}".format(path)


def check_rib(name, cmd, expected_file):
    """Poll until vtysh JSON output matches expected_file (partial match)."""

    def _check():
        tgen = get_topogen()
        router = tgen.gears[name]
        output = json.loads(router.vtysh_cmd(cmd))
        expected = open_json_file("{}/{}".format(CWD, expected_file))
        return topotest.json_cmp(output, expected)

    logger.info('[+] check {} "{}" {}'.format(name, cmd, expected_file))
    _, result = topotest.run_and_expect(_check, None, count=60, wait=1)
    assert result is None, "RIB check failed: {}".format(result)


def check_kernel_route(router, prefix_str, vrf, must_contain, must_not_contain=None):
    """
    Poll until the kernel FIB route for prefix_str in vrf contains all strings
    in must_contain and none of the strings in must_not_contain.
    """

    def _check():
        out = router.run(
            "ip -4 route show vrf {} {}".format(vrf, prefix_str)
        )
        if not out or prefix_str.split("/")[0] not in out:
            return "prefix {} not found in kernel vrf {} FIB".format(prefix_str, vrf)
        for s in must_contain:
            if s not in out:
                return "expected '{}' in kernel route output:\n{}".format(s, out)
        for s in (must_not_contain or []):
            if s in out:
                return "unexpected '{}' found in kernel route output:\n{}".format(
                    s, out
                )
        return None

    _, result = topotest.run_and_expect(_check, None, count=60, wait=1)
    assert result is None, result


# ---------------------------------------------------------------------------
# Test 1: prerequisite — the SRv6 VPN route that is the recursive resolver
# ---------------------------------------------------------------------------


def test_srv6_vpn_route_installed():
    """2600:1000::101/128 must be installed in r1 vrf test1 with SRv6 encap."""
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    check_rib(
        "r1",
        "show ipv6 route vrf test1 json",
        "r1/ipv6_rib_test1.json",
    )


# ---------------------------------------------------------------------------
# Test 2: the bug fix — recursive NH must get SRv6 encap, not MPLS
# ---------------------------------------------------------------------------


def test_srv6_recursive_nhop_encap():
    """
    198.0.0.150/32 in r1 vrf test1 must be installed with SRv6 seg6 encap.

    The nexthop of this static route (2600:1000::101) resolves recursively
    through the SRv6 VPN route 2600:1000::101/128.  The fix in
    nexthop_set_resolved() ensures the SRv6 SID is propagated from the
    resolved nexthop (newhop->nh_srv6) to the new resolved_hop.
    """
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    check_rib(
        "r1",
        "show ip route vrf test1 json",
        "r1/ipv4_rib_test1.json",
    )


# ---------------------------------------------------------------------------
# Test 3: kernel FIB must show encap seg6, NOT encap mpls
# ---------------------------------------------------------------------------


def test_kernel_route_encap_is_seg6():
    """
    The kernel FIB for 198.0.0.150 in vrf test1 must use encap seg6 and must
    not have any MPLS encapsulation.  This directly mirrors what was reported
    in the bug: 'ip route show vrf test1 198.0.0.150' showed 'encap mpls'
    instead of 'encap seg6'.
    """
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]
    check_kernel_route(
        r1,
        "198.0.0.150",
        "test1",
        must_contain=["encap seg6", EXPECTED_SID],
        must_not_contain=["encap mpls"],
    )


# ---------------------------------------------------------------------------
# Test 4: verify the SID on the resolved route matches the VPN route's SID
# ---------------------------------------------------------------------------


def test_recursive_sid_matches_vpn_sid():
    """
    The SID installed for 198.0.0.150/32 must be the same SID that was
    assigned to 2600:1000::101/128 by r2.  This guards against the bug
    variant where SRv6 encap is present but the wrong SID is used.
    """
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]

    def _extract_sid(output, prefix):
        """Return the first seg6 SID found in 'ip route show' text output."""
        import re

        m = re.search(r"segs \d+ \[ ([^\]]+) \]", output)
        if m:
            return m.group(1).strip()
        return None

    def _check():
        vpn_out = r1.run("ip -6 route show vrf test1 2600:1000::101")
        static_out = r1.run("ip -4 route show vrf test1 198.0.0.150")

        vpn_sid = _extract_sid(vpn_out, "2600:1000::101")
        static_sid = _extract_sid(static_out, "198.0.0.150")

        if vpn_sid is None:
            return "SRv6 SID not found in 2600:1000::101 kernel route: {}".format(
                vpn_out
            )
        if static_sid is None:
            return "SRv6 SID not found in 198.0.0.150 kernel route: {}".format(
                static_out
            )
        if vpn_sid != static_sid:
            return (
                "SID mismatch: 2600:1000::101 uses {} but 198.0.0.150 uses {}"
                .format(vpn_sid, static_sid)
            )
        return None

    _, result = topotest.run_and_expect(_check, None, count=60, wait=1)
    assert result is None, result


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
