#!/usr/bin/env python
# SPDX-License-Identifier: ISC

"""
test_bgp_bmp_enhe.py: BMP route monitoring of IPv4 unicast routes that have
an IPv6 next hop (extended next-hop encoding, RFC 8950).

                                   numbered IPv6    +--------+
    +----------+       +--------+-------------------| r2enhe |
    | bmp1enhe |-------| r1enhe |                   +--------+
    +----------+       +--------+-------------------+--------+
                                   unnumbered       | r3enhe |
                                                    +--------+

r2enhe and r3enhe send IPv4 prefixes to r1enhe over IPv6-only sessions with
the extended next-hop capability negotiated, so the routes have an IPv6 next
hop and bgpd carries them in MP_REACH_NLRI instead of using the legacy
NEXT_HOP attribute. The BGP UPDATEs in r1enhe's BMP route monitoring
messages must do the same for the pre-policy, post-policy and loc-rib views,
otherwise they carry no next hop at all.
"""

import ipaddress
import os
import sys
import pytest

# Save the Current Working Directory to find configuration files.
CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join("../"))
sys.path.append(os.path.join("../lib/"))

# pylint: disable=C0413
# Import topogen and topotest helpers
from lib import topotest
from lib.bgp import bgp_configure_prefixes
from .bgpbmp import BMPSequenceContext, bmp_update_seq, get_bmp_messages
from lib.topogen import Topogen, get_topogen

pytestmark = [pytest.mark.bgpd]

POLICIES = ("rib-in-pre-policy", "rib-in-post-policy", "loc-rib")

# announcing router: (ASN, prefix)
ANNOUNCEMENTS = {
    "r2enhe": (65502, "203.0.113.2/32"),
    "r3enhe": (65503, "203.0.113.3/32"),
}

R2_NEXTHOP = "2001:db8:12::2"

bmp_seq_context = BMPSequenceContext()


def build_topo(tgen):
    tgen.add_router("r1enhe")
    tgen.add_router("r2enhe")
    tgen.add_router("r3enhe")
    tgen.add_bmp_server("bmp1enhe", ip="192.0.2.10", defaultRoute="via 192.0.2.1")

    switch = tgen.add_switch("s1")
    switch.add_link(tgen.gears["r1enhe"])
    switch.add_link(tgen.gears["bmp1enhe"])

    tgen.add_link(
        tgen.gears["r1enhe"], tgen.gears["r2enhe"], "r1enhe-eth1", "r2enhe-eth0"
    )
    tgen.add_link(
        tgen.gears["r1enhe"], tgen.gears["r3enhe"], "r1enhe-eth2", "r3enhe-eth0"
    )


def setup_module(mod):
    tgen = Topogen(build_topo, mod.__name__)
    tgen.start_topology()

    for router in tgen.routers().values():
        router.load_frr_config(
            daemons=["zebra", ("bgpd", "-M bmp")],
        )

    tgen.start_router()

    for bmp_name, server in tgen.get_bmp_servers().items():
        server.start(log_file=os.path.join(tgen.logdir, bmp_name, "bmp.log"))


def teardown_module(_mod):
    tgen = get_topogen()
    tgen.stop_topology()


def _bmp_log_file():
    tgen = get_topogen()
    return os.path.join(tgen.logdir, "bmp1enhe", "bmp.log")


def _route_messages(bmp_log_type, prefix, peer_asn):
    """
    Return the BMP route monitoring messages logged after the recorded
    sequence baseline for the given message type and prefix, in the loc-rib
    view or from the peer with the given ASN.

    r1enhe advertises each prefix to the other peer, which sends it back.
    r1enhe rejects that copy because of the AS path loop, but it is still
    reported for that peer, so it is left out.
    """
    tgen = get_topogen()
    baseline = bmp_seq_context.get_seq()
    messages = get_bmp_messages(tgen.gears["bmp1enhe"], _bmp_log_file())
    return [
        m
        for m in messages
        if m.get("seq", 0) > baseline
        and m.get("bmp_log_type") == bmp_log_type
        and m.get("ip_prefix") == prefix
        and (m.get("policy") == "loc-rib" or m.get("peer_asn") == peer_asn)
    ]


def _is_r2_nexthop(msg):
    return msg.get("nxhp_ip") == R2_NEXTHOP


def _is_link_local_nexthop(msg):
    for key in ("nxhp_ip", "nxhp_link-local"):
        try:
            if ipaddress.ip_address(msg.get(key, "")).is_link_local:
                return True
        except ValueError:
            continue
    return False


def test_bgp_convergence():
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    expected = {
        "peers": {
            R2_NEXTHOP: {"state": "Established"},
            "r1enhe-eth2": {"state": "Established"},
        }
    }

    def _converged():
        output = tgen.gears["r1enhe"].vtysh_cmd(
            "show bgp ipv4 unicast summary json", isjson=True
        )
        return topotest.json_cmp(output, expected)

    _, result = topotest.run_and_expect(_converged, None, count=130, wait=1)
    assert result is None, "BGP sessions of r1enhe did not come up"


def test_bmp_server_logging():
    """
    Wait for the BMP collector to start logging (session established).
    """
    tgen = get_topogen()

    def _log_file_exists():
        output = tgen.gears["bmp1enhe"].run(
            "ls {}".format(os.path.join(tgen.logdir, "bmp1enhe"))
        )
        return "bmp.log" in output

    success, _ = topotest.run_and_expect(_log_file_exists, True, count=30, wait=1)
    assert success, "The BMP server is not logging"


def test_bmp_ipv4_enhe_update():
    """
    Announce one IPv4 prefix from each ENHE peer and check that every view
    reports it in an IPv4 unicast MP_REACH_NLRI with the IPv6 next hop.
    """
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    bmp_update_seq(tgen.gears["bmp1enhe"], _bmp_log_file(), bmp_seq_context)

    for router, (asn, prefix) in ANNOUNCEMENTS.items():
        bgp_configure_prefixes(tgen.gears[router], asn, "unicast", [prefix])

    checks = {
        ANNOUNCEMENTS["r2enhe"]: (_is_r2_nexthop, R2_NEXTHOP),
        ANNOUNCEMENTS["r3enhe"]: (_is_link_local_nexthop, "a link-local address"),
    }

    def _updates_ok():
        for (asn, prefix), (nexthop_ok, nexthop_desc) in checks.items():
            messages = _route_messages("update", prefix, asn)
            policies = {m.get("policy") for m in messages}
            missing = [p for p in POLICIES if p not in policies]
            if missing:
                return "no {} update logged for {}".format(", ".join(missing), prefix)

            for m in messages:
                if m.get("afi") != 1 or m.get("safi") != 1:
                    return "{} update for {} not in an IPv4 unicast MP_REACH_NLRI: {}".format(
                        m.get("policy"), prefix, m
                    )
                if not nexthop_ok(m):
                    return "{} update for {} does not have {} as next hop: {}".format(
                        m.get("policy"), prefix, nexthop_desc, m
                    )
        return True

    success, result = topotest.run_and_expect(_updates_ok, True, count=30, wait=1)
    assert success, result


def test_bmp_ipv4_enhe_withdraw():
    """
    Withdraw the prefixes and check that every view reports the withdrawal.
    """
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    bmp_update_seq(tgen.gears["bmp1enhe"], _bmp_log_file(), bmp_seq_context)

    for router, (asn, prefix) in ANNOUNCEMENTS.items():
        bgp_configure_prefixes(
            tgen.gears[router], asn, "unicast", [prefix], update=False
        )

    def _withdrawals_ok():
        for asn, prefix in ANNOUNCEMENTS.values():
            messages = _route_messages("withdraw", prefix, asn)
            policies = {m.get("policy") for m in messages}
            missing = [p for p in POLICIES if p not in policies]
            if missing:
                return "no {} withdraw logged for {}".format(", ".join(missing), prefix)
        return True

    success, result = topotest.run_and_expect(_withdrawals_ok, True, count=30, wait=1)
    assert success, result


def test_memory_leak():
    "Run the memory leak test and report results."
    tgen = get_topogen()
    if not tgen.is_memleak_enabled():
        pytest.skip("Memory leak test/report is disabled")

    tgen.report_memory_leaks()


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
