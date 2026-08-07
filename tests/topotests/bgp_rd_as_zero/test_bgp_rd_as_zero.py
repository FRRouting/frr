#!/usr/bin/env python
# SPDX-License-Identifier: ISC

#
# test_bgp_rd_as_zero.py
# Part of NetDEF Topology Tests
#
# Copyright (c) 2026 by Olasupo Okunaiya
#

"""
test_bgp_rd_as_zero.py: a route distinguisher of the form 0:<value>
must be parsed as a Type 0 RD (AS 0), not as an IPv4 RD.

asn_str2asn() rejects AS 0, so str2prefix_rd() used to fall through to
inet_aton(), which read the "0" administrator subfield as 0.0.0.0 and
truncated the value to 16 bits. "0:1000000" was therefore stored as
"0.0.0.0:16960" (1000000 & 0xffff). This is a regression from the
introduction of AS-dot notation.

The value stays below 2^31 so it is parsed identically on 32-bit and
64-bit platforms.

A VRF route is redistributed and exported to the ipv4 vpn table with
"rd vpn export 0:1000000"; the RD shown for that route must be
0:1000000.
"""

import os
import sys
import pytest

CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

# pylint: disable=C0413
from lib import topotest
from lib.topogen import Topogen, get_topogen
from lib.topolog import logger

pytestmark = [pytest.mark.bgpd]

RD = "0:1000000"
RD_BAD = "0.0.0.0:16960"


def build_topo(tgen):
    "Build function"
    tgen.add_router("r1")


def setup_module(mod):
    "Sets up the pytest environment"
    tgen = Topogen(build_topo, mod.__name__)
    tgen.start_topology()

    r1 = tgen.gears["r1"]
    # A VRF with a connected route to redistribute into the ipv4 vpn table.
    r1.run("ip link add dummy-vrf type vrf table 1001")
    r1.run("ip link set dummy-vrf up")
    r1.run("ip link add dummy0 type dummy")
    r1.run("ip link set dummy0 master dummy-vrf")
    r1.run("ip link set dummy0 up")
    r1.run("ip addr add 192.0.2.100/32 dev dummy0")

    for rname, router in tgen.routers().items():
        router.load_frr_config(os.path.join(CWD, rname, "frr.conf"))
    tgen.start_router()


def teardown_module(_mod):
    "Teardown the pytest environment"
    tgen = get_topogen()
    tgen.stop_topology()


def _vpn_rds():
    tgen = get_topogen()
    out = tgen.gears["r1"].vtysh_cmd("show bgp ipv4 vpn json", isjson=True)
    return out.get("routes", {}).get("routeDistinguishers", {})


def _rd_present():
    rds = _vpn_rds()
    if RD in rds:
        return None
    return "RD %s not in the vpn table yet (have: %s)" % (RD, list(rds.keys()))


def test_bgp_rd_as_zero():
    "0:<32-bit-value> must be a Type 0 RD, not a truncated IPv4 RD."
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    logger.info("checking the exported route carries RD %s", RD)
    _, result = topotest.run_and_expect(_rd_present, None, count=30, wait=1)
    assert result is None, "route distinguisher was not parsed correctly (%s)" % result

    # And it must not have been misparsed to the truncated IPv4 form.
    rds = _vpn_rds()
    assert RD_BAD not in rds, "RD was misparsed as %s" % RD_BAD


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
