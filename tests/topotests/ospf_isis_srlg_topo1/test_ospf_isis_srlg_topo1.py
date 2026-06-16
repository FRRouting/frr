#!/usr/bin/env python
# SPDX-License-Identifier: ISC

#
# test_ospf_isis_srlg_topo1.py
# Part of NetDEF Topology Tests
#
# Copyright (c) 2026 by Vadim Semenov
#

"""
test_ospf_isis_srlg_topo1.py: Test advertisement and reception of Shared Risk
Link Group (SRLG) information in OSPF-TE (RFC 4203) and IS-IS (RFC 5307 / RFC
6119).

Two routers are connected by a single dual-stack (IPv4 + IPv6) point-to-point
link.  Each router is configured with a couple of SRLG values under the
link-params of its interface.  The test checks that:

  * OSPF advertises the SRLG sub-TLV in its MPLS-TE opaque LSA and that the
    neighbour parses and displays it from the LSDB.
  * IS-IS advertises the GMPLS SRLG TLV 138 (IPv4) and the IPv6 SRLG TLV 139
    and that the neighbour parses and displays them from the LSDB.

          +------------+                   +------------+
          |            | r1-eth0   r2-eth0 |            |
          |     R1     +-------------------+     R2     |
          | 10.0.255.1 |   10.0.1.0/24     | 10.0.255.2 |
          |            | 2001:db8:1::/64   |            |
          +------------+                   +------------+
"""

import os
import sys
from functools import partial

# Save the Current Working Directory to find configuration files.
CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

# pylint: disable=C0413
# Import topogen and topotest helpers
from lib import topotest
from lib.topogen import Topogen, TopoRouter, get_topogen
from lib.topolog import logger

# and Finally pytest
import pytest

pytestmark = [pytest.mark.ospfd, pytest.mark.isisd]


def build_topo(tgen):
    "Build function"

    # Create 2 routers
    for routern in range(1, 3):
        tgen.add_router("r{}".format(routern))

    # Interconnect router 1 and 2 with a single link
    switch = tgen.add_switch("s1")
    switch.add_link(tgen.gears["r1"])
    switch.add_link(tgen.gears["r2"])


def setup_module(mod):
    "Sets up the pytest environment"

    logger.info("\n\n---- Starting OSPF/IS-IS SRLG tests ----\n")

    tgen = Topogen(build_topo, mod.__name__)
    tgen.start_topology()

    router_list = tgen.routers()

    for rname, router in router_list.items():
        router.load_config(
            TopoRouter.RD_ZEBRA, os.path.join(CWD, "{}/zebra.conf".format(rname))
        )
        router.load_config(
            TopoRouter.RD_OSPF, os.path.join(CWD, "{}/ospfd.conf".format(rname))
        )
        router.load_config(
            TopoRouter.RD_ISIS, os.path.join(CWD, "{}/isisd.conf".format(rname))
        )

    # Initialize all routers.
    tgen.start_router()


def teardown_module():
    "Teardown the pytest environment"

    tgen = get_topogen()
    tgen.stop_topology()

    logger.info("\n\n---- OSPF/IS-IS SRLG tests End ----\n")


def setup_testcase(msg):
    "Setup test case"

    logger.info(msg)
    tgen = get_topogen()

    # Skip if previous fatal error condition is raised
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    return tgen


def expect_json(tgen, rname, command, expected):
    """Run "command" on "rname" and compare its JSON output against "expected"
    (a subset match, retried for at most ~120s)."""

    logger.info('Checking "%s" JSON output of router "%s"', command, rname)

    test_func = partial(topotest.router_json_cmp, tgen.gears[rname], command, expected)
    _, result = topotest.run_and_expect(test_func, None, count=60, wait=2)
    assertmsg = (
        '"{}" JSON output of router "{}" did not match the expected SRLG state'.format(
            command, rname
        )
    )
    assert result is None, assertmsg


# Expected OSPF MPLS-TE opaque LSA carrying R1's SRLG sub-TLV. Both routers see
# this LSA in their LSDB, so the same subset matches on the originator (R1) and
# the receiver (R2).
OSPF_SRLG = {
    "areaLocalOpaqueLsa": {
        "areas": {
            "0.0.0.0": [
                {"opaqueValues": {"teLink": {"sharedRiskLinkGroups": [100, 200]}}}
            ]
        }
    }
}

# Same OSPF LSA after R1's SRLG values are removed: the TE link is still
# advertised but the SRLG sub-TLV is gone (key absent).
OSPF_SRLG_GONE = {
    "areaLocalOpaqueLsa": {
        "areas": {
            "0.0.0.0": [{"opaqueValues": {"teLink": {"sharedRiskLinkGroups": None}}}]
        }
    }
}

# Expected IS-IS LSP of R1 as seen by R2, carrying the GMPLS SRLG TLV 138 (IPv4)
# and the IPv6 SRLG TLV 139.
ISIS_SRLG = {
    "areas": [
        {
            "levels": [
                {
                    "id": 2,
                    "lsps": [
                        {
                            "lsp": {"id": "r1.00-00"},
                            "srlg": [
                                {
                                    "interfaceAddress": "10.0.1.1",
                                    "neighborAddress": "10.0.1.2",
                                    "values": [100, 200],
                                }
                            ],
                            "srlgIpv6": [
                                {
                                    "interfaceAddress": "2001:db8:1::1",
                                    "neighborAddress": "2001:db8:1::2",
                                    "values": [100, 200],
                                }
                            ],
                        }
                    ],
                }
            ]
        }
    ]
}

# Same IS-IS LSP after R1's SRLG values are removed: both SRLG TLVs are gone.
ISIS_SRLG_GONE = {
    "areas": [
        {
            "levels": [
                {
                    "id": 2,
                    "lsps": [
                        {"lsp": {"id": "r1.00-00"}, "srlg": None, "srlgIpv6": None}
                    ],
                }
            ]
        }
    ]
}


def test_ospf_srlg_originated():
    "Check that R1 originates the SRLG sub-TLV in its MPLS-TE opaque LSA"

    tgen = setup_testcase("Test OSPF SRLG origination on R1")

    expect_json(tgen, "r1", "show ip ospf database opaque-area json", OSPF_SRLG)


def test_ospf_srlg_received():
    "Check that R2 parses and displays R1's SRLG sub-TLV from its LSDB"

    tgen = setup_testcase("Test OSPF SRLG reception on R2")

    expect_json(tgen, "r2", "show ip ospf database opaque-area json", OSPF_SRLG)


def test_isis_srlg_received():
    "Check that R2 parses R1's IS-IS GMPLS (TLV 138) and IPv6 (TLV 139) SRLG"

    tgen = setup_testcase("Test IS-IS SRLG reception on R2")

    expect_json(tgen, "r2", "show isis database detail r1.00-00 json", ISIS_SRLG)


def test_srlg_removed():
    "Remove R1's SRLG values and verify they disappear from R2's LSDB"

    tgen = setup_testcase("Test SRLG removal propagation")

    tgen.net["r1"].cmd(
        'vtysh -c "conf t" -c "interface r1-eth0" -c "link-params"'
        ' -c "no srlg 100" -c "no srlg 200"'
    )

    # OSPF: the TE link LSA remains but no longer carries the SRLG sub-TLV.
    expect_json(tgen, "r2", "show ip ospf database opaque-area json", OSPF_SRLG_GONE)

    # IS-IS: R1's LSP no longer carries the SRLG TLVs.
    expect_json(tgen, "r2", "show isis database detail r1.00-00 json", ISIS_SRLG_GONE)


def test_memory_leak():
    "Run the memory leak test and report results."

    tgen = get_topogen()
    if not tgen.is_memleak_enabled():
        pytest.skip("Memory leak test/report is disabled")

    tgen.report_memory_leaks()


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
