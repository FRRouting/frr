#!/usr/bin/env python
# SPDX-License-Identifier: ISC
#
# Copyright 2026 6WIND S.A.
#

"""
Check that an IS-IS router without any IPv4 address advertises its SRGB
when an MPLS-TE router-address is configured (RFC 7981 appendix A), with
the IPv6 TE Router ID sub-TLV when the Router ID is 0.0.0.0.

    lo: 2001:db8::1      lo: 2001:db8::2      lo: 2001:db8::3
       +-----+              +-----+              +-----+
       | pe1 +--------------+  p  +--------------+ pe2 |
       +-----+              +-----+              +-----+

pe1 needs the SRGB of its nexthop p to compute the label of 2001:db8::3/128.
"""

import os
import sys

import pytest

CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

# pylint: disable=C0413
from lib import topotest
from lib.common_config import retry, step
from lib.topogen import Topogen, get_topogen

pytestmark = [pytest.mark.isisd]


def build_topo(tgen):
    for router in ("pe1", "p", "pe2"):
        tgen.add_router(router)

    switch = tgen.add_switch("s1")
    switch.add_link(tgen.gears["pe1"])
    switch.add_link(tgen.gears["p"])

    switch = tgen.add_switch("s2")
    switch.add_link(tgen.gears["p"])
    switch.add_link(tgen.gears["pe2"])


def setup_module(mod):
    tgen = Topogen(build_topo, mod.__name__)
    tgen.start_topology()

    for router in tgen.routers().values():
        router.load_frr_config()

    tgen.start_router()


def teardown_module():
    get_topogen().stop_topology()


@retry(retry_timeout=60)
def check_pe1_router_cap_and_label(router_cap, labels):
    pe1 = get_topogen().gears["pe1"]

    output = pe1.vtysh_cmd("show isis database detail p.00-00 json", isjson=True)
    expected = {
        "areas": [
            {
                "levels": [
                    {
                        "id": 2,
                        "lsps": [
                            {"lsp": {"id": "p.00-00"}, "routerCapability": router_cap}
                        ],
                    }
                ]
            }
        ]
    }
    result = topotest.json_cmp(output, expected)
    if result is not None:
        return "p LSP: {}".format(result)

    output = pe1.vtysh_cmd("show ipv6 route 2001:db8::3/128 json", isjson=True)
    expected = {
        "2001:db8::3/128": [
            {"protocol": "isis", "selected": True, "nexthops": [{"labels": labels}]}
        ]
    }
    result = topotest.json_cmp(output, expected)
    if result is not None:
        return "pe1 route to pe2: {}".format(result)

    return True


def test_isis_no_router_id():
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    step("Without router-id, p sends no router capability: no label to pe2")
    result = check_pe1_router_cap_and_label(None, None)
    assert result is True, result


def test_isis_mpls_te_ipv6_router_address():
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    step("Set an IPv6 TE router-address on p: router capability with id 0.0.0.0")
    tgen.gears["p"].vtysh_cmd(
        """
        configure terminal
         router isis 1
          mpls-te on
          mpls-te router-address ipv6 2001:db8::2
        """
    )
    result = check_pe1_router_cap_and_label(
        {"id": "0.0.0.0", "ipv6TeRouterId": "2001:db8::2"}, [20003]
    )
    assert result is True, result


def test_isis_mpls_te_ipv4_router_address():
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    step("Set an IPv4 TE router-address on p: router capability with this id")
    tgen.gears["p"].vtysh_cmd(
        """
        configure terminal
         router isis 1
          mpls-te router-address 10.0.0.2
        """
    )
    result = check_pe1_router_cap_and_label(
        {"id": "10.0.0.2", "ipv6TeRouterId": "2001:db8::2"}, [20003]
    )
    assert result is True, result


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
