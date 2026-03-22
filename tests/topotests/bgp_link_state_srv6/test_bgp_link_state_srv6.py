#!/usr/bin/env python
# SPDX-License-Identifier: ISC
#
# Copyright (c) 2026 by Carmine Scarpitta
#
"""
Test BGP Link-State SRv6 Extensions (RFC 9514).

The test creates a five-router IS-IS L2 domain and verifies that all BGP-LS
NLRI types -- Node, IPv6 Prefix (SRv6 locators), SRv6 SID, and Link -- are
correctly originated by the producer (r1) and received by the consumer (rr),
together with their SRv6-specific BGP-LS attributes (RFC 9514).

Topology
--------

                         +---------+
                         |   rr    | (BGP-LS Consumer)
                         +---------+
                              |eth-r1
                              |
                              |eth-rr
                         +---------+
                         |   r1    | (BGP-LS Producer)
                         +---------+
                         /         \
                    eth-r2         eth-r3
                       /             \
                      /               \
                     /                 \
                    /                   \
                eth-r1                 eth-r1
                  /                       \
         +---------+                     +---------+
         |         |                     |         |
         |   r2    |                     |   r3    |
         |         |                     |         |
         +---------+                     +---------+
     eth-r4-1|  |eth-r4-2            eth-r5-1|  |eth-r5-2
             |  |                            |  |
     eth-r2-1|  |eth-r2-2            eth-r3-1|  |eth-r3-2
         +---------+                     +---------+
         |         |                     |         |
         |   r4    |  eth-r5     eth-r4  |   r5    |
         |         +---------------------+         |
         +---------+                     +---------+
"""

import os
import sys
import json
import re
import pytest
import functools

# pylint: disable=C0413
from lib import topotest
from lib.topogen import Topogen, TopoRouter, get_topogen
from lib.topolog import logger
from lib.common_config import create_interface_in_kernel, required_linux_kernel_version

pytestmark = [pytest.mark.bgpd, pytest.mark.isisd]

CWD = os.path.dirname(os.path.realpath(__file__))


_ENDX_SID_FUNC_RE = re.compile(r":e[0-9a-f]{3}::", re.IGNORECASE)


def _normalize_dynamic_srv6_sid_fields(obj):
    """Normalize run-to-run dynamic SRv6 End.X/LAN-End.X SID function bits."""
    if isinstance(obj, dict):
        for key, value in obj.items():
            if key in ("srv6EndxSids", "srv6LanEndxSids") and isinstance(value, list):
                for sid_obj in value:
                    if isinstance(sid_obj, dict) and "sid" in sid_obj:
                        sid = sid_obj["sid"]
                        if isinstance(sid, str):
                            sid_obj["sid"] = _ENDX_SID_FUNC_RE.sub(":e000::", sid)
            else:
                _normalize_dynamic_srv6_sid_fields(value)
    elif isinstance(obj, list):
        for item in obj:
            _normalize_dynamic_srv6_sid_fields(item)


# ---------------------------------------------------------------------------
# Topology definition
# ---------------------------------------------------------------------------


def build_topo(tgen):
    """Instantiate the IS-IS topology (mirrors test_isis_srv6_topo1 without rt6/dst)."""
    for rname in ["r1", "r2", "r3", "r4", "r5"]:
        tgen.add_router(rname)
    tgen.add_router("rr")

    # r1/eth-r2 <-> r2/eth-r1  (10.0.1.0/24)
    tgen.add_link(tgen.gears["r1"], tgen.gears["r2"], "eth-r2", "eth-r1")

    # r1/eth-r3 <-> r3/eth-r1  (10.0.7.0/24)
    tgen.add_link(tgen.gears["r1"], tgen.gears["r3"], "eth-r3", "eth-r1")

    # r2/eth-r4-1 <-> r4/eth-r2-1  (10.0.2.0/24)
    switch = tgen.add_switch("s2")
    switch.add_link(tgen.gears["r2"], nodeif="eth-r4-1")
    switch.add_link(tgen.gears["r4"], nodeif="eth-r2-1")

    # r2/eth-r4-2 <-> r4/eth-r2-2  (10.0.3.0/24)
    switch = tgen.add_switch("s3")
    switch.add_link(tgen.gears["r2"], nodeif="eth-r4-2")
    switch.add_link(tgen.gears["r4"], nodeif="eth-r2-2")

    # r3/eth-r5-1 <-> r5/eth-r3-1  (10.0.4.0/24)
    switch = tgen.add_switch("s4")
    switch.add_link(tgen.gears["r3"], nodeif="eth-r5-1")
    switch.add_link(tgen.gears["r5"], nodeif="eth-r3-1")

    # r3/eth-r5-2 <-> r5/eth-r3-2  (10.0.5.0/24)
    switch = tgen.add_switch("s5")
    switch.add_link(tgen.gears["r3"], nodeif="eth-r5-2")
    switch.add_link(tgen.gears["r5"], nodeif="eth-r3-2")

    # r4/eth-r5 <-> r5/eth-r4  (10.0.6.0/24)
    switch = tgen.add_switch("s6")
    switch.add_link(tgen.gears["r4"], nodeif="eth-r5")
    switch.add_link(tgen.gears["r5"], nodeif="eth-r4")

    # r1/eth-rr <-> rr/eth-r1  (BGP only, 10.0.0.0/24)
    switch = tgen.add_switch("s7")
    switch.add_link(tgen.gears["r1"], nodeif="eth-rr")
    switch.add_link(tgen.gears["rr"], nodeif="eth-r1")

    # Add dummy sr0 interface on each SRv6 router for uN SID installation
    for idx, rname in enumerate(["r1", "r2", "r3", "r4", "r5"], start=1):
        create_interface_in_kernel(
            tgen,
            rname,
            "sr0",
            "fcbb:bbbb:{}::1".format(idx),
            netmask="128",
            create=True,
        )


def setup_module(mod):
    """Build the topology, load FRR configs, and start all routers."""
    result = required_linux_kernel_version("4.10")
    if result is not True:
        pytest.skip("Kernel requirements are not met")

    tgen = Topogen(build_topo, mod.__name__)
    tgen.start_topology()
    for rname, router in tgen.routers().items():
        router.load_frr_config(os.path.join(CWD, "{}/frr.conf".format(rname)))
    tgen.start_router()


def teardown_module(mod):
    """Stop all routers and tear down the topology."""
    get_topogen().stop_topology()


# ---------------------------------------------------------------------------
# Test functions
# ---------------------------------------------------------------------------


def test_isis_convergence():
    """All IS-IS L2 adjacencies converge on every router."""
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    logger.info("Checking IS-IS convergence on r1/r2/r3/r4/r5")

    for rname in ["r1", "r2", "r3", "r4", "r5"]:
        router = tgen.gears[rname]
        expected = json.loads(
            open(os.path.join(CWD, "{}/isis_adj.json".format(rname))).read()
        )
        test_func = functools.partial(
            topotest.router_json_cmp, router, "show isis neighbor json", expected
        )
        _, result = topotest.run_and_expect(test_func, None, count=60, wait=1)
        assert result is None, '"{}" IS-IS adj not established: {}'.format(
            rname, result
        )


def test_bgp_convergence():
    """The BGP Link-State session between r1 and rr reaches Established."""
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    logger.info("Checking BGP-LS session: r1 <-> rr")

    for rname, reffile in [
        ("r1", "r1/bgp_neighbor.json"),
        ("rr", "rr/bgp_neighbor.json"),
    ]:
        router = tgen.gears[rname]
        expected = json.loads(open(os.path.join(CWD, reffile)).read())
        test_func = functools.partial(
            topotest.router_json_cmp, router, "show bgp neighbor json", expected
        )
        _, result = topotest.run_and_expect(test_func, None, count=60, wait=1)
        assert result is None, '"{}" BGP session not established: {}'.format(
            rname, result
        )


def test_bgp_ls_capability():
    """Both r1 and rr advertise and receive the BGP Link-State AFI/SAFI capability."""
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    logger.info("Checking BGP-LS capability negotiation on r1 and rr")

    for rname, reffile in [
        ("r1", "r1/bgp_capability.json"),
        ("rr", "rr/bgp_capability.json"),
    ]:
        router = tgen.gears[rname]
        expected = json.loads(open(os.path.join(CWD, reffile)).read())
        test_func = functools.partial(
            topotest.router_json_cmp, router, "show bgp neighbor json", expected
        )
        _, result = topotest.run_and_expect(test_func, None, count=30, wait=1)
        assert result is None, '"{}" BGP-LS capability not negotiated: {}'.format(
            rname, result
        )


def _check_all_nlris(router, router_name):
    """Assert that *router* holds the expected SRv6-related BGP-LS NLRIs."""
    expected = json.loads(open(os.path.join(CWD, "bgp_ls_nlri_srv6.json")).read())
    _normalize_dynamic_srv6_sid_fields(expected)

    def _cmp_nlri_json():
        output = router.vtysh_cmd("show bgp link-state link-state json", isjson=True)
        _normalize_dynamic_srv6_sid_fields(output)
        return topotest.json_cmp(output, expected)

    test_func = _cmp_nlri_json
    _, result = topotest.run_and_expect(test_func, None, count=120, wait=2)
    assert result is None, "{}: BGP-LS NLRI/attribute mismatch: {}".format(
        router_name, result
    )


def test_bgp_ls_producer():
    """r1 originates the expected SRv6-related BGP-LS NLRIs and attributes."""
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)
    logger.info("Checking all BGP-LS NLRIs + SRv6 attributes on producer r1")
    _check_all_nlris(tgen.gears["r1"], "r1")


def test_bgp_ls_consumer():
    """rr receives the expected SRv6-related BGP-LS NLRIs and attributes."""
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)
    logger.info("Checking all BGP-LS NLRIs + SRv6 attributes on consumer rr")
    _check_all_nlris(tgen.gears["rr"], "rr")


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
