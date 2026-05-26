#!/usr/bin/env python
# SPDX-License-Identifier: ISC
#
# Copyright (c) 2026 by Carmine Scarpitta

"""Topotest for BGP-LS BGP-fabric export with SRv6 locators and uN/uA SIDs."""

import os
import sys
import json
import pytest
import functools

CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

# pylint: disable=C0413
from lib import topotest
from lib.topogen import Topogen, get_topogen
from lib.topolog import logger
from lib.common_config import create_interface_in_kernel, required_linux_kernel_version

pytestmark = [pytest.mark.bgpd]


def _check_rr_srv6_nlris(rr):
    """Load expected SRv6 JSON and compare against RR's BGP-LS table."""
    expected_path = os.path.join(CWD, "rr", "expected_bgp_ls_srv6.json")
    with open(expected_path) as f:
        expected = json.load(f)
    return topotest.router_json_cmp(
        rr, "show bgp link-state link-state json", expected
    )


def build_topo(tgen):
    """Build test topology with rr collector and iBGP/eBGP peer pairs."""

    tgen.add_router("rr")
    tgen.add_router("r1")
    tgen.add_router("r2")
    tgen.add_router("r3")
    tgen.add_router("r4")

    switch = tgen.add_switch("s-rr-r1")
    switch.add_link(tgen.gears["rr"])
    switch.add_link(tgen.gears["r1"])

    switch = tgen.add_switch("s-rr-r2")
    switch.add_link(tgen.gears["rr"])
    switch.add_link(tgen.gears["r2"])

    switch = tgen.add_switch("s-rr-r3")
    switch.add_link(tgen.gears["rr"])
    switch.add_link(tgen.gears["r3"])

    switch = tgen.add_switch("s-rr-r4")
    switch.add_link(tgen.gears["rr"])
    switch.add_link(tgen.gears["r4"])

    switch = tgen.add_switch("s-r1-r2")
    switch.add_link(tgen.gears["r1"])
    switch.add_link(tgen.gears["r2"])

    switch = tgen.add_switch("s-r3-r4")
    switch.add_link(tgen.gears["r3"])
    switch.add_link(tgen.gears["r4"])

    for idx, rname in enumerate(["r1", "r2", "r3", "r4"], start=1):
        create_interface_in_kernel(
            tgen,
            rname,
            "sr0",
            "fcbb:bbbb:{}::1".format(idx),
            netmask="128",
            create=True,
        )


def setup_module(mod):
    """Set up test environment."""
    result = required_linux_kernel_version("4.10")
    if result is not True:
        pytest.skip("Kernel requirements are not met")

    tgen = Topogen(build_topo, mod.__name__)
    tgen.start_topology()

    for rname, router in tgen.routers().items():
        router.load_frr_config(os.path.join(CWD, "{}/frr.conf".format(rname)))

    tgen.start_router()


def teardown_module(mod):
    """Tear down test environment."""
    get_topogen().stop_topology()


def test_bgp_convergence():
    """Test BGP convergence."""
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    logger.info("Waiting for BGP convergence")

    for router in ["rr", "r1", "r2", "r3", "r4"]:
        logger.info("Checking BGP convergence on %s", router)
        test_func = functools.partial(
            topotest.router_json_cmp,
            tgen.gears[router],
            "show bgp summary json",
            {},
        )
        _, result = topotest.run_and_expect(test_func, None, count=60, wait=0.5)
        assert result is None, '"{}" BGP convergence failure'.format(router)


def test_bgp_ls_srv6_export():
    """Verify SRv6 NLRIs and attributes on the RR match the expected JSON."""
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    logger.info("Verifying SRv6 BGP-LS NLRIs on RR against expected JSON")

    rr = tgen.gears["rr"]
    test_func = functools.partial(_check_rr_srv6_nlris, rr)
    _, result = topotest.run_and_expect(test_func, None, count=120, wait=1)
    assert result is None, "SRv6 BGP-LS NLRI/attribute mismatch on RR: {}".format(
        result
    )

    logger.info("SRv6 BGP-LS export validated")


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
