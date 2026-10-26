#!/usr/bin/env python
# SPDX-License-Identifier: ISC
#
# Copyright (c) 2026 by Demetrius Cassidy
#

"""
Run the 6VPE and 6PE checks of test_zebra_6vpe_mapped_nexthop.py with
kernel nexthop objects disabled ('no zebra nexthop kernel enable'), so
zebra encodes the IPv4-mapped gateways inline in each route.
"""

import sys

import pytest

# The tests run in the order they are imported.
# pylint: disable=C0413,W0611
from .test_zebra_6vpe_mapped_nexthop import (
    setup_routers,
    skip_on_failure,
    teardown_module,
    test_isis_sr_transport,
    test_bgp_vpnv6_mapped_nexthop,
    test_zebra_6vpe_route_installed,
    test_kernel_6vpe_route,
    test_vpnv6_ping,
    test_vpnv4_ping,
    test_6pe_connected_route,
    test_6pe_label_swap,
    test_memory_leak,
)

pytestmark = [pytest.mark.bgpd, pytest.mark.isisd]


def setup_module(mod):
    setup_routers(mod, nexthop_objects=False)


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
