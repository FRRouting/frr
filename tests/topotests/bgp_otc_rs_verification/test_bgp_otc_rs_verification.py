#!/usr/bin/env python
# SPDX-License-Identifier: ISC
#
# Copyright (c) 2026 by Donatas Abraitis <donatas@opensourcerouting.org>
#

"""
Test the OTC verification for the routes received from a Route Server, as
described in draft-herdes-idr-otc-rs-verification.

    r1 (65001) --- r2 (65002) --- r3 (65003) --- r4 (65004)
      provider       no roles       rs-client      rs-server
                                    rs-client

r2 is a Route Server that does not implement RFC 9234, thus it accepts a route
that already carries the OTC Attribute (65001, added by r1) and relays it down
to its RS-Client r3. r3 has to consider it ineligible, because the value is not
equal to the AS number of r2.

r4 is a Route Server that does implement RFC 9234, hence the routes it sends
carry the OTC Attribute with its own AS number, and those have to be accepted.
"""

import json
import os
import sys
import pytest
import functools

CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

# pylint: disable=C0413
from lib import topotest
from lib.topogen import Topogen, get_topogen
from lib.common_config import step

pytestmark = [pytest.mark.bgpd]


def setup_module(mod):
    topodef = {"s1": ("r1", "r2"), "s2": ("r2", "r3"), "s3": ("r3", "r4")}
    tgen = Topogen(topodef, mod.__name__)
    tgen.start_topology()

    for _, router in tgen.routers().items():
        router.load_frr_config(os.path.join(CWD, "{}/frr.conf".format(router.name)))

    tgen.start_router()


def teardown_module(mod):
    tgen = get_topogen()
    tgen.stop_topology()


def test_bgp_otc_rs_verification():
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r2 = tgen.gears["r2"]
    r3 = tgen.gears["r3"]

    step("Check if the non-compliant Route Server relays the leaked route")

    def _bgp_check_rs_relays_leak():
        output = json.loads(r2.vtysh_cmd("show bgp ipv4 unicast 192.0.2.1/32 json"))
        expected = {"paths": [{"valid": True, "otc": 65001}]}
        return topotest.json_cmp(output, expected)

    test_func = functools.partial(_bgp_check_rs_relays_leak)
    _, result = topotest.run_and_expect(test_func, None, count=30, wait=1)
    assert result is None, "r2 did not accept the route with an unchecked OTC"

    step("Check if the RS-Client accepts only the routes with a correct OTC")

    def _bgp_check_rs_client_routes():
        output = json.loads(r3.vtysh_cmd("show bgp ipv4 unicast json"))
        expected = {
            "routes": {
                "192.0.2.1/32": None,
                "192.0.2.2/32": [{"valid": True}],
                "192.0.2.4/32": [{"valid": True}],
            }
        }
        return topotest.json_cmp(output, expected)

    test_func = functools.partial(_bgp_check_rs_client_routes)
    _, result = topotest.run_and_expect(test_func, None, count=30, wait=1)
    assert result is None, "OTC verification for a Route Server does not work"

    step("Check if the OTC Attribute of the accepted routes is the AS of the RS")

    def _bgp_check_rs_client_otc():
        for prefix, otc in (("192.0.2.2/32", 65002), ("192.0.2.4/32", 65004)):
            output = json.loads(
                r3.vtysh_cmd("show bgp ipv4 unicast {} json".format(prefix))
            )
            expected = {"paths": [{"otc": otc}]}
            result = topotest.json_cmp(output, expected)
            if result is not None:
                return result
        return None

    test_func = functools.partial(_bgp_check_rs_client_otc)
    _, result = topotest.run_and_expect(test_func, None, count=30, wait=1)
    assert result is None, "OTC Attribute is not equal to the AS number of the RS"


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
