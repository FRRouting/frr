#!/usr/bin/env python
# SPDX-License-Identifier: ISC

#
# test_static_srv6_sids_multiple_locators.py
#
# Copyright (c) 2025 by
# Carmine Scarpitta
#

"""
test_static_srv6_sids_multiple_locators.py:
Test for SRv6 static SIDs allocated from multiple locators
"""

import os
import sys
import json
import pytest
import functools

CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

# pylint: disable=C0413
from lib import topotest
from lib.common_config import retry
from lib.topogen import Topogen, TopoRouter, get_topogen
from lib.topolog import logger

pytestmark = [pytest.mark.staticd]


def open_json_file(filename):
    try:
        with open(filename, "r") as f:
            return json.load(f)
    except IOError:
        assert False, "Could not read file {}".format(filename)


def setup_module(mod):
    # This topotest sets net.vrf.strict_mode during setup. That sysctl is
    # available only after the VRF module is loaded; if the module is not loaded,
    # the strict_mode command may fail and the test can fail later.
    # Ensure the VRF module is present and loaded before setting strict_mode.
    if not topotest.module_present("vrf"):
        pytest.skip("VRF kernel module is not available")

    tgen = Topogen({None: "r1"}, mod.__name__)
    tgen.start_topology()
    for rname, router in tgen.routers().items():
        router.run("/bin/bash {}/{}/setup.sh".format(CWD, rname))
        router.load_frr_config()
    tgen.start_router()


def teardown_module():
    tgen = get_topogen()
    tgen.stop_topology()


def test_srv6_static_sids():
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)
    router = tgen.gears["r1"]

    def _check_srv6_static_sids(router, expected_route_file):
        logger.info("checking zebra srv6 static sids")
        output = json.loads(router.vtysh_cmd("show ipv6 route static json"))
        expected = open_json_file("{}/{}".format(CWD, expected_route_file))
        return topotest.json_cmp(output, expected)

    def check_srv6_static_sids(router, expected_file):
        func = functools.partial(_check_srv6_static_sids, router, expected_file)
        _, result = topotest.run_and_expect(func, None, count=15, wait=1)
        assert result is None, "Failed"

    # FOR DEVELOPER:
    # If you want to stop some specific line and start interactive shell,
    # please use tgen.mininet_cli() to start it.

    logger.info("Test for srv6 sids configuration")
    check_srv6_static_sids(router, "expected_srv6_sids.json")


@retry(retry_timeout=15)
def check_srv6_static_sids_vrf10(router, fe11_installed):
    sid_vrf10 = [
        {
            "installed": True,
            "nexthops": [
                {
                    "interfaceName": "Vrf10",
                    "seg6local": {"action": "uDT4"},
                }
            ],
        }
    ]
    expected = {
        "fcbb:bb01:1:fe10::/64": sid_vrf10,
        "fcbb:bb01:2:fe11::/64": sid_vrf10 if fe11_installed else None,
    }

    output = json.loads(router.vtysh_cmd("show ipv6 route static json"))
    result = topotest.json_cmp(output, expected)
    if result is not None:
        return result
    return True


def test_srv6_static_sids_same_context_other_function():
    """
    Add a uDT4 SID of Vrf10 with the fe11 function on LOC2, in the block of
    the uDT4 SID of Vrf10 with the fe10 function on LOC1. Both are installed.
    """
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)
    router = tgen.gears["r1"]

    router.vtysh_cmd(
        """
        configure terminal
         segment-routing
          srv6
           static-sids
            sid fcbb:bb01:2:fe11::/64 locator LOC2 behavior uDT4 vrf Vrf10
        """
    )
    result = check_srv6_static_sids_vrf10(router, True)
    assert result is True, result


def test_srv6_static_sids_same_context_other_function_removed():
    """
    Remove the uDT4 SID of Vrf10 with the fe11 function. The uDT4 SID of
    Vrf10 with the fe10 function on LOC1 stays installed.
    """
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)
    router = tgen.gears["r1"]

    router.vtysh_cmd(
        """
        configure terminal
         segment-routing
          srv6
           static-sids
            no sid fcbb:bb01:2:fe11::/64 locator LOC2 behavior uDT4 vrf Vrf10
        """
    )
    result = check_srv6_static_sids_vrf10(router, False)
    assert result is True, result


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.loc1(args))
