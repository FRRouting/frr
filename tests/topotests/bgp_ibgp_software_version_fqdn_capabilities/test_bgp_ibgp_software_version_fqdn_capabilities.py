#!/usr/bin/env python
# SPDX-License-Identifier: ISC

# Copyright (c) 2025 by
# Donatas Abraitis <donatas@opensourcerouting.org>
#

import os
import re
import sys
import json
import pytest
import functools

pytestmark = [pytest.mark.bgpd]

CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

# pylint: disable=C0413
from lib import topotest
from lib.topogen import Topogen, get_topogen


def setup_module(mod):
    topodef = {"s1": ("r1", "r2")}
    tgen = Topogen(topodef, mod.__name__)
    tgen.start_topology()

    router_list = tgen.routers()

    for rname, router in router_list.items():
        router.load_frr_config(os.path.join(CWD, "{}/frr.conf".format(rname)))

    tgen.start_router()


def teardown_module(mod):
    tgen = get_topogen()
    tgen.stop_topology()


def test_bgp_software_version():
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]
    r2 = tgen.gears["r2"]

    def _bgp_converge_pre():
        output = json.loads(r2.vtysh_cmd("show bgp neighbor json"))
        expected = {
            "192.168.1.1": {
                "neighborCapabilities": {
                    "hostName": {"advHostName": "r2", "rcvHostName": None},
                    "softwareVersion": {
                        "advertisedSoftwareVersion": "*",
                        "receivedSoftwareVersion": None,
                    },
                },
            }
        }
        return topotest.json_cmp(output, expected)

    test_func = functools.partial(
        _bgp_converge_pre,
    )
    _, result = topotest.run_and_expect(test_func, None, count=30, wait=1)
    assert (
        result is None
    ), "Seen software version and fqdn capabilities, but not expected"

    # Now enable software version and fqdn advertisement on r1
    r1.vtysh_cmd(
        """
    configure terminal
     router bgp
      neighbor 192.168.1.2 capability software-version
      neighbor 192.168.1.2 capability fqdn
    do clear ip bgp 192.168.1.2
                 """
    )

    def _bgp_converge_post():
        output = json.loads(r2.vtysh_cmd("show bgp neighbor json"))
        expected = {
            "192.168.1.1": {
                "neighborCapabilities": {
                    "hostName": {"advHostName": "r2", "rcvHostName": "r1"},
                    "softwareVersion": {
                        "advertisedSoftwareVersion": "*",
                        "receivedSoftwareVersion": "*",
                    },
                },
            }
        }
        return topotest.json_cmp(output, expected)

    test_func = functools.partial(
        _bgp_converge_post,
    )
    _, result = topotest.run_and_expect(test_func, None, count=30, wait=1)
    assert result is None, "Can't see software version and fqdn capabilities"


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
