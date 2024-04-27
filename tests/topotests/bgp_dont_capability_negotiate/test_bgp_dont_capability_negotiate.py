#!/usr/bin/env python
# SPDX-License-Identifier: ISC

# Copyright (c) 2021 by
# Donatas Abraitis <donatas.abraitis@gmail.com>
#

"""
Test if BGP connection is established if at least one peer
sets `dont-capability-negotiate`.
"""

import os
import sys
import json
import pytest
import functools

pytestmark = [pytest.mark.bgpd]

CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

# pylint: disable=C0413
from lib import topotest
from lib.topogen import Topogen, TopoRouter, get_topogen
from lib.common_config import step


def setup_module(mod):
    topodef = {"s1": ("r1", "r2")}
    tgen = Topogen(topodef, mod.__name__)
    tgen.start_topology()

    router_list = tgen.routers()

    for i, (rname, router) in enumerate(router_list.items(), 1):
        router.load_config(
            TopoRouter.RD_ZEBRA, os.path.join(CWD, "{}/zebra.conf".format(rname))
        )
        router.load_config(
            TopoRouter.RD_BGP, os.path.join(CWD, "{}/bgpd.conf".format(rname))
        )

    tgen.start_router()


def teardown_module(mod):
    tgen = get_topogen()
    tgen.stop_topology()


def bgp_converge(router):
    output = json.loads(router.vtysh_cmd("show bgp ipv4 unicast summary json"))
    expected = {
        "peers": {
            "192.168.1.2": {
                "pfxRcd": 2,
                "pfxSnt": 2,
                "state": "Established",
                "peerState": "OK",
            }
        }
    }
    return topotest.json_cmp(output, expected)


def test_bgp_dont_capability_negotiate():
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]

    test_func = functools.partial(bgp_converge, r1)
    _, result = topotest.run_and_expect(test_func, None, count=60, wait=0.5)
    assert result is None, "Can't converge with dont-capability-negotiate"


def test_bgp_check_fqdn():
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]
    r2 = tgen.gears["r2"]

    def _bgp_check_fqdn(fqdn=None):
        output = json.loads(r1.vtysh_cmd("show bgp ipv4 unicast 172.16.16.1/32 json"))
        expected = {
            "paths": [
                {
                    "nexthops": [
                        {
                            "hostname": fqdn,
                        }
                    ],
                    "peer": {
                        "hostname": fqdn,
                    },
                }
            ]
        }
        return topotest.json_cmp(output, expected)

    step("Enable all capabilities")
    r1.vtysh_cmd(
        """
    configure terminal
        router bgp
            address-family ipv4 unicast
                no neighbor 192.168.1.2 dont-capability-negotiate
    end
    clear bgp 192.168.1.2
    """
    )

    step("Wait to converge")
    test_func = functools.partial(bgp_converge, r1)
    _, result = topotest.run_and_expect(test_func, None, count=60, wait=0.5)
    assert result is None, "Can't converge with all capabilities"

    step("Make sure FQDN capability is set")
    test_func = functools.partial(_bgp_check_fqdn, "r2")
    _, result = topotest.run_and_expect(test_func, None, count=60, wait=0.5)
    assert result is None, "FQDN capability enabled, but r1 can't see it"

    step("Disable sending any capabilities from r2")
    r2.vtysh_cmd(
        """
    configure terminal
        router bgp
            address-family ipv4 unicast
                neighbor 192.168.1.1 dont-capability-negotiate
    end
    clear bgp 192.168.1.1
    """
    )

    step("Wait to converge")
    test_func = functools.partial(bgp_converge, r1)
    _, result = topotest.run_and_expect(test_func, None, count=60, wait=0.5)
    assert result is None, "Can't converge with dont-capability-negotiate"

    step("Make sure FQDN capability is reset")
    test_func = functools.partial(_bgp_check_fqdn)
    _, result = topotest.run_and_expect(test_func, None, count=60, wait=0.5)
    assert result is None, "FQDN capability disabled, but we still have a hostname"

    step("Re-enable sending any capability from r2")
    r2.vtysh_cmd(
        """
    configure terminal
        router bgp 65002
            address-family ipv4 unicast
                 no neighbor 192.168.1.1 dont-capability-negotiate
    end
    clear bgp 192.168.1.1
    """
    )
    step("Wait to converge")
    tgen = get_topogen()
    test_func = functools.partial(bgp_converge, r1)
    _, result = topotest.run_and_expect(test_func, None, count=60, wait=0.5)
    assert result is None, "Can't converge with all capabilities re enabled"

    step("Make sure FQDN capability is r2")
    test_func = functools.partial(_bgp_check_fqdn, "r2")
    _, result = topotest.run_and_expect(test_func, None, count=60, wait=0.5)
    assert result is None, "FQDN capability enabled, but r1 can't see it"

    step("Disable sending fqdn capability")
    r2.vtysh_cmd(
        """
    configure terminal
        router bgp 65002
            no neighbor 192.168.1.1 capability fqdn
    end
    clear bgp 192.168.1.1
    """
    )
    step("Wait to converge")
    tgen = get_topogen()
    test_func = functools.partial(bgp_converge, r1)
    _, result = topotest.run_and_expect(test_func, None, count=60, wait=0.5)
    assert result is None, "Can't converge with no capability fqdn"

    step("Make sure FQDN capability is reset")
    test_func = functools.partial(_bgp_check_fqdn)
    _, result = topotest.run_and_expect(test_func, None, count=60, wait=0.5)
    assert result is None, "FQDN capability disabled, but we still have a hostname"


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
