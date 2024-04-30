#!/usr/bin/env python
# SPDX-License-Identifier: ISC

# Copyright (c) 2022 by
# Donatas Abraitis <donatas@opensourcerouting.org>
#

"""
Test if Software Version capability works if forced with a knob.
Reference: https://datatracker.ietf.org/doc/html/draft-abraitis-bgp-version-capability
"""

import os
import re
import sys
import json
import pytest
import functools

pytestmark = pytest.mark.bgpd

CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

# pylint: disable=C0413
from lib import topotest
from lib.topogen import Topogen, TopoRouter, get_topogen

pytestmark = [pytest.mark.bgpd]


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


def test_bgp_software_version():
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]

    def _bgp_converge():
        output = json.loads(r1.vtysh_cmd("show bgp summary json"))
        expected = {"ipv4Unicast": {"peers": {"192.168.1.2": {"state": "Established"}}}}
        return topotest.json_cmp(output, expected)

    test_func = functools.partial(
        _bgp_converge,
    )
    _, result = topotest.run_and_expect(test_func, None, count=60, wait=0.5)
    assert result is None, "Can't converge"

    def _bgp_check_software_version():
        output = json.loads(r1.vtysh_cmd("show bgp neighbor 192.168.1.2 json"))

        try:
            versions = output["192.168.1.2"]["neighborCapabilities"]["softwareVersion"]
            adv = versions["advertisedSoftwareVersion"]
            rcv = versions["receivedSoftwareVersion"]

            if not adv and not rcv:
                return False

            pattern = "^FRRouting/\\d.+"
            if re.search(pattern, adv) and re.search(pattern, rcv):
                return True
        except:
            return False

        return False

    assert _bgp_check_software_version(), "Neighbor's software version is n/a"


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
