#!/usr/bin/env python
# SPDX-License-Identifier: ISC

# Copyright (c) 2024 by
# Donatas Abraitis <donatas@opensourcerouting.org>
#

import os
import re
import sys
import json
import pytest
import functools

CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

# pylint: disable=C0413
from lib import topotest
from lib.topogen import Topogen, get_topogen

pytestmark = [pytest.mark.bgpd]


def setup_module(mod):
    topodef = {"s1": ("r1", "r2", "r3")}
    tgen = Topogen(topodef, mod.__name__)
    tgen.start_topology()

    router_list = tgen.routers()

    for _, (rname, router) in enumerate(router_list.items(), 1):
        router.load_frr_config(os.path.join(CWD, "{}/frr.conf".format(rname)))

    tgen.start_router()


def teardown_module(mod):
    tgen = get_topogen()
    tgen.stop_topology()


def test_bgp_remote_as_auto():
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]

    def _bgp_converge():
        output = json.loads(r1.vtysh_cmd("show bgp ipv4 unicast summary json"))
        expected = {
            "peers": {
                "192.168.1.2": {
                    "remoteAs": 65002,
                    "state": "Established",
                    "peerState": "OK",
                },
                "192.168.1.3": {
                    "remoteAs": 65003,
                    "state": "Established",
                    "peerState": "OK",
                },
            },
            "totalPeers": 2,
        }

        return topotest.json_cmp(output, expected)

    test_func = functools.partial(
        _bgp_converge,
    )
    _, result = topotest.run_and_expect(test_func, None, count=30, wait=1)
    assert result is None, "Can't converge initial state"

    def _bgp_update_groups():
        actual = []
        output = json.loads(r1.vtysh_cmd("show bgp ipv4 unicast update-groups json"))
        expected = [
            {"subGroup": [{"adjListCount": 1, "peers": ["192.168.1.2"]}]},
            {"subGroup": [{"adjListCount": 1, "peers": ["192.168.1.3"]}]},
        ]

        # update-group's number can be random and it's not deterministic,
        # so we need to normalize the data a bit before checking.
        # We care here about the `peers` array only actually.
        for updgrp in output["default"].keys():
            actual.append(output["default"][updgrp])

        return topotest.json_cmp(actual, expected)

    test_func = functools.partial(
        _bgp_update_groups,
    )
    _, result = topotest.run_and_expect(test_func, None, count=30, wait=1)
    assert result is None, "Can't see separate update-groups"


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
