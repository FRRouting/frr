#!/usr/bin/env python
# SPDX-License-Identifier: ISC

# Copyright (c) 2023 by
# Donatas Abraitis <donatas@opensourcerouting.org>
#

"""
Test if RIP `passive-interface default` and `no passive-interface IFNAME`
combination works as expected.
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
from lib.topogen import Topogen, get_topogen
from lib.common_config import step

pytestmark = [pytest.mark.ripd]


def setup_module(mod):
    topodef = {"s1": ("r1")}
    tgen = Topogen(topodef, mod.__name__)
    tgen.start_topology()

    router_list = tgen.routers()

    for _, (rname, router) in enumerate(router_list.items(), 1):
        router.load_frr_config(os.path.join(CWD, "{}/frr.conf".format(rname)))

    tgen.start_router()


def teardown_module():
    tgen = get_topogen()
    tgen.stop_topology()


import re
def getConfOfInterface(i_name, text):
    pattern = f'!\ninterface {i_name}(.*?)!'

    matches = re.findall(pattern, text, re.DOTALL)

    for match in matches:
        return match.strip()
    
    return None

def test_rip_version():
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]

    st = r1.vtysh_cmd("show running-config")
    r1Eth0 = getConfOfInterface("r1-eth0", st)
    assert r1Eth0 != None
    assert "ip rip send version 1 2" not in r1Eth0
    assert "ip rip receive version 1 2" not in r1Eth0
    r1Eth1 = getConfOfInterface("r1-eth1", st)
    assert r1Eth1 != None
    assert "ip rip send version 1 2" in r1Eth1
    assert "ip rip receive version 1 2" in r1Eth1

if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
