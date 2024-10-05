#!/usr/bin/env python
# -*- coding: utf-8 eval: (blacken-mode 1) -*-
# SPDX-License-Identifier: ISC
#
# March 4 2024, Christian Hopps <chopps@labn.net>
#
# Copyright (c) 2024, LabN Consulting, L.L.C.
#
"""
Test static route functionality
"""
import json

import pytest
from lib.topogen import Topogen

pytestmark = [pytest.mark.ripd, pytest.mark.mgmtd]


@pytest.fixture(scope="module")
def tgen(request):
    "Setup/Teardown the environment and provide tgen argument to tests"

    topodef = {"s1": ("r1", "r2")}

    tgen = Topogen(topodef, request.module.__name__)
    tgen.start_topology()

    router_list = tgen.routers()
    for _, router in router_list.items():
        router.load_frr_config("frr.conf")

    tgen.start_router()
    yield tgen
    tgen.stop_topology()


DIR_SEND = 0
DIR_ACCEPT = 1


def is_key_active(router, keychain, keyid, direction):
    dstr = "send" if direction == DIR_SEND else "accept"
    node = f"{dstr}-lifetime-active"
    output = router.net.cmd_raises(
        "vtysh -c 'show mgmt get-data "
        f'/ietf-key-chain:key-chains/key-chain[name="{keychain}"]'
        f'/key[key-id="{keyid}"]/{node} json'
        "'"
    )
    jd = json.loads(output)
    return jd["ietf-key-chain:key-chains"]["key-chain"][0]["key"][0][node]


def test_send_accept(tgen):
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]

    conf = """conf t
key chain kc
 key 1
  key-string theSecret
  cryptographic-algorithm hmac-sha-256
 exit
exit
"""
    r1.vtysh_multicmd(conf.split("\n"), pretty_output=True)
    assert is_key_active(r1, "kc", 1, DIR_SEND)
    assert is_key_active(r1, "kc", 1, DIR_ACCEPT)

    conf = """conf t
key chain kc
 key 1
  key-string theSecret
  cryptographic-algorithm hmac-sha-256
  send-lifetime 00:00:00 Jan 1 2024 infinite
  accept-lifetime 00:00:00 Jan 1 2024 infinite
 exit
exit
"""
    r1.vtysh_multicmd(conf.split("\n"), pretty_output=True)
    assert is_key_active(r1, "kc", 1, DIR_SEND)
    assert is_key_active(r1, "kc", 1, DIR_ACCEPT)

    conf = """conf t
key chain kc
 key 1
  send-lifetime 00:00:00 Jan 1 2035 infinite
  accept-lifetime 00:00:00 Jan 1 2035 infinite
 exit
exit
"""
    r1.vtysh_multicmd(conf.split("\n"), pretty_output=True)
    assert not is_key_active(r1, "kc", 1, DIR_SEND)
    assert not is_key_active(r1, "kc", 1, DIR_ACCEPT)

    secs_in_10_years = 60 * 60 * 24 * 365 * 10
    conf = f"""conf t
key chain kc
 key 2
  key-string theSecret
  cryptographic-algorithm hmac-sha-256
  send-lifetime 00:00:00 Jan 1 2024 duration {secs_in_10_years}
  accept-lifetime 00:00:00 Jan 1 2024 duration {secs_in_10_years}
 exit
exit
"""
    r1.vtysh_multicmd(conf.split("\n"), pretty_output=True)
    assert is_key_active(r1, "kc", 2, DIR_SEND)
    assert is_key_active(r1, "kc", 2, DIR_ACCEPT)

    conf = f"""conf t
key chain kc
 key 2
  send-lifetime 00:00:00 Jan 1 2000 duration 10
  accept-lifetime 00:00:00 Jan 1 2000 duration 10
 exit
exit
"""
    r1.vtysh_multicmd(conf.split("\n"), pretty_output=True)
    assert not is_key_active(r1, "kc", 2, DIR_SEND)
    assert not is_key_active(r1, "kc", 2, DIR_ACCEPT)

    conf = """conf t
key chain kc
 key 3
  key-string theSecret
  cryptographic-algorithm hmac-sha-256
  send-lifetime   00:00:00 Jan 1 2024  23:59:59 Dec 31 2034
  accept-lifetime 00:00:00 Jan 1 2024  23:59:59 Dec 31 2034
 exit
exit
"""
    r1.vtysh_multicmd(conf.split("\n"), pretty_output=True)
    assert is_key_active(r1, "kc", 3, DIR_SEND)
    assert is_key_active(r1, "kc", 3, DIR_ACCEPT)

    conf = """conf t
key chain kc
 key 3
  send-lifetime   00:00:00 Dec 1 2035  23:59:59 Dec 31 2034
  accept-lifetime 00:00:00 Dec 1 2035  23:59:59 Dec 31 2034
 exit
exit
"""
    r1.vtysh_multicmd(conf.split("\n"), pretty_output=True)
    assert not is_key_active(r1, "kc", 3, DIR_SEND)
    assert not is_key_active(r1, "kc", 3, DIR_ACCEPT)
