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

import functools
import json

import pytest
from lib.topogen import Topogen
from lib.topotest import run_and_expect

pytestmark = [pytest.mark.ripd, pytest.mark.mgmtd]


@pytest.fixture(scope="module")
def tgen(request):
    "Setup/Teardown the environment and provide tgen argument to tests"

    topodef = {"s1": ("r1", "r2")}

    tgen = Topogen(topodef, request.module.__name__)
    tgen.start_topology()

    router_list = tgen.routers()
    for router in router_list.values():
        router.load_frr_config()

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


def no_lifetime(router, keyid, direction):
    dstr = "send" if direction == DIR_SEND else "accept"
    conf = f"""conf t
key chain kc
 key {keyid}
  no {dstr}-lifetime
 exit
exit
"""
    router.vtysh_multicmd(conf.split("\n"), pretty_output=True)


def check_active(router, keyid, send, accept):
    "None once the send and accept lifetimes of key keyid have these states."
    active = {
        DIR_SEND: is_key_active(router, "kc", keyid, DIR_SEND),
        DIR_ACCEPT: is_key_active(router, "kc", keyid, DIR_ACCEPT),
    }
    if active == {DIR_SEND: send, DIR_ACCEPT: accept}:
        return None
    return "key {}: send active {}, accept active {}; expected {}, {}".format(
        keyid, active[DIR_SEND], active[DIR_ACCEPT], send, accept
    )


def wait_active(router, keyid, active):
    "Wait for the lifetimes of key keyid to have the states in active."
    test_func = functools.partial(
        check_active, router, keyid, active[DIR_SEND], active[DIR_ACCEPT]
    )
    _, result = run_and_expect(test_func, None, count=30, wait=1)
    assert result is None, result


def check_no_lifetime_config(router):
    "None once the running configuration lists no lifetime for keys 1 and 2."
    config = router.vtysh_cmd("show running-config")
    keys = config[config.index(" key 1\n") : config.index(" key 3\n")]
    if "lifetime" in keys:
        return keys
    return None


def test_no_lifetime(tgen):
    "Removing a lifetime makes the key valid again in that direction only."
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]

    # test_send_accept left keys 1 and 2 with lifetimes not valid now. The
    # first lifetime removed goes with its start time, the second with the
    # container: remove them in both orders.
    for keyid, first, second in ((1, DIR_SEND, DIR_ACCEPT), (2, DIR_ACCEPT, DIR_SEND)):
        wait_active(r1, keyid, {first: False, second: False})

        no_lifetime(r1, keyid, first)
        wait_active(r1, keyid, {first: True, second: False})

        no_lifetime(r1, keyid, second)
        wait_active(r1, keyid, {first: True, second: True})

    test_func = functools.partial(check_no_lifetime_config, r1)
    _, result = run_and_expect(test_func, None, count=30, wait=1)
    assert result is None, "lifetimes still configured:\n{}".format(result)
