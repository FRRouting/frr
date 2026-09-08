#!/usr/bin/env python
# SPDX-License-Identifier: ISC
#
# test_bfd_auth_keychain_topo1.py
# Part of NetDEF Topology Tests
#

"""
test_bfd_auth_keychain_topo1.py: key lengths bfdd will draw from a
keychain, and what happens to a session when it can draw none.

        +---------+                        +---------+
        |         | eth-rt2        eth-rt1 |         |
        |   RT1   +------------------------+   RT2   |
        | 10.0.1.1|           s1           |10.0.1.2 |
        +---------+                        +---------+

RFC 5880 Section 6.7.2 bounds a simple password at 16 bytes and Section
6.7.4 a keyed SHA1 key at 20. A key outside those bounds, or one whose
algorithm bfdd cannot use, leaves the session with no key at all, and a
session configured to authenticate must then stay down rather than come
up carrying unauthenticated packets.
"""

import json
import os
import sys

import pytest

CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

# pylint: disable=C0413
from lib import topotest
from lib.topogen import Topogen, get_topogen
from lib.topolog import logger

pytestmark = [pytest.mark.bfdd]

ROUTERS = ("rt1", "rt2")


def setup_module(mod):
    "Sets up the pytest environment"
    topodef = {
        "s1": ("rt1:eth-rt2", "rt2:eth-rt1"),
    }
    tgen = Topogen(topodef, mod.__name__)
    tgen.start_topology()

    for router in tgen.routers().values():
        router.load_frr_config()

    tgen.start_router()


def teardown_module(mod):
    "Teardown the pytest environment"
    get_topogen().stop_topology()


def set_key(keystring, algorithm):
    "Put the same key on both routers."
    logger.info('setting key-string "%s" algorithm %s', keystring, algorithm)
    for rname in ROUTERS:
        get_topogen().gears[rname].vtysh_cmd(
            """
            configure terminal
            key chain kc1
            key 1
            key-string {}
            cryptographic-algorithm {}
            exit
            exit
            """.format(keystring, algorithm)
        )


def use_keychain(name):
    "Point both peers at a keychain."
    logger.info("pointing both peers at keychain %s", name)
    peer = {"rt1": "10.0.1.2", "rt2": "10.0.1.1"}
    local = {"rt1": "10.0.1.1", "rt2": "10.0.1.2"}
    iface = {"rt1": "eth-rt2", "rt2": "eth-rt1"}
    for rname in ROUTERS:
        get_topogen().gears[rname].vtysh_cmd(
            """
            configure terminal
            bfd
            peer {} local-address {} interface {}
            authentication key-chain {}
            exit
            exit
            """.format(peer[rname], local[rname], iface[rname], name)
        )


def session_status(rname):
    output = json.loads(get_topogen().gears[rname].vtysh_cmd("show bfd peers json"))
    return output[0].get("status") if output else None


def expect_status(want, count=60, wait=0.5):
    for rname in ROUTERS:
        test_func = lambda: session_status(rname) == want
        _, result = topotest.run_and_expect(test_func, True, count=count, wait=wait)
        assert result is True, "{} session is {}, expected {}".format(
            rname, session_status(rname), want
        )


def auth_in_effect(rname):
    """Whether bfdd has a key in hand, not merely a keychain configured.

    A session that falls back to sending unauthenticated still reports a
    keychain, so the session being up is not on its own evidence that
    anything is being authenticated.
    """
    output = json.loads(get_topogen().gears[rname].vtysh_cmd("show bfd peers json"))
    if not output:
        return False
    return output[0].get("authentication", {}).get("enabled", False)


def expect_authenticated(count=60, wait=0.5):
    expect_status("up", count=count, wait=wait)
    for rname in ROUTERS:
        assert auth_in_effect(rname), "{} came up with no key in effect".format(rname)


def skip_on_failure():
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)


def skip_without_sha1():
    """Keyed SHA1 needs a build with crypto-openssl.

    The clear text cases below do not, so they are left to run either
    way rather than taking the whole file out.
    """
    skip_on_failure()
    if not get_topogen().gears["rt1"].has_crypto_openssl():
        pytest.skip("crypto-openssl disabled, skipping keyed SHA1 test")


def test_bfd_auth_keyed_sha1_baseline():
    """A 15 byte keyed SHA1 key authenticates.

    The keychain starts out clear text, because a build without
    crypto-openssl cannot accept an hmac-sha-1 key and rolls back the
    whole bfd block if the startup configuration asks for one, leaving
    the session unconfigured rather than merely unauthenticated.
    """
    skip_without_sha1()
    set_key("sixteenbytekey1", "hmac-sha-1")
    expect_authenticated()


def test_bfd_auth_keyed_sha1_20_bytes():
    "Section 6.7.4 allows a keyed SHA1 key of up to 20 bytes."
    skip_without_sha1()
    set_key("twentybytekey1234567", "hmac-sha-1")
    expect_authenticated()


def test_bfd_auth_keyed_sha1_over_20_bytes():
    "A longer key cannot be used, so the session must not come up."
    skip_without_sha1()
    set_key("twentyonebytekey12345", "hmac-sha-1")
    expect_status("down")


def test_bfd_auth_cleartext_16_bytes():
    "Section 6.7.2 allows a simple password of up to 16 bytes."
    skip_on_failure()
    set_key("sixteenbyteskey1", "cleartext")
    expect_authenticated()


def test_bfd_auth_cleartext_over_16_bytes():
    "A longer password cannot be used either."
    skip_on_failure()
    set_key("seventeenbytekey1", "cleartext")
    expect_status("down")


def test_bfd_auth_without_algorithm():
    """A key with no cryptographic-algorithm is unusable.

    A key defaults to no algorithm, so this is what configuring
    key-string alone leaves behind.
    """
    skip_on_failure()
    # Start from a key that does work, so what is observed is the switch
    # to an unusable one rather than whatever the previous case left.
    use_keychain("kc1")
    set_key("sixteenbyteskey1", "cleartext")
    expect_authenticated()

    use_keychain("kc2")
    expect_status("down")


def test_bfd_auth_recovers():
    "Putting a usable key back brings the session up again."
    skip_on_failure()
    use_keychain("kc1")
    set_key("sixteenbyteskey1", "cleartext")
    expect_authenticated()


def test_memory_leak():
    "Run the memory leak test and report results."
    tgen = get_topogen()
    if not tgen.is_memleak_enabled():
        pytest.skip("Memory leak test/report is disabled")
    tgen.report_memory_leaks()


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
