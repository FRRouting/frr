#!/usr/bin/env python
# SPDX-License-Identifier: ISC

#
# test_bfd_authentication_topo1.py
# Part of NetDEF Topology Tests
#
# Copyright 2026 6WIND S.A.
#

"""
test_bfd_authentication_topo1.py:

        +---------+                      +---------+
        |         |                      |         |
        |   RT1   | eth-rt2 (.1)         |   RT2   |
        | 1.1.1.1 +----------------------+ 2.2.2.2 |
        |         |          eth-rt1 (.2)|         |
        +---------+                      +---------+

"""

import os
import sys
import pytest
import json
from functools import partial

# Save the Current Working Directory to find configuration files.
CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

# pylint: disable=C0413
# Import topogen and topotest helpers
from lib import topotest
from lib.topogen import Topogen, get_topogen
from lib.topolog import logger

pytestmark = [pytest.mark.bfdd, pytest.mark.isisd]


def setup_module(mod):
    "Sets up the pytest environment"
    topodef = {
        "s1": ("rt1:eth-rt2", "rt2:eth-rt1"),
    }
    tgen = Topogen(topodef, mod.__name__)
    tgen.start_topology()

    router_list = tgen.routers()

    # For all registered routers, load the unified frr configuration file
    for rname, router in router_list.items():
        router.load_frr_config(os.path.join(CWD, "{}/frr.conf".format(rname)))

    tgen.start_router()


def teardown_module(mod):
    "Teardown the pytest environment"
    tgen = get_topogen()

    # This function tears down the whole topology.
    tgen.stop_topology()


def print_cmd_result(rname, command):
    print(get_topogen().gears[rname].vtysh_cmd(command, isjson=False))


def router_compare_json_output(rname, command, reference, count=120, wait=0.5):
    "Compare router JSON output"

    logger.info('Comparing router "%s" "%s" output', rname, command)

    tgen = get_topogen()
    filename = "{}/{}/{}".format(CWD, rname, reference)
    expected = json.loads(open(filename).read())

    # Run test function until we get an result. Wait at most 60 seconds.
    test_func = partial(topotest.router_json_cmp, tgen.gears[rname], command, expected)
    _, diff = topotest.run_and_expect(test_func, None, count=count, wait=wait)
    assertmsg = '"{}" JSON output mismatches the expected result'.format(rname)
    assert diff is None, assertmsg


## TEST STEPS


def test_bfd_authentication_rib_step1():
    logger.info("Test (step 1): verify RIB (IPv4 and IPv6) for IS-IS")
    tgen = get_topogen()

    # Skip if previous fatal error condition is raised
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    router_compare_json_output(
        "rt1", "show ip route isis json", "step1/show_ip_route.ref"
    )
    router_compare_json_output(
        "rt1", "show ipv6 route isis json", "step1/show_ipv6_route.ref"
    )


def test_bfd_authentication_sessions_step2():
    logger.info("Test (step 2): verify BFD peers for IS-IS")
    tgen = get_topogen()

    # Skip if previous fatal error condition is raised
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    # BFD is just used on three routers
    for rt in ["rt1", "rt2"]:
        router_compare_json_output(
            rt, "show bfd peers json", "step2/show_bfd_peers.ref"
        )


def test_bfd_authentication_interface_failure_rt2_step3():
    logger.info("Test (step 2): check failover handling when RT2 goes down")
    tgen = get_topogen()

    # Skip if previous fatal error condition is raised
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    # Let's kill the interface on rt2 and see what happens with the RIB and BFD on rt1
    tgen.gears["rt2"].link_enable("eth-rt1", enabled=False)

    # By default BFD provides a recovery time of 900ms plus jitter, so let's wait
    # initial 2 seconds to let the CI not suffer.
    router_compare_json_output(
        "rt1", "show bfd peers json", "step3/show_bfd_peers_rt2_down.ref", 20, 1
    )

    # Check recovery, this can take some time
    tgen.gears["rt2"].link_enable("eth-rt1", enabled=True)

    router_compare_json_output(
        "rt1", "show bfd peers json", "step3/show_bfd_peers_healthy.ref"
    )


def test_bfd_authentication_simple_password_auth_direct_down():
    "Test BFD direct simple paasword authentication down"
    logger.info("Test: BFD-AUTHEN direct simple authentication down")

    tgen = get_topogen()

    # Configure BFD session is with sha1 authentication
    tgen.gears["rt1"].vtysh_cmd("""
        configure terminal
        key chain abcd
        key 0
        key-string mysecret12345
        cryptographic-algorithm cleartext
        exit
        exit
        bfd
        profile 0
        authentication key-chain abcd
        exit
        peer 10.0.1.2 interface eth-rt2
        profile 0
        exit
        exit
        """)

    # Verify BFD session is down with authentication
    router_compare_json_output(
        "rt1", "show bfd peers json", "step4/show_bfd_peers_simple.ref", 20, 1
    )


def test_bfd_authentication_simple_password_auth_direct_up():
    "Test BFD direct simple password authentication up"
    logger.info("Test: BFD-AUTHEN direct simple password authentication up")

    tgen = get_topogen()

    tgen.gears["rt2"].vtysh_cmd("""
        configure terminal
        key chain efgh
        key 0
        key-string mysecret12345
        cryptographic-algorithm cleartext
        exit
        exit
        bfd
        peer 10.0.1.1 interface eth-rt1
        authentication key-chain efgh
        exit
        exit
        """)

    # Verify BFD session is up with authentication
    router_compare_json_output(
        "rt1", "show bfd peers json", "step4/show_bfd_peers_2_simple.ref", 20, 1
    )


def test_bfd_authentication_sha1_auth_direct_down():
    "Test BFD direct sha1 authentication down"
    logger.info("Test: BFD-AUTHEN direct sha1 authentication down")

    tgen = get_topogen()
    if not tgen.gears["rt1"].has_crypto_openssl():
        pytest.skip("crypto-openssl disabled. skipping SHA1 test")

    # Configure BFD session is with sha1 authentication
    tgen.gears["rt1"].vtysh_cmd("""
        configure terminal
        key chain abcd
        key 0
        key-string mysecret12345
        cryptographic-algorithm hmac-sha-1
        exit
        exit
        """)

    # Verify BFD session is down with authentication
    router_compare_json_output(
        "rt1", "show bfd peers json", "step4/show_bfd_peers_sha1.ref", 20, 1
    )


def test_bfd_authentication_sha1_auth_direct_up():
    "Test BFD direct sha1 authentication up"
    logger.info("Test: BFD-AUTHEN direct sha1 authentication up")

    tgen = get_topogen()
    if not tgen.gears["rt1"].has_crypto_openssl():
        pytest.skip("crypto-openssl disabled. skipping SHA1 test")

    tgen.gears["rt2"].vtysh_cmd("""
        configure terminal
        key chain efgh
        key 0
        key-string mysecret12345
        cryptographic-algorithm hmac-sha-1
        exit
        exit
        """)

    # Verify BFD session is up with authentication
    router_compare_json_output(
        "rt1", "show bfd peers json", "step4/show_bfd_peers_2_sha1.ref", 20, 1
    )


def test_bfd_authentication_sha1_auth_direct_down_remove_auth_from_bfd_session():
    "Test BFD direct sha1 authentication down, auth disabled from bfd session"
    logger.info(
        "Test: BFD-AUTHEN direct sha1 authentication down when disable the auth from bfd session"
    )

    tgen = get_topogen()
    if not tgen.gears["rt1"].has_crypto_openssl():
        pytest.skip("crypto-openssl disabled. skipping SHA1 test")

    tgen.gears["rt2"].vtysh_cmd("""
        configure terminal
        bfd
        peer 10.0.1.1 interface eth-rt1
        no authentication key-chain efgh
        exit
        exit
        """)

    # Verify BFD session is down with authentication
    router_compare_json_output(
        "rt1", "show bfd peers json", "step4/show_bfd_peers_sha1.ref", 20, 1
    )


def test_bfd_authentication_sha1_auth_direct_up_readd_auth_to_bfd_session():
    "Test BFD direct sha1 authentication up, when auth is readded to bfd session"
    logger.info(
        "Test: BFD-AUTHEN direct sha1 authentication up when readding auth to bfd session"
    )

    tgen = get_topogen()
    if not tgen.gears["rt1"].has_crypto_openssl():
        pytest.skip("crypto-openssl disabled. skipping SHA1 test")

    tgen.gears["rt2"].vtysh_cmd("""
        configure terminal
        bfd
        peer 10.0.1.1 interface eth-rt1
        authentication key-chain efgh
        exit
        exit
        """)

    # Verify BFD session is up with authentication
    router_compare_json_output(
        "rt1", "show bfd peers json", "step4/show_bfd_peers_2_sha1.ref", 20, 1
    )


def test_bfd_authentication_sha1_auth_direct_down_remove_auth_from_bfd_profile():
    "Test BFD direct sha1 authentication down, profile auth disabled"
    logger.info(
        "Test: BFD-AUTHEN direct sha1 authentication down when disable the auth in bfd profile"
    )

    tgen = get_topogen()
    if not tgen.gears["rt1"].has_crypto_openssl():
        pytest.skip("crypto-openssl disabled. skipping SHA1 test")

    tgen.gears["rt1"].vtysh_cmd("""
        configure terminal
        bfd
        profile 0
        no authentication key-chain abcd
        exit
        exit
        """)

    # Verify BFD session is down with authentication
    router_compare_json_output(
        "rt2", "show bfd peers json", "step4/show_bfd_peers_sha1.ref", 20, 1
    )


def test_bfd_authentication_sha1_auth_direct_up_readd_auth_to_bfd_profile():
    "Test BFD direct sha1 authentication up, when auth is readded to profile"
    logger.info(
        "Test: BFD-AUTHEN direct sha1 authentication up when authentication is reconfigured on profile"
    )

    tgen = get_topogen()
    if not tgen.gears["rt1"].has_crypto_openssl():
        pytest.skip("crypto-openssl disabled. skipping SHA1 test")

    tgen.gears["rt1"].vtysh_cmd("""
        configure terminal
        bfd
        profile 0
        authentication key-chain abcd
        exit
        exit
        """)

    # Verify BFD session is up with authentication
    router_compare_json_output(
        "rt2", "show bfd peers json", "step4/show_bfd_peers_2_sha1.ref", 20, 1
    )


def test_bfd_authentication_sha1_auth_direct_down_remove_bfd_profile_from_peer():
    "Test BFD direct sha1 authentication down, profile auth disabled in the peer section"
    logger.info(
        "Test: BFD-AUTHEN direct sha1 authentication down when disable the profile in bfd peer section"
    )

    tgen = get_topogen()

    tgen.gears["rt1"].vtysh_cmd("""
        configure terminal
        bfd
        peer 10.0.1.2 interface eth-rt2
        no profile 0
        exit
        exit
        """)

    # Verify BFD session is down with authentication
    router_compare_json_output(
        "rt1", "show bfd peers json", "step4/show_bfd_peers.ref", 20, 1
    )


def test_bfd_authentication_sha1_auth_direct_up_add_bfd_profile_to_peer():
    "Test BFD direct sha1 authentication up, profile enabled in the peer section"
    logger.info(
        "Test: BFD-AUTHEN direct sha1 authentication up when enable the bfd profile in bfd peer section"
    )

    tgen = get_topogen()
    if not tgen.gears["rt1"].has_crypto_openssl():
        pytest.skip("crypto-openssl disabled. skipping SHA1 test")

    tgen.gears["rt1"].vtysh_cmd("""
        configure terminal
        bfd
        peer 10.0.1.2 interface eth-rt2
        profile 0
        exit
        exit
        """)

    # Verify BFD session is up with authentication
    router_compare_json_output(
        "rt1", "show bfd peers json", "step4/show_bfd_peers_2_sha1.ref", 20, 1
    )


def test_bfd_authentication_sha1_auth_direct_down_remove_bfd_profile():
    "Test BFD direct sha1 authentication down, profile auth removed"
    logger.info(
        "Test: BFD-AUTHEN direct sha1 authentication down when bfd profile removed"
    )

    tgen = get_topogen()
    if not tgen.gears["rt1"].has_crypto_openssl():
        pytest.skip("crypto-openssl disabled. skipping SHA1 test")

    tgen.gears["rt1"].vtysh_cmd("""
        configure terminal
        bfd
        no profile 0
        """)

    # Verify BFD session is down with authentication
    router_compare_json_output(
        "rt1", "show bfd peers json", "step4/show_bfd_peers.ref", 20, 1
    )


def test_bfd_authentication_sha1_auth_direct_down_add_bfd_profile():
    "Test BFD direct sha1 authentication up, profile auth enabled"
    logger.info(
        "Test: BFD-AUTHEN direct sha1 authentication up when enable the bfd auth profile"
    )

    tgen = get_topogen()
    if not tgen.gears["rt1"].has_crypto_openssl():
        pytest.skip("crypto-openssl disabled. skipping SHA1 test")

    tgen.gears["rt1"].vtysh_cmd("""
        configure terminal
        bfd
        profile 0
        authentication key-chain abcd
        exit
        """)

    # Verify BFD session is up with authentication
    router_compare_json_output(
        "rt1", "show bfd peers json", "step4/show_bfd_peers_2_sha1.ref", 20, 1
    )


def test_bfd_authentication_sha1_to_cleartext_switch_down():
    "Test BFD direct sha1 authentication down, rt1 switch from sha1 to cleartext, rt2 the same"
    logger.info(
        "Test: BFD-AUTHEN direct sha1 authentication down when rt1 configuration changes from sha1 to cleartext while rt2 stays the same"
    )

    tgen = get_topogen()
    if not tgen.gears["rt1"].has_crypto_openssl():
        pytest.skip("crypto-openssl disabled. skipping SHA1 test")

    tgen.gears["rt1"].vtysh_cmd("""
        configure terminal
        key chain abcd
        key 0
        cryptographic-algorithm cleartext
        """)

    # Verify BFD session is down with authentication
    router_compare_json_output(
        "rt1", "show bfd peers json", "step4/show_bfd_peers_simple.ref", 20, 1
    )


def test_bfd_authentication_sha1_to_cleartext_switch_up():
    "Test BFD direct cleartext authentication up, rt2 switch from sha1 to cleartext, rt1 the same"
    logger.info(
        "Test: BFD-AUTHEN direct sha1 authentication up when rt2 configuration changes from sha1 to cleartext while rt1 stays the same"
    )

    tgen = get_topogen()
    if not tgen.gears["rt1"].has_crypto_openssl():
        pytest.skip("crypto-openssl disabled. skipping SHA1 test")

    tgen.gears["rt2"].vtysh_cmd("""
        configure terminal
        key chain efgh
        key 0
        cryptographic-algorithm cleartext
        """)
    # Verify BFD session is up with authentication
    router_compare_json_output(
        "rt1", "show bfd peers json", "step4/show_bfd_peers_2_simple.ref", 20, 1
    )


def test_bfd_authentication_cleartext_to_sha1_switch_up():
    "Test BFD direct sha1 authentication up, rt1 and rt2 switch from cleartext to sha1"
    logger.info(
        "Test: BFD-AUTHEN direct sha1 authentication up when rt1 and rt2 configuration changes from cleartext to sha1"
    )

    tgen = get_topogen()
    if not tgen.gears["rt1"].has_crypto_openssl():
        pytest.skip("crypto-openssl disabled. skipping SHA1 test")

    tgen.gears["rt1"].vtysh_cmd("""
        configure terminal
        key chain abcd
        key 0
        cryptographic-algorithm hmac-sha-1
        exit
        exit
        """)

    tgen.gears["rt2"].vtysh_cmd("""
        configure terminal
        key chain efgh
        key 0
        cryptographic-algorithm hmac-sha-1
        exit
        exit
        """)

    # Verify BFD session is up with authentication
    router_compare_json_output(
        "rt1", "show bfd peers json", "step4/show_bfd_peers_2_sha1.ref", 20, 1
    )


def test_bfd_authentication_sha1_auth_keychain1_direct_different_keystring_down():
    "Test BFD direct sha1 authentication down when key-string differs"
    logger.info(
        "Test: BFD-AUTHEN direct sha1 authentication down when key-string differs"
    )

    tgen = get_topogen()
    if not tgen.gears["rt1"].has_crypto_openssl():
        pytest.skip("crypto-openssl disabled. skipping SHA1 test")

    # Configure BFD session is with sha1 authentication

    tgen.gears["rt1"].vtysh_cmd("""
        configure terminal
        key chain kc1
        key 0
        key-string mysecret123
        cryptographic-algorithm hmac-sha-1
        exit
        exit
        bfd
        profile 0
        authentication key-chain kc1
        exit
        """)

    # Verify BFD session is down with authentication
    router_compare_json_output(
        "rt1", "show bfd peers json", "step4/show_bfd_peers_sha1_newkey.ref", 20, 1
    )


def test_bfd_authentication_sha1_auth_keychain1_direct_up():
    "Test BFD direct sha1 authentication up"
    logger.info("Test: BFD-AUTHEN direct sha1 authentication up")

    tgen = get_topogen()
    if not tgen.gears["rt1"].has_crypto_openssl():
        pytest.skip("crypto-openssl disabled. skipping SHA1 test")

    tgen.gears["rt2"].vtysh_cmd("""
        configure terminal
        key chain kc1
        key 0
        key-string mysecret123
        cryptographic-algorithm hmac-sha-1
        exit
        exit
        bfd
        peer 10.0.1.1 interface eth-rt1
        authentication key-chain kc1
        exit
        """)

    # Verify BFD session is up with authentication
    router_compare_json_output(
        "rt1", "show bfd peers json", "step4/show_bfd_peers_2_sha1_newkey.ref", 20, 1
    )


def test_bfd_authentication_sha1_auth_keychain1_direct_different_key_id_down():
    "Test BFD direct sha1 authentication down when key-id differs"
    logger.info("Test: BFD-AUTHEN direct sha1 authentication down when key-id differs")

    tgen = get_topogen()
    if not tgen.gears["rt1"].has_crypto_openssl():
        pytest.skip("crypto-openssl disabled. skipping SHA1 test")

    # Configure BFD session is with sha1 authentication

    tgen.gears["rt1"].vtysh_cmd("""
        configure terminal
        key chain kc1
        no key 0
        key 40
        key-string mysecret123
        cryptographic-algorithm hmac-sha-1
        exit
        exit
        bfd
        profile 0
        authentication key-chain kc1
        exit
        """)

    # Verify BFD session is down with authentication
    router_compare_json_output(
        "rt1", "show bfd peers json", "step4/show_bfd_peers_sha1_newkey.ref", 20, 1
    )


def test_bfd_authentication_sha1_auth_keychain1_direct_with_same_key_id_up():
    "Test BFD direct sha1 authentication up when a matching key_id configured"
    logger.info(
        "Test: BFD-AUTHEN direct sha1 authentication up, when a matching key_id configured"
    )

    tgen = get_topogen()
    if not tgen.gears["rt1"].has_crypto_openssl():
        pytest.skip("crypto-openssl disabled. skipping SHA1 test")

    tgen.gears["rt2"].vtysh_cmd("""
        configure terminal
        key chain kc1
        key 40
        key-string mysecret123
        cryptographic-algorithm hmac-sha-1
        exit
        exit
        """)

    # Verify BFD session is up with authentication
    router_compare_json_output(
        "rt1", "show bfd peers json", "step4/show_bfd_peers_2_sha1_newkey.ref", 20, 1
    )


def test_bfd_authentication_sha1_auth_keychain1_meticulous_up():
    "Test BFD direct sha1 authentication with meticulous mode up"
    logger.info("Test: BFD-AUTHEN direct sha1 authentication with meticulous mode up")

    tgen = get_topogen()
    if not tgen.gears["rt1"].has_crypto_openssl():
        pytest.skip("crypto-openssl disabled. skipping SHA1 test")

    tgen.gears["rt1"].vtysh_cmd("""
        configure terminal
        bfd
        profile 0
        authentication algorithm meticulous
        """)
    tgen.gears["rt2"].vtysh_cmd("""
        configure terminal
        bfd
        peer 10.0.1.1 interface eth-rt1
        authentication algorithm meticulous
        """)

    # Verify BFD session is up with authentication
    router_compare_json_output(
        "rt1",
        "show bfd peers json",
        "step4/show_bfd_peers_2_sha1_newkey_meticulous.ref",
        20,
        1,
    )


def test_memory_leak():
    "Run the memory leak test and report results."
    tgen = get_topogen()
    if not tgen.is_memleak_enabled():
        pytest.skip("Memory leak test/report is disabled")

    tgen.report_memory_leaks()


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
