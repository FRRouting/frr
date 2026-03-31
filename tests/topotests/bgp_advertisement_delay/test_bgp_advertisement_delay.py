#!/usr/bin/env python
# SPDX-License-Identifier: ISC

#
# test_bgp_advertisement_delay.py
# Part of NetDEF Topology Tests
#
# Copyright (c) 2026 by
# Karthikeya Venkat Muppalla <kmuppalla@nvidia.com>
#

"""
Test the bgp advertisement-delay feature that holds route advertisements
to peers for a configured number of seconds after the first peer reaches
Established state.

r1 -- r2 -- r3

r2 is UUT and peers with r1 and r3 in the default BGP instance.
r1 and r3 each have a loopback and redistribute connected.

Test cases:

1. Initial convergence with no delay configured -- routes exchanged promptly.
2. Configure advertisement-delay, verify show bgp router json.
3. Clear bgp, verify advertisement-delay in progress with pfxSnt=0.
4. Verify r2 installs routes in RIB during the delay (only ads are held).
5. Wait for delay to complete, verify pfxSnt>0 and advertisementDelayResumeTime.
6. Verify r3 learns route from r1 via r2 after delay.
7. Configure both update-delay and advertisement-delay (ad > ud), clear bgp,
   verify ads are held until advertisement-delay ends even though update-delay
   finishes earlier.
8. Re-trigger advertisement-delay on clear ip bgp *.
9. Remove advertisement-delay, verify routes advertised promptly.
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

pytestmark = [pytest.mark.bgpd]


def setup_module(mod):
    topodef = {"s1": ("r1", "r2"), "s2": ("r2", "r3")}
    tgen = Topogen(topodef, mod.__name__)
    tgen.start_topology()

    router_list = tgen.routers()

    for _, (rname, router) in enumerate(router_list.items(), 1):
        router.load_frr_config(os.path.join(CWD, "{}/frr.conf".format(rname)))

    tgen.start_router()


def teardown_module(mod):
    tgen = get_topogen()
    tgen.stop_topology()


def test_bgp_initial_convergence():
    """No delays configured -- routes are exchanged promptly."""
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r2 = tgen.gears["r2"]

    def _bgp_converge():
        output = json.loads(r2.vtysh_cmd("show bgp summary json"))
        expected = {
            "ipv4Unicast": {
                "peers": {
                    "192.168.12.1": {"state": "Established"},
                    "192.168.23.2": {"state": "Established"},
                }
            }
        }
        return topotest.json_cmp(output, expected)

    test_func = functools.partial(_bgp_converge)
    _, result = topotest.run_and_expect(test_func, None, count=30, wait=1)
    assert result is None, "Peers did not reach Established state"

    def _bgp_check_route_install():
        output = json.loads(r2.vtysh_cmd("show ip route 172.16.255.254/32 json"))
        expected = {"172.16.255.254/32": [{"protocol": "bgp"}]}
        return topotest.json_cmp(output, expected)

    test_func = functools.partial(_bgp_check_route_install)
    _, result = topotest.run_and_expect(test_func, None, count=30, wait=1)
    assert result is None, "r2 did not install route from r1 without any delays"


def test_bgp_advertisement_delay_show_router_json():
    """Configure advertisement-delay and verify show bgp router json."""
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r2 = tgen.gears["r2"]

    r2.vtysh_cmd(
        """
          configure terminal
            bgp advertisement-delay 15
        """
    )

    def _check_router_json():
        output = json.loads(r2.vtysh_cmd("show bgp router json"))
        expected = {"bgpAdvertisementDelayTime": 15}
        return topotest.json_cmp(output, expected)

    test_func = functools.partial(_check_router_json)
    _, result = topotest.run_and_expect(test_func, None, count=20, wait=1)
    assert result is None, "bgpAdvertisementDelayTime not shown in show bgp router json"

    def _check_summary_json():
        output = json.loads(r2.vtysh_cmd("show bgp summary json"))
        expected = {"ipv4Unicast": {"advertisementDelay": 15}}
        return topotest.json_cmp(output, expected)

    test_func = functools.partial(_check_summary_json)
    _, result = topotest.run_and_expect(test_func, None, count=20, wait=1)
    assert result is None, "advertisementDelay not shown in show bgp summary json"


def test_bgp_advertisement_delay_in_progress():
    """Clear bgp and verify advertisement-delay is in progress with pfxSnt=0."""
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r2 = tgen.gears["r2"]

    r2.vtysh_cmd("clear ip bgp *")

    def _check_delay_active_with_peers():
        output = json.loads(r2.vtysh_cmd("show bgp summary json"))
        ipv4 = output.get("ipv4Unicast", {})

        if not ipv4.get("advertisementDelayInProgress"):
            return "advertisementDelayInProgress not set"

        peers = ipv4.get("peers", {})
        established_with_zero = False
        for peer_addr, peer_data in peers.items():
            if peer_data.get("state") == "Established":
                if peer_data.get("pfxSnt", -1) != 0:
                    return "pfxSnt is not 0 for {} during delay".format(peer_addr)
                established_with_zero = True

        if not established_with_zero:
            return "No Established peers found yet"

        return None

    test_func = functools.partial(_check_delay_active_with_peers)
    _, result = topotest.run_and_expect(test_func, None, count=15, wait=1)
    assert result is None, (
        "advertisement-delay not active with Established peers: {}".format(result)
    )


def test_bgp_advertisement_delay_route_installed_during_delay():
    """r2 installs routes in its RIB even while advertisement-delay is active."""
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r2 = tgen.gears["r2"]

    def _check_route_in_rib():
        output = json.loads(r2.vtysh_cmd("show ip route 172.16.255.254/32 json"))
        expected = {"172.16.255.254/32": [{"protocol": "bgp"}]}
        return topotest.json_cmp(output, expected)

    test_func = functools.partial(_check_route_in_rib)
    _, result = topotest.run_and_expect(test_func, None, count=20, wait=1)
    assert result is None, (
        "r2 should install routes in RIB during advertisement-delay"
    )


def test_bgp_advertisement_delay_completed():
    """Wait for advertisement-delay to end, verify pfxSnt>0."""
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r2 = tgen.gears["r2"]

    def _check_delay_completed():
        output = json.loads(r2.vtysh_cmd("show bgp summary json"))
        ipv4 = output.get("ipv4Unicast", {})

        if ipv4.get("advertisementDelayInProgress"):
            return "advertisement-delay still in progress"

        if "advertisementDelayResumeTime" not in ipv4:
            return "advertisementDelayResumeTime not set"

        peers = ipv4.get("peers", {})
        for peer_data in peers.values():
            if (
                peer_data.get("state") == "Established"
                and peer_data.get("pfxSnt", 0) > 0
            ):
                return None
        return "No peer has pfxSnt > 0 after delay completed"

    test_func = functools.partial(_check_delay_completed)
    _, result = topotest.run_and_expect(test_func, None, count=30, wait=1)
    assert result is None, (
        "advertisement-delay did not complete properly: {}".format(result)
    )


def test_bgp_advertisement_delay_route_on_peer():
    """After delay, r3 learns route from r1 via r2."""
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r3 = tgen.gears["r3"]

    def _check_route_on_r3():
        output = json.loads(r3.vtysh_cmd("show ip route 172.16.255.254/32 json"))
        expected = {"172.16.255.254/32": [{"protocol": "bgp"}]}
        return topotest.json_cmp(output, expected)

    test_func = functools.partial(_check_route_on_r3)
    _, result = topotest.run_and_expect(test_func, None, count=20, wait=1)
    assert result is None, "r3 did not learn 172.16.255.254/32 from r1 via r2"


def test_bgp_update_delay_with_advertisement_delay():
    """Both update-delay and advertisement-delay (ad > ud).

    With all peers up, update-delay ends on EOR quickly (~2 s).
    Advertisement-delay keeps running until its timer expires.
    Advertisements are sent only after advertisement-delay ends.
    """
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r2 = tgen.gears["r2"]

    r2.vtysh_cmd(
        """
          configure terminal
            router bgp 65002
              update-delay 10
        """
    )
    r2.vtysh_cmd(
        """
          configure terminal
            bgp advertisement-delay 20
        """
    )

    r2.vtysh_cmd("clear ip bgp *")

    def _check_both_configured():
        output = json.loads(r2.vtysh_cmd("show bgp summary json"))
        expected = {
            "ipv4Unicast": {
                "updateDelayLimit": 10,
                "advertisementDelay": 20,
            }
        }
        return topotest.json_cmp(output, expected)

    test_func = functools.partial(_check_both_configured)
    _, result = topotest.run_and_expect(test_func, None, count=20, wait=1)
    assert result is None, "Both timers not shown in show bgp summary json"

    def _check_ad_delay_holding_after_ud():
        """update-delay done (EOR received), ad-delay still active, pfxSnt=0."""
        output = json.loads(r2.vtysh_cmd("show bgp summary json"))
        ipv4 = output.get("ipv4Unicast", {})

        if ipv4.get("updateDelayInProgress"):
            return "update-delay still in progress, waiting for EOR"

        if not ipv4.get("advertisementDelayInProgress"):
            return "advertisement-delay not in progress"

        peers = ipv4.get("peers", {})
        for peer_addr, peer_data in peers.items():
            if peer_data.get("state") == "Established":
                if peer_data.get("pfxSnt", -1) != 0:
                    return "pfxSnt not 0 for {} while ad-delay active".format(
                        peer_addr
                    )
        established = [p for p in peers.values() if p.get("state") == "Established"]
        if not established:
            return "No peers Established yet"
        return None

    test_func = functools.partial(_check_ad_delay_holding_after_ud)
    _, result = topotest.run_and_expect(test_func, None, count=20, wait=1)
    assert result is None, (
        "ad-delay should hold ads after update-delay ends: {}".format(result)
    )

    def _check_both_completed():
        output = json.loads(r2.vtysh_cmd("show bgp summary json"))
        ipv4 = output.get("ipv4Unicast", {})
        if ipv4.get("advertisementDelayInProgress"):
            return "advertisement-delay still in progress"
        if "advertisementDelayResumeTime" not in ipv4:
            return "advertisementDelayResumeTime not set"
        peers = ipv4.get("peers", {})
        for peer_data in peers.values():
            if (
                peer_data.get("state") == "Established"
                and peer_data.get("pfxSnt", 0) > 0
            ):
                return None
        return "No peer has pfxSnt > 0"

    test_func = functools.partial(_check_both_completed)
    _, result = topotest.run_and_expect(test_func, None, count=30, wait=1)
    assert result is None, "Both timers did not complete properly: {}".format(result)


def test_bgp_advertisement_delay_retrigger():
    """Clear bgp again -- advertisement-delay re-triggers."""
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r2 = tgen.gears["r2"]

    r2.vtysh_cmd("clear ip bgp *")

    def _check_retrigger():
        output = json.loads(r2.vtysh_cmd("show bgp summary json"))
        expected = {
            "ipv4Unicast": {
                "advertisementDelayInProgress": True,
            }
        }
        return topotest.json_cmp(output, expected)

    test_func = functools.partial(_check_retrigger)
    _, result = topotest.run_and_expect(test_func, None, count=15, wait=1)
    assert result is None, "advertisement-delay did not re-trigger on clear bgp"


def test_bgp_no_advertisement_delay():
    """Remove advertisement-delay -- routes advertised promptly."""
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r2 = tgen.gears["r2"]

    def _wait_delay_done():
        output = json.loads(r2.vtysh_cmd("show bgp summary json"))
        ipv4 = output.get("ipv4Unicast", {})
        if ipv4.get("advertisementDelayInProgress"):
            return "still in progress"
        return None

    test_func = functools.partial(_wait_delay_done)
    topotest.run_and_expect(test_func, None, count=40, wait=1)

    r2.vtysh_cmd(
        """
          configure terminal
            no bgp advertisement-delay
            router bgp 65002
              no update-delay
        """
    )

    r2.vtysh_cmd("clear ip bgp *")

    def _check_no_delay():
        output = json.loads(r2.vtysh_cmd("show bgp summary json"))
        ipv4 = output.get("ipv4Unicast", {})

        if "advertisementDelay" in ipv4:
            return "advertisementDelay should not be present"

        peers = ipv4.get("peers", {})
        for peer_data in peers.values():
            if (
                peer_data.get("state") == "Established"
                and peer_data.get("pfxSnt", 0) > 0
            ):
                return None
        return "No peer has pfxSnt > 0 yet"

    test_func = functools.partial(_check_no_delay)
    _, result = topotest.run_and_expect(test_func, None, count=30, wait=1)
    assert result is None, (
        "Routes not advertised promptly without advertisement-delay: {}".format(result)
    )


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
