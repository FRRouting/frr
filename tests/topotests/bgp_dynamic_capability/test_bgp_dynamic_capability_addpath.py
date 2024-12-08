#!/usr/bin/env python
# SPDX-License-Identifier: ISC

# Copyright (c) 2023 by
# Donatas Abraitis <donatas@opensourcerouting.org>
#

"""
<<<<<<< HEAD
Test if Addpath capability is adjusted dynamically.
"""

import os
import re
=======
Test if Addpath/Paths-Limit capabilities are adjusted dynamically.
T1: Enable Addpath/Paths-Limit capabilities and check if they are exchanged dynamically
T2: Disable paths limit and check if it's exchanged dynamically
T3: Disable Addpath capability RX and check if it's exchanged dynamically
T4: Disable Addpath capability and check if it's exchanged dynamically
"""

import os
>>>>>>> 3d89c67889 (bgpd: Print the actual prefix when we try to import in vpn_leak_to_vrf_update)
import sys
import json
import pytest
import functools

<<<<<<< HEAD
pytestmark = pytest.mark.bgpd
=======
pytestmark = [pytest.mark.bgpd]
>>>>>>> 3d89c67889 (bgpd: Print the actual prefix when we try to import in vpn_leak_to_vrf_update)

CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

# pylint: disable=C0413
from lib import topotest
<<<<<<< HEAD
from lib.topogen import Topogen, TopoRouter, get_topogen
from lib.common_config import step

pytestmark = [pytest.mark.bgpd]
=======
from lib.topogen import Topogen, get_topogen
>>>>>>> 3d89c67889 (bgpd: Print the actual prefix when we try to import in vpn_leak_to_vrf_update)


def setup_module(mod):
    topodef = {"s1": ("r1", "r2")}
    tgen = Topogen(topodef, mod.__name__)
    tgen.start_topology()

    router_list = tgen.routers()

    for _, (rname, router) in enumerate(router_list.items(), 1):
        router.load_frr_config(os.path.join(CWD, "{}/frr.conf".format(rname)))

    tgen.start_router()


def teardown_module(mod):
    tgen = get_topogen()
    tgen.stop_topology()


<<<<<<< HEAD
def test_bgp_dynamic_capability_addpath():
=======
def test_bgp_addpath_paths_limit():
>>>>>>> 3d89c67889 (bgpd: Print the actual prefix when we try to import in vpn_leak_to_vrf_update)
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]
    r2 = tgen.gears["r2"]

<<<<<<< HEAD
    def _bgp_converge():
=======
    def _converge():
>>>>>>> 3d89c67889 (bgpd: Print the actual prefix when we try to import in vpn_leak_to_vrf_update)
        output = json.loads(r1.vtysh_cmd("show bgp neighbor json"))
        expected = {
            "192.168.1.2": {
                "bgpState": "Established",
                "neighborCapabilities": {
                    "dynamic": "advertisedAndReceived",
                    "addPath": {
                        "ipv4Unicast": {
<<<<<<< HEAD
                            "txAdvertised": True,
                            "rxAdvertisedAndReceived": True,
=======
                            "txAdvertisedAndReceived": False,
                            "txAdvertised": True,
                            "txReceived": False,
                            "rxAdvertisedAndReceived": True,
                            "rxAdvertised": True,
                            "rxReceived": True,
                        }
                    },
                    "pathsLimit": {
                        "ipv4Unicast": {
                            "advertisedAndReceived": True,
                            "advertisedPathsLimit": 10,
                            "receivedPathsLimit": 20,
>>>>>>> 3d89c67889 (bgpd: Print the actual prefix when we try to import in vpn_leak_to_vrf_update)
                        }
                    },
                },
                "addressFamilyInfo": {
                    "ipv4Unicast": {
                        "acceptedPrefixCounter": 3,
                    }
                },
            }
        }
        return topotest.json_cmp(output, expected)

    test_func = functools.partial(
<<<<<<< HEAD
        _bgp_converge,
=======
        _converge,
>>>>>>> 3d89c67889 (bgpd: Print the actual prefix when we try to import in vpn_leak_to_vrf_update)
    )
    _, result = topotest.run_and_expect(test_func, None, count=30, wait=1)
    assert result is None, "Can't converge"

<<<<<<< HEAD
    step("Enable Addpath capability and check if it's exchanged dynamically")

    # Clear message stats to check if we receive a notification or not after we
    # change the settings fo LLGR.
=======
    ####
    # T1: Enable Addpath/Paths-Limit capabilities and check if they are exchanged dynamically
    ####
>>>>>>> 3d89c67889 (bgpd: Print the actual prefix when we try to import in vpn_leak_to_vrf_update)
    r1.vtysh_cmd("clear bgp 192.168.1.2 message-stats")
    r2.vtysh_cmd(
        """
    configure terminal
<<<<<<< HEAD
    router bgp
     address-family ipv4 unicast
      neighbor 192.168.1.1 addpath-tx-all-paths
    """
    )

    def _bgp_check_if_addpath_rx_tx_and_session_not_reset():
=======
     router bgp
      address-family ipv4 unicast
       neighbor 192.168.1.1 addpath-tx-all-paths
       neighbor 192.168.1.1 addpath-rx-paths-limit 21
    """
    )

    def _enable_addpath_paths_limit():
>>>>>>> 3d89c67889 (bgpd: Print the actual prefix when we try to import in vpn_leak_to_vrf_update)
        output = json.loads(r1.vtysh_cmd("show bgp neighbor json"))
        expected = {
            "192.168.1.2": {
                "bgpState": "Established",
                "neighborCapabilities": {
                    "dynamic": "advertisedAndReceived",
                    "addPath": {
                        "ipv4Unicast": {
                            "txAdvertisedAndReceived": True,
<<<<<<< HEAD
                            "rxAdvertisedAndReceived": True,
=======
                            "txAdvertised": True,
                            "txReceived": True,
                            "rxAdvertisedAndReceived": True,
                            "rxAdvertised": True,
                            "rxReceived": True,
                        }
                    },
                    "pathsLimit": {
                        "ipv4Unicast": {
                            "advertisedAndReceived": True,
                            "advertisedPathsLimit": 10,
                            "receivedPathsLimit": 21,
>>>>>>> 3d89c67889 (bgpd: Print the actual prefix when we try to import in vpn_leak_to_vrf_update)
                        }
                    },
                },
                "addressFamilyInfo": {
                    "ipv4Unicast": {
                        "acceptedPrefixCounter": 3,
                    }
                },
                "messageStats": {
                    "notificationsRecv": 0,
<<<<<<< HEAD
                    "capabilityRecv": 1,
=======
                    "notificationsSent": 0,
                    "capabilityRecv": 2,
>>>>>>> 3d89c67889 (bgpd: Print the actual prefix when we try to import in vpn_leak_to_vrf_update)
                },
            }
        }
        return topotest.json_cmp(output, expected)

    test_func = functools.partial(
<<<<<<< HEAD
        _bgp_check_if_addpath_rx_tx_and_session_not_reset,
    )
    _, result = topotest.run_and_expect(test_func, None, count=30, wait=1)
    assert result is None, "Session was reset after enabling Addpath capability"

    step("Disable Addpath capability RX and check if it's exchanged dynamically")

    # Clear message stats to check if we receive a notification or not after we
    # disable addpath-rx.
    r1.vtysh_cmd("clear bgp 192.168.1.2 message-stats")
=======
        _enable_addpath_paths_limit,
    )
    _, result = topotest.run_and_expect(test_func, None, count=30, wait=1)
    assert (
        result is None
    ), "Something went wrong when enabling Addpath/Paths-Limit capabilities"

    ###
    # T2: Disable paths limit and check if it's exchanged dynamically
    ###
    r2.vtysh_cmd(
        """
    configure terminal
    router bgp
     address-family ipv4 unicast
      no neighbor 192.168.1.1 addpath-rx-paths-limit
    """
    )

    def _disable_paths_limit():
        output = json.loads(r1.vtysh_cmd("show bgp neighbor json"))
        expected = {
            "192.168.1.2": {
                "bgpState": "Established",
                "neighborCapabilities": {
                    "dynamic": "advertisedAndReceived",
                    "addPath": {
                        "ipv4Unicast": {
                            "txAdvertisedAndReceived": True,
                            "txAdvertised": True,
                            "txReceived": True,
                            "rxAdvertisedAndReceived": True,
                            "rxAdvertised": True,
                            "rxReceived": True,
                        }
                    },
                    "pathsLimit": {
                        "ipv4Unicast": {
                            "advertisedAndReceived": True,
                            "advertisedPathsLimit": 10,
                            "receivedPathsLimit": 0,
                        }
                    },
                },
                "messageStats": {
                    "notificationsRecv": 0,
                    "notificationsSent": 0,
                    "capabilityRecv": 3,
                },
            }
        }
        return topotest.json_cmp(output, expected)

    test_func = functools.partial(
        _disable_paths_limit,
    )
    _, result = topotest.run_and_expect(test_func, None, count=30, wait=1)
    assert result is None, "Something went wrong after disabling paths limit"

    ###
    # T3: Disable Addpath capability RX and check if it's exchanged dynamically
    ###
>>>>>>> 3d89c67889 (bgpd: Print the actual prefix when we try to import in vpn_leak_to_vrf_update)
    r2.vtysh_cmd(
        """
    configure terminal
    router bgp
     address-family ipv4 unicast
      neighbor 192.168.1.1 disable-addpath-rx
    """
    )

<<<<<<< HEAD
    def _bgp_check_if_addpath_tx_and_session_not_reset():
=======
    def _disable_addpath_rx():
>>>>>>> 3d89c67889 (bgpd: Print the actual prefix when we try to import in vpn_leak_to_vrf_update)
        output = json.loads(r1.vtysh_cmd("show bgp neighbor json"))
        expected = {
            "192.168.1.2": {
                "bgpState": "Established",
                "neighborCapabilities": {
                    "dynamic": "advertisedAndReceived",
                    "addPath": {
                        "ipv4Unicast": {
                            "txAdvertisedAndReceived": True,
<<<<<<< HEAD
                            "rxAdvertised": True,
=======
                            "txAdvertised": True,
                            "txReceived": True,
                            "rxAdvertisedAndReceived": False,
                            "rxAdvertised": True,
                            "rxReceived": False,
                        }
                    },
                    "pathsLimit": {
                        "ipv4Unicast": {
                            "advertisedAndReceived": True,
                            "advertisedPathsLimit": 10,
                            "receivedPathsLimit": 0,
>>>>>>> 3d89c67889 (bgpd: Print the actual prefix when we try to import in vpn_leak_to_vrf_update)
                        }
                    },
                },
                "messageStats": {
                    "notificationsRecv": 0,
<<<<<<< HEAD
                    "capabilityRecv": 1,
=======
                    "notificationsSent": 0,
                    "capabilityRecv": 4,
>>>>>>> 3d89c67889 (bgpd: Print the actual prefix when we try to import in vpn_leak_to_vrf_update)
                },
            }
        }
        return topotest.json_cmp(output, expected)

    test_func = functools.partial(
<<<<<<< HEAD
        _bgp_check_if_addpath_tx_and_session_not_reset,
    )
    _, result = topotest.run_and_expect(test_func, None, count=30, wait=1)
    assert result is None, "Session was reset after disabling Addpath RX flags"

    # Clear message stats to check if we receive a notification or not after we
    # disable Addpath capability.
    r1.vtysh_cmd("clear bgp 192.168.1.2 message-stats")
=======
        _disable_addpath_rx,
    )
    _, result = topotest.run_and_expect(test_func, None, count=30, wait=1)
    assert result is None, "Something went wrong after disabling Addpath RX flags"

    ###
    # T4: Disable Addpath capability and check if it's exchanged dynamically
    ###
>>>>>>> 3d89c67889 (bgpd: Print the actual prefix when we try to import in vpn_leak_to_vrf_update)
    r1.vtysh_cmd(
        """
    configure terminal
    router bgp
     address-family ipv4 unicast
      no neighbor 192.168.1.2 addpath-tx-all-paths
    """
    )

<<<<<<< HEAD
    def _bgp_check_if_addpath_capability_is_absent():
=======
    def _disable_addpath():
>>>>>>> 3d89c67889 (bgpd: Print the actual prefix when we try to import in vpn_leak_to_vrf_update)
        output = json.loads(r1.vtysh_cmd("show bgp neighbor json"))
        expected = {
            "192.168.1.2": {
                "bgpState": "Established",
                "neighborCapabilities": {
                    "dynamic": "advertisedAndReceived",
                    "addPath": {
                        "ipv4Unicast": {
<<<<<<< HEAD
                            "txAdvertisedAndReceived": None,
                            "txAdvertised": None,
                            "rxAdvertised": True,
=======
                            "txAdvertisedAndReceived": False,
                            "txAdvertised": False,
                            "txReceived": True,
                            "rxAdvertisedAndReceived": False,
                            "rxAdvertised": True,
                            "rxReceived": False,
>>>>>>> 3d89c67889 (bgpd: Print the actual prefix when we try to import in vpn_leak_to_vrf_update)
                        }
                    },
                },
                "messageStats": {
                    "notificationsRecv": 0,
<<<<<<< HEAD
=======
                    "notificationsSent": 0,
                    "capabilitySent": 1,
                    "capabilityRecv": 4,
>>>>>>> 3d89c67889 (bgpd: Print the actual prefix when we try to import in vpn_leak_to_vrf_update)
                },
            }
        }
        return topotest.json_cmp(output, expected)

    test_func = functools.partial(
<<<<<<< HEAD
        _bgp_check_if_addpath_capability_is_absent,
    )
    _, result = topotest.run_and_expect(test_func, None, count=30, wait=1)
    assert result is None, "Failed to disable Addpath capability"
=======
        _disable_addpath,
    )
    _, result = topotest.run_and_expect(test_func, None, count=30, wait=1)
    assert result is None, "Something went wrong when disabling Addpath capability"
>>>>>>> 3d89c67889 (bgpd: Print the actual prefix when we try to import in vpn_leak_to_vrf_update)


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
