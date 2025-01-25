#!/usr/bin/env python
# SPDX-License-Identifier: ISC

# Copyright (c) 2023 by
# Donatas Abraitis <donatas@opensourcerouting.org>
#

"""
<<<<<<< HEAD:tests/topotests/bgp_dynamic_capability/test_bgp_dynamic_capability_addpath.py
Test if Addpath capability is adjusted dynamically.
=======
Test if Addpath/Paths-Limit capabilities are adjusted dynamically.
T1: Enable Addpath/Paths-Limit capabilities and check if they are exchanged dynamically
T2: Disable paths limit and check if it's exchanged dynamically
>>>>>>> 4338e21aa (Revert "bgpd: Handle Addpath capability using dynamic capabilities"):tests/topotests/bgp_dynamic_capability/test_bgp_dynamic_capability_path_limit.py
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
from lib.common_config import step

pytestmark = [pytest.mark.bgpd]


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


def test_bgp_dynamic_capability_addpath():
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]
    r2 = tgen.gears["r2"]

    def _bgp_converge():
        output = json.loads(r1.vtysh_cmd("show bgp neighbor json"))
        expected = {
            "192.168.1.2": {
                "bgpState": "Established",
                "neighborCapabilities": {
                    "dynamic": "advertisedAndReceived",
                    "addPath": {
                        "ipv4Unicast": {
<<<<<<< HEAD:tests/topotests/bgp_dynamic_capability/test_bgp_dynamic_capability_addpath.py
                            "txAdvertised": True,
                            "rxAdvertisedAndReceived": True,
=======
                            "txAdvertisedAndReceived": True,
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
                            "receivedPathsLimit": 20,
>>>>>>> 4338e21aa (Revert "bgpd: Handle Addpath capability using dynamic capabilities"):tests/topotests/bgp_dynamic_capability/test_bgp_dynamic_capability_path_limit.py
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
        _bgp_converge,
    )
    _, result = topotest.run_and_expect(test_func, None, count=30, wait=1)
    assert result is None, "Can't converge"

    step("Enable Addpath capability and check if it's exchanged dynamically")

    # Clear message stats to check if we receive a notification or not after we
    # change the settings fo LLGR.
    r1.vtysh_cmd("clear bgp 192.168.1.2 message-stats")
    r2.vtysh_cmd(
        """
    configure terminal
<<<<<<< HEAD:tests/topotests/bgp_dynamic_capability/test_bgp_dynamic_capability_addpath.py
=======
     router bgp
      address-family ipv4 unicast
       neighbor 192.168.1.1 addpath-rx-paths-limit 21
    """
    )

    def _enable_addpath_paths_limit():
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
                            "rxAdvertisedAndReceived": False,
                            "rxAdvertised": True,
                            "rxReceived": False,
                        }
                    },
                    "pathsLimit": {
                        "ipv4Unicast": {
                            "advertisedAndReceived": True,
                            "advertisedPathsLimit": 10,
                            "receivedPathsLimit": 21,
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
                    "notificationsSent": 0,
                    "capabilityRecv": 1,
                },
            }
        }
        return topotest.json_cmp(output, expected)

    test_func = functools.partial(
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
>>>>>>> 4338e21aa (Revert "bgpd: Handle Addpath capability using dynamic capabilities"):tests/topotests/bgp_dynamic_capability/test_bgp_dynamic_capability_path_limit.py
    router bgp
     address-family ipv4 unicast
      neighbor 192.168.1.1 addpath-tx-all-paths
    """
    )

    def _bgp_check_if_addpath_rx_tx_and_session_not_reset():
        output = json.loads(r1.vtysh_cmd("show bgp neighbor json"))
        expected = {
            "192.168.1.2": {
                "bgpState": "Established",
                "neighborCapabilities": {
                    "dynamic": "advertisedAndReceived",
                    "addPath": {
                        "ipv4Unicast": {
                            "txAdvertisedAndReceived": True,
<<<<<<< HEAD:tests/topotests/bgp_dynamic_capability/test_bgp_dynamic_capability_addpath.py
                            "rxAdvertisedAndReceived": True,
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
>>>>>>> 4338e21aa (Revert "bgpd: Handle Addpath capability using dynamic capabilities"):tests/topotests/bgp_dynamic_capability/test_bgp_dynamic_capability_path_limit.py
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
<<<<<<< HEAD:tests/topotests/bgp_dynamic_capability/test_bgp_dynamic_capability_addpath.py
                    "capabilityRecv": 1,
=======
                    "notificationsSent": 0,
                    "capabilityRecv": 2,
>>>>>>> 4338e21aa (Revert "bgpd: Handle Addpath capability using dynamic capabilities"):tests/topotests/bgp_dynamic_capability/test_bgp_dynamic_capability_path_limit.py
                },
            }
        }
        return topotest.json_cmp(output, expected)

    test_func = functools.partial(
        _bgp_check_if_addpath_rx_tx_and_session_not_reset,
    )
    _, result = topotest.run_and_expect(test_func, None, count=30, wait=1)
    assert result is None, "Session was reset after enabling Addpath capability"

<<<<<<< HEAD:tests/topotests/bgp_dynamic_capability/test_bgp_dynamic_capability_addpath.py
    step("Disable Addpath capability RX and check if it's exchanged dynamically")

    # Clear message stats to check if we receive a notification or not after we
    # disable addpath-rx.
    r1.vtysh_cmd("clear bgp 192.168.1.2 message-stats")
    r2.vtysh_cmd(
        """
    configure terminal
    router bgp
     address-family ipv4 unicast
      neighbor 192.168.1.1 disable-addpath-rx
    """
    )

    def _bgp_check_if_addpath_tx_and_session_not_reset():
        output = json.loads(r1.vtysh_cmd("show bgp neighbor json"))
        expected = {
            "192.168.1.2": {
                "bgpState": "Established",
                "neighborCapabilities": {
                    "dynamic": "advertisedAndReceived",
                    "addPath": {
                        "ipv4Unicast": {
                            "txAdvertisedAndReceived": True,
                            "rxAdvertised": True,
                        }
                    },
                },
                "messageStats": {
                    "notificationsRecv": 0,
                    "capabilityRecv": 1,
                },
            }
        }
        return topotest.json_cmp(output, expected)

    test_func = functools.partial(
        _bgp_check_if_addpath_tx_and_session_not_reset,
    )
    _, result = topotest.run_and_expect(test_func, None, count=30, wait=1)
    assert result is None, "Session was reset after disabling Addpath RX flags"

    # Clear message stats to check if we receive a notification or not after we
    # disable Addpath capability.
    r1.vtysh_cmd("clear bgp 192.168.1.2 message-stats")
    r1.vtysh_cmd(
        """
    configure terminal
    router bgp
     address-family ipv4 unicast
      no neighbor 192.168.1.2 addpath-tx-all-paths
    """
    )

    def _bgp_check_if_addpath_capability_is_absent():
        output = json.loads(r1.vtysh_cmd("show bgp neighbor json"))
        expected = {
            "192.168.1.2": {
                "bgpState": "Established",
                "neighborCapabilities": {
                    "dynamic": "advertisedAndReceived",
                    "addPath": {
                        "ipv4Unicast": {
                            "txAdvertisedAndReceived": None,
                            "txAdvertised": None,
                            "rxAdvertised": True,
                        }
                    },
                },
                "messageStats": {
                    "notificationsRecv": 0,
                },
            }
        }
        return topotest.json_cmp(output, expected)

    test_func = functools.partial(
        _bgp_check_if_addpath_capability_is_absent,
    )
    _, result = topotest.run_and_expect(test_func, None, count=30, wait=1)
    assert result is None, "Failed to disable Addpath capability"

=======
>>>>>>> 4338e21aa (Revert "bgpd: Handle Addpath capability using dynamic capabilities"):tests/topotests/bgp_dynamic_capability/test_bgp_dynamic_capability_path_limit.py

if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
