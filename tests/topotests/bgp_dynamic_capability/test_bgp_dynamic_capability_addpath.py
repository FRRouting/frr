#!/usr/bin/env python
# SPDX-License-Identifier: ISC

# Copyright (c) 2023 by
# Donatas Abraitis <donatas@opensourcerouting.org>
#

"""
Test if Addpath/Paths-Limit capabilities are adjusted dynamically.
T1: Enable Addpath/Paths-Limit capabilities and check if they are exchanged dynamically
T2: Disable paths limit and check if it's exchanged dynamically
T3: Disable Addpath capability RX and check if it's exchanged dynamically
T4: Disable Addpath capability and check if it's exchanged dynamically
"""

import os
import sys
import json
import pytest
import functools

pytestmark = [pytest.mark.bgpd]

CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

# pylint: disable=C0413
from lib import topotest
from lib.topogen import Topogen, get_topogen


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


def test_bgp_addpath_paths_limit():
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]
    r2 = tgen.gears["r2"]

    def _converge():
        output = json.loads(r1.vtysh_cmd("show bgp neighbor json"))
        expected = {
            "192.168.1.2": {
                "bgpState": "Established",
                "neighborCapabilities": {
                    "dynamic": "advertisedAndReceived",
                    "addPath": {
                        "ipv4Unicast": {
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
        _converge,
    )
    _, result = topotest.run_and_expect(test_func, None, count=30, wait=1)
    assert result is None, "Can't converge"

    ####
    # T1: Enable Addpath/Paths-Limit capabilities and check if they are exchanged dynamically
    ####
    r1.vtysh_cmd("clear bgp 192.168.1.2 message-stats")
    r2.vtysh_cmd(
        """
    configure terminal
     router bgp
      address-family ipv4 unicast
       neighbor 192.168.1.1 addpath-tx-all-paths
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
                    "capabilityRecv": 2,
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
    r2.vtysh_cmd(
        """
    configure terminal
    router bgp
     address-family ipv4 unicast
      neighbor 192.168.1.1 disable-addpath-rx
    """
    )

    def _disable_addpath_rx():
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
                            "receivedPathsLimit": 0,
                        }
                    },
                },
                "messageStats": {
                    "notificationsRecv": 0,
                    "notificationsSent": 0,
                    "capabilityRecv": 4,
                },
            }
        }
        return topotest.json_cmp(output, expected)

    test_func = functools.partial(
        _disable_addpath_rx,
    )
    _, result = topotest.run_and_expect(test_func, None, count=30, wait=1)
    assert result is None, "Something went wrong after disabling Addpath RX flags"

    ###
    # T4: Disable Addpath capability and check if it's exchanged dynamically
    ###
    r1.vtysh_cmd(
        """
    configure terminal
    router bgp
     address-family ipv4 unicast
      no neighbor 192.168.1.2 addpath-tx-all-paths
    """
    )

    def _disable_addpath():
        output = json.loads(r1.vtysh_cmd("show bgp neighbor json"))
        expected = {
            "192.168.1.2": {
                "bgpState": "Established",
                "neighborCapabilities": {
                    "dynamic": "advertisedAndReceived",
                    "addPath": {
                        "ipv4Unicast": {
                            "txAdvertisedAndReceived": False,
                            "txAdvertised": False,
                            "txReceived": True,
                            "rxAdvertisedAndReceived": False,
                            "rxAdvertised": True,
                            "rxReceived": False,
                        }
                    },
                },
                "messageStats": {
                    "notificationsRecv": 0,
                    "notificationsSent": 0,
                    "capabilitySent": 1,
                    "capabilityRecv": 4,
                },
            }
        }
        return topotest.json_cmp(output, expected)

    test_func = functools.partial(
        _disable_addpath,
    )
    _, result = topotest.run_and_expect(test_func, None, count=30, wait=1)
    assert result is None, "Something went wrong when disabling Addpath capability"


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
