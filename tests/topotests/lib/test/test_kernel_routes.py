# SPDX-License-Identifier: ISC
"""Tests for kernel_routes()."""

import json
import os
import sys

CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../../"))

# pylint: disable=C0413
from lib.kernel_routes import (  # noqa: E402
    KernelRoutesError,
    kernel_routes,
    _freebsd_argv,
    _linux_argv,
    _routes_from_netstat,
)
import pytest  # noqa: E402


# Captured from `netstat --libxo json -rn` on a FreeBSD topotest jail.
NETSTAT = json.loads(
    r"""
{"statistics": {"route-information": {"route-table": {"rt-family": [
{"address-family":"Internet", "rt-entry": [
{"destination":"10.0.1.0/24","gateway":"link#23","flags":"U", "flags_pretty": ["up"],"weight":1,"nhop-kidx":2,"interface-name":"r1-eth0"},
{"destination":"10.0.1.1","gateway":"link#13","flags":"UHS", "flags_pretty": ["up","host","static"],"weight":1,"nhop-kidx":3,"interface-name":"lo0"},
{"destination":"10.0.2.0/24","gateway":"10.0.3.3","flags":"UG1", "flags_pretty": ["up","gateway","proto1"],"weight":1,"nhop-kidx":6,"interface-name":"r1-eth1"},
{"destination":"10.0.3.0/24","gateway":"link#29","flags":"U", "flags_pretty": ["up"],"weight":1,"nhop-kidx":4,"interface-name":"r1-eth1"},
{"destination":"10.0.3.2","gateway":"link#13","flags":"UHS", "flags_pretty": ["up","host","static"],"weight":1,"nhop-kidx":5,"interface-name":"lo0"},
{"destination":"10.0.10.0/24","gateway":"10.0.3.1","flags":"UG1", "flags_pretty": ["up","gateway","proto1"],"weight":1,"nhop-kidx":7,"interface-name":"r1-eth1"},
{"destination":"127.0.0.1","gateway":"link#13","flags":"UH", "flags_pretty": ["up","host"],"weight":1,"nhop-kidx":1,"interface-name":"lo0"},
{"destination":"172.16.0.0/24","gateway":"10.0.3.1","flags":"UG1", "flags_pretty": ["up","gateway","proto1"],"weight":1,"nhop-kidx":7,"interface-name":"r1-eth1"},
{"destination":"172.16.1.0/24","gateway":"10.0.3.1","flags":"UG1", "flags_pretty": ["up","gateway","proto1"],"weight":1,"nhop-kidx":7,"interface-name":"r1-eth1"}
]},
{"address-family":"Internet6", "rt-entry": [
{"destination":"::1","gateway":"link#13","flags":"UHS", "flags_pretty": ["up","host","static"],"weight":1,"nhop-kidx":1,"interface-name":"lo0"},
{"destination":"1::1","gateway":"2001:db8:1::2","flags":"UGH1", "flags_pretty": ["up","gateway","host","proto1"],"weight":1,"nhg-kidx":16,"interface-name":"r1-eth0"},
{"destination":"1::1","gateway":"2001:db8:1::3","flags":"UGH1", "flags_pretty": ["up","gateway","host","proto1"],"weight":1,"nhg-kidx":16,"interface-name":"r1-eth0"},
{"destination":"1::1","gateway":"2001:db8:1::4","flags":"UGH1", "flags_pretty": ["up","gateway","host","proto1"],"weight":1,"nhg-kidx":16,"interface-name":"r1-eth0"},
{"destination":"1::1","gateway":"2001:db8:1::5","flags":"UGH1", "flags_pretty": ["up","gateway","host","proto1"],"weight":1,"nhg-kidx":16,"interface-name":"r1-eth0"},
{"destination":"2001:db8:1::/64","gateway":"link#23","flags":"U", "flags_pretty": ["up"],"weight":1,"nhop-kidx":5,"interface-name":"r1-eth0"},
{"destination":"2001:db8:1::1","gateway":"link#13","flags":"UHS", "flags_pretty": ["up","host","static"],"weight":1,"nhop-kidx":4,"interface-name":"lo0"},
{"destination":"2001:db8:2::/64","gateway":"fe80::6013:37ff:fea9:9ea0%r1-eth1","flags":"UG1", "flags_pretty": ["up","gateway","proto1"],"weight":1,"nhop-kidx":9,"interface-name":"r1-eth1"},
{"destination":"2001:db8:3::/64","gateway":"link#29","flags":"U", "flags_pretty": ["up"],"weight":1,"nhop-kidx":7,"interface-name":"r1-eth1"},
{"destination":"2001:db8:3::2","gateway":"link#13","flags":"UHS", "flags_pretty": ["up","host","static"],"weight":1,"nhop-kidx":6,"interface-name":"lo0"},
{"destination":"2001:db8:100::/64","gateway":"fe80::382f:78ff:fe4a:846c%r1-eth1","flags":"UG1", "flags_pretty": ["up","gateway","proto1"],"weight":1,"nhop-kidx":8,"interface-name":"r1-eth1"},
{"destination":"2001:db8:200::/64","gateway":"fe80::382f:78ff:fe4a:846c%r1-eth1","flags":"UG1", "flags_pretty": ["up","gateway","proto1"],"weight":1,"nhop-kidx":8,"interface-name":"r1-eth1"},
{"destination":"2001:db8:300::/64","gateway":"fe80::382f:78ff:fe4a:846c%r1-eth1","flags":"UG1", "flags_pretty": ["up","gateway","proto1"],"weight":1,"nhop-kidx":8,"interface-name":"r1-eth1"},
{"destination":"fe80::%lo0/64","gateway":"link#13","flags":"U", "flags_pretty": ["up"],"weight":1,"nhop-kidx":3,"interface-name":"lo0"},
{"destination":"fe80::1%lo0","gateway":"link#13","flags":"UHS", "flags_pretty": ["up","host","static"],"weight":1,"nhop-kidx":2,"interface-name":"lo0"},
{"destination":"fe80::%r1-eth0/64","gateway":"link#23","flags":"U", "flags_pretty": ["up"],"weight":1,"nhop-kidx":5,"interface-name":"r1-eth0"},
{"destination":"fe80::c4e7:5cff:fe2a:dfbe%lo0","gateway":"link#13","flags":"UHS", "flags_pretty": ["up","host","static"],"weight":1,"nhop-kidx":4,"interface-name":"lo0"},
{"destination":"fe80::%r1-eth1/64","gateway":"link#29","flags":"U", "flags_pretty": ["up"],"weight":1,"nhop-kidx":7,"interface-name":"r1-eth1"},
{"destination":"fe80::84d1:85ff:fe5b:158d%lo0","gateway":"link#13","flags":"UHS", "flags_pretty": ["up","host","static"],"weight":1,"nhop-kidx":6,"interface-name":"lo0"}
]}]}}}}
"""
)

_LINUX_ONLY = (
    "protocol",
    "metric",
    "flags",
    "nhid",
    "pref",
    "scope",
    "prefsrc",
)


class FakeNode:
    def __init__(self, output):
        self.output = output
        self.cmds = []

    def cmd_raises(self, argv):
        self.cmds.append(list(argv))
        if isinstance(self.output, list):
            return self.output.pop(0)
        return self.output


def test_netstat_sample_matches_iproute_shape():
    routes = _routes_from_netstat(NETSTAT, "all")

    assert len(routes) == 25
    for route in routes:
        for key in _LINUX_ONLY:
            assert key not in route
        blob = json.dumps(route)
        assert "link#" not in blob
        assert "%" not in blob

    assert {"dst": "10.0.1.0/24", "dev": "r1-eth0"} in routes
    assert {
        "dst": "10.0.2.0/24",
        "gateway": "10.0.3.3",
        "dev": "r1-eth1",
    } in routes
    assert {"dst": "10.0.1.1", "dev": "lo0"} in routes
    assert {"dst": "127.0.0.1", "dev": "lo0"} in routes
    assert {
        "dst": "1::1",
        "nexthops": [
            {"gateway": "2001:db8:1::2", "dev": "r1-eth0", "weight": 1},
            {"gateway": "2001:db8:1::3", "dev": "r1-eth0", "weight": 1},
            {"gateway": "2001:db8:1::4", "dev": "r1-eth0", "weight": 1},
            {"gateway": "2001:db8:1::5", "dev": "r1-eth0", "weight": 1},
        ],
    } in routes
    assert {
        "dst": "2001:db8:2::/64",
        "gateway": "fe80::6013:37ff:fea9:9ea0",
        "dev": "r1-eth1",
    } in routes
    assert {"dst": "fe80::/64", "dev": "lo0"} in routes
    assert {"dst": "fe80::/64", "dev": "r1-eth0"} in routes
    assert {"dst": "fe80::/64", "dev": "r1-eth1"} in routes
    assert {"dst": "fe80::1", "dev": "lo0"} in routes

    v4 = _routes_from_netstat(NETSTAT, "ipv4")
    v6 = _routes_from_netstat(NETSTAT, "ipv6")
    assert len(v4) == 9
    assert len(v6) == 16
    assert all(":" not in route["dst"] for route in v4)
    assert all(":" in route["dst"] for route in v6)


def test_netstat_normalizes_host_default_and_special_types():
    payload = {
        "statistics": {
            "route-information": {
                "route-table": {
                    "rt-family": [
                        {
                            "address-family": "Internet",
                            "rt-entry": [
                                {
                                    "destination": "0.0.0.0/0",
                                    "gateway": "10.0.0.1",
                                    "flags_pretty": ["up", "gateway"],
                                    "weight": 1,
                                    "interface-name": "eth0",
                                },
                                {
                                    "destination": "192.0.2.1/32",
                                    "gateway": "10.0.0.1",
                                    "flags_pretty": ["up", "gateway", "host"],
                                    "weight": 1,
                                    "interface-name": "eth0",
                                },
                                {
                                    "destination": "203.0.113.0/24",
                                    "gateway": "lo0",
                                    "flags_pretty": ["up", "blackhole"],
                                    "interface-name": "lo0",
                                },
                                {
                                    "destination": "198.51.100.0/24",
                                    "flags_pretty": "reject",
                                },
                            ],
                        },
                        {
                            "address-family": "Internet6",
                            "rt-entry": {
                                "destination": "2001:db8::1/128",
                                "gateway": "fe80::1%eth0",
                                "flags_pretty": ["up", "gateway", "host"],
                                "interface-name": "eth0",
                            },
                        },
                    ]
                }
            }
        }
    }
    assert _routes_from_netstat(payload, "all") == [
        {"dst": "default", "gateway": "10.0.0.1", "dev": "eth0"},
        {"dst": "192.0.2.1", "gateway": "10.0.0.1", "dev": "eth0"},
        {"type": "blackhole", "dst": "203.0.113.0/24", "dev": "lo0"},
        {"type": "unreachable", "dst": "198.51.100.0/24"},
        {"dst": "2001:db8::1", "gateway": "fe80::1", "dev": "eth0"},
    ]


def test_same_destination_without_nhg_stays_separate():
    payload = {
        "statistics": {
            "route-information": {
                "route-table": {
                    "rt-family": {
                        "address-family": "Internet6",
                        "rt-entry": [
                            {
                                "destination": "fe80::/64",
                                "gateway": "link#1",
                                "interface-name": "lo0",
                            },
                            {
                                "destination": "fe80::/64",
                                "gateway": "link#2",
                                "interface-name": "eth0",
                            },
                        ],
                    }
                }
            }
        }
    }
    assert _routes_from_netstat(payload, "ipv6") == [
        {"dst": "fe80::/64", "dev": "lo0"},
        {"dst": "fe80::/64", "dev": "eth0"},
    ]


def test_linux_command_and_passthrough(monkeypatch):
    monkeypatch.setattr(sys, "platform", "linux")
    shown = [
        {
            "dst": "1::1",
            "nhid": 9922,
            "protocol": "static",
            "metric": 20,
            "flags": [],
            "pref": "medium",
            "nexthops": [
                {
                    "gateway": "2001:db8::2",
                    "dev": "eth0",
                    "weight": 1,
                    "flags": [],
                }
            ],
        }
    ]
    node = FakeNode(json.dumps(shown))
    assert kernel_routes(node, family="ipv6") == shown
    assert node.cmds == [["ip", "-j", "-6", "route", "show"]]

    node = FakeNode(["[]", json.dumps([{"dst": "default", "dev": "eth0"}])])
    assert kernel_routes(node, vrf="vrf1", table=10, family="all") == [
        {"dst": "default", "dev": "eth0"}
    ]
    assert node.cmds == [
        ["ip", "-j", "-4", "route", "show", "vrf", "vrf1", "table", "10"],
        ["ip", "-j", "-6", "route", "show", "vrf", "vrf1", "table", "10"],
    ]


def test_freebsd_command(monkeypatch):
    monkeypatch.setattr(sys, "platform", "freebsd14")
    node = FakeNode(json.dumps(NETSTAT))
    routes = kernel_routes(node, family="ipv4")
    assert node.cmds == [["netstat", "--libxo", "json", "-rn", "-f", "inet"]]
    assert len(routes) == 9
    assert routes[2] == {
        "dst": "10.0.2.0/24",
        "gateway": "10.0.3.3",
        "dev": "r1-eth1",
    }

    node = FakeNode(json.dumps(NETSTAT))
    kernel_routes(node, vrf="default", table=3, family="ipv6")
    assert node.cmds == [
        ["netstat", "--libxo", "json", "-rn", "-f", "inet6", "-F", "3"]
    ]

    node = FakeNode(json.dumps(NETSTAT))
    kernel_routes(node, table="main", family="all")
    assert node.cmds == [["netstat", "--libxo", "json", "-rn"]]

    node = FakeNode("{}")
    with pytest.raises(KernelRoutesError, match="vrf"):
        kernel_routes(node, vrf="vrf1")
    assert node.cmds == []

    with pytest.raises(KernelRoutesError, match="FIB"):
        kernel_routes(node, table="local")
    assert node.cmds == []


def test_run_fallback_quotes_the_command(monkeypatch):
    monkeypatch.setattr(sys, "platform", "linux")

    class RunOnly:
        def __init__(self):
            self.cmds = []

        def run(self, command):
            self.cmds.append(command)
            return "[]"

    node = RunOnly()
    assert kernel_routes(node, vrf="vrf 1") == []
    assert node.cmds == ["ip -j -4 route show vrf 'vrf 1'"]


def test_argv_helpers_match_kernel_routes():
    assert _linux_argv(None, None, "ipv4") == ["ip", "-j", "-4", "route", "show"]
    assert _linux_argv("red", 100, "ipv6") == [
        "ip",
        "-j",
        "-6",
        "route",
        "show",
        "vrf",
        "red",
        "table",
        "100",
    ]
    assert _freebsd_argv(None, None, "all") == ["netstat", "--libxo", "json", "-rn"]
    assert _freebsd_argv(None, 0, "ipv4") == [
        "netstat",
        "--libxo",
        "json",
        "-rn",
        "-f",
        "inet",
        "-F",
        "0",
    ]
    with pytest.raises(KernelRoutesError):
        kernel_routes(FakeNode(""), family="ethernet")
