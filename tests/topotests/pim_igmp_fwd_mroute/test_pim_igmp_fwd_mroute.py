#!/usr/bin/env python
# SPDX-License-Identifier: ISC

#
# test_pim_igmp_fwd_mroute.py
#
# Copyright (c) 2026 Architecture Technology Corporation
#                    Jafar Al-Gharaibeh
#

"""
IGMP Fwd/Mroute columns and the show ip mroute detail Origin column.

Topology: r1 alone, RP on its own loopback, receiver on r1-eth0.

    lo (RP 10.0.0.1) -- r1 -- r1-eth0 -- s1

r1-eth0 has an ASM static-group and an ASM join-group. With the RP local,
(*,G) installs with IIF lo and outputs r1-eth0 plus pimreg. That is enough
to pin the new fields:

  static-group  forwarded false, mroute true, origin S
                groups timer stopped, lastReporter 0.0.0.0, flags S
  join-group    forwarded true,  mroute true, origin LH
                groups flags LH (the join socket also produces a learned report)
  pimreg        origin R
  join-group    lastReporter is r1-eth0's address, queryRetransmit 0
  querier       lastQuerySent once the startup query is transmitted

Inheritance (*), PIM (P),
dense (D) and VxLAN (V) need a second router or a tunnel, so they are not
produced here.
"""

import os
import sys

import pytest

CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

from lib import topotest
from lib.topogen import Topogen, get_topogen

pytestmark = [pytest.mark.pimd]

STATIC_GROUP = "239.1.1.1"
JOIN_GROUP = "239.2.2.2"
RECV_IF = "r1-eth0"


def build_topo(tgen):
    tgen.add_router("r1")

    # Bring r1-eth0 up. No second router: r1 is DR on its own.
    switch = tgen.add_switch("s1")
    switch.add_link(tgen.gears["r1"])


def setup_module(mod):
    tgen = Topogen(build_topo, mod.__name__)
    tgen.start_topology()

    r1 = tgen.gears["r1"]
    r1.load_frr_config("frr.conf")
    tgen.start_router()

    # Boot config applies "ip igmp static-group" before "ip pim". That join
    # stores a channel oil and does not retry, so the interface never becomes
    # an mroute output. Add the group once PIM is up.
    output = r1.vtysh_cmd(
        """
        configure terminal
        interface {}
         ip igmp static-group {}
        """.format(
            RECV_IF, STATIC_GROUP
        )
    )
    assert "Unknown command" not in (output or ""), output


def teardown_module(mod):
    get_topogen().stop_topology()


def _cols(text, group):
    """Whitespace columns of the row that contains group."""
    for line in text.splitlines():
        parts = line.split()
        if group in parts:
            return parts
    return None


def test_igmp_forwarded_and_mroute():
    """Static group is installed but not an IGMP forwarder. Join-group is both."""
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]
    static_expected = {
        "vrf": "default",
        RECV_IF: {
            "groups": [
                {
                    "source": "*",
                    "group": STATIC_GROUP,
                    "primaryAddr": "10.1.1.1",
                    "forwarded": False,
                    "mroute": True,
                }
            ]
        },
    }
    join_expected = {
        "vrf": "default",
        RECV_IF: {
            "groups": [
                {
                    "source": "*",
                    "group": JOIN_GROUP,
                    "primaryAddr": "10.1.1.1",
                    "forwarded": True,
                    "mroute": True,
                }
            ]
        },
    }
    groups_expected = {
        RECV_IF: {
            "groups": [
                {
                    "group": JOIN_GROUP,
                    "forwarded": True,
                    "mroute": True,
                    "flags": "LH",
                    "queryRetransmit": 0,
                    "lastReporter": "10.1.1.1",
                    "lastReport": "*",
                },
                {
                    "group": STATIC_GROUP,
                    "timer": "stopped",
                    "forwarded": False,
                    "mroute": True,
                    "flags": "S",
                    "queryRetransmit": 0,
                    "lastReporter": "0.0.0.0",
                },
            ]
        }
    }
    groups_detail_expected = {
        RECV_IF: {
            "groups": [
                {
                    "group": JOIN_GROUP,
                    "forwarded": True,
                    "mroute": True,
                    "flags": "LH",
                    "queryRetransmit": 0,
                    "lastReporter": "10.1.1.1",
                    "lastReport": "*",
                    "sources": [
                        {
                            "source": "*",
                            "forwarded": True,
                            "mroute": True,
                            "flags": "LH",
                            "queryRetransmit": 0,
                        }
                    ],
                },
                {
                    "group": STATIC_GROUP,
                    "timer": "stopped",
                    "forwarded": False,
                    "mroute": True,
                    "flags": "S",
                    "lastReporter": "0.0.0.0",
                    "sources": [
                        {
                            "source": "*",
                            "forwarded": False,
                            "mroute": True,
                            "flags": "S",
                            "queryRetransmit": 0,
                        }
                    ],
                },
            ]
        }
    }
    sources_expected = {
        RECV_IF: {
            JOIN_GROUP: {
                "group": JOIN_GROUP,
                "queryRetransmit": 0,
                "lastReporter": "10.1.1.1",
                "lastReport": "*",
                "sources": [
                    {
                        "source": "*",
                        "forwarded": True,
                        "mroute": True,
                        "queryRetransmit": 0,
                    }
                ],
            }
        }
    }

    def _check():
        diff = topotest.router_json_cmp(
            r1, "show ip igmp static-group json", static_expected
        )
        if diff is not None:
            return diff
        diff = topotest.router_json_cmp(r1, "show ip igmp join json", join_expected)
        if diff is not None:
            return diff
        diff = topotest.router_json_cmp(r1, "show ip igmp groups json", groups_expected)
        if diff is not None:
            return diff
        diff = topotest.router_json_cmp(
            r1, "show ip igmp groups detail json", groups_detail_expected
        )
        if diff is not None:
            return diff
        diff = topotest.router_json_cmp(
            r1, "show ip igmp sources json", sources_expected
        )
        if diff is not None:
            return diff

        static_text = r1.vtysh_cmd("show ip igmp static-group")
        join_text = r1.vtysh_cmd("show ip igmp join")
        groups_text = r1.vtysh_cmd("show ip igmp groups")
        detail_text = r1.vtysh_cmd("show ip igmp groups detail")
        sources_text = r1.vtysh_cmd("show ip igmp sources")
        if "Fwd Mroute" not in static_text:
            return "static-group text has no Fwd/Mroute header:\n{}".format(static_text)
        if "Fwd Mroute" not in join_text:
            return "join text has no Fwd/Mroute header:\n{}".format(join_text)
        if "Fwd MRT" not in groups_text:
            return "groups text has no Fwd/MRT header:\n{}".format(groups_text)
        if "Fwd Mroute" not in sources_text or "Query" not in sources_text:
            return "sources text has no Fwd/Mroute/Query header:\n{}".format(
                sources_text
            )
        if "MRT Flags Query" not in groups_text:
            return "groups text has no Flags header:\n{}".format(groups_text)
        legend = "Flags: H - host report, L - local join, S - static-group"
        if legend not in groups_text:
            return "groups text has no Flags legend:\n{}".format(groups_text)
        if "MRT Flags Query" not in detail_text or "LastReport" not in detail_text:
            return "groups detail text has no Flags/LastReport:\n{}".format(detail_text)
        static_cols = _cols(static_text, STATIC_GROUP)
        join_cols = _cols(join_text, JOIN_GROUP)
        static_group_cols = _cols(groups_text, STATIC_GROUP)
        group_cols = _cols(groups_text, JOIN_GROUP)
        detail_cols = _cols(detail_text, JOIN_GROUP)
        static_detail = _cols(detail_text, STATIC_GROUP)
        source_cols = _cols(sources_text, JOIN_GROUP)
        if not static_cols or tuple(static_cols[-2:]) != ("N", "Y"):
            return "static-group text flags are not N Y:\n{}".format(static_text)
        if not join_cols or tuple(join_cols[-2:]) != ("Y", "Y"):
            return "join text flags are not Y Y:\n{}".format(join_text)
        # groups row ends Fwd, Mroute, Flags, Query, LastReporter
        if (
            not group_cols
            or tuple(group_cols[-5:-3]) != ("Y", "Y")
            or group_cols[-3] != "LH"
            or group_cols[-1] != "10.1.1.1"
        ):
            return "groups text flags or last reporter:\n{}".format(groups_text)
        if (
            not static_group_cols
            or tuple(static_group_cols[-5:-3]) != ("N", "Y")
            or static_group_cols[-3] != "S"
            or static_group_cols[-1] != "0.0.0.0"
            or "stopped" not in static_group_cols
        ):
            return "static group is not a stopped groups row:\n{}".format(groups_text)
        # detail row ends Fwd, Mroute, Flags, Query, LastReporter, LastReport
        if not detail_cols or detail_cols[-4] != "LH" or detail_cols[-2] != "10.1.1.1":
            return "groups detail flags or last reporter:\n{}".format(detail_text)
        if not static_detail or static_detail[-4] != "S":
            return "static groups detail flags:\n{}".format(detail_text)
        # sources row ends Query, Uptime
        if not source_cols or source_cols[-2] != "0":
            return "sources text query count:\n{}".format(sources_text)
        iface = r1.vtysh_cmd("show ip igmp interface {}".format(RECV_IF))
        if "Last Sent   : never" in iface or "Last Sent" not in iface:
            return "querier has not sent a query:\n{}".format(iface)
        diff = topotest.router_json_cmp(
            r1,
            "show ip igmp interface json",
            {RECV_IF: {"lastQuerySent": "*"}},
        )
        if diff is not None:
            return diff
        return None

    _, result = topotest.run_and_expect(_check, None, count=90, wait=1)
    assert result is None, result


def test_mroute_origin():
    """(*,G) outputs: static S, join LH, register R. IIF is the local RP."""
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]
    expected = {
        STATIC_GROUP: {
            "*": {
                "installed": 1,
                "iif": "lo",
                "oil": {
                    RECV_IF: {
                        "outboundInterface": RECV_IF,
                        "origin": "S",
                        "protocolIgmp": True,
                    },
                    "pimreg": {
                        "outboundInterface": "pimreg",
                        "origin": "R",
                    },
                },
            }
        },
        JOIN_GROUP: {
            "*": {
                "installed": 1,
                "iif": "lo",
                "oil": {
                    RECV_IF: {
                        "outboundInterface": RECV_IF,
                        "origin": "LH",
                        "protocolIgmp": True,
                    },
                    "pimreg": {
                        "outboundInterface": "pimreg",
                        "origin": "R",
                    },
                },
            }
        },
    }

    def _check():
        diff = topotest.router_json_cmp(r1, "show ip mroute detail json", expected)
        if diff is not None:
            return diff
        text = r1.vtysh_cmd("show ip mroute detail")
        legend = "Origin: H - host report, L - local join, S - static-group, P - PIM"
        if legend not in text:
            return "mroute text is missing the Origin legend:\n{}".format(text)
        if "Source" not in text or "Origin" not in text or "Output" not in text:
            return "mroute text is missing the Origin column:\n{}".format(text)
        return None

    _, result = topotest.run_and_expect(_check, None, count=90, wait=1)
    assert result is None, result


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
