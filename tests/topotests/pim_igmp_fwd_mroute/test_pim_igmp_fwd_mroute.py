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
  join-group    forwarded true,  mroute true, origin LH
                (the join socket also produces a learned report)
  pimreg        origin R

Static groups stay out of show ip igmp groups. Inheritance (*), PIM (P),
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


def _yn(text, group):
    """Fwd and Mroute are the last two columns on these IGMP tables."""
    for line in text.splitlines():
        if group in line.split():
            parts = line.split()
            if len(parts) >= 2:
                return parts[-2], parts[-1]
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
                }
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
                    "sources": [
                        {
                            "source": "*",
                            "forwarded": True,
                            "mroute": True,
                        }
                    ],
                }
            ]
        }
    }
    sources_expected = {
        RECV_IF: {
            JOIN_GROUP: {
                "group": JOIN_GROUP,
                "sources": [
                    {
                        "source": "*",
                        "forwarded": True,
                        "mroute": True,
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

        groups = r1.vtysh_cmd("show ip igmp groups json", isjson=True)
        if STATIC_GROUP in str(groups):
            return "static group {} showed up in show ip igmp groups: {}".format(
                STATIC_GROUP, groups
            )

        static_text = r1.vtysh_cmd("show ip igmp static-group")
        join_text = r1.vtysh_cmd("show ip igmp join")
        groups_text = r1.vtysh_cmd("show ip igmp groups")
        sources_text = r1.vtysh_cmd("show ip igmp sources")
        if "Fwd Mroute" not in static_text:
            return "static-group text has no Fwd/Mroute header:\n{}".format(static_text)
        if "Fwd Mroute" not in join_text:
            return "join text has no Fwd/Mroute header:\n{}".format(join_text)
        if "Fwd Mroute" not in groups_text:
            return "groups text has no Fwd/Mroute header:\n{}".format(groups_text)
        if "Fwd Mroute" not in sources_text:
            return "sources text has no Fwd/Mroute header:\n{}".format(sources_text)
        if _yn(static_text, STATIC_GROUP) != ("N", "Y"):
            return "static-group text flags are not N Y:\n{}".format(static_text)
        if _yn(join_text, JOIN_GROUP) != ("Y", "Y"):
            return "join text flags are not Y Y:\n{}".format(join_text)
        if _yn(groups_text, JOIN_GROUP) != ("Y", "Y"):
            return "groups text flags are not Y Y:\n{}".format(groups_text)
        if STATIC_GROUP in groups_text:
            return "static group {} showed up in show ip igmp groups:\n{}".format(
                STATIC_GROUP, groups_text
            )
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
