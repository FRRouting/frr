#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright (C) 2022 Jugroo Jesvin Brian

# pylint: disable=invalid-name, missing-class-docstring, missing-function-docstring, line-too-long, consider-using-f-string, unknown-option-value, wildcard-import, unused-argument, f-string-without-interpolation, too-few-public-methods, unused-wildcard-import

"""
Test if Extended Optional Parameters Length encoding format works
if forced with a knob.
https://datatracker.ietf.org/doc/html/rfc9072
"""

__topotests_file__ = "bgp_extended_optional_parameters_length/test_bgp_extended_optional_parameters_length.py"
__topotests_gitrev__ = "bfe6156ab0f4ea00e399d3374b2131d88108ce14"

from topotato import *


@topology_fixture()
def topology(topo):
    """
    [ r1 ]
       |
    { s1 }
       |
    [ r2 ]
    """


class Configs(FRRConfigs):
    routers = ["r1", "r2"]

    zebra = """
    #% extends "boilerplate.conf"
    #% block main
    #%  if router.name == 'r2'
    interface lo
     ip address {{ routers.r2.lo_ip4[0] }}
    !
    #%  endif
    #%  for iface in router.ifaces
    interface {{ iface.ifname }}
     ip address {{ iface.ip4[0] }}
    !
    #%  endfor
    ip forwarding
    !
    #% endblock
    """

    bgpd = """
    #% block main
    #%  if router.name == 'r2'
    router bgp 65002
     no bgp ebgp-requires-policy
     neighbor {{ routers.r1.ifaces[0].ip4[0].ip }} remote-as external
     neighbor {{ routers.r1.ifaces[0].ip4[0].ip }} extended-optional-parameters
     address-family ipv4
      redistribute connected
     exit-address-family
    #%   elif router.name == 'r1'
    router bgp 65001
     no bgp ebgp-requires-policy
     neighbor {{ routers.r2.ifaces[0].ip4[0].ip }} remote-as external
     neighbor {{ routers.r2.ifaces[0].ip4[0].ip }} extended-optional-parameters
    !
    #%   endif
    #% endblock
    """


class BGPExtendedOptionalParametersLength(
    TestBase, AutoFixture, topo=topology, configs=Configs
):
    @topotatofunc
    def bgp_converge(self, _, r1, r2):
        expected = {
            "peers": {
                str(r2.ifaces[0].ip4[0].ip): {
                    "pfxRcd": 2,
                    "pfxSnt": 2,
                    "state": "Established",
                    "peerState": "OK",
                }
            }
        }
        yield from AssertVtysh.make(
            r1,
            "bgpd",
            f"show bgp ipv4 unicast summary json",
            maxwait=2.0,
            compare=expected,
        )

    @topotatofunc
    def _bgp_extended_optional_parameters_length(self, _, r1, r2):
        expected = {
            str(r2.ifaces[0].ip4[0].ip): {"extendedOptionalParametersLength": True}
        }
        yield from AssertVtysh.make(
            r1,
            "bgpd",
            f"show bgp neighbor {r2.ifaces[0].ip4[0].ip} json",
            maxwait=2.0,
            compare=expected,
        )
