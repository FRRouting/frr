#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright (C) 2018-2022  David Lamparter for NetDEF, Inc.
"""
IPv6 Multicast Listener Discovery tests.
"""

from topotato import *
from topotato.multicast import *
from topotato.scapy import ScapySend
from scapy.all import (
    IPv6,
    ICMPv6MLReport2,
    ICMPv6MLDMultAddrRec,
    IPv6ExtHdrHopByHop,
    RouterAlert,
    UDP,
)


@topology_fixture()
def mld_topo1(topo):
    """
    [     ]-----[ h1 ]
    [     ]
    [ dut ]-----[ h2 ]
    [     ]
    [     ]-----{ lan }-----[ src ]
    """


class Configs(FRRConfigs):
    routers = ["dut"]

    zebra = """
    #% extends "boilerplate.conf"
    #% block main
    debug zebra events
    debug zebra packet
    debug zebra rib detailed
    debug zebra nht detailed
    #% endblock
    """

    pim6d = """
    #% extends "boilerplate.conf"
    #% block main
    #% endblock
    """


@config_fixture(Configs)
def mld_topo1_configs(config, mld_topo1):
    return config


@instance_fixture()
def mld_topo1_testenv(mld_topo1_configs):
    instance = FRRNetworkInstance(mld_topo1_configs.topology, mld_topo1_configs)
    instance.prepare()
    return instance


def iter_mld_records(report):
    for record in report.records:
        while isinstance(record, ICMPv6MLDMultAddrRec):
            yield record
            record = record.payload

class MLDBasic(TestBase):
    instancefn = mld_topo1_testenv

    @topotatofunc
    def prepare(self, topo, dut, h1, h2, src):
        for iface in dut.ifaces:
            yield from AssertVtysh.make(dut, "pim6d", "enable\nconfigure\ninterface %s\nipv6 pim" % iface.ifname)

        yield from AssertVtysh.make(dut, "pim6d", "debug show mld interface %s" % (dut.iface_to('h1').ifname))

        self.receiver = MulticastReceiver(h1, h1.iface_to('dut'))

        # wait for query before continuing
        yield from AssertLog.make(dut, 'pim6d', '[MLD default:dut-h1] MLD query', maxwait=3.0)

        # get out of initial reporting (prevents timing issues later)
        def expect_pkt(ipv6: IPv6, report: ICMPv6MLReport2):
            for record in iter_mld_records(report):
                if record.rtype == 2: # IS_EX
                    return True
        yield from AssertPacket.make("h1_dut", maxwait=5.0, pkt=expect_pkt)

    @topotatofunc
    def test_ssm(self, topo, dut, h1, h2, src):
        """
        Join a (S,G) on MLD and try forwarding a packet on it.
        """
        srcaddr = src.iface_to('lan').ip6[0].ip

        yield from self.receiver.join('ff05::2345', srcaddr)

        yield from AssertLog.make(dut, 'pim6d', '[MLD default:dut-h1 (%s,ff05::2345)] NOINFO => JOIN' % srcaddr, maxwait=3.0)
        yield from AssertVtysh.make(dut, "pim6d", "debug show mld interface %s" % (dut.iface_to('h1').ifname))

        ip = IPv6(hlim=255, src=srcaddr, dst="ff05::2345")
        udp = UDP(sport=9999, dport=9999)
        yield from ScapySend.make(
            src,
            "src-lan",
            pkt = ip/udp,
        )

        def expect_pkt(ipv6: IPv6, udp: UDP):
            return ipv6.src == str(srcaddr) and ipv6.dst == 'ff05::2345' \
                and udp.dport == 9999

        yield from AssertPacket.make("h1_dut", maxwait=2.0, pkt=expect_pkt)

    @topotatofunc
    def test_asm(self, topo, dut, h1, h2, src):
        yield from self.receiver.join('ff05::1234')

        yield from AssertLog.make(dut, 'pim6d', '[MLD default:dut-h1 (*,ff05::1234)] NOINFO => JOIN', maxwait=2.0)
        yield from AssertVtysh.make(dut, "pim6d", "debug show mld interface %s" % (dut.iface_to('h1').ifname))

    @topotatofunc
    def test_no_rtralert(self, topo, dut, h1, h2, src):
        """
        MLD code should be ignoring MLD reports without router alert option.
        """
        ip = IPv6(hlim=1, src=h1.iface_to("dut").ll6, dst="ff02::16")
        rec0 = ICMPv6MLDMultAddrRec(dst="ff0e::1234")

        yield from ScapySend.make(
            h1,
            "h1-dut",
            pkt = ip/ICMPv6MLReport2(records = [rec0]),
        )
        yield from AssertLog.make(dut, 'pim6d', 'packet without IPv6 Router Alert MLD option', maxwait=2.0)

    @topotatofunc
    def test_invalid_group(self, topo, dut, h1, h2, src):
        """
        An unicast address is not a valid group address.
        """
        ip = IPv6(hlim=1, src=h1.iface_to("dut").ll6, dst="ff02::16")
        hbh = IPv6ExtHdrHopByHop(options = RouterAlert())
        mfrec0 = ICMPv6MLDMultAddrRec(dst="fe80::1234")

        yield from ScapySend.make(
            h1,
            "h1-dut",
            pkt = ip/hbh/ICMPv6MLReport2(records = [mfrec0]),
        )
        yield from AssertLog.make(dut, 'pim6d', '[MLD default:dut-h1 fe80::fc02:ff:fefe:100] malformed MLDv2 report (invalid group fe80::1234)', maxwait=2.0)
