import pytest

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
def pim6_topo1(topo):
    """
    [ h1 ]--{ lan }--[ r1 ]---[ r2 ]---[ h2 ]
    """


class Configs(FRRConfigs):
    routers = ["r1", "r2"]

    zebra = """
    #% extends "boilerplate.conf"
    #% block main
    debug zebra events
    debug zebra packet
    debug zebra rib detailed
    debug zebra nht detailed
    #% endblock
    """

    staticd = """
    #% extends "boilerplate.conf"
    #% block main
    #%   if router.name == 'r2'
    ipv6 route {{ routers['r1'].lo_ip6[0].ip }}/128 {{ routers['r1'].iface_to('r2').ll6 }} {{ router.iface_to('r1').ifname }}
    ipv6 route {{ topo.lans['lan'].ip6[0] }} {{ routers['r1'].iface_to('r2').ll6 }} {{ router.iface_to('r1').ifname }}
    #%   elif router.name == 'r1'
    ipv6 route {{ routers['r2'].lo_ip6[0].ip }}/128 {{ routers['r2'].iface_to('r1').ll6 }} {{ router.iface_to('r2').ifname }}
    #%   endif
    #% endblock
    """

    pim6d = """
    #% extends "boilerplate.conf"
    #% block main
    #% endblock
    """


@config_fixture(Configs)
def pim6_topo1_configs(config, pim6_topo1):
    return config


@instance_fixture()
def pim6_topo1_testenv(pim6_topo1_configs):
    instance = FRRNetworkInstance(pim6_topo1_configs.topology, pim6_topo1_configs)
    instance.prepare()
    return instance


class PIM6Basic(TestBase):
    instancefn = pim6_topo1_testenv

    @topotatofunc
    def prepare(self, topo, h1, h2, r1, r2):
        self.receiver = MulticastReceiver(h2, h2.iface_to('r2'))

        for rt in [r1, r2]:
            for iface in rt.ifaces:
                yield from AssertVtysh.make(rt, "pim6d", "enable\nconfigure\ninterface %s\nipv6 pim" % iface.ifname)
            yield from AssertVtysh.make(rt, "pim6d", "enable\nconfigure\ninterface lo\nipv6 pim\nexit\nipv6 pim rp %s ff00::/8" % r1.lo_ip6[0].ip)
            yield from AssertVtysh.make(rt, "zebra", "show ipv6 route")

        self.receiver = MulticastReceiver(h2, h2.iface_to('r2'))

        yield from AssertVtysh.make(r1, "pim6d", "show ipv6 pim rp-info")
        yield from AssertVtysh.make(r2, "pim6d", "show ipv6 pim rp-info", """
        RP address       group/prefix-list   OIF               I am RP    Source   Group-Type
        fd00::3          ff00::/8            r2-r1             no        Static   ASM
        """, maxwait=5.0)

    @topotatofunc
    def test_ssm(self, topo, h1, h2, r1, r2):
        """
        Join a (S,G) on MLD and try forwarding a packet on it.
        """
        srcaddr = h1.iface_to('lan').ip6[0].ip

        yield from self.receiver.join('ff05::2345', srcaddr)

        yield from AssertLog.make(r2, 'pim6d', '[MLD default:r2-h2 (%s,ff05::2345)] NOINFO => JOIN' % srcaddr, maxwait=3.0)
        yield from AssertVtysh.make(r2, "pim6d", "debug show mld interface %s" % (r2.iface_to('h2').ifname))

        yield from AssertLog.make(r1, 'pim6d', 'pim_forward_start: (S,G)=(%s,ff05::2345) oif=r1-r2' % srcaddr, maxwait=3.0)

        ip = IPv6(hlim=255, src=srcaddr, dst="ff05::2345")
        udp = UDP(sport=9999, dport=9999)
        yield from ScapySend.make(
            h1,
            "h1-lan",
            pkt = ip/udp,
        )
        yield from ScapySend.make(
            h1,
            "h1-lan",
            pkt = ip/udp,
        )
        yield from ScapySend.make(
            h1,
            "h1-lan",
            pkt = ip/udp,
        )

        def expect_pkt(pkt):
            if "ipv6" not in pkt or "udp" not in pkt:
                return False
            return (
                pkt["ipv6/.src"].val == srcaddr,
                pkt["ipv6/.dst"].val == 'ff05::2345',
            )

        yield from AssertPacket.make("r2_h2", maxwait=3.0, pkt=expect_pkt)
