#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright (C) 2018-2021  David Lamparter for NetDEF, Inc.
"""
Network object model representation
"""

import ipaddress
import re
import binascii
from itertools import chain

import abc
from typing import (
    Any,
    Callable,
    Dict,
    Generator,
    List,
    Optional,
    Sequence,
    Tuple,
    Type,
    Union,
    cast,
)

try:
    from typing import Literal
except ImportError:
    from typing_extensions import Literal  # type: ignore

from .parse import Topology

AnyNetwork = Union[ipaddress.IPv4Network, ipaddress.IPv6Network]
AnyInterface = Union[ipaddress.IPv4Interface, ipaddress.IPv6Interface]
AnyAddress = Union[ipaddress.IPv4Address, ipaddress.IPv6Address]


def addr2net(addr: AnyAddress, plen: int) -> AnyNetwork:
    return ipaddress.ip_network("%s/%d" % (str(addr), plen))


def addr2iface(addr: AnyAddress, plen: int) -> AnyInterface:
    return ipaddress.ip_interface("%s/%d" % (str(addr), plen))


# automatic assignment ranges

lo4_net = ipaddress.IPv4Interface("10.255.0.0/24")
lo6_net = ipaddress.IPv6Interface("fd00::/64")
lan4_net = lambda n: addr2net(
    ipaddress.IPv4Address("10.0.0.0") + (100 + n) * 2**16, 16
)
lan6_net = lambda n: addr2net(ipaddress.IPv6Address("fdbc::") + n * 2**96, 64)
p2p_ip4 = lambda g, a, b: addr2iface(
    ipaddress.IPv4Address("10.0.0.0") + g * 2**16 + a * 2**8 + b, 16
)


class IPPrefixListBase(list):
    """
    list subclass that only contains IPNetwork/IPInterface items

    .noauto can be set to True to prevent auto() from doing its thing
    """

    cls: Type
    noauto: bool

    def append(self, what):
        """
        helper for adding items, automatically converts strings
        """

        if isinstance(what, self.cls):
            super().append(what)
        elif isinstance(what, str):
            super().append(self.cls(what))
        else:
            raise ValueError(
                "Invalid value for IPPrefixList: %r (want %r)" % (what, self.cls)
            )

    def auto(self, addr):
        """
        add addr only if we have no other address and "noauto" is not set
        """
        if len(self) > 0:
            return
        if self.noauto:
            return
        self.append(addr)


class IPPrefixIfaceList(IPPrefixListBase):
    cls: Type[AnyInterface]

    def __init__(self, af: Union[Literal[4], Literal[6]]):
        super().__init__()
        self.noauto = False
        if af == 4:
            self.cls = ipaddress.IPv4Interface
        elif af == 6:
            self.cls = ipaddress.IPv6Interface
        else:
            raise ValueError("Invalid IPPrefixIfaceList config")


class IPPrefixNetworkList(IPPrefixListBase):
    cls: Type[AnyNetwork]

    def __init__(self, af: Union[Literal[4], Literal[6]]):
        super().__init__()
        self.noauto = False
        if af == 4:
            self.cls = ipaddress.IPv4Network
        elif af == 6:
            self.cls = ipaddress.IPv6Network
        else:
            raise ValueError("Invalid IPPrefixNetworkList config")


num_re = re.compile(r"[0-9]+")


def name_to_tuple(name: str) -> Sequence[Union[str, int]]:
    """
    convert string "abc123def456ghi" to ("abc",123,"def",456,"ghi") for sorting

    this way, "r1" sorts before "r10"
    """
    strs = num_re.split(name)
    nums = [int(i) for i in num_re.findall(name)] + [0]
    return tuple(
        cast(List[Union[str, int]], list(chain.from_iterable(zip(strs, nums)))[:-1])
    )


class NOMNode:
    """
    base for everything in the network model
    """

    network: "Network"

    def __init__(self, network):
        self.network = network


class NOMLinked(NOMNode, metaclass=abc.ABCMeta):
    """
    all the utility functions for finding other elements on the network
    """

    name: str
    ifaces: List["LinkIface"]

    sortkey: Tuple[Any]
    num: int
    dotname: str

    def __init__(self, network):
        super().__init__(network)
        self.ifaces = []

    def __lt__(self, other):
        return self.sortkey < other.sortkey

    def add_iface(self, iface):
        self.ifaces.append(iface)

    def auto_ifnames(self):
        for i in self.ifaces:
            if i.ifname is None:
                ifname = "%s-%s" % (self.name, i.other.endpoint.name)
                if i.link.parallel_num != 0:
                    ifname += "-%d" % (i.link.parallel_num)
                i.ifname = ifname
            if i.macaddr is None:
                typecode = 0xBC if isinstance(i.other.endpoint, LAN) else 0xFE
                i.macaddr = "fe:%02x:%02x:%02x:%02x:%02x" % (
                    self.num,
                    i.link.parallel_num,
                    typecode,
                    i.other.endpoint.num,
                    i.link.parallel_num,
                )

    def ifaces_to(self, other: str) -> List["LinkIface"]:
        """
        get all the interfaces of this node that go to "other"
        """
        return [i for i in self.ifaces if i.other.endpoint.name == other]

    def iface_to(self, other: str) -> "LinkIface":
        """
        get the *one* interfaces of this node that goes to "other"
        """
        ifaces = self.ifaces_to(other)
        assert len(ifaces) == 1
        return ifaces[0]

    def iface_peer(self, other: str, via=Optional["LAN"]) -> "LinkIface":
        """
        get another node's interface connected to us, optionally via LAN

        LAN must be specified if it's not a direct p2p link
        """
        ortr = self.network.routers[other]

        if via is None:
            return ortr.iface_to(self.name)
        return ortr.iface_to(via)

    def flip(self, a: str, b: str) -> "NOMLinked":
        """
        get the one of (a, b) that's not us
        """
        other = b if self.name == a else a
        return self.network.routers[other]

    def addrs(
        self, af: Union[None, Literal[4], Literal[6]] = None
    ) -> Generator[AnyInterface, None, None]:
        for iface in self.ifaces:
            if af in [None, 4]:
                yield from iface.ip4
            if af in [None, 6]:
                yield from iface.ip6

    @abc.abstractmethod
    def __repr__(self):
        pass

    @abc.abstractmethod
    def dot(self, out: List[str]):
        pass


class Router(NOMLinked):
    """
    represent a router on the topology

    can also be used for clients/hosts

    TODO: VRF support
    """

    lo_ip4: IPPrefixIfaceList
    lo_ip6: IPPrefixIfaceList

    def __init__(self, network, name):
        super().__init__(network)
        self.name = name
        self.sortkey = ("a_rtr",) + name_to_tuple(name)
        self.lo_ip4 = IPPrefixIfaceList(4)
        self.lo_ip6 = IPPrefixIfaceList(6)

    def auto_lo4(self):
        self.lo_ip4.auto(lo4_net + self.num)

    def auto_lo6(self):
        self.lo_ip6.auto(lo6_net + self.num)

    def addrs(
        self, af: Union[None, Literal[4], Literal[6]] = None
    ) -> Generator[AnyInterface, None, None]:
        yield from super().addrs(af)
        if af in [None, 4]:
            yield from self.lo_ip4
        if af in [None, 6]:
            yield from self.lo_ip6

    def __repr__(self):
        return '<Router %d "%s">' % (self.num, self.name)

    @property
    def dotname(self):
        return "router-%s" % (self.name)

    def neighbors(
        self,
        *,
        rtr_filter: Callable[["Router"], bool] = lambda nbr: True,
    ) -> Generator[Tuple["LinkIface", "LinkIface", "Router"], None, None]:
        """
        Iterate neighbor routers this router can see.
        """
        for self_iface in self.ifaces:
            ep = self_iface.other.endpoint
            if ep is self:
                continue
            if isinstance(ep, LAN):
                for lanport in ep.ifaces:
                    nbr = lanport.other.endpoint
                    if nbr is self:
                        continue
                    if not isinstance(nbr, Router):
                        raise TypeError(
                            f"topology consistency error, expected router for {nbr!r}"
                        )
                    if not rtr_filter(nbr):
                        continue
                    yield (self_iface, lanport.other, nbr)
            elif not isinstance(ep, Router):
                raise TypeError(
                    f"topology consistency error, expected router for {nbr!r}"
                )
            elif not rtr_filter(ep):
                continue
            else:
                yield (self_iface, self_iface.other, ep)

    def dot(self, out: List[str]):
        """
        graphviz representation
        """

        ip4 = "".join(
            ['<br/><font color="#663300">%s</font>' % str(addr) for addr in self.lo_ip4]
        )
        ip6 = "".join(
            ['<br/><font color="#003366">%s</font>' % str(addr) for addr in self.lo_ip6]
        )
        tabrows = []
        for i in self.ifaces:
            iip4 = "".join(
                [
                    '<font color="#663300" point-size="10">%s</font><br align="right"/>'
                    % str(addr)
                    for addr in i.ip4
                ]
            )
            iip6 = "".join(
                [
                    '<font color="#003366" point-size="11">%s</font><br align="right"/>'
                    % str(addr)
                    for addr in i.ip6
                ]
            )
            tabrows.append(
                '<td id="%s_%s" port="%s" align="right">%s<br align="right"/>'
                '<font point-size="10">%s</font><br align="right"/>%s%s</td>'
                % (self.dotname, i.ifname, i.ifname, i.ifname, i.macaddr, iip4, iip6)
            )
        if len(tabrows) == 0:
            tabrows = [""]
        main = '<td rowspan="%d"><b>%s</b>%s%s</td>' % (
            len(tabrows),
            self.name,
            ip4,
            ip6,
        )
        tabrows[0] = main + tabrows[0]

        out.append(
            """ "%s" [ id="%s", shape=none, label=<<table>
%s
</table>>, style = filled, fillcolor="#ffffff"
];"""
            % (
                self.dotname,
                self.dotname,
                "\n".join(["<tr>%s</tr>" % row for row in tabrows]),
            )
        )


class LAN(NOMLinked):
    """
    a LAN in this topology that 1..n routers may connect to

    direct p2p links between routers are *not* going through this

    stub networks can be represented with a LAN connected to a Router and
    nothing else
    """

    ip4: IPPrefixNetworkList
    ip6: IPPrefixNetworkList

    def __init__(self, network, name):
        super().__init__(network)
        self.name = name
        self.sortkey = ("z_lan",) + name_to_tuple(name)
        self.ip4 = IPPrefixNetworkList(4)
        self.ip6 = IPPrefixNetworkList(6)

    def auto_ip4(self):
        self.ip4.auto(lan4_net(self.num))

    def auto_ip6(self):
        self.ip6.auto(lan6_net(self.num))

    def addrs(
        self, af: Union[None, Literal[4], Literal[6]] = None
    ) -> Generator[AnyInterface, None, None]:
        yield from super().addrs(af)
        if af in [None, 4]:
            for net4 in self.ip4:
                yield ipaddress.IPv4Interface(net4)
        if af in [None, 6]:
            for net6 in self.ip6:
                yield ipaddress.IPv6Interface(net6)

    def __repr__(self):
        return '<LAN %d "%s">' % (self.num, self.name)

    @property
    def dotname(self):
        return "lan-%s" % (self.name)

    def dot(self, out: List[str]):
        """
        graphviz representation
        """
        ip4 = "".join(
            ['<br/><font color="#663300">%s</font>' % str(addr) for addr in self.ip4]
        )
        ip6 = "".join(
            ['<br/><font color="#003366">%s</font>' % str(addr) for addr in self.ip6]
        )
        out.append(
            '  "%s" [ id="%s", shape=ellipse, label=<<b>%s</b>%s%s>, style = filled, fillcolor="#cccccc" ];'
            % (self.dotname, self.dotname, self.name, ip4, ip6)
        )


class LinkIface(NOMNode):
    """
    interface on something

    used pretty much everywhere, even LANs have interfaces to routers.
    everything is NOMNode - LinkIface - Link - LinkIface - NOMNode
    for a router-LAN-router link, above chain repeats twice!
    """

    other: "LinkIface"
    endpoint: NOMLinked
    ifname: Optional[str]
    macaddr: Optional[str]
    ip4: IPPrefixIfaceList
    ip6: IPPrefixIfaceList

    def __init__(self, network, link, endpoint):
        super().__init__(network)
        self.link = link
        self.endpoint = endpoint
        self.ifname = None
        self.macaddr = None
        self.ip4 = IPPrefixIfaceList(4)
        self.ip6 = IPPrefixIfaceList(6)
        # Link.__init__ sets up more stuff here for both ifaces

    def __repr__(self):
        return "%r:%r" % (self.endpoint, self.ifname)

    def auto_ip4(self):
        if isinstance(self.endpoint, LAN):
            return
        if isinstance(self.other.endpoint, LAN):
            if self.ip4.noauto or len(self.ip4) > 0:
                return
            for net in self.other.endpoint.ip4:

                self.ip4.append(
                    addr2iface(
                        net.network_address
                        + self.link.parallel_num * 256
                        + self.endpoint.num,
                        net.prefixlen,
                    )
                )
        else:
            self.ip4.auto(
                p2p_ip4(
                    self.link.global_num, self.endpoint.num, self.other.endpoint.num
                )
            )

    def auto_ip6(self):
        if isinstance(self.other.endpoint, LAN):
            if self.ip6.noauto or len(self.ip6) > 0:
                return

            macparts = [int(p, 16) for p in self.macaddr.split(":")]
            macparts[0] ^= 0x02
            macparts[3:3] = [0xFF, 0xFE]
            eui_int = sum([j << (8 * i) for i, j in enumerate(reversed(macparts))])

            for net in self.other.endpoint.ip6:
                addr = net[eui_int]
                iface = ipaddress.IPv6Interface("%s/%d" % (str(addr), net.prefixlen))
                self.ip6.append(iface)

    @property
    def ll6(self):
        mac = self.macaddr.replace(":", "")
        eui = bytearray(binascii.a2b_hex("".join([mac[:6], "fffe", mac[6:]])))
        eui[0] ^= 0x2
        addr = binascii.a2b_hex("fe80000000000000") + eui
        return ipaddress.IPv6Address(bytes(addr))


class Link(NOMNode):
    """
    two LinkIfaces belonging together

    note: LANs are not Links; a Link here is always exactly 2 interfaces
    """

    a: LinkIface
    b: LinkIface

    # set in Network.load_parse
    parallel_num: int
    global_num: int

    # pylint: disable=too-many-arguments
    def __init__(self, network, a_ep, a_detail, b_ep, b_detail):
        super().__init__(network)

        self.a = LinkIface(network, self, a_ep)
        if a_detail:
            self.a.ifname = a_detail.m.group(1)
        self.b = LinkIface(network, self, b_ep)
        if b_detail:
            self.b.ifname = b_detail.m.group(1)

        self.a.other = self.b
        self.b.other = self.a
        a_ep.add_iface(self.a)
        b_ep.add_iface(self.b)

    def __repr__(self):
        return "<Link %r %r -- %r>" % (self.parallel_num, self.a, self.b)

    def dot(self, out: List[str]):
        """
        graphviz representation
        """
        if isinstance(self.a.endpoint, LAN):
            a_name = self.a.endpoint.dotname
            a_id = self.a.endpoint.dotname
        else:
            a_name = '%s":"%s' % (self.a.endpoint.dotname, self.a.ifname)
            a_id = "%s/%s" % (self.a.endpoint.name, self.a.ifname)
        if isinstance(self.b.endpoint, LAN):
            b_name = self.b.endpoint.dotname
            b_id = self.a.endpoint.dotname
        else:
            b_name = '%s":"%s' % (self.b.endpoint.dotname, self.b.ifname)
            b_id = "%s/%s" % (self.b.endpoint.name, self.b.ifname)

        cheat_name = "%s_%s_%d" % (
            self.a.endpoint.dotname,
            self.b.endpoint.dotname,
            self.parallel_num,
        )

        if not isinstance(self.b.endpoint, LAN) and not isinstance(
            self.a.endpoint, LAN
        ):
            out.append(
                '  "%s" [ id="%s", shape=ellipse, label=<p2p#%d>, style = filled, fillcolor="#eeeecc" ];'
                % (cheat_name, cheat_name, self.global_num)
            )
            out.append('  "%s" -- "%s" [ id="%s" ];' % (a_name, cheat_name, a_id))
            out.append('  "%s" -- "%s" [ id="%s" ];' % (b_name, cheat_name, b_id))
        else:
            out.append('  "%s" -- "%s" [ id="%s" ];' % (a_name, b_name, cheat_name))


class Network:
    """
    container for everything here

    with a bunch of utilities that don't fit on the individual classes
    """

    diagram: Optional[str]
    routers: Dict[str, Router]
    lans: Dict[str, LAN]
    links: Dict[Tuple[NOMLinked, NOMLinked], List[Link]]

    # defaults
    noauto_v4 = False
    noauto_v6 = False
    lo_v4 = True
    lo_v6 = True

    def __init__(self):
        self.diagram = None
        self.routers = {}
        self.lans = {}
        self.links = {}

    def router(self, name: str, create=False):
        if name not in self.routers:
            if not create:
                raise IndexError('router "%s" does not exist' % name)
            self.routers[name] = Router(self, name)
        return self.routers[name]

    def lan(self, name: str, create=False):
        if name not in self.lans:
            if not create:
                raise IndexError('lan "%s" does not exist' % name)
            self.lans[name] = LAN(self, name)
        return self.lans[name]

    def link_all(self, routers):
        assert len(routers) == 2
        a, b = routers
        if b < a:
            a, b = b, a
        return self.links.setdefault((a, b), [])

    def load_parse(self, parse: Topology):
        """
        main entry point
        """
        self.diagram = parse.topo
        for routerp in parse.routers:
            self.router(routerp.name, True)
        for i, router in enumerate(sorted(self.routers.values())):
            router.num = i + 1

        for lanp in parse.lans:
            self.lan(lanp.name, True)
        for i, lan in enumerate(sorted(self.lans.values())):
            lan.num = i + 1

        def topo_rtr_or_lan(item):
            if isinstance(item, Topology.Router):
                return self.router(item.name)
            return self.lan(item.name)

        for linkp in parse.links:
            assert len(linkp.routers) == 2
            a = topo_rtr_or_lan(linkp.routers[0][0])
            b = topo_rtr_or_lan(linkp.routers[1][0])
            links = self.link_all((a, b))
            links.append(Link(self, a, linkp.routers[0][1], b, linkp.routers[1][1]))

        j = 0
        for links in self.links.values():
            for i, link in enumerate(links):
                link.parallel_num = i
                link.global_num = j
                j += 1

    def auto_ifnames(self):
        for r in self.routers.values():
            r.auto_ifnames()
        for r in self.lans.values():
            r.auto_ifnames()

    def auto_ip4(self):
        if self.noauto_v4:
            return

        if self.lo_v4:
            for r in self.routers.values():
                r.auto_lo4()
        for r in self.lans.values():
            r.auto_ip4()
        for links in self.links.values():
            for link in links:
                link.a.auto_ip4()
                link.b.auto_ip4()

    def auto_ip6(self):
        if self.noauto_v6:
            return

        if self.lo_v6:
            for r in self.routers.values():
                r.auto_lo6()
        for r in self.lans.values():
            r.auto_ip6()
        for links in self.links.values():
            for link in links:
                link.a.auto_ip6()
                link.b.auto_ip6()

    def macmap(self):
        macmap = {}
        for r in self.routers.values():
            for i in r.ifaces:
                macmap[i.macaddr.lower()] = "%s (%s)" % (r.name, i.ifname)  # (r, i)
        return macmap

    def dot(self):
        out = []
        out += ["graph net {"]
        out += ["  rankdir = LR;"]
        out += ["  margin = 0;"]
        out += [
            '  node [ margin=0, fontname="Inconsolata Semi-Condensed", fontsize=15 ];'
        ]
        out += ['  edge [ margin=0, fontname="Inconsolata Semi-Condensed", minlen=2 ];']
        out += ["  rank=same { "]
        for r in self.routers.values():
            r.dot(out)
        out += ["  } "]
        for r in self.lans.values():
            r.dot(out)
        for links in self.links.values():
            for link in links:
                link.dot(out)
        out.append("}")
        return "\n".join(out)


def test():
    # pylint: disable=import-outside-toplevel
    from . import parse

    topo = parse.test()

    net = Network()
    net.load_parse(topo)

    net.auto_ifnames()
    net.auto_ip4()
    net.auto_ip6()

    # pylint: disable=import-outside-toplevel
    from pprint import pprint

    pprint(sorted(net.routers.values()))
    pprint(sorted(net.lans.values()))
    pprint(sorted(net.links.items()))
    with open("network.dot", "w", encoding="utf-8") as fd:
        fd.write(net.dot())

    return net


if __name__ == "__main__":
    test()
