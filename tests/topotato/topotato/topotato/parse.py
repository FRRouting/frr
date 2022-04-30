#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright (C) 2018-2021  David Lamparter for NetDEF, Inc.
"""
Parser for diagram ASCII art network diagrams
"""

import re

import abc
from typing import Tuple, List, Dict, Sequence, Optional, ClassVar, Type, cast


class Topology:
    """
    Parse an ASCII network diagram to an intermediate representation:

    - routers are created as ``[ router ]``
    - lans/switches/bridges as ``{ lan }``
    - routers & lans can be continued on another line with an empty ``{ }``
      / ``[ ]`` (but it must be the same size!)
    - links are drawn with ``----`` or ``|`` lines
    - interface names can optionally be added at the end of links with
      ``( eth0 )``

    This class does not do any address/prefix assignment, it only parses the
    topology into usable items.
    """

    # typing annotations at the end due to forward references

    class Token:
        """
        helper base class for the various token types

        :meta private:
        """

        rx: ClassVar["re.Pattern"]

        m: "re.Match"
        lno: int
        cols: Tuple[int, int]
        used: Optional["Topology.Item"]

        def __init__(self, lno: int, m: "re.Match"):
            self.m = m
            self.lno = lno
            self.cols = (m.start(), m.end())
            self.used = None

        def __repr__(self):
            return "<%s line %d cols %d-%d %r>" % (
                self.__class__.__name__,
                self.lno,
                self.m.start(),
                self.m.end(),
                self.m.group(0),
            )

        @classmethod
        def make(cls, lno, m) -> "Topology.Token":
            return cls(lno, m)

    # tokens/regexes for the various inputs

    class TokRouter(Token):
        rx = re.compile(r"\[\s*([a-zA-Z][-_a-zA-Z0-9]*)\s*\]")

    class TokRouterEmpty(Token):
        rx = re.compile(r"\[\s*\]")

    class TokLAN(Token):
        rx = re.compile(r"\{\s*([a-zA-Z][-_a-zA-Z0-9]*)\s*\}")

    class TokLANEmpty(Token):
        rx = re.compile(r"\{\s*\}")

    class TokIface(Token):
        rx = re.compile(r"\(\s*([a-zA-Z][-_a-zA-Z0-9\.]*)\s*\)")

    class TokLinkH(Token):
        rx = re.compile(r"-+")

    class TokLinkV(Token):
        rx = re.compile(r"\|")

    class TokWhite(Token):
        rx = re.compile(r"\s+")

        @classmethod
        def make(cls, lno, m):
            return None

    tokens = [
        TokRouter,
        TokRouterEmpty,
        TokLAN,
        TokLANEmpty,
        TokIface,
        TokLinkH,
        TokLinkV,
        TokWhite,
    ]

    # the following classes are used to "fuse together" various tokens

    class Item(metaclass=abc.ABCMeta):
        x1: int
        x2: int
        y1: int
        y2: int
        tokens: List["Topology.Token"]

        def __init__(self, token: "Topology.Token"):
            self.x1 = token.cols[0]
            self.x2 = token.cols[1]
            self.y1 = token.lno
            self.y2 = token.lno + 1
            self.tokens = [token]
            token.used = self

        @abc.abstractmethod
        def detail(self):
            pass

        def __repr__(self):
            return "<%s%s (%dx%d-%dx%d)>" % (
                self.__class__.__name__,
                self.detail(),
                self.x1,
                self.y1,
                self.x2,
                self.y2,
            )

    class BoxMerge(Item):
        """
        common code for merging vertical groups of [] / {} boxes, e.g.

        [     ]
        [ rtr ]
        [     ]

        is combined into one Router object
        """

        name: str

        def __init__(self, token: "Topology.Token"):
            super().__init__(token)
            self.name = token.m.group(1)

        def can_add(self, token: "Topology.Token"):
            if token.cols[0] != self.x1 or token.cols[1] != self.x2:
                return False
            if token.lno not in (self.y1 - 1, self.y2):
                return False
            return True

        def add(self, token: "Topology.Token"):
            assert self.can_add(token)
            assert token.used is None
            token.used = self
            if token.lno == self.y1 - 1:
                self.y1 = token.lno
            else:
                self.y2 = token.lno + 1
            self.tokens.append(token)

        def detail(self):
            return ' "%s"' % (self.name,)

    class Router(BoxMerge):
        """
        Represent a router/host created from a ``[ name ]`` item.

        .. py:attribute:: name

           The router's name, as given in the diagram (cannot be empty.)
        """

    class LAN(BoxMerge):
        """
        Represent a LAN/multi-access network created from a ``{ name }`` item.

        .. py:attribute:: name

           The network's name, as given in the diagram (cannot be empty.)
        """

    class Link(Item, metaclass=abc.ABCMeta):
        """
        Common code for horizontal & vertical link lines.
        """

        routers: List[Tuple["Topology.Item", "Topology.Router"]]

        def __init__(self, token):
            super().__init__(token)
            self.routers = []

        def detail(self):
            return " [%s]" % (
                " <-> ".join(
                    [
                        "%s:%r" % (r[0].name, r[1] and r[1].m.group(1))
                        for r in self.routers
                    ]
                )
            )

        @abc.abstractmethod
        def connect(self, items: List["Topology.Item"]):
            """
            Find boxes to connect to.
            """

    class LinkH(Link):
        """
        A horizontal ``(ifname)-------(ifname)`` link.

        Interface names are optional.
        """

        def __init__(self, token):
            super().__init__(token)
            self.left, self.right = None, None

        def can_add(self, token):
            if token.lno != self.y1:
                return False
            return token.cols[0] == self.x2 or token.cols[1] == self.x1

        def add(self, token):
            assert self.can_add(token)
            assert token.used is None
            token.used = self
            ref = token if isinstance(token, Topology.TokIface) else None
            if token.cols[0] == self.x2:
                self.x2 = token.cols[1]
                self.right = ref
            elif token.cols[1] == self.x1:
                self.x1 = token.cols[0]
                self.left = ref

        def connect(self, items: List["Topology.Item"]):
            # self.routers is the list of BOTH routers and switches/lans
            for r in items:
                if not r.y1 <= self.y1 < r.y2:
                    continue
                if r.x2 == self.x1:
                    self.routers.append((r, self.left))
                elif r.x1 == self.x2:
                    self.routers.append((r, self.right))

    class LinkV(Link):
        """
        A vertical link.

        .. code-block:: none

           (ifname)
               |
               |
           (ifname)
        """

        def __init__(self, token):
            super().__init__(token)
            self.xmain = token.cols[0]
            self.top, self.bot = None, None

        def can_add(self, token):
            if not token.cols[0] <= self.xmain < token.cols[1]:
                return False
            if token.lno not in (self.y1 - 1, self.y2):
                return False
            return True

        def add(self, token):
            assert self.can_add(token)
            assert token.used is None
            token.used = self
            ref = token if isinstance(token, Topology.TokIface) else None
            if token.lno == self.y1 - 1:
                self.y1 = token.lno
                self.top = ref
            elif token.lno == self.y2:
                self.y2 = token.lno + 1
                self.bot = ref

        def connect(self, items: List["Topology.Item"]):
            # routers is the list of BOTH routers and switches/lans
            for r in items:
                if not r.x1 <= self.xmain < r.x2:
                    continue
                if r.y2 == self.y1:
                    self.routers.append((r, self.top))
                elif r.y1 == self.y2:
                    self.routers.append((r, self.bot))

    topo: str
    """
    Diagram text as given on construction.
    """

    tokendct: Dict[Type[Token], List[Token]]
    alltokens: Sequence[Token]

    routers: List[Router]
    """
    All routers defined in this topology.  Note that same-name routers are
    NOT merged yet in this list.
    """
    lans: List[LAN]
    """
    All networks defined in this topology.  As with routers, same-name networks
    are NOT merged yet in this list.
    """
    links: List[Link]
    """
    All links defined in this topology.
    """

    # pylint: disable=too-many-branches,too-many-locals
    def __init__(self, topo: str):
        """
        ascii art topology parsing
        """

        self.topo = topo
        self.tokendct = {}
        self.alltokens = []

        # part 1: just get the raw tokens

        for lno, line in enumerate(topo.split("\n")):
            col = 0
            while col < len(line):
                for tokcls in self.tokens:
                    m = tokcls.rx.match(line, col)
                    if m is None:
                        continue
                    col = m.end()

                    token = tokcls.make(lno, m)
                    if token is not None:
                        self.tokendct.setdefault(tokcls, []).append(token)
                        self.alltokens.append(token)
                    break

                else:
                    raise ValueError("cannot parse: %r" % (line[col:]))

        def merge(start, items):
            """
            combine multiple raw tokens into one item and set "used"
            """
            i = 0
            while i < len(items):
                if start.can_add(items[i]) and items[i].used is not start:
                    start.add(items[i])
                    i = 0
                else:
                    i += 1

        # part 2: slap together adjacent things

        routers = [self.Router(t) for t in self.tokendct.get(self.TokRouter, [])]
        rtrext = self.tokendct.get(self.TokRouterEmpty, [])
        for r in routers:
            merge(r, rtrext)

        lans = [self.LAN(t) for t in self.tokendct.get(self.TokLAN, [])]
        lanext = self.tokendct.get(self.TokLANEmpty, [])
        for l in lans:
            merge(l, lanext)

        links: List[Topology.Link] = []

        lext = self.tokendct.get(self.TokLinkH, [])
        while len(lext) > 0:
            hlinktok = lext.pop(0)
            if hlinktok.used is not None:
                continue
            hlink = self.LinkH(hlinktok)
            links.append(hlink)
            merge(hlink, lext + self.tokendct.get(self.TokIface, []))

        lext = self.tokendct.get(self.TokLinkV, [])
        while len(lext) > 0:
            vlinktok = lext.pop(0)
            if vlinktok.used is not None:
                continue
            vlink = self.LinkV(vlinktok)
            links.append(vlink)
            merge(vlink, lext + self.tokendct.get(self.TokIface, []))

        # part 3: find endpoints for links

        for liter in links:
            liter.connect(
                cast(List[Topology.Item], routers) + cast(List[Topology.Item], lans)
            )

        # done

        self.routers = routers
        self.lans = lans
        self.links = links


def test():
    topo = """

    [    ](eth0)------[ r2 ]
    [ r1 ]
    [    ](eth1)------[ r4 ]
    [    ]------------[    ]
       |                 |
       |                 |
    (eth2)               |
    [ r3 ]------------{ lan1 }----[ r5 ]
                      {      }----[    ]

    """

    topo = Topology(topo)

    # pylint: disable=import-outside-toplevel
    from pprint import pprint

    pprint(topo.routers)
    pprint(topo.lans)
    pprint(topo.links)
    pprint([t for t in topo.alltokens if t.used is None])

    return topo


if __name__ == "__main__":
    test()
