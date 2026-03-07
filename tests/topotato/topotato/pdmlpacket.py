#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright (C) 2021  David Lamparter for NetDEF, Inc.
"""
Ease of access wrappers around PDML-formatted packet dumps
"""

import xml.etree.ElementTree as etree

from typing import Tuple, Optional, Union, List, Any, TYPE_CHECKING

try:
    from typing import OrderedDict
except ImportError:
    # python 3.6
    from typing import Dict as OrderedDict  # type: ignore

if TYPE_CHECKING:
    from .base import TopotatoItem


class _IndexChainMixin:
    """
    Less verbose/repetetive access to PDML data

    PDML has things like this:
    <proto name="ip" …>
      <field name="ip.flags" …>
        <field name="ip.flags.df" …>

    With this mixin class, the following ways all access this nested field:

    data["ip", 0]["ip.flags", 0]["ip.flags.df", 0]
    data["ip#0/ip.flags#0/ip.flags.df#0"]
    data["ip/ip.flags/ip.flags.df"]
    data["ip/.flags/.df"]

    Using the last makes field access much cleaner.

    Note that child field names do NOT always include the parent field name
    as a prefix.  An example would be:

    <proto name="tcp" …>
      <field name="tcp.options" …>
        <field name="tcp.options.timestamp" …>
          <field name="tcp.option_kind" …>
    """

    def __getitem__(self, k: Union[str, Tuple[str, int]]):
        if not isinstance(k, str):
            return super().__getitem__(k)  # type: ignore

        steps = k.split("/")
        step, remain = steps[0], "/".join(steps[1:])
        if "#" in step:
            name, idxs = step.rsplit("#", 1)
            idx = int(idxs)
        else:
            name, idx = step, 0

        val = super().__getitem__((name, idx))  # type: ignore

        if not remain:
            return val
        if remain.startswith("."):
            remain = name + remain
        return val[remain]

    def __contains__(self, k: Any):
        if not isinstance(k, str):
            return super().__contains__(k)  # type: ignore

        try:
            self.__getitem__(k)
            return True
        except KeyError:
            return False


class PDMLData(_IndexChainMixin, OrderedDict[Tuple[str, int], "PDMLData"]):
    """
    PDML contains a bunch of nested <field> structures, and each item
    has "short" and "long" data ("show" and "showname"), which unfortunately
    is both needed / contains distinct information in some cases.
    """

    _xmlobj: etree.Element
    val: Optional[str]
    desc: Optional[str]

    def __init__(self, xmlobj: etree.Element):
        super().__init__()

        self.val = xmlobj.get("show")
        self.desc = xmlobj.get("showname")

        self._xmlobj = xmlobj
        self._fill(xmlobj)

    def _fill(self, xmlobj):
        for field in xmlobj.findall("field"):
            name = field.get("name")
            i = 0
            while (name, i) in self:
                i += 1

            self[name, i] = PDMLData(field)

    def __repr__(self):
        s = "<%s val:%r, desc:%r" % (self.__class__.__name__, self.val, self.desc)
        if len(self):
            s += ", #%d" % (len(self.keys()),)
        s += ">"
        return s


class PDMLProto(PDMLData):
    pass


class PDMLPacket(_IndexChainMixin, OrderedDict[Tuple[str, int], PDMLProto]):
    _xmlpkt: etree.Element
    ts: float

    match_for: List["TopotatoItem"]

    def __init__(self, xmlpkt: etree.Element):
        super().__init__()
        self._xmlpkt = xmlpkt
        self.match_for = []

        for xmlproto in xmlpkt.findall("proto"):
            protoobj = PDMLProto(xmlproto)
            proto = xmlproto.get("name")
            assert proto is not None

            i = 0
            while (proto, i) in self:
                i += 1
            self[proto, i] = protoobj

        self.ts = float(self["frame/.time_epoch"].val)

    def __repr__(self):
        return "<PDMLPacket: [%s]>" % (",".join([pname for pname, i in self.keys()]))
