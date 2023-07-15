# some basic tests for xrelfo & the python ELF machinery
#
# Copyright (C) 2020  David Lamparter for NetDEF, Inc.
#
# This program is free software; you can redistribute it and/or modify it
# under the terms of the GNU General Public License as published by the Free
# Software Foundation; either version 2 of the License, or (at your option)
# any later version.
#
# This program is distributed in the hope that it will be useful, but WITHOUT
# ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
# FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
# more details.
#
# You should have received a copy of the GNU General Public License along
# with this program; see the file COPYING; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA

import sys
import os
import pytest
from pprint import pprint

root = os.path.dirname(os.path.dirname(__file__))
sys.path.append(os.path.join(root, "python"))

import xrelfo
from clippy import elf, uidhash


def test_uidhash():
    assert uidhash.uidhash("lib/test_xref.c", "logging call", 3, 0) == "H7KJB-67TBH"


def test_xrelfo_other():
    for data in [
        elf.ELFNull(),
        elf.ELFUnresolved("somesym", 0),
    ]:

        dissect = xrelfo.XrefPtr(data)
        print(repr(dissect))

        with pytest.raises(AttributeError):
            dissect.xref


def test_xrelfo_obj():
    xrelfo_ = xrelfo.Xrelfo()
    edf = xrelfo_.load_elf(os.path.join(root, "lib/.libs/zclient.o"), "zclient.lo")
    xrefs = xrelfo_._xrefs

    with pytest.raises(elf.ELFAccessError):
        edf[0:4]

    pprint(xrefs[0])
    pprint(xrefs[0]._data)


def test_xrelfo_bin():
    xrelfo_ = xrelfo.Xrelfo()
    edf = xrelfo_.load_elf(os.path.join(root, "lib/.libs/libfrr.so"), "libfrr.la")
    xrefs = xrelfo_._xrefs

    assert edf[0:4] == b"\x7fELF"

    pprint(xrefs[0])
    pprint(xrefs[0]._data)
