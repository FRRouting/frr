# SPDX-License-Identifier: GPL-2.0-or-later
# some basic tests for xrelfo & the python ELF machinery
#
# Copyright (C) 2020  David Lamparter for NetDEF, Inc.

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
