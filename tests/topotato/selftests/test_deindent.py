#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright (C) 2022  David Lamparter for NetDEF, Inc.
"""
test deindent()
"""

from topotato.utils import deindent


def test_empty():
    assert deindent("") == ""


def test_head_strip():
    assert deindent("\n") == ""
    assert deindent("\n\n\n") == ""

    assert deindent("\n\na\n") == "a\n"
    assert deindent("\n\na") == "a"


def test_main():
    assert deindent(" a\n b\n") == "a\nb\n"
    assert deindent(" a\n\n b\n\n") == "a\n\nb\n\n"
    assert deindent(" a\n \n b\n\n") == "a\n\nb\n\n"
    assert deindent(" a\n  \n b\n\n") == "a\n \nb\n\n"
    assert deindent(" a\n  b\n") == "a\n b\n"
    assert deindent("  a\n b\n") == " a\nb\n"
    assert deindent("\n\n a\n b\n") == "a\nb\n"
