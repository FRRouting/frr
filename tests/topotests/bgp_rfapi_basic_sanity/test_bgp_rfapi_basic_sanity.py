#!/usr/bin/env python

#
# Part of NetDEF Topology Tests
#
# Copyright (c) 2018, LabN Consulting, L.L.C.
# Authored by Lou Berger <lberger@labn.net>
#
# Permission to use, copy, modify, and/or distribute this software
# for any purpose with or without fee is hereby granted, provided
# that the above copyright notice and this permission notice appear
# in all copies.
#
# THE SOFTWARE IS PROVIDED "AS IS" AND NETDEF DISCLAIMS ALL WARRANTIES
# WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
# MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL NETDEF BE LIABLE FOR
# ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY
# DAMAGES WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS,
# WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS
# ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE
# OF THIS SOFTWARE.
#

import os
import sys
import pytest

sys.path.append(os.path.join(os.path.dirname(os.path.realpath(__file__)), ".."))

from lib.ltemplate import *

pytestmark = [pytest.mark.bgpd, pytest.mark.ospfd]


def test_add_routes():
    CliOnFail = None
    # For debugging, uncomment the next line
    # CliOnFail = 'tgen.mininet_cli'
    CheckFunc = "ltemplateVersionCheck('3.1')"
    # uncomment next line to start cli *before* script is run
    # CheckFunc = 'ltemplateVersionCheck(\'3.1\', cli=True)'
    ltemplateTest("scripts/add_routes.py", False, CliOnFail, CheckFunc)


def test_adjacencies():
    CliOnFail = None
    # For debugging, uncomment the next line
    # CliOnFail = 'tgen.mininet_cli'
    CheckFunc = "ltemplateVersionCheck('3.1')"
    # uncomment next line to start cli *before* script is run
    # CheckFunc = 'ltemplateVersionCheck(\'3.1\', cli=True)'
    ltemplateTest("scripts/adjacencies.py", False, CliOnFail, CheckFunc)


def test_check_routes():
    CliOnFail = None
    # For debugging, uncomment the next line
    # CliOnFail = 'tgen.mininet_cli'
    CheckFunc = "ltemplateVersionCheck('3.1')"
    # uncomment next line to start cli *before* script is run
    # CheckFunc = 'ltemplateVersionCheck(\'3.1\', cli=True)'
    ltemplateTest("scripts/check_routes.py", False, CliOnFail, CheckFunc)


def test_check_close():
    CliOnFail = None
    # For debugging, uncomment the next line
    # CliOnFail = 'tgen.mininet_cli'
    CheckFunc = "ltemplateVersionCheck('3.1')"
    # uncomment next line to start cli *before* script is run
    # CheckFunc = 'ltemplateVersionCheck(\'3.1\', cli=True)'
    ltemplateTest("scripts/check_close.py", False, CliOnFail, CheckFunc)


def test_check_timeout():
    CliOnFail = None
    # For debugging, uncomment the next line
    # CliOnFail = 'tgen.mininet_cli'
    CheckFunc = "ltemplateVersionCheck('3.1')"
    # uncomment next line to start cli *before* script is run
    # CheckFunc = 'ltemplateVersionCheck(\'3.1\', cli=True)'
    ltemplateTest("scripts/check_timeout.py", False, CliOnFail, CheckFunc)


def test_cleanup_all():
    CliOnFail = None
    # For debugging, uncomment the next line
    # CliOnFail = 'tgen.mininet_cli'
    CheckFunc = "ltemplateVersionCheck('3.1')"
    # uncomment next line to start cli *before* script is run
    # CheckFunc = 'ltemplateVersionCheck(\'3.1\', cli=True)'
    ltemplateTest("scripts/cleanup_all.py", False, CliOnFail, CheckFunc)


if __name__ == "__main__":
    retval = pytest.main(["-s"])
    sys.exit(retval)
