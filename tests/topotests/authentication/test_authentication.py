#!/usr/bin/env python

#
# Part of NetDEF Topology Tests
#
# Copyright (c) 2020, LabN Consulting, L.L.C.
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

sys.path.append(os.path.join(os.path.dirname(os.path.realpath(__file__)), '../'))

from lib.ltemplate import *
from lib.lutil import luCommand

CliOnFail = None
# For debugging, uncomment the next line
#CliOnFail = 'tgen.mininet_cli'

RunTests = None

#code currently doesn't handle case where key created after startup
def test_have_keycrypt():
    global RunTests
    RunTests = True
    ErrStr = 'not included in software build'
    ret = luCommand('r0','vtysh -c "show k s"', ErrStr, 'none')
    found = luLast()
    if ret != False and found != None:
        if len(found.group()):
            luCommand('r0','vtysh -c "show k s"', ErrStr, 'pass', 'Skipping test - keycrypt %s' % ErrStr)
            RunTests = False

def test_init_keys():
    CheckFunc = 'ltemplateVersionCheck(\'4.1\', kernel=None)'
    #uncomment next line to start cli *before* script is run
    #CheckFunc = 'ltemplateVersionCheck(\'4.1\', cli=True, kernel=None)'
    if RunTests != True:
         pytest.skip('keycrypt not included in software build')
    else:
        ltemplateTest('scripts/init-keys.py', False, CliOnFail, CheckFunc)

def test_check_keys1():
    CheckFunc = 'ltemplateVersionCheck(\'4.1\', kernel=None)'
    #uncomment next line to start cli *before* script is run
    #CheckFunc = 'ltemplateVersionCheck(\'4.1\', cli=True, kernel=None)'
    if RunTests != True:
         pytest.skip('keycrypt not included in software build')
    else:
        ltemplateTest('scripts/check-keys.py', False, CliOnFail, CheckFunc)

#test conversion first (then do re-boots, and test again)

def test_rip_show1():
    CheckFunc = 'ltemplateVersionCheck(\'4.1\', kernel=None)'
    #uncomment next line to start cli *before* script is run
    #CheckFunc = 'ltemplateVersionCheck(\'4.1\', cli=True, kernel=None)'
    if RunTests != True:
         pytest.skip('keycrypt not included in software build')
    else:
        ltemplateTest('scripts/rip-show.py', False, CliOnFail, CheckFunc)

def test_ripng_show1():
    CheckFunc = 'ltemplateVersionCheck(\'4.1\', kernel=None)'
    #uncomment next line to start cli *before* script is run
    #CheckFunc = 'ltemplateVersionCheck(\'4.1\', cli=True, kernel=None)'
    if RunTests != True:
         pytest.skip('keycrypt not included in software build')
    else:
        ltemplateTest('scripts/ripng-show.py', False, CliOnFail, CheckFunc)

#test conversion
def test_ospf_neighbors1():
    CheckFunc = 'ltemplateVersionCheck(\'4.1\', kernel=None)'
    #uncomment next line to start cli *before* script is run
    #CheckFunc = 'ltemplateVersionCheck(\'4.1\', cli=True, kernel=None)'
    if RunTests != True:
         pytest.skip('keycrypt not included in software build')
    else:
        ltemplateTest('scripts/ospf-neighbors.py', False, CliOnFail, CheckFunc)

def test_bgp_adjacencies1():
    CheckFunc = 'ltemplateVersionCheck(\'4.1\', kernel=None)'
    #uncomment next line to start cli *before* script is run
    #CheckFunc = 'ltemplateVersionCheck(\'4.1\', cli=True, kernel=None)'
    if RunTests != True:
         pytest.skip('keycrypt not included in software build')
    else:
        ltemplateTest('scripts/bgp-adjacencies.py', False, CliOnFail, CheckFunc)

def test_notification_check1():
    CheckFunc = 'ltemplateVersionCheck(\'4.1\', kernel=None)'
    #uncomment next line to start cli *before* script is run
    #CheckFunc = 'ltemplateVersionCheck(\'4.1\', cli=True, kernel=None)'
    if RunTests != True:
         pytest.skip('keycrypt not included in software build')
    else:
        ltemplateTest('scripts/notification_check.py', False, CliOnFail, CheckFunc)

def test_ldp1():
    CheckFunc = 'ltemplateVersionCheck(\'4.1\', kernel=None)'
    #uncomment next line to start cli *before* script is run
    #CheckFunc = 'ltemplateVersionCheck(\'4.1\', cli=True, kernel=None)'
    if RunTests != True:
         pytest.skip('keycrypt not included in software build')
    else:
        ltemplateTest('scripts/ldp-neighbors.py', False, CliOnFail, CheckFunc)

#do restarts
def test_restart_rip():
    CheckFunc = 'ltemplateVersionCheck(\'4.1\', kernel=None)'
    #uncomment next line to start cli *before* script is run
    #CheckFunc = 'ltemplateVersionCheck(\'4.1\', cli=True, kernel=None)'
    if RunTests != True:
         pytest.skip('keycrypt not included in software build')
    else:
        ltemplateTest('scripts/restart-rip.py', False, CliOnFail, CheckFunc)

def test_restart_ospf():
    CheckFunc = 'ltemplateVersionCheck(\'4.1\', kernel=None)'
    #uncomment next line to start cli *before* script is run
    #CheckFunc = 'ltemplateVersionCheck(\'4.1\', cli=True, kernel=None)'
    if RunTests != True:
         pytest.skip('keycrypt not included in software build')
    else:
        ltemplateTest('scripts/restart-ospf.py', False, CliOnFail, CheckFunc)

def test_restart_bgp():
    CheckFunc = 'ltemplateVersionCheck(\'4.1\', kernel=None)'
    #uncomment next line to start cli *before* script is run
    #CheckFunc = 'ltemplateVersionCheck(\'4.1\', cli=True, kernel=None)'
    if RunTests != True:
         pytest.skip('keycrypt not included in software build')
    else:
        ltemplateTest('scripts/restart-bgp.py', False, CliOnFail, CheckFunc)

def test_restart_ldp():
    CheckFunc = 'ltemplateVersionCheck(\'4.1\', kernel=None)'
    #uncomment next line to start cli *before* script is run
    #CheckFunc = 'ltemplateVersionCheck(\'4.1\', cli=True, kernel=None)'
    if RunTests != True:
         pytest.skip('keycrypt not included in software build')
    else:
        ltemplateTest('scripts/restart-ldp.py', False, CliOnFail, CheckFunc)

def test_check_keys2():
    CheckFunc = 'ltemplateVersionCheck(\'4.1\', kernel=None)'
    #uncomment next line to start cli *before* script is run
    #CheckFunc = 'ltemplateVersionCheck(\'4.1\', cli=True, kernel=None)'
    if RunTests != True:
         pytest.skip('keycrypt not included in software build')
    else:
        ltemplateTest('scripts/check-keys.py', False, CliOnFail, CheckFunc)

#test load from file
def test_rip_show2():
    CheckFunc = 'ltemplateVersionCheck(\'4.1\', kernel=None)'
    #uncomment next line to start cli *before* script is run
    #CheckFunc = 'ltemplateVersionCheck(\'4.1\', cli=True, kernel=None)'
    if RunTests != True:
         pytest.skip('keycrypt not included in software build')
    else:
        ltemplateTest('scripts/rip-show.py', False, CliOnFail, CheckFunc)

def test_ospf_neighbors2():
    CheckFunc = 'ltemplateVersionCheck(\'4.1\', kernel=None)'
    #uncomment next line to start cli *before* script is run
    #CheckFunc = 'ltemplateVersionCheck(\'4.1\', cli=True, kernel=None)'
    if RunTests != True:
         pytest.skip('keycrypt not included in software build')
    else:
        ltemplateTest('scripts/ospf-neighbors.py', False, CliOnFail, CheckFunc)

def test_bgp_adjacencies2():
    CheckFunc = 'ltemplateVersionCheck(\'4.1\', kernel=None)'
    #uncomment next line to start cli *before* script is run
    #CheckFunc = 'ltemplateVersionCheck(\'4.1\', cli=True, kernel=None)'
    if RunTests != True:
         pytest.skip('keycrypt not included in software build')
    else:
        ltemplateTest('scripts/bgp-adjacencies.py', False, CliOnFail, CheckFunc)

def test_notification_check():
    CheckFunc = 'ltemplateVersionCheck(\'4.1\', kernel=None)'
    #uncomment next line to start cli *before* script is run
    #CheckFunc = 'ltemplateVersionCheck(\'4.1\', cli=True, kernel=None)'
    if RunTests != True:
         pytest.skip('keycrypt not included in software build')
    else:
        ltemplateTest('scripts/notification_check.py', False, CliOnFail, CheckFunc)

#
# encrypted protocol key conservation test:
# - move openssl private key file away
# - save cfg/restart protocol (have plaintext keys, but save encrypted keys;
#				load encrypted keys but can't decrypt)
# - save cfg/restart protocol (save encrypted keys, load encrypted keys but
#				can't decrypt)
# - verify encrypted protocol keys in running configuration but no plain
# - move openssl private key file back (same private key as before!)
# - save cfg/restart protocol (save encrypted keys, load encrypted keys
#				and able to decrypt)
# - verify peerings
# - verify correct plain/encrypted key counts (scripts/check-keys.py)
#
def test_protocol_key_conservation():
    CheckFunc = 'ltemplateVersionCheck(\'4.1\', kernel=None)'
    #uncomment next line to start cli *before* script is run
    #CheckFunc = 'ltemplateVersionCheck(\'4.1\', cli=True, kernel=None)'
    if RunTests != True:
         pytest.skip('keycrypt not included in software build')
    else:
        ltemplateTest('scripts/move-key-away.py', False, CliOnFail, CheckFunc)
        ltemplateTest('scripts/restart-rip.py', False, CliOnFail, CheckFunc)
        ltemplateTest('scripts/restart-rip.py', False, CliOnFail, CheckFunc)
        ltemplateTest('scripts/restart-ospf.py', False, CliOnFail, CheckFunc)
        ltemplateTest('scripts/restart-ospf.py', False, CliOnFail, CheckFunc)
        ltemplateTest('scripts/restart-bgp.py', False, CliOnFail, CheckFunc)
        ltemplateTest('scripts/restart-bgp.py', False, CliOnFail, CheckFunc)
        ltemplateTest('scripts/restart-ldp.py', False, CliOnFail, CheckFunc)
        ltemplateTest('scripts/restart-ldp.py', False, CliOnFail, CheckFunc)
        ltemplateTest('scripts/check-keys-encrypted-only.py', False, CliOnFail,
                      CheckFunc, LogTag='ck 1')
        ltemplateTest('scripts/check-decrypt-fail-cfg-warning.py',
                      False, CliOnFail, CheckFunc)
        ltemplateTest('scripts/move-key-back.py', False, CliOnFail, CheckFunc)
        ltemplateTest('scripts/restart-rip.py', False, CliOnFail, CheckFunc)
        ltemplateTest('scripts/rip-show.py', False, CliOnFail, CheckFunc)
        ltemplateTest('scripts/restart-ospf.py', False, CliOnFail, CheckFunc)
        ltemplateTest('scripts/ospf-neighbors.py', False, CliOnFail, CheckFunc)
        ltemplateTest('scripts/restart-bgp.py', False, CliOnFail, CheckFunc)
        ltemplateTest('scripts/bgp-adjacencies.py', False, CliOnFail, CheckFunc)
        ltemplateTest('scripts/restart-ldp.py', False, CliOnFail, CheckFunc)
        ltemplateTest('scripts/ldp-neighbors.py', False, CliOnFail, CheckFunc)
        ltemplateTest('scripts/check-keys.py', False, CliOnFail,
                      CheckFunc, LogTag='ck 2')

if __name__ == '__main__':
    retval = pytest.main(["-s"])
    sys.exit(retval)
