#!/usr/bin/env python

#
# Part of NetDEF Topology Tests
#
# Copyright (c) 2017 by
# Network Device Education Foundation, Inc. ("NetDEF")
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

"""
ltemplate.py: LabN template for FRR tests.
"""

import os
import sys
import pytest

# pylint: disable=C0413
# Import topogen and topotest helpers
from lib import topotest
from lib.topogen import Topogen, TopoRouter, get_topogen
from lib.topolog import logger
from lib.lutil import *

# Required to instantiate the topology builder class.
from mininet.topo import Topo
from customize import *

def setup_module(mod):
    "Sets up the pytest environment"
    # This function initiates the topology build with Topogen...
    tgen = Topogen(ThisTestTopo, mod.__name__)
    # ... and here it calls Mininet initialization functions.
    tgen.start_topology()

    logger.info('Topology started')
    try:
        ltemplatePreRouterStartHook()
    except NameError:
        #not defined
        logger.debug("ltemplatePreRouterStartHook() not defined")

    # This is a sample of configuration loading.
    router_list = tgen.routers()

    # For all registred routers, load the zebra configuration file
    for rname, router in router_list.iteritems():
        print("Setting up %s" % rname)
        config = os.path.join(CWD, '{}/zebra.conf'.format(rname))
        if os.path.exists(config):
            router.load_config(TopoRouter.RD_ZEBRA, config)
        config = os.path.join(CWD, '{}/ospfd.conf'.format(rname))
        if os.path.exists(config):
            router.load_config(TopoRouter.RD_OSPF, config)
        config = os.path.join(CWD, '{}/ldpd.conf'.format(rname))
        if os.path.exists(config):
            router.load_config(TopoRouter.RD_LDP, config)
        config = os.path.join(CWD, '{}/bgpd.conf'.format(rname))
        if os.path.exists(config):
            router.load_config(TopoRouter.RD_BGP, config)

    # After loading the configurations, this function loads configured daemons.
    logger.info('Starting routers')
    tgen.start_router()
    try:
        ltemplatePostRouterStartHook()
    except NameError:
        #not defined
        logger.debug("ltemplatePostRouterStartHook() not defined")

def teardown_module(mod):
    "Teardown the pytest environment"
    tgen = get_topogen()

    # This function tears down the whole topology.
    tgen.stop_topology()

class LTemplate:
    scriptdir = None

#init class
_lt = LTemplate()

def ltemplate_start(testDir):
    logger.info('ltemplate start in ' + testDir)
    test = os.path.basename(testDir)
    logDir = '/tmp/topotests/{0}.test_{0}'.format(test)
    tgen = get_topogen()
    luStart(baseScriptDir=testDir, baseLogDir=logDir, net=tgen.net)
    _lt.scriptdir = testDir

def ltemplateTest(script, SkipIfFailed=True, CallOnFail=None, CheckFuncStr=None):
    tgen = get_topogen()
    if not os.path.isfile(script):
        if not os.path.isfile(os.path.join(_lt.scriptdir, script)):
            logger.error('Could not find script file: ' + script)
            assert 'Could not find script file: ' + script
    logger.info("Starting template test: " + script)
    numEntry = luNumFail()

    if SkipIfFailed and tgen.routers_have_failure():
        pytest.skip(tgen.errors)
    if numEntry > 0:
        pytest.skip("Have %d errors" % numEntry)

    if CheckFuncStr != None:
        check = eval(CheckFuncStr)
        if check != True:
            pytest.skip("Check function '"+CheckFuncStr+"' returned: " + check)

    if CallOnFail != None:
        CallOnFail = eval(CallOnFail)
    luInclude(script, CallOnFail)
    numFail = luNumFail() - numEntry
    if numFail > 0:
        luShowFail()
        fatal_error = "%d tests failed" % numFail
        assert "scripts/cleanup_all.py failed" == "See summary output above", fatal_error

# Memory leak test template
def test_memory_leak():
    "Run the memory leak test and report results."
    tgen = get_topogen()
    if not tgen.is_memleak_enabled():
        pytest.skip('Memory leak test/report is disabled')

    tgen.report_memory_leaks()

#clean up ltemplate

def test_ltemplate_finish():
    logger.info('Done with ltemplate tests')
    if _lt.scriptdir != None:
        print(luFinish())

#for testing
if __name__ == '__main__':
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
