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
import platform
import pytest
import imp

# pylint: disable=C0413
# Import topogen and topotest helpers
from lib import topotest
from lib.topogen import Topogen, TopoRouter, get_topogen
from lib.topolog import logger
from lib.lutil import *

# Required to instantiate the topology builder class.
from mininet.topo import Topo

customize = None

class LTemplate():
    test = None
    testdir = None
    scriptdir = None
    logdir = None
    prestarthooksuccess = True
    poststarthooksuccess = True
    iproute2Ver = None

    def __init__(self, test, testdir):
        global customize
        customize = imp.load_source('customize', os.path.join(testdir, 'customize.py'))
        self.test = test
        self.testdir = testdir
        self.scriptdir = testdir
        self.logdir = '/tmp/topotests/{0}.test_{0}'.format(test)
        logger.info('LTemplate: '+test)

    def setup_module(self, mod):
        "Sets up the pytest environment"
        # This function initiates the topology build with Topogen...
        tgen = Topogen(customize.ThisTestTopo, mod.__name__)
        # ... and here it calls Mininet initialization functions.
        tgen.start_topology()

        logger.info('Topology started')
        try:
            self.prestarthooksuccess = customize.ltemplatePreRouterStartHook()
        except AttributeError:
            #not defined
            logger.debug("ltemplatePreRouterStartHook() not defined")
        if self.prestarthooksuccess != True:
            logger.info('ltemplatePreRouterStartHook() failed, skipping test')
            return

        # This is a sample of configuration loading.
        router_list = tgen.routers()

        # For all registred routers, load the zebra configuration file
        for rname, router in router_list.iteritems():
            print("Setting up %s" % rname)
            config = os.path.join(self.testdir, '{}/zebra.conf'.format(rname))
            if os.path.exists(config):
                router.load_config(TopoRouter.RD_ZEBRA, config)
            config = os.path.join(self.testdir, '{}/ospfd.conf'.format(rname))
            if os.path.exists(config):
                router.load_config(TopoRouter.RD_OSPF, config)
            config = os.path.join(self.testdir, '{}/ldpd.conf'.format(rname))
            if os.path.exists(config):
                router.load_config(TopoRouter.RD_LDP, config)
            config = os.path.join(self.testdir, '{}/bgpd.conf'.format(rname))
            if os.path.exists(config):
                router.load_config(TopoRouter.RD_BGP, config)
            config = os.path.join(self.testdir, '{}/isisd.conf'.format(rname))
            if os.path.exists(config):
                router.load_config(TopoRouter.RD_ISIS, config)

        # After loading the configurations, this function loads configured daemons.
        logger.info('Starting routers')
        tgen.start_router()
        try:
            self.poststarthooksuccess = customize.ltemplatePostRouterStartHook()
        except AttributeError:
            #not defined
            logger.debug("ltemplatePostRouterStartHook() not defined")
        luStart(baseScriptDir=self.scriptdir, baseLogDir=self.logdir, net=tgen.net)

#initialized by ltemplate_start
_lt = None

def setup_module(mod):
    global _lt
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    test = mod.__name__[:mod.__name__.rfind(".")]
    testdir = os.path.join(root, test)

    #don't do this for now as reload didn't work as expected
    #fixup sys.path, want test dir there only once
    #try:
    #    sys.path.remove(testdir)
    #except ValueError:
    #    logger.debug(testdir+" not found in original sys.path")
    #add testdir
    #sys.path.append(testdir)

    #init class
    _lt = LTemplate(test, testdir)
    _lt.setup_module(mod)

    #drop testdir
    #sys.path.remove(testdir)

def teardown_module(mod):
    global _lt
    "Teardown the pytest environment"
    tgen = get_topogen()

    if _lt != None and _lt.scriptdir != None and _lt.prestarthooksuccess == True:
        print(luFinish())

    # This function tears down the whole topology.
    tgen.stop_topology()
    _lt = None

def ltemplateTest(script, SkipIfFailed=True, CallOnFail=None, CheckFuncStr=None, KeepGoing=False):
    global _lt
    if _lt == None or _lt.prestarthooksuccess != True:
        return

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
	if not KeepGoing:
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
	if not KeepGoing:
	    assert "scripts/cleanup_all.py failed" == "See summary output above", fatal_error

# Memory leak test template
def test_memory_leak():
    "Run the memory leak test and report results."
    tgen = get_topogen()
    if not tgen.is_memleak_enabled():
        pytest.skip('Memory leak test/report is disabled')

    tgen.report_memory_leaks()

class ltemplateRtrCmd():
    def __init__(self):
        self.resetCounts()

    def doCmd(self, tgen, rtr, cmd, checkstr = None):
        output = tgen.net[rtr].cmd(cmd).strip()
        if len(output):
            self.output += 1
            if checkstr != None:
                ret = re.search(checkstr, output)
                if ret == None:
                    self.nomatch += 1
                else:
                    self.match += 1
                return ret
            logger.info('command: {} {}'.format(rtr, cmd))
            logger.info('output: ' + output)
        self.none += 1
        return None

    def resetCounts(self):
        self.match = 0
        self.nomatch = 0
        self.output = 0
        self.none = 0

    def getMatch(self):
        return self.match

    def getNoMatch(self):
        return self.nomatch

    def getOutput(self):
        return self.output

    def getNone(self):
        return self.none

def ltemplateVersionCheck(vstr, rname='r1', compstr='<',cli=False, kernel='4.9', iproute2=None, mpls=True):
    tgen = get_topogen()
    router = tgen.gears[rname]

    if cli:
        logger.info('calling mininet CLI')
        tgen.mininet_cli()
        logger.info('exited mininet CLI')

    if _lt == None:
        ret = 'Template not initialized'
        return ret

    if _lt.prestarthooksuccess != True:
        ret = 'ltemplatePreRouterStartHook failed'
        return ret

    if _lt.poststarthooksuccess != True:
        ret = 'ltemplatePostRouterStartHook failed'
        return ret

    if mpls == True and tgen.hasmpls != True:
        ret = 'MPLS not initialized'
        return ret

    if kernel != None:
        krel = platform.release()
        if topotest.version_cmp(krel, kernel) < 0:
            ret = 'Skipping tests, old kernel ({} < {})'.format(krel, kernel)
            return ret

    if iproute2 != None:
        if _lt.iproute2Ver == None:
            #collect/log info on iproute2
            cc = ltemplateRtrCmd()
            found = cc.doCmd(tgen, rname, 'apt-cache policy iproute2', 'Installed: ([\d\.]*)')
            if found != None:
                iproute2Ver = found.group(1)
            else:
                iproute2Ver = '0-unknown'
            logger.info('Have iproute2 version=' + iproute2Ver)

        if topotest.version_cmp(iproute2Ver, iproute2) < 0:
            ret = 'Skipping tests, old iproute2 ({} < {})'.format(iproute2Ver, iproute2)
            return ret

    ret = True
    try:
        if router.has_version(compstr, vstr):
            ret = 'Skipping tests, old FRR version {} {}'.format(compstr, vstr)
            return ret
    except:
        ret = True

    return ret

#for testing
if __name__ == '__main__':
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
