#
# Test helpers for FRR
#
# Copyright (C) 2017 by David Lamparter & Christian Franke,
#                       Open Source Routing / NetDEF Inc.
#
# This file is part of FRRouting (FRR)
#
# FRR is free software; you can redistribute it and/or modify it
# under the terms of the GNU General Public License as published by the
# Free Software Foundation; either version 2, or (at your option) any
# later version.
#
# FRR is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
# General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with FRR; see the file COPYING.  If not, write to the Free
# Software Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA
# 02111-1307, USA.
#

import subprocess
import sys
import re
import inspect
import os
import difflib

import frrsix

#
# These are the gritty internals of the TestMultiOut implementation.
# See below for the definition of actual TestMultiOut tests.
#

srcbase = os.path.abspath(inspect.getsourcefile(frrsix))
for i in range(0, 3):
    srcbase = os.path.dirname(srcbase)
def binpath(srcpath):
    return os.path.relpath(os.path.abspath(srcpath), srcbase)

class MultiTestFailure(Exception):
    pass

class MetaTestMultiOut(type):
    def __getattr__(cls, name):
        if name.startswith('_'):
            raise AttributeError

        internal_name = '_{}'.format(name)
        if internal_name not in dir(cls):
            raise AttributeError

        def registrar(*args, **kwargs):
            cls._add_test(getattr(cls,internal_name), *args, **kwargs)
        return registrar

@frrsix.add_metaclass(MetaTestMultiOut)
class _TestMultiOut(object):
    def _run_tests(self):
        if 'tests_run' in dir(self.__class__) and self.tests_run:
            return
        self.__class__.tests_run = True
        basedir = os.path.dirname(inspect.getsourcefile(type(self)))
        program = os.path.join(basedir, self.program)
        proc = subprocess.Popen([binpath(program)], stdout=subprocess.PIPE)
        self.output,_ = proc.communicate('')
        self.exitcode = proc.wait()

        self.__class__.testresults = {}
        for test in self.tests:
            try:
                test(self)
            except MultiTestFailure:
                self.testresults[test] = sys.exc_info()
            else:
                self.testresults[test] = None

    def _exit_cleanly(self):
        if self.exitcode != 0:
            raise MultiTestFailure("Program did not terminate with exit code 0")

    @classmethod
    def _add_test(cls, method, *args, **kwargs):
        if 'tests' not in dir(cls):
            setattr(cls,'tests',[])
            if method is not cls._exit_cleanly:
                cls._add_test(cls._exit_cleanly)

        def matchfunction(self):
            method(self, *args, **kwargs)
        cls.tests.append(matchfunction)

        def testfunction(self):
            self._run_tests()
            result = self.testresults[matchfunction]
            if result is not None:
                frrsix.reraise(*result)

        testname = re.sub(r'[^A-Za-z0-9]', '_', '%r%r' % (args, kwargs))
        testname = re.sub(r'__*', '_', testname)
        testname = testname.strip('_')
        if not testname:
            testname = method.__name__.strip('_')
        if "test_%s" % testname in dir(cls):
            index = 2
            while "test_%s_%d" % (testname,index) in dir(cls):
                index += 1
            testname = "%s_%d" % (testname, index)
        setattr(cls,"test_%s" % testname, testfunction)

#
# This class houses the actual TestMultiOut tests types.
# If you want to add a new test type, you probably do it here.
#
# Say you want to add a test type called foobarlicious. Then define
# a function _foobarlicious here that takes self and the test arguments
# when called. That function should check the output in self.output
# to see whether it matches the expectation of foobarlicious with the
# given arguments and should then adjust self.output according to how
# much output it consumed.
# If the output doesn't meet the expectations, MultiTestFailure can be
# raised, however that should only be done after self.output has been
# modified according to consumed content.
#

re_okfail = re.compile(r'(?:[3[12]m|^)?(?P<ret>OK|failed)'.encode('utf8'),
                       re.MULTILINE)
class TestMultiOut(_TestMultiOut):
    def _onesimple(self, line):
        if type(line) is str:
            line = line.encode('utf8')
        idx = self.output.find(line)
        if idx != -1:
            self.output = self.output[idx+len(line):]
        else:
            raise MultiTestFailure("%r could not be found" % line)

    def _okfail(self, line, okfail=re_okfail):
        self._onesimple(line)

        m = okfail.search(self.output)
        if m is None:
            raise MultiTestFailure('OK/fail not found')
        self.output = self.output[m.end():]

        if m.group('ret') != 'OK'.encode('utf8'):
            raise MultiTestFailure('Test output indicates failure')

#
# This class implements a test comparing the output of a program against
# an existing reference output
#

class TestRefMismatch(Exception):
    def __init__(self, _test, outtext, reftext):
        self.outtext = outtext.decode('utf8') if type(outtext) is bytes else outtext
        self.reftext = reftext.decode('utf8') if type(reftext) is bytes else reftext

    def __str__(self):
        rv = 'Expected output and actual output differ:\n'
        rv += '\n'.join(difflib.unified_diff(self.reftext.splitlines(),
                                             self.outtext.splitlines(),
                                             'outtext', 'reftext',
                                             lineterm=''))
        return rv

class TestExitNonzero(Exception):
    pass

class TestRefOut(object):
    def test_refout(self):
        basedir = os.path.dirname(inspect.getsourcefile(type(self)))
        program = os.path.join(basedir, self.program)

        refin = program + '.in'
        refout = program + '.refout'

        intext = ''
        if os.path.exists(refin):
            with open(refin, 'rb') as f:
                intext = f.read()
        with open(refout, 'rb') as f:
            reftext = f.read()

        proc = subprocess.Popen([binpath(program)],
                                stdin=subprocess.PIPE,
                                stdout=subprocess.PIPE)
        outtext,_ = proc.communicate(intext)
        if outtext != reftext:
            raise TestRefMismatch(self, outtext, reftext)
        if proc.wait() != 0:
            raise TestExitNonzero(self)
