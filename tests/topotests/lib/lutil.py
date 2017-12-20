#!/usr/bin/env python

# Copyright 2017, LabN Consulting, L.L.C.
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License along
# with this program; see the file COPYING; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA

import os
import re
import sys
import time
import datetime
from topolog import logger
from mininet.net import Mininet


# L utility functions
#
# These functions are inteneted to provide support for CI testing within MiniNet
# environments.

class lUtil:
    #to be made configurable in the future
    base_script_dir = '.'
    base_log_dir = '.'
    fout_name = 'output.log'
    fsum_name = 'summary.txt'
    l_level = 9
    CallOnFail = False

    l_total = 0
    l_pass = 0
    l_fail = 0
    l_filename = ''
    l_line = 0

    fout = ''
    fsum = ''
    net  = ''

    def log(self, str):
        if self.l_level > 0:
            if self.fout == '':
                self.fout = open(self.fout_name, 'w', 0)
            self.fout.write(str+'\n')
        if self.l_level > 5:
            print(str)

    def result(self, target, success, str):
        if success:
            p = 1
            f = 0
            self.l_pass += 1
        else:
            f = 1
            p = 0
            self.l_fail += 1
        res = "%-4d %-6s %-56s %-4d %d" % (self.l_total, target, str, p, f)
        self.log ('R:'+res)
        if self.fsum == '':
            self.fsum = open(self.fsum_name, 'w', 0)
            self.fsum.write('\
******************************************************************************\n')
            self.fsum.write('\
Test Target Summary                                                  Pass Fail\n')
            self.fsum.write('\
******************************************************************************\n')
        self.fsum.write(res+'\n')
        if f == 1 and self.CallOnFail != False:
            self.CallOnFail()

    def closeFiles(self):
        ret = '\
******************************************************************************\n\
Total %-4d                                                           %-4d %d\n\
******************************************************************************'\
% (self.l_total, self.l_pass, self.l_fail)
        if self.fsum != '':
            self.fsum.write(ret + '\n')
            self.fsum.close()
            self.fsum = ''
        if self.fout != '':
            if os.path.isfile(self.fsum_name):
                r = open(self.fsum_name, 'r')
                self.fout.write(r.read())
                r.close()
            self.fout.close()
            self.fout = ''
        return ret

    def setFilename(self, name):
        self.log('FILE: ' + name)
        self.l_filename = name
        self.line = 0

    def getCallOnFail(self):
        return self.CallOnFail

    def setCallOnFail(self, CallOnFail):
        self.CallOnFail = CallOnFail

    def strToArray(self, string):
        a = []
        c = 0
        end = ''
        words = string.split()
        if len(words) < 1 or words[0].startswith('#'):
            return a
        words = string.split()
        for word in words:
            if len(end) == 0:
                a.append(word)
            else:
                a[c] += str(' '+word)
            if end == '\\':
                end = ''
            if not word.endswith('\\'):
                if end != '"':
                    if word.startswith('"'):
                        end = '"'
                    else:
                        c += 1
                else:
                    if word.endswith('"'):
                        end = ''
                        c += 1
                    else:
                        c += 1
            else:
                end = '\\'
    #        if len(end) == 0:
    #            print('%d:%s:' % (c, a[c-1]))

        return a

    def execTestFile(self, tstFile):
        if os.path.isfile(tstFile):
            f = open(tstFile)
            for line in f:
                if len(line) > 1:
                    a = self.strToArray(line)
                    if len(a) >= 6:
                        luCommand(a[1], a[2], a[3], a[4], a[5])
                    else:
                        self.l_line += 1
                        self.log('%s:%s %s' % (self.l_filename, self.l_line , line))
                        if len(a) >= 2:
                            if a[0] == 'sleep':
                                time.sleep(int(a[1]))
                            elif a[0] == 'include':
                                self.execTestFile(a[1])
            f.close()
        else:
            self.log('unable to read: ' + tstFile)
            sys.exit(1)

    def command(self, target, command, regexp, op, result):
        global net
        if op != 'wait':
            self.l_line  += 1
            self.l_total += 1
        self.log('%s:%s COMMAND:%s:%s:%s:%s:%s:' % \
                 (self.l_filename, self.l_line, target, command, regexp, op, result))
        if self.net == '':
            return False
        #self.log("Running %s %s" % (target, command))
        out = self.net[target].cmd(command).rstrip()
        if len(out) == 0:
            report = "<no output>"
        else:
            report = out
        self.log('COMMAND OUTPUT:%s:' % report)
        out = " ".join(out.splitlines())
        search = re.search(regexp, out)
        self.l_last = search
        if search == None:
            if op == 'fail':
                success = True
            else:
                success = False
            ret = success
        else:
            ret = search.group()
            self.log('found:%s:' % ret)
            if op != 'fail':
                success = True
            else:
                success = False
        if op == 'pass' or op == 'fail':
            self.result(target, success, result)
        return ret

    def wait(self, target, command, regexp, op, result, wait):
        self.log('%s:%s WAIT:%s:%s:%s:%s:%s:%s:' % \
                 (self.l_filename, self.l_line, target, command, regexp, op, result,wait))
        llevel = LUtil.l_level
        found = False
        n = 0
        startt = time.time()
        delta = time.time() - startt
        while delta < wait and found is False:
            found = self.command(target, command, regexp, op, result)
            n+=1
            LUtil.l_level = 0
            delta = time.time() - startt
            if delta < wait and found is False:
                time.sleep (0.5)
        LUtil.l_level = llevel
        self.log('Done after %d loops, time=%s, Found=%s' % (n, delta, found))
        found = self.command(target, command, regexp, 'pass', '%s +%4.2f secs' % (result, delta))
        return found

#init class
LUtil=lUtil()

#entry calls
def luStart(baseScriptDir='.', baseLogDir='.', net='',
            fout='output.log', fsum='summary.txt', level=9):
    LUtil.base_script_dir = baseScriptDir
    LUtil.base_log_dir = baseLogDir
    LUtil.net = net
    if fout != '':
        LUtil.fout_name = baseLogDir + '/' + fout
    if fsum != None:
        LUtil.fsum_name = baseLogDir + '/' + fsum
    LUtil.l_level = level

def luCommand(target, command, regexp='.', op='none', result='', time=10):
    if op != 'wait':
        return LUtil.command(target, command, regexp, op, result)
    else:
        return LUtil.wait(target, command, regexp, op, result, time)


def luInclude(filename, CallOnFail=None):
    global LUtil
    tstFile = LUtil.base_script_dir + '/' + filename
    LUtil.setFilename(filename)
    if CallOnFail != None:
        oldCallOnFail = LUtil.getCallOnFail()
        LUtil.setCallOnFail(CallOnFail)
    if filename.endswith('.py'):
        execfile(tstFile)
    else:
        LUtil.execTestFile(tstFile)
    if CallOnFail != None:
        LUtil.setCallOnFail(oldCallOnFail)

def luFinish():
    return LUtil.closeFiles()

def luNumFail():
    return LUtil.l_fail

def luNumPass():
    return LUtil.l_pass

def luShowFail():
    printed = 0
    sf = open(LUtil.fsum_name, 'r')
    for line in sf:
        if line[-2] != "0":
            printed+=1
            logger.error(line.rstrip())
    sf.close()
    if printed > 0:
         logger.error("See %s for details of errors" % LUtil.fout_name)

#for testing
if __name__ == '__main__':
    print(os.path.dirname(os.path.dirname(os.path.abspath(__file__))) + '/lib')
    luStart()
    for arg in sys.argv[1:]:
        luInclude(arg)
    luFinish()
    sys.exit(0)

