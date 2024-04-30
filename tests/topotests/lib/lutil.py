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
import json
import math
import time
from lib.topolog import logger
from lib.topotest import json_cmp


# L utility functions
#
# These functions are inteneted to provide support for CI testing within MiniNet
# environments.


class lUtil:
    # to be made configurable in the future
    base_script_dir = "."
    base_log_dir = "."
    fout_name = "output.log"
    fsum_name = "summary.txt"
    l_level = 6
    CallOnFail = False

    l_total = 0
    l_pass = 0
    l_fail = 0
    l_filename = ""
    l_last = None
    l_line = 0
    l_dotall_experiment = False
    l_last_nl = None
    l_wait_strict = 1

    fout = ""
    fsum = ""
    net = ""

    def log(self, str, level=6):
        if self.l_level > 0:
            if self.fout == "":
                self.fout = open(self.fout_name, "w")
            self.fout.write(str + "\n")
        if level <= self.l_level:
            print(str)

    def summary(self, str):
        if self.fsum == "":
            self.fsum = open(self.fsum_name, "w")
            self.fsum.write(
                "\
******************************************************************************\n"
            )
            self.fsum.write(
                "\
Test Target Summary                                                  Pass Fail\n"
            )
            self.fsum.write(
                "\
******************************************************************************\n"
            )
        self.fsum.write(str + "\n")

    def result(self, target, success, str, logstr=None):
        if success:
            p = 1
            f = 0
            self.l_pass += 1
            sstr = "PASS"
        else:
            f = 1
            p = 0
            self.l_fail += 1
            sstr = "FAIL"
        self.l_total += 1
        if logstr != None:
            self.log("R:%d %s: %s" % (self.l_total, sstr, logstr))
        res = "%-4d %-6s %-56s %-4d %d" % (self.l_total, target, str, p, f)
        self.log("R:" + res)
        self.summary(res)
        if f == 1 and self.CallOnFail != False:
            self.CallOnFail()

    def closeFiles(self):
        ret = (
            "\
******************************************************************************\n\
Total %-4d                                                           %-4d %d\n\
******************************************************************************"
            % (self.l_total, self.l_pass, self.l_fail)
        )
        if self.fsum != "":
            self.fsum.write(ret + "\n")
            self.fsum.close()
            self.fsum = ""
        if self.fout != "":
            if os.path.isfile(self.fsum_name):
                r = open(self.fsum_name, "r")
                self.fout.write(r.read())
                r.close()
            self.fout.close()
            self.fout = ""
        return ret

    def setFilename(self, name):
        str = "FILE: " + name
        self.log(str)
        self.summary(str)
        self.l_filename = name
        self.line = 0

    def getCallOnFail(self):
        return self.CallOnFail

    def setCallOnFail(self, CallOnFail):
        self.CallOnFail = CallOnFail

    def strToArray(self, string):
        a = []
        c = 0
        end = ""
        words = string.split()
        if len(words) < 1 or words[0].startswith("#"):
            return a
        words = string.split()
        for word in words:
            if len(end) == 0:
                a.append(word)
            else:
                a[c] += str(" " + word)
            if end == "\\":
                end = ""
            if not word.endswith("\\"):
                if end != '"':
                    if word.startswith('"'):
                        end = '"'
                    else:
                        c += 1
                else:
                    if word.endswith('"'):
                        end = ""
                        c += 1
                    else:
                        c += 1
            else:
                end = "\\"
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
                        self.log("%s:%s %s" % (self.l_filename, self.l_line, line))
                        if len(a) >= 2:
                            if a[0] == "sleep":
                                time.sleep(int(a[1]))
                            elif a[0] == "include":
                                self.execTestFile(a[1])
            f.close()
        else:
            self.log("unable to read: " + tstFile)
            sys.exit(1)

    def command(self, target, command, regexp, op, result, returnJson, startt=None, force_result=False):
        global net
        if op == "jsoncmp_pass" or op == "jsoncmp_fail":
            returnJson = True

        self.log(
            "%s (#%d) %s:%s COMMAND:%s:%s:%s:%s:%s:"
            % (
                time.asctime(),
                self.l_total + 1,
                self.l_filename,
                self.l_line,
                target,
                command,
                regexp,
                op,
                result,
            )
        )
        if self.net == "":
            return False
        # self.log("Running %s %s" % (target, command))
        js = None
        out = self.net[target].cmd(command).rstrip()
        if len(out) == 0:
            report = "<no output>"
        else:
            report = out
            if returnJson == True:
                try:
                    js = json.loads(out)
                except:
                    js = None
                    self.log(
                        "WARNING: JSON load failed -- confirm command output is in JSON format."
                    )
        self.log("COMMAND OUTPUT:%s:" % report)

        # JSON comparison
        if op == "jsoncmp_pass" or op == "jsoncmp_fail":
            try:
                expect = json.loads(regexp)
            except:
                expect = None
                self.log(
                    "WARNING: JSON load failed -- confirm regex input is in JSON format."
                )
            json_diff = json_cmp(js, expect)
            if json_diff != None:
                if op == "jsoncmp_fail":
                    success = True
                else:
                    success = False
                    self.log("JSON DIFF:%s:" % json_diff)
                ret = success
            else:
                if op == "jsoncmp_fail":
                    success = False
                else:
                    success = True
            self.result(target, success, result)
            if js != None:
                return js
            return ret

        # Experiment: can we achieve the same match behavior via DOTALL
        # without converting newlines to spaces?
        out_nl = out
        search_nl = re.search(regexp, out_nl, re.DOTALL)
        self.l_last_nl = search_nl
        # Set up for comparison
        if search_nl != None:
            group_nl = search_nl.group()
            group_nl_converted = " ".join(group_nl.splitlines())
        else:
            group_nl_converted = None

        out = " ".join(out.splitlines())
        search = re.search(regexp, out)
        self.l_last = search
        if search == None:
            if op == "fail":
                success = True
            else:
                success = False
            ret = success
        else:
            ret = search.group()
            if op != "fail":
                success = True
                level = 7
            else:
                success = False
                level = 5
            self.log("found:%s:" % ret, level)
            # Experiment: compare matched strings obtained each way
            if self.l_dotall_experiment and (group_nl_converted != ret):
                self.log(
                    "DOTALL experiment: strings differ dotall=[%s] orig=[%s]"
                    % (group_nl_converted, ret),
                    9,
                )
        if startt != None:
            if js != None or ret is not False or force_result is not False:
                delta = time.time() - startt
                self.result(target, success, "%s +%4.2f secs" % (result, delta))
        elif op == "pass" or op == "fail":
            self.result(target, success, result)
        if js != None:
            return js
        return ret

    def wait(
        self, target, command, regexp, op, result, wait, returnJson, wait_time=0.5
    ):
        self.log(
            "%s:%s WAIT:%s:%s:%s:%s:%s:%s:%s:"
            % (
                self.l_filename,
                self.l_line,
                target,
                command,
                regexp,
                op,
                result,
                wait,
                wait_time,
            )
        )
        found = False
        n = 0
        startt = time.time()

        if (op == "wait-strict") or ((op == "wait") and self.l_wait_strict):
            strict = True
        else:
            strict = False

        # Calculate the amount of `sleep`s we are going to peform.
        wait_count = int(math.ceil(wait / wait_time)) + 1

        force_result = False
        while wait_count > 0:
            n += 1

            # log a failure on last iteration if we don't get desired regexp
            if strict and (wait_count == 1):
                force_result = True

            found = self.command(target, command, regexp, op, result, returnJson, startt, force_result)
            if found is not False:
                break

            wait_count -= 1
            if wait_count > 0:
                time.sleep(wait_time)

        delta = time.time() - startt
        self.log("Done after %d loops, time=%s, Found=%s" % (n, delta, found))
        return found


# initialized by luStart
LUtil = None

# entry calls
def luStart(
    baseScriptDir=".",
    baseLogDir=".",
    net="",
    fout="output.log",
    fsum="summary.txt",
    level=None,
):
    global LUtil
    # init class
    LUtil = lUtil()
    LUtil.base_script_dir = baseScriptDir
    LUtil.base_log_dir = baseLogDir
    LUtil.net = net
    if fout != "":
        LUtil.fout_name = baseLogDir + "/" + fout
    if fsum != None:
        LUtil.fsum_name = baseLogDir + "/" + fsum
    if level != None:
        LUtil.l_level = level
    LUtil.l_dotall_experiment = False
    LUtil.l_dotall_experiment = True


def luCommand(
    target,
    command,
    regexp=".",
    op="none",
    result="",
    time=10,
    returnJson=False,
    wait_time=0.5,
):
    waitops = ["wait", "wait-strict", "wait-nostrict"]

    if op in waitops:
        return LUtil.wait(
            target, command, regexp, op, result, time, returnJson, wait_time
        )
    else:
        return LUtil.command(target, command, regexp, op, result, returnJson)


def luLast(usenl=False):
    if usenl:
        if LUtil.l_last_nl != None:
            LUtil.log("luLast:%s:" % LUtil.l_last_nl.group(), 7)
        return LUtil.l_last_nl
    else:
        if LUtil.l_last != None:
            LUtil.log("luLast:%s:" % LUtil.l_last.group(), 7)
        return LUtil.l_last


def luInclude(filename, CallOnFail=None):
    tstFile = LUtil.base_script_dir + "/" + filename
    LUtil.setFilename(filename)
    if CallOnFail != None:
        oldCallOnFail = LUtil.getCallOnFail()
        LUtil.setCallOnFail(CallOnFail)
    if filename.endswith(".py"):
        LUtil.log("luInclude: execfile " + tstFile)
        with open(tstFile) as infile:
            exec(infile.read())
    else:
        LUtil.log("luInclude: execTestFile " + tstFile)
        LUtil.execTestFile(tstFile)
    if CallOnFail != None:
        LUtil.setCallOnFail(oldCallOnFail)


def luFinish():
    global LUtil
    ret = LUtil.closeFiles()
    # done
    LUtil = None
    return ret


def luNumFail():
    return LUtil.l_fail


def luNumPass():
    return LUtil.l_pass


def luResult(target, success, str, logstr=None):
    return LUtil.result(target, success, str, logstr)


def luShowResults(prFunction):
    printed = 0
    sf = open(LUtil.fsum_name, "r")
    for line in sf:
        printed += 1
        prFunction(line.rstrip())
    sf.close()


def luShowFail():
    printed = 0
    sf = open(LUtil.fsum_name, "r")
    for line in sf:
        if line[-2] != "0":
            printed += 1
            logger.error(line.rstrip())
    sf.close()
    if printed > 0:
        logger.error("See %s for details of errors" % LUtil.fout_name)

#
# Sets default wait type for luCommand(op="wait) (may be overridden by
# specifying luCommand(op="wait-strict") or luCommand(op="wait-nostrict")).
#
# "nostrict" is the historical default behavior, which is to ignore
# failures to match the specified regexp in the specified time.
#
# "strict" means that failure to match the specified regexp in the
# specified time yields an explicit, logged failure result
#
def luSetWaitType(waittype):
    if waittype == "strict":
        LUtil.l_wait_strict = 1
    else:
        if waittype == "nostrict":
            LUtil.l_wait_strict = 0
        else:
            raise ValueError('waittype must be one of "strict" or "nostrict"')


# for testing
if __name__ == "__main__":
    print(os.path.dirname(os.path.dirname(os.path.abspath(__file__))) + "/lib")
    luStart()
    for arg in sys.argv[1:]:
        luInclude(arg)
    luFinish()
    sys.exit(0)
