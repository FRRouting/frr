#!/usr/bin/env python3
# -*- coding: utf-8 eval: (yapf-mode 1) -*-
#
# July 9 2021, Christian Hopps <chopps@labn.net>
#
# Copyright (c) 2021, LabN Consulting, L.L.C.
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
#

import argparse
import glob
import logging
import os
import re
import xmltodict


def get_summary(results):
    ntest = int(results["@tests"])
    nfail = int(results["@failures"])
    nerror = int(results["@errors"])
    nskip = int(results["@skipped"])
    npass = ntest - nfail - nskip - nerror
    return ntest, npass, nfail, nerror, nskip


def print_summary(results, args):
    ntest, npass, nfail, nerror, nskip = (0, 0, 0, 0, 0)
    for group in sorted(results):
        _ntest, _npass, _nfail, _nerror, _nskip = get_summary(results[group])
        if args.verbose:
            print(f"Group: {group} Total: {_ntest} PASSED: {_npass}"
                  " FAIL: {_nfail} ERROR: {_nerror} SKIP: {_nskip}")
        ntest += _ntest
        npass += _npass
        nfail += _nfail
        nerror += _nerror
        nskip += _nskip
    print(f"Total: {ntest} PASSED: {npass} FAIL: {nfail} ERROR: {nerror} SKIP: {nskip}")


def print_filter(tfilter, results, args):
    del args
    found_files = set()
    for group in sorted(results):
        for testcase in results[group]["testcase"]:
            if tfilter not in testcase:
                continue
            #cname = testcase["@classname"]
            fname = testcase["@file"]
            #name = testcase["@name"]
            #line = testcase["@line"]
            found_files.add(fname)
    if found_files:
        print("\n".join(sorted(found_files)))


def print_passed(results, args):
    del args
    found_files = set()
    for group in sorted(results):
        for testcase in results[group]["testcase"]:
            if ("failure" in testcase or "error" in testcase or "skipped" in testcase):
                continue
            if "@file" not in testcase:
                logging.error("@file not found in testcase %s", testcase)
                continue
            fname = testcase["@file"]
            found_files.add(fname)
    if found_files:
        print("\n".join(sorted(found_files)))


def print_failed(results, args):
    print_filter("failure", results, args)


def print_errored(results, args):
    print_filter("error", results, args)


def print_skipped(results, args):
    print_filter("skipped", results, args)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--rundir", help="split-test.sh topotest results base directory")
    parser.add_argument("-r", "--runfile", help="tpotests.xml results file")
    parser.add_argument("-f", "--failed", action="store_true", help="print failed tests")
    parser.add_argument("-e", "--errored", action="store_true", help="print errored tests")
    parser.add_argument("-p", "--passed", action="store_true", help="print passed tests")
    parser.add_argument("-S", "--skipped", action="store_true", help="print skipped tests")
    parser.add_argument("-s", "--summary", action="store_true", help="print summary")
    parser.add_argument("-v", "--verbose", action="store_true", help="be verbose")
    args = parser.parse_args()

    results = {}
    ttfiles = []
    if args.rundir:
        basedir = os.path.realpath(args.rundir)
        os.chdir(basedir)

        newfiles = glob.glob("tt-group-*/topotests.xml")
        if newfiles:
            ttfiles.extend(newfiles)
        if os.path.exists("topotests.xml"):
            ttfiles.append("topotests.xml")
    else:
        if args.runfile:
            ttfiles = [args.runfile]

        if not ttfiles and os.path.exists("/tmp/topotests.xml"):
            ttfiles.append("/tmp/topotests.xml")

    for f in ttfiles:
        m = re.match(r"tt-group-(\d+)/topotests.xml", f)
        group = int(m.group(1)) if m else 0
        with open(f) as xml_file:
            results[group] = xmltodict.parse(xml_file.read())["testsuites"]["testsuite"]

    if args.errored:
        print_errored(results, args)
    if args.failed:
        print_failed(results, args)
    if args.skipped:
        print_skipped(results, args)
    if args.passed:
        print_passed(results, args)
    if args.summary:
        print_summary(results, args)


if __name__ == "__main__":
    main()
