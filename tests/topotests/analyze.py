#!/usr/bin/env python3
# -*- coding: utf-8 eval: (blacken-mode 1) -*-
# SPDX-License-Identifier: GPL-2.0-or-later
#
# July 9 2021, Christian Hopps <chopps@labn.net>
#
# Copyright (c) 2021, LabN Consulting, L.L.C.
#
import argparse
import atexit
import logging
import os
import re
import subprocess
import sys
import tempfile
from collections import OrderedDict

import xmltodict

# pytest-xdist collection errors use the worker id (e.g. gw5) as @name.
XDIST_WORKER_RE = re.compile(r"^gw\d+$")


def _first_node(node):
    """Return the first dict node when xmltodict yields a list."""
    if isinstance(node, list):
        node = node[0] if node else None
    return node if isinstance(node, dict) else None


def _skipped_node(testcase):
    return _first_node(testcase.get("skipped"))


def is_xfail(testcase):
    """Expected failure: <skipped type="pytest.xfail" .../>."""
    skipped = _skipped_node(testcase)
    return bool(skipped) and skipped.get("@type") == "pytest.xfail"


def is_xpass(testcase):
    """Strict unexpected pass: <failure message="[XPASS(strict)] ..."/>."""
    failure = _first_node(testcase.get("failure"))
    if not failure:
        return False
    return failure.get("@message", "").startswith("[XPASS")


def is_error(testcase):
    return "error" in testcase


def is_failure(testcase):
    """Any JUnit failure, including strict XPASS."""
    return "failure" in testcase


def is_skip(testcase):
    """Real skip, excluding expected xfails."""
    return "skipped" in testcase and not is_xfail(testcase)


def is_pass(testcase):
    return (
        "failure" not in testcase
        and "error" not in testcase
        and "skipped" not in testcase
    )


STATUS_XFAIL = "Known Failure"
STATUS_XPASS = "Unexpected Pass"
STATUS_FAIL = "Failure"
STATUS_WIDTH = max(len(STATUS_XFAIL), len(STATUS_XPASS), len(STATUS_FAIL))


def testcase_label(tcname, testcase):
    if is_xfail(testcase):
        status = STATUS_XFAIL
    elif is_xpass(testcase):
        status = STATUS_XPASS
    elif is_failure(testcase) or is_error(testcase):
        status = STATUS_FAIL
    else:
        return tcname
    return "{}: {}".format(status.ljust(STATUS_WIDTH), tcname)


def get_errmsg(testcase):
    error = _first_node(testcase.get("error"))
    if error is not None:
        return error.get("@message", "none found")
    failure = _first_node(testcase.get("failure"))
    if failure is not None:
        return failure.get("@message", "none found")
    if is_xfail(testcase):
        skipped = _skipped_node(testcase)
        return skipped.get("@message", "none found") if skipped else "none found"
    return "none found"


def get_errtext(testcase):
    error = _first_node(testcase.get("error"))
    if error is not None:
        return error.get("#text") or error.get("@message", "none found")
    failure = _first_node(testcase.get("failure"))
    if failure is not None:
        return failure.get("#text") or failure.get("@message", "none found")
    if is_xfail(testcase):
        skipped = _skipped_node(testcase)
        if skipped is None:
            return "none found"
        return skipped.get("#text") or skipped.get("@message", "none found")
    return "none found"


def iter_testcases(suite):
    testcases = suite.get("testcase", [])
    if isinstance(testcases, dict):
        return [testcases]
    return testcases or []


def get_range_list(rangestr):
    result = []
    for e in rangestr.split(","):
        e = e.strip()
        if not e:
            continue
        if e.find("-") == -1:
            result.append(int(e))
        else:
            start, end = e.split("-")
            result.extend(list(range(int(start), int(end) + 1)))
    return result


def dict_range_(dct, rangestr, dokeys):
    keys = list(dct.keys())
    if not rangestr or rangestr == "all":
        for key in keys:
            if dokeys:
                yield key
            else:
                yield dct[key]
        return

    dlen = len(keys)
    for index in get_range_list(rangestr):
        if index >= dlen:
            break
        key = keys[index]
        if dokeys:
            yield key
        else:
            yield dct[key]


def dict_range_keys(dct, rangestr):
    return dict_range_(dct, rangestr, True)


def dict_range_values(dct, rangestr):
    return dict_range_(dct, rangestr, False)


def get_summary(suite):
    # Suite @failures includes strict XPASS; @skipped includes expected xfail.
    ntest = int(suite["@tests"])
    nfail_attr = int(suite["@failures"])
    nerror = int(suite["@errors"])
    nskip_attr = int(suite["@skipped"])
    nxfail = 0
    nxpass = 0
    for testcase in iter_testcases(suite):
        if is_xfail(testcase):
            nxfail += 1
        elif is_xpass(testcase):
            nxpass += 1
    nfail = nfail_attr - nxpass
    nskip = nskip_attr - nxfail
    npass = ntest - nfail_attr - nerror - nskip_attr
    return ntest, npass, nfail, nxpass, nerror, nxfail, nskip


def format_summary(ntest, npass, nfail, nxpass, nerror, nxfail, nskip):
    return (
        f"Total: {ntest} PASSED: {npass} FAIL: {nfail} XPASS: {nxpass}"
        f" ERROR: {nerror} XFAIL: {nxfail} SKIP: {nskip}"
    )


def print_summary(results, args):
    ntest, npass, nfail, nxpass, nerror, nxfail, nskip = (0, 0, 0, 0, 0, 0, 0)
    for group in results:
        (
            _ntest,
            _npass,
            _nfail,
            _nxpass,
            _nerror,
            _nxfail,
            _nskip,
        ) = get_summary(results[group])
        if args.verbose:
            print(
                f"Group: {group} "
                + format_summary(
                    _ntest, _npass, _nfail, _nxpass, _nerror, _nxfail, _nskip
                )
            )
        ntest += _ntest
        npass += _npass
        nfail += _nfail
        nxpass += _nxpass
        nerror += _nerror
        nxfail += _nxfail
        nskip += _nskip
    print(format_summary(ntest, npass, nfail, nxpass, nerror, nxfail, nskip))


def get_global_testcase(results):
    for group in results:
        for testcase in results[group]["testcase"]:
            if "@file" not in testcase:
                return testcase
    return None


def get_filtered(tfilters, results, args):
    if not isinstance(tfilters, (list, tuple)):
        tfilters = [tfilters]
    found_files = OrderedDict()
    for group in results:
        for testcase in iter_testcases(results[group]):
            for tfilter in tfilters:
                if tfilter(testcase):
                    break
            else:
                continue
            # cname = testcase["@classname"]
            fname = testcase.get("@file", "")
            cname = testcase.get("@classname", "")
            if not fname and not cname:
                name = testcase.get("@name", "")
                if not name:
                    continue
                if XDIST_WORKER_RE.match(name):
                    continue
                # If we had a failure at the module level we could be here.
                fname = name.replace(".", "/") + ".py"
                tcname = fname
            else:
                if not fname:
                    fname = cname.replace(".", "/") + ".py"
                if "@name" not in testcase:
                    tcname = fname
                else:
                    tcname = fname + "::" + testcase["@name"]
            found_files[tcname] = testcase
    return found_files


def search_testcase(testcase, regexp):
    for key, val in testcase.items():
        if regexp.search(str(val)):
            return True
    return False


def dump_testcase(testcase):
    s = ""
    for key, val in testcase.items():
        if isinstance(val, str) or isinstance(val, float) or isinstance(val, int):
            s += "{}: {}\n".format(key, val)
        elif isinstance(val, list):
            for k2, v2 in enumerate(val):
                s += "{}: {}\n".format(k2, v2)
        else:
            for k2, v2 in val.items():
                s += "{}: {}\n".format(k2, v2)
    return s


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "-a",
        "--save-xml",
        action="store_true",
        help=(
            "Move [container:]/tmp/topotests/topotests.xml "
            "to --results value if --results does not exist yet"
        ),
    )
    parser.add_argument(
        "-A",
        "--save",
        action="store_true",
        help=(
            "Move [container:]/tmp/topotests{,.xml} "
            "to --results value if --results does not exist yet"
        ),
    )
    parser.add_argument(
        "-C",
        "--container",
        help="specify docker/podman container of the run",
    )
    parser.add_argument(
        "--use-podman",
        action="store_true",
        help="Use `podman` instead of `docker` for saving container data",
    )
    parser.add_argument(
        "-S",
        "--select",
        help=(
            "select results combination of letters: "
            "'e'rrored 'f'ailed 'X'pass(strict) 'x'fail 'p'assed 's'kipped. "
            "'f' includes strict XPASS; 's' excludes expected XFAIL. "
            "Default is 'fex', unless --search or --time which default to 'efspx'"
        ),
    )
    parser.add_argument(
        "-R",
        "--search",
        help=(
            "filter results to those which match a regex. "
            "All test text is search unless restricted by --errmsg or --errtext"
        ),
    )
    parser.add_argument(
        "-r",
        "--results",
        help="xml results file or directory containing xml results file",
    )
    parser.add_argument("--rundir", help=argparse.SUPPRESS)
    parser.add_argument(
        "-E",
        "--enumerate",
        action="store_true",
        help="enumerate each item (results scoped)",
    )
    parser.add_argument(
        "-T", "--test", help="select testcase at given ordinal from the enumerated list"
    )
    parser.add_argument(
        "--errmsg", action="store_true", help="print testcase error message"
    )
    parser.add_argument(
        "--errtext", action="store_true", help="print testcase error text"
    )
    parser.add_argument(
        "--full", action="store_true", help="print all logging for selected testcases"
    )
    parser.add_argument("--time", action="store_true", help="print testcase run times")

    parser.add_argument("-s", "--summary", action="store_true", help="print summary")
    parser.add_argument("-v", "--verbose", action="store_true", help="be verbose")
    args = parser.parse_args()

    if args.save and args.save_xml:
        logging.critical("Only one of --save or --save-xml allowed")
        sys.exit(1)

    scount = bool(args.save) + bool(args.save_xml)

    #
    # Saving/Archiving results
    #

    docker_bin = "podman" if args.use_podman else "docker"
    contid = ""
    if args.container:
        # check for container existence
        contid = args.container
        try:
            # p =
            subprocess.run(
                f"{docker_bin} inspect {contid}",
                check=True,
                shell=True,
                errors="ignore",
                capture_output=True,
            )
        except subprocess.CalledProcessError:
            logging.critical(f"{docker_bin} container '{contid}' does not exist")
            sys.exit(1)
        # If you need container info someday...
        # cont_info = json.loads(p.stdout)

    cppath = "/tmp/topotests"
    if args.save_xml or scount == 0:
        cppath += "/topotests.xml"
    if contid:
        cppath = contid + ":" + cppath

    tresfile = None

    if scount and args.results and not os.path.exists(args.results):
        if not contid:
            if not os.path.exists(cppath):
                logging.critical(f"'{cppath}' doesn't exist to save")
                sys.exit(1)
            if args.save_xml:
                subprocess.run(["cp", cppath, args.results])
            else:
                subprocess.run(["mv", cppath, args.results])
        else:
            try:
                subprocess.run(
                    f"{docker_bin} cp {cppath} {args.results}",
                    check=True,
                    shell=True,
                    errors="ignore",
                    capture_output=True,
                )
            except subprocess.CalledProcessError as error:
                logging.critical(f"Can't {docker_bin} cp '{cppath}': %s", str(error))
                sys.exit(1)

        if "SUDO_USER" in os.environ:
            subprocess.run(["chown", "-R", os.environ["SUDO_USER"], args.results])
    elif not args.results:
        # User doesn't want to save results just use them inplace
        if not contid:
            if not os.path.exists(cppath):
                logging.critical(f"'{cppath}' doesn't exist")
                sys.exit(1)
            args.results = cppath
        else:
            tresfile, tresname = tempfile.mkstemp(
                suffix=".xml", prefix="topotests-", text=True
            )
            atexit.register(lambda: os.unlink(tresname))
            os.close(tresfile)
            try:
                subprocess.run(
                    f"{docker_bin} cp {cppath} {tresname}",
                    check=True,
                    shell=True,
                    errors="ignore",
                    capture_output=True,
                )
            except subprocess.CalledProcessError as error:
                logging.critical(f"Can't {docker_bin} cp '{cppath}': %s", str(error))
                sys.exit(1)
            args.results = tresname

    #
    # Result option validation
    #

    count = 0
    if args.errmsg:
        count += 1
    if args.errtext:
        count += 1
    if args.full:
        count += 1
    if count > 1:
        logging.critical("Only one of --full, --errmsg or --errtext allowed")
        sys.exit(1)

    if args.time and count:
        logging.critical("Can't use --full, --errmsg or --errtext with --time")
        sys.exit(1)

    if args.enumerate and (count or args.time or args.test):
        logging.critical(
            "Can't use --enumerate with --errmsg, --errtext, --full, --test or --time"
        )
        sys.exit(1)

    results = {}
    ttfiles = []

    if os.path.exists(os.path.join(args.results, "topotests.xml")):
        args.results = os.path.join(args.results, "topotests.xml")
    if not os.path.exists(args.results):
        logging.critical("%s doesn't exist", args.results)
        sys.exit(1)

    ttfiles = [args.results]

    for f in ttfiles:
        m = re.match(r"tt-group-(\d+)/topotests.xml", f)
        group = int(m.group(1)) if m else 0
        with open(f) as xml_file:
            results[group] = xmltodict.parse(xml_file.read())["testsuites"]["testsuite"]

    search_re = re.compile(args.search) if args.search else None

    if args.select is None:
        if search_re or args.time:
            args.select = "efspx"
        else:
            args.select = "fex"

    filters = []
    if "e" in args.select:
        filters.append(is_error)
    if "f" in args.select:
        filters.append(is_failure)
    elif "X" in args.select:
        # 'f' already includes strict XPASS; only add when 'f' is absent.
        filters.append(is_xpass)
    if "x" in args.select:
        filters.append(is_xfail)
    if "s" in args.select:
        filters.append(is_skip)
    if "p" in args.select:
        filters.append(is_pass)

    found_files = get_filtered(filters, results, args)

    if search_re:
        found_files = {
            k: v for k, v in found_files.items() if search_testcase(v, search_re)
        }

    if args.enumerate or (args.test is None and count == 0 and not args.time):
        # print the selected test names with ordinal (usable with --test)
        print(
            "\n".join(
                "{}: {}".format(i, testcase_label(name, found_files[name]))
                for i, name in enumerate(found_files)
            )
        )
    else:
        rangestr = args.test if args.test else "all"
        for key in dict_range_keys(found_files, rangestr):
            testcase = found_files[key]
            label = testcase_label(key, testcase)
            if args.time:
                text = testcase["@time"]
                s = "{}: {}".format(text, label)
            elif args.errtext:
                s = "{}: {}".format(label, get_errtext(testcase))
            elif args.errmsg:
                s = "{}: {}".format(label, get_errmsg(testcase))
            else:
                s = dump_testcase(testcase)
            print(s)

    if args.summary:
        print_summary(results, args)


if __name__ == "__main__":
    main()
