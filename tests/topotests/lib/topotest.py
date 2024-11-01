#!/usr/bin/env python
# SPDX-License-Identifier: ISC

#
# topotest.py
# Library of helper functions for NetDEF Topology Tests
#
# Copyright (c) 2016 by
# Network Device Education Foundation, Inc. ("NetDEF")
#

import configparser
import difflib
import errno
import functools
import glob
import json
import os
import platform
import re
import resource
import signal
import subprocess
import sys
import tempfile
import time
import logging
from collections.abc import Mapping
from copy import deepcopy
from pathlib import Path

import lib.topolog as topolog
from lib.micronet_compat import Node
from lib.topolog import logger
from munet.base import commander, get_exec_path_host, Timeout
from munet.testing.util import retry

from lib import micronet

g_pytest_config = None


def get_logs_path(rundir):
    logspath = topolog.get_test_logdir(module=True)
    return os.path.join(rundir, logspath)


def gdb_core(obj, daemon, corefiles):
    gdbcmds = r"""
set print elements 1024
echo -------\n
echo threads\n
echo -------\n
info threads
echo ---------\n
echo registers\n
echo ---------\n
info registers
echo ---------\n
echo backtrace\n
echo ---------\n
bt
    """
    gdbcmds = [["-ex", i.strip()] for i in gdbcmds.strip().split("\n")]
    gdbcmds = [item for sl in gdbcmds for item in sl]

    daemon_path = os.path.join(obj.daemondir, daemon)
    p = subprocess.run(
        ["gdb", daemon_path, corefiles[0], "--batch"] + gdbcmds,
        encoding="utf-8",
        errors="ignore",
        capture_output=True,
    )
    backtrace = p.stdout

    #
    # Grab the disassemble of top couple frames
    #
    m = re.search(r"#(\d+) .*assert.*", backtrace)
    if not m:
        m = re.search(r"#(\d+) .*abort.*", backtrace)
    frames = re.findall(r"\n#(\d+) ", backtrace)
    if m:
        frstart = -1
        astart = int(m.group(1)) + 1
        ocount = f"-{int(frames[-1]) - astart + 1}"
    else:
        astart = -1
        frstart = 0
        ocount = ""
        m = re.search(r"#(\d+) .*core_handler.*", backtrace)
        if m:
            frstart = int(m.group(1)) + 2
            ocount = f"-{int(frames[-1]) - frstart + 1}"

    sys.stderr.write(
        f"\nCORE FOUND: {obj.name}: {daemon} crashed: see log for backtrace and more\n"
    )

    gdbcmds = rf"""
set print elements 1024
echo -------------------------\n
echo backtrace with local args\n
echo -------------------------\n
bt full {ocount}
"""
    if frstart >= 0:
        gdbcmds += rf"""echo ---------------------------------------\n
echo disassemble of failing funciton (guess)\n
echo ---------------------------------------\n
fr {frstart}
disassemble /m
"""

    gdbcmds = [["-ex", i.strip()] for i in gdbcmds.strip().split("\n")]
    gdbcmds = [item for sl in gdbcmds for item in sl]

    daemon_path = os.path.join(obj.daemondir, daemon)
    p = subprocess.run(
        ["gdb", daemon_path, corefiles[0], "-q", "--batch"] + gdbcmds,
        encoding="utf-8",
        errors="ignore",
        capture_output=True,
    )
    btdump = p.stdout

    # sys.stderr.write(
    #     "\n%s: %s crashed. Core file found - Backtrace follows:\n" % (obj.name, daemon)
    # )

    return backtrace + btdump


class json_cmp_result(object):
    "json_cmp result class for better assertion messages"

    def __init__(self):
        self.errors = []

    def add_error(self, error):
        "Append error message to the result"
        for line in error.splitlines():
            self.errors.append(line)

    def has_errors(self):
        "Returns True if there were errors, otherwise False."
        return len(self.errors) > 0

    def gen_report(self):
        headline = ["Generated JSON diff error report:", ""]
        return headline + self.errors

    def __str__(self):
        return (
            "Generated JSON diff error report:\n\n\n" + "\n".join(self.errors) + "\n\n"
        )


def gen_json_diff_report(output, expected, exact=False, path="> $", acc=(0, "")):
    """
    Internal workhorse which compares two JSON data structures and generates an error report suited to be read by a human eye.
    """

    def dump_json(v):
        if isinstance(v, (dict, list)):
            return "\t" + "\t".join(
                json.dumps(v, indent=4, separators=(",", ": ")).splitlines(True)
            )
        else:
            return "'{}'".format(v)

    def json_type(v):
        if isinstance(v, (list, tuple)):
            return "Array"
        elif isinstance(v, dict):
            return "Object"
        elif isinstance(v, (int, float)):
            return "Number"
        elif isinstance(v, bool):
            return "Boolean"
        elif isinstance(v, str):
            return "String"
        elif v == None:
            return "null"

    def get_errors(other_acc):
        return other_acc[1]

    def get_errors_n(other_acc):
        return other_acc[0]

    def add_error(acc, msg, points=1):
        return (acc[0] + points, acc[1] + "{}: {}\n".format(path, msg))

    def merge_errors(acc, other_acc):
        return (acc[0] + other_acc[0], acc[1] + other_acc[1])

    def add_idx(idx):
        return "{}[{}]".format(path, idx)

    def add_key(key):
        return "{}->{}".format(path, key)

    def has_errors(other_acc):
        return other_acc[0] > 0

    if expected == "*" or (
        not isinstance(output, (list, dict))
        and not isinstance(expected, (list, dict))
        and output == expected
    ):
        return acc
    elif (
        not isinstance(output, (list, dict))
        and not isinstance(expected, (list, dict))
        and output != expected
    ):
        acc = add_error(
            acc,
            "output has element with value '{}' but in expected it has value '{}'".format(
                output, expected
            ),
        )
    elif (
        isinstance(output, list)
        and isinstance(expected, list)
        and ((len(expected) > 0 and expected[0] == "__ordered__") or exact)
    ):
        if not exact:
            del expected[0]
        if len(output) != len(expected):
            acc = add_error(
                acc,
                "output has Array of length {} but in expected it is of length {}".format(
                    len(output), len(expected)
                ),
            )
        else:
            for idx, v1, v2 in zip(range(0, len(output)), output, expected):
                acc = merge_errors(
                    acc, gen_json_diff_report(v1, v2, exact=exact, path=add_idx(idx))
                )
    elif isinstance(output, list) and isinstance(expected, list):
        if len(output) < len(expected):
            acc = add_error(
                acc,
                "output has Array of length {} but in expected it is of length {}".format(
                    len(output), len(expected)
                ),
            )
        else:
            for idx2, v2 in zip(range(0, len(expected)), expected):
                found_match = False
                closest_diff = None
                closest_idx = None
                for idx1, v1 in zip(range(0, len(output)), output):
                    tmp_v1 = deepcopy(v1)
                    tmp_v2 = deepcopy(v2)
                    tmp_diff = gen_json_diff_report(tmp_v1, tmp_v2, path=add_idx(idx1))
                    if not has_errors(tmp_diff):
                        found_match = True
                        del output[idx1]
                        break
                    elif not closest_diff or get_errors_n(tmp_diff) < get_errors_n(
                        closest_diff
                    ):
                        closest_diff = tmp_diff
                        closest_idx = idx1
                if not found_match and isinstance(v2, (list, dict)):
                    sub_error = "\n\n\t{}".format(
                        "\t".join(get_errors(closest_diff).splitlines(True))
                    )
                    acc = add_error(
                        acc,
                        (
                            "expected has the following element at index {} which is not present in output: "
                            + "\n\n{}\n\n\tClosest match in output is at index {} with the following errors: {}"
                        ).format(idx2, dump_json(v2), closest_idx, sub_error),
                    )
                if not found_match and not isinstance(v2, (list, dict)):
                    acc = add_error(
                        acc,
                        "expected has the following element at index {} which is not present in output: {}".format(
                            idx2, dump_json(v2)
                        ),
                    )
    elif isinstance(output, dict) and isinstance(expected, dict) and exact:
        invalid_keys_d1 = [k for k in output.keys() if k not in expected.keys()]
        invalid_keys_d2 = [k for k in expected.keys() if k not in output.keys()]
        for k in invalid_keys_d1:
            acc = add_error(
                acc, "output has key '{}' which is not present in expected".format(k)
            )
        for k in invalid_keys_d2:
            acc = add_error(
                acc, "expected has key '{}' which is not present in output".format(k)
            )
        valid_keys_intersection = [k for k in output.keys() if k in expected.keys()]
        for k in valid_keys_intersection:
            acc = merge_errors(
                acc,
                gen_json_diff_report(
                    output[k], expected[k], exact=exact, path=add_key(k)
                ),
            )
    elif isinstance(output, dict) and isinstance(expected, dict):
        none_keys = [k for k, v in expected.items() if v == None]
        none_keys_present = [k for k in output.keys() if k in none_keys]
        for k in none_keys_present:
            acc = add_error(
                acc, "output has key '{}' which is not supposed to be present".format(k)
            )
        keys = [k for k, v in expected.items() if v != None]
        invalid_keys_intersection = [k for k in keys if k not in output.keys()]
        for k in invalid_keys_intersection:
            acc = add_error(
                acc, "expected has key '{}' which is not present in output".format(k)
            )
        valid_keys_intersection = [k for k in keys if k in output.keys()]
        for k in valid_keys_intersection:
            acc = merge_errors(
                acc,
                gen_json_diff_report(
                    output[k], expected[k], exact=exact, path=add_key(k)
                ),
            )
    else:
        acc = add_error(
            acc,
            "output has element of type '{}' but the corresponding element in expected is of type '{}'".format(
                json_type(output), json_type(expected)
            ),
            points=2,
        )

    return acc


def json_cmp(output, expected, exact=False):
    """
    JSON compare function. Receives two parameters:
    * `output`: parsed JSON data structure from outputed vtysh command
    * `expected``: parsed JSON data structure from what is expected to be seen

    Returns 'None' when all JSON Object keys and all Array elements of expected have a match
    in output, i.e., when expected is a "subset" of output without honoring any order. Otherwise an
    error report is generated and wrapped in a 'json_cmp_result()'. There are special
    parameters and notations explained below which can be used to cover rather unusual
    cases:

    * when 'exact is set to 'True' then output and expected are tested for equality (including
      order within JSON Arrays)
    * using 'null' (or 'None' in Python) as JSON Object value is checking for key
      absence in output
    * using '*' as JSON Object value or Array value is checking for presence in output
      without checking the values
    * using '__ordered__' as first element in a JSON Array in expected will also check the
      order when it is compared to an Array in output
    """

    (errors_n, errors) = gen_json_diff_report(
        deepcopy(output), deepcopy(expected), exact=exact
    )

    if errors_n > 0:
        result = json_cmp_result()
        result.add_error(errors)
        return result
    else:
        return None


def router_output_cmp(router, cmd, expected):
    """
    Runs `cmd` in router and compares the output with `expected`.
    """
    return difflines(
        normalize_text(router.vtysh_cmd(cmd)),
        normalize_text(expected),
        title1="Current output",
        title2="Expected output",
    )


def router_json_cmp(router, cmd, data, exact=False):
    """
    Runs `cmd` that returns JSON data (normally the command ends with 'json')
    and compare with `data` contents.
    """
    return json_cmp(router.vtysh_cmd(cmd, isjson=True), data, exact)


def run_and_expect(func, what, count=20, wait=3):
    """
    Run `func` and compare the result with `what`. Do it for `count` times
    waiting `wait` seconds between tries. By default it tries 20 times with
    3 seconds delay between tries.

    Changing default count/wait values, please change them below also for
    `minimum_wait`, and `minimum_count`.

    Returns (True, func-return) on success or
    (False, func-return) on failure.

    ---

    Helper functions to use with this function:
    - router_output_cmp
    - router_json_cmp
    """
    start_time = time.time()
    func_name = "<unknown>"
    if func.__class__ == functools.partial:
        func_name = func.func.__name__
    else:
        func_name = func.__name__

    # Just a safety-check to avoid running topotests with very
    # small wait/count arguments.
    # If too low count/wait values are defined, override them
    # with the minimum values.
    minimum_count = 20
    minimum_wait = 3
    minimum_wait_time = 15  # The overall minimum seconds for the test to wait
    wait_time = wait * count
    if wait_time < minimum_wait_time:
        logger.warning(
            f"Waiting time is too small (count={count}, wait={wait}), using default values (count={minimum_count}, wait={minimum_wait})"
        )
        count = minimum_count
        wait = minimum_wait

    logger.debug(
        "'{}' polling started (interval {} secs, maximum {} tries)".format(
            func_name, wait, count
        )
    )

    while count > 0:
        result = func()
        if result != what:
            time.sleep(wait)
            count -= 1
            continue

        end_time = time.time()
        logger.debug(
            "'{}' succeeded after {:.2f} seconds".format(
                func_name, end_time - start_time
            )
        )
        return (True, result)

    end_time = time.time()
    logger.error(
        "'{}' failed after {:.2f} seconds".format(func_name, end_time - start_time)
    )
    return (False, result)


def run_and_expect_type(func, etype, count=20, wait=3, avalue=None):
    """
    Run `func` and compare the result with `etype`. Do it for `count` times
    waiting `wait` seconds between tries. By default it tries 20 times with
    3 seconds delay between tries.

    This function is used when you want to test the return type and,
    optionally, the return value.

    Returns (True, func-return) on success or
    (False, func-return) on failure.
    """
    start_time = time.time()
    func_name = "<unknown>"
    if func.__class__ == functools.partial:
        func_name = func.func.__name__
    else:
        func_name = func.__name__

    # Just a safety-check to avoid running topotests with very
    # small wait/count arguments.
    wait_time = wait * count
    if wait_time < 5:
        assert (
            wait_time >= 5
        ), "Waiting time is too small (count={}, wait={}), adjust timer values".format(
            count, wait
        )

    logger.debug(
        "'{}' polling started (interval {} secs, maximum wait {} secs)".format(
            func_name, wait, int(wait * count)
        )
    )

    while count > 0:
        result = func()
        if not isinstance(result, etype):
            logger.debug(
                "Expected result type '{}' got '{}' instead".format(etype, type(result))
            )
            time.sleep(wait)
            count -= 1
            continue

        if etype != type(None) and avalue != None and result != avalue:
            logger.debug("Expected value '{}' got '{}' instead".format(avalue, result))
            time.sleep(wait)
            count -= 1
            continue

        end_time = time.time()
        logger.debug(
            "'{}' succeeded after {:.2f} seconds".format(
                func_name, end_time - start_time
            )
        )
        return (True, result)

    end_time = time.time()
    logger.error(
        "'{}' failed after {:.2f} seconds".format(func_name, end_time - start_time)
    )
    return (False, result)


def router_json_cmp_retry(router, cmd, data, exact=False, retry_timeout=10.0):
    """
    Runs `cmd` that returns JSON data (normally the command ends with 'json')
    and compare with `data` contents. Retry by default for 10 seconds
    """

    def test_func():
        return router_json_cmp(router, cmd, data, exact)

    ok, _ = run_and_expect(test_func, None, int(retry_timeout), 1)
    return ok


def int2dpid(dpid):
    "Converting Integer to DPID"

    try:
        dpid = hex(dpid)[2:]
        dpid = "0" * (16 - len(dpid)) + dpid
        return dpid
    except IndexError:
        raise Exception(
            "Unable to derive default datapath ID - "
            "please either specify a dpid or use a "
            "canonical switch name such as s23."
        )


def get_textdiff(text1, text2, title1="", title2="", **opts):
    "Returns empty string if same or formatted diff"

    diff = "\n".join(
        difflib.unified_diff(text1, text2, fromfile=title1, tofile=title2, **opts)
    )
    # Clean up line endings
    diff = os.linesep.join([s for s in diff.splitlines() if s])
    return diff


def difflines(text1, text2, title1="", title2="", **opts):
    "Wrapper for get_textdiff to avoid string transformations."
    text1 = ("\n".join(text1.rstrip().splitlines()) + "\n").splitlines(1)
    text2 = ("\n".join(text2.rstrip().splitlines()) + "\n").splitlines(1)
    return get_textdiff(text1, text2, title1, title2, **opts)


def get_file(content):
    """
    Generates a temporary file in '/tmp' with `content` and returns the file name.
    """
    if isinstance(content, list) or isinstance(content, tuple):
        content = "\n".join(content)
    fde = tempfile.NamedTemporaryFile(mode="w", delete=False)
    fname = fde.name
    fde.write(content)
    fde.close()
    return fname


def normalize_text(text):
    """
    Strips formating spaces/tabs, carriage returns and trailing whitespace.
    """
    text = re.sub(r"[ \t]+", " ", text)
    text = re.sub(r"\r", "", text)

    # Remove whitespace in the middle of text.
    text = re.sub(r"[ \t]+\n", "\n", text)
    # Remove whitespace at the end of the text.
    text = text.rstrip()

    return text


def is_linux():
    """
    Parses unix name output to check if running on GNU/Linux.

    Returns True if running on Linux, returns False otherwise.
    """

    if os.uname()[0] == "Linux":
        return True
    return False


def iproute2_is_json_capable():
    """
    Checks if the iproute2 version installed on the system is capable of
    handling JSON outputss

    Returns True if capability can be detected, returns False otherwise.
    """
    if is_linux():
        try:
            subp = subprocess.Popen(
                ["ip", "-json", "route", "show"],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                stdin=subprocess.PIPE,
            )
            iproute2_err = subp.communicate()[1].splitlines()[0].split()[0]

            if iproute2_err != "Error:":
                return True
        except Exception:
            pass
    return False


def iproute2_is_vrf_capable():
    """
    Checks if the iproute2 version installed on the system is capable of
    handling VRFs by interpreting the output of the 'ip' utility found in PATH.

    Returns True if capability can be detected, returns False otherwise.
    """

    if is_linux():
        try:
            subp = subprocess.Popen(
                ["ip", "route", "show", "vrf"],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                stdin=subprocess.PIPE,
            )
            iproute2_err = subp.communicate()[1].splitlines()[0].split()[0]

            if iproute2_err != "Error:":
                return True
        except Exception:
            pass
    return False


def iproute2_is_fdb_get_capable():
    """
    Checks if the iproute2 version installed on the system is capable of
    handling `bridge fdb get` commands to query neigh table resolution.

    Returns True if capability can be detected, returns False otherwise.
    """

    if is_linux():
        try:
            subp = subprocess.Popen(
                ["bridge", "fdb", "get", "help"],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                stdin=subprocess.PIPE,
            )
            iproute2_out = subp.communicate()[1].splitlines()[0].split()[0]

            if "Usage" in str(iproute2_out):
                return True
        except Exception:
            pass
    return False


def module_present_linux(module, load):
    """
    Returns whether `module` is present.

    If `load` is true, it will try to load it via modprobe.
    """
    with open("/proc/modules", "r") as modules_file:
        if module.replace("-", "_") in modules_file.read():
            return True
    cmd = "/sbin/modprobe {}{}".format("" if load else "-n ", module)
    if os.system(cmd) != 0:
        return False
    else:
        return True


def module_present_freebsd(module, load):
    return True


def module_present(module, load=True):
    if sys.platform.startswith("linux"):
        return module_present_linux(module, load)
    elif sys.platform.startswith("freebsd"):
        return module_present_freebsd(module, load)


def version_cmp(v1, v2):
    """
    Compare two version strings and returns:

    * `-1`: if `v1` is less than `v2`
    * `0`: if `v1` is equal to `v2`
    * `1`: if `v1` is greater than `v2`

    Raises `ValueError` if versions are not well formated.
    """
    vregex = r"(?P<whole>\d+(\.(\d+))*)"
    v1m = re.match(vregex, v1)
    v2m = re.match(vregex, v2)
    if v1m is None or v2m is None:
        raise ValueError("got a invalid version string")

    # Split values
    v1g = v1m.group("whole").split(".")
    v2g = v2m.group("whole").split(".")

    # Get the longest version string
    vnum = len(v1g)
    if len(v2g) > vnum:
        vnum = len(v2g)

    # Reverse list because we are going to pop the tail
    v1g.reverse()
    v2g.reverse()
    for _ in range(vnum):
        try:
            v1n = int(v1g.pop())
        except IndexError:
            while v2g:
                v2n = int(v2g.pop())
                if v2n > 0:
                    return -1
            break

        try:
            v2n = int(v2g.pop())
        except IndexError:
            if v1n > 0:
                return 1
            while v1g:
                v1n = int(v1g.pop())
                if v1n > 0:
                    return 1
            break

        if v1n > v2n:
            return 1
        if v1n < v2n:
            return -1
    return 0


def interface_set_status(node, ifacename, ifaceaction=False, vrf_name=None):
    if ifaceaction:
        str_ifaceaction = "no shutdown"
    else:
        str_ifaceaction = "shutdown"
    if vrf_name == None:
        cmd = 'vtysh -c "configure terminal" -c "interface {0}" -c "{1}"'.format(
            ifacename, str_ifaceaction
        )
    else:
        cmd = (
            'vtysh -c "configure terminal" -c "interface {0} vrf {1}" -c "{2}"'.format(
                ifacename, vrf_name, str_ifaceaction
            )
        )
    node.run(cmd)


def ip4_route_zebra(node, vrf_name=None):
    """
    Gets an output of 'show ip route' command. It can be used
    with comparing the output to a reference
    """
    if vrf_name == None:
        tmp = node.vtysh_cmd("show ip route")
    else:
        tmp = node.vtysh_cmd("show ip route vrf {0}".format(vrf_name))
    output = re.sub(r" [0-2][0-9]:[0-5][0-9]:[0-5][0-9]", " XX:XX:XX", tmp)

    lines = output.splitlines()
    header_found = False
    while lines and (not lines[0].strip() or not header_found):
        if "o - offload failure" in lines[0]:
            header_found = True
        lines = lines[1:]
    return "\n".join(lines)


def ip6_route_zebra(node, vrf_name=None):
    """
    Retrieves the output of 'show ipv6 route [vrf vrf_name]', then
    canonicalizes it by eliding link-locals.
    """

    if vrf_name == None:
        tmp = node.vtysh_cmd("show ipv6 route")
    else:
        tmp = node.vtysh_cmd("show ipv6 route vrf {0}".format(vrf_name))

    # Mask out timestamp
    output = re.sub(r" [0-2][0-9]:[0-5][0-9]:[0-5][0-9]", " XX:XX:XX", tmp)

    # Mask out the link-local addresses
    output = re.sub(r"fe80::[^ ]+,", "fe80::XXXX:XXXX:XXXX:XXXX,", output)

    lines = output.splitlines()
    header_found = False
    while lines and (not lines[0].strip() or not header_found):
        if "o - offload failure" in lines[0]:
            header_found = True
        lines = lines[1:]

    return "\n".join(lines)


def proto_name_to_number(protocol):
    return {
        "bgp": "186",
        "isis": "187",
        "ospf": "188",
        "rip": "189",
        "ripng": "190",
        "nhrp": "191",
        "eigrp": "192",
        "ldp": "193",
        "sharp": "194",
        "pbr": "195",
        "static": "196",
        "ospf6": "197",
    }.get(
        protocol, protocol
    )  # default return same as input


def ip4_route(node):
    """
    Gets a structured return of the command 'ip route'. It can be used in
    conjunction with json_cmp() to provide accurate assert explanations.

    Return example:
    {
        '10.0.1.0/24': {
            'dev': 'eth0',
            'via': '172.16.0.1',
            'proto': '188',
        },
        '10.0.2.0/24': {
            'dev': 'eth1',
            'proto': 'kernel',
        }
    }
    """
    output = normalize_text(node.run("ip route")).splitlines()
    result = {}
    for line in output:
        columns = line.split(" ")
        route = result[columns[0]] = {}
        prev = None
        for column in columns:
            if prev == "dev":
                route["dev"] = column
            if prev == "via":
                route["via"] = column
            if prev == "proto":
                # translate protocol names back to numbers
                route["proto"] = proto_name_to_number(column)
            if prev == "metric":
                route["metric"] = column
            if prev == "scope":
                route["scope"] = column
            prev = column

    return result


def ip4_vrf_route(node):
    """
    Gets a structured return of the command 'ip route show vrf {0}-cust1'.
    It can be used in conjunction with json_cmp() to provide accurate assert explanations.

    Return example:
    {
        '10.0.1.0/24': {
            'dev': 'eth0',
            'via': '172.16.0.1',
            'proto': '188',
        },
        '10.0.2.0/24': {
            'dev': 'eth1',
            'proto': 'kernel',
        }
    }
    """
    output = normalize_text(
        node.run("ip route show vrf {0}-cust1".format(node.name))
    ).splitlines()

    result = {}
    for line in output:
        columns = line.split(" ")
        route = result[columns[0]] = {}
        prev = None
        for column in columns:
            if prev == "dev":
                route["dev"] = column
            if prev == "via":
                route["via"] = column
            if prev == "proto":
                # translate protocol names back to numbers
                route["proto"] = proto_name_to_number(column)
            if prev == "metric":
                route["metric"] = column
            if prev == "scope":
                route["scope"] = column
            prev = column

    return result


def ip6_route(node):
    """
    Gets a structured return of the command 'ip -6 route'. It can be used in
    conjunction with json_cmp() to provide accurate assert explanations.

    Return example:
    {
        '2001:db8:1::/64': {
            'dev': 'eth0',
            'proto': '188',
        },
        '2001:db8:2::/64': {
            'dev': 'eth1',
            'proto': 'kernel',
        }
    }
    """
    output = normalize_text(node.run("ip -6 route")).splitlines()
    result = {}
    for line in output:
        columns = line.split(" ")
        route = result[columns[0]] = {}
        prev = None
        for column in columns:
            if prev == "dev":
                route["dev"] = column
            if prev == "via":
                route["via"] = column
            if prev == "proto":
                # translate protocol names back to numbers
                route["proto"] = proto_name_to_number(column)
            if prev == "metric":
                route["metric"] = column
            if prev == "pref":
                route["pref"] = column
            prev = column

    return result


def ip6_vrf_route(node):
    """
    Gets a structured return of the command 'ip -6 route show vrf {0}-cust1'.
    It can be used in conjunction with json_cmp() to provide accurate assert explanations.

    Return example:
    {
        '2001:db8:1::/64': {
            'dev': 'eth0',
            'proto': '188',
        },
        '2001:db8:2::/64': {
            'dev': 'eth1',
            'proto': 'kernel',
        }
    }
    """
    output = normalize_text(
        node.run("ip -6 route show vrf {0}-cust1".format(node.name))
    ).splitlines()
    result = {}
    for line in output:
        columns = line.split(" ")
        route = result[columns[0]] = {}
        prev = None
        for column in columns:
            if prev == "dev":
                route["dev"] = column
            if prev == "via":
                route["via"] = column
            if prev == "proto":
                # translate protocol names back to numbers
                route["proto"] = proto_name_to_number(column)
            if prev == "metric":
                route["metric"] = column
            if prev == "pref":
                route["pref"] = column
            prev = column

    return result


def ip_rules(node):
    """
    Gets a structured return of the command 'ip rule'. It can be used in
    conjunction with json_cmp() to provide accurate assert explanations.

    Return example:
    [
        {
            "pref": "0"
            "from": "all"
        },
        {
            "pref": "32766"
            "from": "all"
        },
        {
            "to": "3.4.5.0/24",
            "iif": "r1-eth2",
            "pref": "304",
            "from": "1.2.0.0/16",
            "proto": "zebra"
        }
    ]
    """
    output = normalize_text(node.run("ip rule")).splitlines()
    result = []
    for line in output:
        columns = line.split(" ")

        route = {}
        # remove last character, since it is ':'
        pref = columns[0][:-1]
        route["pref"] = pref
        prev = None
        for column in columns:
            if prev == "from":
                route["from"] = column
            if prev == "to":
                route["to"] = column
            if prev == "proto":
                route["proto"] = column
            if prev == "iif":
                route["iif"] = column
            if prev == "fwmark":
                route["fwmark"] = column
            prev = column

        result.append(route)
    return result


def sleep(amount, reason=None):
    """
    Sleep wrapper that registers in the log the amount of sleep
    """
    if reason is None:
        logger.info("Sleeping for {} seconds".format(amount))
    else:
        logger.info(reason + " ({} seconds)".format(amount))

    time.sleep(amount)


def checkAddressSanitizerError(output, router, component, logdir=""):
    "Checks for AddressSanitizer in output. If found, then logs it and returns true, false otherwise"

    def processAddressSanitizerError(asanErrorRe, output, router, component):
        sys.stderr.write(
            "%s: %s triggered an exception by AddressSanitizer\n" % (router, component)
        )
        # Sanitizer Error found in log
        pidMark = asanErrorRe.group(1)
        addressSanitizerLog = re.search(
            "%s(.*)%s" % (pidMark, pidMark), output, re.DOTALL
        )
        if addressSanitizerLog:
            # Find Calling Test. Could be multiple steps back
            testframe = list(sys._current_frames().values())[0]
            level = 0
            while level < 10:
                test = os.path.splitext(
                    os.path.basename(testframe.f_globals["__file__"])
                )[0]
                if (test != "topotest") and (test != "topogen"):
                    # Found the calling test
                    callingTest = os.path.basename(testframe.f_globals["__file__"])
                    break
                level = level + 1
                testframe = testframe.f_back
            if level >= 10:
                # somehow couldn't find the test script.
                callingTest = "unknownTest"
            #
            # Now finding Calling Procedure
            level = 0
            while level < 20:
                callingProc = sys._getframe(level).f_code.co_name
                if (
                    (callingProc != "processAddressSanitizerError")
                    and (callingProc != "checkAddressSanitizerError")
                    and (callingProc != "checkRouterCores")
                    and (callingProc != "stopRouter")
                    and (callingProc != "stop")
                    and (callingProc != "stop_topology")
                    and (callingProc != "checkRouterRunning")
                    and (callingProc != "check_router_running")
                    and (callingProc != "routers_have_failure")
                ):
                    # Found the calling test
                    break
                level = level + 1
            if level >= 20:
                # something wrong - couldn't found the calling test function
                callingProc = "unknownProc"
            with open("/tmp/AddressSanitzer.txt", "a") as addrSanFile:
                sys.stderr.write(
                    "AddressSanitizer error in topotest `%s`, test `%s`, router `%s`\n\n"
                    % (callingTest, callingProc, router)
                )
                sys.stderr.write(
                    "\n".join(addressSanitizerLog.group(1).splitlines()) + "\n"
                )
                addrSanFile.write("## Error: %s\n\n" % asanErrorRe.group(2))
                addrSanFile.write(
                    "### AddressSanitizer error in topotest `%s`, test `%s`, router `%s`\n\n"
                    % (callingTest, callingProc, router)
                )
                addrSanFile.write(
                    "    "
                    + "\n    ".join(addressSanitizerLog.group(1).splitlines())
                    + "\n"
                )
                addrSanFile.write("\n---------------\n")
        return

    addressSanitizerError = re.search(
        r"(==[0-9]+==)ERROR: AddressSanitizer: ([^\s]*) ", output
    )
    if addressSanitizerError:
        processAddressSanitizerError(addressSanitizerError, output, router, component)
        return True

    # No Address Sanitizer Error in Output. Now check for AddressSanitizer daemon file
    if logdir:
        filepattern = logdir + "/" + router + ".asan." + component + ".*"
        logger.debug(
            "Log check for %s on %s, pattern %s\n" % (component, router, filepattern)
        )
        for file in glob.glob(filepattern):
            with open(file, "r") as asanErrorFile:
                asanError = asanErrorFile.read()
            addressSanitizerError = re.search(
                r"(==[0-9]+==)ERROR: AddressSanitizer: ([^\s]*) ", asanError
            )
            if addressSanitizerError:
                processAddressSanitizerError(
                    addressSanitizerError, asanError, router, component
                )
                return True
    return False


def _sysctl_atleast(commander, variable, min_value):
    if isinstance(min_value, tuple):
        min_value = list(min_value)
    is_list = isinstance(min_value, list)

    sval = commander.cmd_raises("sysctl -n " + variable).strip()
    if is_list:
        cur_val = [int(x) for x in sval.split()]
    else:
        cur_val = int(sval)

    set_value = False
    if is_list:
        for i, v in enumerate(cur_val):
            if v < min_value[i]:
                set_value = True
            else:
                min_value[i] = v
    else:
        if cur_val < min_value:
            set_value = True
    if set_value:
        if is_list:
            valstr = " ".join([str(x) for x in min_value])
        else:
            valstr = str(min_value)
        logger.debug("Increasing sysctl %s from %s to %s", variable, cur_val, valstr)
        commander.cmd_raises('sysctl -w {}="{}"'.format(variable, valstr))


def _sysctl_assure(commander, variable, value):
    if isinstance(value, tuple):
        value = list(value)
    is_list = isinstance(value, list)

    sval = commander.cmd_raises("sysctl -n " + variable).strip()
    if is_list:
        cur_val = [int(x) for x in sval.split()]
    else:
        cur_val = sval

    set_value = False
    if is_list:
        for i, v in enumerate(cur_val):
            if v != value[i]:
                set_value = True
            else:
                value[i] = v
    else:
        if cur_val != str(value):
            set_value = True

    if set_value:
        if is_list:
            valstr = " ".join([str(x) for x in value])
        else:
            valstr = str(value)
        logger.debug("Changing sysctl %s from %s to %s", variable, cur_val, valstr)
        commander.cmd_raises('sysctl -w {}="{}"\n'.format(variable, valstr))


def sysctl_atleast(commander, variable, min_value, raises=False):
    try:
        if commander is None:
            topotest_logger = logging.getLogger("topotest")
            commander = micronet.Commander("sysctl", logger=topotest_logger)

        return _sysctl_atleast(commander, variable, min_value)
    except subprocess.CalledProcessError as error:
        logger.warning(
            "%s: Failed to assure sysctl min value %s = %s",
            commander,
            variable,
            min_value,
        )
        if raises:
            raise


def sysctl_assure(commander, variable, value, raises=False):
    try:
        if commander is None:
            topotest_logger = logging.getLogger("topotest")
            commander = micronet.Commander("sysctl", logger=topotest_logger)
        return _sysctl_assure(commander, variable, value)
    except subprocess.CalledProcessError as error:
        logger.warning(
            "%s: Failed to assure sysctl value %s = %s",
            commander,
            variable,
            value,
            exc_info=True,
        )
        if raises:
            raise


def rlimit_atleast(rname, min_value, raises=False):
    try:
        cval = resource.getrlimit(rname)
        soft, hard = cval
        if soft < min_value:
            nval = (min_value, hard if min_value < hard else min_value)
            logger.debug("Increasing rlimit %s from %s to %s", rname, cval, nval)
            resource.setrlimit(rname, nval)
    except subprocess.CalledProcessError as error:
        logger.warning(
            "Failed to assure rlimit [%s] = %s", rname, min_value, exc_info=True
        )
        if raises:
            raise


def fix_netns_limits(ns):
    # Maximum read and write socket buffer sizes
    sysctl_atleast(ns, "net.ipv4.tcp_rmem", [10 * 1024, 87380, 16 * 2**20])
    sysctl_atleast(ns, "net.ipv4.tcp_wmem", [10 * 1024, 87380, 16 * 2**20])

    sysctl_assure(ns, "net.ipv4.conf.all.rp_filter", 0)
    sysctl_assure(ns, "net.ipv4.conf.default.rp_filter", 0)
    sysctl_assure(ns, "net.ipv4.conf.lo.rp_filter", 0)

    sysctl_assure(ns, "net.ipv4.conf.all.forwarding", 1)
    sysctl_assure(ns, "net.ipv4.conf.default.forwarding", 1)

    # XXX if things fail look here as this wasn't done previously
    sysctl_assure(ns, "net.ipv6.conf.all.forwarding", 1)
    sysctl_assure(ns, "net.ipv6.conf.default.forwarding", 1)

    # ARP
    sysctl_assure(ns, "net.ipv4.conf.default.arp_announce", 2)
    sysctl_assure(ns, "net.ipv4.conf.default.arp_notify", 1)
    # Setting this to 1 breaks topotests that rely on lo addresses being proxy arp'd for
    sysctl_assure(ns, "net.ipv4.conf.default.arp_ignore", 0)
    sysctl_assure(ns, "net.ipv4.conf.all.arp_announce", 2)
    sysctl_assure(ns, "net.ipv4.conf.all.arp_notify", 1)
    # Setting this to 1 breaks topotests that rely on lo addresses being proxy arp'd for
    sysctl_assure(ns, "net.ipv4.conf.all.arp_ignore", 0)

    sysctl_assure(ns, "net.ipv4.icmp_errors_use_inbound_ifaddr", 1)

    # Keep ipv6 permanent addresses on an admin down
    sysctl_assure(ns, "net.ipv6.conf.all.keep_addr_on_down", 1)
    if version_cmp(platform.release(), "4.20") >= 0:
        sysctl_assure(ns, "net.ipv6.route.skip_notify_on_dev_down", 1)

    sysctl_assure(ns, "net.ipv4.conf.all.ignore_routes_with_linkdown", 1)
    sysctl_assure(ns, "net.ipv6.conf.all.ignore_routes_with_linkdown", 1)
    sysctl_assure(ns, "net.ipv4.conf.default.ignore_routes_with_linkdown", 1)
    sysctl_assure(ns, "net.ipv6.conf.default.ignore_routes_with_linkdown", 1)

    # igmp
    sysctl_atleast(ns, "net.ipv4.igmp_max_memberships", 1000)

    # Use neigh information on selection of nexthop for multipath hops
    sysctl_assure(ns, "net.ipv4.fib_multipath_use_neigh", 1)


def fix_host_limits():
    """Increase system limits."""

    rlimit_atleast(resource.RLIMIT_NPROC, 8 * 1024)
    rlimit_atleast(resource.RLIMIT_NOFILE, 16 * 1024)
    sysctl_atleast(None, "fs.file-max", 16 * 1024)
    sysctl_atleast(None, "kernel.pty.max", 16 * 1024)

    # Enable coredumps
    # Original on ubuntu 17.x, but apport won't save as in namespace
    # |/usr/share/apport/apport %p %s %c %d %P
    sysctl_assure(None, "kernel.core_pattern", "%e_core-sig_%s-pid_%p.dmp")
    sysctl_assure(None, "kernel.core_uses_pid", 1)
    sysctl_assure(None, "fs.suid_dumpable", 1)

    # Maximum connection backlog
    sysctl_atleast(None, "net.core.netdev_max_backlog", 4 * 1024)

    # Maximum read and write socket buffer sizes
    sysctl_atleast(None, "net.core.rmem_max", 16 * 2**20)
    sysctl_atleast(None, "net.core.wmem_max", 16 * 2**20)

    # Garbage Collection Settings for ARP and Neighbors
    sysctl_atleast(None, "net.ipv4.neigh.default.gc_thresh2", 4 * 1024)
    sysctl_atleast(None, "net.ipv4.neigh.default.gc_thresh3", 8 * 1024)
    sysctl_atleast(None, "net.ipv6.neigh.default.gc_thresh2", 4 * 1024)
    sysctl_atleast(None, "net.ipv6.neigh.default.gc_thresh3", 8 * 1024)
    # Hold entries for 10 minutes
    sysctl_assure(None, "net.ipv4.neigh.default.base_reachable_time_ms", 10 * 60 * 1000)
    sysctl_assure(None, "net.ipv6.neigh.default.base_reachable_time_ms", 10 * 60 * 1000)

    # igmp
    sysctl_assure(None, "net.ipv4.neigh.default.mcast_solicit", 10)

    # MLD
    sysctl_atleast(None, "net.ipv6.mld_max_msf", 512)

    # Increase routing table size to 128K
    sysctl_atleast(None, "net.ipv4.route.max_size", 128 * 1024)
    sysctl_atleast(None, "net.ipv6.route.max_size", 128 * 1024)


def setup_node_tmpdir(logdir, name):
    # Cleanup old log, valgrind, and core files.
    subprocess.check_call(
        "rm -rf {0}/{1}.valgrind.* {0}/{1}.asan.* {0}/{1}/".format(logdir, name),
        shell=True,
    )

    # Setup the per node directory.
    nodelogdir = "{}/{}".format(logdir, name)
    subprocess.check_call(
        "mkdir -p {0} && chmod 1777 {0}".format(nodelogdir), shell=True
    )
    logfile = "{0}/{1}.log".format(logdir, name)
    return logfile


class Router(Node):
    "A Node with IPv4/IPv6 forwarding enabled"

    gdb_emacs_router = None

    def __init__(self, name, *posargs, **params):
        # Backward compatibility:
        #   Load configuration defaults like topogen.
        self.config_defaults = configparser.ConfigParser(
            defaults={
                "verbosity": "info",
                "frrdir": "/usr/lib/frr",
                "routertype": "frr",
                "memleak_path": "",
            }
        )

        self.config_defaults.read(
            os.path.join(os.path.dirname(os.path.realpath(__file__)), "../pytest.ini")
        )

        self.perf_daemons = {}
        self.rr_daemons = {}
        self.valgrind_gdb_daemons = {}

        # If this topology is using old API and doesn't have logdir
        # specified, then attempt to generate an unique logdir.
        self.logdir = params.get("logdir")
        if self.logdir is None:
            self.logdir = get_logs_path(g_pytest_config.getoption("--rundir"))

        if not params.get("logger"):
            # If logger is present topogen has already set this up
            logfile = setup_node_tmpdir(self.logdir, name)
            l = topolog.get_logger(name, log_level="debug", target=logfile)
            params["logger"] = l

        super(Router, self).__init__(name, *posargs, **params)

        self.daemondir = None
        self.hasmpls = False
        self.routertype = "frr"
        self.unified_config = False
        self.daemons = {
            "zebra": 0,
            "ripd": 0,
            "ripngd": 0,
            "ospfd": 0,
            "ospf6d": 0,
            "isisd": 0,
            "bgpd": 0,
            "pimd": 0,
            "pim6d": 0,
            "ldpd": 0,
            "eigrpd": 0,
            "nhrpd": 0,
            "staticd": 0,
            "bfdd": 0,
            "sharpd": 0,
            "babeld": 0,
            "pbrd": 0,
            "pathd": 0,
            "snmpd": 0,
            "mgmtd": 0,
            "snmptrapd": 0,
            "fpm_listener": 0,
        }
        self.daemons_options = {"zebra": ""}
        self.reportCores = True
        self.version = None

        self.ns_cmd = "sudo nsenter -a -t {} ".format(self.pid)
        try:
            # Allow escaping from running inside docker
            cgroup = open("/proc/1/cgroup").read()
            m = re.search("[0-9]+:cpuset:/docker/([a-f0-9]+)", cgroup)
            if m:
                self.ns_cmd = "docker exec -it {} ".format(m.group(1)) + self.ns_cmd
        except IOError:
            pass
        else:
            logger.debug("CMD to enter {}: {}".format(self.name, self.ns_cmd))

    def _config_frr(self, **params):
        "Configure FRR binaries"
        self.daemondir = params.get("frrdir")
        if self.daemondir is None:
            self.daemondir = self.config_defaults.get("topogen", "frrdir")

        zebra_path = os.path.join(self.daemondir, "zebra")
        if not os.path.isfile(zebra_path):
            raise Exception("FRR zebra binary doesn't exist at {}".format(zebra_path))

        mgmtd_path = os.path.join(self.daemondir, "mgmtd")
        if not os.path.isfile(mgmtd_path):
            raise Exception("FRR MGMTD binary doesn't exist at {}".format(mgmtd_path))

    # pylint: disable=W0221
    # Some params are only meaningful for the parent class.
    def config_host(self, **params):
        super(Router, self).config_host(**params)

        # User did not specify the daemons directory, try to autodetect it.
        self.daemondir = params.get("daemondir")
        if self.daemondir is None:
            self.routertype = params.get(
                "routertype", self.config_defaults.get("topogen", "routertype")
            )
            self._config_frr(**params)
        else:
            # Test the provided path
            zpath = os.path.join(self.daemondir, "zebra")
            if not os.path.isfile(zpath):
                raise Exception("No zebra binary found in {}".format(zpath))

            cpath = os.path.join(self.daemondir, "mgmtd")
            if not os.path.isfile(zpath):
                raise Exception("No MGMTD binary found in {}".format(cpath))
            # Allow user to specify routertype when the path was specified.
            if params.get("routertype") is not None:
                self.routertype = params.get("routertype")

        # Set ownership of config files
        self.cmd("chown {0}:{0}vty /etc/{0}".format(self.routertype))

    def terminate(self):
        # Stop running FRR daemons
        self.stopRouter()
        super(Router, self).terminate()
        os.system("chmod -R go+rw " + self.logdir)

    # Return count of running daemons
    def listDaemons(self):
        ret = []
        rc, stdout, _ = self.cmd_status(
            "ls -1 /var/run/%s/*.pid" % self.routertype, warn=False
        )
        if rc:
            return ret
        for d in stdout.strip().split("\n"):
            pidfile = d.strip()
            try:
                pid = int(self.cmd_raises("cat %s" % pidfile, warn=False).strip())
                name = os.path.basename(pidfile[:-4])

                # probably not compatible with bsd.
                rc, _, _ = self.cmd_status("test -d /proc/{}".format(pid), warn=False)
                if rc:
                    logger.warning(
                        "%s: %s exited leaving pidfile %s (%s)",
                        self.name,
                        name,
                        pidfile,
                        pid,
                    )
                    self.cmd("rm -- " + pidfile)
                else:
                    ret.append((name, pid))
            except (subprocess.CalledProcessError, ValueError):
                pass
        return ret

    def stopRouter(self, assertOnError=True):
        # Stop Running FRR Daemons
        running = self.listDaemons()
        if not running:
            return ""

        logger.info("%s: stopping %s", self.name, ", ".join([x[0] for x in running]))
        for name, pid in running:
            logger.debug("{}: sending SIGTERM to {}".format(self.name, name))
            try:
                os.kill(pid, signal.SIGTERM)
            except OSError as err:
                logger.debug(
                    "%s: could not kill %s (%s): %s", self.name, name, pid, str(err)
                )

        running = self.listDaemons()
        if running:
            for _ in range(0, 30):
                sleep(
                    0.5,
                    "{}: waiting for daemons stopping: {}".format(
                        self.name, ", ".join([x[0] for x in running])
                    ),
                )
                running = self.listDaemons()
                if not running:
                    break

        if running:
            logger.warning(
                "%s: sending SIGBUS to: %s",
                self.name,
                ", ".join([x[0] for x in running]),
            )
            for name, pid in running:
                pidfile = "/var/run/{}/{}.pid".format(self.routertype, name)
                logger.info("%s: killing %s", self.name, name)
                self.cmd("kill -SIGBUS %d" % pid)
                self.cmd("rm -- " + pidfile)

            sleep(
                0.5,
                "%s: waiting for daemons to exit/core after initial SIGBUS" % self.name,
            )

        errors = self.checkRouterCores(reportOnce=True)
        if assertOnError and (errors is not None) and len(errors) > 0:
            assert "Errors found - details follow:" == 0, errors
        return errors

    def removeIPs(self):
        for interface in self.intfNames():
            try:
                self.intf_ip_cmd(interface, "ip -4 address flush " + interface)
                self.intf_ip_cmd(
                    interface, "ip -6 address flush " + interface + " scope global"
                )
            except Exception as ex:
                logger.error("%s can't remove IPs %s", self, str(ex))
                # breakpoint()
                # assert False, "can't remove IPs %s" % str(ex)

    def checkCapability(self, daemon, param):
        if param is not None:
            daemon_path = os.path.join(self.daemondir, daemon)
            daemon_search_option = param.replace("-", "")
            output = self.cmd(
                "{0} -h | grep {1}".format(daemon_path, daemon_search_option)
            )
            if daemon_search_option not in output:
                return False
        return True

    def loadConf(self, daemon, source=None, param=None):
        """Enabled and set config for a daemon.

        Arranges for loading of daemon configuration from the specified source. Possible
        `source` values are `None` for an empty config file, a path name which is used
        directly, or a file name with no path components which is first looked for
        directly and then looked for under a sub-directory named after router.
        """

        # Unfortunately this API allowsfor source to not exist for any and all routers.
        source_was_none = source is None
        if source_was_none:
            source = f"{daemon}.conf"

        # "" to avoid loading a default config which is present in router dir
        if source:
            head, tail = os.path.split(source)
            if not head and not self.path_exists(tail):
                script_dir = os.environ["PYTEST_TOPOTEST_SCRIPTDIR"]
                router_relative = os.path.join(script_dir, self.name, tail)
                if self.path_exists(router_relative):
                    source = router_relative
                    self.logger.debug(
                        "using router relative configuration: {}".format(source)
                    )

        # print "Daemons before:", self.daemons
        if daemon in self.daemons.keys() or daemon == "frr":
            if daemon == "frr":
                self.unified_config = True
            else:
                self.daemons[daemon] = 1
            if param is not None:
                self.daemons_options[daemon] = param
            conf_file = "/etc/{}/{}.conf".format(self.routertype, daemon)
            if source and not os.path.exists(source):
                logger.warning(
                    "missing config '%s' for '%s' creating empty file '%s'",
                    self.name,
                    source,
                    conf_file,
                )
                if daemon == "frr" or not self.unified_config:
                    self.cmd_raises("rm -f " + conf_file)
                    self.cmd_raises("touch " + conf_file)
                    self.cmd_raises(
                        "chown {0}:{0} {1}".format(self.routertype, conf_file)
                    )
                    self.cmd_raises("chmod 664 {}".format(conf_file))
            elif source:
                # copy zebra.conf to mgmtd folder, which can be used during startup
                if daemon == "zebra" and not self.unified_config:
                    conf_file_mgmt = "/etc/{}/{}.conf".format(self.routertype, "mgmtd")
                    logger.debug(
                        "copying '%s' as '%s' on '%s'",
                        source,
                        conf_file_mgmt,
                        self.name,
                    )
                    self.cmd_raises("cp {} {}".format(source, conf_file_mgmt))
                    self.cmd_raises(
                        "chown {0}:{0} {1}".format(self.routertype, conf_file_mgmt)
                    )
                    self.cmd_raises("chmod 664 {}".format(conf_file_mgmt))

                logger.debug(
                    "copying '%s' as '%s' on '%s'", source, conf_file, self.name
                )
                self.cmd_raises("cp {} {}".format(source, conf_file))
                self.cmd_raises("chown {0}:{0} {1}".format(self.routertype, conf_file))
                self.cmd_raises("chmod 664 {}".format(conf_file))

            if (daemon == "snmpd") and (self.routertype == "frr"):
                # /etc/snmp is private mount now
                self.cmd('echo "agentXSocket /etc/frr/agentx" >> /etc/snmp/frr.conf')
                self.cmd('echo "mibs +ALL" > /etc/snmp/snmp.conf')

            if (daemon == "zebra") and (self.daemons["mgmtd"] == 0):
                # Add mgmtd with zebra - if it exists
                mgmtd_path = os.path.join(self.daemondir, "mgmtd")
                if os.path.isfile(mgmtd_path):
                    self.daemons["mgmtd"] = 1
                    self.daemons_options["mgmtd"] = ""
                    # Auto-Started mgmtd has no config, so it will read from zebra config

            if (daemon == "zebra") and (self.daemons["staticd"] == 0):
                # Add staticd with zebra - if it exists
                staticd_path = os.path.join(self.daemondir, "staticd")
                if os.path.isfile(staticd_path):
                    self.daemons["staticd"] = 1
                    self.daemons_options["staticd"] = ""
                    # Auto-Started staticd has no config, so it will read from zebra config

        else:
            logger.warning("No daemon {} known".format(daemon))

        return source if os.path.exists(source) else ""

    def runInWindow(self, cmd, title=None):
        return self.run_in_window(cmd, title)

    def startRouter(self, tgen=None):
        if self.unified_config:
            self.cmd(
                'echo "service integrated-vtysh-config" >> /etc/%s/vtysh.conf'
                % self.routertype
            )
        else:
            # Disable integrated-vtysh-config
            self.cmd(
                'echo "no service integrated-vtysh-config" >> /etc/%s/vtysh.conf'
                % self.routertype
            )

        self.cmd(
            "chown %s:%svty /etc/%s/vtysh.conf"
            % (self.routertype, self.routertype, self.routertype)
        )
        # TODO remove the following lines after all tests are migrated to Topogen.
        # Try to find relevant old logfiles in /tmp and delete them
        map(os.remove, glob.glob("{}/{}/*.log".format(self.logdir, self.name)))
        # Remove IP addresses from OS first - we have them in zebra.conf
        self.removeIPs()
        # If ldp is used, check for LDP to be compiled and Linux Kernel to be 4.5 or higher
        # No error - but return message and skip all the tests
        if self.daemons["ldpd"] == 1:
            ldpd_path = os.path.join(self.daemondir, "ldpd")
            if not os.path.isfile(ldpd_path):
                logger.info("LDP Test, but no ldpd compiled or installed")
                return "LDP Test, but no ldpd compiled or installed"

            if version_cmp(platform.release(), "4.5") < 0:
                logger.info("LDP Test need Linux Kernel 4.5 minimum")
                return "LDP Test need Linux Kernel 4.5 minimum"
            # Check if have mpls
            if tgen != None:
                self.hasmpls = tgen.hasmpls
                if self.hasmpls != True:
                    logger.info(
                        "LDP/MPLS Tests will be skipped, platform missing module(s)"
                    )
            else:
                # Test for MPLS Kernel modules available
                self.hasmpls = False
                if not module_present("mpls-router"):
                    logger.info(
                        "MPLS tests will not run (missing mpls-router kernel module)"
                    )
                elif not module_present("mpls-iptunnel"):
                    logger.info(
                        "MPLS tests will not run (missing mpls-iptunnel kernel module)"
                    )
                else:
                    self.hasmpls = True
            if self.hasmpls != True:
                return "LDP/MPLS Tests need mpls kernel modules"

        # Really want to use sysctl_atleast here, but only when MPLS is actually being
        # used
        self.cmd("echo 100000 > /proc/sys/net/mpls/platform_labels")

        if g_pytest_config.name_in_option_list(self.name, "--shell"):
            self.run_in_window(os.getenv("SHELL", "bash"), title="sh-%s" % self.name)

        if self.daemons["eigrpd"] == 1:
            eigrpd_path = os.path.join(self.daemondir, "eigrpd")
            if not os.path.isfile(eigrpd_path):
                logger.info("EIGRP Test, but no eigrpd compiled or installed")
                return "EIGRP Test, but no eigrpd compiled or installed"

        if self.daemons["bfdd"] == 1:
            bfdd_path = os.path.join(self.daemondir, "bfdd")
            if not os.path.isfile(bfdd_path):
                logger.info("BFD Test, but no bfdd compiled or installed")
                return "BFD Test, but no bfdd compiled or installed"

        status = self.startRouterDaemons(tgen=tgen)

        if g_pytest_config.name_in_option_list(self.name, "--vtysh"):
            self.run_in_window("vtysh", title="vt-%s" % self.name)

        if self.unified_config:
            self.cmd("vtysh -f /etc/frr/frr.conf")

        return status

    def getStdErr(self, daemon):
        return self.getLog("err", daemon)

    def getStdOut(self, daemon):
        return self.getLog("out", daemon)

    def getLog(self, log, daemon):
        filename = "{}/{}/{}.{}".format(self.logdir, self.name, daemon, log)
        log = ""
        with open(filename) as file:
            log = file.read()
        return log

    def startRouterDaemons(self, daemons=None, tgen=None):
        "Starts FRR daemons for this router."

        asan_abort = bool(g_pytest_config.option.asan_abort)
        cov_option = bool(g_pytest_config.option.cov_topotest)
        cov_dir = Path(g_pytest_config.option.rundir) / "gcda"
        gdb_breakpoints = g_pytest_config.get_option_list("--gdb-breakpoints")
        gdb_daemons = g_pytest_config.get_option_list("--gdb-daemons")
        gdb_routers = g_pytest_config.get_option_list("--gdb-routers")
        gdb_use_emacs = bool(g_pytest_config.option.gdb_use_emacs)
        rr_daemons = g_pytest_config.get_option_list("--rr-daemons")
        rr_routers = g_pytest_config.get_option_list("--rr-routers")
        rr_options = g_pytest_config.get_option("--rr-options", "")
        valgrind_extra = bool(g_pytest_config.option.valgrind_extra)
        valgrind_leak_kinds = g_pytest_config.option.valgrind_leak_kinds
        valgrind_memleaks = bool(g_pytest_config.option.valgrind_memleaks)
        strace_daemons = g_pytest_config.get_option_list("--strace-daemons")

        # Get global bundle data
        if not self.path_exists("/etc/frr/support_bundle_commands.conf"):
            # Copy global value if was covered by namespace mount
            bundle_data = ""
            if os.path.exists("/etc/frr/support_bundle_commands.conf"):
                with open("/etc/frr/support_bundle_commands.conf", "r") as rf:
                    bundle_data = rf.read()
            self.cmd_raises(
                "cat > /etc/frr/support_bundle_commands.conf",
                stdin=bundle_data,
            )

        # Starts actual daemons without init (ie restart)
        # cd to per node directory
        self.cmd("install -m 775 -o frr -g frr -d {}/{}".format(self.logdir, self.name))
        self.set_cwd("{}/{}".format(self.logdir, self.name))
        self.cmd("umask 000")

        # Re-enable to allow for report per run
        self.reportCores = True

        perfds = {}
        perf_options = g_pytest_config.get_option("--perf-options", "-g")
        for perf in g_pytest_config.get_option("--perf", []):
            if "," in perf:
                daemon, routers = perf.split(",", 1)
                perfds[daemon] = routers.split(",")
            else:
                daemon = perf
                perfds[daemon] = ["all"]

        logd_options = {}
        for logd in g_pytest_config.get_option("--logd", []):
            if "," in logd:
                daemon, routers = logd.split(",", 1)
                logd_options[daemon] = routers.split(",")
            else:
                daemon = logd
                logd_options[daemon] = ["all"]

        # If `daemons` was specified then some upper API called us with
        # specific daemons, otherwise just use our own configuration.
        daemons_list = []
        if daemons is not None:
            daemons_list = daemons
        else:
            # Append all daemons configured.
            for daemon in self.daemons:
                if self.daemons[daemon] == 1:
                    daemons_list.append(daemon)

        tail_log_files = []
        check_daemon_files = []

        def start_daemon(daemon):
            daemon_opts = self.daemons_options.get(daemon, "")

            # get pid and vty filenames and remove the files
            m = re.match(r"(.* |^)-n (\d+)( ?.*|$)", daemon_opts)
            dfname = daemon if not m else "{}-{}".format(daemon, m.group(2))
            runbase = "/var/run/{}/{}".format(self.routertype, dfname)
            # If this is a new system bring-up remove the pid/vty files, otherwise
            # do not since apparently presence of the pidfile impacts BGP GR
            self.cmd_status("rm -f {0}.pid {0}.vty".format(runbase))

            def do_gdb_or_rr(gdb):
                routers = gdb_routers if gdb else rr_routers
                daemons = gdb_daemons if gdb else rr_daemons
                return (
                    (routers or daemons)
                    and (not routers or self.name in routers or "all" in routers)
                    and (not daemons or daemon in daemons or "all" in daemons)
                )

            rediropt = " > {0}.out 2> {0}.err".format(daemon)
            if daemon == "fpm_listener":
                binary = "/usr/lib/frr/fpm_listener"
                cmdenv = ""
                cmdopt = "-d {}".format(daemon_opts)
            elif daemon == "snmpd":
                binary = "/usr/sbin/snmpd"
                cmdenv = ""
                cmdopt = "{} -C -c /etc/frr/snmpd.conf -p ".format(
                    daemon_opts
                ) + "{}.pid -x /etc/frr/agentx".format(runbase)
                # check_daemon_files.append(runbase + ".pid")
            elif daemon == "snmptrapd":
                binary = "/usr/sbin/snmptrapd"
                cmdenv = ""
                cmdopt = (
                    "{} ".format(daemon_opts)
                    + "-C -c /etc/{}/snmptrapd.conf".format(self.routertype)
                    + " -p {}.pid".format(runbase)
                    + " -LF 6-7 {}/{}/snmptrapd.log".format(self.logdir, self.name)
                )
            else:
                binary = os.path.join(self.daemondir, daemon)
                check_daemon_files.extend([runbase + ".pid", runbase + ".vty"])

                cmdenv = "ASAN_OPTIONS="
                if asan_abort:
                    cmdenv += "abort_on_error=1:"
                cmdenv += "log_path={0}/{1}.asan.{2} ".format(
                    self.logdir, self.name, daemon
                )

                if cov_option:
                    scount = os.environ["GCOV_PREFIX_STRIP"]
                    cmdenv += f"GCOV_PREFIX_STRIP={scount} GCOV_PREFIX={cov_dir}"

                if valgrind_memleaks:
                    this_dir = os.path.dirname(
                        os.path.abspath(os.path.realpath(__file__))
                    )
                    supp_file = os.path.abspath(
                        os.path.join(this_dir, "../../../tools/valgrind.supp")
                    )

                    valgrind_logbase = f"{self.logdir}/{self.name}.valgrind.{daemon}"
                    if do_gdb_or_rr(True):
                        cmdenv += " exec"
                    cmdenv += (
                        " /usr/bin/valgrind --num-callers=50"
                        f" --log-file={valgrind_logbase}.%p"
                        f" --leak-check=full --suppressions={supp_file}"
                    )
                    if valgrind_leak_kinds:
                        cmdenv += f" --show-leak-kinds={valgrind_leak_kinds}"
                    if valgrind_extra:
                        cmdenv += (
                            " --gen-suppressions=all --expensive-definedness-checks=yes"
                        )
                    if do_gdb_or_rr(True):
                        cmdenv += " --vgdb-error=0"
                elif daemon in strace_daemons or "all" in strace_daemons:
                    cmdenv = "strace -f -D -o {1}/{2}.strace.{0} ".format(
                        daemon, self.logdir, self.name
                    )

                cmdopt = "{} --command-log-always ".format(daemon_opts)
                cmdopt += "--log file:{}.log --log-level debug".format(daemon)

                if daemon in logd_options:
                    logdopt = logd_options[daemon]
                    if "all" in logdopt or self.name in logdopt:
                        tail_log_files.append(
                            "{}/{}/{}.log".format(self.logdir, self.name, daemon)
                        )

            if do_gdb_or_rr(True) and do_gdb_or_rr(False):
                logger.warning("cant' use gdb and rr at same time")

            if (
                not gdb_use_emacs or Router.gdb_emacs_router or valgrind_memleaks
            ) and do_gdb_or_rr(True):
                if Router.gdb_emacs_router is not None:
                    logger.warning(
                        "--gdb-use-emacs can only run a single router and daemon, using"
                        " new window"
                    )

                if daemon == "snmpd":
                    cmdopt += " -f "

                cmdopt += rediropt
                gdbcmd = "sudo -E gdb " + binary
                if gdb_breakpoints:
                    gdbcmd += " -ex 'set breakpoint pending on'"
                for bp in gdb_breakpoints:
                    gdbcmd += " -ex 'b {}'".format(bp)

                if not valgrind_memleaks:
                    gdbcmd += " -ex 'run {}'".format(cmdopt)
                    self.run_in_window(gdbcmd, daemon)

                    logger.info(
                        "%s: %s %s launched in gdb window",
                        self,
                        self.routertype,
                        daemon,
                    )

                else:
                    cmd = " ".join([cmdenv, binary, cmdopt])
                    p = self.popen(cmd)
                    self.valgrind_gdb_daemons[daemon] = p
                    if p.poll() and p.returncode:
                        self.logger.error(
                            '%s: Failed to launch "%s" (%s) with perf using: %s',
                            self,
                            daemon,
                            p.returncode,
                            cmd,
                        )
                        assert False, "Faled to launch valgrind with gdb"
                    logger.debug(
                        "%s: %s %s started with perf", self, self.routertype, daemon
                    )
                    # Now read the erorr log file until we ae given launch priority
                    timeout = Timeout(30)
                    vpid = None
                    for remaining in timeout:
                        try:
                            fname = f"{valgrind_logbase}.{p.pid}"
                            logging.info("Checking %s for valgrind launch info", fname)
                            o = open(fname, encoding="ascii").read()
                        except FileNotFoundError:
                            logging.info("%s not present yet", fname)
                        else:
                            m = re.search(r"target remote \| (.*vgdb) --pid=(\d+)", o)
                            if m:
                                vgdb_cmd = m.group(0)
                                break
                        time.sleep(1)
                    else:
                        assert False, "Faled to get launch info for valgrind with gdb"

                    gdbcmd += f" -ex '{vgdb_cmd}'"
                    gdbcmd += " -ex 'c'"
                    self.run_in_window(gdbcmd, daemon)

                    logger.info(
                        "%s: %s %s launched in gdb window",
                        self,
                        self.routertype,
                        daemon,
                    )
            elif gdb_use_emacs and do_gdb_or_rr(True):
                assert Router.gdb_emacs_router is None
                Router.gdb_emacs_router = self

                assert not valgrind_memleaks, "vagrind gdb in emacs not supported yet"

                if daemon == "snmpd":
                    cmdopt += " -f "
                cmdopt += rediropt

                sudo_path = get_exec_path_host("sudo")
                ecbin = [
                    sudo_path,
                    "-Eu",
                    os.environ["SUDO_USER"],
                    get_exec_path_host("emacsclient"),
                ]
                pre_cmd = self._get_pre_cmd(True, False, ns_only=True, root_level=True)
                # why fail:? gdb -i=mi -iex='set debuginfod enabled off' {binary} "
                gdbcmd = f"{sudo_path} {pre_cmd} gdb -i=mi {binary} "

                commander.cmd_raises(
                    ecbin
                    + [
                        "--eval",
                        f'(gdb "{gdbcmd}"))',
                    ]
                )

                elcheck = (
                    '(ignore-errors (with-current-buffer "*gud-nsenter*"'
                    " (and (string-match-p"
                    ' "(gdb) "'
                    " (buffer-substring-no-properties "
                    '  (- (point-max) 10) (point-max))) "ready")))'
                )

                @retry(10)
                def emacs_gdb_ready():
                    check = commander.cmd_nostatus(ecbin + ["--eval", elcheck])
                    return None if "ready" in check else False

                emacs_gdb_ready()

                # target gdb commands
                cmd = "set breakpoint pending on"
                self.cmd_raises(
                    ecbin
                    + [
                        "--eval",
                        f'(gud-gdb-run-command-fetch-lines "{cmd}" "*gud-gdb*")',
                    ]
                )
                # gdb breakpoints
                for bp in gdb_breakpoints:
                    self.cmd_raises(
                        ecbin
                        + [
                            "--eval",
                            f'(gud-gdb-run-command-fetch-lines "br {bp}" "*gud-gdb*")',
                        ]
                    )

                self.cmd_raises(
                    ecbin
                    + [
                        "--eval",
                        f'(gud-gdb-run-command-fetch-lines "run {cmdopt}" "*gud-gdb*")',
                    ]
                )

                logger.info(
                    "%s: %s %s launched in gdb window", self, self.routertype, daemon
                )
            elif daemon in perfds and (
                self.name in perfds[daemon] or "all" in perfds[daemon]
            ):
                cmdopt += rediropt
                cmd = " ".join(
                    ["perf record {} --".format(perf_options), binary, cmdopt]
                )
                p = self.popen(cmd)
                self.perf_daemons[daemon] = p
                if p.poll() and p.returncode:
                    self.logger.error(
                        '%s: Failed to launch "%s" (%s) with perf using: %s',
                        self,
                        daemon,
                        p.returncode,
                        cmd,
                    )
                else:
                    logger.debug(
                        "%s: %s %s started with perf", self, self.routertype, daemon
                    )
            elif do_gdb_or_rr(False):
                cmdopt += rediropt
                cmd = " ".join(
                    [
                        "rr record -o {} {} --".format(self.rundir / "rr", rr_options),
                        binary,
                        cmdopt,
                    ]
                )
                p = self.popen(cmd)
                self.rr_daemons[daemon] = p
                if p.poll() and p.returncode:
                    self.logger.error(
                        '%s: Failed to launch "%s" (%s) with rr using: %s',
                        self,
                        daemon,
                        p.returncode,
                        cmd,
                    )
                else:
                    logger.debug(
                        "%s: %s %s started with rr", self, self.routertype, daemon
                    )
            else:
                if (
                    daemon != "snmpd"
                    and daemon != "snmptrapd"
                    and daemon != "fpm_listener"
                ):
                    cmdopt += " -d "
                cmdopt += rediropt

                try:
                    self.cmd_raises(" ".join([cmdenv, binary, cmdopt]), warn=False)
                except subprocess.CalledProcessError as error:
                    self.logger.error(
                        '%s: Failed to launch "%s" daemon (%d) using: %s%s%s:',
                        self,
                        daemon,
                        error.returncode,
                        error.cmd,
                        (
                            '\n:stdout: "{}"'.format(error.stdout.strip())
                            if error.stdout
                            else ""
                        ),
                        (
                            '\n:stderr: "{}"'.format(error.stderr.strip())
                            if error.stderr
                            else ""
                        ),
                    )
                else:
                    logger.debug("%s: %s %s started", self, self.routertype, daemon)

        # Start mgmtd first
        if "mgmtd" in daemons_list:
            start_daemon("mgmtd")
            while "mgmtd" in daemons_list:
                daemons_list.remove("mgmtd")

        # Start Zebra after mgmtd
        if "zebra" in daemons_list:
            start_daemon("zebra")
            while "zebra" in daemons_list:
                daemons_list.remove("zebra")

        # Start staticd next if required
        if "staticd" in daemons_list:
            start_daemon("staticd")
            while "staticd" in daemons_list:
                daemons_list.remove("staticd")

        if "snmpd" in daemons_list:
            # Give zerbra a chance to configure interface addresses that snmpd daemon
            # may then use.
            time.sleep(2)

            start_daemon("snmpd")
            while "snmpd" in daemons_list:
                daemons_list.remove("snmpd")

        if "fpm_listener" in daemons_list:
            start_daemon("fpm_listener")
            while "fpm_listener" in daemons_list:
                daemons_list.remove("fpm_listener")

        # Now start all the other daemons
        for daemon in daemons_list:
            if self.daemons[daemon] == 0:
                continue
            start_daemon(daemon)

        # Check if daemons are running.
        wait_time = 30 if (gdb_routers or gdb_daemons) else 10
        timeout = Timeout(wait_time)
        for remaining in timeout:
            if not check_daemon_files:
                break
            check = check_daemon_files[0]
            if self.path_exists(check):
                check_daemon_files.pop(0)
                continue
            self.logger.debug("Waiting {}s for {} to appear".format(remaining, check))
            time.sleep(0.5)

        if check_daemon_files:
            assert False, "Timeout({}) waiting for {} to appear on {}".format(
                wait_time, check_daemon_files[0], self.name
            )

        # Update the permissions on the log files
        self.cmd("chown frr:frr -R {}/{}".format(self.logdir, self.name))
        self.cmd("chmod ug+rwX,o+r -R {}/{}".format(self.logdir, self.name))

        if "frr" in logd_options:
            logdopt = logd_options["frr"]
            if "all" in logdopt or self.name in logdopt:
                tail_log_files.append("{}/{}/frr.log".format(self.logdir, self.name))

        for tailf in tail_log_files:
            self.run_in_window("tail -n10000 -F " + tailf, title=tailf, background=True)

        return ""

    def pid_exists(self, pid):
        if pid <= 0:
            return False
        try:
            # If we are not using PID namespaces then we will be a parent of the pid,
            # otherwise the init process of the PID namespace will have reaped the proc.
            os.waitpid(pid, os.WNOHANG)
        except Exception:
            pass

        rc, o, e = self.cmd_status("kill -0 " + str(pid), warn=False)
        return rc == 0 or "No such process" not in e

    def killRouterDaemons(self, daemons, wait=True, assertOnError=True):
        # Kill Running FRR
        # Daemons(user specified daemon only) using SIGKILL
        rundaemons = self.cmd("ls -1 /var/run/%s/*.pid" % self.routertype)
        errors = ""
        daemonsNotRunning = []
        if re.search(r"No such file or directory", rundaemons):
            return errors
        for daemon in daemons:
            if rundaemons is not None and daemon in rundaemons:
                numRunning = 0
                dmns = rundaemons.split("\n")
                # Exclude empty string at end of list
                for d in dmns[:-1]:
                    if re.search(r"%s" % daemon, d):
                        daemonpidfile = d.rstrip()
                        daemonpid = self.cmd("cat %s" % daemonpidfile).rstrip()
                        if daemonpid.isdigit() and self.pid_exists(int(daemonpid)):
                            logger.debug(
                                "{}: killing {}".format(
                                    self.name,
                                    os.path.basename(daemonpidfile.rsplit(".", 1)[0]),
                                )
                            )
                            self.cmd_status("kill -KILL {}".format(daemonpid))
                            if self.pid_exists(int(daemonpid)):
                                numRunning += 1
                        while wait and numRunning > 0:
                            sleep(
                                2,
                                "{}: waiting for {} daemon to be stopped".format(
                                    self.name, daemon
                                ),
                            )

                            # 2nd round of kill if daemons didn't exit
                            for d in dmns[:-1]:
                                if re.search(r"%s" % daemon, d):
                                    daemonpid = self.cmd("cat %s" % d.rstrip()).rstrip()
                                    if daemonpid.isdigit() and self.pid_exists(
                                        int(daemonpid)
                                    ):
                                        logger.info(
                                            "{}: killing {}".format(
                                                self.name,
                                                os.path.basename(
                                                    d.rstrip().rsplit(".", 1)[0]
                                                ),
                                            )
                                        )
                                        self.cmd_status(
                                            "kill -KILL {}".format(daemonpid)
                                        )
                                    if daemonpid.isdigit() and not self.pid_exists(
                                        int(daemonpid)
                                    ):
                                        numRunning -= 1
                        self.cmd("rm -- {}".format(daemonpidfile))
                    if wait:
                        errors = self.checkRouterCores(reportOnce=True)
                        if assertOnError and len(errors) > 0:
                            assert "Errors found - details follow:" == 0, errors
            else:
                daemonsNotRunning.append(daemon)
        if len(daemonsNotRunning) > 0:
            errors = errors + "Daemons are not running", daemonsNotRunning

        return errors

    def checkRouterCores(self, reportLeaks=True, reportOnce=False):
        if reportOnce and not self.reportCores:
            return
        reportMade = False
        traces = ""
        for daemon in self.daemons:
            if self.daemons[daemon] == 1:
                # Look for core file
                corefiles = glob.glob(
                    "{}/{}/{}_core*.dmp".format(self.logdir, self.name, daemon)
                )
                if len(corefiles) > 0:
                    backtrace = gdb_core(self, daemon, corefiles)
                    traces = (
                        traces
                        + f"\nCORE FOUND: {self.name}: {daemon} crashed. Backtrace follows:\n{backtrace}"
                    )
                    reportMade = True
                elif reportLeaks:
                    log = self.getStdErr(daemon)
                    if "memstats" in log:
                        sys.stderr.write(
                            "%s: %s has memory leaks:\n" % (self.name, daemon)
                        )
                        traces = traces + "\n%s: %s has memory leaks:\n" % (
                            self.name,
                            daemon,
                        )
                        log = re.sub("core_handler: ", "", log)
                        log = re.sub(
                            r"(showing active allocations in memory group [a-zA-Z0-9]+)",
                            r"\n  ## \1",
                            log,
                        )
                        log = re.sub("memstats:  ", "    ", log)
                        sys.stderr.write(log)
                        reportMade = True
                # Look for AddressSanitizer Errors and append to /tmp/AddressSanitzer.txt if found
                if checkAddressSanitizerError(
                    self.getStdErr(daemon), self.name, daemon, self.logdir
                ):
                    sys.stderr.write(
                        "%s: Daemon %s killed by AddressSanitizer" % (self.name, daemon)
                    )
                    traces = traces + "\n%s: Daemon %s killed by AddressSanitizer" % (
                        self.name,
                        daemon,
                    )
                    reportMade = True
        if reportMade:
            self.reportCores = False
        return traces

    def checkRouterRunning(self):
        "Check if router daemons are running and collect crashinfo they don't run"

        global fatal_error

        daemonsRunning = self.cmd(
            'vtysh -c "show logging" | grep "Logging configuration for"'
        )
        # Look for AddressSanitizer Errors in vtysh output and append to /tmp/AddressSanitzer.txt if found
        if checkAddressSanitizerError(daemonsRunning, self.name, "vtysh"):
            return "%s: vtysh killed by AddressSanitizer" % (self.name)

        for daemon in self.daemons:
            if daemon == "snmpd":
                continue
            if daemon == "snmptrapd":
                continue
            if daemon == "fpm_listener":
                continue
            if (self.daemons[daemon] == 1) and not (daemon in daemonsRunning):
                sys.stderr.write("%s: Daemon %s not running\n" % (self.name, daemon))
                if daemon == "staticd":
                    sys.stderr.write(
                        "You may have a copy of staticd installed but are attempting to test against\n"
                    )
                    sys.stderr.write(
                        "a version of FRR that does not have staticd, please cleanup the install dir\n"
                    )

                # Look for core file
                corefiles = glob.glob(
                    "{}/{}/{}_core*.dmp".format(self.logdir, self.name, daemon)
                )
                if len(corefiles) > 0:
                    gdb_core(self, daemon, corefiles)
                else:
                    # No core found - If we find matching logfile in /tmp, then print last 20 lines from it.
                    if os.path.isfile(
                        "{}/{}/{}.log".format(self.logdir, self.name, daemon)
                    ):
                        log_tail = subprocess.check_output(
                            [
                                "tail -n20 {}/{}/{}.log 2> /dev/null".format(
                                    self.logdir, self.name, daemon
                                )
                            ],
                            shell=True,
                        )
                        sys.stderr.write(
                            "\nFrom %s %s %s log file:\n"
                            % (self.routertype, self.name, daemon)
                        )
                        sys.stderr.write("%s\n" % log_tail)

                # Look for AddressSanitizer Errors and append to /tmp/AddressSanitzer.txt if found
                if checkAddressSanitizerError(
                    self.getStdErr(daemon), self.name, daemon, self.logdir
                ):
                    return "%s: Daemon %s not running - killed by AddressSanitizer" % (
                        self.name,
                        daemon,
                    )

                return "%s: Daemon %s not running" % (self.name, daemon)
        return ""

    def checkRouterVersion(self, cmpop, version):
        """
        Compares router version using operation `cmpop` with `version`.
        Valid `cmpop` values:
        * `>=`: has the same version or greater
        * '>': has greater version
        * '=': has the same version
        * '<': has a lesser version
        * '<=': has the same version or lesser

        Usage example: router.checkRouterVersion('>', '1.0')
        """

        # Make sure we have version information first
        if self.version == None:
            self.version = self.cmd(
                os.path.join(self.daemondir, "bgpd") + " -v"
            ).split()[2]
            logger.info("{}: running version: {}".format(self.name, self.version))

        rversion = self.version
        if rversion == None:
            return False

        result = version_cmp(rversion, version)
        if cmpop == ">=":
            return result >= 0
        if cmpop == ">":
            return result > 0
        if cmpop == "=":
            return result == 0
        if cmpop == "<":
            return result < 0
        if cmpop == "<":
            return result < 0
        if cmpop == "<=":
            return result <= 0

    def get_ipv6_linklocal(self):
        "Get LinkLocal Addresses from interfaces"

        linklocal = []

        ifaces = self.cmd("ip -6 address")
        # Fix newlines (make them all the same)
        ifaces = ("\n".join(ifaces.splitlines()) + "\n").splitlines()
        interface = ""
        ll_per_if_count = 0
        for line in ifaces:
            m = re.search("[0-9]+: ([^:@]+)[-@a-z0-9:]+ <", line)
            if m:
                interface = m.group(1)
                ll_per_if_count = 0
            m = re.search(
                "inet6 (fe80::[0-9a-f]+:[0-9a-f]+:[0-9a-f]+:[0-9a-f]+)[/0-9]* scope link",
                line,
            )
            if m:
                local = m.group(1)
                ll_per_if_count += 1
                if ll_per_if_count > 1:
                    linklocal += [["%s-%s" % (interface, ll_per_if_count), local]]
                else:
                    linklocal += [[interface, local]]
        return linklocal

    def daemon_available(self, daemon):
        "Check if specified daemon is installed (and for ldp if kernel supports MPLS)"

        daemon_path = os.path.join(self.daemondir, daemon)
        if not os.path.isfile(daemon_path):
            return False
        if daemon == "ldpd":
            if version_cmp(platform.release(), "4.5") < 0:
                return False
            if not module_present("mpls-router", load=False):
                return False
            if not module_present("mpls-iptunnel", load=False):
                return False
        return True

    def get_routertype(self):
        "Return the type of Router (frr)"

        return self.routertype

    def report_memory_leaks(self, filename_prefix, testscript):
        "Report Memory Leaks to file prefixed with given string"

        leakfound = False
        filename = filename_prefix + re.sub(r"\.py", "", testscript) + ".txt"
        for daemon in self.daemons:
            if self.daemons[daemon] == 1:
                log = self.getStdErr(daemon)
                if "memstats" in log:
                    # Found memory leak
                    logger.warning(
                        "\nRouter {} {} StdErr Log:\n{}".format(self.name, daemon, log)
                    )
                    if not leakfound:
                        leakfound = True
                        # Check if file already exists
                        fileexists = os.path.isfile(filename)
                        leakfile = open(filename, "a")
                        if not fileexists:
                            # New file - add header
                            leakfile.write(
                                "# Memory Leak Detection for topotest %s\n\n"
                                % testscript
                            )
                        leakfile.write("## Router %s\n" % self.name)
                    leakfile.write("### Process %s\n" % daemon)
                    log = re.sub("core_handler: ", "", log)
                    log = re.sub(
                        r"(showing active allocations in memory group [a-zA-Z0-9]+)",
                        r"\n#### \1\n",
                        log,
                    )
                    log = re.sub("memstats:  ", "    ", log)
                    leakfile.write(log)
                    leakfile.write("\n")
        if leakfound:
            leakfile.close()


def frr_unicode(s):
    """Convert string to unicode, depending on python version"""
    if sys.version_info[0] > 2:
        return s
    else:
        return unicode(s)  # pylint: disable=E0602


def is_mapping(o):
    return isinstance(o, Mapping)
