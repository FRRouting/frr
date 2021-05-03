#!/usr/bin/env python

#
# topotest.py
# Library of helper functions for NetDEF Topology Tests
#
# Copyright (c) 2016 by
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

import json
import os
import errno
import re
import sys
import functools
import glob
import subprocess
import tempfile
import platform
import difflib
import time
import signal

from lib.topolog import logger
from copy import deepcopy

if sys.version_info[0] > 2:
    import configparser
else:
    import ConfigParser as configparser

from mininet.topo import Topo
from mininet.net import Mininet
from mininet.node import Node, OVSSwitch, Host
from mininet.log import setLogLevel, info
from mininet.cli import CLI
from mininet.link import Intf
from mininet.term import makeTerm

g_extra_config = {}


def gdb_core(obj, daemon, corefiles):
    gdbcmds = """
        info threads
        bt full
        disassemble
        up
        disassemble
        up
        disassemble
        up
        disassemble
        up
        disassemble
        up
        disassemble
    """
    gdbcmds = [["-ex", i.strip()] for i in gdbcmds.strip().split("\n")]
    gdbcmds = [item for sl in gdbcmds for item in sl]

    daemon_path = os.path.join(obj.daemondir, daemon)
    backtrace = subprocess.check_output(
        ["gdb", daemon_path, corefiles[0], "--batch"] + gdbcmds
    )
    sys.stderr.write(
        "\n%s: %s crashed. Core file found - Backtrace follows:\n" % (obj.name, daemon)
    )
    sys.stderr.write("%s" % backtrace)
    return backtrace


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


def gen_json_diff_report(d1, d2, exact=False, path="> $", acc=(0, "")):
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

    if d2 == "*" or (
        not isinstance(d1, (list, dict))
        and not isinstance(d2, (list, dict))
        and d1 == d2
    ):
        return acc
    elif (
        not isinstance(d1, (list, dict))
        and not isinstance(d2, (list, dict))
        and d1 != d2
    ):
        acc = add_error(
            acc,
            "d1 has element with value '{}' but in d2 it has value '{}'".format(d1, d2),
        )
    elif (
        isinstance(d1, list)
        and isinstance(d2, list)
        and ((len(d2) > 0 and d2[0] == "__ordered__") or exact)
    ):
        if not exact:
            del d2[0]
        if len(d1) != len(d2):
            acc = add_error(
                acc,
                "d1 has Array of length {} but in d2 it is of length {}".format(
                    len(d1), len(d2)
                ),
            )
        else:
            for idx, v1, v2 in zip(range(0, len(d1)), d1, d2):
                acc = merge_errors(
                    acc, gen_json_diff_report(v1, v2, exact=exact, path=add_idx(idx))
                )
    elif isinstance(d1, list) and isinstance(d2, list):
        if len(d1) < len(d2):
            acc = add_error(
                acc,
                "d1 has Array of length {} but in d2 it is of length {}".format(
                    len(d1), len(d2)
                ),
            )
        else:
            for idx2, v2 in zip(range(0, len(d2)), d2):
                found_match = False
                closest_diff = None
                closest_idx = None
                for idx1, v1 in zip(range(0, len(d1)), d1):
                    tmp_v1 = deepcopy(v1)
                    tmp_v2 = deepcopy(v2)
                    tmp_diff = gen_json_diff_report(tmp_v1, tmp_v2, path=add_idx(idx1))
                    if not has_errors(tmp_diff):
                        found_match = True
                        del d1[idx1]
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
                            "d2 has the following element at index {} which is not present in d1: "
                            + "\n\n{}\n\n\tClosest match in d1 is at index {} with the following errors: {}"
                        ).format(idx2, dump_json(v2), closest_idx, sub_error),
                    )
                if not found_match and not isinstance(v2, (list, dict)):
                    acc = add_error(
                        acc,
                        "d2 has the following element at index {} which is not present in d1: {}".format(
                            idx2, dump_json(v2)
                        ),
                    )
    elif isinstance(d1, dict) and isinstance(d2, dict) and exact:
        invalid_keys_d1 = [k for k in d1.keys() if k not in d2.keys()]
        invalid_keys_d2 = [k for k in d2.keys() if k not in d1.keys()]
        for k in invalid_keys_d1:
            acc = add_error(acc, "d1 has key '{}' which is not present in d2".format(k))
        for k in invalid_keys_d2:
            acc = add_error(acc, "d2 has key '{}' which is not present in d1".format(k))
        valid_keys_intersection = [k for k in d1.keys() if k in d2.keys()]
        for k in valid_keys_intersection:
            acc = merge_errors(
                acc, gen_json_diff_report(d1[k], d2[k], exact=exact, path=add_key(k))
            )
    elif isinstance(d1, dict) and isinstance(d2, dict):
        none_keys = [k for k, v in d2.items() if v == None]
        none_keys_present = [k for k in d1.keys() if k in none_keys]
        for k in none_keys_present:
            acc = add_error(
                acc, "d1 has key '{}' which is not supposed to be present".format(k)
            )
        keys = [k for k, v in d2.items() if v != None]
        invalid_keys_intersection = [k for k in keys if k not in d1.keys()]
        for k in invalid_keys_intersection:
            acc = add_error(acc, "d2 has key '{}' which is not present in d1".format(k))
        valid_keys_intersection = [k for k in keys if k in d1.keys()]
        for k in valid_keys_intersection:
            acc = merge_errors(
                acc, gen_json_diff_report(d1[k], d2[k], exact=exact, path=add_key(k))
            )
    else:
        acc = add_error(
            acc,
            "d1 has element of type '{}' but the corresponding element in d2 is of type '{}'".format(
                json_type(d1), json_type(d2)
            ),
            points=2,
        )

    return acc


def json_cmp(d1, d2, exact=False):
    """
    JSON compare function. Receives two parameters:
    * `d1`: parsed JSON data structure
    * `d2`: parsed JSON data structure

    Returns 'None' when all JSON Object keys and all Array elements of d2 have a match
    in d1, e.g. when d2 is a "subset" of d1 without honoring any order. Otherwise an
    error report is generated and wrapped in a 'json_cmp_result()'. There are special
    parameters and notations explained below which can be used to cover rather unusual
    cases:

    * when 'exact is set to 'True' then d1 and d2 are tested for equality (including
      order within JSON Arrays)
    * using 'null' (or 'None' in Python) as JSON Object value is checking for key
      absence in d1
    * using '*' as JSON Object value or Array value is checking for presence in d1
      without checking the values
    * using '__ordered__' as first element in a JSON Array in d2 will also check the
      order when it is compared to an Array in d1
    """

    (errors_n, errors) = gen_json_diff_report(deepcopy(d1), deepcopy(d2), exact=exact)

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

    logger.info(
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
        logger.info(
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

    logger.info(
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
        logger.info(
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


def pid_exists(pid):
    "Check whether pid exists in the current process table."

    if pid <= 0:
        return False
    try:
        os.waitpid(pid, os.WNOHANG)
    except:
        pass
    try:
        os.kill(pid, 0)
    except OSError as err:
        if err.errno == errno.ESRCH:
            # ESRCH == No such process
            return False
        elif err.errno == errno.EPERM:
            # EPERM clearly means there's a process to deny access to
            return True
        else:
            # According to "man 2 kill" possible error values are
            # (EINVAL, EPERM, ESRCH)
            raise
    else:
        return True


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
    }.get(
        protocol, protocol
    )  # default return same as input


def ip4_route(node):
    """
    Gets a structured return of the command 'ip route'. It can be used in
    conjuction with json_cmp() to provide accurate assert explanations.

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
    It can be used in conjuction with json_cmp() to provide accurate assert explanations.

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
    conjuction with json_cmp() to provide accurate assert explanations.

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
    It can be used in conjuction with json_cmp() to provide accurate assert explanations.

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
    conjuction with json_cmp() to provide accurate assert explanations.

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
            testframe = sys._current_frames().values()[0]
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
                    and (callingProc != "__stop_internal")
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
        "(==[0-9]+==)ERROR: AddressSanitizer: ([^\s]*) ", output
    )
    if addressSanitizerError:
        processAddressSanitizerError(addressSanitizerError, output, router, component)
        return True

    # No Address Sanitizer Error in Output. Now check for AddressSanitizer daemon file
    if logdir:
        filepattern = logdir + "/" + router + "/" + component + ".asan.*"
        logger.debug(
            "Log check for %s on %s, pattern %s\n" % (component, router, filepattern)
        )
        for file in glob.glob(filepattern):
            with open(file, "r") as asanErrorFile:
                asanError = asanErrorFile.read()
            addressSanitizerError = re.search(
                "(==[0-9]+==)ERROR: AddressSanitizer: ([^\s]*) ", asanError
            )
            if addressSanitizerError:
                processAddressSanitizerError(
                    addressSanitizerError, asanError, router, component
                )
                return True
    return False


def addRouter(topo, name):
    "Adding a FRRouter to Topology"

    MyPrivateDirs = [
        "/etc/frr",
        "/var/run/frr",
        "/var/log",
    ]
    if sys.platform.startswith("linux"):
        return topo.addNode(name, cls=LinuxRouter, privateDirs=MyPrivateDirs)
    elif sys.platform.startswith("freebsd"):
        return topo.addNode(name, cls=FreeBSDRouter, privateDirs=MyPrivateDirs)


def set_sysctl(node, sysctl, value):
    "Set a sysctl value and return None on success or an error string"
    valuestr = "{}".format(value)
    command = "sysctl {0}={1}".format(sysctl, valuestr)
    cmdret = node.cmd(command)

    matches = re.search(r"([^ ]+) = ([^\s]+)", cmdret)
    if matches is None:
        return cmdret
    if matches.group(1) != sysctl:
        return cmdret
    if matches.group(2) != valuestr:
        return cmdret

    return None


def assert_sysctl(node, sysctl, value):
    "Set and assert that the sysctl is set with the specified value."
    assert set_sysctl(node, sysctl, value) is None


class Router(Node):
    "A Node with IPv4/IPv6 forwarding enabled"

    def __init__(self, name, **params):
        super(Router, self).__init__(name, **params)
        self.logdir = params.get("logdir")

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

        # If this topology is using old API and doesn't have logdir
        # specified, then attempt to generate an unique logdir.
        if self.logdir is None:
            cur_test = os.environ["PYTEST_CURRENT_TEST"]
            self.logdir = "/tmp/topotests/" + cur_test[
                cur_test.find("/") + 1 : cur_test.find(".py")
            ].replace("/", ".")

        # If the logdir is not created, then create it and set the
        # appropriated permissions.
        if not os.path.isdir(self.logdir):
            os.system("mkdir -p " + self.logdir + "/" + name)
            os.system("chmod -R go+rw /tmp/topotests")
            # Erase logs of previous run
            os.system("rm -rf " + self.logdir + "/" + name)

        self.daemondir = None
        self.hasmpls = False
        self.routertype = "frr"
        self.daemons = {
            "zebra": 0,
            "ripd": 0,
            "ripngd": 0,
            "ospfd": 0,
            "ospf6d": 0,
            "isisd": 0,
            "bgpd": 0,
            "pimd": 0,
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
        }
        self.daemons_options = {"zebra": ""}
        self.reportCores = True
        self.version = None

    def _config_frr(self, **params):
        "Configure FRR binaries"
        self.daemondir = params.get("frrdir")
        if self.daemondir is None:
            self.daemondir = self.config_defaults.get("topogen", "frrdir")

        zebra_path = os.path.join(self.daemondir, "zebra")
        if not os.path.isfile(zebra_path):
            raise Exception("FRR zebra binary doesn't exist at {}".format(zebra_path))

    # pylint: disable=W0221
    # Some params are only meaningful for the parent class.
    def config(self, **params):
        super(Router, self).config(**params)

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
            # Allow user to specify routertype when the path was specified.
            if params.get("routertype") is not None:
                self.routertype = params.get("routertype")

        self.cmd("ulimit -c unlimited")
        # Set ownership of config files
        self.cmd("chown {0}:{0}vty /etc/{0}".format(self.routertype))

    def terminate(self):
        # Stop running FRR daemons
        self.stopRouter()

        # Disable forwarding
        set_sysctl(self, "net.ipv4.ip_forward", 0)
        set_sysctl(self, "net.ipv6.conf.all.forwarding", 0)
        super(Router, self).terminate()
        os.system("chmod -R go+rw /tmp/topotests")

    # Return count of running daemons
    def listDaemons(self):
        ret = []
        rundaemons = self.cmd("ls -1 /var/run/%s/*.pid" % self.routertype)
        errors = ""
        if re.search(r"No such file or directory", rundaemons):
            return 0
        if rundaemons is not None:
            bet = rundaemons.split("\n")
            for d in bet[:-1]:
                daemonpid = self.cmd("cat %s" % d.rstrip()).rstrip()
                if daemonpid.isdigit() and pid_exists(int(daemonpid)):
                    ret.append(os.path.basename(d.rstrip().rsplit(".", 1)[0]))

        return ret

    def stopRouter(self, wait=True, assertOnError=True, minErrorVersion="5.1"):
        # Stop Running FRR Daemons
        rundaemons = self.cmd("ls -1 /var/run/%s/*.pid" % self.routertype)
        errors = ""
        if re.search(r"No such file or directory", rundaemons):
            return errors
        if rundaemons is not None:
            dmns = rundaemons.split("\n")
            # Exclude empty string at end of list
            for d in dmns[:-1]:
                # Only check if daemonfilepath starts with /
                # Avoids hang on "-> Connection closed" in above self.cmd()
                if d[0] == '/':
                    daemonpid = self.cmd("cat %s" % d.rstrip()).rstrip()
                    if daemonpid.isdigit() and pid_exists(int(daemonpid)):
                        daemonname = os.path.basename(d.rstrip().rsplit(".", 1)[0])
                        logger.info("{}: stopping {}".format(self.name, daemonname))
                        try:
                            os.kill(int(daemonpid), signal.SIGTERM)
                        except OSError as err:
                            if err.errno == errno.ESRCH:
                                logger.error(
                                    "{}: {} left a dead pidfile (pid={})".format(
                                        self.name, daemonname, daemonpid
                                    )
                                )
                            else:
                                logger.info(
                                    "{}: {} could not kill pid {}: {}".format(
                                        self.name, daemonname, daemonpid, str(err)
                                    )
                                )

            if not wait:
                return errors

            running = self.listDaemons()

            if running:
                sleep(
                    0.1,
                    "{}: waiting for daemons stopping: {}".format(
                        self.name, ", ".join(running)
                    ),
                )
                running = self.listDaemons()

                counter = 20
                while counter > 0 and running:
                    sleep(
                        0.5,
                        "{}: waiting for daemons stopping: {}".format(
                            self.name, ", ".join(running)
                        ),
                    )
                    running = self.listDaemons()
                    counter -= 1

            if running:
                # 2nd round of kill if daemons didn't exit
                dmns = rundaemons.split("\n")
                # Exclude empty string at end of list
                for d in dmns[:-1]:
                    daemonpid = self.cmd("cat %s" % d.rstrip()).rstrip()
                    if daemonpid.isdigit() and pid_exists(int(daemonpid)):
                        logger.info(
                            "{}: killing {}".format(
                                self.name,
                                os.path.basename(d.rstrip().rsplit(".", 1)[0]),
                            )
                        )
                        self.cmd("kill -7 %s" % daemonpid)
                        self.waitOutput()
                    self.cmd("rm -- {}".format(d.rstrip()))

        if not wait:
            return errors

        errors = self.checkRouterCores(reportOnce=True)
        if self.checkRouterVersion("<", minErrorVersion):
            # ignore errors in old versions
            errors = ""
        if assertOnError and errors is not None and len(errors) > 0:
            assert "Errors found - details follow:" == 0, errors
        return errors

    def removeIPs(self):
        for interface in self.intfNames():
            self.cmd("ip address flush", interface)

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
        # print "Daemons before:", self.daemons
        if daemon in self.daemons.keys():
            self.daemons[daemon] = 1
            if param is not None:
                self.daemons_options[daemon] = param
            if source is None:
                self.cmd("touch /etc/%s/%s.conf" % (self.routertype, daemon))
                self.waitOutput()
            else:
                self.cmd("cp %s /etc/%s/%s.conf" % (source, self.routertype, daemon))
                self.waitOutput()
            self.cmd("chmod 640 /etc/%s/%s.conf" % (self.routertype, daemon))
            self.waitOutput()
            self.cmd(
                "chown %s:%s /etc/%s/%s.conf"
                % (self.routertype, self.routertype, self.routertype, daemon)
            )
            self.waitOutput()
            if (daemon == "snmpd") and (self.routertype == "frr"):
                self.cmd('echo "agentXSocket /etc/frr/agentx" > /etc/snmp/frr.conf')
            if (daemon == "zebra") and (self.daemons["staticd"] == 0):
                # Add staticd with zebra - if it exists
                staticd_path = os.path.join(self.daemondir, "staticd")
                if os.path.isfile(staticd_path):
                    self.daemons["staticd"] = 1
                    self.daemons_options["staticd"] = ""
                    # Auto-Started staticd has no config, so it will read from zebra config
        else:
            logger.info("No daemon {} known".format(daemon))
        # print "Daemons after:", self.daemons

    # Run a command in a new window (gnome-terminal, screen, tmux, xterm)
    def runInWindow(self, cmd, title=None):
        topo_terminal = os.getenv("FRR_TOPO_TERMINAL")
        if topo_terminal or ("TMUX" not in os.environ and "STY" not in os.environ):
            term = topo_terminal if topo_terminal else "xterm"
            makeTerm(self, title=title if title else cmd, term=term, cmd=cmd)
        else:
            nscmd = "sudo nsenter -m -n -t {} {}".format(self.pid, cmd)
            if "TMUX" in os.environ:
                self.cmd("tmux select-layout main-horizontal")
                wcmd = "tmux split-window -h"
                cmd = "{} {}".format(wcmd, nscmd)
            elif "STY" in os.environ:
                if os.path.exists(
                    "/run/screen/S-{}/{}".format(os.environ["USER"], os.environ["STY"])
                ):
                    wcmd = "screen"
                else:
                    wcmd = "sudo -u {} screen".format(os.environ["SUDO_USER"])
                cmd = "{} {}".format(wcmd, nscmd)
            self.cmd(cmd)

    def startRouter(self, tgen=None):
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
        # Remove old core files
        map(os.remove, glob.glob("{}/{}/*.dmp".format(self.logdir, self.name)))
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
        self.cmd("echo 100000 > /proc/sys/net/mpls/platform_labels")

        shell_routers = g_extra_config["shell"]
        if "all" in shell_routers or self.name in shell_routers:
            self.runInWindow(os.getenv("SHELL", "bash"))

        vtysh_routers = g_extra_config["vtysh"]
        if "all" in vtysh_routers or self.name in vtysh_routers:
            self.runInWindow("vtysh")

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

        return self.startRouterDaemons()

    def getStdErr(self, daemon):
        return self.getLog("err", daemon)

    def getStdOut(self, daemon):
        return self.getLog("out", daemon)

    def getLog(self, log, daemon):
        return self.cmd("cat {}/{}/{}.{}".format(self.logdir, self.name, daemon, log))

    def startRouterDaemons(self, daemons=None):
        "Starts all FRR daemons for this router."

        gdb_breakpoints = g_extra_config["gdb_breakpoints"]
        gdb_daemons = g_extra_config["gdb_daemons"]
        gdb_routers = g_extra_config["gdb_routers"]

        bundle_data = ""

        if os.path.exists("/etc/frr/support_bundle_commands.conf"):
            bundle_data = subprocess.check_output(
                ["cat /etc/frr/support_bundle_commands.conf"], shell=True
            )
        self.cmd(
            "echo '{}' > /etc/frr/support_bundle_commands.conf".format(bundle_data)
        )

        # Starts actual daemons without init (ie restart)
        # cd to per node directory
        self.cmd("install -d {}/{}".format(self.logdir, self.name))
        self.cmd("cd {}/{}".format(self.logdir, self.name))
        self.cmd("umask 000")

        # Re-enable to allow for report per run
        self.reportCores = True

        # XXX: glue code forward ported from removed function.
        if self.version == None:
            self.version = self.cmd(
                os.path.join(self.daemondir, "bgpd") + " -v"
            ).split()[2]
            logger.info("{}: running version: {}".format(self.name, self.version))

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

        def start_daemon(daemon, extra_opts=None):
            daemon_opts = self.daemons_options.get(daemon, "")
            rediropt = " > {0}.out 2> {0}.err".format(daemon)
            if daemon == "snmpd":
                binary = "/usr/sbin/snmpd"
                cmdenv = ""
                cmdopt = "{} -C -c /etc/frr/snmpd.conf -p ".format(
                    daemon_opts
                ) + "/var/run/{}/snmpd.pid -x /etc/frr/agentx".format(self.routertype)
            else:
                binary = os.path.join(self.daemondir, daemon)
                cmdenv = "ASAN_OPTIONS=log_path={0}.asan".format(daemon)
                cmdopt = "{} --log file:{}.log --log-level debug".format(
                    daemon_opts, daemon
                )
            if extra_opts:
                cmdopt += " " + extra_opts

            if (
                (gdb_routers or gdb_daemons)
                and (
                    not gdb_routers or self.name in gdb_routers or "all" in gdb_routers
                )
                and (not gdb_daemons or daemon in gdb_daemons or "all" in gdb_daemons)
            ):
                if daemon == "snmpd":
                    cmdopt += " -f "

                cmdopt += rediropt
                gdbcmd = "sudo -E gdb " + binary
                if gdb_breakpoints:
                    gdbcmd += " -ex 'set breakpoint pending on'"
                for bp in gdb_breakpoints:
                    gdbcmd += " -ex 'b {}'".format(bp)
                gdbcmd += " -ex 'run {}'".format(cmdopt)

                self.runInWindow(gdbcmd, daemon)
            else:
                if daemon != "snmpd":
                    cmdopt += " -d "
                cmdopt += rediropt
                self.cmd(" ".join([cmdenv, binary, cmdopt]))
            logger.info("{}: {} {} started".format(self, self.routertype, daemon))

        # Start Zebra first
        if "zebra" in daemons_list:
            start_daemon("zebra", "-s 90000000")
            while "zebra" in daemons_list:
                daemons_list.remove("zebra")

        # Start staticd next if required
        if "staticd" in daemons_list:
            start_daemon("staticd")
            while "staticd" in daemons_list:
                daemons_list.remove("staticd")

        if "snmpd" in daemons_list:
            start_daemon("snmpd")
            while "snmpd" in daemons_list:
                daemons_list.remove("snmpd")

        # Fix Link-Local Addresses
        # Somehow (on Mininet only), Zebra removes the IPv6 Link-Local addresses on start. Fix this
        self.cmd(
            "for i in `ls /sys/class/net/` ; do mac=`cat /sys/class/net/$i/address`; IFS=':'; set $mac; unset IFS; ip address add dev $i scope link fe80::$(printf %02x $((0x$1 ^ 2)))$2:${3}ff:fe$4:$5$6/64; done"
        )

        # Now start all the other daemons
        for daemon in daemons_list:
            if self.daemons[daemon] == 0:
                continue
            start_daemon(daemon)

        # Check if daemons are running.
        rundaemons = self.cmd("ls -1 /var/run/%s/*.pid" % self.routertype)
        if re.search(r"No such file or directory", rundaemons):
            return "Daemons are not running"

        return ""

    def killRouterDaemons(
        self, daemons, wait=True, assertOnError=True, minErrorVersion="5.1"
    ):
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
                        daemonpid = self.cmd("cat %s" % d.rstrip()).rstrip()
                        if daemonpid.isdigit() and pid_exists(int(daemonpid)):
                            logger.info(
                                "{}: killing {}".format(
                                    self.name,
                                    os.path.basename(d.rstrip().rsplit(".", 1)[0]),
                                )
                            )
                            self.cmd("kill -9 %s" % daemonpid)
                            self.waitOutput()
                            if pid_exists(int(daemonpid)):
                                numRunning += 1
                        if wait and numRunning > 0:
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
                                    if daemonpid.isdigit() and pid_exists(
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
                                        self.cmd("kill -9 %s" % daemonpid)
                                        self.waitOutput()
                                    self.cmd("rm -- {}".format(d.rstrip()))
                    if wait:
                        errors = self.checkRouterCores(reportOnce=True)
                        if self.checkRouterVersion("<", minErrorVersion):
                            # ignore errors in old versions
                            errors = ""
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
                        + "\n%s: %s crashed. Core file found - Backtrace follows:\n%s"
                        % (self.name, daemon, backtrace)
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
                    logger.info(
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


class LinuxRouter(Router):
    "A Linux Router Node with IPv4/IPv6 forwarding enabled."

    def __init__(self, name, **params):
        Router.__init__(self, name, **params)

    def config(self, **params):
        Router.config(self, **params)
        # Enable forwarding on the router
        assert_sysctl(self, "net.ipv4.ip_forward", 1)
        assert_sysctl(self, "net.ipv6.conf.all.forwarding", 1)
        # Enable coredumps
        assert_sysctl(self, "kernel.core_uses_pid", 1)
        assert_sysctl(self, "fs.suid_dumpable", 1)
        # this applies to the kernel not the namespace...
        # original on ubuntu 17.x, but apport won't save as in namespace
        # |/usr/share/apport/apport %p %s %c %d %P
        corefile = "%e_core-sig_%s-pid_%p.dmp"
        assert_sysctl(self, "kernel.core_pattern", corefile)

    def terminate(self):
        """
        Terminate generic LinuxRouter Mininet instance
        """
        set_sysctl(self, "net.ipv4.ip_forward", 0)
        set_sysctl(self, "net.ipv6.conf.all.forwarding", 0)
        Router.terminate(self)


class FreeBSDRouter(Router):
    "A FreeBSD Router Node with IPv4/IPv6 forwarding enabled."

    def __init__(self, name, **params):
        Router.__init__(self, name, **params)


class LegacySwitch(OVSSwitch):
    "A Legacy Switch without OpenFlow"

    def __init__(self, name, **params):
        OVSSwitch.__init__(self, name, failMode="standalone", **params)
        self.switchIP = None


def frr_unicode(s):
    """Convert string to unicode, depending on python version"""
    if sys.version_info[0] > 2:
        return s
    else:
        return unicode(s)
