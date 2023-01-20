#!/usr/bin/env python
#
# SPDX-License-Identifier: ISC
# Copyright (c) 2023 VyOS Inc.
# Volodymyr Huti <v.huti@vyos.io>
#

import os
import sys
import json
import pytest

from lib.topolog import logger
from lib.common_config import (
    start_router_daemons,
    kill_router_daemons,
)

from bcc import BPF, DEBUG_PREPROCESSOR, DEBUG_SOURCE, DEBUG_BPF, DEBUG_BTF
from pyroute2.netns import pushns, popns
from pyroute2 import IPRoute
from ctypes import Structure, c_int, c_uint, c_ubyte
from enum import Enum

CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))
sys.path.append(os.path.join(CWD, "../lib/"))

# os.environ["PYTHONBREAKPOINT"] = "pudb.set_trace"
DEV_DEBUG = False


class BgpPolicy(Enum):
    NONE = c_int(0)
    Dst = c_int(1)
    Src = c_int(2)


class XdpMode(str, Enum):
    META = "MARK_META"
    SKB = "MARK_SKB"


class KeyV4(Structure):
    _fields_ = [("prefixlen", c_uint), ("data", c_ubyte * 4)]


def router_attach_xdp(rnode, iface):
    """
    - swap netns to rnode,
    - attach `xdp_qppb` to `iface`
    - switch back to root ns
    """
    ns = "/proc/%d/ns/net" % rnode.net.pid
    qppb_fn = rnode.bpf.funcs[b"xdp_qppb"]

    pushns(ns)
    logger.debug("Attach XDP handler '{}'\nNetNS --> {})".format(iface, ns))
    rnode.bpf.attach_xdp(iface, qppb_fn, BPF.XDP_FLAGS_DRV_MODE)
    popns()


def router_remove_xdp(rnode, iface):
    pushns("/proc/%d/ns/net" % rnode.net.pid)
    logger.debug("Removing XDP handler for {}:{}".format(rnode.name, iface))
    rnode.bpf.remove_xdp(iface)
    popns()


def load_qppb_plugin(tgen, rnode, mode=XdpMode.SKB, debug_on=DEV_DEBUG):
    """
    Initialize rnode XDP hooks and BPF mapping handlers
      - compile xdp handlers from `xdp_qppb.c` in specified `mode`
      - load `xdp_qppb` and `xdp_tc_mark` hooks
      - restart router with QPPB plugin

    Parameters
    ----------
    * `tgen`: topogen object
    * `rnode`: router object
    * `mode`: xdp processing mode required
    * `debug_on`: enable debug logs for bpf compilation / xdp handlers

    Usage
    ---------
    load_qppb_plugin(tgen, r1, mode=XdpMode.META)
    Returns -> None (XXX)
    """
    debug_flags = DEBUG_BPF | DEBUG_PREPROCESSOR | DEBUG_SOURCE | DEBUG_BTF
    debug = debug_flags if debug_on else 0
    src_file = CWD + "/bgp_xdp_qppb.c"
    bpf_flags = [
        '-DMODE_STR="{}"'.format(mode),
        "-D{}".format(mode.value),
        "-DRESPECT_TOS",
        "-w",
    ]
    if debug_on:
        bpf_flags.append("-DLOG_QPPB")
        bpf_flags.append("-DLOG_TC")

    try:
        logger.info("Preparing the XDP src: " + src_file)
        b = BPF(src_file=src_file.encode(), cflags=bpf_flags, debug=debug)

        logger.info("Loading XDP hooks -- xdp_qppb, xdp_tc_mark")
        b.load_func(b"xdp_qppb", BPF.XDP)
        b.load_func(b"xdp_tc_mark", BPF.SCHED_CLS)
        rnode.bpf = b
    except Exception as e:
        pytest.skip("Failed to configure XDP environment -- \n" + str(e))

    qppb_module = "-M vyos_qppb"
    logger.info(
        "Restart {}, XDP hooks loading...\nPlugin :: {}".format(rnode.name, qppb_module)
    )
    kill_router_daemons(tgen, rnode.name, ["bgpd"])
    start_router_daemons(tgen, rnode.name, ["bgpd"], {"bgpd": qppb_module})


def tc_bpf_filter(rnode, ifid):
    "Attach tc bpf filter, depends on pyroute2 package"
    tc_fn = rnode.bpf.funcs[b"xdp_tc_mark"]
    rnode_ns = "/proc/{}/ns/net".format(rnode.net.pid)

    logger.debug("Attach TC-BPF handler '{}'\nNetNS --> {})".format(ifid, rnode_ns))
    # ip.tc("add", "clsact", ifid, "1:")
    pushns(rnode_ns)
    ip = IPRoute()
    ip.tc(
        "add-filter",
        "bpf",
        ifid,
        20,  # XXX:
        fd=tc_fn.fd,
        name=tc_fn.name,
        parent=0x10000,
        classid=0x10030,  # XXX: should be default? default is taken from htb
        direct_action=True,
    )
    popns()


def assert_bw(out, bw_target, tolerance, time=10):
    "Assert that connection matches BW in Mbits +- %tolerance"
    _min = bw_target * (1 - tolerance)
    _max = bw_target * (1 + tolerance)
    half_samples = time / 2
    data = json.loads(out)
    bws = []

    for sample in data["intervals"]:
        bits = int(sample["sum"]["bits_per_second"])
        mbits = bits / 1024 / 1024
        bw = mbits / 8
        logger.debug("BW sample [{} <= {} <= {}]".format(_min, bw, _max))
        if _min <= bw <= _max:
            bws.append(bw)

    _len = len(bws)
    assert (
        _len >= half_samples
    ), "Only {} samples are within targeted BW [{}:{}%]".format(
        _len, bw_target, tolerance * 100
    )


def bpf_print_trace(b):
    "XXX: Call this from debugger, to avoid blocking / IO collissions"
    logger.info("=" * 40)
    logger.debug("Dump bpf log buffer:\n")
    line = b.trace_readline(nonblocking=True)
    while line:
        logger.debug(line)
        line = b.trace_readline(nonblocking=True)


def tc(rnode, cmd):
    logger.debug("TC cmd: " + cmd)
    return rnode.cmd_raises("tc " + cmd)


def tc_check(host, cmds):
    tcoutputs = [tc(host, cmd) for cmd in cmds]
    for output in tcoutputs:
        if output != "":
            logger.debug("TC: " + output)


def tc_log_stats(host, iface):
    if not DEV_DEBUG:
        return
    tc_flags = "-g -s -d -p -col"
    tc_check(
        host,
        [
            tc_flags + " filter ls dev " + iface,
            tc_flags + " class ls dev " + iface,
            tc_flags + " qdisc ls ",
        ],
    )
