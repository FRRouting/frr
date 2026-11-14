#!/usr/bin/env python
# SPDX-License-Identifier: ISC

# Copyright (C) 2026 Dave Seddon

"""
isisd refuses a Flex-Algo definition too large to advertise.

A FAD sub-TLV (2 + len bytes) has to fit in a Router Capability TLV that also
carries an IPv6 TE Router ID, which leaves 255 - 23 bytes, so len <= 230:

    len = 4 + per non-empty affinity (2 + 4 * words) + 3 with prefix-metric
    words = highest bit-position / 32 + 1

rt1 has that IPv6 TE Router ID, so a definition it accepts is the largest it
can advertise. Each row configures rt1, and "expected" is the length of the
definition rt1 then advertises and rt2 decodes, or None if rt1 must refuse it.

    rt1 ------------------- rt2
"""

import functools
import os
import re
import sys

import pytest

CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

# pylint: disable=C0413
from lib import topotest
from lib.topogen import Topogen, get_topogen

pytestmark = [pytest.mark.isisd]

ERROR = "flex-algo 128 definition too large to advertise"
SEND_ZERO = ["router isis 1", " admin-group-send-zero", "exit"]
TWO_GROUPS = ["affinity exclude-any a", "affinity include-any b"]
THREE_GROUPS = TWO_GROUPS + ["affinity include-all c"]

# fmt: off
CASES = [
    {"description": "one affinity at bit 1023 (134 bytes)",
     "maps": {"a": 1023}, "flex_algo": ["affinity exclude-any a"],
     "expected": 134},
    {"description": "two affinities on the same low bit",
     "maps": {"a": 5}, "flex_algo": ["affinity exclude-any a", "affinity include-any a"],
     "expected": 16},
    {"description": "two affinities at bits 1023 and 1022 (264 bytes)",
     "maps": {"a": 1023, "b": 1022}, "flex_algo": TWO_GROUPS,
     "expected": None},
    {"description": "28 + 27 words (228 bytes), the largest two-group FAD",
     "maps": {"a": 895, "b": 863}, "flex_algo": TWO_GROUPS,
     "expected": 228},
    {"description": "28 + 28 words (232 bytes)",
     "maps": {"a": 895, "b": 894}, "flex_algo": TWO_GROUPS,
     "expected": None},
    {"description": "19 + 18 + 18 words (230 bytes), exactly the limit",
     "maps": {"a": 607, "b": 575, "c": 574}, "flex_algo": THREE_GROUPS,
     "expected": 230},
    {"description": "19 + 19 + 18 words (234 bytes)",
     "maps": {"a": 607, "b": 606, "c": 575}, "flex_algo": THREE_GROUPS,
     "expected": None},
    {"description": "prefix-metric on a 224-byte FAD (227 bytes)",
     "maps": {"a": 863, "b": 862}, "flex_algo": TWO_GROUPS + ["prefix-metric"],
     "expected": 227},
    {"description": "prefix-metric on a 228-byte FAD (231 bytes)",
     "maps": {"a": 895, "b": 863}, "flex_algo": TWO_GROUPS + ["prefix-metric"],
     "expected": None},
    {"description": "admin-group-send-zero before a 224-byte FAD (230 bytes)",
     "maps": {"a": 863, "b": 862}, "before": SEND_ZERO, "flex_algo": TWO_GROUPS,
     "expected": 230},
    {"description": "admin-group-send-zero before a 228-byte FAD (234 bytes)",
     "maps": {"a": 895, "b": 863}, "before": SEND_ZERO, "flex_algo": TWO_GROUPS,
     "expected": None},
    {"description": "admin-group-send-zero after a 228-byte FAD",
     "maps": {"a": 895, "b": 863}, "flex_algo": TWO_GROUPS, "after": SEND_ZERO,
     "expected": None},
    {"description": "too large without advertise-definition",
     "maps": {"a": 1023, "b": 1022}, "flex_algo": TWO_GROUPS, "advertise": False,
     "expected": None},
    {"description": "fits without advertise-definition, so nothing is sent",
     "maps": {"a": 5}, "flex_algo": ["affinity exclude-any a"], "advertise": False,
     "expected": 0},
]
# fmt: on


def setup_module(mod):
    tgen = Topogen({"s1": ("rt1", "rt2")}, mod.__name__)
    tgen.start_topology()

    for router in tgen.routers().values():
        router.load_frr_config(os.path.join(CWD, "{}/frr.conf".format(router.name)))

    tgen.start_router()


def teardown_module():
    get_topogen().stop_topology()


def configure(router, commands):
    return router.vtysh_cmd("\n".join(["configure terminal"] + commands))


def fad_of_rt1(router):
    "Flex-Algo Definition of rt1's LSP as shown on router, or None."
    output = router.vtysh_cmd("show isis database detail rt1.00-00")
    match = re.search(r"Flex-Algo Definition: 128\n.*?M-Flag: \d", output, re.DOTALL)
    return match.group(0) if match else None


def fad_size(router):
    "Value length of the Flex-Algo Definition of rt1's LSP on router, or None."
    fad = fad_of_rt1(router)
    if fad is None:
        return None
    size = 4
    groups = re.split(r"(?:Exclude-Any|Include-Any|Include-All): ", fad)[1:]
    for group in groups:
        words = re.findall(r"\b(?:0x)?[0-9a-f]{8}\b", group)
        if words:
            size += 2 + 4 * len(words)
    return size + (3 if "M-Flag: 1" in fad else 0)


def wait_for(func, expected):
    _, result = topotest.run_and_expect(func, expected, count=30, wait=1)
    return result


@pytest.fixture(autouse=True)
def clean_rt1():
    yield
    tgen = get_topogen()
    rt1, rt2 = tgen.gears["rt1"], tgen.gears["rt2"]
    commands = [
        "router isis 1",
        " no flex-algo 128",
        " no admin-group-send-zero",
        "exit",
    ]
    configure(rt1, commands + ["no affinity-map " + m for m in "abc"])
    assert wait_for(functools.partial(fad_of_rt1, rt2), None) is None


def test_adjacency():
    rt2 = get_topogen().gears["rt2"]

    def rt1_lsp_seen():
        return "rt1.00-00" in rt2.vtysh_cmd("show isis database")

    assert wait_for(rt1_lsp_seen, True), "rt2 has no LSP from rt1"


@pytest.mark.parametrize("case", CASES, ids=lambda case: case["description"])
def test_fad_size(case):
    tgen = get_topogen()
    rt1, rt2 = tgen.gears["rt1"], tgen.gears["rt2"]
    advertise = case.get("advertise", True)

    commands = [
        "affinity-map {} bit-position {}".format(name, bit)
        for name, bit in case["maps"].items()
    ]
    commands += case.get("before", [])
    commands += ["router isis 1", " flex-algo 128"]
    if advertise:
        commands.append("  advertise-definition")
    commands += ["  " + line for line in case["flex_algo"]]
    commands += ["exit", "exit"]
    commands += case.get("after", [])

    output = configure(rt1, commands)
    if case["expected"] is None:
        assert ERROR in output, output
        return
    assert "%" not in output, output

    if not advertise:
        assert fad_of_rt1(rt1) is None
        return

    for router in (rt1, rt2):
        size = wait_for(functools.partial(fad_size, router), case["expected"])
        assert size == case["expected"], "{}: size {}".format(router.name, size)
    assert fad_of_rt1(rt2) == fad_of_rt1(rt1)


def test_memory_leak():
    tgen = get_topogen()
    if not tgen.is_memleak_enabled():
        pytest.skip("Memory leak test/report is disabled")
    tgen.report_memory_leaks()


if __name__ == "__main__":
    sys.exit(pytest.main(["-s"] + sys.argv[1:]))
