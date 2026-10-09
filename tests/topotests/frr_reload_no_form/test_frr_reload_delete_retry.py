#!/usr/bin/env python
# SPDX-License-Identifier: ISC
#
# test_frr_reload_delete_retry.py
# Part of NetDEF Topology Tests
#
# Copyright (c) 2026 by
# Network Device Education Foundation, Inc. ("NetDEF")
#
"""
Unit tests for the frr-reload "no" command word-trimming retry (no daemons).

When vtysh rejects "no FOO BAR BAZ", delete_line_with_vtysh() drops the last
word and tries again. lines_to_config() closes every context it opens with
"exit", so the word to drop is on the "no" line, not on the last line.
"""

import importlib.util
import logging
import os
import shutil

import pytest

CWD = os.path.dirname(os.path.realpath(__file__))

# CI runs the topotests tree detached from the source tree, so the in-tree
# tools/ directory is not always reachable; fall back to the installed script.
FRR_RELOAD_CANDIDATES = (
    os.environ.get("FRR_RELOAD_PY"),
    os.path.abspath(os.path.join(CWD, "../../../tools/frr-reload.py")),
    "/usr/lib/frr/frr-reload.py",
    shutil.which("frr-reload.py"),
)


def _find_reload():
    for path in FRR_RELOAD_CANDIDATES:
        if path and os.path.isfile(path):
            return path
    return None


def _load_reload(path):
    spec = importlib.util.spec_from_file_location("frr_reload", path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


@pytest.fixture(scope="module")
def reload():
    path = _find_reload()
    if path is None:
        pytest.skip(
            "frr-reload.py not found (looked in {})".format(
                ", ".join(p for p in FRR_RELOAD_CANDIDATES if p)
            )
        )
    return _load_reload(path)


class FakeVtysh:
    """Record "vtysh -c" calls, accepting only the given "no" lines."""

    def __init__(self, reload, accepted):
        self.reload = reload
        self.accepted = accepted
        self.calls = []

    def __call__(self, command, stdouts=None):
        self.calls.append(list(command))
        if not any(line in self.accepted for line in command):
            raise self.reload.VtyshException("% Unknown command")


def _delete(reload, accepted, ctx_keys, line):
    vtysh = FakeVtysh(reload, accepted)
    # Failed attempts are logged at error level; keep the test output clean.
    logging.disable(logging.CRITICAL)
    try:
        ok = reload.delete_line_with_vtysh(vtysh, ctx_keys, line)
    finally:
        logging.disable(logging.NOTSET)
    return ok, vtysh.calls


def test_trim_inside_context(reload):
    """Interface description: only "no description" exists."""
    ok, calls = _delete(
        reload,
        [" no description"],
        ("interface eth0",),
        "description link to s1",
    )
    assert ok
    assert calls == [
        ["configure", "interface eth0", " no description link to s1", "exit"],
        ["configure", "interface eth0", " no description link to", "exit"],
        ["configure", "interface eth0", " no description link", "exit"],
        ["configure", "interface eth0", " no description", "exit"],
    ]


def test_trim_inside_nested_context(reload):
    """Both "exit" lines are kept, the "no" line keeps its indentation."""
    ok, calls = _delete(
        reload,
        ["  no foo bar"],
        ("router bgp 65000", "address-family ipv4 unicast"),
        "foo bar baz",
    )
    assert ok
    assert calls[-1] == [
        "configure",
        "router bgp 65000",
        " address-family ipv4 unicast",
        "  no foo bar",
        " exit",
        "exit",
    ]


def test_trim_top_level(reload):
    """A command outside any context has no "exit" to skip."""
    ok, calls = _delete(reload, ["no ip foo"], ("ip foo bar",), None)
    assert ok
    assert calls == [
        ["configure", "no ip foo bar"],
        ["configure", "no ip foo"],
    ]


def test_trim_gives_up_at_two_words(reload):
    """Never accepted: stop after "no WORD", report failure."""
    ok, calls = _delete(reload, [], ("router ospf",), "foo bar baz")
    assert not ok
    assert [call[2] for call in calls] == [
        " no foo bar baz",
        " no foo bar",
        " no foo",
    ]
    assert all(call[-1] == "exit" for call in calls)
