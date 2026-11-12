#!/usr/bin/env python3
# SPDX-License-Identifier: ISC

"""Integration tests for vtysh output modifiers."""

import re
import pytest
from lib.topogen import Topogen


def build_topo(tgen):
    """Build a minimal one-router topology."""
    r1 = tgen.add_router("r1")
    switch = tgen.add_switch("s1")
    switch.add_link(r1)


@pytest.fixture(scope="module")
def tgen(request):
    """Start one router and expose it to the tests."""
    tgen = Topogen(build_topo, request.module.__name__)
    tgen.start_topology()

    for router in tgen.routers().values():
        router.load_frr_config()

    tgen.start_router()
    yield tgen
    tgen.stop_topology()


def _matching_lines(output, pattern):
    """Return output lines matching a test pattern."""
    return [line for line in output.splitlines() if re.search(pattern, line)]


def test_include_filters_matching_lines(tgen):
    """include must retain matching lines and discard all other lines."""
    router = tgen.gears["r1"]
    unfiltered = router.vtysh_cmd("show version")
    expected = _matching_lines(unfiltered, r"FRRouting")

    assert expected, "show version did not contain the expected FRRouting line"

    actual = router.vtysh_cmd("show version | include FRRouting")
    assert actual.splitlines() == expected

def test_recognize_partial_modifier(tgen):
    router = tgen.gears["r1"]
    unfiltered = router.vtysh_cmd("show version")
    expected = _matching_lines(unfiltered, r"FRRouting")

    assert expected, "show version did not contain the expected FRRouting line"

    actual = router.vtysh_cmd("show version | incl FRRouting")
    assert actual.splitlines() == expected

def test_support_spacing_between_tokens(tgen):
    router = tgen.gears["r1"]
    unfiltered = router.vtysh_cmd("show version")
    expected = _matching_lines(unfiltered, r"FRRouting")

    assert expected, "show version did not contain the expected FRRouting line"

    actual = router.vtysh_cmd("show version   |   include   FRRouting")
    assert actual.splitlines() == expected

def test_include_supports_regex_alternation(tgen):
    """A pipe inside the regex must not be mistaken for another modifier."""
    router = tgen.gears["r1"]
    pattern = r"FRRouting|Copyright"
    unfiltered = router.vtysh_cmd("show version")
    expected = _matching_lines(unfiltered, pattern)

    assert any("FRRouting" in line for line in expected)
    assert any("Copyright" in line for line in expected)

    actual = router.vtysh_cmd("show version | include " + pattern)
    assert actual.splitlines() == expected

def test_pipe_must_be_separated_from_command(tgen):
    """A pipe without whitespace before it is not a modifier delimiter."""
    router = tgen.gears["r1"]
    actual = router.vtysh_cmd("show version| include FRRouting")
    assert "% Unknown command" in actual


def test_include_with_no_matches_returns_no_output(tgen):
    router = tgen.gears["r1"]
    actual = router.vtysh_cmd(
        "show version | include NOT_MATCH_ANY_LINE"
    )
    assert actual.strip() == ""


def test_include_rejects_missing_regex(tgen):
    router = tgen.gears["r1"]
    actual = router.vtysh_cmd("show version | include")
    assert "% Command incomplete:" in actual


def test_include_rejects_empty_regex(tgen):
    """Whitespace after include is not a valid regular expression."""
    router = tgen.gears["r1"]
    actual = router.vtysh_cmd("show version | include ")
    assert "% Need a regexp to filter with" in actual


def test_include_rejects_invalid_regex(tgen):
    router = tgen.gears["r1"]
    actual = router.vtysh_cmd("show version | include [")
    assert "% Bad regexp '['" in actual


def test_unknown_modifier_is_rejected(tgen):
    router = tgen.gears["r1"]
    actual = router.vtysh_cmd("show version | modifier FRRouting")
    assert "% Unknown action 'modifier'" in actual


def test_filter_is_cleared_after_command(tgen):
    """The filter must not affect the next command on the same vty session."""
    router = tgen.gears["r1"]
    actual = router.vtysh_cmd(
        "show version | include Copyright\n"
        "show version"
    )

    assert "FRRouting" in actual

def test_filter_on_configure_node(tgen):
    router = tgen.gears["r1"]
    actual = router.vtysh_cmd(
        "configure terminal\n"
        "do show version | include Copyright\n"
        "end"
    )

    assert "Copyright" in actual

def test_modifier_is_not_applied_to_non_show_commands(tgen):
    """A pipe modifier must not turn a configuration command into a valid one."""
    router = tgen.gears["r1"]

    try:
        router.vtysh_cmd(
            "configure terminal\n"
            "hostname should-not-be-applied | include no-such-line\n"
            "end"
        )
        running_config = router.vtysh_cmd("show running-config")
        assert "hostname r1" in running_config.splitlines()
        assert "hostname should-not-be-applied" not in running_config.splitlines()
    finally:
        router.vtysh_cmd("configure terminal\nhostname r1\nend")


if __name__ == "__main__":
    import sys

    sys.exit(pytest.main(["-s"] + sys.argv[1:]))
