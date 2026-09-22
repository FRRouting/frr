#!/usr/bin/env python
# SPDX-License-Identifier: ISC
#
# test_frr_reload_rt_emit.py
#
# Copyright (c) 2026 by Nvidia, Inc.
#
"""Unit tests for frr-reload EVPN AF route-target grouping (no daemons)."""

import importlib.util
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


VRF_AF = (
    "router bgp 4200000102 vrf vrf_shared1",
    "address-family l2vpn evpn",
)
VRF2_AF = (
    "router bgp 4200000102 vrf vrf_shared2",
    "address-family l2vpn evpn",
)
VNI_CTX = (
    "router bgp 4200000102",
    "address-family l2vpn evpn",
    "vni 100",
)
DEFAULT_AF = (
    "router bgp 65000",
    "address-family l2vpn evpn",
)
VRF_CTX = ("vrf vrf1",)
ROUTE_MAP_CTX = ("route-map RM permit 10",)


def _text(blocks):
    return "\n".join(blocks)


def _config(reload, lines):
    config = reload.Config(None)
    config.lines = lines
    config.load_contexts()
    return config


def _evpn_lines(vrf, rts, as_num=65000):
    head = "router bgp %d" % as_num
    if vrf:
        head = "%s vrf %s" % (head, vrf)
    lines = [head, "address-family l2vpn evpn"]
    lines.extend(rts)
    lines.extend(["exit", "exit"])
    return lines


def _batch_entries(reload, entries):
    """Split a compare delta the same way frr-reload.py --reload does."""
    batch = []
    remain = []
    for ctx_keys, line in entries:
        if reload.delete_via_vtysh_file(ctx_keys, line):
            batch.append((ctx_keys, line))
        else:
            remain.append((ctx_keys, line))
    return batch, remain


def test_one_af_packs_import_and_export(reload):
    """One VRF EVPN AF; import and export pack onto separate RTLIST lines."""
    entries = [
        (VRF_AF, "route-target import 60005:1"),
        (VRF_AF, "route-target import 60005:2"),
        (VRF_AF, "route-target export 65000:1"),
    ]
    text = _text(reload.emit_grouped_config(entries, True))
    assert text.count("router bgp") == 1
    assert "no route-target import 60005:1 60005:2" in text
    assert "no route-target export 65000:1" in text
    assert "no route-target import 60005:1 60005:2 65000:1" not in text


def _import_lines(text):
    return [
        ln.strip()
        for ln in text.splitlines()
        if ln.strip().startswith("no route-target import")
    ]


def test_chunk_stays_under_argc_max(reload):
    """Split before CMD_ARGC_MAX so vtysh does not reject the batch file."""
    entries = [
        (VRF_AF, "route-target import 1:%d" % i)
        for i in range(1, reload.RT_LIST_CHUNK + 3)
    ]
    text = _text(reload.emit_grouped_config(entries, True))
    lines = _import_lines(text)
    assert len(lines) == 2
    first = lines[0].split()
    assert first[:3] == ["no", "route-target", "import"]
    assert len(first) == 3 + reload.RT_LIST_CHUNK

    # command_match() prepends a dummy token, so a command whose own token
    # count reaches CMD_ARGC_MAX (256) is rejected with "% Unknown command"
    # and vtysh abandons the whole batch file.
    for line in lines:
        assert len(line.split()) < 256


def test_field_scale_import_rt_chunks(reload):
    """1,536 field-scale import RTs stay in one AF as parse-safe RTLIST lines."""
    entries = [
        (VRF_AF, "route-target import {}:{}".format(asn, value))
        for asn in (60005, 60006, 65001)
        for value in range(102011, 102523)
    ]
    text = _text(reload.emit_grouped_config(entries, True))
    lines = _import_lines(text)
    emitted = [rt for line in lines for rt in line.split()[3:]]

    assert text.count("router bgp") == 1
    assert len(entries) == 1536
    assert len(lines) == 7
    assert emitted == [line[1].split()[-1] for line in entries]
    assert all(len(line.split()) < 256 for line in lines)


def test_chunk_stays_under_vty_bufsiz(reload):
    """Wide RT tokens hit the byte budget before the 252-token chunk."""
    wide = "4200000102:%d"
    entries = [
        (VRF_AF, "route-target import " + wide % i)
        for i in range(100000, 100000 + reload.RT_LIST_CHUNK)
    ]
    text = _text(reload.emit_grouped_config(entries, True))
    for line in _import_lines(text):
        assert len(line) <= reload.RT_LINE_MAX_BYTES


def test_auto_not_packed(reload):
    """'route-target import auto' is not an RT value and must not join an RTLIST."""
    entries = [
        (VRF_AF, "route-target import auto"),
        (VRF_AF, "route-target import 1:1"),
    ]
    text = _text(reload.emit_grouped_config(entries, True))
    assert "no route-target import 1:1" in text
    assert "no route-target import auto" in text
    assert "no route-target import auto 1:1" not in text
    assert "no route-target import 1:1 auto" not in text


def test_vni_context_not_packed(reload):
    """L2 VNI import RTs are not VRF RTLIST; keep one RT per line."""
    entries = [
        (VNI_CTX, "route-target import 1:1"),
        (VNI_CTX, "route-target import 1:2"),
    ]
    text = _text(reload.emit_grouped_config(entries, True))
    assert text.count("vni 100") == 1
    assert "no route-target import 1:1 1:2" not in text
    assert "no route-target import 1:1" in text
    assert "no route-target import 1:2" in text


def test_same_ctx_coalesces_interleaved_vrfs(reload):
    """First-seen ctx_keys coalesces later lines, so interleaved same-VRF RTs pack."""
    entries = [
        (VRF_AF, "route-target import 1:1"),
        (VRF2_AF, "route-target import 2:1"),
        (VRF_AF, "route-target import 1:2"),
    ]
    text = _text(reload.emit_grouped_config(entries, True))
    assert text.count("vrf vrf_shared1") == 1
    assert text.count("vrf vrf_shared2") == 1
    assert "no route-target import 1:1 1:2" in text
    assert text.index("vrf_shared1") < text.index("vrf_shared2")


def test_vrf_context_still_grouped(reload):
    """Non-RT VRF lines still share one vrf stanza (grouping is not RT-only)."""
    entries = [
        (VRF_CTX, "vni 4001"),
        (VRF_CTX, "vni 4002"),
    ]
    text = _text(reload.emit_grouped_config(entries, True))
    assert text.count("vrf vrf1") == 1
    assert " no vni 4001" in text
    assert " no vni 4002" in text


def test_route_map_group_closes_like_lines_to_config(reload):
    """Batching groups clauses in one stanza and closes with exit, matching lines_to_config."""
    entries = [
        (ROUTE_MAP_CTX, "set metric 10"),
        (ROUTE_MAP_CTX, "match tag 20"),
    ]
    text = _text(reload.emit_grouped_config(entries, True))
    assert text.count("route-map RM permit 10") == 1
    assert " no set metric 10" in text
    assert " no match tag 20" in text
    single = "\n".join(reload.lines_to_config(ROUTE_MAP_CTX, "set metric 10", True))
    assert single.rstrip().endswith("exit")
    assert text.rstrip().endswith("exit")


@pytest.mark.parametrize(
    "entry",
    [
        (VRF_CTX, "vni 4001"),
        (ROUTE_MAP_CTX, "set metric 10"),
        (ROUTE_MAP_CTX, None),
        (VNI_CTX, "route-target import 1:1"),
    ],
)
def test_single_non_rtlist_delete_matches_old_serializer(reload, entry):
    """Batching keeps lines_to_config output for every non-RTLIST entry shape."""
    expected = "\n".join(reload.lines_to_config(entry[0], entry[1], True)) + "\n"
    assert reload.emit_grouped_config([entry], True) == [expected]


def test_delete_packs_explicit_rts_then_auto_leftover(reload):
    """auto is leftover; explicit imports pack first, then leftover lines."""
    entries = [
        (VRF_AF, "route-target import 1:1"),
        (VRF_AF, "route-target import auto"),
        (VRF_AF, "route-target import 1:2"),
    ]
    text = _text(reload.emit_grouped_config(entries, True))
    assert "no route-target import 1:1 1:2" in text
    assert "no route-target import auto" in text
    assert "no route-target import auto 1:1" not in text
    assert text.index("1:1 1:2") < text.index("route-target import auto")


def test_add_symmetric_packing(reload):
    """Adds pack the same way as deletes, without a 'no' prefix."""
    entries = [
        (VRF_AF, "route-target import 60005:1"),
        (VRF_AF, "route-target import 60005:2"),
        (("router bgp 1",), "bgp router-id 1.1.1.1"),
    ]
    cmds = reload.emit_add_config(entries)
    text = "\n".join(cmds)
    assert "route-target import 60005:1 60005:2" in text
    assert "no route-target" not in text
    assert "bgp router-id 1.1.1.1" in text


@pytest.mark.parametrize(
    "entry",
    [
        (("no ipv6 forwarding",), None),
        (("ip route 192.0.2.0/24 192.0.2.1",), None),
        (("no ip prefix-list PL",), None),
        (("no bgp community-list standard CL",), None),
        (("router bgp 65000",), None),
        (("router bgp 65000",), "no bgp default ipv4-unicast"),
        (("router bgp 65000",), "bgp router-id 192.0.2.1"),
        (VRF_CTX, "vni 4001"),
        (VNI_CTX, "route-target import 1:1"),
        (VRF_AF, "route-target import auto"),
        (VRF_AF, "route-target import 1:1 1:2"),
    ],
)
def test_nonpackable_add_matches_old_serializer(reload, entry):
    """Every non-RTLIST add keeps the exact lines_to_config representation."""
    expected = "\n".join(reload.lines_to_config(entry[0], entry[1], False)) + "\n"
    assert reload.emit_add_config([entry]) == [expected]


def test_compare_context_only_adds_survive_emitter(reload):
    """Exercise real compare output, including its line=None representation."""
    target = _config(
        reload,
        [
            "no ipv6 forwarding",
            "ip route 192.0.2.0/24 192.0.2.1",
            "router bgp 65000",
            "no bgp default ipv4-unicast",
            "exit",
        ],
    )
    running = _config(reload, [])
    entries, _dels = reload.compare_context_objects(target, running)
    emitted = _text(reload.emit_add_config(entries))

    assert entries == [
        (("no ipv6 forwarding",), None),
        (("ip route 192.0.2.0/24 192.0.2.1",), None),
        (("router bgp 65000",), None),
        (("router bgp 65000",), "no bgp default ipv4-unicast"),
    ]
    assert emitted.count("no ipv6 forwarding") == 1
    assert emitted.count("ip route 192.0.2.0/24 192.0.2.1") == 1
    assert emitted.count("router bgp 65000") == 2
    assert emitted.count("no bgp default ipv4-unicast") == 1


def test_new_evpn_context_does_not_duplicate_packed_rts(reload):
    """New contexts must not turn one copy of each RT into duplicate RTLIST values."""
    target = _config(
        reload,
        [
            "router bgp 65000 vrf blue",
            "address-family l2vpn evpn",
            "route-target import 1:1",
            "route-target import 1:2",
            "exit",
            "exit",
        ],
    )
    entries, _dels = reload.compare_context_objects(target, _config(reload, []))
    text = _text(reload.emit_add_config(entries))

    assert text.count("route-target import 1:1 1:2") == 1
    assert "route-target import 1:1 1:1" not in text
    assert "route-target import 1:2 1:2" not in text


def test_add_packs_ctx_rts_at_first_rt_slot(reload):
    """All packable RTs of one VRF EVPN AF emit at the first RT slot."""
    entries = [
        (VRF_AF, "route-target import 1:1"),
        (VRF_AF, "advertise ipv4 unicast"),
        (VRF_AF, "route-target import 1:2"),
    ]
    text = _text(reload.emit_add_config(entries))
    assert "route-target import 1:1 1:2" in text
    assert text.index("1:1 1:2") < text.index("advertise ipv4 unicast")


def test_add_packs_explicit_rts_then_auto_slot(reload):
    """auto stays a non-RTLIST slot; explicit imports still pack at the first RT slot."""
    entries = [
        (VRF_AF, "route-target import 1:1"),
        (VRF_AF, "route-target import auto"),
        (VRF_AF, "route-target import 1:2"),
    ]
    text = _text(reload.emit_add_config(entries))
    assert "route-target import 1:1 1:2" in text
    assert "route-target import auto" in text
    assert text.index("1:1 1:2") < text.index("route-target import auto")


def test_adjacent_adds_still_pack(reload):
    """Adjacent same-AF import and export RTs pack onto separate RTLIST lines."""
    entries = [
        (VRF_AF, "route-target import 1:1"),
        (VRF_AF, "route-target import 1:2"),
        (VRF_AF, "route-target export 2:1"),
        (VRF_AF, "route-target export 2:2"),
    ]
    text = _text(reload.emit_add_config(entries))
    assert "route-target import 1:1 1:2" in text
    assert "route-target export 2:1 2:2" in text
    assert text.index("route-target import") < text.index("route-target export")


def test_fallback_still_one_rt(reload):
    """Per-line fallback uses lines_to_config, not RTLIST packing."""
    cmd = reload.lines_to_config(VRF_AF, "route-target import 1:1", True)
    text = "\n".join(cmd)
    assert "no route-target import 1:1" in text
    assert text.count("router bgp") == 1


def test_both_direction_packs_separately(reload):
    """import, export, and both stay on separate RTLIST commands."""
    entries = [
        (VRF_AF, "route-target both 3:1"),
        (VRF_AF, "route-target import 1:1"),
        (VRF_AF, "route-target export 2:1"),
        (VRF_AF, "route-target both 3:2"),
        (VRF_AF, "route-target import 1:2"),
    ]
    text = _text(reload.emit_grouped_config(entries, True))
    assert "no route-target import 1:1 1:2" in text
    assert "no route-target export 2:1" in text
    assert "no route-target both 3:1 3:2" in text
    assert text.index("route-target import") < text.index("route-target export")
    assert text.index("route-target export") < text.index("route-target both")


def test_leftover_non_rt_stays_after_packed_rts(reload):
    """Non-RT AF lines are leftover after the import/export/both buckets."""
    entries = [
        (VRF_AF, "rd 1:1"),
        (VRF_AF, "route-target import 1:1"),
        (VRF_AF, "route-target import 1:2"),
        (VRF_AF, "advertise ipv4 unicast"),
    ]
    text = _text(reload.emit_grouped_config(entries, True))
    assert "no route-target import 1:1 1:2" in text
    assert " no rd 1:1" in text
    assert " no advertise ipv4 unicast" in text
    assert text.index("1:1 1:2") < text.index("advertise ipv4 unicast")


def test_prepacked_rtlist_line_is_leftover(reload):
    """A line that is already an RTLIST is not packable (parse expects one value)."""
    entries = [
        (VRF_AF, "route-target import 1:1 1:2"),
        (VRF_AF, "route-target import 1:3"),
    ]
    text = _text(reload.emit_grouped_config(entries, True))
    assert "no route-target import 1:3" in text
    assert "no route-target import 1:1 1:2" in text
    assert "no route-target import 1:1 1:2 1:3" not in text


def test_wildcard_rt_is_packable(reload):
    """Wildcard tokens are RT values, not auto, so they join RTLIST."""
    parsed = reload.parse_rt_line("route-target import *:100")
    assert parsed == ("import", "*:100")
    text = _text(
        reload.emit_grouped_config(
            [
                (VRF_AF, "route-target import *:100"),
                (VRF_AF, "route-target import 1:1"),
            ],
            True,
        )
    )
    assert "no route-target import *:100 1:1" in text


def test_chunk_boundary_exactly_argc_max(reload):
    """RT_LIST_CHUNK values fit one command; one more splits."""
    n = reload.RT_LIST_CHUNK
    exact = [(VRF_AF, "route-target import 1:%d" % i) for i in range(n)]
    over = exact + [(VRF_AF, "route-target import 1:%d" % n)]
    exact_lines = _import_lines(_text(reload.emit_grouped_config(exact, True)))
    over_lines = _import_lines(_text(reload.emit_grouped_config(over, True)))
    assert len(exact_lines) == 1
    assert len(exact_lines[0].split()) == 3 + n
    assert len(over_lines) == 2
    assert len(over_lines[0].split()) == 3 + n
    assert over_lines[1].split()[-1] == "1:%d" % n


def test_vni_rt_is_batched_but_not_packed(reload):
    """L2 VNI RT deletes take the vtysh -f batch, but emit keeps one RT per line."""
    ctx = VNI_CTX
    assert reload.delete_via_vtysh_file(ctx, "route-target import 1:1")
    assert not reload.is_vrf_evpn_af(ctx)
    text = _text(
        reload.emit_grouped_config(
            [
                (ctx, "route-target import 1:1"),
                (ctx, "route-target import 1:2"),
            ],
            True,
        )
    )
    assert text.count("vni 100") == 1
    assert "no route-target import 1:1 1:2" not in text


@pytest.mark.parametrize(
    "ctx_keys, line, expect",
    [
        (("vrf vrf1",), "vni 4001", True),
        (("vrf vrf1",), None, False),
        (("route-map RM permit 10",), None, True),
        (("route-map RM permit 10",), "set metric 10", True),
        (VRF_AF, "route-target import 1:1", True),
        (DEFAULT_AF, "route-target import 1:1", True),
        (VNI_CTX, "route-target import 1:1", True),
        (("router bgp 1",), "bgp router-id 1.1.1.1", False),
        (("router bgp 1", "address-family ipv4 unicast"), "network 1.1.1.1/32", False),
        ((), "route-target import 1:1", False),
    ],
)
def test_delete_via_vtysh_file_gate(reload, ctx_keys, line, expect):
    """Only scaled VRF / route-map / RT line deletes use the vtysh -f batch."""
    assert reload.delete_via_vtysh_file(ctx_keys, line) is expect


def test_mixed_batch_keeps_rtlist_and_other_stanzas(reload):
    """One batch file can mix packed RTs, VRF VNI unsets, and whole route-map deletes."""
    entries = [
        (VRF_AF, "route-target import 1:1"),
        (VRF_AF, "route-target import 1:2"),
        (VRF_CTX, "vni 4001"),
        (ROUTE_MAP_CTX, None),
    ]
    blocks = reload.emit_grouped_config(entries, True)
    text = _text(blocks)
    assert "no route-target import 1:1 1:2" in text
    assert " no vni 4001" in text
    assert "no route-map RM permit 10" in text
    assert text.count("router bgp") == 1


def test_parse_rt_line_rejects_non_values(reload):
    assert reload.parse_rt_line(None) is None
    assert reload.parse_rt_line("route-target import auto") is None
    assert reload.parse_rt_line("advertise ipv4 unicast") is None
    assert reload.parse_rt_line("route-target import 1:1 1:2") is None
    assert reload.parse_rt_line("route-target import 1:1") == ("import", "1:1")
    assert reload.parse_rt_line("route-target export 2:1") == ("export", "2:1")
    assert reload.parse_rt_line("route-target both 3:1") == ("both", "3:1")


def test_is_vrf_evpn_af(reload):
    assert reload.is_vrf_evpn_af(VRF_AF)
    assert reload.is_vrf_evpn_af(DEFAULT_AF)
    assert not reload.is_vrf_evpn_af(VNI_CTX)
    assert not reload.is_vrf_evpn_af(("router bgp 1",))
    assert not reload.is_vrf_evpn_af(("vrf vrf1", "address-family l2vpn evpn"))


def test_default_instance_evpn_af_packs(reload):
    """Default-VRF EVPN AF is still a 2-tuple AF, so RTLIST packing applies."""
    entries = [
        (DEFAULT_AF, "route-target import 1:1"),
        (DEFAULT_AF, "route-target import 1:2"),
        (DEFAULT_AF, "route-target export 2:1"),
    ]
    text = _text(reload.emit_grouped_config(entries, True))
    assert reload.is_vrf_evpn_af(DEFAULT_AF)
    assert "no route-target import 1:1 1:2" in text
    assert "no route-target export 2:1" in text
    assert text.count("router bgp") == 1


def test_ipv4_addr_and_indented_rt_parse(reload):
    """CLI RT forms A.B.C.D:MN and indented running-config lines are packable."""
    assert reload.parse_rt_line("route-target import 10.1.1.1:99") == (
        "import",
        "10.1.1.1:99",
    )
    assert reload.parse_rt_line("  route-target export 65000:1") == (
        "export",
        "65000:1",
    )
    text = _text(
        reload.emit_grouped_config(
            [
                (VRF_AF, "  route-target import 10.1.1.1:99"),
                (VRF_AF, "route-target import *:100"),
            ],
            True,
        )
    )
    assert "no route-target import 10.1.1.1:99 *:100" in text


def test_byte_budget_splits_before_token_chunk(reload):
    """Oversized tokens split on RT_LINE_MAX_BYTES even when under RT_LIST_CHUNK."""
    wide = "a" * 500
    n = 30
    entries = [(VRF_AF, "route-target import %s:%d" % (wide, i)) for i in range(n)]
    lines = _import_lines(_text(reload.emit_grouped_config(entries, True)))
    emitted = [rt for line in lines for rt in line.split()[3:]]
    assert len(lines) > 1
    assert len(lines) < n
    assert emitted == ["%s:%d" % (wide, i) for i in range(n)]
    for line in lines:
        assert len(line) <= reload.RT_LINE_MAX_BYTES
        assert len(line.split()) < 256
        assert len(line.split()) - 3 < reload.RT_LIST_CHUNK


def test_single_rt_is_still_one_command(reload):
    """A one-value RTLIST is still valid CLI; packing does not skip n_rts == 1."""
    text = _text(
        reload.emit_grouped_config([(VRF_AF, "route-target import 1:1")], True)
    )
    assert "no route-target import 1:1" in text
    assert text.count("route-target import") == 1


def test_batch_gate_keeps_non_rt_bgp_on_per_line_path(reload):
    """Only RT lines under router bgp join the vtysh -f batch; other BGP stays per-line."""
    entries = [
        (VRF_AF, "route-target import 1:1"),
        (VRF_AF, "route-target import 1:2"),
        (("router bgp 4200000102 vrf vrf_shared1",), "bgp router-id 1.1.1.2"),
        (VRF_AF, "advertise ipv4 unicast"),
    ]
    batch, remain = _batch_entries(reload, entries)
    assert batch == entries[:2]
    assert remain == entries[2:]
    text = _text(reload.emit_grouped_config(batch, True))
    assert "no route-target import 1:1 1:2" in text
    assert "advertise" not in text
    assert "bgp router-id" not in text


def test_compare_delete_packs_rtlist(reload):
    """The real --reload delete delta packs import and export RTs in one AF."""
    running = _config(
        reload,
        _evpn_lines(
            "blue",
            [
                "route-target import 1:1",
                "route-target import 1:2",
                "route-target export 2:1",
                "route-target export 2:2",
            ],
        ),
    )
    target = _config(reload, _evpn_lines("blue", []))
    _adds, dels = reload.compare_context_objects(target, running)
    batch, remain = _batch_entries(reload, dels)
    text = _text(reload.emit_grouped_config(batch, True))

    assert remain == []
    assert "no route-target import 1:1 1:2" in text
    assert "no route-target export 2:1 2:2" in text
    assert text.count("router bgp") == 1
    assert "no route-target import 1:1 1:2 2:1" not in text


def test_compare_mixed_add_and_delete_packs(reload):
    """Keeping one RT while replacing the rest packs each direction's delta."""
    running = _config(
        reload,
        _evpn_lines(
            "blue",
            [
                "route-target import 1:1",
                "route-target import 1:2",
                "route-target import 1:3",
                "route-target export 2:1",
            ],
        ),
    )
    target = _config(
        reload,
        _evpn_lines(
            "blue",
            [
                "route-target import 1:3",
                "route-target import 1:4",
                "route-target import 1:5",
                "route-target export 2:1",
                "route-target export 2:2",
            ],
        ),
    )
    adds, dels = reload.compare_context_objects(target, running)
    del_text = _text(reload.emit_grouped_config(dels, True))
    add_text = _text(reload.emit_add_config(adds))

    assert "no route-target import 1:1 1:2" in del_text
    assert "no route-target import 1:3" not in del_text
    assert "route-target import 1:4 1:5" in add_text
    assert "route-target export 2:2" in add_text
    assert "route-target import 1:3" not in add_text


def test_compare_removed_af_still_packs_rts(reload):
    """Dropping the EVPN AF still emits per-line RT deletes, which pack."""
    running = _config(
        reload,
        _evpn_lines(
            "blue",
            ["route-target import 1:1", "route-target import 1:2"],
        ),
    )
    target = _config(reload, ["router bgp 65000 vrf blue", "exit"])
    _adds, dels = reload.compare_context_objects(target, running)
    batch, _remain = _batch_entries(reload, dels)
    text = _text(reload.emit_grouped_config(batch, True))
    assert "no route-target import 1:1 1:2" in text


def test_compare_two_vrfs_pack_independently(reload):
    """Each VRF EVPN AF gets its own packed stanza, first-seen order kept."""
    running = _config(
        reload,
        _evpn_lines("blue", ["route-target import 1:1", "route-target import 1:2"])
        + _evpn_lines("red", ["route-target import 2:1", "route-target import 2:2"]),
    )
    target = _config(
        reload,
        _evpn_lines("blue", []) + _evpn_lines("red", []),
    )
    _adds, dels = reload.compare_context_objects(target, running)
    text = _text(reload.emit_grouped_config(dels, True))
    assert "no route-target import 1:1 1:2" in text
    assert "no route-target import 2:1 2:2" in text
    assert text.count("router bgp") == 2
    assert text.index("vrf blue") < text.index("vrf red")


def test_vni_context_delete_is_not_vtysh_file_batched(reload):
    """Whole L2 VNI context deletes are line=None and stay on the per-line path."""
    running = _config(
        reload,
        [
            "router bgp 65000",
            "address-family l2vpn evpn",
            "vni 100",
            "route-target import 1:1",
            "exit",
            "exit",
            "exit",
        ],
    )
    target = _config(
        reload,
        [
            "router bgp 65000",
            "address-family l2vpn evpn",
            "exit",
            "exit",
        ],
    )
    _adds, dels = reload.compare_context_objects(target, running)
    batch, remain = _batch_entries(reload, dels)
    assert batch == []
    assert any(line is None and ctx[-1].startswith("vni ") for ctx, line in remain)
