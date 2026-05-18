#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
"""
audit_bgp_yang.py — gap audit between bgpd CLI commands and frr-bgp YANG schema.

For each DEFPY/DEFUN/DEFSH/ALIAS in bgpd/*.c, attempt to map its first config
keyword to a node in yang/frr-bgp*.yang. Emit a report of:

  - commands whose keyword path has no plausible YANG home (action: add leaf
    to YANG before writing NB callbacks)
  - YANG leaves with no obvious CLI mapping (informational; may be future
    work or operational-only)
  - rough coverage stats per CLI keyword family

This is a heuristic tool, not a proof. It surfaces the gaps a human needs to
look at. Re-run as new commands land — wire into CI in Phase 1+.

Usage:  python3 tools/audit_bgp_yang.py [--repo PATH] [--json]
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from collections import defaultdict
from pathlib import Path

# Files we audit on the CLI side.
BGPD_CLI_SOURCES = [
    "bgpd/bgp_vty.c",
    "bgpd/bgp_routemap.c",
    "bgpd/bgp_evpn_vty.c",
    "bgpd/bgp_rpki.c",
    "bgpd/bgp_bmp.c",
    "bgpd/bgp_flowspec_vty.c",
    "bgpd/bgp_debug.c",
    "bgpd/bgp_bfd.c",
    "bgpd/bgp_mplsvpn_vty.c",
]

# YANG files we treat as the BGP schema surface.
BGPD_YANG_SOURCES = [
    "yang/frr-bgp.yang",
    "yang/frr-bgp-common.yang",
    "yang/frr-bgp-common-structure.yang",
    "yang/frr-bgp-common-multiprotocol.yang",
    "yang/frr-bgp-neighbor.yang",
    "yang/frr-bgp-peer-group.yang",
    "yang/frr-bgp-types.yang",
    "yang/frr-bgp-route-map.yang",
    "yang/frr-bgp-filter.yang",
    "yang/frr-bgp-bmp.yang",
    "yang/frr-bgp-rpki.yang",
]

# DEF(PY|UN)[_YANG|_HIDDEN|_NOSH|_ATTR](?:_NOSH)? variants and ALIAS.
DEF_RX = re.compile(
    r"\b(?:DEFPY|DEFPY_YANG|DEFPY_HIDDEN|DEFPY_NOSH|DEFPY_YANG_NOSH|"
    r"DEFPY_YANG_HIDDEN|DEFUN|DEFUN_YANG|DEFUN_HIDDEN|DEFUN_NOSH|"
    r"DEFUN_YANG_NOSH|DEFSH|DEFSH_HIDDEN|ALIAS|ALIAS_YANG|ALIAS_HIDDEN)\b"
    r"\s*\(",
    re.MULTILINE,
)

# Keywords whose CLI commands are operational/exec and don't need YANG.
SHOW_PREFIXES = ("show", "clear", "debug", "no debug", "test", "dump")
# Operational/exec commands inside config mode that we still skip.
SKIP_FIRST_TOKENS = {"end", "exit", "quit", "write"}

# Map "first config keyword" -> expected owning YANG file/container family.
KEYWORD_FAMILY = {
    "router":              ("frr-bgp.yang",                   "router-bgp-entry"),
    "bgp":                 ("frr-bgp-common.yang",            "global/*"),
    "neighbor":            ("frr-bgp-neighbor.yang",          "neighbors/neighbor"),
    "no":                  ("(varies)",                       "delete-form"),
    "address-family":      ("frr-bgp.yang",                   "global/afi-safis/afi-safi"),
    "network":             ("frr-bgp-common-multiprotocol.yang", "afi-safi/network-config"),
    "aggregate-address":   ("frr-bgp-common-multiprotocol.yang", "afi-safi/aggregate"),
    "redistribute":        ("frr-bgp-common-multiprotocol.yang", "afi-safi/redistribute"),
    "maximum-paths":       ("frr-bgp-common-multiprotocol.yang", "afi-safi/use-multiple-paths"),
    "distance":            ("frr-bgp-common.yang",            "global/distance"),
    "timers":              ("frr-bgp-common.yang",            "global/timers"),
    "import":              ("frr-bgp-common.yang",            "global/import-export"),
    "export":              ("frr-bgp-common.yang",            "global/import-export"),
    "rd":                  ("frr-bgp-common.yang",            "afi-safi/rd"),
    "label":               ("frr-bgp-common.yang",            "afi-safi/label"),
    "rt":                  ("frr-bgp-common.yang",            "afi-safi/rt"),
    "rt6":                 ("frr-bgp-common.yang",            "afi-safi/rt"),
    "route-target":        ("frr-bgp-common.yang",            "afi-safi/rt"),
    "route-target6":       ("frr-bgp-common.yang",            "afi-safi/rt"),
    "route-map":           ("frr-bgp-route-map.yang",         "(top-level lib/route-map)"),
    "match":               ("frr-bgp-route-map.yang",         "match/*"),
    "set":                 ("frr-bgp-route-map.yang",         "set/*"),
    "bmp":                 ("frr-bgp-bmp.yang",               "bmp/*"),
    "rpki":                ("frr-bgp-rpki.yang",              "rpki/*"),
    "bfd":                 ("frr-bgp.yang",                   "neighbor/bfd"),
    "ip":                  ("(varies)",                       "ip community-list / etc."),
    "ipv6":                ("(varies)",                       "ipv6 prefix-list / etc."),
    "bgp-evpn":            ("frr-bgp.yang",                   "afi-safi[l2vpn-evpn]"),
    "evpn":                ("frr-bgp.yang",                   "afi-safi[l2vpn-evpn]"),
    "flowspec":            ("(needs YANG)",                   "flowspec config"),
    "srv6":                ("(needs YANG)",                   "srv6 config"),
    "vni":                 ("frr-bgp.yang",                   "afi-safi[l2vpn-evpn]/vni"),
}


def find_repo_root(start: Path) -> Path:
    """Walk up looking for the FRR repo marker."""
    cur = start.resolve()
    while cur != cur.parent:
        if (cur / "bgpd" / "bgp_vty.c").exists() and (cur / "yang" / "frr-bgp.yang").exists():
            return cur
        cur = cur.parent
    raise SystemExit("Could not locate FRR repo root from %s" % start)


def extract_commands(src: Path) -> list[tuple[str, int, str]]:
    """Return [(cmdname, lineno, cmdstr), ...] for every DEF* in `src`."""
    out = []
    text = src.read_text(encoding="utf-8", errors="replace")
    lines = text.splitlines(keepends=True)
    line_starts = [0]
    for ln in lines:
        line_starts.append(line_starts[-1] + len(ln))

    for m in DEF_RX.finditer(text):
        start = m.start()
        # Find line number for the macro.
        lineno = next(i for i, off in enumerate(line_starts) if off > start)
        # Walk forward to find the cmd struct name (first arg) and the
        # command-string (always the line beginning with '"' inside the
        # parens before the help text).
        paren_depth = 0
        i = m.end() - 1  # at the '('
        # Collect through matching close-paren.
        end = i
        while end < len(text):
            ch = text[end]
            if ch == "(":
                paren_depth += 1
            elif ch == ")":
                paren_depth -= 1
                if paren_depth == 0:
                    break
            end += 1
        chunk = text[i:end + 1]
        # First arg = cmdname (e.g. ip_route_blackhole)
        first_arg_match = re.search(r"\(\s*([A-Za-z0-9_]+)", chunk)
        cmdname = first_arg_match.group(1) if first_arg_match else "<unknown>"

        # First quoted string after the second '(', skipping help-strings.
        # Pattern: DEF*( name, name_cmd, "cmd string ...", "help" ...
        # We find quoted strings and pick the longest one whose first word is
        # a likely CLI keyword (heuristic: lowercase letter or '[' or 'no ').
        quoted = re.findall(r'"((?:\\.|[^"\\])*)"', chunk)
        cmdstr = ""
        for q in quoted:
            if not q:
                continue
            head = q.lstrip().split(" ", 1)[0].strip("[]<>")
            if not head:
                continue
            if head.lower() == head and re.match(r"[a-z]", head):
                # Picks first plausible. The "help string" for DEFUN/DEFPY
                # is always the longer-form sentence after the cmd-string.
                cmdstr = q
                break
        out.append((cmdname, lineno, cmdstr.strip()))
    return out


def first_keyword(cmdstr: str) -> list[str]:
    """Strip leading [no] / [optional] tokens to find the real first keyword(s).

    Returns a list of plausible first-keyword candidates: for `<a|b|c>`
    alternation the result is `["a","b","c"]`; for a plain word it's a
    single-element list. Callers should treat all candidates as the
    keywords this command could start with.
    """
    if not cmdstr:
        return []
    # Drop a leading `[no]`, `[no$name]`, `no$negate`, or `[no]$name` etc.
    s = cmdstr.strip()
    s = re.sub(r"^\[?\s*no(?:\$[a-z_]+)?\s*\]?(?:\$[a-z_]+)?\s*", "", s, count=1)
    # Drop a leading optional [...] group entirely.
    if s.startswith("["):
        depth = 0
        for i, ch in enumerate(s):
            if ch == "[":
                depth += 1
            elif ch == "]":
                depth -= 1
                if depth == 0:
                    s = s[i + 1:].lstrip()
                    break
    # Take first whitespace-delimited token.
    tok = s.split(None, 1)[0] if s else ""
    tok = tok.split("$", 1)[0]
    tok = tok.strip("{}")
    # If the token is an alternation `<a|b|c>`, return each alternative as
    # a separate keyword candidate (with any per-alt $name suffix stripped).
    if tok.startswith("<") and tok.endswith(">") and "|" in tok:
        inner = tok[1:-1]
        return [
            re.sub(r"\$[A-Za-z_]+$", "", alt).strip()
            for alt in inner.split("|")
            if alt.strip()
        ]
    # Otherwise plain word; strip remaining decoration.
    return [tok.strip("<>[]")]


def first_keyword_single(cmdstr: str) -> str:
    """Compatibility shim returning the first candidate."""
    kws = first_keyword(cmdstr)
    return kws[0] if kws else ""


def is_config_command(cmdstr: str) -> bool:
    """Heuristic: filter out show/clear/debug/test/dump."""
    if not cmdstr:
        return False
    s = cmdstr.strip().lower()
    for pfx in SHOW_PREFIXES:
        if s.startswith(pfx + " ") or s == pfx:
            return False
    kws = first_keyword(cmdstr)
    if any(tok in SKIP_FIRST_TOKENS for tok in kws):
        return False
    # Treat `debug` as operational even when not detected by SHOW_PREFIXES
    # (some `[no] debug ...` forms slip through because the cmd-string
    # begins with `[no]`).
    if kws and kws[0] == "debug":
        return False
    return True


def extract_yang_paths(yang_files: list[Path]) -> list[str]:
    """Return a flat list of fully-qualified node paths (best-effort)."""
    paths = []
    for f in yang_files:
        if not f.exists():
            continue
        text = f.read_text(encoding="utf-8", errors="replace")
        # Collect leaf / container / list / leaf-list / choice / grouping names.
        # This is a simple regex; lyang would be more correct but we want
        # zero extra deps for CI.
        node_rx = re.compile(
            r"\b(leaf|leaf-list|container|list|choice|grouping)\s+([A-Za-z0-9_\-]+)"
        )
        for m in node_rx.finditer(text):
            kind, name = m.group(1), m.group(2)
            paths.append(f"{f.name}::{kind} {name}")
    return paths


def extract_yang_node_names(yang_files: list[Path]) -> set[str]:
    """Return the set of YANG node *short names* (leaf/list/container/etc.).

    Used to detect "the CLI keyword exists in the YANG schema under some
    name" — a weaker signal than full path matching but catches the
    common-case false positives in keyword bucketing.
    """
    names: set[str] = set()
    node_rx = re.compile(
        r"\b(?:leaf|leaf-list|container|list|choice|grouping)\s+"
        r"([A-Za-z0-9_\-]+)"
    )
    for f in yang_files:
        if not f.exists():
            continue
        text = f.read_text(encoding="utf-8", errors="replace")
        for m in node_rx.finditer(text):
            names.add(m.group(1))
    return names


# Aliases: CLI keyword -> set of plausible YANG node names. Used to forgive
# keyword/leaf naming differences (e.g. `update-delay` cmd -> `update-delay-time`
# leaf). Add entries here as they're confirmed.
KEYWORD_ALIASES: dict[str, set[str]] = {
    "update-delay":          {"update-delay", "update-delay-time"},
    "advertisement-delay":   {"advertisement-delay", "advertise-interval"},
    "coalesce-time":         {"coalesce-time"},
    "read-quanta":           {"read-quanta", "rpkt-quanta"},
    "write-quanta":          {"write-quanta", "wpkt-quanta"},
    "nexthop":               {"nexthop", "next-hop", "next-hops"},
    "import":                {"import", "import-policy"},
    "export":                {"export", "export-policy"},
    "route-target":          {"route-target", "route-targets", "rt-list"},
    "rt|route-target":       {"route-target", "route-targets"},
    "advertise-all-vni":     {"advertise-all-vni"},
    "advertise-svi-ip":      {"advertise-svi-ip"},
    "advertise-default-gw":  {"advertise-default-gw"},
    "advertise-subnet":      {"advertise-subnet"},
    "advertise-pip":         {"advertise-pip"},
    "advertise":             {"advertise", "ipv4-unicast", "ipv6-unicast"},
    "default-originate":     {"default-originate"},
    "autort":                {"autort", "autort-rfc8365-compatible"},
    "dup-addr-detection":    {"dup-addr-detection",
                              "duplicate-address-detection",
                              "max-moves", "freeze-time", "freeze-permanent"},
    "flooding":              {"flooding"},
    "mac-vrf":               {"mac-vrf-soo"},
    "ead-es-frag":           {"ead-es-frag", "ead-es-fragmentation",
                              "fragmentation", "evi-limit"},
    "ead-es-route-target":   {"ead-es-route-target", "route-target-export"},
    "disable-ead-evi-rx":    {"disable-ead-evi-rx"},
    "disable-ead-evi-tx":    {"disable-ead-evi-tx"},
    "use-es-l3nhg":          {"use-es-l3nhg"},
    "enable-resolve-overlay-index": {"enable-resolve-overlay-index"},
    "encap-behavior":        {"encap-behavior"},
    "segment-routing":       {"segment-routing", "srv6"},
    "srv6-only":             {"srv6-only"},
    "locator":               {"locator", "locator-name"},
    "sid":                   {"sid", "export-mode", "export-index", "export-value"},
    "encap-behavior":        {"encap-behavior"},
    "exit-vni":              set(),         # context-exit, no YANG home
    "exit-address-family":   set(),         # context-exit, no YANG home
    "mpls":                  {"mpls", "mpls-forwarding",
                              "mpls-l3vpn-multi-domain-switching"},
    "distribute":            {"distribute"},
    "local-install":         {"local-install", "local-install-interface"},
    "test":                  set(),         # test-* commands are not config
    "router":                {"control-plane-protocol", "bgp"},
    "match":                 set(),         # always under route-map
    "set":                   set(),         # always under route-map
    # Phase 0a additions to global-bgp-config (2026-05-17):
    "minimum-holdtime":      {"minimum-holdtime"},
    "fast-convergence":      {"fast-convergence"},
    "allow-martian-nexthop": {"allow-martian-nexthop"},
    "use-underlays-nexthop-weight": {"use-underlays-nexthop-weight"},
    "distribute":            {"bgp-ls-distribute"},
    # BMP `[no] <ip|ipv6> access-list ...` alternation — both alts map
    # to the same access-list-name leaf in frr-bgp-bmp.yang.
    "ip":                    {"access-list-name", "access-list"},
    "ipv6":                  {"access-list-name", "access-list"},
    # L3VPN `<rt|route-target>`, `<import|export>`, etc. — alternations
    # for the same underlying route-target leaves.
    "rt":                    {"route-target", "route-targets"},
    "route-target":          {"route-target", "route-targets"},
    "route-target6":         {"route-target", "route-targets"},
    "rt6":                   {"route-target", "route-targets"},
    "import":                {"import", "import-export"},
    "export":                {"export", "import-export"},
}


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--repo", default=str(Path(__file__).resolve().parent.parent),
                    help="path to FRR repo root")
    ap.add_argument("--json", action="store_true",
                    help="emit machine-readable JSON report instead of human text")
    args = ap.parse_args()

    repo = find_repo_root(Path(args.repo))

    # ---- Collect CLI commands ----
    all_cmds = []
    per_file = {}
    for rel in BGPD_CLI_SOURCES:
        p = repo / rel
        if not p.exists():
            per_file[rel] = {"total": 0, "config": 0, "skipped": 0, "missing_file": True}
            continue
        cmds = extract_commands(p)
        total = len(cmds)
        config = [(n, ln, s) for (n, ln, s) in cmds if is_config_command(s)]
        per_file[rel] = {
            "total": total,
            "config": len(config),
            "skipped": total - len(config),
        }
        for n, ln, s in config:
            all_cmds.append({"file": rel, "lineno": ln, "name": n, "cmdstr": s,
                             "first_kw": first_keyword(s)})

    # ---- Bucket by first keyword (one bucket per alternative) ----
    by_kw = defaultdict(list)
    for c in all_cmds:
        kws = c["first_kw"] or ["<empty>"]
        for kw in kws:
            by_kw[kw].append(c)

    unknown_kw = sorted(k for k in by_kw if k not in KEYWORD_FAMILY and k != "<empty>")

    # ---- Collect YANG nodes ----
    yang_files = [repo / y for y in BGPD_YANG_SOURCES]
    yang_paths = extract_yang_paths(yang_files)
    yang_names = extract_yang_node_names(yang_files)

    # ---- True gaps: keywords NOT in KEYWORD_FAMILY AND no plausible YANG node name ----
    true_gaps = []
    forgiven = []
    for kw in unknown_kw:
        candidates = KEYWORD_ALIASES.get(kw, {kw})
        if not candidates:
            forgiven.append((kw, "exit/test/context-only — no YANG node expected"))
            continue
        hit = candidates & yang_names
        if hit:
            forgiven.append((kw, f"YANG node(s) present: {sorted(hit)}"))
        else:
            true_gaps.append((kw, sorted(candidates)))

    # ---- Build report ----
    report = {
        "repo": str(repo),
        "summary": {
            "cli_files_scanned":   len(BGPD_CLI_SOURCES),
            "yang_files_scanned":  len(BGPD_YANG_SOURCES),
            "total_config_cmds":   len(all_cmds),
            "yang_nodes":          len(yang_paths),
            "unknown_keywords":    len(unknown_kw),
            "forgiven_after_alias":len(forgiven),
            "true_yang_gaps":      len(true_gaps),
        },
        "forgiven_keywords": [{"keyword": k, "reason": r} for k, r in forgiven],
        "true_yang_gaps": [{"keyword": k, "candidate_yang_names": cands}
                           for k, cands in true_gaps],
        "per_file": per_file,
        "by_keyword": {
            kw: {
                "count": len(items),
                "expected_owner": KEYWORD_FAMILY.get(kw, ("(unmapped)", "(unmapped)")),
                "examples": [
                    {"file": it["file"], "lineno": it["lineno"], "cmdstr": it["cmdstr"]}
                    for it in items[:3]
                ],
            }
            for kw, items in sorted(by_kw.items(), key=lambda kv: -len(kv[1]))
        },
        "unknown_keywords": unknown_kw,
    }

    if args.json:
        json.dump(report, sys.stdout, indent=2)
        print()
        return 0 if not unknown_kw else 1

    # Human-friendly text report.
    s = report["summary"]
    print(f"# bgpd YANG audit report")
    print(f"repo: {report['repo']}")
    print()
    print(f"CLI files scanned : {s['cli_files_scanned']}")
    print(f"YANG files scanned: {s['yang_files_scanned']}")
    print(f"Config commands   : {s['total_config_cmds']}")
    print(f"YANG nodes        : {s['yang_nodes']}")
    print(f"Unknown keywords  : {s['unknown_keywords']}")
    print()
    print("## Per-file CLI tallies")
    for f, info in per_file.items():
        if info.get("missing_file"):
            print(f"  {f:36s}  (not present in tree)")
        else:
            print(f"  {f:36s}  total={info['total']:4d}  config={info['config']:4d}  "
                  f"skipped={info['skipped']:4d}")
    print()
    print("## Top keyword families")
    for kw, info in list(report["by_keyword"].items())[:25]:
        owner = info["expected_owner"]
        owner_str = f"{owner[0]} :: {owner[1]}"
        print(f"  {kw:24s} count={info['count']:4d}   owner={owner_str}")
    print()
    if forgiven:
        print("## Keywords forgiven after YANG-name lookup")
        print(f"({len(forgiven)} keyword(s) had no entry in KEYWORD_FAMILY but matched"
              " a YANG node name via KEYWORD_ALIASES.)")
        for kw, reason in forgiven:
            print(f"  {kw:30s}  {reason}")
        print()

    if true_gaps:
        print("## True YANG schema gaps")
        print("These CLI keywords have no matching YANG leaf/container/list.")
        print("Phase 2+ must close these before writing NB callbacks.")
        for kw, cands in true_gaps:
            items = by_kw[kw]
            print(f"  {kw!r:30s} ({len(items)} cmd(s); searched: {cands})")
            for it in items[:2]:
                print(f"      {it['file']}:{it['lineno']}  {it['cmdstr']!r}")
        return 1
    print("OK: no true YANG schema gaps.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
