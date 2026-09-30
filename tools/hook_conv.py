#!/usr/bin/python3
# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright (c) 2026  David Lamparter for NetDEF, Inc.
"""
Flips the "cardinality" of DEFINE_HOOK/DECLARE_HOOK parameters.

Before:
    DECLARE_HOOK(foo, (int a, char *b), (a, b));
After:
    DECLARE_HOOK(foo, (int, a), (char *, b));

It won't be useful to rerun this script, it's just provided for posterity.
"""

import sys
import os
import re
from dataclasses import dataclass, field
import subprocess
import argparse
from pprint import pprint
import _clippy

cmdargp = argparse.ArgumentParser(description="FRR hook rewriting tool")
cmdargp.add_argument("--verbose", "-v", action="store_true")
cmdargp.add_argument("--nosplit", "-n", action="store_true")
cmdargp.add_argument("--git-add", "-G", action="store_true")
cmdargs = cmdargp.parse_args()


def git(*args) -> str:
    return subprocess.check_output(["git"] + list(args), encoding="UTF-8")


class CPPStack(list):
    def __init__(self, *args):
        super().__init__(*args)
        self.ignored_header_guard = False

    def feed(self, pp_token, filename):
        line = pp_token["line"].strip()
        directive_args = line.split(maxsplit=1)

        if not directive_args:
            return
        directive = directive_args[0]
        if directive in ["if", "ifdef", "ifndef"]:
            if filename.endswith(".h") and not self and not self.ignored_header_guard:
                macro_name = filename.upper().rsplit("/", 1)[-1].replace(".", "_")
                fudges = {"LIBFRR_H": "FRR_H", "SMUX_H": "SNMP_H", "RIPD_H": "RIP_H"}
                macro_name = fudges.get(macro_name, macro_name)
                macro_names = [macro_name]
                for m in macro_names[:]:
                    macro_names.append(m + "_")
                    macro_names.append(m + "__")
                if line.endswith(tuple(macro_names)):
                    self.ignored_header_guard = True
                    return
                assert False, f"header guard problem in {filename}"
            self.append(line)
        elif directive in ["elif", "else"]:
            prev_line = self.pop(-1)
            self.append(prev_line + "\n" + line)
        elif directive in ["endif"]:
            if self.ignored_header_guard and not self:
                self.ignored_header_guard = False
            else:
                self.pop(-1)

    def copy(self):
        return CPPStack(self)

    def output(self, prev_stack: CPPStack) -> bytes:
        out = []
        for _ in prev_stack[len(self) :]:
            out.insert(0, "#endif\n")
        same_until = 0
        for i, (prev, this) in enumerate(zip(prev_stack, self)):
            if prev != this:
                break
            same_until = i
        for _ in prev_stack[same_until : len(self)]:
            out.insert(0, "#endif\n")
        for cond in self[same_until:]:
            out.append("#" + cond.replace("\n", "\n#") + "\n")
        prev_stack[:] = self[:]
        return "".join(out).encode("UTF-8")


@dataclass
class Item:
    filename: str
    lineno: int
    hookname: str
    raw_argspec: str
    cpp_stack: CPPStack
    comments: list[bytes] = field(default_factory=list)
    replacement: bytes | None = None

    @property
    def loc(self):
        return f"{self.filename}:{self.lineno}"

    def to_bytes(self, prev_stack: CPPStack) -> bytes:
        return (
            b"\n"
            + self.cpp_stack.output(prev_stack)
            + b"".join(line + b"\n" for line in self.comments)
            + self.replacement
            + b";\n"
        )


@dataclass
class SplitFile:
    filename: str
    orig_filename: str
    spdx: str
    hooks: list[Item] = field(default_factory=list)
    decl_from: str | None = None


spdx_re = re.compile(
    rb"""SPDX-License-Identifier:[ \t]*(?P<license>[0-9a-zA-Z-. \t]+)[ \t]*(?:\*[ \t]*)?$""",
    flags=re.MULTILINE,
)
line_comment_re = re.compile(rb"""^\s*//.*""")
comment_start_re = re.compile(rb"""^\s*/\*""")
comment_end_re = re.compile(rb"""\*/\s*$""")

os.chdir(git("rev-parse", "--show-toplevel").removesuffix("\n"))

all_hooks: dict[str, dict[str, Item]] = {}
decl_def_map: dict[str, list[str]] = {}
split_files: dict[str, list[bytes]] = {}
nosplit: set(str) = set()


def file_order(filename):
    if filename.startswith("tests/"):
        return (4, filename)
    if filename.endswith(".c"):
        return (1, filename)
    if filename == "bgpd/bgpd.h":
        return (2, filename)
    if filename.endswith(".h"):
        return (3, filename)
    return (0, filename)


hookfiles = git("grep", "-lE", "(DEFINE|DECLARE)_(HOOK|KOOH)").splitlines()
hookfiles.sort(key=file_order)
for filename in hookfiles:
    if filename.rsplit(".")[-1] not in ["c", "h"]:
        sys.stderr.write(f"ignoring {filename}, not a C file\n")
        continue
    if filename in ["lib/hooks_begin.h", "lib/hooks_end.h"]:
        continue

    with open(filename, "rb") as fd:
        rawdata = fd.read()

    spdx_m = spdx_re.search(rawdata)
    assert spdx_m is not None, f"no license ID in {filename}!"
    spdx = spdx_m.group("license").decode("UTF-8")

    cpp_stack = CPPStack()
    fparse = _clippy.parse(filename)
    tokens = fparse["data"]
    replacements = []
    splitfiles_decl = set()
    splitfiles_def = set()
    while tokens:
        token = tokens.pop(0)
        if token["type"] == "PREPROC":
            cpp_stack.feed(token, filename)
        if token["type"] != "HOOK":
            continue
        loc = f"{filename}:{token["lineno"]}"

        if len(token["args"]) != 3:
            sys.stderr.write(
                f"{loc}: HOOK macro with {len(token["args"])} args.\n"
                + "Has this script already been run?  Aborting.\n"
            )
            sys.exit(1)

        assert len(token["args"][0]) == 1
        assert len(token["args"][1]) >= 2
        assert token["args"][1][0] == "(" and token["args"][1][-1] == ")"
        assert len(token["args"][2]) >= 2
        assert token["args"][2][0] == "(" and token["args"][2][-1] == ")"

        hookname = token["args"][0][0]
        which = "def" if token["value"].startswith("DEFINE_") else "decl"

        argspec = token["args"][1][1:-1]

        argtmp = token["args"][2][1:-1]
        argnames = argtmp[0::2]
        assert set(argtmp[1::2]) <= set([","])

        all_hook = all_hooks.setdefault(hookname, {})
        if not filename.startswith("tests/"):
            raw_argspec = " ".join(argspec)
            item = Item(
                filename, token["lineno"], hookname, raw_argspec, cpp_stack.copy()
            )
            if which in all_hook:
                sys.stderr.write(
                    f"{loc}: \033[91mduplicate {which} for {hookname}, previous one in {all_hook[which].loc}\033[m\n"
                )
            else:
                all_hook[which] = item

            if all_hook.get("def", item).raw_argspec != raw_argspec:
                sys.stderr.write(
                    f"{loc}: \033[91m{hookname} mismatch with existing definition @ {all_hook["def"].loc}\033[m\n"
                )
                continue
            if all_hook.get("decl", item).raw_argspec != raw_argspec:
                sys.stderr.write(
                    f"{loc}: \033[91m{hookname} mismatch with existing declaration @ {all_hook["decl"].loc}\033[m\n"
                )
                continue

            if "def" in all_hook and "decl" in all_hook:
                decl_def_map.setdefault(all_hook["decl"].filename, set()).add(
                    all_hook["def"].filename
                )

        if "def" not in all_hook:
            sys.stderr.write(
                f"{loc}: \033[91mhaven't seen definition for {hookname} yet!\033[m\n"
            )
            nosplit.add(hookname)
            nosplit_this = True
        elif filename.startswith("tests/"):
            nosplit_this = True
        else:
            nosplit_this = cmdargs.nosplit or hookname in nosplit
            split_filename = all_hook["def"].filename.removesuffix(".c") + "_hooks.h"

        args = {}
        i = 0
        while argspec:
            if i >= len(argnames):
                sys.stderr.write(
                    f"{loc}: \033[91m{hookname} missing arg-pass name\033[m\n"
                )
                i = None
                break

            arg = {
                "name": argnames[i],
                "decl": [],
            }
            args[i] = arg
            i += 1

            braces = 0
            while argspec and (argspec[0] != "," or braces > 0):
                argtoken = argspec.pop(0)
                arg["decl"].append(argtoken)
                if argtoken in ["(", "[", "{"]:
                    braces += 1
                elif argtoken in [")", "]", "}"]:
                    braces -= 1

            assert braces == 0
            if argspec:
                assert argspec.pop(0) == ","

            if arg["decl"][-1] != arg["name"]:
                sys.stderr.write(
                    f"{loc}: \033[91m{hookname} argument declaration/name mismatch\033[m\n"
                )
            arg["declstr"] = " ".join(arg["decl"][:-1])

        if i is None:
            continue
        if len(args) != len(argnames):
            sys.stderr.write(
                f"{loc}: \033[91m{hookname} malformed argument list\033[m\n"
            )
            continue

        if cmdargs.verbose:
            sys.stderr.write(
                f"{loc}: {hookname} {token["args"][0][0]} ({", ".join(argnames)})\n"
            )
            rawdef = rawdata[token["start"] : token["end"]].decode("UTF-8")
            sys.stderr.write(
                f"{token["start"]}->{token["end"]}:\n\033[100m{rawdef}\033[94m%%\033[K\033[m\n"
            )
            pprint(args)

        ilen = len(token["value"]) + 1
        indent = "\t" * (ilen // 8) + " " * (ilen % 8)
        replacement = []
        replacement.append(f"{token["value"]}({hookname}")
        for idx, arg in args.items():
            replacement.append(f",\n{indent}({arg["declstr"]}, {arg["name"]})")
        replacement.append(")")
        replacement = "".join(replacement).encode("UTF-8")

        if nosplit_this:
            replacements.insert(0, (token["start"], token["end"], replacement))
        else:
            start = token["start"]
            end = token["end"] + 1
            assert rawdata[end - 1 : end] == b";"
            while rawdata[end : end + 1] == b"\n":
                end += 1

            start -= 1
            assert rawdata[start : start + 1] == b"\n"
            scan_start = start
            prev_start = None
            in_comment = False
            comment_lines = []
            while scan_start != prev_start:
                prev_start = scan_start

                line_start = rawdata.rfind(b"\n", 0, scan_start)
                line = rawdata[line_start + 1 : scan_start]
                if comment_end_re.search(line):
                    in_comment = True
                if in_comment:
                    comment_lines.insert(0, line)
                    start = line_start
                    if comment_start_re.search(line):
                        in_comment = False
                elif line != b"":
                    break

                scan_start = line_start

            assert rawdata[start : start + 1] == b"\n"
            start += 1

            all_hook["def"].comments.extend(comment_lines)
            text = b""

            if replacements:
                prev_s, prev_e, prev_text = replacements[0]
                if prev_e == start:
                    start = prev_s
                    text = prev_text
                    replacements.pop(0)

            replacements.insert(0, (start, end, text))
            if which == "decl":
                sf = split_files[split_filename]
                if sf.decl_from is not None and sf.decl_from != filename:
                    sys.stderr.write(
                        f"{loc}: \033[91m{hookname}: {split_filename} decls already in {sf.decl_from}, not duplicating in {filename}\033[m\n"
                    )
                else:
                    sf.decl_from = filename
                    splitfiles_decl.add(split_filename)
            else:
                splitfiles_def.add(split_filename)
                sf = split_files.setdefault(
                    split_filename, SplitFile(split_filename, filename, spdx)
                )
                replacement = b"DO_" + replacement.removeprefix(b"DEFINE_")
                assert item.replacement in [None, replacement]
                item.replacement = replacement
                sf.hooks.append(item)

    if splitfiles_decl or splitfiles_def:
        if filename.endswith(".h"):
            hookpos = 0
        else:
            hookpos = -1

        start, end, text = replacements[hookpos]
        if rawdata[start - 2 : start - 1] != b"\n":
            text = b"\n" + text
        if rawdata[start - 3 : start - 1] == b"\n\n":
            start -= 1
        if splitfiles_decl:
            incls = "".join(
                f"""#include "{filename}"\n""" for filename in sorted(splitfiles_decl)
            ).encode("UTF-8")
            text = (
                text
                + b"""#define HOOKS_DECLARE\n#include "lib/hooks_begin.h"\n"""
                + incls
                + b"""#include "lib/hooks_end.h"\n\n"""
            )
        if splitfiles_def:
            incls = "".join(
                f"""#include "{filename}"\n""" for filename in sorted(splitfiles_def)
            ).encode("UTF-8")
            text = (
                text
                + b"""#define HOOKS_DEFINE\n#include "lib/hooks_begin.h"\n"""
                + incls
                + b"""#include "lib/hooks_end.h"\n\n"""
            )
        replacements[hookpos] = start, end, text

    for start, end, text in replacements:
        rawdata = rawdata[:start] + text + rawdata[end:]

    with open(filename, "wb") as fd:
        fd.write(rawdata)

    if cmdargs.git_add:
        git("add", filename)

for header, sources in decl_def_map.items():
    if len(sources) > 1:
        sys.stderr.write(
            f"note: hooks declared in {header} definitions spread over multiple source files:\n\t{"\n\t".join(sorted(sources))}\n"
        )

for sf in split_files.values():
    prev_stack = CPPStack()
    with open(sf.filename, "wb") as fd:
        fd.write(f"""// SPDX-License-Identifier: {sf.spdx}
/* hook definitions for {sf.orig_filename}
 *
 * note: file may be included multiple times - intentionally no include guard!
 */
""".encode("UTF-8"))
        fd.write(b"".join(hook.to_bytes(prev_stack) for hook in sf.hooks))
        fd.write(CPPStack().output(prev_stack))

    if cmdargs.git_add:
        git("add", sf.filename)
