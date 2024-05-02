# SPDX-License-Identifier: GPL-2.0-or-later
# FRR ELF xref extractor
#
# Copyright (C) 2020  David Lamparter for NetDEF, Inc.

import sys
import os
import struct
import re
import traceback

json_dump_args = {}

try:
    import ujson as json

    json_dump_args["escape_forward_slashes"] = False
except ImportError:
    import json

import argparse

from clippy.uidhash import uidhash
from clippy.elf import *
from clippy import frr_top_src, CmdAttr, elf_notes
from tiabwarfo import FieldApplicator
from xref2vtysh import CommandEntry

try:
    with open(os.path.join(frr_top_src, "python", "xrefstructs.json"), "r") as fd:
        xrefstructs = json.load(fd)
except FileNotFoundError:
    sys.stderr.write(
        """
The "xrefstructs.json" file (created by running tiabwarfo.py with the pahole
tool available) could not be found.  It should be included with the sources.
"""
    )
    sys.exit(1)

# constants, need to be kept in sync manually...

XREFT_EVENTSCHED = 0x100
XREFT_LOGMSG = 0x200
XREFT_DEFUN = 0x300
XREFT_INSTALL_ELEMENT = 0x301

# LOG_*
priovals = {}
prios = ["0", "1", "2", "E", "W", "N", "I", "D"]


class XrelfoJson(object):
    def dump(self):
        pass

    def check(self, wopt):
        yield from []

    def to_dict(self, refs):
        pass


class Xref(ELFDissectStruct, XrelfoJson):
    struct = "xref"
    fieldrename = {"type": "typ"}
    containers = {}

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        self._container = None
        if self.xrefdata:
            self.xrefdata.ref_from(self, self.typ)

    def container(self):
        if self._container is None:
            if self.typ in self.containers:
                self._container = self.container_of(self.containers[self.typ], "xref")
        return self._container

    def check(self, *args, **kwargs):
        if self._container:
            yield from self._container.check(*args, **kwargs)


class Xrefdata(ELFDissectStruct):
    struct = "xrefdata"

    # uid is all zeroes in the data loaded from ELF
    fieldrename = {"uid": "_uid"}

    def ref_from(self, xref, typ):
        self.xref = xref

    @property
    def uid(self):
        if self.hashstr is None:
            return None
        return uidhash(self.xref.file, self.hashstr, self.hashu32_0, self.hashu32_1)


class XrefPtr(ELFDissectStruct):
    fields = [
        ("xref", "P", Xref),
    ]


class XrefThreadSched(ELFDissectStruct, XrelfoJson):
    struct = "xref_threadsched"


Xref.containers[XREFT_EVENTSCHED] = XrefThreadSched


class XrefLogmsg(ELFDissectStruct, XrelfoJson):
    struct = "xref_logmsg"

    def _warn_fmt(self, text):
        lines = text.split("\n")
        yield (
            (self.xref.file, self.xref.line),
            "%s:%d: %s (in %s())%s\n"
            % (
                self.xref.file,
                self.xref.line,
                lines[0],
                self.xref.func,
                "".join(["\n" + l for l in lines[1:]]),
            ),
        )

    fmt_regexes = [
        (re.compile(r"([\n\t]+)"), "error: log message contains tab or newline"),
        #    (re.compile(r'^(\s+)'),   'warning: log message starts with whitespace'),
        (
            re.compile(r"^((?:warn(?:ing)?|error):\s*)", re.I),
            "warning: log message starts with severity",
        ),
    ]
    arg_regexes = [
        # the (?<![\?:] ) avoids warning for x ? inet_ntop(...) : "(bla)"
        (
            re.compile(r"((?<![\?:] )inet_ntop\s*\(\s*(?:[AP]F_INET|2)\s*,)"),
            "cleanup: replace inet_ntop(AF_INET, ...) with %pI4",
            lambda s: True,
        ),
        (
            re.compile(r"((?<![\?:] )inet_ntop\s*\(\s*(?:[AP]F_INET6|10)\s*,)"),
            "cleanup: replace inet_ntop(AF_INET6, ...) with %pI6",
            lambda s: True,
        ),
        (
            # string split-up here is to not trigger "inet_ntoa forbidden"
            re.compile(r"((?<![\?:] )inet_" + r"ntoa)"),
            "cleanup: replace inet_" + "ntoa(...) with %pI4",
            lambda s: True,
        ),
        (
            re.compile(r"((?<![\?:] )ipaddr2str)"),
            "cleanup: replace ipaddr2str(...) with %pIA",
            lambda s: True,
        ),
        (
            re.compile(r"((?<![\?:] )prefix2str)"),
            "cleanup: replace prefix2str(...) with %pFX",
            lambda s: True,
        ),
        (
            re.compile(r"((?<![\?:] )prefix_mac2str)"),
            "cleanup: replace prefix_mac2str(...) with %pEA",
            lambda s: True,
        ),
        (
            re.compile(r"((?<![\?:] )sockunion2str)"),
            "cleanup: replace sockunion2str(...) with %pSU",
            lambda s: True,
        ),
        #   (re.compile(r'^(\s*__(?:func|FUNCTION|PRETTY_FUNCTION)__\s*)'), 'error: debug message starts with __func__', lambda s: (s.priority & 7 == 7) ),
    ]

    def check(self, wopt):
        def fmt_msg(rex, itext):
            if sys.stderr.isatty():
                items = rex.split(itext)
                out = []
                for i, text in enumerate(items):
                    if (i % 2) == 1:
                        out.append("\033[41;37;1m%s\033[m" % repr(text)[1:-1])
                    else:
                        out.append(repr(text)[1:-1])

                excerpt = "".join(out)
            else:
                excerpt = repr(itext)[1:-1]
            return excerpt

        if wopt.Wlog_format:
            for rex, msg in self.fmt_regexes:
                if not rex.search(self.fmtstring):
                    continue

                excerpt = fmt_msg(rex, self.fmtstring)
                yield from self._warn_fmt('%s: "%s"' % (msg, excerpt))

        if wopt.Wlog_args:
            for rex, msg, cond in self.arg_regexes:
                if not cond(self):
                    continue
                if not rex.search(self.args):
                    continue

                excerpt = fmt_msg(rex, self.args)
                yield from self._warn_fmt(
                    '%s:\n\t"%s",\n\t%s' % (msg, repr(self.fmtstring)[1:-1], excerpt)
                )

    def dump(self):
        print(
            "%-60s %s%s %-25s [EC %d] %s"
            % (
                "%s:%d %s()" % (self.xref.file, self.xref.line, self.xref.func),
                prios[self.priority & 7],
                priovals.get(self.priority & 0x30, " "),
                self.xref.xrefdata.uid,
                self.ec,
                self.fmtstring,
            )
        )

    def to_dict(self, xrelfo):
        jsobj = dict([(i, getattr(self.xref, i)) for i in ["file", "line", "func"]])
        if self.ec != 0:
            jsobj["ec"] = self.ec
        jsobj["fmtstring"] = self.fmtstring
        jsobj["args"] = self.args
        jsobj["priority"] = self.priority & 7
        jsobj["type"] = "logmsg"
        jsobj["binary"] = self._elfsect._elfwrap.orig_filename

        if self.priority & 0x10:
            jsobj.setdefault("flags", []).append("errno")
        if self.priority & 0x20:
            jsobj.setdefault("flags", []).append("getaddrinfo")

        xrelfo["refs"].setdefault(self.xref.xrefdata.uid, []).append(jsobj)


Xref.containers[XREFT_LOGMSG] = XrefLogmsg


class CmdElement(ELFDissectStruct, XrelfoJson):
    struct = "cmd_element"

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

    def to_dict(self, xrelfo):
        jsobj = (
            xrelfo["cli"]
            .setdefault(self.name, {})
            .setdefault(self._elfsect._elfwrap.orig_filename, {})
        )

        jsobj.update(
            {
                "string": self.string,
                "doc": self.doc,
            }
        )
        if self.attr:
            jsobj["attr"] = attr = self.attr
            for attrname in CmdAttr.__members__:
                val = CmdAttr[attrname]
                if attr & val:
                    jsobj.setdefault("attrs", []).append(attrname.lower())
                    attr &= ~val

        jsobj["defun"] = dict(
            [(i, getattr(self.xref, i)) for i in ["file", "line", "func"]]
        )


Xref.containers[XREFT_DEFUN] = CmdElement


class XrefInstallElement(ELFDissectStruct, XrelfoJson):
    struct = "xref_install_element"

    def to_dict(self, xrelfo):
        jsobj = (
            xrelfo["cli"]
            .setdefault(self.cmd_element.name, {})
            .setdefault(self._elfsect._elfwrap.orig_filename, {})
        )
        nodes = jsobj.setdefault("nodes", [])

        nodes.append(
            {
                "node": self.node_type,
                "install": dict(
                    [(i, getattr(self.xref, i)) for i in ["file", "line", "func"]]
                ),
            }
        )


Xref.containers[XREFT_INSTALL_ELEMENT] = XrefInstallElement

# shove in field defs
fieldapply = FieldApplicator(xrefstructs)
fieldapply.add(Xref)
fieldapply.add(Xrefdata)
fieldapply.add(XrefLogmsg)
fieldapply.add(XrefThreadSched)
fieldapply.add(CmdElement)
fieldapply.add(XrefInstallElement)
fieldapply()


class Xrelfo(dict):
    def __init__(self):
        super().__init__(
            {
                "refs": {},
                "cli": {},
            }
        )
        self._xrefs = []
        self.note_warn = False

    def load_file(self, filename):
        orig_filename = filename
        if filename.endswith(".la") or filename.endswith(".lo"):
            with open(filename, "r") as fd:
                for line in fd:
                    line = line.strip()
                    if line.startswith("#") or line == "" or "=" not in line:
                        continue

                    var, val = line.split("=", 1)
                    if var not in ["library_names", "pic_object"]:
                        continue
                    if val.startswith("'") or val.startswith('"'):
                        val = val[1:-1]

                    if var == "pic_object":
                        filename = os.path.join(os.path.dirname(filename), val)
                        break

                    val = val.strip().split()[0]
                    filename = os.path.join(os.path.dirname(filename), ".libs", val)
                    break
                else:
                    raise ValueError(
                        'could not process libtool file "%s"' % orig_filename
                    )

        while True:
            with open(filename, "rb") as fd:
                hdr = fd.read(4)

            if hdr == b"\x7fELF":
                self.load_elf(filename, orig_filename)
                return

            if hdr[:2] == b"#!":
                path, name = os.path.split(filename)
                filename = os.path.join(path, ".libs", name)
                continue

            if hdr[:1] == b"{":
                with open(filename, "r") as fd:
                    self.load_json(fd)
                return

            raise ValueError("cannot determine file type for %s" % (filename))

    def load_elf(self, filename, orig_filename):
        edf = ELFDissectFile(filename)
        edf.orig_filename = orig_filename

        note = edf._elffile.find_note("FRRouting", "XREF")
        if note is not None:
            endian = ">" if edf._elffile.bigendian else "<"
            mem = edf._elffile[note]
            if edf._elffile.elfclass == 64:
                start, end = struct.unpack(endian + "QQ", mem)
                start += note.start
                end += note.start + 8
            else:
                start, end = struct.unpack(endian + "II", mem)
                start += note.start
                end += note.start + 4

            ptrs = edf.iter_data(XrefPtr, slice(start, end))

        else:
            if elf_notes:
                self.note_warn = True
                sys.stderr.write(
                    """%s: warning: binary has no FRRouting.XREF note
%s-   one of FRR_MODULE_SETUP, FRR_DAEMON_INFO or XREF_SETUP must be used
"""
                    % (orig_filename, orig_filename)
                )

            xrefarray = edf.get_section("xref_array")
            if xrefarray is None:
                raise ValueError("file has neither xref note nor xref_array section")

            ptrs = xrefarray.iter_data(XrefPtr)

        for ptr in ptrs:
            if ptr.xref is None:
                print("NULL xref")
                continue
            self._xrefs.append(ptr.xref)

            container = ptr.xref.container()
            if container is None:
                continue
            container.to_dict(self)

        return edf

    def load_json(self, fd):
        data = json.load(fd)
        for uid, items in data["refs"].items():
            myitems = self["refs"].setdefault(uid, [])
            for item in items:
                if item in myitems:
                    continue
                myitems.append(item)

        for cmd, items in data["cli"].items():
            self["cli"].setdefault(cmd, {}).update(items)

        return data

    def check(self, checks):
        for xref in self._xrefs:
            yield from xref.check(checks)


def main():
    argp = argparse.ArgumentParser(description="FRR xref ELF extractor")
    argp.add_argument("-o", dest="output", type=str, help="write JSON output")
    argp.add_argument("--out-by-file", type=str, help="write by-file JSON output")
    argp.add_argument("-c", dest="vtysh_cmds", type=str, help="write vtysh_cmd.c")
    argp.add_argument("-Wlog-format", action="store_const", const=True)
    argp.add_argument("-Wlog-args", action="store_const", const=True)
    argp.add_argument("-Werror", action="store_const", const=True)
    argp.add_argument("--profile", action="store_const", const=True)
    argp.add_argument(
        "binaries",
        metavar="BINARY",
        nargs="+",
        type=str,
        help="files to read (ELF files or libtool objects)",
    )
    args = argp.parse_args()

    if args.profile:
        import cProfile

        cProfile.runctx("_main(args)", globals(), {"args": args}, sort="cumtime")
    else:
        _main(args)


def _main(args):
    errors = 0
    xrelfo = Xrelfo()

    for fn in args.binaries:
        try:
            xrelfo.load_file(fn)
        except:
            errors += 1
            sys.stderr.write("while processing %s:\n" % (fn))
            traceback.print_exc()

    if xrelfo.note_warn and args.Werror:
        errors += 1

    for option in dir(args):
        if option.startswith("W") and option != "Werror":
            checks = sorted(xrelfo.check(args))
            sys.stderr.write("".join([c[-1] for c in checks]))

            if args.Werror and len(checks) > 0:
                errors += 1
            break

    refs = xrelfo["refs"]

    counts = {}
    for k, v in refs.items():
        strs = set([i["fmtstring"] for i in v])
        if len(strs) != 1:
            print("\033[31;1m%s\033[m" % k)
        counts[k] = len(v)

    out = xrelfo
    outbyfile = {}
    for uid, locs in refs.items():
        for loc in locs:
            filearray = outbyfile.setdefault(loc["file"], [])
            loc = dict(loc)
            del loc["file"]
            filearray.append(loc)

    for k in outbyfile.keys():
        outbyfile[k] = sorted(outbyfile[k], key=lambda x: x["line"])

    if errors:
        sys.exit(1)

    if args.output:
        with open(args.output + ".tmp", "w") as fd:
            json.dump(out, fd, indent=2, sort_keys=True, **json_dump_args)
        os.rename(args.output + ".tmp", args.output)

    if args.out_by_file:
        with open(args.out_by_file + ".tmp", "w") as fd:
            json.dump(outbyfile, fd, indent=2, sort_keys=True, **json_dump_args)
        os.rename(args.out_by_file + ".tmp", args.out_by_file)

    if args.vtysh_cmds:
        with open(args.vtysh_cmds + ".tmp", "w") as fd:
            CommandEntry.run(out, fd)
        os.rename(args.vtysh_cmds + ".tmp", args.vtysh_cmds)
        if args.Werror and CommandEntry.warn_counter:
            sys.exit(1)


if __name__ == "__main__":
    main()
