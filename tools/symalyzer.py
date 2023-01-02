#!/usr/bin/python3
#
# 2019 by David Lamparter, placed in public domain
#
# This tool generates a report of possibly unused symbols in the build.  It's
# particularly useful for libfrr to find bitrotting functions that aren't even
# used anywhere anymore.
#
# Note that the tool can't distinguish between "a symbol is completely unused"
# and "a symbol is used only in its file" since file-internal references are
# invisible in nm output.  However, the compiler will warn you if a static
# symbol is unused.
#
# This tool is only tested on Linux, it probably needs `nm` from GNU binutils
# (as opposed to BSD `nm`).  Could use pyelftools instead but that's a lot of
# extra work.
#
# This is a developer tool, please don't put it in any packages :)

import sys, os, subprocess
import re
from collections import namedtuple

sys.path.insert(
    0,
    os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "python"),
)

from makevars import MakeVars

SymRowBase = namedtuple(
    "SymRow",
    [
        "target",
        "object",
        "name",
        "address",
        "klass",
        "typ",
        "size",
        "line",
        "section",
        "loc",
    ],
)


class SymRow(SymRowBase):
    """
    wrapper around a line of `nm` output
    """

    lib_re = re.compile(r"/lib[^/]+\.(so|la)$")

    def is_global(self):
        return self.klass.isupper() or self.klass in "uvw"

    def scope(self):
        if self.lib_re.search(self.target) is None:
            return self.target
        # "global"
        return None

    def is_export(self):
        """
        FRR-specific list of symbols which are considered "externally used"

        e.g. hooks are by design APIs for external use, same for qobj_t_*
        frr_inet_ntop is here because it's used through an ELF alias to
        "inet_ntop()"
        """
        if self.name in ["main", "frr_inet_ntop", "_libfrr_version"]:
            return True
        if self.name.startswith("_hook_"):
            return True
        if self.name.startswith("qobj_t_"):
            return True
        return False


class Symbols(dict):
    """
    dict of all symbols in all libs & executables
    """

    from_re = re.compile(r"^Symbols from (.*?):$")
    lt_re = re.compile(r"^(.*/)([^/]+)\.l[oa]$")

    def __init__(self):
        super().__init__()

    class ReportSym(object):
        def __init__(self, sym):
            self.sym = sym

        def __repr__(self):
            return "<%-25s %-40s [%s]>" % (
                self.__class__.__name__ + ":",
                self.sym.name,
                self.sym.loc,
            )

        def __lt__(self, other):
            return self.sym.name.__lt__(other.sym.name)

    class ReportSymCouldBeStaticAlreadyLocal(ReportSym):
        idshort = "Z"
        idlong = "extrastatic"
        title = "symbol is local to library, but only used in its source file (make static?)"

    class ReportSymCouldBeStatic(ReportSym):
        idshort = "S"
        idlong = "static"
        title = "symbol is only used in its source file (make static?)"

    class ReportSymCouldBeLibLocal(ReportSym):
        idshort = "L"
        idlong = "liblocal"
        title = "symbol is only used inside of library"

    class ReportSymModuleAPI(ReportSym):
        idshort = "A"
        idlong = "api"
        title = "symbol (in executable) is referenced externally from a module"

    class Symbol(object):
        def __init__(self, name):
            super().__init__()
            self.name = name
            self.defs = {}
            self.refs = []

        def process(self, row):
            scope = row.scope()
            if row.section == "*UND*":
                self.refs.append(row)
            else:
                self.defs.setdefault(scope, []).append(row)

        def evaluate(self, out):
            """
            generate output report

            invoked after all object files have been read in, so it can look
            at inter-object-file relationships
            """
            if len(self.defs) == 0:
                out.extsyms.add(self.name)
                return

            for scopename, symdefs in self.defs.items():
                common_defs = [
                    symdef for symdef in symdefs if symdef.section == "*COM*"
                ]
                proper_defs = [
                    symdef for symdef in symdefs if symdef.section != "*COM*"
                ]

                if len(proper_defs) > 1:
                    print(self.name, " DUPLICATE")
                    print(
                        "\tD: %s %s"
                        % (scopename, "\n\t\t".join([repr(s) for s in symdefs]))
                    )
                    for syms in self.refs:
                        print("\tR: %s" % (syms,))
                    return

                if len(proper_defs):
                    primary_def = proper_defs[0]
                elif len(common_defs):
                    # "common" = global variables without initializer;
                    # they can occur in multiple .o files and the linker will
                    # merge them into one variable/storage location.
                    primary_def = common_defs[0]
                else:
                    # undefined symbol, e.g. libc
                    continue

                if scopename is not None and len(self.refs) > 0:
                    for ref in self.refs:
                        if ref.target != primary_def.target and ref.target.endswith(
                            ".la"
                        ):
                            outobj = out.report.setdefault(primary_def.object, [])
                            outobj.append(out.ReportSymModuleAPI(primary_def))
                            break

                if len(self.refs) == 0:
                    if primary_def.is_export():
                        continue
                    outobj = out.report.setdefault(primary_def.object, [])
                    if primary_def.visible:
                        outobj.append(out.ReportSymCouldBeStatic(primary_def))
                    else:
                        outobj.append(
                            out.ReportSymCouldBeStaticAlreadyLocal(primary_def)
                        )
                    continue

                if scopename is None and primary_def.visible:
                    # lib symbol
                    for ref in self.refs:
                        if ref.target != primary_def.target:
                            break
                    else:
                        outobj = out.report.setdefault(primary_def.object, [])
                        outobj.append(out.ReportSymCouldBeLibLocal(primary_def))

    def evaluate(self):
        self.extsyms = set()
        self.report = {}

        for sym in self.values():
            sym.evaluate(self)

    def load(self, target, files):
        def libtoolmustdie(fn):
            m = self.lt_re.match(fn)
            if m is None:
                return fn
            return m.group(1) + ".libs/" + m.group(2) + ".o"

        def libtooltargetmustdie(fn):
            m = self.lt_re.match(fn)
            if m is None:
                a, b = fn.rsplit("/", 1)
                return "%s/.libs/%s" % (a, b)
            return m.group(1) + ".libs/" + m.group(2) + ".so"

        files = list(set([libtoolmustdie(fn) for fn in files]))

        def parse_nm_output(text):
            filename = None
            path_rel_to = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

            for line in text.split("\n"):
                if line.strip() == "":
                    continue
                m = self.from_re.match(line)
                if m is not None:
                    filename = m.group(1)
                    continue
                if line.startswith("Name"):
                    continue

                items = [i.strip() for i in line.split("|")]
                loc = None
                if "\t" in items[-1]:
                    items[-1], loc = items[-1].split("\t", 1)
                    fn, lno = loc.rsplit(":", 1)
                    fn = os.path.relpath(fn, path_rel_to)
                    loc = "%s:%s" % (fn, lno)

                items[1] = int(items[1] if items[1] != "" else "0", 16)
                items[4] = int(items[4] if items[4] != "" else "0", 16)
                items.append(loc)
                row = SymRow(target, filename, *items)

                if row.section == ".group" or row.name == "_GLOBAL_OFFSET_TABLE_":
                    continue
                if not row.is_global():
                    continue

                yield row

        visible_syms = set()

        # the actual symbol report uses output from the individual object files
        # (e.g. lib/.libs/foo.o), but we also read the linked binary (e.g.
        # lib/.libs/libfrr.so) to determine which symbols are actually visible
        # in the linked result (this covers ELF "hidden"/"internal" linkage)

        libfile = libtooltargetmustdie(target)
        nmlib = subprocess.Popen(
            ["nm", "-l", "-g", "--defined-only", "-f", "sysv", libfile],
            stdout=subprocess.PIPE,
        )
        out = nmlib.communicate()[0].decode("US-ASCII")

        for row in parse_nm_output(out):
            visible_syms.add(row.name)

        nm = subprocess.Popen(
            ["nm", "-l", "-f", "sysv"] + files, stdout=subprocess.PIPE
        )
        out = nm.communicate()[0].decode("US-ASCII")

        for row in parse_nm_output(out):
            row.visible = row.name in visible_syms
            sym = self.setdefault(row.name, self.Symbol(row.name))
            sym.process(row)


def write_html_report(syms):
    try:
        import jinja2
    except ImportError:
        sys.stderr.write("jinja2 could not be imported, not writing HTML report!\n")
        return

    self_path = os.path.dirname(os.path.abspath(__file__))
    jenv = jinja2.Environment(loader=jinja2.FileSystemLoader(self_path))
    template = jenv.get_template("symalyzer.html")

    dirgroups = {}
    for fn, reports in syms.report.items():
        dirname, filename = fn.replace(".libs/", "").rsplit("/", 1)
        dirgroups.setdefault(dirname, {})[fn] = reports

    klasses = {
        "T": "code / plain old regular function (Text)",
        "D": "global variable, read-write, with nonzero initializer (Data)",
        "B": "global variable, read-write, with zero initializer (BSS)",
        "C": "global variable, read-write, with zero initializer (Common)",
        "R": "global variable, read-only (Rodata)",
    }

    with open("symalyzer_report.html.tmp", "w") as fd:
        fd.write(template.render(dirgroups=dirgroups, klasses=klasses))
    os.rename("symalyzer_report.html.tmp", "symalyzer_report.html")

    if not os.path.exists("jquery-3.4.1.min.js"):
        url = "https://code.jquery.com/jquery-3.4.1.min.js"
        sys.stderr.write(
            "trying to grab a copy of jquery from %s\nif this fails, please get it manually (the HTML output is done.)\n"
            % (url)
        )
        import requests

        r = requests.get("https://code.jquery.com/jquery-3.4.1.min.js")
        if r.status_code != 200:
            sys.stderr.write(
                "failed -- please download jquery-3.4.1.min.js and put it next to the HTML report\n"
            )
        else:
            with open("jquery-3.4.1.min.js.tmp", "w") as fd:
                fd.write(r.text)
            os.rename("jquery-3.4.1.min.js.tmp", "jquery-3.4.1.min.js")
            sys.stderr.write("done.\n")


def automake_escape(s):
    return s.replace(".", "_").replace("/", "_")


if __name__ == "__main__":
    mv = MakeVars()

    if not (os.path.exists("config.version") and os.path.exists("lib/.libs/libfrr.so")):
        sys.stderr.write(
            "please execute this script in the root directory of an FRR build tree\n"
        )
        sys.stderr.write("./configure && make need to have completed successfully\n")
        sys.exit(1)

    amtargets = [
        "bin_PROGRAMS",
        "sbin_PROGRAMS",
        "lib_LTLIBRARIES",
        "module_LTLIBRARIES",
    ]
    targets = []

    mv.getvars(amtargets)
    for amtarget in amtargets:
        targets.extend(
            [item for item in mv[amtarget].strip().split() if item != "tools/ssd"]
        )

    mv.getvars(["%s_LDADD" % automake_escape(t) for t in targets])
    ldobjs = targets[:]
    for t in targets:
        ldadd = mv["%s_LDADD" % automake_escape(t)].strip().split()
        for item in ldadd:
            if item.startswith("-"):
                continue
            if item.endswith(".a"):
                ldobjs.append(item)

    mv.getvars(["%s_OBJECTS" % automake_escape(o) for o in ldobjs])

    syms = Symbols()

    for t in targets:
        objs = mv["%s_OBJECTS" % automake_escape(t)].strip().split()
        ldadd = mv["%s_LDADD" % automake_escape(t)].strip().split()
        for item in ldadd:
            if item.startswith("-"):
                continue
            if item.endswith(".a"):
                objs.extend(mv["%s_OBJECTS" % automake_escape(item)].strip().split())

        sys.stderr.write("processing %s...\n" % t)
        sys.stderr.flush()
        # print(t, '\n\t', objs)
        syms.load(t, objs)

    syms.evaluate()

    for obj, reports in sorted(syms.report.items()):
        print("%s:" % obj)
        for report in reports:
            print("\t%r" % report)

    write_html_report(syms)
