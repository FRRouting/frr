#!/usr/bin/python3
#
# FRR extended automake/Makefile functionality helper
#
# This script is executed on/after generating Makefile to add some pieces for
# clippy.

import sys
import os
import subprocess
import re
import argparse
from string import Template
from makevars import MakeReVars

argp = argparse.ArgumentParser(description="FRR Makefile extensions")
argp.add_argument(
    "--dev-build",
    action="store_const",
    const=True,
    help="run additional developer checks",
)
args = argp.parse_args()

with open("Makefile", "r") as fd:
    before = fd.read()

mv = MakeReVars(before)

clippy_scan = mv["clippy_scan"].strip().split()
for clippy_file in clippy_scan:
    assert clippy_file.endswith(".c")

xref_targets = []
for varname in [
    "bin_PROGRAMS",
    "sbin_PROGRAMS",
    "lib_LTLIBRARIES",
    "module_LTLIBRARIES",
]:
    xref_targets.extend(mv[varname].strip().split())

# check for files using clippy but not listed in clippy_scan
if args.dev_build:
    basepath = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    if os.path.exists(os.path.join(basepath, ".git")):
        clippy_ref = subprocess.check_output(
            [
                "git",
                "-C",
                basepath,
                "grep",
                "-l",
                "-P",
                "^#\s*include.*_clippy.c",
                "--",
                "**.c",
            ]
        ).decode("US-ASCII")

        clippy_ref = set(clippy_ref.splitlines())
        missing = clippy_ref - set(clippy_scan)

        if len(missing) > 0:
            sys.stderr.write(
                'error: files seem to be using clippy, but not listed in "clippy_scan" in subdir.am:\n\t%s\n'
                % ("\n\t".join(sorted(missing)))
            )
            sys.exit(1)

# this additional-dependency rule is stuck onto all compile targets that
# compile a file which uses clippy-generated input, so it has a dependency to
# make that first.
clippydep = Template(
    """
${clippybase}.$$(OBJEXT): ${clippybase}_clippy.c
${clippybase}.lo: ${clippybase}_clippy.c
${clippybase}_clippy.c: $$(CLIPPY_DEPS)"""
)

# this one is used when one .c file is built multiple times with different
# CFLAGS
clippyauxdep = Template(
    """# clippy{
# auxiliary clippy target
${target}: ${clippybase}_clippy.c
# }clippy"""
)

lines = before.splitlines()
autoderp = "#AUTODERP# "
out_lines = []
bcdeps = []
make_rule_re = re.compile(r"^([^:\s]+):\s*([^:\s]+)\s*($|\n)")

while lines:
    line = lines.pop(0)
    if line.startswith(autoderp):
        line = line[len(autoderp) :]

    # allow rerunning on already-clippified Makefile
    if line == "# clippy{":
        while lines:
            line = lines.pop(0)
            if line == "# }clippy":
                break
        continue

    if line.startswith("#"):
        out_lines.append(line)
        continue

    full_line = line
    full_lines = lines[:]
    while full_line.endswith("\\"):
        full_line = full_line[:-1] + full_lines.pop(0)

    m = make_rule_re.match(full_line)
    if m is None:
        out_lines.append(line)
        continue

    line, lines = full_line, full_lines

    target, dep = m.group(1), m.group(2)

    filename = os.path.basename(target)
    if "-" in filename:
        # dashes in output filename = building same .c with different CFLAGS
        am_name, _ = filename.split("-", 1)
        am_name = os.path.join(os.path.dirname(target), am_name)
        am_name = am_name.replace("/", "_")
        extraflags = " $(%s_CFLAGS)" % (am_name,)
    else:
        # this path isn't really triggered because automake is using a generic
        # .c => .o rule unless CFLAGS are customized for a target
        extraflags = ""

    if target.endswith(".lo") or target.endswith(".o"):
        if not dep.endswith(".h"):
            # LLVM bitcode targets for analysis tools
            bcdeps.append("%s.bc: %s" % (target, target))
            bcdeps.append(
                "\t$(AM_V_LLVM_BC)$(COMPILE)%s -emit-llvm -c -o $@ %s"
                % (extraflags, dep)
            )
    if m.group(2) in clippy_scan:
        # again - this is only hit for targets with custom CFLAGS, because
        # automake uses a generic .c -> .o rule for standard CFLAGS
        out_lines.append(
            clippyauxdep.substitute(target=m.group(1), clippybase=m.group(2)[:-2])
        )

    out_lines.append(line)

# now, cover all the .c files that don't have special build rules
out_lines.append("# clippy{\n# main clippy targets")
for clippy_file in clippy_scan:
    out_lines.append(clippydep.substitute(clippybase=clippy_file[:-2]))

# combine daemon .xref files into frr.xref
out_lines.append("")
xref_targets = [
    target
    for target in xref_targets
    if target
    not in [
        "bgpd/rfp-example/rfptest/rfptest",
        "pimd/mtracebis",
        "tools/ssd",
        "vtysh/vtysh",
    ]
]
out_lines.append(
    "xrefs = %s" % (" ".join(["%s.xref" % target for target in xref_targets]))
)
out_lines.append("frr.xref: $(xrefs)")
out_lines.append("")

# analog but slower way to get the same frr.xref
# frr.xref: $(bin_PROGRAMS) $(sbin_PROGRAMS) $(lib_LTLIBRARIES) $(module_LTLIBRARIES)
# 	$(AM_V_XRELFO) $(CLIPPY) $(top_srcdir)/python/xrelfo.py -o $@ $^

# LLVM bitcode link targets creating a .bc file for whole daemon or lib
out_lines.append("")
out_lines.extend(bcdeps)
out_lines.append("")
bc_targets = []
for varname in [
    "bin_PROGRAMS",
    "sbin_PROGRAMS",
    "lib_LTLIBRARIES",
    "module_LTLIBRARIES",
    "noinst_LIBRARIES",
]:
    bc_targets.extend(mv[varname].strip().split())
for target in bc_targets:
    amtgt = target.replace("/", "_").replace(".", "_").replace("-", "_")
    objs = mv[amtgt + "_OBJECTS"].strip().split()
    objs = [obj + ".bc" for obj in objs]
    deps = mv.get(amtgt + "_DEPENDENCIES", "").strip().split()
    deps = [d + ".bc" for d in deps if d.endswith(".a")]
    objs.extend(deps)
    out_lines.append("%s.bc: %s" % (target, " ".join(objs)))
    out_lines.append("\t$(AM_V_LLVM_LD)$(LLVM_LINK) -o $@ $^")
    out_lines.append("")

out_lines.append("# }clippy")
out_lines.append("")

after = "\n".join(out_lines)
if after == before:
    sys.exit(0)

with open("Makefile.pyout", "w") as fd:
    fd.write(after)
os.rename("Makefile.pyout", "Makefile")
