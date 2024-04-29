#!/usr/bin/python3
# SPDX-License-Identifier: MIT
#
# 2024 by David Lamparter
#
# this tool edits an FRR source .c file to expand the typesafe DECLARE_DLIST
# et al. definitions.  This can be helpful to get better warnings/errors from
# GCC when something re. a typesafe container is involved.  You can also use
# it on .h files.
# The actual expansions created by this tool are written to separate files
# called something like "lib/cspf__visited_tsexpand.h" (for a container named
# "visited")
#
# THIS TOOL EDITS THE FILE IN PLACE.  MAKE A BACKUP IF YOU HAVE UNSAVED WORK
# IN PROGRESS (which is likely because you're debugging a typesafe container
# problem!)
#
# The PREDECL_XYZ is irrelevant for this tool, it needs to be run on the file
# that has the DECLARE_XYZ (can be .c or .h)
#
# the lines added by this tool all have /* $ts_expand: remove$ */ at the end
# you can undo the effects of this tool by calling sed:
#
#   sed -e '/\$ts_expand: remove\$/ d' -i.orig filename.c

import os
import sys
import re
import subprocess
import shlex

decl_re = re.compile(
    r"""(?<=\n)[ \t]*DECLARE_(LIST|ATOMLIST|DLIST|HEAP|HASH|(SORTLIST|SKIPLIST|RBTREE|ATOMSORT)_(NON)?UNIQ)\(\s*(?P<name>[^, \t\n]+)\s*,[^)]+\)\s*;[ \t]*\n"""
)
kill_re = re.compile(r"""(?<=\n)[^\n]*/\* \$ts_expand: remove\$ \*/\n""")

src_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# some files may be compiled with different CPPFLAGS, that's not supported
# here...
cpp = subprocess.check_output(
    ["make", "var-CPP", "var-AM_CPPFLAGS", "var-DEFS"], cwd=src_root
)
cpp = shlex.split(cpp.decode("UTF-8"))


def process_file(filename):
    with open(filename, "r") as ifd:
        data = ifd.read()

    data = kill_re.sub("", data)

    before = 0

    dirname = os.path.dirname(filename)
    basename = os.path.basename(filename).removesuffix(".c").removesuffix(".h")

    xname = filename + ".exp"
    with open(filename + ".exp", "w") as ofd:
        for m in decl_re.finditer(data):
            s = m.start()
            e = m.end()
            ofd.write(data[before:s])

            # start gcc/clang with some "magic" options to make it expand the
            # typesafe macros, but nothing else.
            #   -P removes the "#line" markers (which are useless because
            #      everything ends up on one line anyway)
            #   -D_TYPESAFE_EXPAND_MACROS prevents the system header files
            #      (stddef.h, stdint.h, etc.) from being included and expanded
            #   -imacros loads the macro definitions from typesafe.h, but
            #      doesn't include any of the "plain text" (i.e. prototypes
            #      and outside-macro struct definitions) from it
            #   atomlist.h is sufficient because it includes typesafe.h which
            #   includes typerb.h, that's all of them
            p_expand = subprocess.Popen(
                cpp
                + [
                    "-P",
                    "-D_TYPESAFE_EXPAND_MACROS",
                    "-imacros",
                    "lib/atomlist.h",
                    "-",
                ],
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                cwd=src_root,
            )
            # the output will look like shit, all on one line.  format it.
            p_format = subprocess.Popen(
                ["clang-format", "-"],
                stdin=p_expand.stdout,
                stdout=subprocess.PIPE,
                cwd=src_root,
            )
            # pipe between cpp & clang-format needs to be closed
            p_expand.stdout.close()

            # ... and finally, write the DECLARE_XYZ statement, and ONLY that
            # statements.  No headers, no other definitions.
            p_expand.stdin.write(data[s:e].encode("UTF-8"))
            p_expand.stdin.close()

            odata = b""
            while rd := p_format.stdout.read():
                odata = odata + rd

            p_expand.wait()
            p_format.wait()

            # and now that we have the expanded text, write it out, put an
            # #include in the .c file, and put "#if 0" around the original
            # DECLARE_XYZ statement (otherwise it'll be duplicate...)
            newname = os.path.join(dirname, f"{basename}__{m.group('name')}_tsexpand.h")
            with open(newname, "wb") as nfd:
                nfd.write(odata)

            ofd.write(f'#include "{newname}" /* $ts_expand: remove$ */\n')
            ofd.write("#if 0 /* $ts_expand: remove$ */\n")
            ofd.write(data[s:e])
            ofd.write("#endif /* $ts_expand: remove$ */\n")
            before = e

        ofd.write(data[before:])

    os.rename(xname, filename)


if __name__ == "__main__":
    for filename in sys.argv[1:]:
        process_file(filename)
