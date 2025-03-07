# SPDX-License-Identifier: GPL-2.0-or-later
# check that the first header included in C files is either
# zebra.h or config.h
#
# Copyright (C) 2020  David Lamparter for NetDEF, Inc.

import sys
import os
import re
import subprocess
import argparse

argp = argparse.ArgumentParser(description="include fixer")
argp.add_argument("--autofix", action="store_const", const=True)
argp.add_argument("--warn-empty", action="store_const", const=True)
argp.add_argument("--pipe", action="store_const", const=True)

include_re = re.compile(r'^#\s*include\s+["<]([^ ">]+)[">]', re.M)

ignore = [
    lambda fn: fn.startswith("tools/"),
    lambda fn: fn
    in [
        "lib/elf_py.c",
    ],
]


def run(args):
    out = []

    files = subprocess.check_output(["git", "ls-files"]).decode("ASCII")
    for fn in files.splitlines():
        if not fn.endswith(".c"):
            continue
        if max([i(fn) for i in ignore]):
            continue

        with open(fn, "r") as fd:
            data = fd.read()

        m = include_re.search(data)
        if m is None:
            if args.warn_empty:
                sys.stderr.write("no #include in %s?\n" % (fn))
            continue
        if m.group(1) in ["config.h", "zebra.h", "lib/zebra.h"]:
            continue

        if args.autofix:
            sys.stderr.write("%s: %s - fixing\n" % (fn, m.group(0)))
            if fn.startswith("pceplib/"):
                insert = '#ifdef HAVE_CONFIG_H\n#include "config.h"\n#endif\n\n'
            else:
                insert = "#include <zebra.h>\n\n"

            pos = m.span()[0]

            data = data[:pos] + insert + data[pos:]
            with open(fn + ".new", "w") as fd:
                fd.write(data)
            os.rename(fn + ".new", fn)
        else:
            sys.stderr.write("%s: %s\n" % (fn, m.group(0)))
            out.append(fn)

    if len(out):
        if args.pipe:
            # for "vim `firstheader.py`"
            print("\n".join(out))
        return 1
    return 0


if __name__ == "__main__":
    args = argp.parse_args()
    sys.exit(run(args))
