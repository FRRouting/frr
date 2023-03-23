# SPDX-License-Identifier: NONE
# 2020 by David Lamparter, placed in the public domain.

import sys
import os
import re
import argparse

wrap_res = [
    (re.compile(r'(?<!\\n)"\s*\n\s*"', re.M), r""),
]
pri_res = [
    (re.compile(r'(PRI[udx][0-9]+)\s*\n\s*"', re.M), r'\1"'),
    (re.compile(r'"\s*PRI([udx])32\s*"'), r"\1"),
    (re.compile(r'"\s*PRI([udx])32'), r'\1"'),
    (re.compile(r'"\s*PRI([udx])16\s*"'), r"h\1"),
    (re.compile(r'"\s*PRI([udx])16'), r'h\1"'),
    (re.compile(r'"\s*PRI([udx])8\s*"'), r"hh\1"),
    (re.compile(r'"\s*PRI([udx])8'), r'hh\1"'),
]


def main():
    argp = argparse.ArgumentParser(description="C string mangler")
    argp.add_argument("--unwrap", action="store_const", const=True)
    argp.add_argument("--pri8-16-32", action="store_const", const=True)
    argp.add_argument("files", type=str, nargs="+")
    args = argp.parse_args()

    regexes = []
    if args.unwrap:
        regexes.extend(wrap_res)
    if args.pri8_16_32:
        regexes.extend(pri_res)
    if len(regexes) == 0:
        sys.stderr.write("no action selected to execute\n")
        sys.exit(1)

    l = 0

    for fn in args.files:
        sys.stderr.write(fn + "\033[K\r")
        with open(fn, "r") as ifd:
            data = ifd.read()

        newdata = data
        n = 0
        for regex, repl in regexes:
            newdata, m = regex.subn(repl, newdata)
            n += m

        if n > 0:
            sys.stderr.write("changed: %s\n" % fn)
            with open(fn + ".new", "w") as ofd:
                ofd.write(newdata)
            os.rename(fn + ".new", fn)
            l += 1

    sys.stderr.write("%d files changed.\n" % (l))


main()
