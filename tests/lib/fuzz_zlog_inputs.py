# SPDX-License-Identifier: GPL-2.0-or-later
# zlog fuzz-tester input generator
#
# Copyright (C) 2021  David Lamparter for NetDEF, Inc.

from itertools import chain
import struct

lengths = set([128])
# lengths = [[i, i + 1, i + 3, i - 1, i - 3] for i in lengths]
# lengths = set([i for i in chain(*lengths) if i >= 0])

dsts = [0, 1, 2, 3]
fmts = [0, 1, 2, 3]


def combo():
    for l0 in lengths:
        for l1 in lengths:
            for l2 in lengths:
                for fmt in fmts:
                    for dst in dsts:
                        yield (l0, l1, l2, fmt, dst)


for i, tup in enumerate(combo()):
    with open("input/i%d" % i, "wb") as fd:
        fd.write(struct.pack("HHHBB", *tup))
