# zlog fuzz-tester input generator
#
# Copyright (C) 2021  David Lamparter for NetDEF, Inc.
#
# This program is free software; you can redistribute it and/or modify it
# under the terms of the GNU General Public License as published by the Free
# Software Foundation; either version 2 of the License, or (at your option)
# any later version.
#
# This program is distributed in the hope that it will be useful, but WITHOUT
# ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
# FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
# more details.
#
# You should have received a copy of the GNU General Public License along
# with this program; see the file COPYING; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA

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
