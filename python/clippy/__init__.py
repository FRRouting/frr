# SPDX-License-Identifier: GPL-2.0-or-later
# FRR CLI preprocessor
#
# Copyright (C) 2017  David Lamparter for NetDEF, Inc.

import os, stat

try:
    from enum import IntFlag as _IntFlag
except ImportError:
    # python <3.6
    from enum import IntEnum as _IntFlag  # type: ignore

import _clippy
from _clippy import (
    parse,
    Graph,
    GraphNode,
    CMD_ATTR_YANG,
    CMD_ATTR_HIDDEN,
    CMD_ATTR_DEPRECATED,
    CMD_ATTR_NOSH,
    elf_notes,
)


frr_top_src = os.path.dirname(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
)


def graph_iterate(graph):
    """iterator yielding all nodes of a graph

    nodes arrive in input/definition order, graph circles are avoided.
    """

    queue = [(graph.first(), frozenset(), 0)]
    while len(queue) > 0:
        node, stop, depth = queue.pop(0)
        yield node, depth

        join = node.join()
        if join is not None:
            queue.insert(0, (join, stop.union(frozenset([node])), depth))
            join = frozenset([join])

        stop = join or stop
        nnext = node.next()
        for n in reversed(nnext):
            if n not in stop and n is not node:
                queue.insert(0, (n, stop, depth + 1))


def dump(graph):
    """print out clippy.Graph"""

    for i, depth in graph_iterate(graph):
        print("\t%s%s %r" % ("  " * (depth * 2), i.type, i.text))


def wrdiff(filename, buf, reffiles=[]):
    """write buffer to file if contents changed"""

    expl = ""
    if hasattr(buf, "getvalue"):
        buf = buf.getvalue()
    old = None
    try:
        old = open(filename, "r").read()
    except:
        pass
    if old == buf:
        for reffile in reffiles:
            # ensure output timestamp is newer than inputs, for make
            reftime = os.stat(reffile)[stat.ST_MTIME]
            outtime = os.stat(filename)[stat.ST_MTIME]
            if outtime <= reftime:
                os.utime(filename, (reftime + 1, reftime + 1))
        # sys.stderr.write('%s unchanged, not written\n' % (filename))
        return

    newname = "%s.new-%d" % (filename, os.getpid())
    with open(newname, "w") as out:
        out.write(buf)
    os.rename(newname, filename)


class CmdAttr(_IntFlag):
    YANG = CMD_ATTR_YANG
    HIDDEN = CMD_ATTR_HIDDEN
    DEPRECATED = CMD_ATTR_DEPRECATED
    NOSH = CMD_ATTR_NOSH
