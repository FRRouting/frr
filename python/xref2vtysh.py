# SPDX-License-Identifier: GPL-2.0-or-later
# FRR xref vtysh command extraction
#
# Copyright (C) 2022  David Lamparter for NetDEF, Inc.

"""
Generate vtysh_cmd.c from frr .xref file(s).

This can run either standalone or as part of xrelfo.  The latter saves a
non-negligible amount of time (0.5s on average systems, more on e.g. slow ARMs)
since serializing and deserializing JSON is a significant bottleneck in this.
"""

import sys
import os
import re
import pathlib
import argparse
from collections import defaultdict
import difflib

import json

try:
    import ujson as json  # type: ignore
except ImportError:
    pass

<<<<<<< HEAD
=======
import _clippy

>>>>>>> 9b0b9282d (bgpd: Fix bgp core with a possible Intf delete)
frr_top_src = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# vtysh needs to know which daemon(s) to send commands to.  For lib/, this is
# not quite obvious...

daemon_flags = {
<<<<<<< HEAD
    "lib/agentx.c": "VTYSH_ISISD|VTYSH_RIPD|VTYSH_OSPFD|VTYSH_OSPF6D|VTYSH_BGPD|VTYSH_ZEBRA",
    "lib/filter.c": "VTYSH_ACL",
    "lib/filter_cli.c": "VTYSH_ACL",
    "lib/if.c": "VTYSH_INTERFACE",
    "lib/keychain.c": "VTYSH_RIPD|VTYSH_EIGRPD|VTYSH_OSPF6D",
    "lib/mgmt_be_client.c": "VTYSH_STATICD",
    "lib/mgmt_fe_client.c": "VTYSH_MGMTD",
=======
    "lib/libagentx.c": "VTYSH_ISISD|VTYSH_RIPD|VTYSH_OSPFD|VTYSH_OSPF6D|VTYSH_BGPD|VTYSH_ZEBRA",
    "lib/filter.c": "VTYSH_ACL_SHOW",
    "lib/filter_cli.c": "VTYSH_ACL_CONFIG",
    "lib/if.c": "VTYSH_INTERFACE",
    "lib/keychain_cli.c": "VTYSH_KEYS",
    "lib/mgmt_be_client.c": "VTYSH_MGMT_BACKEND",
    "lib/mgmt_fe_client.c": "VTYSH_MGMT_FRONTEND",
>>>>>>> 9b0b9282d (bgpd: Fix bgp core with a possible Intf delete)
    "lib/lib_vty.c": "VTYSH_ALL",
    "lib/log_vty.c": "VTYSH_ALL",
    "lib/nexthop_group.c": "VTYSH_NH_GROUP",
    "lib/resolver.c": "VTYSH_NHRPD|VTYSH_BGPD",
<<<<<<< HEAD
    "lib/routemap.c": "VTYSH_RMAP",
    "lib/routemap_cli.c": "VTYSH_RMAP",
=======
    "lib/routemap.c": "VTYSH_RMAP_SHOW",
    "lib/routemap_cli.c": "VTYSH_RMAP_CONFIG",
>>>>>>> 9b0b9282d (bgpd: Fix bgp core with a possible Intf delete)
    "lib/spf_backoff.c": "VTYSH_ISISD",
    "lib/event.c": "VTYSH_ALL",
    "lib/vrf.c": "VTYSH_VRF",
    "lib/vty.c": "VTYSH_ALL",
}

vtysh_cmd_head = """/* autogenerated file, DO NOT EDIT! */
#include <zebra.h>

#include "command.h"
#include "linklist.h"

#include "vtysh/vtysh.h"
<<<<<<< HEAD
=======

#pragma GCC visibility push(internal)

#define MAKE_VECTOR(name, len, ...)                        \\
        static void * name ## _vitems[] = { __VA_ARGS__ }; \\
        static struct _vector name = {                     \\
                .active = len,                             \\
                .count = len,                              \\
                .index = name ## _vitems,                  \\
        }
>>>>>>> 9b0b9282d (bgpd: Fix bgp core with a possible Intf delete)
"""

if sys.stderr.isatty():
    _fmt_red = "\033[31m"
    _fmt_green = "\033[32m"
    _fmt_clear = "\033[m"
else:
    _fmt_red = _fmt_green = _fmt_clear = ""


def c_escape(text: str) -> str:
    """
    Escape string for output into C source code.

    Handles only what's needed here.  CLI strings and help text don't contain
    weird special characters.
    """
    return text.replace("\\", "\\\\").replace('"', '\\"').replace("\n", "\\n")


class NodeDict(defaultdict):
    """
    CLI node ID (integer) -> dict of commands in that node.
    """

    nodenames = {}  # Dict[int, str]

    def __init__(self):
        super().__init__(dict)

    def items_named(self):
        for k, v in self.items():
            yield self.nodename(k), v

    @classmethod
    def nodename(cls, nodeid: int) -> str:
        return cls.nodenames.get(nodeid, str(nodeid))

    @classmethod
    def load_nodenames(cls):
        with open(os.path.join(frr_top_src, "lib", "command.h"), "r") as fd:
            command_h = fd.read()

        nodes = re.search(r"enum\s+node_type\s+\{(.*?)\}", command_h, re.S)
        if nodes is None:
            raise RuntimeError(
                "regex failed to match on lib/command.h (to get CLI node names)"
            )

        text = nodes.group(1)
        text = re.sub(r"/\*.*?\*/", "", text, flags=re.S)
        text = re.sub(r"//.*?$", "", text, flags=re.M)
        text = text.replace(",", " ")
        text = text.split()

        for i, name in enumerate(text):
            cls.nodenames[i] = name


class CommandEntry:
    """
    CLI command definition.

    - one DEFUN creates at most one of these, even if the same command is
      installed in multiple CLI nodes (e.g. BGP address-family nodes)
    - for each CLI node, commands with the same CLI string are merged.  This
      is *almost* irrelevant - ospfd & ospf6d define some identical commands
      in the route-map node.  Those must be merged for things to work
      correctly.
    """

    all_defs = []  # List[CommandEntry]
    warn_counter = 0

    def __init__(self, origin, name, spec):
        self.origin = origin
        self.name = name
        self._spec = spec
        self._registered = False

        self.cmd = spec["string"]
        self._cmd_normalized = self.normalize_cmd(self.cmd)

        self.hidden = "hidden" in spec.get("attrs", [])
        self.daemons = self._get_daemons()

        self.doclines = self._spec["doc"].splitlines(keepends=True)
        if not self.doclines[-1].endswith("\n"):
            self.warn_loc("docstring does not end with \\n")

    def warn_loc(self, wtext, nodename=None):
        """
        Print warning with parseable (compiler style) location

        Matching the way compilers emit file/lineno means editors/IDE can
        identify / jump to the error location.
        """

        if nodename:
            prefix = ": [%s] %s:" % (nodename, self.name)
        else:
            prefix = ": %s:" % (self.name,)

        for line in wtext.rstrip("\n").split("\n"):
            sys.stderr.write(
                "%s:%d%s %s\n"
                % (
                    self._spec["defun"]["file"],
                    self._spec["defun"]["line"],
                    prefix,
                    line,
                )
            )
            prefix = "-    "

        CommandEntry.warn_counter += 1

    def _get_daemons(self):
        path = pathlib.Path(self.origin)
        if path.name == "vtysh":
            return {}

        defun_file = os.path.relpath(self._spec["defun"]["file"], frr_top_src)
        defun_path = pathlib.Path(defun_file)

        if defun_path.parts[0] != "lib":
            if "." not in path.name:
                # daemons don't have dots in their filename
                return {"VTYSH_" + path.name.upper()}

            # loadable modules - use directory name to determine daemon
            return {"VTYSH_" + path.parts[-2].upper()}

        if defun_file in daemon_flags:
            return {daemon_flags[defun_file]}

        v6_cmd = "ipv6" in self.name
        if defun_file == "lib/plist.c":
            if v6_cmd:
                return {
                    "VTYSH_RIPNGD|VTYSH_OSPF6D|VTYSH_BGPD|VTYSH_ZEBRA|VTYSH_PIM6D|VTYSH_BABELD|VTYSH_ISISD|VTYSH_FABRICD"
                }
            else:
                return {
                    "VTYSH_RIPD|VTYSH_OSPFD|VTYSH_BGPD|VTYSH_ZEBRA|VTYSH_PIMD|VTYSH_EIGRPD|VTYSH_BABELD|VTYSH_ISISD|VTYSH_FABRICD"
                }

        if defun_file == "lib/if_rmap.c":
<<<<<<< HEAD
            if v6_cmd:
                return {"VTYSH_RIPNGD"}
            else:
                return {"VTYSH_RIPD"}
=======
            return {"VTYSH_MGMTD"}
>>>>>>> 9b0b9282d (bgpd: Fix bgp core with a possible Intf delete)

        return {}

    def __repr__(self):
        return "<CommandEntry %s: %r>" % (self.name, self.cmd)

    def register(self):
        """Track DEFUNs so each is only output once."""
        if not self._registered:
            self.all_defs.append(self)
            self._registered = True
        return self

    def merge(self, other, nodename):
        if self._cmd_normalized != other._cmd_normalized:
            self.warn_loc(
                "command definition mismatch, first definied as:\n%r" % (self.cmd,),
                nodename=nodename,
            )
            other.warn_loc("later defined as:\n%r" % (other.cmd,), nodename=nodename)

        if self._spec["doc"] != other._spec["doc"]:
            self.warn_loc(
                "help string mismatch, first defined here (-)", nodename=nodename
            )
            other.warn_loc(
                "later defined here (+)\nnote: both commands define %r in same node (%s)"
                % (self.cmd, nodename),
                nodename=nodename,
            )

            d = difflib.Differ()
            for diffline in d.compare(self.doclines, other.doclines):
                if diffline.startswith("  "):
                    continue
                if diffline.startswith("+ "):
                    diffline = _fmt_green + diffline
                elif diffline.startswith("- "):
                    diffline = _fmt_red + diffline
                sys.stderr.write("\t" + diffline.rstrip("\n") + _fmt_clear + "\n")

        if self.hidden != other.hidden:
            self.warn_loc(
                "hidden flag mismatch, first %r here" % (self.hidden,),
                nodename=nodename,
            )
            other.warn_loc(
                "later %r here (+)\nnote: both commands define %r in same node (%s)"
                % (other.hidden, self.cmd, nodename),
                nodename=nodename,
            )

        # ensure name is deterministic regardless of input DEFUN order
        self.name = min([self.name, other.name], key=lambda i: (len(i), i))
        self.daemons.update(other.daemons)

    def get_def(self):
        doc = "\n".join(['\t"%s"' % c_escape(line) for line in self.doclines])
        defsh = "DEFSH_HIDDEN" if self.hidden else "DEFSH"

        # make daemon list deterministic
        daemons = set()
        for daemon in self.daemons:
            daemons.update(daemon.split("|"))
        daemon_str = "|".join(sorted(daemons))

        return """
%s (%s, %s_vtysh,
\t"%s",
%s)
""" % (
            defsh,
            daemon_str,
            self.name,
            c_escape(self.cmd),
            doc,
        )

    # accept slightly different command definitions that result in the same command
    re_collapse_ws = re.compile(r"\s+")
    re_remove_varnames = re.compile(r"\$[a-z][a-z0-9_]*")

    @classmethod
    def normalize_cmd(cls, cmd):
        cmd = cmd.strip()
        cmd = cls.re_collapse_ws.sub(" ", cmd)
        cmd = cls.re_remove_varnames.sub("", cmd)
        return cmd

    @classmethod
    def process(cls, nodes, name, origin, spec):
        if "nosh" in spec.get("attrs", []):
            return
        if origin == "vtysh/vtysh":
            return

        if origin == "isisd/fabricd":
            # dirty workaround :(
            name = "fabricd_" + name

        entry = cls(origin, name, spec)
        if not entry.daemons:
            return

        for nodedata in spec.get("nodes", []):
            node = nodes[nodedata["node"]]
            if entry._cmd_normalized not in node:
                node[entry._cmd_normalized] = entry.register()
            else:
                node[entry._cmd_normalized].merge(
                    entry, nodes.nodename(nodedata["node"])
                )

    @classmethod
    def load(cls, xref):
        nodes = NodeDict()

<<<<<<< HEAD
        mgmtname = "mgmtd/libmgmt_be_nb.la"
        for cmd_name, origins in xref.get("cli", {}).items():
            # If mgmtd has a yang version of a CLI command, make it the only daemon
            # to handle it.  For now, daemons can still be compiling their cmds into the
            # binaries to allow for running standalone with CLI config files. When they
            # do this they will also be present in the xref file, but we want to ignore
            # those in vtysh.
            if "yang" in origins.get(mgmtname, {}).get("attrs", []):
                CommandEntry.process(nodes, cmd_name, mgmtname, origins[mgmtname])
                continue

=======
        for cmd_name, origins in xref.get("cli", {}).items():
>>>>>>> 9b0b9282d (bgpd: Fix bgp core with a possible Intf delete)
            for origin, spec in origins.items():
                CommandEntry.process(nodes, cmd_name, origin, spec)
        return nodes

    @classmethod
    def output_defs(cls, ofd):
        for entry in sorted(cls.all_defs, key=lambda i: i.name):
            ofd.write(entry.get_def())

    @classmethod
<<<<<<< HEAD
    def output_install(cls, ofd, nodes):
        ofd.write("\nvoid vtysh_init_cmd(void)\n{\n")

        for name, items in sorted(nodes.items_named()):
            for item in sorted(items.values(), key=lambda i: i.name):
                ofd.write("\tinstall_element(%s, &%s_vtysh);\n" % (name, item.name))

        ofd.write("}\n")

    @classmethod
    def run(cls, xref, ofd):
        ofd.write(vtysh_cmd_head)
=======
    def output_node_graph(cls, ofd, node, cmds, splitfile):
        graph = _clippy.Graph(None)

        for _, cmd in sorted(cmds.items()):
            cg = _clippy.Graph(cmd.cmd, cmd._spec["doc"], cmd.name)
            graph.merge(cg)

        if len(graph) <= 2:
            return []

        ofd.write("\n")
        ofd.write(f"static struct cmd_token ctkn_{node}[];\n")
        ofd.write(f"static struct graph_node gn_{node}[];\n")
        ofd.write("\n")

        vectors = []
        cmdels = set()

        ofd.write(f"static struct cmd_token ctkn_{node}[] = {'{'}\n")
        for i, token in enumerate(graph):
            vectors.append(
                (
                    list(i.idx for i in token.next()),
                    list(i.idx for i in token.prev()),
                )
            )

            if token.type == "CMD_ELEMENT_TKN":
                ofd.write(f"\t{'{'} /* [{i}] = {token.text} */ {'}'},\n")
                cmdels.add(token.text)
                continue

            ofd.write(f"\t{'{'} /* [{i}] */\n\t\t.type = {token.type},\n")
            if token.attr:
                ofd.write(f"\t\t.attr = {token.attr},\n")
            if token.allowrepeat:
                ofd.write(f"\t\t.allowrepeat = true,\n")
            if token.varname_src:
                ofd.write(f"\t\t.varname_src = {token.varname_src},\n")
            if token.text:
                ofd.write(f'\t\t.text = (char *)"{c_escape(token.text)}",\n')
            if token.desc:
                ofd.write(f'\t\t.desc = (char *)"{c_escape(token.desc)}",\n')
            if token.min:
                ofd.write(f"\t\t.min = {token.min},\n")
            if token.max:
                ofd.write(f"\t\t.max = {token.max},\n")
            if token.varname:
                ofd.write(f'\t\t.varname = (char *)"{c_escape(token.varname)}",\n')

            if token.type == "FORK_TKN":
                fj = token.join()
                ofd.write(f"\t\t.forkjoin = &gn_{node}[{fj.idx}],\n")
            if token.type == "JOIN_TKN":
                fj = token.fork()
                ofd.write(f"\t\t.forkjoin = &gn_{node}[{fj.idx}],\n")

            ofd.write(f"\t{'}'},\n")

        ofd.write("};\n\n")

        if splitfile:
            for cmdel in sorted(cmdels):
                ofd.write(f"extern struct cmd_element {cmdel}_vtysh;\n")
            ofd.write("\n")

        for i, next_prev in enumerate(vectors):
            n, p = next_prev
            items = ", ".join(f"&gn_{node}[{i}]" for i in n)
            ofd.write(f"MAKE_VECTOR(gn_{node}_{i}_next, {len(n)}, {items});\n")
            items = ", ".join(f"&gn_{node}[{i}]" for i in p)
            ofd.write(f"MAKE_VECTOR(gn_{node}_{i}_prev, {len(p)}, {items});\n")

        ofd.write(f"\nstatic struct graph_node gn_{node}[] = {'{'}\n")
        for i, token in enumerate(graph):
            ofd.write("\t{\n")
            ofd.write(f"\t\t.from = &gn_{node}_{i}_prev,\n")
            ofd.write(f"\t\t.to = &gn_{node}_{i}_next,\n")
            if token.type == "CMD_ELEMENT_TKN":
                ofd.write(f"\t\t.data = (void *)&{token.text}_vtysh,\n")
            else:
                ofd.write(f"\t\t.data = &ctkn_{node}[{i}],\n")
            ofd.write("\t},\n")
        ofd.write("};\n")

        items = ", ".join(f"&gn_{node}[{i}]" for i in range(0, len(graph)))
        ofd.write(f"MAKE_VECTOR(gvec_{node}, {len(graph)}, {items});\n")

        ofd.write(
            f"""
{"extern " if splitfile else "static "}void install_{node}(void);\n
{""        if splitfile else "static "}void install_{node}(void)\n
{'{'}
	unsigned node_id = {node};
	struct cmd_node *node;

	assert(node_id < vector_active(cmdvec));
	node = vector_slot(cmdvec, node_id);
	assert(node);
	assert(vector_active(node->cmdgraph->nodes) == 1);
	graph_delete_node(node->cmdgraph, vector_slot(node->cmdgraph->nodes, 0));
	vector_free(node->cmdgraph->nodes);
	node->cmdgraph->nodes = &gvec_{node};
"""
        )
        for cmdel in sorted(cmdels):
            ofd.write(f"\tvector_set(node->cmd_vector, &{cmdel}_vtysh);\n")
        ofd.write("}\n")

        return [node]

    @classmethod
    def run(cls, xref, ofds):
        for ofd in ofds:
            ofd.write(vtysh_cmd_head)

        ofd = ofds.pop(0)
>>>>>>> 9b0b9282d (bgpd: Fix bgp core with a possible Intf delete)

        NodeDict.load_nodenames()
        nodes = cls.load(xref)
        cls.output_defs(ofd)
<<<<<<< HEAD
        cls.output_install(ofd, nodes)
=======

        out_nodes = []
        for nodeid, cmds in nodes.items():
            node = nodes.nodename(nodeid)

            if ofds:
                gfd, splitfile = ofds[nodeid % len(ofds)], True
            else:
                gfd, splitfile = ofd, False

            # install_element(VIEW_NODE, x) implies install_element(ENABLE_NODE, x)
            # this needs to be handled here.
            if node == "ENABLE_NODE":
                nodeid_view = list(
                    k for k, v in nodes.nodenames.items() if v == "VIEW_NODE"
                )
                assert len(nodeid_view) == 1
                cmds.update(nodes[nodeid_view[0]])

            out_nodes.extend(cls.output_node_graph(gfd, node, cmds, splitfile))

        out_nodes.sort()

        if ofds:
            ofd.write("\n")
            for name in out_nodes:
                ofd.write(f"extern void install_{name}(void);\n")

        ofd.write("\nvoid vtysh_init_cmd(void)\n{\n")

        for name in out_nodes:
            ofd.write(f"\tinstall_{name}();\n")

        ofd.write("}\n")
>>>>>>> 9b0b9282d (bgpd: Fix bgp core with a possible Intf delete)


def main():
    argp = argparse.ArgumentParser(description="FRR xref to vtysh defs")
    argp.add_argument(
        "xreffile", metavar="XREFFILE", type=str, help=".xref file to read"
    )
    argp.add_argument("-Werror", action="store_const", const=True)
    args = argp.parse_args()

    with open(args.xreffile, "r") as fd:
        data = json.load(fd)

    CommandEntry.run(data, sys.stdout)

    if args.Werror and CommandEntry.warn_counter:
        sys.exit(1)


if __name__ == "__main__":
    main()
