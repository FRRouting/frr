# SPDX-License-Identifier: GPL-2.0-or-later
# callgraph json to graphviz generator for FRR
#
# Copyright (C) 2020  David Lamparter for NetDEF, Inc.

import re
import sys
import json


class FunctionNode(object):
    funcs = {}

    def __init__(self, name):
        super().__init__()
        FunctionNode.funcs[name] = self

        self.name = name
        self.out = []
        self.inb = []
        self.rank = None
        self.defined = False
        self.defs = []

    def __repr__(self):
        return '<"%s()" rank=%r>' % (self.name, self.rank)

    def define(self, attrs):
        self.defined = True
        self.defs.append((attrs["filename"], attrs["line"]))
        return self

    def add_call(self, called, attrs):
        return CallEdge(self, called, attrs)

    def calls(self):
        for e in self.out:
            yield e.o

    def calld(self):
        for e in self.inb:
            yield e.i

    def unlink(self, other):
        self.out = list([edge for edge in self.out if edge.o != other])
        other.inb = list([edge for edge in other.inb if edge.i != other])

    @classmethod
    def get(cls, name):
        if name in cls.funcs:
            return cls.funcs[name]
        return FunctionNode(name)


class CallEdge(object):
    def __init__(self, i, o, attrs):
        self.i = i
        self.o = o
        self.is_external = attrs["is_external"]
        self.attrs = attrs

        i.out.append(self)
        o.inb.append(self)

    def __repr__(self):
        return '<"%s()" -> "%s()">' % (self.i.name, self.o.name)


def nameclean(n):
    if "." in n:
        return n.split(".", 1)[0]
    return n


def calc_rank(queue, direction):
    nextq = queue

    if direction == 1:
        aggr = max
        elem = lambda x: x.calls()
    else:
        aggr = min
        elem = lambda x: x.calld()

    currank = direction
    cont = True

    while len(nextq) > 0 and cont:
        queue = nextq
        nextq = []

        # sys.stderr.write('rank %d\n' % currank)

        cont = False

        for node in queue:
            if not node.defined:
                node.rank = 0
                continue

            rank = direction
            for other in elem(node):
                if other is node:
                    continue
                if other.rank is None:
                    nextq.append(node)
                    break
                rank = aggr(rank, other.rank + direction)
            else:
                cont = True
                node.rank = rank

        currank += direction

    return nextq


class Graph(dict):
    class Subgraph(set):
        def __init__(self):
            super().__init__()

    class NodeGroup(set):
        def __init__(self, members):
            super().__init__(members)

    class Node(object):
        def __init__(self, graph, fn):
            super().__init__()
            self._fn = fn
            self._fns = [fn]
            self._graph = graph
            self._calls = set()
            self._calld = set()
            self._group = None

        def __repr__(self):
            return '<Graph.Node "%s()"/%d>' % (self._fn.name, len(self._fns))

        def __hash__(self):
            return hash(self._fn.name)

        def _finalize(self):
            for called in self._fn.calls():
                if called.name == self._fn.name:
                    continue
                if called.name in self._graph:
                    self._calls.add(self._graph[called.name])
                    self._graph[called.name]._calld.add(self)

        def unlink(self, other):
            self._calls.remove(other)
            other._calld.remove(self)

        @property
        def name(self):
            return self._fn.name

        def calls(self):
            return self._calls

        def calld(self):
            return self._calld

        def group(self, members):
            assert self in members

            pregroups = []
            for g in [m._group for m in members]:
                if g is None:
                    continue
                if g in pregroups:
                    continue

                assert g <= members
                pregroups.append(g)

            if len(pregroups) == 0:
                group = self._graph.NodeGroup(members)
                self._graph._groups.append(group)
            elif len(pregroups) == 1:
                group = pregroups[0]
                group |= members
            else:
                for g in pregroups:
                    self._graph._groups.remove(g)
                group = self._graph.NodeGroup(members)
                self._graph._groups.append(group)

            for m in members:
                m._group = group
            return group

        def merge(self, other):
            self._fns.extend(other._fns)
            self._calls = (self._calls | other._calls) - {self, other}
            self._calld = (self._calld | other._calld) - {self, other}
            for c in other._calls:
                if c == self:
                    continue
                c._calld.remove(other)
                c._calld.add(self)
            for c in other._calld:
                if c == self:
                    continue
                c._calls.remove(other)
                c._calls.add(self)
            del self._graph[other._fn.name]

    def __init__(self, funcs):
        super().__init__()
        self._funcs = funcs
        for fn in funcs:
            self[fn.name] = self.Node(self, fn)
        for node in self.values():
            node._finalize()
        self._groups = []

    def automerge(self):
        nodes = list(self.values())

        while len(nodes):
            node = nodes.pop(0)

            candidates = {node}
            evalset = set(node.calls())
            prevevalset = None

            while prevevalset != evalset:
                prevevalset = evalset
                evalset = set()

                for evnode in prevevalset:
                    inbound = set(evnode.calld())
                    if inbound <= candidates:
                        candidates.add(evnode)
                        evalset |= set(evnode.calls()) - candidates
                    else:
                        evalset.add(evnode)

            # if len(candidates) > 1:
            #    for candidate in candidates:
            #        if candidate != node:
            #            #node.merge(candidate)
            #            if candidate in nodes:
            #                nodes.remove(candidate)
            node.group(candidates)

            for candidate in candidates:
                if candidate in nodes:
                    nodes.remove(candidate)

    def calc_subgraphs(self):
        nodes = list(self.values())
        self._subgraphs = []
        up = {}
        down = {}

        self._linear_nodes = []

        while len(nodes):
            sys.stderr.write("%d\n" % len(nodes))
            node = nodes.pop(0)

            down[node] = set()
            queue = [node]
            while len(queue):
                now = queue.pop()
                down[node].add(now)
                for calls in now.calls():
                    if calls in down[node]:
                        continue
                    queue.append(calls)

            up[node] = set()
            queue = [node]
            while len(queue):
                now = queue.pop()
                up[node].add(now)
                for calld in now.calld():
                    if calld in up[node]:
                        continue
                    queue.append(calld)

            common = up[node] & down[node]

            if len(common) == 1:
                self._linear_nodes.append(node)
            else:
                sg = self.Subgraph()
                sg |= common
                self._subgraphs.append(sg)
                for n in common:
                    if n != node:
                        nodes.remove(n)

        return self._subgraphs, self._linear_nodes


with open(sys.argv[1], "r") as fd:
    data = json.load(fd)

extra_info = {
    # zebra - LSP WQ
    ("lsp_processq_add", "work_queue_add"): [
        "lsp_process",
        "lsp_processq_del",
        "lsp_processq_complete",
    ],
    # zebra - main WQ
    ("mq_add_handler", "work_queue_add"): [
        "meta_queue_process",
    ],
    ("meta_queue_process", "work_queue_add"): [
        "meta_queue_process",
    ],
    # bgpd - label pool WQ
    ("bgp_lp_get", "work_queue_add"): [
        "lp_cbq_docallback",
    ],
    ("bgp_lp_event_chunk", "work_queue_add"): [
        "lp_cbq_docallback",
    ],
    ("bgp_lp_event_zebra_up", "work_queue_add"): [
        "lp_cbq_docallback",
    ],
    # bgpd - main WQ
    ("bgp_process", "work_queue_add"): [
        "bgp_process_wq",
        "bgp_processq_del",
    ],
    ("bgp_add_eoiu_mark", "work_queue_add"): [
        "bgp_process_wq",
        "bgp_processq_del",
    ],
    # clear node WQ
    ("bgp_clear_route_table", "work_queue_add"): [
        "bgp_clear_route_node",
        "bgp_clear_node_queue_del",
        "bgp_clear_node_complete",
    ],
    # rfapi WQs
    ("rfapi_close", "work_queue_add"): [
        "rfapi_deferred_close_workfunc",
    ],
    ("rfapiRibUpdatePendingNode", "work_queue_add"): [
        "rfapiRibDoQueuedCallback",
        "rfapiRibQueueItemDelete",
    ],
}


for func, fdata in data["functions"].items():
    func = nameclean(func)
    fnode = FunctionNode.get(func).define(fdata)

    for call in fdata["calls"]:
        if call.get("type") in [None, "unnamed", "thread_sched"]:
            if call.get("target") is None:
                continue
            tgt = nameclean(call["target"])
            fnode.add_call(FunctionNode.get(tgt), call)
            for fptr in call.get("funcptrs", []):
                fnode.add_call(FunctionNode.get(nameclean(fptr)), call)
            if tgt == "work_queue_add":
                if (func, tgt) not in extra_info:
                    sys.stderr.write(
                        "%s:%d:%s(): work_queue_add() not handled\n"
                        % (call["filename"], call["line"], func)
                    )
                else:
                    attrs = dict(call)
                    attrs.update({"is_external": False, "type": "workqueue"})
                    for dst in extra_info[func, tgt]:
                        fnode.add_call(FunctionNode.get(dst), call)
        elif call["type"] == "install_element":
            vty_node = FunctionNode.get("VTY_NODE_%d" % call["vty_node"])
            vty_node.add_call(FunctionNode.get(nameclean(call["target"])), call)
        elif call["type"] == "hook":
            # TODO: edges for hooks from data['hooks']
            pass

n = FunctionNode.funcs

# fix some very low end functions cycling back very far to the top
if "peer_free" in n:
    n["peer_free"].unlink(n["bgp_timer_set"])
    n["peer_free"].unlink(n["bgp_addpath_set_peer_type"])
if "bgp_path_info_extra_free" in n:
    n["bgp_path_info_extra_free"].rank = 0

if "zlog_ref" in n:
    n["zlog_ref"].rank = 0
if "mt_checkalloc" in n:
    n["mt_checkalloc"].rank = 0

queue = list(FunctionNode.funcs.values())
queue = calc_rank(queue, 1)
queue = calc_rank(queue, -1)

sys.stderr.write("%d functions in cyclic set\n" % len(queue))

graph = Graph(queue)
graph.automerge()

gv_nodes = []
gv_edges = []

sys.stderr.write("%d groups after automerge\n" % len(graph._groups))


def is_vnc(n):
    return n.startswith("rfapi") or n.startswith("vnc") or ("_vnc_" in n)


_vncstyle = ',fillcolor="#ffffcc",style=filled'
cyclic_set_names = set([fn.name for fn in graph.values()])

for i, group in enumerate(graph._groups):
    if len(group) > 1:
        group.num = i
        gv_nodes.append("\tsubgraph cluster_%d {" % i)
        gv_nodes.append("\t\tcolor=blue;")
        for gn in group:
            has_cycle_callers = set(gn.calld()) - group
            has_ext_callers = (
                set([edge.i.name for edge in gn._fn.inb]) - cyclic_set_names
            )

            style = ""
            etext = ""
            if is_vnc(gn.name):
                style += _vncstyle
            if has_cycle_callers:
                style += ",color=blue,penwidth=3"
            if has_ext_callers:
                style += ',fillcolor="#ffeebb",style=filled'
                etext += '<br/><font point-size="10">(%d other callers)</font>' % (
                    len(has_ext_callers)
                )

            gv_nodes.append(
                '\t\t"%s" [shape=box,label=<%s%s>%s];'
                % (gn.name, "<br/>".join([fn.name for fn in gn._fns]), etext, style)
            )
        gv_nodes.append("\t}")
    else:
        for gn in group:
            has_ext_callers = (
                set([edge.i.name for edge in gn._fn.inb]) - cyclic_set_names
            )

            style = ""
            etext = ""
            if is_vnc(gn.name):
                style += _vncstyle
            if has_ext_callers:
                style += ',fillcolor="#ffeebb",style=filled'
                etext += '<br/><font point-size="10">(%d other callers)</font>' % (
                    len(has_ext_callers)
                )
            gv_nodes.append(
                '\t"%s" [shape=box,label=<%s%s>%s];'
                % (gn.name, "<br/>".join([fn.name for fn in gn._fns]), etext, style)
            )

edges = set()
for gn in graph.values():
    for calls in gn.calls():
        if gn._group == calls._group:
            gv_edges.append(
                '\t"%s" -> "%s" [color="#55aa55",style=dashed];' % (gn.name, calls.name)
            )
        else:

            def xname(nn):
                if len(nn._group) > 1:
                    return "cluster_%d" % nn._group.num
                else:
                    return nn.name

            tup = xname(gn), calls.name
            if tup[0] != tup[1] and tup not in edges:
                gv_edges.append('\t"%s" -> "%s" [weight=0.0,w=0.0,color=blue];' % tup)
                edges.add(tup)

with open(sys.argv[2], "w") as fd:
    fd.write(
        """digraph {
    node [fontsize=13,fontname="Fira Sans"];
%s
}"""
        % "\n".join(gv_nodes + [""] + gv_edges)
    )
