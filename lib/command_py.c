// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * clippy (CLI preparator in python) wrapper for FRR command_graph
 * Copyright (C) 2016-2017  David Lamparter for NetDEF, Inc.
 */

/* note: this wrapper is intended to be used as build-time helper.  while
 * it should be generally correct and proper, there may be the occasional
 * memory leak or SEGV for things that haven't been well-tested.
 */

/* This file is "exempt" from having
#include "config.h"
 * as the first include statement because Python.h also does environment
 * setup & these trample over each other.
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif
#include <Python.h>
#include "structmember.h"
#include <string.h>
#include <stdlib.h>

#include "command_graph.h"
#include "clippy.h"

struct wrap_graph;
static PyObject *graph_to_pyobj(struct wrap_graph *graph,
				struct graph_node *gn);
static PyObject *graph_to_pyobj_idx(struct wrap_graph *wgraph, size_t i);

/*
 * nodes are wrapped as follows:
 *  - instances can only be acquired from a graph
 *  - the same node will return the same wrapper object (they're buffered
 *    through "idx")
 *  - a reference is held onto the graph
 *  - fields are copied for easy access with PyMemberDef
 */
struct wrap_graph_node {
	PyObject_HEAD

		bool allowrepeat;
	const char *type;

	struct graph_node *node;
	struct wrap_graph *wgraph;
	size_t idx;
};

/*
 * graphs are wrapped as follows:
 *  - they can only be created by parsing a definition string
 *  - there's a table here for the wrapped nodes (nodewrappers), indexed
 *    by "idx" (corresponds to node's position in graph's table of nodes)
 *  - graphs do NOT hold references to nodes (would be circular)
 */
struct wrap_graph {
	PyObject_HEAD

		char *definition;
	struct graph *graph;
	size_t n_nodewrappers;
	struct wrap_graph_node **nodewrappers;
};

static PyObject *refuse_new(PyTypeObject *type, PyObject *args, PyObject *kwds)
{
	PyErr_SetString(PyExc_ValueError,
			"cannot create instances of this type");
	return NULL;
}

#define member(name, type)                                                     \
	{                                                                      \
		(char *)#name, type, offsetof(struct wrap_graph_node, name),   \
			READONLY, (char *)#name " (" #type ")"                 \
	}
static PyMemberDef members_graph_node[] = {
	/* clang-format off */
	member(type, T_STRING),
	member(idx, T_ULONG),
	{},
	/* clang-format on */
};
#undef member

static PyObject *graph_node_get_str(PyObject *self, void *poffset)
{
	struct wrap_graph_node *wrap = (struct wrap_graph_node *)self;
	void *offset = (char *)wrap->node->data + (ptrdiff_t)poffset;
	const char *val = *(const char **)offset;

	if (!val)
		Py_RETURN_NONE;
	return PyUnicode_FromString(val);
}

static PyObject *graph_node_get_bool(PyObject *self, void *poffset)
{
	struct wrap_graph_node *wrap = (struct wrap_graph_node *)self;
	void *offset = (char *)wrap->node->data + (ptrdiff_t)poffset;
	bool val = *(bool *)offset;

	return PyBool_FromLong(val);
}

static PyObject *graph_node_get_ll(PyObject *self, void *poffset)
{
	struct wrap_graph_node *wrap = (struct wrap_graph_node *)self;
	void *offset = (char *)wrap->node->data + (ptrdiff_t)poffset;
	long long val = *(long long *)offset;

	return PyLong_FromLongLong(val);
}

static PyObject *graph_node_get_u8(PyObject *self, void *poffset)
{
	struct wrap_graph_node *wrap = (struct wrap_graph_node *)self;
	void *offset = (char *)wrap->node->data + (ptrdiff_t)poffset;
	uint8_t val = *(uint8_t *)offset;

	return PyLong_FromUnsignedLong(val);
}

/* clang-format off */
#define member(name, variant)                                                  \
	{                                                                      \
		(char *)#name,                                                 \
		graph_node_get_##variant,                                      \
		NULL,                                                          \
		(char *)#name " (" #variant ")",                               \
		(void *)offsetof(struct cmd_token, name),                      \
	}
/* clang-format on */

static PyGetSetDef getset_graph_node[] = {
	/* clang-format off */
	member(attr, u8),
	member(allowrepeat, bool),
	member(varname_src, u8),
	member(text, str),
	member(desc, str),
	member(min, ll),
	member(max, ll),
	member(varname, str),
	{},
	/* clang-format on */
};
#undef member

/*
 * node.next() -- returns list of all "next" nodes.
 * this will include circles if the graph has them.
 */
static PyObject *graph_node_next(PyObject *self, PyObject *args)
{
	struct wrap_graph_node *wrap = (struct wrap_graph_node *)self;
	PyObject *pylist;

	if (wrap->node->data &&
	    ((struct cmd_token *)wrap->node->data)->type == CMD_ELEMENT_TKN)
		return PyList_New(0);
	pylist = PyList_New(vector_active(wrap->node->to));
	for (size_t i = 0; i < vector_active(wrap->node->to); i++) {
		struct graph_node *gn = vector_slot(wrap->node->to, i);

		PyList_SetItem(pylist, i, graph_to_pyobj(wrap->wgraph, gn));
	}
	return pylist;
};

static PyObject *graph_node_prev(PyObject *self, PyObject *args)
{
	struct wrap_graph_node *wrap = (struct wrap_graph_node *)self;
	PyObject *pylist;

	if (wrap->node->data &&
	    ((struct cmd_token *)wrap->node->data)->type == START_TKN)
		return PyList_New(0);
	pylist = PyList_New(vector_active(wrap->node->from));
	for (size_t i = 0; i < vector_active(wrap->node->from); i++) {
		struct graph_node *gn = vector_slot(wrap->node->from, i);

		PyList_SetItem(pylist, i, graph_to_pyobj(wrap->wgraph, gn));
	}
	return pylist;
};

/*
 * node.join() -- return FORK's JOIN node or None
 */
static PyObject *graph_node_join(PyObject *self, PyObject *args)
{
	struct wrap_graph_node *wrap = (struct wrap_graph_node *)self;
	struct cmd_token *tok;

	if (!wrap->node->data
	    || ((struct cmd_token *)wrap->node->data)->type == END_TKN)
		Py_RETURN_NONE;

	tok = wrap->node->data;
	if (tok->type != FORK_TKN)
		Py_RETURN_NONE;

	return graph_to_pyobj(wrap->wgraph, tok->forkjoin);
};

static PyObject *graph_node_fork(PyObject *self, PyObject *args)
{
	struct wrap_graph_node *wrap = (struct wrap_graph_node *)self;
	struct cmd_token *tok;

	if (!wrap->node->data ||
	    ((struct cmd_token *)wrap->node->data)->type == END_TKN)
		Py_RETURN_NONE;

	tok = wrap->node->data;
	if (tok->type != JOIN_TKN)
		Py_RETURN_NONE;

	return graph_to_pyobj(wrap->wgraph, tok->forkjoin);
};

static PyMethodDef methods_graph_node[] = {
	{ "next", graph_node_next, METH_NOARGS, "outbound graph edge list" },
	{ "prev", graph_node_prev, METH_NOARGS, "inbound graph edge list" },
	{ "join", graph_node_join, METH_NOARGS, "outbound join node" },
	{ "fork", graph_node_fork, METH_NOARGS, "inbound fork node" },
	{}
};

static void graph_node_wrap_free(void *arg)
{
	struct wrap_graph_node *wrap = arg;

	assert(wrap->idx < wrap->wgraph->n_nodewrappers);
	wrap->wgraph->nodewrappers[wrap->idx] = NULL;
	Py_DECREF(wrap->wgraph);
}

static PyObject *repr_graph_node(PyObject *arg)
{
	struct wrap_graph_node *wrap = (struct wrap_graph_node *)arg;

	return PyUnicode_FromFormat("<_clippy.GraphNode %p [%zu] %s>",
				    wrap->node, wrap->idx, wrap->type);
}

static PyTypeObject typeobj_graph_node = {
	PyVarObject_HEAD_INIT(NULL, 0).tp_name = "_clippy.GraphNode",
	.tp_basicsize = sizeof(struct wrap_graph_node),
	.tp_flags = Py_TPFLAGS_DEFAULT,
	.tp_doc = "struct graph_node *",
	.tp_new = refuse_new,
	.tp_free = graph_node_wrap_free,
	.tp_members = members_graph_node,
	.tp_getset = getset_graph_node,
	.tp_methods = methods_graph_node,
	.tp_repr = repr_graph_node,
};

static PyObject *graph_to_pyobj(struct wrap_graph *wgraph,
				struct graph_node *gn)
{
	size_t i;

	for (i = 0; i < vector_active(wgraph->graph->nodes); i++)
		if (vector_slot(wgraph->graph->nodes, i) == gn)
			break;
	if (i == vector_active(wgraph->graph->nodes)) {
		PyErr_SetString(PyExc_ValueError, "cannot find node in graph");
		return NULL;
	}

	return graph_to_pyobj_idx(wgraph, i);
}

static PyObject *graph_to_pyobj_idx(struct wrap_graph *wgraph, size_t i)
{
	struct wrap_graph_node *wrap;
	struct graph_node *gn = vector_slot(wgraph->graph->nodes, i);

	if (i >= wgraph->n_nodewrappers) {
		wgraph->nodewrappers =
			realloc(wgraph->nodewrappers,
				(i + 1) * sizeof(wgraph->nodewrappers[0]));
		memset(wgraph->nodewrappers + wgraph->n_nodewrappers, 0,
		       sizeof(wgraph->nodewrappers[0]) *
			       (i + 1 - wgraph->n_nodewrappers));
		wgraph->n_nodewrappers = i + 1;
	}
	if (wgraph->nodewrappers[i]) {
		PyObject *obj = (PyObject *)wgraph->nodewrappers[i];
		Py_INCREF(obj);
		return obj;
	}

	wrap = (struct wrap_graph_node *)typeobj_graph_node.tp_alloc(
		&typeobj_graph_node, 0);
	if (!wrap)
		return NULL;
	wgraph->nodewrappers[i] = wrap;
	Py_INCREF(wgraph);

	wrap->idx = i;
	wrap->wgraph = wgraph;
	wrap->node = gn;
	wrap->type = "NULL";
	wrap->allowrepeat = false;
	if (gn->data) {
		struct cmd_token *tok = gn->data;
		switch (tok->type) {
#define item(x)                                                                \
	case x:                                                                \
		wrap->type = #x;                                               \
		break /* no semicolon */

			item(WORD_TKN);	       // words
			item(VARIABLE_TKN);    // almost anything
			item(RANGE_TKN);       // integer range
			item(IPV4_TKN);	       // IPV4 addresses
			item(IPV4_PREFIX_TKN); // IPV4 network prefixes
			item(IPV6_TKN);	       // IPV6 prefixes
			item(IPV6_PREFIX_TKN); // IPV6 network prefixes
			item(MAC_TKN);	       // MAC address
			item(MAC_PREFIX_TKN);  // MAC address with mask
			item(ASNUM_TKN);       // ASNUM

			/* plumbing types */
			item(FORK_TKN);
			item(JOIN_TKN);
			item(START_TKN);
			item(END_TKN);
			item(NEG_ONLY_TKN);
			item(CMD_ELEMENT_TKN);
#undef item
		default:
			wrap->type = "???";
		}
	}

	return (PyObject *)wrap;
}

#define member(name, type)                                                     \
	{                                                                      \
		(char *)#name, type, offsetof(struct wrap_graph, name),        \
			READONLY, (char *)#name " (" #type ")"                 \
	}
static PyMemberDef members_graph[] = {
	member(definition, T_STRING),
	{},
};
#undef member

/* graph.first() - root node */
static PyObject *graph_first(PyObject *self, PyObject *args)
{
	struct wrap_graph *gwrap = (struct wrap_graph *)self;
	struct graph_node *gn = vector_slot(gwrap->graph->nodes, 0);
	return graph_to_pyobj(gwrap, gn);
};

static PyObject *graph_merge(PyObject *self, PyObject *args);

static PyMethodDef methods_graph[] = {
	{ "first", graph_first, METH_NOARGS, "first graph node" },
	{ "merge", graph_merge, METH_VARARGS, "merge graphs" },
	{}
};

static PyObject *graph_parse(PyTypeObject *type, PyObject *args,
			     PyObject *kwds);

static void graph_wrap_free(void *arg)
{
	struct wrap_graph *wgraph = arg;

	graph_delete_graph(wgraph->graph);
	free(wgraph->nodewrappers);
	free(wgraph->definition);
}

static Py_ssize_t graph_length(PyObject *self)
{
	struct wrap_graph *gwrap = (struct wrap_graph *)self;

	return vector_active(gwrap->graph->nodes);
}

static PyObject *graph_item(PyObject *self, Py_ssize_t idx)
{
	struct wrap_graph *gwrap = (struct wrap_graph *)self;

	if (idx >= vector_active(gwrap->graph->nodes))
		return PyErr_Format(PyExc_IndexError,
				    "index %zd past graph size %u", idx,
				    vector_active(gwrap->graph->nodes));

	return graph_to_pyobj_idx(gwrap, idx);
}

static PySequenceMethods seq_graph = {
	.sq_length = graph_length,
	.sq_item = graph_item,
};

static PyTypeObject typeobj_graph = {
	PyVarObject_HEAD_INIT(NULL, 0).tp_name = "_clippy.Graph",
	.tp_basicsize = sizeof(struct wrap_graph),
	.tp_flags = Py_TPFLAGS_DEFAULT,
	.tp_doc = "struct graph *",
	.tp_new = graph_parse,
	.tp_free = graph_wrap_free,
	.tp_members = members_graph,
	.tp_methods = methods_graph,
	.tp_as_sequence = &seq_graph,
};

static PyObject *graph_merge(PyObject *self, PyObject *args)
{
	PyObject *py_other;
	struct wrap_graph *gwrap = (struct wrap_graph *)self;
	struct wrap_graph *gother;

	if (!PyArg_ParseTuple(args, "O!", &typeobj_graph, &py_other))
		return NULL;

	gother = (struct wrap_graph *)py_other;
	cmd_graph_merge(gwrap->graph, gother->graph, +1);
	Py_RETURN_NONE;
}

/* top call / entrypoint for python code */
static PyObject *graph_parse(PyTypeObject *type, PyObject *args, PyObject *kwds)
{
	const char *def, *doc = NULL, *name = NULL;
	struct wrap_graph *gwrap;
	static const char *const kwnames[] = { "cmddef", "doc", "name", NULL };

	gwrap = (struct wrap_graph *)typeobj_graph.tp_alloc(&typeobj_graph, 0);
	if (!gwrap)
		return NULL;

	if (!PyArg_ParseTupleAndKeywords(args, kwds, "z|ss", (char **)kwnames,
					 &def, &doc, &name))
		return NULL;

	struct graph *graph = graph_new();
	struct cmd_token *token = cmd_token_new(START_TKN, 0, NULL, NULL);
	graph_new_node(graph, token, (void (*)(void *)) & cmd_token_del);

	if (def) {
		struct cmd_element cmd = { .string = def, .doc = doc };
		struct graph_node *last;

		cmd_graph_parse(graph, &cmd);
		cmd_graph_names(graph);

		last = vector_slot(graph->nodes,
				   vector_active(graph->nodes) - 1);
		assert(last->data == &cmd);

		last->data = cmd_token_new(CMD_ELEMENT_TKN, 0, name, def);
		last->del = (void (*)(void *))cmd_token_del;

		gwrap->definition = strdup(def);
	} else {
		gwrap->definition = strdup("NULL");
	}

	gwrap->graph = graph;
	return (PyObject *)gwrap;
}

static PyMethodDef clippy_methods[] = {
	{"parse", clippy_parse, METH_VARARGS, "Parse a C file"},
	{NULL, NULL, 0, NULL}};

#if PY_MAJOR_VERSION >= 3
static struct PyModuleDef pymoddef_clippy = {
	PyModuleDef_HEAD_INIT,
	"_clippy",
	NULL, /* docstring */
	-1,
	clippy_methods,
};
#define modcreate() PyModule_Create(&pymoddef_clippy)
#define initret(val) return val;
#else
#define modcreate() Py_InitModule("_clippy", clippy_methods)
#define initret(val)                                                           \
	do {                                                                   \
		if (!val)                                                      \
			Py_FatalError("initialization failure");               \
		return;                                                        \
	} while (0)
#endif

#pragma GCC diagnostic ignored "-Wstrict-aliasing"
PyMODINIT_FUNC command_py_init(void)
{
	PyObject *pymod;

	if (PyType_Ready(&typeobj_graph_node) < 0)
		initret(NULL);
	if (PyType_Ready(&typeobj_graph) < 0)
		initret(NULL);

	pymod = modcreate();
	if (!pymod)
		initret(NULL);

	if (PyModule_AddIntMacro(pymod, CMD_ATTR_YANG)
	    || PyModule_AddIntMacro(pymod, CMD_ATTR_HIDDEN)
	    || PyModule_AddIntMacro(pymod, CMD_ATTR_DEPRECATED)
	    || PyModule_AddIntMacro(pymod, CMD_ATTR_NOSH))
		initret(NULL);

	Py_INCREF(&typeobj_graph_node);
	PyModule_AddObject(pymod, "GraphNode", (PyObject *)&typeobj_graph_node);
	Py_INCREF(&typeobj_graph);
	PyModule_AddObject(pymod, "Graph", (PyObject *)&typeobj_graph);
	if (!elf_py_init(pymod))
		initret(NULL);
	initret(pymod);
}
