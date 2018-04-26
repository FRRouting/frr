/*
 * CLI graph handling
 *
 * --
 * Copyright (C) 2016 Cumulus Networks, Inc.
 * Copyright (C) 1997, 98, 99 Kunihiro Ishiguro
 * Copyright (C) 2013 by Open Source Routing.
 * Copyright (C) 2013 by Internet Systems Consortium, Inc. ("ISC")
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the Free
 * Software Foundation; either version 2 of the License, or (at your option)
 * any later version.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; see the file COPYING; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA
 */

#include <zebra.h>

#include "command_graph.h"

DEFINE_MTYPE_STATIC(LIB, CMD_TOKENS, "Command Tokens")
DEFINE_MTYPE_STATIC(LIB, CMD_DESC, "Command Token Text")
DEFINE_MTYPE_STATIC(LIB, CMD_TEXT, "Command Token Help")
DEFINE_MTYPE(LIB, CMD_ARG, "Command Argument")
DEFINE_MTYPE_STATIC(LIB, CMD_VAR, "Command Argument Name")

struct cmd_token *cmd_token_new(enum cmd_token_type type, uint8_t attr,
				const char *text, const char *desc)
{
	struct cmd_token *token =
		XCALLOC(MTYPE_CMD_TOKENS, sizeof(struct cmd_token));
	token->type = type;
	token->attr = attr;
	token->text = text ? XSTRDUP(MTYPE_CMD_TEXT, text) : NULL;
	token->desc = desc ? XSTRDUP(MTYPE_CMD_DESC, desc) : NULL;
	token->refcnt = 1;
	token->arg = NULL;
	token->allowrepeat = false;
	token->varname = NULL;

	return token;
}

void cmd_token_del(struct cmd_token *token)
{
	if (!token)
		return;

	XFREE(MTYPE_CMD_TEXT, token->text);
	XFREE(MTYPE_CMD_DESC, token->desc);
	XFREE(MTYPE_CMD_ARG, token->arg);
	XFREE(MTYPE_CMD_VAR, token->varname);

	XFREE(MTYPE_CMD_TOKENS, token);
}

struct cmd_token *cmd_token_dup(struct cmd_token *token)
{
	struct cmd_token *copy =
		cmd_token_new(token->type, token->attr, NULL, NULL);
	copy->max = token->max;
	copy->min = token->min;
	copy->text = token->text ? XSTRDUP(MTYPE_CMD_TEXT, token->text) : NULL;
	copy->desc = token->desc ? XSTRDUP(MTYPE_CMD_DESC, token->desc) : NULL;
	copy->arg = token->arg ? XSTRDUP(MTYPE_CMD_ARG, token->arg) : NULL;
	copy->varname =
		token->varname ? XSTRDUP(MTYPE_CMD_VAR, token->varname) : NULL;

	return copy;
}

void cmd_token_varname_set(struct cmd_token *token, const char *varname)
{
	XFREE(MTYPE_CMD_VAR, token->varname);
	if (!varname) {
		token->varname = NULL;
		return;
	}

	size_t len = strlen(varname), i;
	token->varname = XMALLOC(MTYPE_CMD_VAR, len + 1);

	for (i = 0; i < len; i++)
		switch (varname[i]) {
		case '-':
		case '+':
		case '*':
		case ':':
			token->varname[i] = '_';
			break;
		default:
			token->varname[i] = tolower((int)varname[i]);
		}
	token->varname[len] = '\0';
}

static bool cmd_nodes_link(struct graph_node *from, struct graph_node *to)
{
	for (size_t i = 0; i < vector_active(from->to); i++)
		if (vector_slot(from->to, i) == to)
			return true;
	return false;
}

static bool cmd_nodes_equal(struct graph_node *ga, struct graph_node *gb);

/* returns a single node to be excluded as "next" from iteration
 * - for JOIN_TKN, never continue back to the FORK_TKN
 * - in all other cases, don't try the node itself (in case of "...")
 */
static inline struct graph_node *cmd_loopstop(struct graph_node *gn)
{
	struct cmd_token *tok = gn->data;
	if (tok->type == JOIN_TKN)
		return tok->forkjoin;
	else
		return gn;
}

static bool cmd_subgraph_equal(struct graph_node *ga, struct graph_node *gb,
			       struct graph_node *a_join)
{
	size_t i, j;
	struct graph_node *a_fork, *b_fork;
	a_fork = cmd_loopstop(ga);
	b_fork = cmd_loopstop(gb);

	if (vector_active(ga->to) != vector_active(gb->to))
		return false;
	for (i = 0; i < vector_active(ga->to); i++) {
		struct graph_node *cga = vector_slot(ga->to, i);

		for (j = 0; j < vector_active(gb->to); j++) {
			struct graph_node *cgb = vector_slot(gb->to, i);

			if (cga == a_fork && cgb != b_fork)
				continue;
			if (cga == a_fork && cgb == b_fork)
				break;

			if (cmd_nodes_equal(cga, cgb)) {
				if (cga == a_join)
					break;
				if (cmd_subgraph_equal(cga, cgb, a_join))
					break;
			}
		}
		if (j == vector_active(gb->to))
			return false;
	}
	return true;
}

/* deep compare -- for FORK_TKN, the entire subgraph is compared.
 * this is what's needed since we're not currently trying to partially
 * merge subgraphs */
static bool cmd_nodes_equal(struct graph_node *ga, struct graph_node *gb)
{
	struct cmd_token *a = ga->data, *b = gb->data;

	if (a->type != b->type || a->allowrepeat != b->allowrepeat)
		return false;
	if (a->type < SPECIAL_TKN && strcmp(a->text, b->text))
		return false;
	/* one a ..., the other not. */
	if (cmd_nodes_link(ga, ga) != cmd_nodes_link(gb, gb))
		return false;
	if (!a->varname != !b->varname)
		return false;
	if (a->varname && strcmp(a->varname, b->varname))
		return false;

	switch (a->type) {
	case RANGE_TKN:
		return a->min == b->min && a->max == b->max;

	case FORK_TKN:
		/* one is keywords, the other just option or selector ... */
		if (cmd_nodes_link(a->forkjoin, ga)
		    != cmd_nodes_link(b->forkjoin, gb))
			return false;
		if (cmd_nodes_link(ga, a->forkjoin)
		    != cmd_nodes_link(gb, b->forkjoin))
			return false;
		return cmd_subgraph_equal(ga, gb, a->forkjoin);

	default:
		return true;
	}
}

static void cmd_fork_bump_attr(struct graph_node *gn, struct graph_node *join,
			       uint8_t attr)
{
	size_t i;
	struct cmd_token *tok = gn->data;
	struct graph_node *stop = cmd_loopstop(gn);

	tok->attr = attr;
	for (i = 0; i < vector_active(gn->to); i++) {
		struct graph_node *next = vector_slot(gn->to, i);
		if (next == stop || next == join)
			continue;
		cmd_fork_bump_attr(next, join, attr);
	}
}

/* move an entire subtree from the temporary graph resulting from
 * parse() into the permanent graph for the command node.
 *
 * this touches rather deeply into the graph code unfortunately.
 */
static void cmd_reparent_tree(struct graph *fromgraph, struct graph *tograph,
			      struct graph_node *node)
{
	struct graph_node *stop = cmd_loopstop(node);
	size_t i;

	for (i = 0; i < vector_active(fromgraph->nodes); i++)
		if (vector_slot(fromgraph->nodes, i) == node) {
			/* agressive iteration punching through subgraphs - may
			 * hit some
			 * nodes twice.  reparent only if found on old graph */
			vector_unset(fromgraph->nodes, i);
			vector_set(tograph->nodes, node);
			break;
		}

	for (i = 0; i < vector_active(node->to); i++) {
		struct graph_node *next = vector_slot(node->to, i);
		if (next != stop)
			cmd_reparent_tree(fromgraph, tograph, next);
	}
}

static void cmd_free_recur(struct graph *graph, struct graph_node *node,
			   struct graph_node *stop)
{
	struct graph_node *next, *nstop;

	for (size_t i = vector_active(node->to); i; i--) {
		next = vector_slot(node->to, i - 1);
		if (next == stop)
			continue;
		nstop = cmd_loopstop(next);
		if (nstop != next)
			cmd_free_recur(graph, next, nstop);
		cmd_free_recur(graph, nstop, stop);
	}
	graph_delete_node(graph, node);
}

static void cmd_free_node(struct graph *graph, struct graph_node *node)
{
	struct cmd_token *tok = node->data;
	if (tok->type == JOIN_TKN)
		cmd_free_recur(graph, tok->forkjoin, node);
	graph_delete_node(graph, node);
}

/* recursive graph merge.  call with
 *   old ~= new
 * (which holds true for old == START_TKN, new == START_TKN)
 */
static void cmd_merge_nodes(struct graph *oldgraph, struct graph *newgraph,
			    struct graph_node *old, struct graph_node *new,
			    int direction)
{
	struct cmd_token *tok;
	struct graph_node *old_skip, *new_skip;
	old_skip = cmd_loopstop(old);
	new_skip = cmd_loopstop(new);

	assert(direction == 1 || direction == -1);

	tok = old->data;
	tok->refcnt += direction;

	size_t j, i;
	for (j = 0; j < vector_active(new->to); j++) {
		struct graph_node *cnew = vector_slot(new->to, j);
		if (cnew == new_skip)
			continue;

		for (i = 0; i < vector_active(old->to); i++) {
			struct graph_node *cold = vector_slot(old->to, i);
			if (cold == old_skip)
				continue;

			if (cmd_nodes_equal(cold, cnew)) {
				struct cmd_token *told = cold->data,
						 *tnew = cnew->data;

				if (told->type == END_TKN) {
					if (direction < 0) {
						graph_delete_node(
							oldgraph,
							vector_slot(cold->to,
								    0));
						graph_delete_node(oldgraph,
								  cold);
					} else
						/* force no-match handling to
						 * install END_TKN */
						i = vector_active(old->to);
					break;
				}

				/* the entire fork compared as equal, we
				 * continue after it. */
				if (told->type == FORK_TKN) {
					if (tnew->attr < told->attr
					    && direction > 0)
						cmd_fork_bump_attr(
							cold, told->forkjoin,
							tnew->attr);
					/* XXX: no reverse bump on uninstall */
					told = (cold = told->forkjoin)->data;
					tnew = (cnew = tnew->forkjoin)->data;
				}
				if (tnew->attr < told->attr)
					told->attr = tnew->attr;

				cmd_merge_nodes(oldgraph, newgraph, cold, cnew,
						direction);
				break;
			}
		}
		/* nothing found => add new to old */
		if (i == vector_active(old->to) && direction > 0) {
			graph_remove_edge(new, cnew);

			cmd_reparent_tree(newgraph, oldgraph, cnew);

			graph_add_edge(old, cnew);
		}
	}

	if (!tok->refcnt)
		cmd_free_node(oldgraph, old);
}

void cmd_graph_merge(struct graph *old, struct graph *new, int direction)
{
	assert(vector_active(old->nodes) >= 1);
	assert(vector_active(new->nodes) >= 1);

	cmd_merge_nodes(old, new, vector_slot(old->nodes, 0),
			vector_slot(new->nodes, 0), direction);
}

static void cmd_node_names(struct graph_node *gn, struct graph_node *join,
			   const char *prevname)
{
	size_t i;
	struct cmd_token *tok = gn->data, *jointok;
	struct graph_node *stop = cmd_loopstop(gn);

	switch (tok->type) {
	case WORD_TKN:
		prevname = tok->text;
		break;

	case VARIABLE_TKN:
		if (!tok->varname && strcmp(tok->text, "WORD")
		    && strcmp(tok->text, "NAME"))
			cmd_token_varname_set(tok, tok->text);
	/* fallthrough */
	case RANGE_TKN:
	case IPV4_TKN:
	case IPV4_PREFIX_TKN:
	case IPV6_TKN:
	case IPV6_PREFIX_TKN:
	case MAC_TKN:
	case MAC_PREFIX_TKN:
		if (!tok->varname && prevname)
			cmd_token_varname_set(tok, prevname);
		prevname = NULL;
		break;

	case START_TKN:
	case JOIN_TKN:
		/* "<foo|bar> WORD" -> word is not "bar" or "foo" */
		prevname = NULL;
		break;

	case FORK_TKN:
		/* apply "<A.B.C.D|X:X::X:X>$name" */
		jointok = tok->forkjoin->data;
		if (!jointok->varname)
			break;
		for (i = 0; i < vector_active(tok->forkjoin->from); i++) {
			struct graph_node *tail =
				vector_slot(tok->forkjoin->from, i);
			struct cmd_token *tailtok = tail->data;
			if (tail == gn || tailtok->varname)
				continue;
			cmd_token_varname_set(tailtok, jointok->varname);
		}
		break;

	case END_TKN:
		return;
	}

	for (i = 0; i < vector_active(gn->to); i++) {
		struct graph_node *next = vector_slot(gn->to, i);
		if (next == stop || next == join)
			continue;
		cmd_node_names(next, join, prevname);
	}

	if (tok->type == FORK_TKN && tok->forkjoin != join)
		cmd_node_names(tok->forkjoin, join, NULL);
}

void cmd_graph_names(struct graph *graph)
{
	struct graph_node *start;

	assert(vector_active(graph->nodes) >= 1);
	start = vector_slot(graph->nodes, 0);

	/* apply varname on initial "[no]" */
	do {
		if (vector_active(start->to) != 1)
			break;

		struct graph_node *first = vector_slot(start->to, 0);
		struct cmd_token *tok = first->data;
		/* looking for an option with 2 choices, nothing or "no" */
		if (tok->type != FORK_TKN || vector_active(first->to) != 2)
			break;

		struct graph_node *next0 = vector_slot(first->to, 0);
		struct graph_node *next1 = vector_slot(first->to, 1);
		/* one needs to be empty */
		if (next0 != tok->forkjoin && next1 != tok->forkjoin)
			break;

		struct cmd_token *tok0 = next0->data;
		struct cmd_token *tok1 = next1->data;
		/* the other one needs to be "no" (only one will match here) */
		if ((tok0->type == WORD_TKN && !strcmp(tok0->text, "no")))
			cmd_token_varname_set(tok0, "no");
		if ((tok1->type == WORD_TKN && !strcmp(tok1->text, "no")))
			cmd_token_varname_set(tok1, "no");
	} while (0);

	cmd_node_names(start, NULL, NULL);
}

#ifndef BUILDING_CLIPPY

#include "command.h"
#include "log.h"

void cmd_graph_node_print_cb(struct graph_node *gn, struct buffer *buf)
{
	static bool wasend;

	char nbuf[512];
	struct cmd_token *tok = gn->data;
	const char *color;

	if (wasend == true) {
		wasend = false;
		return;
	}

	if (tok->type == END_TKN) {
		wasend = true;
		return;
	}

	snprintf(nbuf, sizeof(nbuf), "  n%p [ shape=box, label=<", gn);
	buffer_putstr(buf, nbuf);
	snprintf(nbuf, sizeof(nbuf), "<b>%s</b>",
		 lookup_msg(tokennames, tok->type, NULL));
	buffer_putstr(buf, nbuf);
	if (tok->attr == CMD_ATTR_DEPRECATED)
		buffer_putstr(buf, " (d)");
	else if (tok->attr == CMD_ATTR_HIDDEN)
		buffer_putstr(buf, " (h)");
	if (tok->text) {
		if (tok->type == WORD_TKN)
			snprintf(
				nbuf, sizeof(nbuf),
				"<br/>\"<font color=\"#0055ff\" point-size=\"11\"><b>%s</b></font>\"",
				tok->text);
		else
			snprintf(nbuf, sizeof(nbuf), "<br/>%s", tok->text);
		buffer_putstr(buf, nbuf);
	}

	switch (tok->type) {
	case START_TKN:
		color = "#ccffcc";
		break;
	case FORK_TKN:
		color = "#aaddff";
		break;
	case JOIN_TKN:
		color = "#ddaaff";
		break;
	case WORD_TKN:
		color = "#ffffff";
		break;
	default:
		color = "#ffffff";
		break;
	}
	snprintf(nbuf, sizeof(nbuf),
		 ">, style = filled, fillcolor = \"%s\" ];\n", color);
	buffer_putstr(buf, nbuf);

	for (unsigned int i = 0; i < vector_active(gn->to); i++) {
		struct graph_node *adj = vector_slot(gn->to, i);

		if (((struct cmd_token *)adj->data)->type == END_TKN) {
			snprintf(nbuf, sizeof(nbuf), "  n%p -> end%p;\n", gn,
				 adj);
			buffer_putstr(buf, nbuf);
			snprintf(
				nbuf, sizeof(nbuf),
				"  end%p [ shape=box, label=<end>, style = filled, fillcolor = \"#ffddaa\" ];\n",
				adj);
		} else
			snprintf(nbuf, sizeof(nbuf), "  n%p -> n%p;\n", gn,
				 adj);

		buffer_putstr(buf, nbuf);
	}
}

char *cmd_graph_dump_dot(struct graph *cmdgraph)
{
	struct graph_node *start = vector_slot(cmdgraph->nodes, 0);

	return graph_dump_dot(cmdgraph, start, cmd_graph_node_print_cb);
}

#endif /* BUILDING_CLIPPY */
