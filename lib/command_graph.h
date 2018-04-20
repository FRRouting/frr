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

#ifndef _FRR_COMMAND_GRAPH_H
#define _FRR_COMMAND_GRAPH_H

#include <stdbool.h>
#include <stdint.h>

#include "memory.h"
#include "vector.h"
#include "graph.h"

DECLARE_MTYPE(CMD_ARG)

struct vty;

/**
 * Types for tokens.
 *
 * The type determines what kind of data the token can match (in the
 * matching use case) or hold (in the argv use case).
 */
/* clang-format off */
enum cmd_token_type {
	WORD_TKN,        // words
	VARIABLE_TKN,    // almost anything
	RANGE_TKN,       // integer range
	IPV4_TKN,        // IPV4 addresses
	IPV4_PREFIX_TKN, // IPV4 network prefixes
	IPV6_TKN,        // IPV6 prefixes
	IPV6_PREFIX_TKN, // IPV6 network prefixes
	MAC_TKN,         // Ethernet address
	MAC_PREFIX_TKN,  // Ethernet address w/ CIDR mask

	/* plumbing types */
	FORK_TKN,  // marks subgraph beginning
	JOIN_TKN,  // marks subgraph end
	START_TKN, // first token in line
	END_TKN,   // last token in line

	SPECIAL_TKN = FORK_TKN,
};
/* clang-format on */

#define IS_VARYING_TOKEN(x) ((x) >= VARIABLE_TKN && (x) < FORK_TKN)

/* Command attributes */
enum { CMD_ATTR_NORMAL,
       CMD_ATTR_DEPRECATED,
       CMD_ATTR_HIDDEN,
};

/* Comamand token struct. */
struct cmd_token {
	enum cmd_token_type type; // token type
	uint8_t attr;		  // token attributes
	bool allowrepeat;	 // matcher allowed to match token repetively?
	uint32_t refcnt;

	char *text;	 // token text
	char *desc;	 // token description
	long long min, max; // for ranges
	char *arg;	  // user input that matches this token
	char *varname;

	struct graph_node *forkjoin; // paired FORK/JOIN for JOIN/FORK
};

/* Structure of command element. */
struct cmd_element {
	const char *string; /* Command specification by string. */
	const char *doc;    /* Documentation of this command. */
	int daemon;	 /* Daemon to which this command belong. */
	uint8_t attr;       /* Command attributes */

	/* handler function for command */
	int (*func)(const struct cmd_element *, struct vty *, int,
		    struct cmd_token *[]);

	const char *name; /* symbol name for debugging */
};

/* text for <cr> command */
#define CMD_CR_TEXT "<cr>"

/* memory management for cmd_token */
extern struct cmd_token *cmd_token_new(enum cmd_token_type, uint8_t attr,
				       const char *text, const char *desc);
extern struct cmd_token *cmd_token_dup(struct cmd_token *);
extern void cmd_token_del(struct cmd_token *);
extern void cmd_token_varname_set(struct cmd_token *token, const char *varname);

extern void cmd_graph_parse(struct graph *graph, struct cmd_element *cmd);
extern void cmd_graph_names(struct graph *graph);
extern void cmd_graph_merge(struct graph *old, struct graph *new,
			    int direction);
/*
 * Print callback for DOT dumping.
 *
 * See graph.h for more details.
 */
extern void cmd_graph_node_print_cb(struct graph_node *gn, struct buffer *buf);
/*
 * Dump command graph to DOT.
 *
 * cmdgraph
 *    A command graph to dump
 *
 * Returns:
 *    String allocated with MTYPE_TMP representing this graph
 */
char *cmd_graph_dump_dot(struct graph *cmdgraph);

#endif /* _FRR_COMMAND_GRAPH_H */
