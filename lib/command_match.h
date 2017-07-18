/*
 * Input matching routines for CLI backend.
 *
 * --
 * Copyright (C) 2016 Cumulus Networks, Inc.
 *
 * This file is part of GNU Zebra.
 *
 * GNU Zebra is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2, or (at your option) any
 * later version.
 *
 * GNU Zebra is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; see the file COPYING; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA
 */

#ifndef _ZEBRA_COMMAND_MATCH_H
#define _ZEBRA_COMMAND_MATCH_H

#include "graph.h"
#include "linklist.h"
#include "command.h"

/* These definitions exist in command.c in the current engine but should be
 * relocated here in the new engine
 */
enum filter_type { FILTER_RELAXED, FILTER_STRICT };

/* matcher result value */
enum matcher_rv {
	MATCHER_NO_MATCH,
	MATCHER_INCOMPLETE,
	MATCHER_AMBIGUOUS,
	MATCHER_OK,
};

/* completion match types */
enum match_type {
	trivial_match, // the input is null
	no_match,      // the input does not match
	partly_match,  // the input matches but is incomplete
	exact_match    // the input matches and is complete
};

/* Defines which matcher_rv values constitute an error. Should be used with
 * matcher_rv return values to do basic error checking.
 */
#define MATCHER_ERROR(matcher_rv)                                              \
	((matcher_rv) == MATCHER_INCOMPLETE                                    \
	 || (matcher_rv) == MATCHER_NO_MATCH                                   \
	 || (matcher_rv) == MATCHER_AMBIGUOUS)

/**
 * Attempt to find an exact command match for a line of user input.
 *
 * @param[in] cmdgraph command graph to match against
 * @param[in] vline vectorized input string
 * @param[out] argv pointer to argument list if successful match, NULL
 * otherwise. The elements of this list are pointers to struct cmd_token
 * and represent the sequence of tokens matched by the inpu. The ->arg
 * field of each token points to a copy of the input matched on it. These
 * may be safely deleted or modified.
 * @param[out] element pointer to matched cmd_element if successful match,
 * or NULL when MATCHER_ERROR(rv) is true. The cmd_element may *not* be
 * safely deleted or modified; it is the instance initialized on startup.
 * @return matcher status
 */
enum matcher_rv command_match(struct graph *cmdgraph, vector vline,
			      struct list **argv,
			      const struct cmd_element **element);

/**
 * Compiles possible completions for a given line of user input.
 *
 * @param[in] start the start node of the DFA to match against
 * @param[in] vline vectorized input string
 * @param[out] completions pointer to list of cmd_token representing
 * acceptable next inputs, or NULL when MATCHER_ERROR(rv) is true.
 * The elements of this list are pointers to struct cmd_token and take on a
 * variety of forms depending on the passed vline. If the last element in vline
 * is NULL, all previous elements are considered to be complete words (the case
 * when a space is the last token of the line) and completions are generated
 * based on what could follow that input. If the last element in vline is not
 * NULL and each sequential element matches the corresponding tokens of one or
 * more commands exactly (e.g. 'encapv4' and not 'en') the same result is
 * generated. If the last element is not NULL and the best possible match is a
 * partial match, then the result generated will be all possible continuations
 * of that element (e.g. 'encapv4', 'encapv6', etc for input 'en').
 * @return matcher status
 */
enum matcher_rv command_complete(struct graph *cmdgraph, vector vline,
				 struct list **completions);

#endif /* _ZEBRA_COMMAND_MATCH_H */
