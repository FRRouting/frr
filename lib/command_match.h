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
 * You should have received a copy of the GNU General Public License
 * along with GNU Zebra; see the file COPYING.  If not, write to the Free
 * Software Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA
 * 02111-1307, USA.
 */

#ifndef _ZEBRA_COMMAND_MATCH_H
#define _ZEBRA_COMMAND_MATCH_H

#include "graph.h"
#include "linklist.h"
#include "command.h"

/* These definitions exist in command.c in the current engine but should be
 * relocated here in the new engine
 */
enum filter_type
{
  FILTER_RELAXED,
  FILTER_STRICT
};

/* matcher result value */
enum matcher_rv
{
  MATCHER_NO_MATCH,
  MATCHER_INCOMPLETE,
  MATCHER_AMBIGUOUS,
  MATCHER_OK,
};

/* completion match types */
enum match_type
{
  no_match,
  partly_match,
  exact_match
};

/* Defines which matcher_rv values constitute an error. Should be used with
 * matcher_rv return values to do basic error checking.
 */
#define MATCHER_ERROR(matcher_rv) \
  (   (matcher_rv) == MATCHER_INCOMPLETE \
   || (matcher_rv) == MATCHER_NO_MATCH \
   || (matcher_rv) == MATCHER_AMBIGUOUS \
  )

/**
 * Attempt to find an exact command match for a line of user input.
 *
 * @param[in] cmdgraph command graph to match against
 * @param[in] vline vectorized input string
 * @param[out] argv pointer to argument list if successful match
 * @param[out] element pointer to matched cmd_element if successful match
 * @return matcher status
 */
enum matcher_rv
command_match (struct graph *cmdgraph,
               vector vline,
               struct list **argv,
               struct cmd_element **element);

/**
 * Compiles possible completions for a given line of user input.
 *
 * @param[in] start the start node of the DFA to match against
 * @param[in] vline vectorized input string
 * @param[in] completions pointer to list of cmd_token representing
 *            acceptable next inputs
 */
enum matcher_rv
command_complete (struct graph *cmdgraph,
                  vector vline,
                  struct list **completions);


/**
 * Compiles possible completions for a given line of user input.
 *
 * @param[in] start the start node of the DFA to match against
 * @param[in] vline vectorized input string
 * @param[in] completions vector to fill with string completions
 * @return matcher status
enum matcher_rv
command_complete_str (struct graph *cmdgraph,
                      vector vline,
                      vector completions);

 */
#endif /* _ZEBRA_COMMAND_MATCH_H */
