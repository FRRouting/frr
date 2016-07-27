#ifndef COMMAND_MATCH_H
#define COMMAND_MATCH_H

#include "command.h"
#include "command_graph.h"
#include "linklist.h"


/** These definitions exist in command.c in
 * the current engine but will be relocated
 * here in the new engine*/
enum filter_type
{
  FILTER_RELAXED,
  FILTER_STRICT
};

/* matcher result value. */
enum matcher_rv
{
  MATCHER_OK,
  MATCHER_COMPLETE,
  MATCHER_INCOMPLETE,
  MATCHER_NO_MATCH,
  MATCHER_AMBIGUOUS,
  MATCHER_EXCEED_ARGC_MAX
};

/* Completion match types. */
enum match_type
{
  no_match,
  partly_match,
  exact_match
};

/* Defines which matcher_rv values constitute
 * an error. Should be used against matcher_rv
 * return values to do basic error checking.
 */
#define MATCHER_ERROR(matcher_rv) \
  (   (matcher_rv) == MATCHER_INCOMPLETE \
   || (matcher_rv) == MATCHER_NO_MATCH \
   || (matcher_rv) == MATCHER_AMBIGUOUS \
   || (matcher_rv) == MATCHER_EXCEED_ARGC_MAX \
  )

/**
 * Attempt to find an exact command match for a line of user input.
 *
 * @return cmd_element found, or NULL if there is no match.
 */
struct cmd_element *
match_command (struct graph_node *, const char *, enum filter_type);

/**
 * Compiles next-hops for a given line of user input.
 *
 * Given a string of input and a start node for a matching DFA, runs the input
 * against the DFA until the input is exhausted or a mismatch is encountered.
 *
 * This function returns all valid next hops away from the current node.
 *  - If the input is a valid prefix to a longer command(s), the set of next
 *    hops determines what tokens are valid to follow the prefix. In other words,
 *    the returned list is a list of possible completions.
 *  - If the input matched a full command, exactly one of the next hops will be
 *    a node of type END_GN and its function pointer will be set.
 *  - If the input did not match any valid token sequence, the returned list
 *    will be empty (there are no transitions away from a nonexistent state).
 *
 * @param[in] start the start node of the DFA to match against
 * @param[in] filter the filtering method
 * @param[in] input the input string
 * @return pointer to linked list with all possible next hops from the last
 *         matched token. If this is empty, the input did not match any command.
 */
struct list *
match_command_complete (struct graph_node *, const char *, enum filter_type);

/**
 * Builds an argument list given a cmd_element and a matching input line.
 *
 * @param[in] input line
 * @param[in] cmd_element struct
 * @return pointer to argument linked list
 */
struct list *
match_build_argv (const char *, struct cmd_element *);

#endif
