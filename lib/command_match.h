#ifndef COMMAND_MATCH_H
#define COMMAND_MATCH_H

#include "command_graph.h"
#include "linklist.h"

/**
 * Filter types. These tell the parser whether to allow
 * partial matching on tokens.
 */
enum filter_type
{
  FILTER_RELAXED,
  FILTER_STRICT
};

/**
 * Command matcher result value.
 */
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
/**
 * Defines which matcher_rv values constitute
 * an error. Should be used against matcher_rv
 * return values to do basic error checking.
 */
#define MATCHER_ERROR(matcher_rv) \
  (   (matcher_rv) == MATCHER_INCOMPLETE \
   || (matcher_rv) == MATCHER_NO_MATCH \
   || (matcher_rv) == MATCHER_AMBIGUOUS \
   || (matcher_rv) == MATCHER_EXCEED_ARGC_MAX \
  )

struct list *
match_command (struct graph_node *, enum filter_type, const char *);

#endif
