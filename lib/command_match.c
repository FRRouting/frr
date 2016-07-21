#include <zebra.h>
#include "memory.h"
#include "vector.h"
#include "command_match.h"

static enum match_type
match_token (struct graph_node *node, char *token, enum filter_type filter)
{
  switch (node->type) {
    case WORD_GN:
      return cmd_word_match (node, filter, token);
    case IPV4_GN:
      return cmd_ipv4_match (token);
    case IPV4_PREFIX_GN:
      return cmd_ipv4_prefix_match (token);
    case IPV6_GN:
      return cmd_ipv6_match (token);
    case IPV6_PREFIX_GN:
      return cmd_ipv6_prefix_match (token);
    case RANGE_GN:
      return cmd_range_match (node, token);
    case NUMBER_GN:
      return node->value == atoi(token);
    case VARIABLE_GN:
    default:
      return no_match;
  }
}

/* Breaking up string into each command piece. I assume given
   character is separated by a space character. Return value is a
   vector which includes char ** data element. */
static vector
cmd_make_strvec (const char *string)
{
  const char *cp, *start;
  char *token;
  int strlen;
  vector strvec;

  if (string == NULL)
    return NULL;

  cp = string;

  /* Skip white spaces. */
  while (isspace ((int) *cp) && *cp != '\0')
    cp++;

  /* Return if there is only white spaces */
  if (*cp == '\0')
    return NULL;

  if (*cp == '!' || *cp == '#')
    return NULL;

  /* Prepare return vector. */
  strvec = vector_init (VECTOR_MIN_SIZE);

  /* Copy each command piece and set into vector. */
  while (1)
    {
      start = cp;
      while (!(isspace ((int) *cp) || *cp == '\r' || *cp == '\n') &&
            *cp != '\0')
         cp++;
      strlen = cp - start;
      token = XMALLOC (MTYPE_STRVEC, strlen + 1);
      memcpy (token, start, strlen);
      *(token + strlen) = '\0';
      vector_set (strvec, token);

      while ((isspace ((int) *cp) || *cp == '\n' || *cp == '\r') &&
            *cp != '\0')
         cp++;

      if (*cp == '\0')
        return strvec;
    }
}

/**
 * Adds all children that are reachable by one parser hop
 * to the given list. NUL_GN, SELECTOR_GN, and OPTION_GN
 * nodes are treated as though their children are attached
 * to their parent.
 *
 * @param[out] l the list to add the children to
 * @param[in] node the node to get the children of
 * @return the number of children added to the list
 */
static int
add_nexthops(struct list *l, struct graph_node *node)
{
  int added = 0;
  struct graph_node *child;
  for (unsigned int i = 0; i < vector_active(node->children); i++)
  {
    child = vector_slot(node->children, i);
    if (child->type == OPTION_GN || child->type == SELECTOR_GN || child->type == NUL_GN)
      added += add_nexthops(l, child);
    else {
      listnode_add(l, child);
      added++;
    }
  }
  return added;
}

/**
 * Compiles matches or next-hops for a given line of user input.
 *
 * Given a string of input and a start node for a matching DFA, runs the input
 * against the DFA until the input is exhausted, there are no possible
 * transitions, or both.
 * If there are no further state transitions available, one of two scenarios is possible:
 *  - The end of input has been reached. This indicates a valid command.
 *  - The end of input has not yet been reached. The input does not match any command.
 * If there are further transitions available, one of two scenarios is possible:
 *  - The current input is a valid prefix to a longer command
 *  - The current input matches a command
 *  - The current input matches a command, and is also a valid prefix to a longer command
 *
 * Any other states indicate a programming error.
 *
 * @param[in] start the start node of the DFA to match against
 * @param[in] filter the filtering method
 * @param[in] input the input string
 * @return an array with two lists. The first list is
 */
struct list**
match_command (struct graph_node *start, enum filter_type filter, const char *input)
{
  // break command
  vector command = cmd_make_strvec (input);

  // pointer to next input token to match
  char *token;

  struct list *current  = list_new(), // current nodes to match input token against
              *matched  = list_new(), // current nodes that match the input token
              *next     = list_new(); // possible next hops to current input token

  // pointers used for iterating lists
  struct graph_node *cnode;
  struct listnode *node;

  // add all children of start node to list
  add_nexthops(next, start);

  unsigned int idx;
  for (idx = 0; idx < vector_active(command) && next->count > 0; idx++)
  {
    list_free (current);
    current = next;
    next = list_new();

    token = vector_slot(command, idx);

    list_delete_all_node(matched);

    for (ALL_LIST_ELEMENTS_RO(current,node,cnode))
    {
      if (match_token(cnode, token, filter) == exact_match) {
        listnode_add(matched, cnode);
        add_nexthops(next, cnode);
      }
    }
  }

  /* Variable summary
   * -----------------------------------------------------------------
   * token    = last input token processed
   * idx      = index in `command` of last token processed
   * current  = set of all transitions from the previous input token
   * matched  = set of all nodes reachable with current input
   * next     = set of all nodes reachable from all nodes in `matched`
   */

  struct list **result = malloc( 2 * sizeof(struct list *) );
  result[0] = matched;
  result[1] = next;

  return result;
}


#define IPV4_ADDR_STR   "0123456789."
#define IPV4_PREFIX_STR "0123456789./"

enum match_type
cmd_ipv4_match (const char *str)
{
  struct sockaddr_in sin_dummy;

  if (str == NULL)
    return partly_match;

  if (strspn (str, IPV4_ADDR_STR) != strlen (str))
    return no_match;

  if (inet_pton(AF_INET, str, &sin_dummy.sin_addr) != 1)
    return no_match;

  return exact_match;
}

enum match_type
cmd_ipv4_prefix_match (const char *str)
{
  struct sockaddr_in sin_dummy;
  const char *delim = "/\0";
  char *dupe, *prefix, *mask, *context, *endptr;
  int nmask = -1;

  if (str == NULL)
    return partly_match;

  if (strspn (str, IPV4_PREFIX_STR) != strlen (str))
    return no_match;

  /* tokenize to address + mask */
  dupe = XMALLOC(MTYPE_TMP, strlen(str)+1);
  strncpy(dupe, str, strlen(str)+1);
  prefix = strtok_r(dupe, delim, &context);
  mask   = strtok_r(NULL, delim, &context);

  if (!mask)
    return partly_match;

  /* validate prefix */
  if (inet_pton(AF_INET, prefix, &sin_dummy.sin_addr) != 1)
    return no_match;

  /* validate mask */
  nmask = strtol (mask, &endptr, 10);
  if (*endptr != '\0' || nmask < 0 || nmask > 32)
    return no_match;

  XFREE(MTYPE_TMP, dupe);

  return exact_match;
}

#define IPV6_ADDR_STR   "0123456789abcdefABCDEF:."
#define IPV6_PREFIX_STR "0123456789abcdefABCDEF:./"

#ifdef HAVE_IPV6
enum match_type
cmd_ipv6_match (const char *str)
{
  struct sockaddr_in6 sin6_dummy;
  int ret;

  if (str == NULL)
    return partly_match;

  if (strspn (str, IPV6_ADDR_STR) != strlen (str))
    return no_match;

  ret = inet_pton(AF_INET6, str, &sin6_dummy.sin6_addr);

  if (ret == 1)
    return exact_match;

  return no_match;
}

enum match_type
cmd_ipv6_prefix_match (const char *str)
{
  struct sockaddr_in6 sin6_dummy;
  const char *delim = "/\0";
  char *dupe, *prefix, *mask, *context, *endptr;
  int nmask = -1;

  if (str == NULL)
    return partly_match;

  if (strspn (str, IPV6_PREFIX_STR) != strlen (str))
    return no_match;

  /* tokenize to address + mask */
  dupe = XMALLOC(MTYPE_TMP, strlen(str)+1);
  strncpy(dupe, str, strlen(str)+1);
  prefix = strtok_r(dupe, delim, &context);
  mask   = strtok_r(NULL, delim, &context);

  if (!mask)
    return partly_match;

  /* validate prefix */
  if (inet_pton(AF_INET6, prefix, &sin6_dummy.sin6_addr) != 1)
    return no_match;

  /* validate mask */
  nmask = strtol (mask, &endptr, 10);
  if (*endptr != '\0' || nmask < 0 || nmask > 128)
    return no_match;

  XFREE(MTYPE_TMP, dupe);

  return exact_match;
}
#endif

enum match_type
cmd_range_match (struct graph_node *rangenode, const char *str)
{
  char *endptr = NULL;
  signed long long val;

  if (str == NULL)
    return 1;

  val = strtoll (str, &endptr, 10);
  if (*endptr != '\0')
    return 0;
  val = llabs(val);

  if (val < rangenode->min || val > rangenode->max)
    return no_match;
  else
    return exact_match;
}

enum match_type
cmd_word_match(struct graph_node *wordnode,
               enum filter_type filter,
               const char *word)
{
  if (filter == FILTER_RELAXED)
    if (!word || !strlen(word))
      return partly_match;

  if (!word)
    return no_match;

  if (filter == FILTER_RELAXED && !strncmp(wordnode->text, word, strlen(word)))
  {
    if (!strcmp(wordnode->text, word))
      return exact_match;
    return partly_match;
  }
  if (filter == FILTER_STRICT && !strcmp(wordnode->text, word))
    return exact_match;

  return no_match;
}
