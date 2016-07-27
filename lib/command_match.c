#include "command_match.h"
#include "command_parse.h"
#include <zebra.h>
#include "memory.h"

/* matcher helper prototypes */
static int
add_nexthops(struct list *, struct graph_node *);

static struct list *
match_build_argv_r (struct graph_node *start, vector vline, unsigned int n);

/* token matcher prototypes */
static enum match_type
match_ipv4 (const char *);

static enum match_type
match_ipv4_prefix (const char *);

static enum match_type
match_ipv6 (const char *);

static enum match_type
match_ipv6_prefix (const char *);

static enum match_type
match_range (struct graph_node *, const char *str);

static enum match_type
match_word (struct graph_node *, enum filter_type, const char *);

static enum match_type
match_number (struct graph_node *, const char *);

static enum match_type
match_variable (struct graph_node *, const char *);

static enum match_type
match_token (struct graph_node *, char *, enum filter_type);

/* matching functions */

struct cmd_element *
match_command (struct graph_node *start, const char *line, enum filter_type filter)
{
  // get all possible completions
  struct list *completions = match_command_complete (start, line, filter);

  // one of them should be END_GN if this command matches
  struct graph_node *gn;
  struct listnode *node;
  for (ALL_LIST_ELEMENTS_RO(completions,node,gn))
  {
    if (gn->type == END_GN)
      break;
    gn = NULL;
  }
  return gn ? gn->element : NULL;
}

struct list *
match_command_complete (struct graph_node *start, const char *line, enum filter_type filter)
{
  // vectorize command line
  vector vline = cmd_make_strvec (line);

  // pointer to next input token to match
  char *token;

  struct list *current  = list_new(), // current nodes to match input token against
              *matched  = list_new(), // current nodes that match the input token
              *next     = list_new(); // possible next hops to current input token

  // pointers used for iterating lists
  struct graph_node *gn;
  struct listnode *node;

  // add all children of start node to list
  add_nexthops(next, start);

  unsigned int idx;
  for (idx = 0; idx < vector_active(vline) && next->count > 0; idx++)
  {
    list_free (current);
    current = next;
    next = list_new();

    token = vector_slot(vline, idx);

    list_delete_all_node(matched);

    for (ALL_LIST_ELEMENTS_RO(current,node,gn))
    {
      if (match_token(gn, token, filter) == exact_match) {
        listnode_add(matched, gn);
        add_nexthops(next, gn);
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
  list_free (current);
  list_free (matched);

  cmd_free_strvec(vline);

  return next;
}

/**
 * Adds all children that are reachable by one parser hop
 * to the given list. NUL_GN, SELECTOR_GN, and OPTION_GN
 * nodes are treated as transparent.
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
    switch (child->type) {
      case OPTION_GN:
      case SELECTOR_GN:
      case NUL_GN:
        added += add_nexthops(l, child);
        break;
      default:
        listnode_add(l, child);
        added++;
    }
  }
  return added;
}

struct list *
match_build_argv (const char *line, struct cmd_element *element)
{
  struct list *argv = NULL;

  // parse command
  struct graph_node *start = new_node(NUL_GN);
  parse_command_format(start, element);

  vector vline = cmd_make_strvec (line);

  for (unsigned int i = 0; i < vector_active(start->children); i++)
  {
    // call recursive builder on each starting child
    argv = match_build_argv_r (vector_slot(start->children, i), vline, 0);
    // if any of them succeed, return their argv (there should only be one)
    if (argv) break;
  }

  return argv;
}

static struct list *
match_build_argv_r (struct graph_node *start, vector vline, unsigned int n)
{
  // if we don't match this node, die
  if (match_token(start, vector_slot(vline, n), FILTER_STRICT) == no_match)
    return NULL;

  // some stuffs we need
  struct list *argv = list_new();
  struct graph_node *gn;
  struct listnode   *ln;

  // append current arg
  start->arg = strdup(vector_slot(vline, n));
  listnode_add(argv, start);

  // get all possible nexthops
  struct list *next = list_new();
  add_nexthops(next, start);

  // check if one of them is END_GN
  for (ALL_LIST_ELEMENTS_RO(next,ln,gn))
  {
    if (gn->type == END_GN){
      fprintf(stderr, "Hit END_GN while searching next set of node with text %s\n", start->text);
      return argv;
    }
  }

  // if we have no more input, why even live?
  if (n+1 >= vector_active(vline)) return NULL;

  // otherwise recurse on all nexthops
  for (ALL_LIST_ELEMENTS_RO(next,ln,gn))
  {
    for (unsigned int i = 0; i < n; i++) fprintf(stderr, "\t");
    fprintf(stderr, "Recursing on node %s for token %s\n", gn->text, (char*) vector_slot(vline, n+1));
    struct list *result = match_build_argv_r (gn, vline, n+1);
    if (result != NULL) {
      list_add_list (argv, result);
      return argv;
    }
  }
  return NULL;
}

/* matching utility functions */

static enum match_type
match_token (struct graph_node *node, char *token, enum filter_type filter)
{
  switch (node->type) {
    case WORD_GN:
      return match_word (node, filter, token);
    case IPV4_GN:
      return match_ipv4 (token);
    case IPV4_PREFIX_GN:
      return match_ipv4_prefix (token);
    case IPV6_GN:
      return match_ipv6 (token);
    case IPV6_PREFIX_GN:
      return match_ipv6_prefix (token);
    case RANGE_GN:
      return match_range (node, token);
    case NUMBER_GN:
      return match_number (node, token);
    case VARIABLE_GN:
      return match_variable (node, token);
    case END_GN:
    default:
      return no_match;
  }
}

#define IPV4_ADDR_STR   "0123456789."
#define IPV4_PREFIX_STR "0123456789./"

static enum match_type
match_ipv4 (const char *str)
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

static enum match_type
match_ipv4_prefix (const char *str)
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

#ifdef HAVE_IPV6
#define IPV6_ADDR_STR   "0123456789abcdefABCDEF:."
#define IPV6_PREFIX_STR "0123456789abcdefABCDEF:./"

static enum match_type
match_ipv6 (const char *str)
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

static enum match_type
match_ipv6_prefix (const char *str)
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

static enum match_type
match_range (struct graph_node *rangenode, const char *str)
{
  char *endptr = NULL;
  signed long val;

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

static enum match_type
match_word(struct graph_node *wordnode,
           enum filter_type filter,
           const char *word)
{
  if (filter == FILTER_RELAXED)
  {
    if (!word || !strlen(word))
      return partly_match;
    else if (!strncmp(wordnode->text, word, strlen(word)))
      return !strcmp(wordnode->text, word) ? exact_match : partly_match;
    else
      return no_match;
  }
  else
  {
     if (!word)
       return no_match;
     else
       return !strcmp(wordnode->text, word) ? exact_match : no_match;
  }
}

static enum match_type
match_number(struct graph_node *numnode, const char *word)
{
  if (!strcmp("\0", word)) return no_match;
  char *endptr;
  long num = strtol(word, &endptr, 10);
  if (endptr != '\0') return no_match;
  return num == numnode->value ? exact_match : no_match;
}

#define VARIABLE_ALPHABET "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz1234567890"

static enum match_type
match_variable(struct graph_node *varnode, const char *word)
{
  return strlen(word) == strspn(word, VARIABLE_ALPHABET) && isalpha(word[0]) ?
     exact_match : no_match;
}
