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

#include <zebra.h>
#include "command_match.h"
#include "command_parse.h"
#include "memory.h"

/* matcher helper prototypes */
static int
add_nexthops (struct list *, struct graph_node *);

static struct list *
match_command_r (struct graph_node *, vector, unsigned int);

static int
score_precedence (enum graph_node_type);

static enum match_type
min_match_level (enum node_type);

static struct graph_node *
copy_node (struct graph_node *);

static void
delete_nodelist (void *);

static struct graph_node *
disambiguate_nodes (struct graph_node *, struct graph_node *, char *);

static struct list *
disambiguate (struct list *, struct list *, vector, unsigned int);

/* token matcher prototypes */
static enum match_type
match_token (struct graph_node *, char *);

static enum match_type
match_ipv4 (const char *);

static enum match_type
match_ipv4_prefix (const char *);

static enum match_type
match_ipv6 (const char *);

static enum match_type
match_ipv6_prefix (const char *);

static enum match_type
match_range (struct graph_node *, const char *);

static enum match_type
match_word (struct graph_node *, const char *);

static enum match_type
match_number (struct graph_node *, const char *);

static enum match_type
match_variable (struct graph_node *node, const char *word);

/* matching functions */
static enum matcher_rv matcher_rv;

enum matcher_rv
match_command (struct graph_node *start,
               vector vline,
               struct list **argv,
               struct cmd_element **el)
{
  matcher_rv = MATCHER_NO_MATCH;

  // call recursive matcher on each starting child
  for (unsigned int i = 0; i < vector_active (start->children); i++)
    {
      *argv = match_command_r (vector_slot (start->children, i), vline, 0);
      if (*argv) // successful match
        {
          struct graph_node *end = listgetdata (listtail (*argv));
          *el = end->element;
          assert (*el);
          break;
        }
    }

  return matcher_rv;
}

/**
 * Builds an argument list given a DFA and a matching input line.
 *
 * First the function determines if the node it is passed matches the first
 * token of input. If it does not, it returns NULL (MATCHER_NO_MATCH). If it
 * does match, then it saves the input token as the head of an argument list.
 *
 * The next step is to see if there is further input in the input line. If
 * there is not, the current node's children are searched to see if any of them
 * are leaves (type END_GN). If this is the case, then the bottom of the
 * recursion stack has been reached, the leaf is pushed onto the argument list,
 * the current node is pushed, and the resulting argument list is
 * returned (MATCHER_OK). If it is not the case, NULL is returned, indicating
 * that there is no match for the input along this path (MATCHER_INCOMPLETE).
 *
 * If there is further input, then the function recurses on each of the current
 * node's children, passing them the input line minus the token that was just
 * matched. For each child, the return value of the recursive call is
 * inspected. If it is null, then there is no match for the input along the
 * subgraph headed by that child. If it is not null, then there is at least one
 * input match in that subgraph (more on this in a moment).
 *
 * If a recursive call on a child returns a non-null value, then it has matched
 * the input given it on the subgraph that starts with that child. However, due
 * to the flexibility of the grammar, it is sometimes the case that two or more
 * child graphs match the same input (two or more of the recursive calls have
 * non-NULL return values). This is not a valid state, since only one true
 * match is possible. In order to resolve this conflict, the function keeps a
 * reference to the child node that most specifically matches the input. This
 * is done by assigning each node type a precedence. If a child is found to
 * match the remaining input, then the precedence values of the current
 * best-matching child and this new match are compared. The node with higher
 * precedence is kept, and the other match is discarded. Due to the recursive
 * nature of this function, it is only necessary to compare the precedence of
 * immediate children, since all subsequent children will already have been
 * disambiguated in this way.
 *
 * In the event that two children are found to match with the same precedence,
 * then the input is ambiguous for the passed cmd_element and NULL is returned.
 *
 * The ultimate return value is an ordered linked list of nodes that comprise
 * the best match for the command, each with their `arg` fields pointing to the
 * matching token string.
 *
 * @param[in] start the start node.
 * @param[in] vline the vectorized input line.
 * @param[in] n the index of the first input token.
 */
static struct list *
match_command_r (struct graph_node *start, vector vline, unsigned int n)
{
  // get the minimum match level that can count as a full match
  enum match_type minmatch = min_match_level (start->type);

  // get the current operating token
  char *token = vector_slot (vline, n);

  // if we don't match this node, die
  if (match_token (start, token) < minmatch)
    return NULL;

  // pointers for iterating linklist
  struct listnode *ln;
  struct graph_node *gn;

  // get all possible nexthops
  struct list *next = list_new();
  add_nexthops (next, start);

  // determine the best match
  int ambiguous = 0;
  struct list *currbest = NULL;
  for (ALL_LIST_ELEMENTS_RO (next,ln,gn))
    {
      // if we've matched all input we're looking for END_GN
      if (n+1 == vector_active (vline))
        {
          if (gn->type == END_GN)
            {
              currbest = list_new();
              listnode_add (currbest, copy_node(gn));
              currbest->del = &delete_nodelist;
              break;
            }
          else continue;
        }

      // else recurse on candidate child node
      struct list *result = match_command_r (gn, vline, n+1);

      // save the best match
      if (result && currbest)
        {
          struct list *newbest = disambiguate (currbest, result, vline, n+1);
          ambiguous = !newbest || (ambiguous && newbest == currbest);
          list_delete ((newbest && newbest == result) ? currbest : result);
          currbest = newbest ? newbest : currbest;
        }
      else if (result)
        currbest = result;
    }

  if (currbest)
    {
      if (ambiguous)
        {
          list_delete (currbest);
          currbest = NULL;
          matcher_rv = MATCHER_AMBIGUOUS;
        }
      else
        {
          // copy current node, set arg and prepend to currbest
          struct graph_node *curr = copy_node (start);
          curr->arg = XSTRDUP(MTYPE_CMD_TOKENS, token);
          list_add_node_prev (currbest, currbest->head, curr);
          matcher_rv = MATCHER_OK;
        }
    }
  else if (n+1 == vector_active (vline) && matcher_rv == MATCHER_NO_MATCH)
    matcher_rv = MATCHER_INCOMPLETE;

  // cleanup
  list_delete (next);

  return currbest;
}

enum matcher_rv
match_command_complete (struct graph_node *start, vector vline, struct list **completions)
{
  // pointer to next input token to match
  char *token;

  struct list *current = list_new(), // current nodes to match input token against
                 *next = list_new(); // possible next hops after current input token

  // pointers used for iterating lists
  struct graph_node *gn;
  struct listnode *node;

  // add all children of start node to list
  add_nexthops (next, start);

  unsigned int idx;
  for (idx = 0; idx < vector_active (vline) && next->count > 0; idx++)
    {
      list_free (current);
      current = next;
      next = list_new();

      token = vector_slot (vline, idx);

      for (ALL_LIST_ELEMENTS_RO (current,node,gn))
        {
          switch (match_token (gn, token))
            {
              case partly_match:
                if (idx == vector_active (vline) - 1)
                  {
                    listnode_add (next, gn);
                    break;
                  }
              case exact_match:
                add_nexthops (next, gn);
                break;
              default:
                break;
            }
        }
    }

  /* Variable summary
   * -----------------------------------------------------------------
   * token    = last input token processed
   * idx      = index in `command` of last token processed
   * current  = set of all transitions from the previous input token
   * next     = set of all nodes reachable from all nodes in `matched`
   */

  matcher_rv =
     idx + 1 == vector_active(vline) && next->count ?
     MATCHER_OK :
     MATCHER_NO_MATCH;

  list_free (current);
  *completions = next;

  return matcher_rv;
}

/**
 * Adds all children that are reachable by one parser hop to the given list.
 * NUL_GN, SELECTOR_GN, and OPTION_GN nodes are treated as transparent.
 *
 * @param[in] list to add the nexthops to
 * @param[in] node to start calculating nexthops from
 * @return the number of children added to the list
 */
static int
add_nexthops (struct list *list, struct graph_node *node)
{
  int added = 0;
  struct graph_node *child;
  for (unsigned int i = 0; i < vector_active (node->children); i++)
    {
      child = vector_slot (node->children, i);
      switch (child->type)
        {
          case OPTION_GN:
          case SELECTOR_GN:
          case NUL_GN:
            added += add_nexthops (list, child);
            break;
          default:
            listnode_add (list, child);
            added++;
        }
    }

  return added;
}

/**
 * Determines the node types for which a partial match may count as a full
 * match. Enables command abbrevations.
 *
 * @param[in] type node type
 * @return minimum match level needed to for a token to fully match
 */
static enum match_type
min_match_level (enum node_type type)
{
  switch (type)
    {
      // allowing words to partly match enables command abbreviation
      case WORD_GN:
        return partly_match;
      default:
        return exact_match;
    }
}

/**
 * Assigns precedence scores to node types.
 *
 * @param[in] type node type to score
 * @return precedence score
 */
static int
score_precedence (enum graph_node_type type)
{
  switch (type)
    {
      // some of these are mutually exclusive, so they share
      // the same precedence value
      case IPV4_GN:
      case IPV4_PREFIX_GN:
      case IPV6_GN:
      case IPV6_PREFIX_GN:
      case NUMBER_GN:
        return 1;
      case RANGE_GN:
        return 2;
      case WORD_GN:
        return 3;
      case VARIABLE_GN:
        return 4;
      default:
        return 10;
    }
}

/**
 * Picks the better of two possible matches for a token.
 *
 * @param[in] first candidate node matching token
 * @param[in] second candidate node matching token
 * @param[in] token the token being matched
 * @return the best-matching node, or NULL if the two are entirely ambiguous
 */
static struct graph_node *
disambiguate_nodes (struct graph_node *first,
                    struct graph_node *second,
                    char *token)
{
  // if the types are different, simply go off of type precedence
  if (first->type != second->type)
    {
      int firstprec = score_precedence (first->type);
      int secndprec = score_precedence (second->type);
      if (firstprec != secndprec)
        return firstprec < secndprec ? first : second;
      else
        return NULL;
    }

  // if they're the same, return the more exact match
  enum match_type fmtype = match_token (first, token);
  enum match_type smtype = match_token (second, token);
  if (fmtype != smtype)
    return fmtype > smtype ? first : second;

  return NULL;
}

/**
 * Picks the better of two possible matches for an input line.
 *
 * @param[in] first candidate list of graph_node matching vline
 * @param[in] second candidate list of graph_node matching vline
 * @param[in] vline the input line being matched
 * @param[in] n index into vline to start comparing at
 * @return the best-matching list, or NULL if the two are entirely ambiguous
 */
static struct list *
disambiguate (struct list *first,
              struct list *second,
              vector vline,
              unsigned int n)
{
  // doesn't make sense for these to be inequal length
  assert (first->count == second->count);
  assert (first->count == vector_active (vline) - n+1);

  struct listnode *fnode = listhead (first),
                  *snode = listhead (second);
  struct graph_node *fgn = listgetdata (fnode),
                    *sgn = listgetdata (snode),
                    *best = NULL;

  // compare each node, if one matches better use that one
  for (unsigned int i = n; i < vector_active (vline); i++)
    {
      char *token = vector_slot(vline, i);
      if ((best = disambiguate_nodes (fgn, sgn, token)))
        return best == fgn ? first : second;
      fnode = listnextnode (fnode);
      snode = listnextnode (snode);
      fgn = (struct graph_node *) listgetdata (fnode);
      sgn = (struct graph_node *) listgetdata (snode);
    }

  return NULL;
}

/**
 * Performs a deep copy on a node.
 * Used to build argv node lists that can be safely deleted or modified by
 * endpoint functions. Everything is copied except the children vector,
 * subgraph end pointer and reference count.
 *
 * @param[in] node to copy
 * @return the copy
 */
static struct graph_node *
copy_node (struct graph_node *node)
{
  struct graph_node *new = new_node(node->type);
  new->children = NULL;
  new->end      = NULL;
  new->text     = node->text ? XSTRDUP(MTYPE_CMD_TOKENS, node->text) : NULL;
  new->value    = node->value;
  new->min      = node->min;
  new->max      = node->max;
  new->element  = node->element ? copy_cmd_element(node->element) : NULL;
  new->arg      = node->arg ? XSTRDUP(MTYPE_CMD_TOKENS, node->arg) : NULL;
  new->refs     = 0;
  return new;
}

/**
 * List deletion callback for argv lists.
 */
static void
delete_nodelist (void *node)
{
  delete_node ((struct graph_node *) node);
}


/* token level matching functions */

static enum match_type
match_token (struct graph_node *node, char *token)
{
  switch (node->type) {
    case WORD_GN:
      return match_word (node, token);
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
  const char *sp;
  int dots = 0, nums = 0;
  char buf[4];

  if (str == NULL)
    return partly_match;

  for (;;)
    {
      memset (buf, 0, sizeof (buf));
      sp = str;
      while (*str != '\0')
        {
          if (*str == '.')
            {
              if (dots >= 3)
                return no_match;

              if (*(str + 1) == '.')
                return no_match;

              if (*(str + 1) == '\0')
                return partly_match;

              dots++;
              break;
            }
          if (!isdigit ((int) *str))
            return no_match;

          str++;
        }

      if (str - sp > 3)
        return no_match;

      strncpy (buf, sp, str - sp);
      if (atoi (buf) > 255)
        return no_match;

      nums++;

      if (*str == '\0')
        break;

      str++;
    }

  if (nums < 4)
    return partly_match;

  return exact_match;
}

static enum match_type
match_ipv4_prefix (const char *str)
{
  const char *sp;
  int dots = 0;
  char buf[4];

  if (str == NULL)
    return partly_match;

  for (;;)
    {
      memset (buf, 0, sizeof (buf));
      sp = str;
      while (*str != '\0' && *str != '/')
        {
          if (*str == '.')
            {
              if (dots == 3)
                return no_match;

              if (*(str + 1) == '.' || *(str + 1) == '/')
                return no_match;

              if (*(str + 1) == '\0')
                return partly_match;

              dots++;
              break;
            }

          if (!isdigit ((int) *str))
            return no_match;

          str++;
        }

      if (str - sp > 3)
        return no_match;

      strncpy (buf, sp, str - sp);
      if (atoi (buf) > 255)
        return no_match;

      if (dots == 3)
        {
          if (*str == '/')
            {
              if (*(str + 1) == '\0')
                return partly_match;

              str++;
              break;
            }
          else if (*str == '\0')
            return partly_match;
        }

      if (*str == '\0')
        return partly_match;

      str++;
    }

  sp = str;
  while (*str != '\0')
    {
      if (!isdigit ((int) *str))
        return no_match;

      str++;
    }

  if (atoi (sp) > 32)
    return no_match;

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
  dupe = XCALLOC(MTYPE_TMP, strlen(str)+1);
  strncpy(dupe, str, strlen(str)+1);
  prefix = strtok_r(dupe, delim, &context);
  mask   = strtok_r(NULL, delim, &context);

  if (!mask)
    return partly_match;

  /* validate prefix */
  if (inet_pton(AF_INET6, prefix, &sin6_dummy.sin6_addr) != 1)
    return no_match;

  /* validate mask */
  nmask = strtoimax (mask, &endptr, 10);
  if (*endptr != '\0' || nmask < 0 || nmask > 128)
    return no_match;

  XFREE(MTYPE_TMP, dupe);

  return exact_match;
}
#endif

static enum match_type
match_range (struct graph_node *node, const char *str)
{
  assert (node->type == RANGE_GN);

  char *endptr = NULL;
  long long val;

  if (str == NULL)
    return 1;

  val = strtoll (str, &endptr, 10);
  if (*endptr != '\0')
    return 0;

  if (val < node->min || val > node->max)
    return no_match;
  else
    return exact_match;
}

static enum match_type
match_word (struct graph_node *node, const char *word)
{
  assert (node->type == WORD_GN);

  // if the passed token is null or 0 length, partly match
  if (!word || !strlen(word))
    return partly_match;

  // if the passed token is strictly a prefix of the full word, partly match
  if (strlen (word) < strlen (node->text))
    return !strncmp (node->text, word, strlen (word)) ?
       partly_match :
       no_match;

  // if they are the same length and exactly equal, exact match
  else if (strlen (word) == strlen (node->text))
    return !strncmp (node->text, word, strlen (word)) ? exact_match : no_match;

  return no_match;
}

static enum match_type
match_number (struct graph_node *node, const char *word)
{
  assert (node->type == NUMBER_GN);

  if (!strcmp ("\0", word)) return no_match;
  char *endptr;
  long long num = strtoll (word, &endptr, 10);
  if (endptr != '\0') return no_match;
  return num == node->value ? exact_match : no_match;
}

#define VARIABLE_ALPHABET \
"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz1234567890:"

static enum match_type
match_variable (struct graph_node *node, const char *word)
{
  assert (node->type == VARIABLE_GN);

  return strlen (word) == strspn(word, VARIABLE_ALPHABET) ?
     exact_match : no_match;
}
