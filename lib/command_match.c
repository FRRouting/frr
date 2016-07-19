#include <zebra.h>
#include "memory.h"
#include "command_match.h"

enum match_type
match_command (struct graph_node *start, enum filter_type filter, const char *input)
{
  // match input on DFA
  return exact_match;
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
