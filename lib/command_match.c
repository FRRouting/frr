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

#include <zebra.h>

#include "command_match.h"
#include "memory.h"

DEFINE_MTYPE_STATIC(LIB, CMD_MATCHSTACK, "Command Match Stack")

#ifdef TRACE_MATCHER
#define TM 1
#else
#define TM 0
#endif

#define trace_matcher(...)                                                     \
	do {                                                                   \
		if (TM)                                                        \
			fprintf(stderr, __VA_ARGS__);                          \
	} while (0);

/* matcher helper prototypes */
static int add_nexthops(struct list *, struct graph_node *,
			struct graph_node **, size_t);

static enum matcher_rv command_match_r(struct graph_node *, vector,
				       unsigned int, struct graph_node **,
				       struct list **);

static int score_precedence(enum cmd_token_type);

static enum match_type min_match_level(enum cmd_token_type);

static void del_arglist(struct list *);

static struct cmd_token *disambiguate_tokens(struct cmd_token *,
					     struct cmd_token *, char *);

static struct list *disambiguate(struct list *, struct list *, vector,
				 unsigned int);

int compare_completions(const void *, const void *);

/* token matcher prototypes */
static enum match_type match_token(struct cmd_token *, char *);

static enum match_type match_ipv4(const char *);

static enum match_type match_ipv4_prefix(const char *);

static enum match_type match_ipv6_prefix(const char *, bool);

static enum match_type match_range(struct cmd_token *, const char *);

static enum match_type match_word(struct cmd_token *, const char *);

static enum match_type match_variable(struct cmd_token *, const char *);

static enum match_type match_mac(const char *, bool);

enum matcher_rv command_match(struct graph *cmdgraph, vector vline,
			      struct list **argv, const struct cmd_element **el)
{
	struct graph_node *stack[CMD_ARGC_MAX];
	enum matcher_rv status;
	*argv = NULL;

	// prepend a dummy token to match that pesky start node
	vector vvline = vector_init(vline->alloced + 1);
	vector_set_index(vvline, 0, (void *)XSTRDUP(MTYPE_TMP, "dummy"));
	memcpy(vvline->index + 1, vline->index,
	       sizeof(void *) * vline->alloced);
	vvline->active = vline->active + 1;

	struct graph_node *start = vector_slot(cmdgraph->nodes, 0);
	status = command_match_r(start, vvline, 0, stack, argv);
	if (status == MATCHER_OK) { // successful match
		struct listnode *head = listhead(*argv);
		struct listnode *tail = listtail(*argv);

		assert(head);
		assert(tail);

		// delete dummy start node
		cmd_token_del((struct cmd_token *)head->data);
		list_delete_node(*argv, head);

		// get cmd_element out of list tail
		*el = listgetdata(tail);
		list_delete_node(*argv, tail);

		// now argv is an ordered list of cmd_token matching the user
		// input, with each cmd_token->arg holding the corresponding
		// input
		assert(*el);
	} else if (*argv) {
		del_arglist(*argv);
		*argv = NULL;
	}

	if (!*el) {
		trace_matcher("No match\n");
	} else {
		trace_matcher("Matched command\n->string %s\n->desc %s\n",
			      (*el)->string, (*el)->doc);
	}

	// free the leader token we alloc'd
	XFREE(MTYPE_TMP, vector_slot(vvline, 0));
	// free vector
	vector_free(vvline);

	return status;
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
 * are leaves (type END_TKN). If this is the case, then the bottom of the
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
 * @param[in] start the start node.
 * @param[in] vline the vectorized input line.
 * @param[in] n the index of the first input token.
 * @return A linked list of n elements. The first n-1 elements are pointers to
 * struct cmd_token and represent the sequence of tokens matched by the input.
 * The ->arg field of each token points to a copy of the input matched on it.
 * The final nth element is a pointer to struct cmd_element, which is the
 * command that was matched.
 *
 * If no match was found, the return value is NULL.
 */
static enum matcher_rv command_match_r(struct graph_node *start, vector vline,
				       unsigned int n,
				       struct graph_node **stack,
				       struct list **currbest)
{
	assert(n < vector_active(vline));

	enum matcher_rv status = MATCHER_NO_MATCH;

	// get the minimum match level that can count as a full match
	struct cmd_token *copy, *token = start->data;
	enum match_type minmatch = min_match_level(token->type);

	/* check history/stack of tokens
	 * this disallows matching the same one more than once if there is a
	 * circle in the graph (used for keyword arguments) */
	if (n == CMD_ARGC_MAX)
		return MATCHER_NO_MATCH;
	if (!token->allowrepeat)
		for (size_t s = 0; s < n; s++)
			if (stack[s] == start)
				return MATCHER_NO_MATCH;

	// get the current operating input token
	char *input_token = vector_slot(vline, n);

#ifdef TRACE_MATCHER
	fprintf(stdout, "\"%-20s\" matches \"%-30s\" ? ", input_token,
		token->text);
	enum match_type mt = match_token(token, input_token);
	fprintf(stdout, "type: %d ", token->type);
	fprintf(stdout, "min: %d - ", minmatch);
	switch (mt) {
	case trivial_match:
		fprintf(stdout, "trivial_match ");
		break;
	case no_match:
		fprintf(stdout, "no_match ");
		break;
	case partly_match:
		fprintf(stdout, "partly_match ");
		break;
	case exact_match:
		fprintf(stdout, "exact_match ");
		break;
	}
	if (mt >= minmatch)
		fprintf(stdout, " MATCH");
	fprintf(stdout, "\n");
#endif

	// if we don't match this node, die
	if (match_token(token, input_token) < minmatch)
		return MATCHER_NO_MATCH;

	stack[n] = start;

	// pointers for iterating linklist
	struct listnode *ln;
	struct graph_node *gn;

	// get all possible nexthops
	struct list *next = list_new();
	add_nexthops(next, start, NULL, 0);

	// determine the best match
	for (ALL_LIST_ELEMENTS_RO(next, ln, gn)) {
		// if we've matched all input we're looking for END_TKN
		if (n + 1 == vector_active(vline)) {
			struct cmd_token *tok = gn->data;
			if (tok->type == END_TKN) {
				// if more than one END_TKN in the follow set
				if (*currbest) {
					status = MATCHER_AMBIGUOUS;
					break;
				} else {
					status = MATCHER_OK;
				}
				*currbest = list_new();
				// node should have one child node with the
				// element
				struct graph_node *leaf =
					vector_slot(gn->to, 0);
				// last node in the list will hold the
				// cmd_element; this is important because
				// list_delete() expects that all nodes have
				// the same data type, so when deleting this
				// list the last node must be manually deleted
				struct cmd_element *el = leaf->data;
				listnode_add(*currbest, el);
				(*currbest)->del =
					(void (*)(void *)) & cmd_token_del;
				// do not break immediately; continue walking
				// through the follow set to ensure that there
				// is exactly one END_TKN
			}
			continue;
		}

		// else recurse on candidate child node
		struct list *result = NULL;
		enum matcher_rv rstat =
			command_match_r(gn, vline, n + 1, stack, &result);

		// save the best match
		if (result && *currbest) {
			// pick the best of two matches
			struct list *newbest =
				disambiguate(*currbest, result, vline, n + 1);

			// current best and result are ambiguous
			if (!newbest)
				status = MATCHER_AMBIGUOUS;
			// current best is still the best, but ambiguous
			else if (newbest == *currbest
				 && status == MATCHER_AMBIGUOUS)
				status = MATCHER_AMBIGUOUS;
			// result is better, but also ambiguous
			else if (newbest == result
				 && rstat == MATCHER_AMBIGUOUS)
				status = MATCHER_AMBIGUOUS;
			// one or the other is superior and not ambiguous
			else
				status = MATCHER_OK;

			// delete the unnecessary result
			struct list *todelete =
				((newbest && newbest == result) ? *currbest
								: result);
			del_arglist(todelete);

			*currbest = newbest ? newbest : *currbest;
		} else if (result) {
			status = rstat;
			*currbest = result;
		} else if (!*currbest) {
			status = MAX(rstat, status);
		}
	}
	if (*currbest) {
		// copy token, set arg and prepend to currbest
		token = start->data;
		copy = cmd_token_dup(token);
		copy->arg = XSTRDUP(MTYPE_CMD_ARG, input_token);
		listnode_add_before(*currbest, (*currbest)->head, copy);
	} else if (n + 1 == vector_active(vline) && status == MATCHER_NO_MATCH)
		status = MATCHER_INCOMPLETE;

	// cleanup
	list_delete(&next);

	return status;
}

static void stack_del(void *val)
{
	XFREE(MTYPE_CMD_MATCHSTACK, val);
}

enum matcher_rv command_complete(struct graph *graph, vector vline,
				 struct list **completions)
{
	// pointer to next input token to match
	char *input_token;

	struct list *
		current =
		       list_new(), // current nodes to match input token against
		*next = list_new(); // possible next hops after current input
				    // token
	current->del = next->del = stack_del;

	// pointers used for iterating lists
	struct graph_node **gstack, **newstack;
	struct listnode *node;

	// add all children of start node to list
	struct graph_node *start = vector_slot(graph->nodes, 0);
	add_nexthops(next, start, &start, 0);

	unsigned int idx;
	for (idx = 0; idx < vector_active(vline) && next->count > 0; idx++) {
		list_delete(&current);
		current = next;
		next = list_new();
		next->del = stack_del;

		input_token = vector_slot(vline, idx);

		int exact_match_exists = 0;
		for (ALL_LIST_ELEMENTS_RO(current, node, gstack))
			if (!exact_match_exists)
				exact_match_exists =
					(match_token(gstack[0]->data,
						     input_token)
					 == exact_match);
			else
				break;

		for (ALL_LIST_ELEMENTS_RO(current, node, gstack)) {
			struct cmd_token *token = gstack[0]->data;

			if (token->attr == CMD_ATTR_HIDDEN
			    || token->attr == CMD_ATTR_DEPRECATED)
				continue;

			enum match_type minmatch = min_match_level(token->type);
			trace_matcher("\"%s\" matches \"%s\" (%d) ? ",
				      input_token, token->text, token->type);

			unsigned int last_token =
				(vector_active(vline) - 1 == idx);
			enum match_type matchtype =
				match_token(token, input_token);
			switch (matchtype) {
			// occurs when last token is whitespace
			case trivial_match:
				trace_matcher("trivial_match\n");
				assert(last_token);
				newstack = XMALLOC(MTYPE_CMD_MATCHSTACK,
						   sizeof(struct graph_node *));
				/* we're not recursing here, just the first
				 * element is OK */
				newstack[0] = gstack[0];
				listnode_add(next, newstack);
				break;
			case partly_match:
				trace_matcher("trivial_match\n");
				if (exact_match_exists && !last_token)
					break;
			/* fallthru */
			case exact_match:
				trace_matcher("exact_match\n");
				if (last_token) {
					newstack = XMALLOC(
						MTYPE_CMD_MATCHSTACK,
						sizeof(struct graph_node *));
					/* same as above, not recursing on this
					 */
					newstack[0] = gstack[0];
					listnode_add(next, newstack);
				} else if (matchtype >= minmatch)
					add_nexthops(next, gstack[0], gstack,
						     idx + 1);
				break;
			default:
				trace_matcher("no_match\n");
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

	enum matcher_rv mrv = idx == vector_active(vline) && next->count
				      ? MATCHER_OK
				      : MATCHER_NO_MATCH;

	*completions = NULL;
	if (!MATCHER_ERROR(mrv)) {
		// extract cmd_token into list
		*completions = list_new();
		for (ALL_LIST_ELEMENTS_RO(next, node, gstack)) {
			listnode_add(*completions, gstack[0]->data);
		}
	}

	list_delete(&current);
	list_delete(&next);

	return mrv;
}

/**
 * Adds all children that are reachable by one parser hop to the given list.
 * special tokens except END_TKN are treated as transparent.
 *
 * @param[in] list to add the nexthops to
 * @param[in] node to start calculating nexthops from
 * @param[in] stack listing previously visited nodes, if non-NULL.
 * @param[in] stackpos how many valid entries are in stack
 * @return the number of children added to the list
 *
 * NB: non-null "stack" means that new stacks will be added to "list" as
 * output, instead of direct node pointers!
 */
static int add_nexthops(struct list *list, struct graph_node *node,
			struct graph_node **stack, size_t stackpos)
{
	int added = 0;
	struct graph_node *child;
	struct graph_node **nextstack;
	for (unsigned int i = 0; i < vector_active(node->to); i++) {
		child = vector_slot(node->to, i);
		size_t j;
		struct cmd_token *token = child->data;
		if (!token->allowrepeat && stack) {
			for (j = 0; j < stackpos; j++)
				if (child == stack[j])
					break;
			if (j != stackpos)
				continue;
		}
		if (token->type >= SPECIAL_TKN && token->type != END_TKN) {
			added += add_nexthops(list, child, stack, stackpos);
		} else {
			if (stack) {
				nextstack = XMALLOC(
					MTYPE_CMD_MATCHSTACK,
					(stackpos + 1)
						* sizeof(struct graph_node *));
				nextstack[0] = child;
				memcpy(nextstack + 1, stack,
				       stackpos * sizeof(struct graph_node *));

				listnode_add(list, nextstack);
			} else
				listnode_add(list, child);
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
static enum match_type min_match_level(enum cmd_token_type type)
{
	switch (type) {
	// anything matches a start node, for the sake of recursion
	case START_TKN:
		return no_match;
	// allowing words to partly match enables command abbreviation
	case WORD_TKN:
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
static int score_precedence(enum cmd_token_type type)
{
	switch (type) {
	// some of these are mutually exclusive, so they share
	// the same precedence value
	case IPV4_TKN:
	case IPV4_PREFIX_TKN:
	case IPV6_TKN:
	case IPV6_PREFIX_TKN:
	case MAC_TKN:
	case MAC_PREFIX_TKN:
	case RANGE_TKN:
		return 2;
	case WORD_TKN:
		return 3;
	case VARIABLE_TKN:
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
static struct cmd_token *disambiguate_tokens(struct cmd_token *first,
					     struct cmd_token *second,
					     char *input_token)
{
	// if the types are different, simply go off of type precedence
	if (first->type != second->type) {
		int firstprec = score_precedence(first->type);
		int secndprec = score_precedence(second->type);
		if (firstprec != secndprec)
			return firstprec < secndprec ? first : second;
		else
			return NULL;
	}

	// if they're the same, return the more exact match
	enum match_type fmtype = match_token(first, input_token);
	enum match_type smtype = match_token(second, input_token);
	if (fmtype != smtype)
		return fmtype > smtype ? first : second;

	return NULL;
}

/**
 * Picks the better of two possible matches for an input line.
 *
 * @param[in] first candidate list of cmd_token matching vline
 * @param[in] second candidate list of cmd_token matching vline
 * @param[in] vline the input line being matched
 * @param[in] n index into vline to start comparing at
 * @return the best-matching list, or NULL if the two are entirely ambiguous
 */
static struct list *disambiguate(struct list *first, struct list *second,
				 vector vline, unsigned int n)
{
	assert(first != NULL);
	assert(second != NULL);
	// doesn't make sense for these to be inequal length
	assert(first->count == second->count);
	assert(first->count == vector_active(vline) - n + 1);

	struct listnode *fnode = listhead_unchecked(first),
			*snode = listhead_unchecked(second);
	struct cmd_token *ftok = listgetdata(fnode), *stok = listgetdata(snode),
			 *best = NULL;

	// compare each token, if one matches better use that one
	for (unsigned int i = n; i < vector_active(vline); i++) {
		char *token = vector_slot(vline, i);
		if ((best = disambiguate_tokens(ftok, stok, token)))
			return best == ftok ? first : second;
		fnode = listnextnode(fnode);
		snode = listnextnode(snode);
		ftok = listgetdata(fnode);
		stok = listgetdata(snode);
	}

	return NULL;
}

/*
 * Deletion function for arglist.
 *
 * Since list->del for arglists expects all listnode->data to hold cmd_token,
 * but arglists have cmd_element as the data for the tail, this function
 * manually deletes the tail before deleting the rest of the list as usual.
 *
 * The cmd_element at the end is *not* a copy. It is the one and only.
 *
 * @param list the arglist to delete
 */
static void del_arglist(struct list *list)
{
	// manually delete last node
	struct listnode *tail = listtail(list);
	tail->data = NULL;
	list_delete_node(list, tail);

	// delete the rest of the list as usual
	list_delete(&list);
}

/*---------- token level matching functions ----------*/

static enum match_type match_token(struct cmd_token *token, char *input_token)
{
	// nothing trivially matches everything
	if (!input_token)
		return trivial_match;

	switch (token->type) {
	case WORD_TKN:
		return match_word(token, input_token);
	case IPV4_TKN:
		return match_ipv4(input_token);
	case IPV4_PREFIX_TKN:
		return match_ipv4_prefix(input_token);
	case IPV6_TKN:
		return match_ipv6_prefix(input_token, false);
	case IPV6_PREFIX_TKN:
		return match_ipv6_prefix(input_token, true);
	case RANGE_TKN:
		return match_range(token, input_token);
	case VARIABLE_TKN:
		return match_variable(token, input_token);
	case MAC_TKN:
		return match_mac(input_token, false);
	case MAC_PREFIX_TKN:
		return match_mac(input_token, true);
	case END_TKN:
	default:
		return no_match;
	}
}

#define IPV4_ADDR_STR   "0123456789."
#define IPV4_PREFIX_STR "0123456789./"

static enum match_type match_ipv4(const char *str)
{
	const char *sp;
	int dots = 0, nums = 0;
	char buf[4];

	for (;;) {
		memset(buf, 0, sizeof(buf));
		sp = str;
		while (*str != '\0') {
			if (*str == '.') {
				if (dots >= 3)
					return no_match;

				if (*(str + 1) == '.')
					return no_match;

				if (*(str + 1) == '\0')
					return partly_match;

				dots++;
				break;
			}
			if (!isdigit((unsigned char)*str))
				return no_match;

			str++;
		}

		if (str - sp > 3)
			return no_match;

		memcpy(buf, sp, str - sp);

		int v = atoi(buf);

		if (v > 255)
			return no_match;
		if (v > 0 && buf[0] == '0')
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

static enum match_type match_ipv4_prefix(const char *str)
{
	const char *sp;
	int dots = 0;
	char buf[4];

	for (;;) {
		memset(buf, 0, sizeof(buf));
		sp = str;
		while (*str != '\0' && *str != '/') {
			if (*str == '.') {
				if (dots == 3)
					return no_match;

				if (*(str + 1) == '.' || *(str + 1) == '/')
					return no_match;

				if (*(str + 1) == '\0')
					return partly_match;

				dots++;
				break;
			}

			if (!isdigit((unsigned char)*str))
				return no_match;

			str++;
		}

		if (str - sp > 3)
			return no_match;

		memcpy(buf, sp, str - sp);

		int v = atoi(buf);

		if (v > 255)
			return no_match;
		if (v > 0 && buf[0] == '0')
			return no_match;

		if (dots == 3) {
			if (*str == '/') {
				if (*(str + 1) == '\0')
					return partly_match;

				str++;
				break;
			} else if (*str == '\0')
				return partly_match;
		}

		if (*str == '\0')
			return partly_match;

		str++;
	}

	sp = str;
	while (*str != '\0') {
		if (!isdigit((unsigned char)*str))
			return no_match;

		str++;
	}

	if (atoi(sp) > 32)
		return no_match;

	return exact_match;
}


#define IPV6_ADDR_STR   "0123456789abcdefABCDEF:."
#define IPV6_PREFIX_STR "0123456789abcdefABCDEF:./"
#define STATE_START     1
#define STATE_COLON     2
#define STATE_DOUBLE    3
#define STATE_ADDR      4
#define STATE_DOT       5
#define STATE_SLASH     6
#define STATE_MASK      7

static enum match_type match_ipv6_prefix(const char *str, bool prefix)
{
	int state = STATE_START;
	int colons = 0, nums = 0, double_colon = 0;
	int mask;
	const char *sp = NULL, *start = str;
	char *endptr = NULL;

	if (str == NULL)
		return partly_match;

	if (strspn(str, prefix ? IPV6_PREFIX_STR : IPV6_ADDR_STR)
	    != strlen(str))
		return no_match;

	while (*str != '\0' && state != STATE_MASK) {
		switch (state) {
		case STATE_START:
			if (*str == ':') {
				if (*(str + 1) != ':' && *(str + 1) != '\0')
					return no_match;
				colons--;
				state = STATE_COLON;
			} else {
				sp = str;
				state = STATE_ADDR;
			}

			continue;
		case STATE_COLON:
			colons++;
			if (*(str + 1) == '/')
				return no_match;
			else if (*(str + 1) == ':')
				state = STATE_DOUBLE;
			else {
				sp = str + 1;
				state = STATE_ADDR;
			}
			break;
		case STATE_DOUBLE:
			if (double_colon)
				return no_match;

			if (*(str + 1) == ':')
				return no_match;
			else {
				if (*(str + 1) != '\0' && *(str + 1) != '/')
					colons++;
				sp = str + 1;

				if (*(str + 1) == '/')
					state = STATE_SLASH;
				else
					state = STATE_ADDR;
			}

			double_colon++;
			nums += 1;
			break;
		case STATE_ADDR:
			if (*(str + 1) == ':' || *(str + 1) == '.'
			    || *(str + 1) == '\0' || *(str + 1) == '/') {
				if (str - sp > 3)
					return no_match;

				for (; sp <= str; sp++)
					if (*sp == '/')
						return no_match;

				nums++;

				if (*(str + 1) == ':')
					state = STATE_COLON;
				else if (*(str + 1) == '.') {
					if (colons || double_colon)
						state = STATE_DOT;
					else
						return no_match;
				} else if (*(str + 1) == '/')
					state = STATE_SLASH;
			}
			break;
		case STATE_DOT:
			state = STATE_ADDR;
			break;
		case STATE_SLASH:
			if (*(str + 1) == '\0')
				return partly_match;

			state = STATE_MASK;
			break;
		default:
			break;
		}

		if (nums > 11)
			return no_match;

		if (colons > 7)
			return no_match;

		str++;
	}

	if (!prefix) {
		struct sockaddr_in6 sin6_dummy;
		int ret = inet_pton(AF_INET6, start, &sin6_dummy.sin6_addr);
		return ret == 1 ? exact_match : partly_match;
	}

	if (state < STATE_MASK)
		return partly_match;

	mask = strtol(str, &endptr, 10);
	if (*endptr != '\0')
		return no_match;

	if (mask < 0 || mask > 128)
		return no_match;

	return exact_match;
}

static enum match_type match_range(struct cmd_token *token, const char *str)
{
	assert(token->type == RANGE_TKN);

	char *endptr = NULL;
	long long val;

	val = strtoll(str, &endptr, 10);
	if (*endptr != '\0')
		return no_match;

	if (val < token->min || val > token->max)
		return no_match;
	else
		return exact_match;
}

static enum match_type match_word(struct cmd_token *token, const char *word)
{
	assert(token->type == WORD_TKN);

	// if the passed token is 0 length, partly match
	if (!strlen(word))
		return partly_match;

	// if the passed token is strictly a prefix of the full word, partly
	// match
	if (strlen(word) < strlen(token->text))
		return !strncmp(token->text, word, strlen(word)) ? partly_match
								 : no_match;

	// if they are the same length and exactly equal, exact match
	else if (strlen(word) == strlen(token->text))
		return !strncmp(token->text, word, strlen(word)) ? exact_match
								 : no_match;

	return no_match;
}

static enum match_type match_variable(struct cmd_token *token, const char *word)
{
	assert(token->type == VARIABLE_TKN);
	return exact_match;
}

#define MAC_CHARS "ABCDEFabcdef0123456789:"

static enum match_type match_mac(const char *word, bool prefix)
{
	/* 6 2-digit hex numbers separated by 5 colons */
	size_t mac_explen = 6 * 2 + 5;
	/* '/' + 2-digit integer */
	size_t mask_len = 1 + 2;
	unsigned int i;
	char *eptr;
	unsigned int maskval;

	/* length check */
	if (strlen(word) > mac_explen + (prefix ? mask_len : 0))
		return no_match;

	/* address check */
	for (i = 0; i < mac_explen; i++) {
		if (word[i] == '\0' || !strchr(MAC_CHARS, word[i]))
			break;
		if (((i + 1) % 3 == 0) != (word[i] == ':'))
			return no_match;
	}

	/* incomplete address */
	if (i < mac_explen && word[i] == '\0')
		return partly_match;
	else if (i < mac_explen)
		return no_match;

	/* mask check */
	if (prefix && word[i] == '/') {
		if (word[++i] == '\0')
			return partly_match;

		maskval = strtoul(&word[i], &eptr, 10);
		if (*eptr != '\0' || maskval > 48)
			return no_match;
	} else if (prefix && word[i] == '\0') {
		return partly_match;
	} else if (prefix) {
		return no_match;
	}

	return exact_match;
}
