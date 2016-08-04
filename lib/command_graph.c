/*
 * Command DFA module.
 * Provides a DFA data structure and associated functions for manipulating it.
 * Used to match user command line input.
 *
 * @author Quentin Young <qlyoung@cumulusnetworks.com>
 */

#include "command_graph.h"
#include <zebra.h>
#include "memory.h"

struct graph_node *
add_node(struct graph_node *parent, struct graph_node *child)
{
  vector_set(parent->children, child);
  child->refs++;
  return child;
}

int
cmp_node(struct graph_node *first, struct graph_node *second)
{
  // compare types
  if (first->type != second->type) return 0;

  switch (first->type) {
    case WORD_GN:
    case VARIABLE_GN:
      if (first->text && second->text) {
        if (strcmp(first->text, second->text)) return 0;
      }
      else if (first->text != second->text) return 0;
      break;
    case RANGE_GN:
      if (first->min != second->min || first->max != second->max)
        return 0;
      break;
    case NUMBER_GN:
      if (first->value != second->value) return 0;
      break;
    /* selectors and options should be equal if all paths are equal,
     * but the graph isomorphism problem is not solvable in polynomial
     * time so we consider selectors and options inequal in all cases
     */
    case SELECTOR_GN:
    case OPTION_GN:
      return 0;
    /* end nodes are always considered equal, since each node may only
     * have one at a time
     */
    case START_GN:
    case END_GN:
    case NUL_GN:
    default:
      break;
  }

  return 1;
}

struct graph_node *
new_node(enum graph_node_type type)
{
  struct graph_node *node =
     XMALLOC(MTYPE_CMD_TOKENS, sizeof(struct graph_node));

  node->type = type;
  node->children = vector_init(VECTOR_MIN_SIZE);
  node->end      = NULL;
  node->text     = NULL;
  node->element  = NULL;
  node->arg      = NULL;
  node->is_start = 0;
  node->value    = 0;
  node->min      = 0;
  node->max      = 0;
  node->refs     = 0;

  return node;
}

void
free_node (struct graph_node *node)
{
  if (!node) return;
  if (node->children) vector_free (node->children);
  if (node->element) free_cmd_element (node->element);
  free (node->text);
  free (node->arg);
  free (node);
}

void
free_graph (struct graph_node *start)
{
  if (start && start->children && vector_active(start->children) > 0) {
    for (unsigned int i = 0; i < vector_active(start->children); i++) {
      free_graph (vector_slot(start->children, i));
      vector_unset(start->children, i);
    }
  }

  if (--(start->refs) == 0)
    free_node (start);
}

char *
describe_node(struct graph_node *node, char* buffer, unsigned int bufsize)
{
  if (node == NULL) {
    snprintf(buffer, bufsize, "(null node)");
    return buffer;
  }

  // print this node
  switch (node->type) {
    case WORD_GN:
    case IPV4_GN:
    case IPV4_PREFIX_GN:
    case IPV6_GN:
    case IPV6_PREFIX_GN:
    case VARIABLE_GN:
    case RANGE_GN:
      snprintf(buffer, bufsize, node->text);
      break;
    case NUMBER_GN:
      snprintf(buffer, bufsize, "%ld", node->value);
      break;
    case SELECTOR_GN:
      snprintf(buffer, bufsize, "<>");
      break;
    case OPTION_GN:
      snprintf(buffer, bufsize, "[]");
      break;
    case NUL_GN:
      snprintf(buffer, bufsize, "NUL");
      break;
    case END_GN:
      snprintf(buffer, bufsize, "END");
      break;
    case START_GN:
      snprintf(buffer, bufsize, "START");
      break;
    default:
      snprintf(buffer, bufsize, "ERROR");
  }

  return buffer;
}


void
walk_graph(struct graph_node *start, int level)
{
  char* desc = malloc(50);
  // print this node
  fprintf(stderr, "%s[%d] ", describe_node(start, desc, 50), vector_active(start->children));
  free(desc);

  if (vector_active(start->children)) {
    if (vector_active(start->children) == 1)
      walk_graph(vector_slot(start->children, 0), level);
    else {
      fprintf(stderr, "\n");
      for (unsigned int i = 0; i < vector_active(start->children); i++) {
        struct graph_node *r = vector_slot(start->children, i);
        for (int j = 0; j < level+1; j++)
          fprintf(stderr, "    ");
        walk_graph(r, level+1);
      }
    }
  }
  else
    fprintf(stderr, "\n");
}

void
dump_node (struct graph_node *node)
{
  char buf[50];
  describe_node(node, buf, 50);
  fprintf(stderr, "%s[%d]\n", buf, node->type);
  fprintf(stderr, "\t->text: %s\n", node->text);
  fprintf(stderr, "\t->value: %ld\n", node->value);
  fprintf(stderr, "\t->is_start: %d\n", node->is_start);
  fprintf(stderr, "\t->element: %p\n", node->element);
  fprintf(stderr, "\t->min: %d\n->max: %d\n", node->min, node->max);
  fprintf(stderr, "\t->arg: %s\n", node->arg);
  fprintf(stderr, "\t->refs: %d\n", node->refs);
  fprintf(stderr, "\tnum children: %d\n", vector_active(node->children));
}
