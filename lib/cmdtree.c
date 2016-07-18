/*
 * Command DFA module.
 * Provides a DFA data structure and associated functions for manipulating it.
 * Used to match user command line input.
 *
 * @author Quentin Young <qlyoung@cumulusnetworks.com>
 */

#include <zebra.h>
#include "cmdtree.h"
#include "memory.h"

struct graph_node *
add_node(struct graph_node *parent, struct graph_node *child)
{
  unsigned int index;
  struct graph_node *p_child;

  for (index = 0; index < vector_active(parent->children); index++)
  {
    p_child = vector_slot(parent->children, index);
    if (cmp_node(child, p_child))
      return p_child;
  }
  vector_set(parent->children, child);
  return child;
}

int
cmp_node(struct graph_node *first, struct graph_node *second)
{
  return 0;
}

struct graph_node *
new_node(enum graph_node_type type)
{
  struct graph_node *node = malloc(sizeof(struct graph_node));
  node->type = type;
  node->children = vector_init(VECTOR_MIN_SIZE);
  node->is_leaf = 0;
  node->is_root = 0;
  node->func = NULL;

  return node;
}

void
walk_graph(struct graph_node *start, int level)
{
  // print this node
  switch (start->type) {
    case WORD_GN:
    case IPV4_GN:
    case IPV4_PREFIX_GN:
    case IPV6_GN:
    case IPV6_PREFIX_GN:
    case VARIABLE_GN:
    case RANGE_GN:
      fprintf(stderr, "%s", start->text);
      break;
    case NUMBER_GN:
      fprintf(stderr, "%d", start->value);
      break;
    case SELECTOR_GN:
      fprintf(stderr, "<>");
      break;
    case OPTION_GN:
      fprintf(stderr, "[]");
      break;
    case NUL_GN:
      fprintf(stderr, "NUL");
      break;
    default:
      fprintf(stderr, "ERROR");
  }
  fprintf(stderr, "[%d] ", vector_active(start->children));

  if (vector_active(start->children))
    for (unsigned int i = 0; i < vector_active(start->children); i++) {
      struct graph_node *r = vector_slot(start->children, i);
      if (!r) {
        fprintf(stderr, "Child seems null?\n");
        break;
      }
      else {
        if (start->type == OPTION_GN || start->type == SELECTOR_GN) {
          fprintf(stderr, "\n");
          for (int i = 0; i < level+1; i++)
            fprintf(stderr, "\t");
        }
        walk_graph(r, level+1);
      }
    }
  else {
    fprintf(stderr, "\n");
  }
}
