/*
 * Command DFA module.
 * Provides a DFA data structure and associated functions for manipulating it.
 * Used to match user command line input.
 *
 * @author Quentin Young <qlyoung@cumulusnetworks.com>
 */

#include "memory.h"
#include "cmdtree.h"

struct graph_node *
add_node(struct graph_node *parent, struct graph_node *child)
{
  int index;
  struct graph_node *p_child;

  for (index = 0; index < vector_active(parent->children); index++)
  {
    *p_child = vector_slot(parent->children, index);
    if (cmp_node(child, p_child))
      return p_child;
  }
  vector_set(parent->children, child);
  return child;
}

int
cmp_node(struct graph_node *first, struct graph_node *second)
{
}

struct graph_node *
new_node(enum graph_node_type type)
{
  struct graph_node *node = XMALLOC(MTYPE_TMP, sizeof(graph_node));
  node->type = type;
  node->children = vector_init(VECTOR_MIN_SIZE);
  node->is_leaf = 0;
  node->is_root = 0;
  node->func = NULL;

  return node;
}
