#include "vector.h"

enum graph_node_type
{
  WORD_GN,
  IPV4_GN,
  IPV4_PREFIX_GN,
  IPV6_GN,
  IPV6_PREFIX_GN,
  VARIABLE_GN,
  RANGE_GN,
  NUMBER_GN,
  SELECTOR_GN,
  OPTION_GN,
  NUL_GN
};

struct graph_node
{
  enum graph_node_type type;
  vector children;
  int is_leaf, is_root;
  // int (*func(struct cmd_info *, struct vty *, int, const char *[]));
};

/*
 * Adds a child to a node. If the node already has the exact same
 * child, nothing is done.
 */
struct graph_node *
add_node(struct graph_node *, struct graph_node *);

/*
 * Compares two nodes for equivalence.
 * What exactly constitutes two nodes being equal depends on the
 * node type.
 * @return 0 if equal, nonzero otherwise.
 */
int
cmp_node(struct graph_node *first, struct graph_node *second);

struct graph_node *
new_node(enum graph_node_type type);
