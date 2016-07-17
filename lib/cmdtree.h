#include "vty.h"
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
  int is_root;      // true if first token in command
  int is_leaf;      // true if last token in command

  int (*func)(struct vty *, int, const char *[]);

  /* various data fields for nodes */
  char* text;       // for words and variables
  int value;        // for numbers
  int start, end;   // for ranges
};

/*
 * Adds a child to a node. If the node already has the exact same
 * child, nothing is done.
 * @param[in] parent node
 * @param[in] child node
 * @return the new child, or the existing child if the parent already has the
 *         new child
 */
extern struct graph_node *
add_node(struct graph_node *, struct graph_node *);

/*
 * Compares two nodes for equivalence.
 * What exactly constitutes two nodes being equal depends on the
 * node type.
 * @return 0 if equal, nonzero otherwise.
 */
extern int
cmp_node(struct graph_node *first, struct graph_node *second);

extern struct graph_node *
new_node(enum graph_node_type type);
