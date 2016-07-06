#include <command.h>
#include <vector.h>

enum tree_node_type
{
  WORD_TN,
  IPV4_TN,
  IPV4_PREFIX_TN,
  IPV6_TN,
  IPV6_PREFIX_TN,
  VARIABLE_TN,
  RANGE_TN,
  NUMBER_TN,
  SELECTOR_TN,
  OPTION_TN
}

struct tree_node
{
  enum tree_node_type type;
  vector children;
  int leaf;
  (int) (*func(struct cmd_info *, struct vty *, int, const char *[]));
}

void add_node(struct tree_node *parent, struct tree_node *child)
{

}

// checks nodes for equivalence; definition of equivalence depends
// on node type (WORD_TN strcmps words, etc)
int cmp_node(struct tree_node *first, struct tree_node *second)
{
  
}

int merge_tree(struct tree_node *first, struct tree_node *second)
{

}
