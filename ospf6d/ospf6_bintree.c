
#include <zebra.h>
#include "ospf6_bintree.h"

static struct bintree_node *
bintree_lookup_node_min (struct bintree_node *subroot)
{
  struct bintree_node *node;

  if (subroot == NULL)
    return NULL;

  node = subroot;
  while (node->bl_left)
    node = node->bl_left;
  return node;
}

static struct bintree_node *
bintree_lookup_node_max (struct bintree_node *subroot)
{
  struct bintree_node *node;

  assert (subroot != NULL);
  node = subroot;
  while (node->bl_right)
    node = node->bl_right;
  return node;
}

void *
bintree_lookup (void *data, struct bintree *tree)
{
  int cmp;
  struct bintree_node *node;

  node = tree->root;

  while (node)
    {
      if (tree->cmp)
        cmp = (*tree->cmp) (node->data, data);
      else
        cmp = (node->data - data);

      if (cmp == 0)
        break;

      if (cmp > 0)
        node = node->bl_left;
      else /* if (cmp < 0) */
        node = node->bl_right;
    }

  if (node)
    return node->data;

  return NULL;
}

void *
bintree_lookup_min (struct bintree *tree)
{
  struct bintree_node *node;
  node = bintree_lookup_node_min (tree->root);
  if (node == NULL)
    return NULL;
  return node->data;
}

void *
bintree_lookup_max (struct bintree *tree)
{
  struct bintree_node *node;
  node = bintree_lookup_node_max (tree->root);
  if (node == NULL)
    return NULL;
  return node->data;
}

int
bintree_add (void *data, struct bintree *tree)
{
  int cmp = 0;
  struct bintree_node *node, *parent;

  node = tree->root;
  parent = NULL;

  while (node)
    {
      if (tree->cmp)
        cmp = (*tree->cmp) (node->data, data);
      else
        cmp = (node->data - data);

      if (cmp == 0)
        break;

      parent = node;
      if (cmp > 0)
        node = node->bl_left;
      else /* if (cmp < 0) */
        node = node->bl_right;
    }

  if (node)
    return -1;

  node = malloc (sizeof (struct bintree_node));
  memset (node, 0, sizeof (struct bintree_node));
  node->tree = tree;
  node->data = data;

  if (parent)
    {
      node->parent = parent;

      assert (cmp != 0);
      if (cmp > 0)
        {
          node->parent_link = BL_LEFT;
          parent->bl_left = node;
        }
      else /* if (cmp < 0) */
        {
          node->parent_link = BL_RIGHT;
          parent->bl_right = node;
        }
    }
  else
    tree->root = node;

  tree->count++;
  return 0;
}

static void
bintree_remove_nochild (struct bintree_node *node)
{
  assert (node->bl_left == NULL && node->bl_right == NULL);

  if (node->parent == NULL)
    node->tree->root = NULL;
  else
    node->parent->link[node->parent_link] = NULL;
}

static void
bintree_remove_onechild (struct bintree_node *node)
{
  assert ((node->bl_left == NULL && node->bl_right != NULL) ||
          (node->bl_left != NULL && node->bl_right == NULL));

  if (node->bl_left)
    {
      if (node->parent == NULL)
        {
          node->tree->root = node->bl_left;
          node->bl_left->parent = NULL;
        }
      else
        {
          node->parent->link[node->parent_link] = node->bl_left;
          node->bl_left->parent = node->parent;
          node->bl_left->parent_link = node->parent_link;
        }
    }
  else if (node->bl_right)
    {
      if (node->parent == NULL)
        {
          node->tree->root = node->bl_right;
          node->bl_right->parent = NULL;
        }
      else
        {
          node->parent->link[node->parent_link] = node->bl_right;
          node->bl_right->parent = node->parent;
          node->bl_right->parent_link = node->parent_link;
        }
    }
  else
    assert (0);
}

int
bintree_remove (void *data, struct bintree *tree)
{
  int cmp;
  struct bintree_node *node;

  node = tree->root;

  while (node)
    {
      if (tree->cmp)
        cmp = (*tree->cmp) (node->data, data);
      else
        cmp = (node->data - data);

      if (cmp == 0)
        break;

      if (cmp > 0)
        node = node->bl_left;
      else /* if (cmp < 0) */
        node = node->bl_right;
    }

  if (node == NULL)
    return -1;

  if (node->bl_left == NULL && node->bl_right == NULL)
    {
      bintree_remove_nochild (node);
      free (node);
      tree->count--;
      return 0;
    }

  if ((node->bl_left == NULL && node->bl_right != NULL) ||
      (node->bl_left != NULL && node->bl_right == NULL))
    {
      bintree_remove_onechild (node);
      free (node);
      tree->count--;
      return 0;
    }

  if (node->bl_left != NULL && node->bl_right != NULL)
    {
      struct bintree_node *successor;

      /* find successor of the removing node */
      successor = bintree_lookup_node_min (node->bl_right);

      /* remove successor from tree */
      if (successor->bl_right)
        bintree_remove_onechild (successor);
      else
        bintree_remove_nochild (successor);

      /* swap removing node with successor */
      successor->parent = node->parent;
      successor->parent_link = node->parent_link;
      successor->bl_left = node->bl_left;
      successor->bl_right = node->bl_right;

      /* if the successor was the node->bl_right itself,
         bintree_remove_**child may touch node->bl_right,
         so only the successor->bl_right may be NULL
         by above assignment */
      successor->bl_left->parent = successor;
      if (successor->bl_right)
        successor->bl_right->parent = successor;

      if (successor->parent == NULL)
        tree->root = successor;
      else
        successor->parent->link[successor->parent_link] = successor;

      free (node);
      tree->count--;
      return 0;
    }

  /* not reached */
  return -1;
}

/* in-order traversal */

void
bintree_head (struct bintree *tree, struct bintree_node *node)
{
  struct bintree_node *head;

  head = bintree_lookup_node_min (tree->root);
  if (head == NULL)
    {
      node->parent = NULL;
      node->bl_left = NULL;
      node->bl_right = NULL;
      node->data = NULL;
      return;
    }

  node->tree = head->tree;
  node->parent = head->parent;
  node->parent_link = head->parent_link;
  node->bl_left = head->bl_left;
  node->bl_right = head->bl_right;
  node->data = head->data;
}

int
bintree_end (struct bintree_node *node)
{
  if (node->parent || node->bl_left || node->bl_right || node->data)
    return 0;
  return 1;
}

#define GOTO_PROCED_SUBTREE_TOP(node) \
  while (node->parent && node->parent->bl_right && \
         node->parent->bl_right->data == node->data) \
    { \
      node->data = node->parent->data; \
      node->bl_left = node->parent->bl_left; \
      node->bl_right = node->parent->bl_right; \
      node->parent_link = node->parent->parent_link; \
      node->parent = node->parent->parent; \
    }

void
bintree_next (struct bintree_node *node)
{
  struct bintree_node *next = NULL;

  /* if node have just been removed, current point should have just been
     replaced with its successor. that certainly  will not be processed
     yet, so process it */
  if (node->parent == NULL)
    {
      if (node->tree->root == NULL)
        {
          assert (node->tree->count == 0);
          node->parent = NULL;
          node->bl_left = NULL;
          node->bl_right = NULL;
          node->data = NULL;
          return;
        }
      else if (node->tree->root->data != node->data)
        next = node->tree->root;
    }
  else if (node->parent->link[node->parent_link] == NULL)
    {
      if (node->parent_link == BL_LEFT)
        next = node->parent;
      else
        {
          GOTO_PROCED_SUBTREE_TOP (node);
          next = node->parent;
        }
    }
  else if (node->parent->link[node->parent_link]->data != node->data)
    next = node->parent->link[node->parent_link];

  if (next == NULL)
    {
      if (node->bl_right)
        next = bintree_lookup_node_min (node->bl_right);
      else
        {
          GOTO_PROCED_SUBTREE_TOP (node);
          next = node->parent;
        }
    }

  if (next)
    {
      node->tree = next->tree;
      node->parent = next->parent;
      node->parent_link = next->parent_link;
      node->bl_left = next->bl_left;
      node->bl_right = next->bl_right;
      node->data = next->data;
    }
  else
    {
      node->parent = NULL;
      node->bl_left = NULL;
      node->bl_right = NULL;
      node->data = NULL;
    }
}

struct bintree *
bintree_create ()
{
  struct bintree *tree;

  tree = malloc (sizeof (struct bintree));
  memset (tree, 0, sizeof (struct bintree));

  return tree;
}

void
bintree_delete (struct bintree *tree)
{
  struct bintree_node node;

  for (bintree_head (tree, &node); ! bintree_end (&node);
       bintree_next (&node))
    bintree_remove (node.data, tree);

  assert (tree->count == 0);
  free (tree);
}

int indent_num = 0;

void
bintree_print_sub (void (*print) (int, void *), struct bintree_node *subroot)
{
  if (subroot == NULL)
    return;

  if (subroot->bl_right)
    {
      indent_num++;
      bintree_print_sub (print, subroot->bl_right);
      indent_num--;
    }

  (*print) (indent_num, subroot->data);

  if (subroot->bl_left)
    {
      indent_num++;
      bintree_print_sub (print, subroot->bl_left);
      indent_num--;
    }
}

void
bintree_print (void (*print) (int, void *), struct bintree *tree)
{
  indent_num = 0;
  bintree_print_sub (print, tree->root);
}


