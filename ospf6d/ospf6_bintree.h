
#ifndef _BINTREE_H_
#define _BINTREE_H_

struct bintree_node
{
  struct bintree *tree;

  struct bintree_node *parent;
  int parent_link;

#define BL_LEFT  0
#define BL_RIGHT 1
#define BL_MAX   2
  struct bintree_node *link[BL_MAX];
#define bl_left  link[BL_LEFT]
#define bl_right link[BL_RIGHT]

  void *data;
};

struct bintree
{
  int count;
  struct bintree_node *root;

  int  (*cmp)   (void *, void *);
};

void *bintree_lookup (void *data, struct bintree *tree);
void *bintree_lookup_min (struct bintree *tree);
void *bintree_lookup_max (struct bintree *tree);

int   bintree_add (void *data, struct bintree *tree);
int   bintree_remove (void *data, struct bintree *tree);

void bintree_head (struct bintree *tree, struct bintree_node *node);
int  bintree_end (struct bintree_node *node);
void bintree_next (struct bintree_node *node);

struct bintree *bintree_create ();
void bintree_delete (struct bintree *);

void bintree_print (void (*print) (int, void *), struct bintree *);

#endif /*_BINTREE_H_*/

