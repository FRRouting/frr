
#ifndef _LINKLIST_H_
#define _LINKLIST_H_

struct linklist_node
{
  struct linklist_node *prev;
  struct linklist_node *next;

  void *data;
};

struct linklist
{
  int count;
  struct linklist_node *head;
  struct linklist_node *tail;

  int    (*cmp) (void *, void *);
};

void *linklist_lookup (void *data, struct linklist *linklist);
int   linklist_add (void *data, struct linklist *linklist);
int   linklist_remove (void *data, struct linklist *linklist);
void  linklist_remove_all (struct linklist *linklist);

void linklist_head (struct linklist *linklist, struct linklist_node *node);
int  linklist_end (struct linklist_node *node);
void linklist_next (struct linklist_node *node);

struct linklist *linklist_create ();
void linklist_delete (struct linklist *);

#endif /*_LINKLIST_H_*/

