
#include <zebra.h>

#include "ospf6_linklist.h"

static struct linklist_node *
linklist_lookup_node (void *data, struct linklist *linklist)
{
  struct linklist_node *node;

  for (node = linklist->head; node; node = node->next)
    {
      if (linklist->cmp && (*linklist->cmp) (node->data, data) == 0)
        return node;
      if (node->data == data)
        return node;
    }

  return NULL;
}

void *
linklist_lookup (void *data, struct linklist *linklist)
{
  struct linklist_node *node;

  node = linklist_lookup_node (data, linklist);
  if (node)
    return node->data;
  return NULL;
}

int
linklist_add (void *data, struct linklist *linklist)
{
  struct linklist_node *node = NULL, *add;

  if (linklist_lookup_node (data, linklist))
    return -1;

  add = malloc (sizeof (struct linklist_node));
  if (add == NULL)
    return -1;
  memset (add, 0, sizeof (struct linklist_node));
  add->data = data;

  if (linklist->cmp)
    {
      for (node = linklist->head; node; node = node->next)
        {
          if ((*linklist->cmp) (node->data, add->data) > 0)
            break;
        }
    }

  if (! node)
    {
      /* add to tail */
      if (linklist->tail)
        {
          linklist->tail->next = add;
          add->prev = linklist->tail;
        }
      else
        {
          linklist->head = add;
          add->prev = NULL;
        }

      linklist->tail = add;
      add->next = NULL;
    }
  else
    {
      /* insert just before 'node' */
      if (node->prev)
        {
          node->prev->next = add;
          add->prev = node->prev;
        }
      else
        {
          linklist->head = add;
          add->prev = NULL;
        }

      add->next = node;
      node->prev = add;
    }

  linklist->count++;
  return 0;
}

int
linklist_remove (void *data, struct linklist *linklist)
{
  struct linklist_node *rem;

  rem = linklist_lookup_node (data, linklist);
  if (rem == NULL)
    return -1;

  if (rem->prev)
    rem->prev->next = rem->next;
  else
    linklist->head = rem->next;

  if (rem->next)
    rem->next->prev = rem->prev;
  else
    linklist->tail = rem->prev;

  free (rem);
  linklist->count--;
  return 0;
}

void
linklist_head (struct linklist *linklist, struct linklist_node *node)
{
  if (linklist->head == NULL)
    {
      node->prev = NULL;
      node->next = NULL;
      node->data = NULL;
      return;
    }

  node->prev = linklist->head->prev;
  node->next = linklist->head->next;
  node->data = linklist->head->data;
}

int
linklist_end (struct linklist_node *node)
{
  if (node->data == NULL && node->next == NULL)
    return 1;
  return 0;
}

void
linklist_next (struct linklist_node *node)
{
  if (node->next == NULL)
    {
      node->prev = NULL;
      node->next = NULL;
      node->data = NULL;
      return;
    }

  node->data = node->next->data;
  node->prev = node->next->prev;
  node->next = node->next->next;
}

struct linklist *
linklist_create ()
{
  struct linklist *linklist;

  linklist = malloc (sizeof (struct linklist));
  if (linklist == NULL)
    return NULL;
  memset (linklist, 0, sizeof (struct linklist));

  return linklist;
}

void
linklist_remove_all (struct linklist *linklist)
{
  struct linklist_node node;

  for (linklist_head (linklist, &node); ! linklist_end (&node);
       linklist_next (&node))
    linklist_remove (node.data, linklist);
}

void
linklist_delete (struct linklist *linklist)
{
  linklist_remove_all (linklist);
  assert (linklist->count == 0);
  assert (linklist->head == NULL);
  assert (linklist->tail == NULL);

  free (linklist);
}


