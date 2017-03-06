#include <zebra.h>

#include "linklist.h"
#include "log.h"

#include "pimd.h"
#include "pim_msg.h"
#include "pim_jp_agg.h"
#include "pim_join.h"
#include "pim_iface.h"

void
pim_jp_agg_group_list_free (struct pim_jp_agg_group *jag)
{
  list_delete(jag->sources);

  XFREE (MTYPE_PIM_JP_AGG_GROUP, jag);
}

static void
pim_jp_agg_src_free (struct pim_jp_sources *js)
{
  /*
   * When we are being called here, we know
   * that the neighbor is going away start
   * the normal j/p timer so that it can
   * pick this shit back up when the
   * nbr comes back alive
   */
  join_timer_start(js->up);
  XFREE (MTYPE_PIM_JP_AGG_SOURCE, js);
}

int
pim_jp_agg_group_list_cmp (void *arg1, void *arg2)
{
  const struct pim_jp_agg_group *jag1 = (const struct pim_jp_agg_group *)arg1;
  const struct pim_jp_agg_group *jag2 = (const struct pim_jp_agg_group *)arg2;

  if (jag1->group.s_addr < jag2->group.s_addr)
    return -1;

  if (jag1->group.s_addr > jag2->group.s_addr)
    return 1;

  return 0;
}

static int
pim_jp_agg_src_cmp (void *arg1, void *arg2)
{
  const struct pim_jp_sources *js1 = (const struct pim_jp_sources *)arg1;
  const struct pim_jp_sources *js2 = (const struct pim_jp_sources *)arg2;

  if (js1->up->sg.src.s_addr < js2->up->sg.src.s_addr)
    return -1;

  if (js1->up->sg.src.s_addr > js2->up->sg.src.s_addr)
    return 1;

  return 0;
}

void
pim_jp_agg_clear_group (struct list *group)
{
  struct listnode *node, *nnode;
  struct pim_jp_agg_group *jag;

  for (ALL_LIST_ELEMENTS(group, node, nnode, jag))
    {
      list_delete(jag->sources);
      jag->sources = NULL;
      listnode_delete(group, jag);
      XFREE(MTYPE_PIM_JP_AGG_GROUP, jag);
    }
}

static struct pim_iface_upstream_switch *
pim_jp_agg_get_interface_upstream_switch_list (struct pim_rpf *rpf)
{
  struct pim_interface *pim_ifp = rpf->source_nexthop.interface->info;
  struct pim_iface_upstream_switch *pius;
  struct listnode *node, *nnode;

  for (ALL_LIST_ELEMENTS(pim_ifp->upstream_switch_list, node, nnode, pius))
    {
      if (pius->address.s_addr == rpf->rpf_addr.u.prefix4.s_addr)
        break;
    }

  if (!pius)
    {
      pius = XCALLOC(MTYPE_PIM_JP_AGG_GROUP, sizeof (struct pim_iface_upstream_switch));
      pius->address.s_addr = rpf->rpf_addr.u.prefix4.s_addr;
      pius->us = list_new();
      listnode_add (pim_ifp->upstream_switch_list, pius);
    }

  return pius;
}

void
pim_jp_agg_remove_group (struct list *group, struct pim_upstream *up)
{
  struct listnode *node, *nnode;
  struct pim_jp_agg_group *jag = NULL;
  struct pim_jp_sources *js = NULL;

  for (ALL_LIST_ELEMENTS(group, node, nnode, jag))
    {
      if (jag->group.s_addr == up->sg.grp.s_addr)
        break;
    }

  if (!jag)
    return;

  for (ALL_LIST_ELEMENTS(jag->sources, node, nnode, js))
    {
      if (js->up == up)
        break;
    }

  listnode_delete(jag->sources, js);

  XFREE(MTYPE_PIM_JP_AGG_SOURCE, js);

  if (jag->sources->count == 0)
    {
      list_delete(jag->sources);
      listnode_delete(group, jag);
    }
}

void
pim_jp_agg_add_group (struct list *group, struct pim_upstream *up, bool is_join)
{
  struct listnode *node, *nnode;
  struct pim_jp_agg_group *jag = NULL;
  struct pim_jp_sources *js;

  for (ALL_LIST_ELEMENTS(group, node, nnode, jag))
    {
      if (jag->group.s_addr == up->sg.grp.s_addr)
        break;
    }

  if (!jag)
    {
      jag = XCALLOC(MTYPE_PIM_JP_AGG_GROUP, sizeof (struct pim_jp_agg_group));
      jag->group.s_addr = up->sg.grp.s_addr;
      jag->sources = list_new();
      jag->sources->cmp = pim_jp_agg_src_cmp;
      jag->sources->del = (void (*)(void *))pim_jp_agg_src_free;
      listnode_add (group, jag);
    }

  js = XCALLOC(MTYPE_PIM_JP_AGG_SOURCE, sizeof (struct pim_jp_sources));
  js->up = up;
  js->is_join = is_join;

  listnode_add (jag->sources, js);
}

void
pim_jp_agg_switch_interface (struct pim_rpf *orpf,
                             struct pim_rpf *nrpf,
                             struct pim_upstream *up)
{
  struct pim_iface_upstream_switch *opius;
  struct pim_iface_upstream_switch *npius;

  opius = pim_jp_agg_get_interface_upstream_switch_list(orpf);
  npius = pim_jp_agg_get_interface_upstream_switch_list(nrpf);

  /*
   * RFC 4601: 4.5.7.  Sending (S,G) Join/Prune Messages
   *
   * Transitions from Joined State
   *
   * RPF'(S,G) changes not due to an Assert
   *
   * The upstream (S,G) state machine remains in Joined
   * state. Send Join(S,G) to the new upstream neighbor, which is
   * the new value of RPF'(S,G).  Send Prune(S,G) to the old
   * upstream neighbor, which is the old value of RPF'(S,G).  Set
   * the Join Timer (JT) to expire after t_periodic seconds.
   */

  /* send Prune(S,G) to the old upstream neighbor */
  pim_jp_agg_add_group (opius->us, up, false);

  /* send Join(S,G) to the current upstream neighbor */
  pim_jp_agg_add_group (npius->us, up, true);

}


void
pim_jp_agg_single_upstream_send (struct pim_rpf *rpf,
                                 struct pim_upstream *up,
                                 bool is_join)
{
  static struct list *groups = NULL;
  static struct pim_jp_agg_group jag;
  static struct pim_jp_sources js;

  static bool first = true;

  if (first)
    {
      groups = list_new();

      jag.sources = list_new();

      listnode_add(groups, &jag);
      listnode_add(jag.sources, &js);

      first = false;
    }

  jag.group.s_addr = up->sg.grp.s_addr;
  js.up = up;
  js.is_join = is_join;

  pim_joinprune_send(rpf, groups);
}
