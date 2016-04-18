/* Zebra MPLS code
 * Copyright (C) 2013 Cumulus Networks, Inc.
 *
 * This file is part of GNU Zebra.
 *
 * GNU Zebra is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2, or (at your option) any
 * later version.
 *
 * GNU Zebra is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with GNU Zebra; see the file COPYING.  If not, write to the Free
 * Software Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA
 * 02111-1307, USA.
 */

#include <zebra.h>

#include "prefix.h"
#include "table.h"
#include "memory.h"
#include "str.h"
#include "command.h"
#include "if.h"
#include "log.h"
#include "sockunion.h"
#include "linklist.h"
#include "thread.h"
#include "workqueue.h"
#include "prefix.h"
#include "routemap.h"
#include "stream.h"
#include "nexthop.h"

#include "zebra/rib.h"
#include "zebra/rt.h"
#include "zebra/zserv.h"
#include "zebra/redistribute.h"
#include "zebra/debug.h"
#include "zebra/zebra_memory.h"
#include "zebra/zebra_vrf.h"
#include "zebra/zebra_mpls.h"

DEFINE_MTYPE_STATIC(ZEBRA, LSP,			"MPLS LSP object")
DEFINE_MTYPE_STATIC(ZEBRA, SLSP,		"MPLS static LSP config")
DEFINE_MTYPE_STATIC(ZEBRA, NHLFE,		"MPLS nexthop object")
DEFINE_MTYPE_STATIC(ZEBRA, SNHLFE,		"MPLS static nexthop object")
DEFINE_MTYPE_STATIC(ZEBRA, SNHLFE_IFNAME,	"MPLS static nexthop ifname")

/* Default rtm_table for all clients */
extern struct zebra_t zebrad;

/* static function declarations */
static unsigned int
label_hash (void *p);
static int
label_cmp (const void *p1, const void *p2);
static int
nhlfe_nexthop_active_ipv4 (zebra_nhlfe_t *nhlfe, struct nexthop *nexthop);
static int
nhlfe_nexthop_active_ipv6 (zebra_nhlfe_t *nhlfe, struct nexthop *nexthop);
static int
nhlfe_nexthop_active (zebra_nhlfe_t *nhlfe);
static void
lsp_select_best_nhlfe (zebra_lsp_t *lsp);
static void
lsp_uninstall_from_kernel (struct hash_backet *backet, void *ctxt);
static void
lsp_schedule (struct hash_backet *backet, void *ctxt);
static wq_item_status
lsp_process (struct work_queue *wq, void *data);
static void
lsp_processq_del (struct work_queue *wq, void *data);
static void
lsp_processq_complete (struct work_queue *wq);
static int
lsp_processq_add (zebra_lsp_t *lsp);
static void *
lsp_alloc (void *p);
static char *
nhlfe2str (zebra_nhlfe_t *nhlfe, char *buf, int size);
static int
nhlfe_nhop_match (zebra_nhlfe_t *nhlfe, enum nexthop_types_t gtype,
                  union g_addr *gate, char *ifname, ifindex_t ifindex);
static zebra_nhlfe_t *
nhlfe_find (zebra_lsp_t *lsp, enum lsp_types_t lsp_type,
            enum nexthop_types_t gtype, union g_addr *gate,
            char *ifname, ifindex_t ifindex);
static zebra_nhlfe_t *
nhlfe_add (zebra_lsp_t *lsp, enum lsp_types_t lsp_type,
           enum nexthop_types_t gtype, union g_addr *gate,
           char *ifname, ifindex_t ifindex, mpls_label_t out_label);
static int
nhlfe_del (zebra_nhlfe_t *snhlfe);
static int
static_lsp_install (struct zebra_vrf *zvrf, mpls_label_t in_label,
                    mpls_label_t out_label, enum nexthop_types_t gtype,
                    union g_addr *gate, char *ifname, ifindex_t ifindex);
static int
static_lsp_uninstall (struct zebra_vrf *zvrf, mpls_label_t in_label,
                      enum nexthop_types_t gtype, union g_addr *gate,
                      char *ifname, ifindex_t ifindex);
static int
static_lsp_uninstall_all (struct zebra_vrf *zvrf, mpls_label_t in_label);
static void
nhlfe_print (zebra_nhlfe_t *nhlfe, struct vty *vty);
static void
lsp_print (zebra_lsp_t *lsp, void *ctxt);
static void
lsp_print_hash (struct hash_backet *backet, void *ctxt);
static void
lsp_config_write (struct hash_backet *backet, void *ctxt);
static void *
slsp_alloc (void *p);
static int
snhlfe_match (zebra_snhlfe_t *snhlfe, enum nexthop_types_t gtype,
              union g_addr *gate, char *ifname, ifindex_t ifindex);
static zebra_snhlfe_t *
snhlfe_find (zebra_slsp_t *slsp, enum nexthop_types_t gtype,
             union g_addr *gate, char *ifname, ifindex_t ifindex);
static zebra_snhlfe_t *
snhlfe_add (zebra_slsp_t *slsp, enum nexthop_types_t gtype,
            union g_addr *gate, char *ifname, ifindex_t ifindex,
            mpls_label_t out_label);
static int
snhlfe_del (zebra_snhlfe_t *snhlfe);
static int
snhlfe_del_all (zebra_slsp_t *slsp);
static char *
snhlfe2str (zebra_snhlfe_t *snhlfe, char *buf, int size);
static void
mpls_processq_init (struct zebra_t *zebra);




/* Static functions */

/*
 * Hash function for label.
 */
static unsigned int
label_hash (void *p)
{
  const zebra_ile_t *ile = p;

  return (jhash_1word(ile->in_label, 0));
}

/*
 * Compare 2 LSP hash entries based on in-label.
 */
static int
label_cmp (const void *p1, const void *p2)
{
  const zebra_ile_t *ile1 = p1;
  const zebra_ile_t *ile2 = p2;

  return (ile1->in_label == ile2->in_label);
}

/*
 * Check if an IPv4 nexthop for a NHLFE is active. Update nexthop based on
 * the passed flag.
 * NOTE: Looking only for connected routes right now.
 */
static int
nhlfe_nexthop_active_ipv4 (zebra_nhlfe_t *nhlfe, struct nexthop *nexthop)
{
  struct route_table *table;
  struct prefix_ipv4 p;
  struct route_node *rn;
  struct rib *match;

  table = zebra_vrf_table (AFI_IP, SAFI_UNICAST, VRF_DEFAULT);
  if (!table)
    return 0;

  /* Lookup nexthop in IPv4 routing table. */
  memset (&p, 0, sizeof (struct prefix_ipv4));
  p.family = AF_INET;
  p.prefixlen = IPV4_MAX_PREFIXLEN;
  p.prefix = nexthop->gate.ipv4;

  rn = route_node_match (table, (struct prefix *) &p);
  if (!rn)
    return 0;

  route_unlock_node (rn);

  /* Locate a valid connected route. */
  RNODE_FOREACH_RIB (rn, match)
    {
      if ((match->type == ZEBRA_ROUTE_CONNECT) &&
          !CHECK_FLAG (match->status, RIB_ENTRY_REMOVED) &&
          CHECK_FLAG (match->flags, ZEBRA_FLAG_SELECTED))
        break;
    }

  if (!match || !match->nexthop)
    return 0;

  nexthop->ifindex = match->nexthop->ifindex;
  return 1;
}


/*
 * Check if an IPv6 nexthop for a NHLFE is active. Update nexthop based on
 * the passed flag.
 * NOTE: Looking only for connected routes right now.
 */
static int
nhlfe_nexthop_active_ipv6 (zebra_nhlfe_t *nhlfe, struct nexthop *nexthop)
{
  struct route_table *table;
  struct prefix_ipv6 p;
  struct route_node *rn;
  struct rib *match;

  table = zebra_vrf_table (AFI_IP6, SAFI_UNICAST, VRF_DEFAULT);
  if (!table)
    return 0;

  /* Lookup nexthop in IPv6 routing table. */
  memset (&p, 0, sizeof (struct prefix_ipv6));
  p.family = AF_INET6;
  p.prefixlen = IPV6_MAX_PREFIXLEN;
  p.prefix = nexthop->gate.ipv6;

  rn = route_node_match (table, (struct prefix *) &p);
  if (!rn)
    return 0;

  route_unlock_node (rn);

  /* Locate a valid connected route. */
  RNODE_FOREACH_RIB (rn, match)
    {
      if ((match->type == ZEBRA_ROUTE_CONNECT) &&
          !CHECK_FLAG (match->status, RIB_ENTRY_REMOVED) &&
          CHECK_FLAG (match->flags, ZEBRA_FLAG_SELECTED))
        break;
    }

  if (!match || !match->nexthop)
    return 0;

  nexthop->ifindex = match->nexthop->ifindex;
  return 1;
}


/*
 * Check the nexthop reachability for a NHLFE and return if valid (reachable)
 * or not.
 * NOTE: Each NHLFE points to only 1 nexthop.
 */
static int
nhlfe_nexthop_active (zebra_nhlfe_t *nhlfe)
{
  struct nexthop *nexthop;
  struct interface *ifp;

  nexthop = nhlfe->nexthop;
  if (!nexthop) // unexpected
    return 0;

  /* Check on nexthop based on type. */
  switch (nexthop->type)
    {
      case NEXTHOP_TYPE_IPV4:
        if (nhlfe_nexthop_active_ipv4 (nhlfe, nexthop))
          SET_FLAG (nexthop->flags, NEXTHOP_FLAG_ACTIVE);
        else
          UNSET_FLAG (nexthop->flags, NEXTHOP_FLAG_ACTIVE);
        break;

      case NEXTHOP_TYPE_IPV6:
        if (nhlfe_nexthop_active_ipv6 (nhlfe, nexthop))
          SET_FLAG (nexthop->flags, NEXTHOP_FLAG_ACTIVE);
        else
          UNSET_FLAG (nexthop->flags, NEXTHOP_FLAG_ACTIVE);
        break;

      case NEXTHOP_TYPE_IPV6_IFINDEX:
        if (IN6_IS_ADDR_LINKLOCAL (&nexthop->gate.ipv6))
          {
            ifp = if_lookup_by_index (nexthop->ifindex);
            if (ifp && if_is_operative(ifp))
              SET_FLAG (nexthop->flags, NEXTHOP_FLAG_ACTIVE);
            else
              UNSET_FLAG (nexthop->flags, NEXTHOP_FLAG_ACTIVE);
          }
        else
          {
            if (nhlfe_nexthop_active_ipv6 (nhlfe, nexthop))
              SET_FLAG (nexthop->flags, NEXTHOP_FLAG_ACTIVE);
            else
              UNSET_FLAG (nexthop->flags, NEXTHOP_FLAG_ACTIVE);
          }
        break;

    default:
      break;
    }

  return CHECK_FLAG (nexthop->flags, NEXTHOP_FLAG_ACTIVE);
}

/*
 * Walk through NHLFEs for a LSP forwarding entry, verify nexthop
 * reachability and select the best. Multipath entries are also
 * marked. This is invoked when an LSP scheduled for processing (due
 * to some change) is examined.
 */
static void
lsp_select_best_nhlfe (zebra_lsp_t *lsp)
{
  zebra_nhlfe_t *nhlfe;
  zebra_nhlfe_t *best;
  struct nexthop *nexthop;
  int changed = 0;

  if (!lsp)
    return;

  best = NULL;
  lsp->num_ecmp = 0;
  UNSET_FLAG (lsp->flags, LSP_FLAG_CHANGED);

  /*
   * First compute the best path, after checking nexthop status. We are only
   * concerned with non-deleted NHLFEs.
   */
  for (nhlfe = lsp->nhlfe_list; nhlfe; nhlfe = nhlfe->next)
    {
      /* Clear selection flags. */
      UNSET_FLAG (nhlfe->flags,
                  (NHLFE_FLAG_SELECTED | NHLFE_FLAG_MULTIPATH));

      if (!CHECK_FLAG (nhlfe->flags, NHLFE_FLAG_DELETED) &&
          nhlfe_nexthop_active (nhlfe))
        {
          if (!best || (nhlfe->distance < best->distance))
            best = nhlfe;
        }
    }

  lsp->best_nhlfe = best;
  if (!lsp->best_nhlfe)
    return;

  /* Mark best NHLFE as selected. */
  SET_FLAG (lsp->best_nhlfe->flags, NHLFE_FLAG_SELECTED);

  /*
   * If best path exists, see if there is ECMP. While doing this, note if a
   * new (uninstalled) NHLFE has been selected, an installed entry that is
   * still selected has a change or an installed entry is to be removed.
   */
  for (nhlfe = lsp->nhlfe_list; nhlfe; nhlfe = nhlfe->next)
    {
      int nh_chg, nh_sel, nh_inst;

      nexthop = nhlfe->nexthop;
      if (!nexthop) // unexpected
        continue;

      if (!CHECK_FLAG (nhlfe->flags, NHLFE_FLAG_DELETED) &&
          CHECK_FLAG (nexthop->flags, NEXTHOP_FLAG_ACTIVE) &&
          (nhlfe->distance == lsp->best_nhlfe->distance))
        {
          SET_FLAG (nhlfe->flags, NHLFE_FLAG_SELECTED);
          SET_FLAG (nhlfe->flags, NHLFE_FLAG_MULTIPATH);
          lsp->num_ecmp++;
        }

      if (CHECK_FLAG (lsp->flags, LSP_FLAG_INSTALLED) &&
          !changed)
        {
          nh_chg = CHECK_FLAG (nhlfe->flags, NHLFE_FLAG_CHANGED);
          nh_sel = CHECK_FLAG (nhlfe->flags, NHLFE_FLAG_SELECTED);
          nh_inst = CHECK_FLAG (nhlfe->flags, NHLFE_FLAG_INSTALLED);

          if ((nh_sel && !nh_inst) ||
              (nh_sel && nh_inst && nh_chg) ||
              (nh_inst && !nh_sel))
            changed = 1;
        }

      /* We have finished examining, clear changed flag. */
      UNSET_FLAG (nhlfe->flags, NHLFE_FLAG_CHANGED);
    }

  if (changed)
    SET_FLAG (lsp->flags, LSP_FLAG_CHANGED);
}

/*
 * Delete LSP forwarding entry from kernel, if installed. Called upon
 * process exit.
 */
static void
lsp_uninstall_from_kernel (struct hash_backet *backet, void *ctxt)
{
  zebra_lsp_t *lsp;

  lsp = (zebra_lsp_t *) backet->data;
  if (CHECK_FLAG(lsp->flags, LSP_FLAG_INSTALLED))
    kernel_del_lsp (lsp);
}

/*
 * Schedule LSP forwarding entry for processing. Called upon changes
 * that may impact LSPs such as nexthop / connected route changes.
 */
static void
lsp_schedule (struct hash_backet *backet, void *ctxt)
{
  zebra_lsp_t *lsp;

  lsp = (zebra_lsp_t *) backet->data;
  lsp_processq_add (lsp);
}

/*
 * Process a LSP entry that is in the queue. Recalculate best NHLFE and
 * any multipaths and update or delete from the kernel, as needed.
 */
static wq_item_status
lsp_process (struct work_queue *wq, void *data)
{
  zebra_lsp_t *lsp;
  zebra_nhlfe_t *oldbest, *newbest;
  char buf[BUFSIZ], buf2[BUFSIZ];

  lsp = (zebra_lsp_t *)data;
  if (!lsp) // unexpected
    return WQ_SUCCESS;

  oldbest = lsp->best_nhlfe;

  /* Select best NHLFE(s) */
  lsp_select_best_nhlfe (lsp);

  newbest = lsp->best_nhlfe;

  if (IS_ZEBRA_DEBUG_MPLS)
    {
      if (oldbest)
        nhlfe2str (oldbest, buf, BUFSIZ);
      if (newbest)
        nhlfe2str (newbest, buf2, BUFSIZ);
      zlog_debug ("Process LSP in-label %u oldbest %s newbest %s "
                  "flags 0x%x ecmp# %d",
                  lsp->ile.in_label, oldbest ? buf : "NULL",
                  newbest ? buf2 : "NULL", lsp->flags, lsp->num_ecmp);
    }

  if (!CHECK_FLAG (lsp->flags, LSP_FLAG_INSTALLED))
    {
      /* Not already installed */
      if (newbest)
        kernel_add_lsp (lsp);
    }
  else
    {
      /* Installed, may need an update and/or delete. */
      if (!newbest)
        kernel_del_lsp (lsp);
      else if (CHECK_FLAG (lsp->flags, LSP_FLAG_CHANGED))
        kernel_upd_lsp (lsp);
    }

  return WQ_SUCCESS;
}


/*
 * Callback upon processing completion of a LSP forwarding entry.
 */
static void
lsp_processq_del (struct work_queue *wq, void *data)
{
  struct zebra_vrf *zvrf;
  zebra_lsp_t *lsp;
  struct hash *lsp_table;
  zebra_nhlfe_t *nhlfe, *nhlfe_next;

  zvrf = vrf_info_lookup(VRF_DEFAULT);
  assert (zvrf);

  lsp_table = zvrf->lsp_table;
  if (!lsp_table) // unexpected
    return;

  lsp = (zebra_lsp_t *)data;
  if (!lsp) // unexpected
    return;

  /* Clear flag, remove any NHLFEs marked for deletion. If no NHLFEs exist,
   * delete LSP entry also.
   */
  UNSET_FLAG (lsp->flags, LSP_FLAG_SCHEDULED);

  for (nhlfe = lsp->nhlfe_list; nhlfe; nhlfe = nhlfe_next)
    {
      nhlfe_next = nhlfe->next;
      if (CHECK_FLAG(nhlfe->flags, NHLFE_FLAG_DELETED))
        nhlfe_del (nhlfe);
    }

  if (!lsp->nhlfe_list)
    {
      if (IS_ZEBRA_DEBUG_MPLS)
        zlog_debug ("Free LSP in-label %u flags 0x%x",
                    lsp->ile.in_label, lsp->flags);

      lsp = hash_release(lsp_table, &lsp->ile);
      if (lsp)
        XFREE(MTYPE_LSP, lsp);
    }
}

/*
 * Callback upon finishing the processing of all scheduled
 * LSP forwarding entries.
 */
static void
lsp_processq_complete (struct work_queue *wq)
{
  /* Nothing to do for now. */
}

/*
 * Add LSP forwarding entry to queue for subsequent processing.
 */
static int
lsp_processq_add (zebra_lsp_t *lsp)
{
  /* If already scheduled, exit. */
  if (CHECK_FLAG (lsp->flags, LSP_FLAG_SCHEDULED))
    return 0;

  work_queue_add (zebrad.lsp_process_q, lsp);
  SET_FLAG (lsp->flags, LSP_FLAG_SCHEDULED);
  return 0;
}

/*
 * Callback to allocate LSP forwarding table entry.
 */
static void *
lsp_alloc (void *p)
{
  const zebra_ile_t *ile = p;
  zebra_lsp_t *lsp;

  lsp = XCALLOC (MTYPE_LSP, sizeof(zebra_lsp_t));
  lsp->ile = *ile;

  if (IS_ZEBRA_DEBUG_MPLS)
    zlog_debug ("Alloc LSP in-label %u", lsp->ile.in_label);

  return ((void *)lsp);
}

/*
 * Create printable string for NHLFE entry.
 */
static char *
nhlfe2str (zebra_nhlfe_t *nhlfe, char *buf, int size)
{
  struct nexthop *nexthop;

  buf[0] = '\0';
  nexthop = nhlfe->nexthop;
  switch (nexthop->type)
    {
      case NEXTHOP_TYPE_IPV4:
        inet_ntop (AF_INET, &nexthop->gate.ipv4, buf, size);
        break;
      case NEXTHOP_TYPE_IPV6:
        inet_ntop (AF_INET6, &nexthop->gate.ipv6, buf, size);
        break;
      default:
        break;
    }

  return buf;
}

/*
 * Check if NHLFE matches with search info passed.
 */
static int
nhlfe_nhop_match (zebra_nhlfe_t *nhlfe, enum nexthop_types_t gtype,
                  union g_addr *gate, char *ifname, ifindex_t ifindex)
{
  struct nexthop *nhop;
  int cmp = 1;

  nhop = nhlfe->nexthop;
  if (!nhop)
    return 1;

  if (nhop->type != gtype)
    return 1;

  switch (nhop->type)
    {
    case NEXTHOP_TYPE_IPV4:
      cmp = memcmp(&(nhop->gate.ipv4), &(gate->ipv4),
                   sizeof(struct in_addr));
      break;
    case NEXTHOP_TYPE_IPV6:
    case NEXTHOP_TYPE_IPV6_IFINDEX:
      cmp = memcmp(&(nhop->gate.ipv6), &(gate->ipv6),
		   sizeof(struct in6_addr));
      if (!cmp && nhop->type == NEXTHOP_TYPE_IPV6_IFINDEX)
        cmp = !(nhop->ifindex == ifindex);
      break;
    default:
      break;
    }

  return cmp;
}


/*
 * Locate NHLFE that matches with passed info.
 */
static zebra_nhlfe_t *
nhlfe_find (zebra_lsp_t *lsp, enum lsp_types_t lsp_type,
            enum nexthop_types_t gtype, union g_addr *gate,
            char *ifname, ifindex_t ifindex)
{
  zebra_nhlfe_t *nhlfe;

  if (!lsp)
    return NULL;

  for (nhlfe = lsp->nhlfe_list; nhlfe; nhlfe = nhlfe->next)
    {
      if (nhlfe->type != lsp_type)
        continue;
      if (!nhlfe_nhop_match (nhlfe, gtype, gate, ifname, ifindex))
        break;
    }

  return nhlfe;
}

/*
 * Add NHLFE. Base entry must have been created and duplicate
 * check done.
 */
static zebra_nhlfe_t *
nhlfe_add (zebra_lsp_t *lsp, enum lsp_types_t lsp_type,
           enum nexthop_types_t gtype, union g_addr *gate,
           char *ifname, ifindex_t ifindex, mpls_label_t out_label)
{
  zebra_nhlfe_t *nhlfe;
  struct nexthop *nexthop;

  if (!lsp)
    return NULL;

  nhlfe = XCALLOC(MTYPE_NHLFE, sizeof(zebra_nhlfe_t));
  if (!nhlfe)
    return NULL;

  nhlfe->lsp = lsp;
  nhlfe->type = lsp_type;
  nhlfe->distance = lsp_distance (lsp_type);

  nexthop = nexthop_new();
  if (!nexthop)
    {
      XFREE (MTYPE_NHLFE, nhlfe);
      return NULL;
    }
  nexthop_add_labels (nexthop, 1, &out_label);

  nexthop->type = gtype;
  switch (nexthop->type)
    {
    case NEXTHOP_TYPE_IPV4:
      nexthop->gate.ipv4 = gate->ipv4;
      break;
    case NEXTHOP_TYPE_IPV6:
    case NEXTHOP_TYPE_IPV6_IFINDEX:
      nexthop->gate.ipv6 = gate->ipv6;
      if (ifindex)
        nexthop->ifindex = ifindex;
      break;
    default:
      nexthop_free(nexthop);
      XFREE (MTYPE_NHLFE, nhlfe);
      return NULL;
      break;
    }

  nhlfe->nexthop = nexthop;
  if (lsp->nhlfe_list)
    lsp->nhlfe_list->prev = nhlfe;
  nhlfe->next = lsp->nhlfe_list;
  lsp->nhlfe_list = nhlfe;

  return nhlfe;
}

/*
 * Delete NHLFE. Entry must be present on list.
 */
static int
nhlfe_del (zebra_nhlfe_t *nhlfe)
{
  zebra_lsp_t *lsp;

  if (!nhlfe)
    return -1;

  lsp = nhlfe->lsp;
  if (!lsp)
    return -1;

  /* Free nexthop. */
  if (nhlfe->nexthop)
    nexthop_free(nhlfe->nexthop);

  /* Unlink from LSP */
  if (nhlfe->next)
    nhlfe->next->prev = nhlfe->prev;
  if (nhlfe->prev)
    nhlfe->prev->next = nhlfe->next;
  else
    lsp->nhlfe_list = nhlfe->next;

  XFREE (MTYPE_NHLFE, nhlfe);

  return 0;
}


/*
 * Install/update a static NHLFE for an LSP in the forwarding table. This may
 * be a new LSP entry or a new NHLFE for an existing in-label or an update of
 * the out-label for an existing NHLFE (update case).
 */
static int
static_lsp_install (struct zebra_vrf *zvrf, mpls_label_t in_label,
                    mpls_label_t out_label, enum nexthop_types_t gtype,
                    union g_addr *gate, char *ifname, ifindex_t ifindex)
{
  struct hash *lsp_table;
  zebra_ile_t tmp_ile;
  zebra_lsp_t *lsp;
  zebra_nhlfe_t *nhlfe;
  char buf[BUFSIZ];

  /* Lookup table. */
  lsp_table = zvrf->lsp_table;
  if (!lsp_table)
    return -1;

  /* If entry is present, exit. */
  tmp_ile.in_label = in_label;
  lsp = hash_get (lsp_table, &tmp_ile, lsp_alloc);
  if (!lsp)
    return -1;
  nhlfe = nhlfe_find (lsp, ZEBRA_LSP_STATIC, gtype, gate, ifname, ifindex);
  if (nhlfe)
    {
      struct nexthop *nh = nhlfe->nexthop;

      assert (nh);
      assert (nh->nh_label);

      /* Clear deleted flag (in case it was set) */
      UNSET_FLAG (nhlfe->flags, NHLFE_FLAG_DELETED);
      if (nh->nh_label->label[0] == out_label)
        /* No change */
        return 0;

      if (IS_ZEBRA_DEBUG_MPLS)
        {
          nhlfe2str (nhlfe, buf, BUFSIZ);
          zlog_debug ("LSP in-label %u type %d nexthop %s "
                      "out-label changed to %u (old %u)",
                      in_label, ZEBRA_LSP_STATIC, buf,
                      out_label, nh->nh_label->label[0]);
        }

      /* Update out label, trigger processing. */
      nh->nh_label->label[0] = out_label;
    }
  else
    {
      /* Add LSP entry to this nexthop */
      nhlfe = nhlfe_add (lsp, ZEBRA_LSP_STATIC, gtype, gate,
                         ifname, ifindex, out_label);
      if (!nhlfe)
        return -1;

      if (IS_ZEBRA_DEBUG_MPLS)
        {
          nhlfe2str (nhlfe, buf, BUFSIZ);
          zlog_debug ("Add LSP in-label %u type %d nexthop %s "
                      "out-label %u",
                      in_label, ZEBRA_LSP_STATIC, buf,
                      out_label);
        }

      lsp->addr_family = NHLFE_FAMILY (nhlfe);
    }

  /* Mark NHLFE, queue LSP for processing. */
  SET_FLAG(nhlfe->flags, NHLFE_FLAG_CHANGED);
  if (lsp_processq_add (lsp))
    return -1;

  return 0;
}

/*
 * Uninstall a particular static NHLFE in the forwarding table. If this is
 * the only NHLFE, the entire LSP forwarding entry has to be deleted.
 */
static int
static_lsp_uninstall (struct zebra_vrf *zvrf, mpls_label_t in_label,
                      enum nexthop_types_t gtype, union g_addr *gate,
                      char *ifname, ifindex_t ifindex)
{
  struct hash *lsp_table;
  zebra_ile_t tmp_ile;
  zebra_lsp_t *lsp;
  zebra_nhlfe_t *nhlfe;
  char buf[BUFSIZ];

  /* Lookup table. */
  lsp_table = zvrf->lsp_table;
  if (!lsp_table)
    return -1;

  /* If entry is not present, exit. */
  tmp_ile.in_label = in_label;
  lsp = hash_lookup (lsp_table, &tmp_ile);
  if (!lsp)
    return 0;
  nhlfe = nhlfe_find (lsp, ZEBRA_LSP_STATIC, gtype, gate, ifname, ifindex);
  if (!nhlfe)
    return 0;

  if (IS_ZEBRA_DEBUG_MPLS)
    {
      nhlfe2str (nhlfe, buf, BUFSIZ);
      zlog_debug ("Del LSP in-label %u type %d nexthop %s flags 0x%x",
                  in_label, ZEBRA_LSP_STATIC, buf, nhlfe->flags);
    }

  /* Mark NHLFE for delete or directly delete, as appropriate. */
  if (CHECK_FLAG(nhlfe->flags, NHLFE_FLAG_INSTALLED))
    {
      UNSET_FLAG (nhlfe->flags, NHLFE_FLAG_CHANGED);
      SET_FLAG (nhlfe->flags, NHLFE_FLAG_DELETED);
      if (lsp_processq_add (lsp))
        return -1;
    }
  else
    {
      nhlfe_del (nhlfe);

      /* Free LSP entry if no other NHLFEs and not scheduled. */
      if (!lsp->nhlfe_list &&
          !CHECK_FLAG (lsp->flags, LSP_FLAG_SCHEDULED))
        {
          if (IS_ZEBRA_DEBUG_MPLS)
            zlog_debug ("Free LSP in-label %u flags 0x%x",
                        lsp->ile.in_label, lsp->flags);

          lsp = hash_release(lsp_table, &lsp->ile);
          if (lsp)
            XFREE(MTYPE_LSP, lsp);
        }
    }
  return 0;
}

/*
 * Uninstall all static NHLFEs for a particular LSP forwarding entry.
 * If no other NHLFEs exist, the entry would be deleted.
 */
static int
static_lsp_uninstall_all (struct zebra_vrf *zvrf, mpls_label_t in_label)
{
  struct hash *lsp_table;
  zebra_ile_t tmp_ile;
  zebra_lsp_t *lsp;
  zebra_nhlfe_t *nhlfe, *nhlfe_next;
  int schedule_lsp = 0;
  char buf[BUFSIZ];

  /* Lookup table. */
  lsp_table = zvrf->lsp_table;
  if (!lsp_table)
    return -1;

  /* If entry is not present, exit. */
  tmp_ile.in_label = in_label;
  lsp = hash_lookup (lsp_table, &tmp_ile);
  if (!lsp || !lsp->nhlfe_list)
    return 0;

  /* Mark NHLFEs for delete or directly delete, as appropriate. */
  for (nhlfe = lsp->nhlfe_list; nhlfe; nhlfe = nhlfe_next)
    {
      nhlfe_next = nhlfe->next;

      /* Skip non-static NHLFEs */
      if (nhlfe->type != ZEBRA_LSP_STATIC)
        continue;

      if (IS_ZEBRA_DEBUG_MPLS)
        {
          nhlfe2str (nhlfe, buf, BUFSIZ);
          zlog_debug ("Del LSP in-label %u type %d nexthop %s flags 0x%x",
                      in_label, ZEBRA_LSP_STATIC, buf, nhlfe->flags);
        }

      if (CHECK_FLAG(nhlfe->flags, NHLFE_FLAG_INSTALLED))
        {
          UNSET_FLAG (nhlfe->flags, NHLFE_FLAG_CHANGED);
          SET_FLAG (nhlfe->flags, NHLFE_FLAG_DELETED);
          schedule_lsp = 1;
        }
      else
        {
          nhlfe_del (nhlfe);
        }
    }

  /* Queue LSP for processing, if needed, else delete. */
  if (schedule_lsp)
    {
      if (lsp_processq_add (lsp))
        return -1;
    }
  else if (!lsp->nhlfe_list &&
           !CHECK_FLAG (lsp->flags, LSP_FLAG_SCHEDULED))
    {
      if (IS_ZEBRA_DEBUG_MPLS)
        zlog_debug ("Free LSP in-label %u flags 0x%x",
                    lsp->ile.in_label, lsp->flags);

      lsp = hash_release(lsp_table, &lsp->ile);
      if (lsp)
        XFREE(MTYPE_LSP, lsp);
    }

  return 0;
}

/*
 * Print the NHLFE for a LSP forwarding entry.
 */
static void
nhlfe_print (zebra_nhlfe_t *nhlfe, struct vty *vty)
{
  struct nexthop *nexthop;
  char buf[BUFSIZ];

  nexthop = nhlfe->nexthop;
  if (!nexthop || !nexthop->nh_label) // unexpected
    return;

  vty_out(vty, " type: %s remote label: %s distance: %d%s",
          nhlfe_type2str(nhlfe->type),
          label2str(nexthop->nh_label->label[0], buf, BUFSIZ),
          nhlfe->distance, VTY_NEWLINE);
  switch (nexthop->type)
    {
    case NEXTHOP_TYPE_IPV4:
      vty_out (vty, "  via %s", inet_ntoa (nexthop->gate.ipv4));
      break;
    case NEXTHOP_TYPE_IPV6:
    case NEXTHOP_TYPE_IPV6_IFINDEX:
      vty_out (vty, "  via %s",
	       inet_ntop (AF_INET6, &nexthop->gate.ipv6, buf, BUFSIZ));
      if (nexthop->ifindex)
        vty_out (vty, " dev %s", ifindex2ifname (nexthop->ifindex));
      break;
    default:
      break;
    }
  vty_out(vty, "%s", CHECK_FLAG (nhlfe->flags, NHLFE_FLAG_INSTALLED) ?
          " (installed)" : "");
  vty_out(vty, "%s", VTY_NEWLINE);
}

/*
 * Print an LSP forwarding entry.
 */
static void
lsp_print (zebra_lsp_t *lsp, void *ctxt)
{
  zebra_nhlfe_t *nhlfe;
  struct vty *vty;

  vty = (struct vty *) ctxt;

  vty_out(vty, "Local label: %u%s%s",
          lsp->ile.in_label,
          CHECK_FLAG (lsp->flags, LSP_FLAG_INSTALLED) ? " (installed)" : "",
          VTY_NEWLINE);

  for (nhlfe = lsp->nhlfe_list; nhlfe; nhlfe = nhlfe->next)
    nhlfe_print (nhlfe, vty);
}

/*
 * Print an LSP forwarding hash entry.
 */
static void
lsp_print_hash (struct hash_backet *backet, void *ctxt)
{
  zebra_lsp_t *lsp;

  lsp = (zebra_lsp_t *) backet->data;
  if (!lsp)
    return;

  lsp_print (lsp, ctxt);
}

/*
 * Write out static LSP configuration.
 */
static void
lsp_config_write (struct hash_backet *backet, void *ctxt)
{
  zebra_slsp_t *slsp;
  zebra_snhlfe_t *snhlfe;
  struct vty *vty = (struct vty *) ctxt;
  char buf[INET6_ADDRSTRLEN];

  slsp = (zebra_slsp_t *) backet->data;
  if (!slsp)
    return;

  for (snhlfe = slsp->snhlfe_list; snhlfe; snhlfe = snhlfe->next)
    {
      char lstr[30];
      snhlfe2str (snhlfe, buf, BUFSIZ);
      vty_out (vty, "mpls lsp %u %s %s%s",
               slsp->ile.in_label, buf,
               label2str(snhlfe->out_label, lstr, 30), VTY_NEWLINE);
    }
}

/*
 * Callback to allocate static LSP.
 */
static void *
slsp_alloc (void *p)
{
  const zebra_ile_t *ile = p;
  zebra_slsp_t *slsp;

  slsp = XCALLOC (MTYPE_SLSP, sizeof(zebra_slsp_t));
  slsp->ile = *ile;
  return ((void *)slsp);
}

/*
 * Check if static NHLFE matches with search info passed.
 */
static int
snhlfe_match (zebra_snhlfe_t *snhlfe, enum nexthop_types_t gtype,
              union g_addr *gate, char *ifname, ifindex_t ifindex)
{
  int cmp = 1;

  if (snhlfe->gtype != gtype)
    return 1;

  switch (snhlfe->gtype)
    {
    case NEXTHOP_TYPE_IPV4:
      cmp = memcmp(&(snhlfe->gate.ipv4), &(gate->ipv4),
		   sizeof(struct in_addr));
      break;
    case NEXTHOP_TYPE_IPV6:
    case NEXTHOP_TYPE_IPV6_IFINDEX:
      cmp = memcmp(&(snhlfe->gate.ipv6), &(gate->ipv6),
		   sizeof(struct in6_addr));
      if (!cmp && snhlfe->gtype == NEXTHOP_TYPE_IPV6_IFINDEX)
        cmp = !(snhlfe->ifindex == ifindex);
      break;
    default:
      break;
    }

  return cmp;
}

/*
 * Locate static NHLFE that matches with passed info.
 */
static zebra_snhlfe_t *
snhlfe_find (zebra_slsp_t *slsp, enum nexthop_types_t gtype,
             union g_addr *gate, char *ifname, ifindex_t ifindex)
{
  zebra_snhlfe_t *snhlfe;

  if (!slsp)
    return NULL;

  for (snhlfe = slsp->snhlfe_list; snhlfe; snhlfe = snhlfe->next)
    {
      if (!snhlfe_match (snhlfe, gtype, gate, ifname, ifindex))
        break;
    }

  return snhlfe;
}


/*
 * Add static NHLFE. Base LSP config entry must have been created
 * and duplicate check done.
 */
static zebra_snhlfe_t *
snhlfe_add (zebra_slsp_t *slsp, enum nexthop_types_t gtype,
            union g_addr *gate, char *ifname, ifindex_t ifindex,
            mpls_label_t out_label)
{
  zebra_snhlfe_t *snhlfe;

  if (!slsp)
    return NULL;

  snhlfe = XCALLOC(MTYPE_SNHLFE, sizeof(zebra_snhlfe_t));
  snhlfe->slsp = slsp;
  snhlfe->out_label = out_label;
  snhlfe->gtype = gtype;
  switch (gtype)
    {
    case NEXTHOP_TYPE_IPV4:
      snhlfe->gate.ipv4 = gate->ipv4;
      break;
    case NEXTHOP_TYPE_IPV6:
    case NEXTHOP_TYPE_IPV6_IFINDEX:
      snhlfe->gate.ipv6 = gate->ipv6;
      if (ifindex)
        snhlfe->ifindex = ifindex;
      break;
    default:
      XFREE (MTYPE_SNHLFE, snhlfe);
      return NULL;
    }

  if (slsp->snhlfe_list)
    slsp->snhlfe_list->prev = snhlfe;
  snhlfe->next = slsp->snhlfe_list;
  slsp->snhlfe_list = snhlfe;

  return snhlfe;
}

/*
 * Delete static NHLFE. Entry must be present on list.
 */
static int
snhlfe_del (zebra_snhlfe_t *snhlfe)
{
  zebra_slsp_t *slsp;

  if (!snhlfe)
    return -1;

  slsp = snhlfe->slsp;
  if (!slsp)
    return -1;

  if (snhlfe->next)
    snhlfe->next->prev = snhlfe->prev;
  if (snhlfe->prev)
    snhlfe->prev->next = snhlfe->next;
  else
    slsp->snhlfe_list = snhlfe->next;

  snhlfe->prev = snhlfe->next = NULL;
  if (snhlfe->ifname)
    XFREE (MTYPE_SNHLFE_IFNAME, snhlfe->ifname);
  XFREE (MTYPE_SNHLFE, snhlfe);

  return 0;
}

/*
 * Delete all static NHLFE entries for this LSP (in label).
 */
static int
snhlfe_del_all (zebra_slsp_t *slsp)
{
  zebra_snhlfe_t *snhlfe, *snhlfe_next;

  if (!slsp)
    return -1;

  for (snhlfe = slsp->snhlfe_list; snhlfe; snhlfe = snhlfe_next)
    {
      snhlfe_next = snhlfe->next;
      snhlfe_del (snhlfe);
    }

  return 0;
}

/*
 * Create printable string for NHLFE configuration.
 */
static char *
snhlfe2str (zebra_snhlfe_t *snhlfe, char *buf, int size)
{
  buf[0] = '\0';
  switch (snhlfe->gtype)
    {
      case NEXTHOP_TYPE_IPV4:
        inet_ntop (AF_INET, &snhlfe->gate.ipv4, buf, size);
        break;
      case NEXTHOP_TYPE_IPV6:
      case NEXTHOP_TYPE_IPV6_IFINDEX:
        inet_ntop (AF_INET6, &snhlfe->gate.ipv6, buf, size);
        if (snhlfe->ifindex)
          strcat (buf, ifindex2ifname (snhlfe->ifindex));
        break;
      default:
        break;
    }

  return buf;
}

/*
 * Initialize work queue for processing changed LSPs.
 */
static void
mpls_processq_init (struct zebra_t *zebra)
{
  zebra->lsp_process_q = work_queue_new (zebra->master, "LSP processing");
  if (!zebra->lsp_process_q)
    {
      zlog_err ("%s: could not initialise work queue!", __func__);
      return;
    }

  zebra->lsp_process_q->spec.workfunc = &lsp_process;
  zebra->lsp_process_q->spec.del_item_data = &lsp_processq_del;
  zebra->lsp_process_q->spec.errorfunc = NULL;
  zebra->lsp_process_q->spec.completion_func = &lsp_processq_complete;
  zebra->lsp_process_q->spec.max_retries = 0;
  zebra->lsp_process_q->spec.hold = 10;
}



/* Public functions */

/*
 * Check that the label values used in LSP creation are consistent. The
 * main criteria is that if there is ECMP, the label operation must still
 * be consistent - i.e., all paths either do a swap or do PHP. This is due
 * to current HW restrictions.
 */
int
zebra_mpls_lsp_label_consistent (struct zebra_vrf *zvrf, mpls_label_t in_label,
                     mpls_label_t out_label, enum nexthop_types_t gtype,
                     union g_addr *gate, char *ifname, ifindex_t ifindex)
{
  struct hash *slsp_table;
  zebra_ile_t tmp_ile;
  zebra_slsp_t *slsp;
  zebra_snhlfe_t *snhlfe;

  /* Lookup table. */
  slsp_table = zvrf->slsp_table;
  if (!slsp_table)
    return 0;

  /* If entry is not present, exit. */
  tmp_ile.in_label = in_label;
  slsp = hash_lookup (slsp_table, &tmp_ile);
  if (!slsp)
    return 1;

  snhlfe = snhlfe_find (slsp, gtype, gate, ifname, ifindex);
  if (snhlfe)
    {
      if (snhlfe->out_label == out_label)
        return 1;

      /* If not only NHLFE, cannot allow label change. */
      if (snhlfe != slsp->snhlfe_list ||
          snhlfe->next)
        return 0;
    }
  else
    {
      /* If other NHLFEs exist, label operation must match. */
      if (slsp->snhlfe_list)
        {
          int cur_op, new_op;

          cur_op = (slsp->snhlfe_list->out_label == MPLS_IMP_NULL_LABEL);
          new_op = (out_label == MPLS_IMP_NULL_LABEL);
          if (cur_op != new_op)
            return 0;
        }
    }

  /* Label values are good. */
  return 1;
}


/*
 * Add static LSP entry. This may be the first entry for this incoming label
 * or an additional nexthop; an existing entry may also have outgoing label
 * changed.
 * Note: The label operation (swap or PHP) is common for the LSP entry (all
 * NHLFEs).
 */
int
zebra_mpls_static_lsp_add (struct zebra_vrf *zvrf, mpls_label_t in_label,
                     mpls_label_t out_label, enum nexthop_types_t gtype,
                     union g_addr *gate, char *ifname, ifindex_t ifindex)
{
  struct hash *slsp_table;
  zebra_ile_t tmp_ile;
  zebra_slsp_t *slsp;
  zebra_snhlfe_t *snhlfe;
  char buf[BUFSIZ];

  /* Lookup table. */
  slsp_table = zvrf->slsp_table;
  if (!slsp_table)
    return -1;

  /* If entry is present, exit. */
  tmp_ile.in_label = in_label;
  slsp = hash_get (slsp_table, &tmp_ile, slsp_alloc);
  if (!slsp)
    return -1;
  snhlfe = snhlfe_find (slsp, gtype, gate, ifname, ifindex);
  if (snhlfe)
    {
      if (snhlfe->out_label == out_label)
        /* No change */
        return 0;

      if (IS_ZEBRA_DEBUG_MPLS)
        {
          snhlfe2str (snhlfe, buf, BUFSIZ);
          zlog_debug ("Upd static LSP in-label %u nexthop %s "
                      "out-label %u (old %u)",
                      in_label, buf, out_label, snhlfe->out_label);
        }
      snhlfe->out_label = out_label;
    }
  else
    {
      /* Add static LSP entry to this nexthop */
      snhlfe = snhlfe_add (slsp, gtype, gate, ifname, ifindex, out_label);
      if (!snhlfe)
        return -1;

      if (IS_ZEBRA_DEBUG_MPLS)
        {
          snhlfe2str (snhlfe, buf, BUFSIZ);
          zlog_debug ("Add static LSP in-label %u nexthop %s out-label %u",
                      in_label, buf, out_label);
        }
    }

  /* (Re)Install LSP in the main table. */
  if (static_lsp_install (zvrf, in_label, out_label, gtype,
                          gate, ifname, ifindex))
    return -1;

  return 0;
}

/*
 * Delete static LSP entry. This may be the delete of one particular
 * NHLFE for this incoming label or the delete of the entire entry (i.e.,
 * all NHLFEs).
 * NOTE: Delete of the only NHLFE will also end up deleting the entire
 * LSP configuration.
 */
int
zebra_mpls_static_lsp_del (struct zebra_vrf *zvrf, mpls_label_t in_label,
                           enum nexthop_types_t gtype, union g_addr *gate,
                           char *ifname, ifindex_t ifindex)
{
  struct hash *slsp_table;
  zebra_ile_t tmp_ile;
  zebra_slsp_t *slsp;
  zebra_snhlfe_t *snhlfe;

  /* Lookup table. */
  slsp_table = zvrf->slsp_table;
  if (!slsp_table)
    return -1;

  /* If entry is not present, exit. */
  tmp_ile.in_label = in_label;
  slsp = hash_lookup (slsp_table, &tmp_ile);
  if (!slsp)
    return 0;

  /* Is it delete of entire LSP or a specific NHLFE? */
  if (gtype == NEXTHOP_TYPE_BLACKHOLE)
    {
      if (IS_ZEBRA_DEBUG_MPLS)
        zlog_debug ("Del static LSP in-label %u", in_label);

      /* Uninstall entire LSP from the main table. */
      static_lsp_uninstall_all (zvrf, in_label);

      /* Delete all static NHLFEs */
      snhlfe_del_all (slsp);
    }
  else
    {
      /* Find specific NHLFE, exit if not found. */
      snhlfe = snhlfe_find (slsp, gtype, gate, ifname, ifindex);
      if (!snhlfe)
        return 0;

      if (IS_ZEBRA_DEBUG_MPLS)
        {
          char buf[BUFSIZ];
          snhlfe2str (snhlfe, buf, BUFSIZ);
          zlog_debug ("Del static LSP in-label %u nexthop %s",
                      in_label, buf);
        }

      /* Uninstall LSP from the main table. */
      static_lsp_uninstall (zvrf, in_label, gtype,
                            gate, ifname, ifindex);

      /* Delete static LSP NHLFE */
      snhlfe_del (snhlfe);
    }

  /* Remove entire static LSP entry if no NHLFE - valid in either case above. */
  if (!slsp->snhlfe_list)
    {
      slsp = hash_release(slsp_table, &tmp_ile);
      if (slsp)
        XFREE(MTYPE_SLSP, slsp);
    }

  return 0;
}

/*
 * Schedule all MPLS label forwarding entries for processing.
 * Called upon changes that may affect one or more of them such as
 * interface or nexthop state changes.
 */
void
zebra_mpls_lsp_schedule (struct zebra_vrf *zvrf)
{
  if (!zvrf)
    return;
  hash_iterate(zvrf->lsp_table, lsp_schedule, NULL);
}

/*
 * Display MPLS label forwarding table for a specific LSP
 * (VTY command handler).
 */
void
zebra_mpls_print_lsp (struct vty *vty, struct zebra_vrf *zvrf, mpls_label_t label)
{
  struct hash *lsp_table;
  zebra_lsp_t *lsp;
  zebra_ile_t tmp_ile;

  /* Lookup table. */
  lsp_table = zvrf->lsp_table;
  if (!lsp_table)
    return;

  /* If entry is not present, exit. */
  tmp_ile.in_label = label;
  lsp = hash_lookup (lsp_table, &tmp_ile);
  if (!lsp)
    return;

  lsp_print (lsp, (void *)vty);
}

/*
 * Display MPLS label forwarding table (VTY command handler).
 */
void
zebra_mpls_print_lsp_table (struct vty *vty, struct zebra_vrf *zvrf)
{
  hash_iterate(zvrf->lsp_table, lsp_print_hash, vty);
}

/*
 * Display MPLS LSP configuration of all static LSPs (VTY command handler).
 */
int
zebra_mpls_write_lsp_config (struct vty *vty, struct zebra_vrf *zvrf)
{
  hash_iterate(zvrf->slsp_table, lsp_config_write, vty);
  return (zvrf->slsp_table->count ? 1 : 0);
}

/*
 * Called upon process exiting, need to delete LSP forwarding
 * entries from the kernel.
 * NOTE: Currently supported only for default VRF.
 */
void
zebra_mpls_close_tables (struct zebra_vrf *zvrf)
{
  if (!zvrf)
    return;
  hash_iterate(zvrf->lsp_table, lsp_uninstall_from_kernel, NULL);
}

/*
 * Allocate MPLS tables for this VRF and do other initialization.
 * NOTE: Currently supported only for default VRF.
 */
void
zebra_mpls_init_tables (struct zebra_vrf *zvrf)
{
  if (!zvrf)
    return;
  zvrf->slsp_table = hash_create(label_hash, label_cmp);
  zvrf->lsp_table = hash_create(label_hash, label_cmp);
  zvrf->mpls_flags = 0;
}

/*
 * Global MPLS initialization.
 */
void
zebra_mpls_init (void)
{
  mpls_processq_init (&zebrad);
}
