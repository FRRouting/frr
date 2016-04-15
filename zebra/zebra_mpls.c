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
DEFINE_MTYPE_STATIC(ZEBRA, SNHLFE,		"MPLS static nexthop object")
DEFINE_MTYPE_STATIC(ZEBRA, SNHLFE_IFNAME,	"MPLS static nexthop ifname")

/* Default rtm_table for all clients */
extern struct zebra_t zebrad;

/* static function declarations */
static unsigned int
label_hash (void *p);
static int
label_cmp (const void *p1, const void *p2);
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
  u_char cmp = -1;

  if (snhlfe->gtype != gtype)
    return -1;

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
 * Display MPLS LSP configuration of all static LSPs (VTY command handler).
 */
int
zebra_mpls_write_lsp_config (struct vty *vty, struct zebra_vrf *zvrf)
{
  hash_iterate(zvrf->slsp_table, lsp_config_write, vty);
  return (zvrf->slsp_table->count ? 1 : 0);
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
}

/*
 * Global MPLS initialization.
 */
void
zebra_mpls_init (void)
{
  /* Filler for subsequent use. */
}
