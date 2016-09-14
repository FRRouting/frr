/*
 * Zebra MPLS Data structures and definitions
 * Copyright (C) 2015 Cumulus Networks, Inc.
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

#ifndef _ZEBRA_MPLS_H
#define _ZEBRA_MPLS_H

#include "prefix.h"
#include "table.h"
#include "queue.h"
#include "hash.h"
#include "jhash.h"
#include "nexthop.h"
#include "vty.h"
#include "memory.h"
#include "mpls.h"
#include "zebra/zserv.h"
#include "zebra/zebra_vrf.h"


/* Definitions and macros. */

#define MPLS_MAX_LABELS 2  /* Maximum # labels that can be pushed. */

#define NHLFE_FAMILY(nhlfe)                        \
  (((nhlfe)->nexthop->type == NEXTHOP_TYPE_IPV6 || \
    (nhlfe)->nexthop->type == NEXTHOP_TYPE_IPV6_IFINDEX) ? AF_INET6 : AF_INET)


/* Typedefs */

typedef struct zebra_ile_t_ zebra_ile_t;
typedef struct zebra_snhlfe_t_ zebra_snhlfe_t;
typedef struct zebra_slsp_t_ zebra_slsp_t;
typedef struct zebra_nhlfe_t_ zebra_nhlfe_t;
typedef struct zebra_lsp_t_ zebra_lsp_t;

/*
 * (Outgoing) nexthop label forwarding entry configuration
 */
struct zebra_snhlfe_t_
{
  /* Nexthop information */
  enum nexthop_types_t gtype;
  union g_addr gate;
  char *ifname;
  ifindex_t ifindex;

  /* Out label. */
  mpls_label_t out_label;

  /* Backpointer to base entry. */
  zebra_slsp_t *slsp;

  /* Pointers to more outgoing information for same in-label */
  zebra_snhlfe_t *next;
  zebra_snhlfe_t *prev;
};

/*
 * (Outgoing) nexthop label forwarding entry
 */
struct zebra_nhlfe_t_
{
  /* Type of entry - static etc. */
  enum lsp_types_t type;

  /* Nexthop information (with outgoing label) */
  struct nexthop *nexthop;

  /* Backpointer to base entry. */
  zebra_lsp_t *lsp;

  /* Runtime info - flags, pointers etc. */
  u_int32_t flags;
#define NHLFE_FLAG_CHANGED     (1 << 0)
#define NHLFE_FLAG_SELECTED    (1 << 1)
#define NHLFE_FLAG_MULTIPATH   (1 << 2)
#define NHLFE_FLAG_DELETED     (1 << 3)
#define NHLFE_FLAG_INSTALLED   (1 << 4)

  zebra_nhlfe_t *next;
  zebra_nhlfe_t *prev;
  u_char distance;
};

/*
 * Incoming label entry
 */
struct zebra_ile_t_
{
  mpls_label_t in_label;
};

/*
 * Label swap entry static configuration.
 */
struct zebra_slsp_t_
{
  /* Incoming label */
  zebra_ile_t ile;

  /* List of outgoing nexthop static configuration */
  zebra_snhlfe_t *snhlfe_list;

};

/*
 * Label swap entry (ile -> list of nhlfes)
 */
struct zebra_lsp_t_
{
  /* Incoming label */
  zebra_ile_t ile;

  /* List of NHLFE, pointer to best and num equal-cost. */
  zebra_nhlfe_t *nhlfe_list;
  zebra_nhlfe_t *best_nhlfe;
  u_int32_t num_ecmp;

  /* Flags */
  u_int32_t flags;
#define LSP_FLAG_SCHEDULED        (1 << 0)
#define LSP_FLAG_INSTALLED        (1 << 1)
#define LSP_FLAG_CHANGED          (1 << 2)

  /* Address-family of NHLFE - saved here for delete. All NHLFEs */
  /* have to be of the same AF */
  u_char addr_family;
};


/* Function declarations. */

/*
 * String to label conversion, labels separated by '/'.
 */
int
mpls_str2label (const char *label_str, u_int8_t *num_labels,
                mpls_label_t *labels);

/*
 * Label to string conversion, labels in string separated by '/'.
 */
char *
mpls_label2str (u_int8_t num_labels, mpls_label_t *labels,
                char *buf, int len);

/*
 * Install/uninstall a FEC-To-NHLFE (FTN) binding.
 */
int
mpls_ftn_update (int add, struct zebra_vrf *zvrf, enum lsp_types_t type,
		 struct prefix *prefix, union g_addr *gate, u_int8_t distance,
		 mpls_label_t out_label);

/*
 * Install/update a NHLFE for an LSP in the forwarding table. This may be
 * a new LSP entry or a new NHLFE for an existing in-label or an update of
 * the out-label for an existing NHLFE (update case).
 */
int
mpls_lsp_install (struct zebra_vrf *zvrf, enum lsp_types_t type,
		  mpls_label_t in_label, mpls_label_t out_label,
		  enum nexthop_types_t gtype, union g_addr *gate,
		  char *ifname, ifindex_t ifindex);

/*
 * Uninstall a particular NHLFE in the forwarding table. If this is
 * the only NHLFE, the entire LSP forwarding entry has to be deleted.
 */
int
mpls_lsp_uninstall (struct zebra_vrf *zvrf, enum lsp_types_t type,
		    mpls_label_t in_label, enum nexthop_types_t gtype,
		    union g_addr *gate, char *ifname, ifindex_t ifindex);

/*
 * Uninstall all LDP NHLFEs for a particular LSP forwarding entry.
 * If no other NHLFEs exist, the entry would be deleted.
 */
void
mpls_ldp_lsp_uninstall_all (struct hash_backet *backet, void *ctxt);

/*
 * Uninstall all LDP FEC-To-NHLFE (FTN) bindings of the given address-family.
 */
void
mpls_ldp_ftn_uninstall_all (struct zebra_vrf *zvrf, int afi);

#if defined(HAVE_CUMULUS)
/*
 * Check that the label values used in LSP creation are consistent. The
 * main criteria is that if there is ECMP, the label operation must still
 * be consistent - i.e., all paths either do a swap or do PHP. This is due
 * to current HW restrictions.
 */
int
zebra_mpls_lsp_label_consistent (struct zebra_vrf *zvrf, mpls_label_t in_label,
                     mpls_label_t out_label, enum nexthop_types_t gtype,
                     union g_addr *gate, char *ifname, ifindex_t ifindex);
#endif /* HAVE_CUMULUS */

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
                     union g_addr *gate, char *ifname, ifindex_t ifindex);

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
                           char *ifname, ifindex_t ifindex);

/*
 * Schedule all MPLS label forwarding entries for processing.
 * Called upon changes that may affect one or more of them such as
 * interface or nexthop state changes.
 */
void
zebra_mpls_lsp_schedule (struct zebra_vrf *zvrf);

/*
 * Display MPLS label forwarding table for a specific LSP
 * (VTY command handler).
 */
void
zebra_mpls_print_lsp (struct vty *vty, struct zebra_vrf *zvrf, mpls_label_t label,
                      u_char use_json);

/*
 * Display MPLS label forwarding table (VTY command handler).
 */
void
zebra_mpls_print_lsp_table (struct vty *vty, struct zebra_vrf *zvrf,
                            u_char use_json);

/*
 * Display MPLS LSP configuration of all static LSPs (VTY command handler).
 */
int
zebra_mpls_write_lsp_config (struct vty *vty, struct zebra_vrf *zvrf);

/*
 * Called upon process exiting, need to delete LSP forwarding
 * entries from the kernel.
 * NOTE: Currently supported only for default VRF.
 */
void
zebra_mpls_close_tables (struct zebra_vrf *zvrf);

/*
 * Allocate MPLS tables for this VRF.
 * NOTE: Currently supported only for default VRF.
 */
void
zebra_mpls_init_tables (struct zebra_vrf *zvrf);

/*
 * Global MPLS initialization.
 */
void
zebra_mpls_init (void);

/* Inline functions. */

/*
 * Distance (priority) definition for LSP NHLFE.
 */
static inline u_char
lsp_distance (enum lsp_types_t type)
{
  if (type == ZEBRA_LSP_STATIC)
    return (route_distance (ZEBRA_ROUTE_STATIC));

  return 150;
}

/*
 * Map RIB type to LSP type. Used when labeled-routes from BGP
 * are converted into LSPs.
 */
static inline enum lsp_types_t
lsp_type_from_rib_type (int rib_type)
{
  switch (rib_type)
    {
      case ZEBRA_ROUTE_STATIC:
        return ZEBRA_LSP_STATIC;
      default:
        return ZEBRA_LSP_NONE;
    }
}

/* NHLFE type as printable string. */
static inline const char *
nhlfe_type2str(enum lsp_types_t lsp_type)
{
  switch (lsp_type)
    {
      case ZEBRA_LSP_STATIC:
        return "Static";
      case ZEBRA_LSP_LDP:
        return "LDP";
      default:
        return "Unknown";
    }
}

static inline void
mpls_mark_lsps_for_processing(struct zebra_vrf *zvrf)
{
  if (!zvrf)
    return;

  zvrf->mpls_flags |= MPLS_FLAG_SCHEDULE_LSPS;
}

static inline void
mpls_unmark_lsps_for_processing(struct zebra_vrf *zvrf)
{
  if (!zvrf)
    return;

  zvrf->mpls_flags &= ~MPLS_FLAG_SCHEDULE_LSPS;
}

static inline int
mpls_should_lsps_be_processed(struct zebra_vrf *zvrf)
{
  if (!zvrf)
    return 0;

  return ((zvrf->mpls_flags & MPLS_FLAG_SCHEDULE_LSPS) ? 1 : 0);
}

#endif /*_ZEBRA_MPLS_H */
