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


/* Definitions and macros. */

#define NHLFE_FAMILY(nhlfe)                        \
  (((nhlfe)->nexthop->type == NEXTHOP_TYPE_IPV6 || \
    (nhlfe)->nexthop->type == NEXTHOP_TYPE_IPV6_IFINDEX) ? AF_INET6 : AF_INET)


/* Typedefs */

typedef struct zebra_ile_t_ zebra_ile_t;
typedef struct zebra_snhlfe_t_ zebra_snhlfe_t;
typedef struct zebra_slsp_t_ zebra_slsp_t;
typedef struct zebra_nhlfe_t_ zebra_nhlfe_t;
typedef struct zebra_lsp_t_ zebra_lsp_t;

/* LSP types. */
enum lsp_types_t
{
  ZEBRA_LSP_INVALID = 0,     /* Invalid. */
  ZEBRA_LSP_STATIC = 1,      /* Static LSP. */
};

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


#endif /*_ZEBRA_MPLS_H */
