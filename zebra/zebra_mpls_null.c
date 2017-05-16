/*
 * Copyright (C) 2016 by Open Source Routing.
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
#include "zebra/rt.h"
#include "zebra/zebra_mpls.h"

int kernel_add_lsp (zebra_lsp_t *lsp) { return 0; }
int kernel_upd_lsp (zebra_lsp_t *lsp) { return 0; }
int kernel_del_lsp (zebra_lsp_t *lsp) { return 0; }
int mpls_kernel_init (void) { return -1; };

int mpls_enabled;

char *
mpls_label2str (u_int8_t num_labels, mpls_label_t *labels,
                char *buf, int len)
{
  return NULL;
}

int
mpls_str2label (const char *label_str, u_int8_t *num_labels,
                mpls_label_t *labels)
{
  return 0;
}

int
zebra_mpls_label_block_add (struct zebra_vrf *vrf, u_int32_t start_label,
                            u_int32_t end_label)
{
  return 0;
}

int
zebra_mpls_label_block_del (struct zebra_vrf *zvrf)
{
  return 0;
}

int
zebra_mpls_write_label_block_config (struct vty *vty, struct zebra_vrf *zvrf)
{
  return 0;
}

int
zebra_mpls_lsp_install (struct zebra_vrf *zvrf, struct route_node *rn, struct rib *rib)
{
  return 0;
}

int
zebra_mpls_lsp_uninstall (struct zebra_vrf *zvrf, struct route_node *rn, struct rib *rib)
{
  return 0;
}

void
zebra_mpls_init_tables (struct zebra_vrf *zvrf)
{
}

void
zebra_mpls_print_lsp (struct vty *vty, struct zebra_vrf *zvrf, mpls_label_t label,
                      u_char use_json)
{
}

void
zebra_mpls_print_lsp_table (struct vty *vty, struct zebra_vrf *zvrf,
                            u_char use_json)
{
}

int
zebra_mpls_write_lsp_config (struct vty *vty, struct zebra_vrf *zvrf)
{
  return 0;
}

#ifdef HAVE_CUMULUS
int
zebra_mpls_lsp_label_consistent (struct zebra_vrf *zvrf, mpls_label_t in_label,
                                 mpls_label_t out_label, enum nexthop_types_t gtype,
                                 union g_addr *gate, ifindex_t ifindex)
{
  return 0;
}
#endif

int
zebra_mpls_static_lsp_add (struct zebra_vrf *zvrf, mpls_label_t in_label,
                           mpls_label_t out_label, enum nexthop_types_t gtype,
                           union g_addr *gate, ifindex_t ifindex)
{
  return 0;
}

int
zebra_mpls_static_lsp_del (struct zebra_vrf *zvrf, mpls_label_t in_label,
                           enum nexthop_types_t gtype, union g_addr *gate,
                           ifindex_t ifindex)
{
  return 0;
}

void
zebra_mpls_lsp_schedule (struct zebra_vrf *zvrf)
{
}

void
zebra_mpls_close_tables (struct zebra_vrf *zvrf)
{
}

zebra_fec_t *
zebra_mpls_fec_for_label (struct zebra_vrf *zvrf, mpls_label_t label)
{
  return NULL;
}

int
zebra_mpls_label_already_bound (struct zebra_vrf *zvrf, mpls_label_t label)
{
  return 0;
}

int
zebra_mpls_static_fec_add (struct zebra_vrf *zvrf, struct prefix *p,
                           mpls_label_t in_label)
{
  return 0;
}

int
zebra_mpls_static_fec_del (struct zebra_vrf *zvrf, struct prefix *p)
{
  return 0;
}

int
zebra_mpls_write_fec_config (struct vty *vty, struct zebra_vrf *zvrf)
{
  return 0;
}

void
zebra_mpls_print_fec_table (struct vty *vty, struct zebra_vrf *zvrf)
{
}

void
zebra_mpls_print_fec (struct vty *vty, struct zebra_vrf *zvrf, struct prefix *p)
{
}

int
zebra_mpls_fec_register (struct zebra_vrf *zvrf, struct prefix *p,
                         u_int32_t label_index, struct zserv *client)
{
  return 0;
}

int
zebra_mpls_fec_unregister (struct zebra_vrf *zvrf, struct prefix *p,
                           struct zserv *client)
{
  return 0;
}

int
zebra_mpls_cleanup_fecs_for_client (struct zebra_vrf *zvrf, struct zserv *client)
{
  return 0;
}

void mpls_ldp_lsp_uninstall_all (struct hash_backet *backet, void *ctxt)
{
  return;
}

void mpls_ldp_ftn_uninstall_all (struct zebra_vrf *zvrf, int afi)
{
  return;
}

void zebra_mpls_init (void)
{
  return;
}

int mpls_lsp_install (struct zebra_vrf *zvrf, enum lsp_types_t type,
              mpls_label_t in_label, mpls_label_t out_label,
              enum nexthop_types_t gtype, union g_addr *gate,
              ifindex_t ifindex)
{
  return 0;
}

int mpls_lsp_uninstall (struct zebra_vrf *zvrf, enum lsp_types_t type,
                 mpls_label_t in_label, enum nexthop_types_t gtype,
                 union g_addr *gate, ifindex_t ifindex)
{
  return 0;
}

int mpls_ftn_update (int add, struct zebra_vrf *zvrf, enum lsp_types_t type,
              struct prefix *prefix, enum nexthop_types_t gtype,
              union g_addr *gate, ifindex_t ifindex, u_int8_t distance,
              mpls_label_t out_label)
{
  return 0;
}

