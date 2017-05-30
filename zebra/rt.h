/*
 * kernel routing table update prototype.
 * Copyright (C) 1998 Kunihiro Ishiguro
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
 * You should have received a copy of the GNU General Public License along
 * with this program; see the file COPYING; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA
 */

#ifndef _ZEBRA_RT_H
#define _ZEBRA_RT_H

#include "prefix.h"
#include "if.h"
#include "zebra/rib.h"
#include "zebra/zebra_ns.h"
#include "zebra/zebra_mpls.h"

extern int kernel_route_rib (struct prefix *, struct prefix *,
                             struct rib *, struct rib *);

extern int kernel_address_add_ipv4 (struct interface *, struct connected *);
extern int kernel_address_delete_ipv4 (struct interface *, struct connected *);
extern int kernel_neigh_update (int, int, uint32_t, char *, int);

extern int kernel_add_lsp (zebra_lsp_t *);
extern int kernel_upd_lsp (zebra_lsp_t *);
extern int kernel_del_lsp (zebra_lsp_t *);
extern int mpls_kernel_init (void);

extern int kernel_get_ipmr_sg_stats (void *mroute);
#endif /* _ZEBRA_RT_H */
