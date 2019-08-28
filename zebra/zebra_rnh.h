/*
 * Zebra next hop tracking header
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
 * You should have received a copy of the GNU General Public License along
 * with this program; see the file COPYING; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA
 */

#ifndef _ZEBRA_RNH_H
#define _ZEBRA_RNH_H

#include "prefix.h"
#include "vty.h"

#ifdef __cplusplus
extern "C" {
#endif

extern void zebra_rnh_init(void);

static inline const char *rnh_type2str(rnh_type_t type)
{
	switch (type) {
	case RNH_NEXTHOP_TYPE:
		return "Nexthop";
	case RNH_IMPORT_CHECK_TYPE:
		return "Import";
	}

	return "ERROR";
}

extern struct rnh *zebra_add_rnh(struct prefix *p, vrf_id_t vrfid,
				 rnh_type_t type, bool *exists);
extern struct rnh *zebra_lookup_rnh(struct prefix *p, vrf_id_t vrfid,
				    rnh_type_t type);
extern void zebra_free_rnh(struct rnh *rnh);
extern void zebra_add_rnh_client(struct rnh *rnh, struct zserv *client,
				 rnh_type_t type, vrf_id_t vrfid);
extern void zebra_register_rnh_pseudowire(vrf_id_t, struct zebra_pw *);
extern void zebra_deregister_rnh_pseudowire(vrf_id_t, struct zebra_pw *);
extern void zebra_remove_rnh_client(struct rnh *rnh, struct zserv *client,
				    rnh_type_t type);
extern void zebra_evaluate_rnh(struct zebra_vrf *zvrf, afi_t afi, int force,
			       rnh_type_t type, struct prefix *p);
extern void zebra_print_rnh_table(vrf_id_t vrfid, afi_t afi, struct vty *vty,
				  rnh_type_t type, struct prefix *p);
extern char *rnh_str(struct rnh *rnh, char *buf, int size);

extern int rnh_resolve_via_default(struct zebra_vrf *zvrf, int family);

#ifdef __cplusplus
}
#endif

#endif /*_ZEBRA_RNH_H */
