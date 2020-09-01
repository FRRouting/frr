/*
 * Zebra connect library for SHARP
 * Copyright (C) Cumulus Networks, Inc.
 *               Donald Sharp
 *
 * This file is part of FRR.
 *
 * FRR is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2, or (at your option) any
 * later version.
 *
 * FRR is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; see the file COPYING; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA
 */
#ifndef __SHARP_ZEBRA_H__
#define __SHARP_ZEBRA_H__

extern void sharp_zebra_init(void);

/* Add and delete extra zapi client sessions, for testing */
int sharp_zclient_create(uint32_t session_id);
int sharp_zclient_delete(uint32_t session_id);

extern void vrf_label_add(vrf_id_t vrf_id, afi_t afi, mpls_label_t label);
extern void nhg_add(uint32_t id, const struct nexthop_group *nhg,
		    const struct nexthop_group *backup_nhg);
extern void nhg_del(uint32_t id);
extern int route_add(const struct prefix *p, vrf_id_t, uint8_t instance,
		     uint32_t nhgid, const struct nexthop_group *nhg,
		     const struct nexthop_group *backup_nhg);
extern void route_delete(struct prefix *p, vrf_id_t vrf_id, uint8_t instance);
extern void sharp_zebra_nexthop_watch(struct prefix *p, vrf_id_t vrf_id,
				      bool import, bool watch, bool connected);

extern void sharp_install_routes_helper(struct prefix *p, vrf_id_t vrf_id,
					uint8_t instance, uint32_t nhgid,
					const struct nexthop_group *nhg,
					const struct nexthop_group *backup_nhg,
					uint32_t routes);
extern void sharp_remove_routes_helper(struct prefix *p, vrf_id_t vrf_id,
				       uint8_t instance, uint32_t routes);

int sharp_install_lsps_helper(bool install_p, bool update_p,
			      const struct prefix *p, uint8_t type,
			      int instance, uint32_t in_label,
			      const struct nexthop_group *nhg,
			      const struct nexthop_group *backup_nhg);

/* Send OPAQUE messages, using subtype 'type'. */
void sharp_opaque_send(uint32_t type, uint32_t proto, uint32_t instance,
		       uint32_t session_id, uint32_t count);

/* Send OPAQUE registration messages, using subtype 'type'. */
void sharp_opaque_reg_send(bool is_reg, uint32_t proto, uint32_t instance,
			   uint32_t session_id, uint32_t type);

extern void sharp_zebra_send_arp(const struct interface *ifp,
				 const struct prefix *p);

#endif
