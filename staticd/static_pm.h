/**
 * static_pm.h: STATIC PM definitions and structures
 *
 * Copyright 2019 6WIND S.A.
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

#ifndef _STATIC_PM_H
#define _STATIC_PM_H

extern void static_pm_init(void);

void static_next_hop_pm_update(struct static_nexthop *sn);
void static_next_hop_pm_destroy(struct static_nexthop *sn);
extern int static_pm_param_unset(struct static_nexthop *si);

extern void static_pm_update_si(struct static_nexthop *nh, bool install);
void static_pm_update_status(struct prefix *dp, vrf_id_t nh_vrf_id, int status);
void static_pm_update_interface(ifindex_t idx, struct prefix *dp,
				vrf_id_t nh_vrf_id, ifindex_t old_idx);

#endif /* _STATIC_PM_H */
