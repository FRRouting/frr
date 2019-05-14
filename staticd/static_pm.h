/**
 * static_pm.h: STATIC PM definitions and structures
 *
 * @copyright Copyright (C) 2019 6WIND
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

extern int static_pm_param_unset(struct static_route *si);

extern int static_pm_param_set(struct static_route *si, uint32_t frequency,
			       uint32_t timeout, uint16_t packet_size,
			       uint8_t tos_val);
extern void static_pm_update_si(struct static_route *si, bool install);

extern void static_pm_update_connected(struct zapi_route *nhr,
				       struct prefix *dp,
				       vrf_id_t vrf_id);

#endif /* _STATIC_PM_H */
