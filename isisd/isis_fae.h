/* IS-IS Flex-Algo Endpoint Registration Tracking
 *
 * Copyright 2022 6WIND S.A.
 *
 * This file is part of FRRouting.
 *
 * FRRouting is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2, or (at your option) any
 * later version.
 *
 * FRRouting is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; see the file COPYING; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA
 */

#ifndef __ISIS_FAE_H
#define __ISIS_FAE_H

#include <zebra.h>
#include "zclient.h"
#include "lib/fae_db.h"
#include "lib/table.h" /* route_node */
#include "isisd/isis_fae_db.h"
#include "isisd/isisd.h"
#include "isisd/isis_route.h"
#include "zapi_fae.h"

enum { ISIS_FAE_OK = 0,
       ISIS_FAE_NO_MATCH,
};

void isis_fae_send_update_all(const struct isis_area *const area,
			      const struct isis_route_info *const rinfo,
			      uint8_t algorithm);

int isis_fae_alloc_db(struct isis_fae_db *);

void isis_fae_free_db(struct isis_fae_db *);

extern int isis_fae_process_register(
	const struct zapi_fae_daemon_id *const client_daemon_id,
	const struct zapi_fae_igp_discriminator *const igp_disc,
	const struct zapi_fae_query *const query);

extern int isis_fae_process_unregister(
	const struct zapi_fae_daemon_id *const client_daemon_id,
	const struct zapi_fae_igp_discriminator *const igp_disc,
	const struct zapi_fae_query *const query);

extern int isis_fae_process_client_ready(
	const struct zapi_fae_daemon_id *const client_daemon_id);

struct route_node *isis_fae_promote(struct isis_area *, struct route_node *,
				    uint8_t);

struct route_node *isis_fae_demote(struct isis_area *, struct route_node *,
				   uint8_t);

void isis_fae_check_inactive(struct isis_area *,
			     const struct route_node *const);

void isis_fae_route_info_reg_move(struct isis_route_info *,
				  struct isis_route_info *);

void isis_fae_route_info_reg_deactivate(struct isis_area *,
					struct isis_route_info *, uint8_t);

void isis_fae_route_info_delete(struct isis_area *, struct isis_route_info *);

struct isis_area *
isis_fae_area_lookup(const struct zapi_fae_igp_discriminator *const);

void isis_fae_init(void);

#endif
