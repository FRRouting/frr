/*
 * Zebra dataplane layer api interfaces.
 * Copyright (c) 2018 Volta Networks, Inc.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; see the file COPYING; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA
 */

#ifndef _ZEBRA_DPLANE_H
#define _ZEBRA_DPLANE_H 1

#include "zebra.h"
#include "zserv.h"
#include "prefix.h"
#include "nexthop.h"
#include "nexthop_group.h"


/*
 * API between the zebra dataplane system and the main zebra processing
 * context.
 */

/*
 * Enqueue a route install or update for the dataplane.
 */

/*
 * Enqueue a route removal for the dataplane.
 */

/*
 * Result codes used when returning status back to the main zebra context.
 */
typedef enum {
	ZEBRA_DPLANE_STATUS_NONE = 0,
	ZEBRA_DPLANE_INSTALL_SUCCESS,
	ZEBRA_DPLANE_INSTALL_FAILURE,
	ZEBRA_DPLANE_DELETE_SUCCESS,
	ZEBRA_DPLANE_DELETE_FAILURE,

} zebra_dplane_status_e;

/*
 * Context block used to return info from the dataplane module(s) to the
 * main zebra context.
 */
typedef struct zebra_dplane_ctx_s * zebra_dplane_ctx_h;

/*
 * Callback function used to return status about a dataplane operation. The
 * context block must be freed/released after use.
 */
typedef int (*zebra_dplane_status_fp)(zebra_dplane_ctx_h ctx);

/* Free a dataplane results context block after use; the caller's pointer will
 * be cleared on return.
 */
void zebra_dplane_ctx_free(zebra_dplane_ctx_h *h_p);

/* Accessors for information from the context object */
zebra_dplane_status_e zebra_dplane_ctx_get_status(const zebra_dplane_ctx_h h);
const struct prefix *zebra_dplane_ctx_get_dest(const zebra_dplane_ctx_h h);
const struct prefix *zebra_dplane_ctx_get_src(const zebra_dplane_ctx_h h);
vrf_id_t zebra_dplane_ctx_get_vrf(const zebra_dplane_ctx_h h);
int zebra_dplane_ctx_get_type(const zebra_dplane_ctx_h h);
uint32_t zebra_dplane_ctx_get_table(const zebra_dplane_ctx_h h);
route_tag_t zebra_dplane_ctx_get_tag(const zebra_dplane_ctx_h h);
uint16_t zebra_dplane_ctx_get_instance(const zebra_dplane_ctx_h h);
uint32_t zebra_dplane_ctx_get_metric(const zebra_dplane_ctx_h h);


/*
 * Initialize the dataplane module;
 * register a callback that will receive status updates from the dataplane.
 */
int zebra_dplane_init(zebra_dplane_status_fp fp);


#endif	/* _ZEBRA_DPLANE_H */
