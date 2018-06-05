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
#include "rib.h"
#include "prefix.h"
#include "nexthop.h"
#include "nexthop_group.h"
#include "zebra_ns.h"


/*
 * API between the zebra dataplane system and the main zebra processing
 * context.
 */

/*
 * Operation codes used when returning status back to the main zebra context.
 */
typedef enum {
	DPLANE_OP_NONE = 0,

	/* Route update */
	DPLANE_OP_ROUTE_INSTALL,
	DPLANE_OP_ROUTE_UPDATE,
	DPLANE_OP_ROUTE_DELETE,

	/* Interface address update */
	DPLANE_OP_INTF_ADDR,
	DPLANE_OP_INTF_ADDR_DELETE,

} dplane_op_e;

/*
 * Result codes used when returning status back to the main zebra context.
 */
typedef enum {
	DPLANE_STATUS_NONE = 0,
	DPLANE_INSTALL_SUCCESS,
	DPLANE_INSTALL_FAILURE,
	DPLANE_DELETE_SUCCESS,
	DPLANE_DELETE_FAILURE,

} dplane_status_e;

/*
 * Opaque context block used to exchange info between the main zebra
 * context and the dataplane module(s). If these are two independent pthreads,
 * they cannot share existing global data structures safely.
 */
typedef struct zebra_dplane_ctx_s * dplane_ctx_h;

/*
 * Allocate an opaque context block
 */
dplane_ctx_h dplane_ctx_alloc(void);

/* Free a dataplane results context block after use; the caller's pointer will
 * be cleared on return.
 */
void dplane_ctx_free(dplane_ctx_h *pctx);

/*
 * Accessors for information from the context object
 */
dplane_status_e dplane_ctx_get_status(const dplane_ctx_h ctx);

dplane_op_e dplane_ctx_get_op(const dplane_ctx_h ctx);

const struct prefix *dplane_ctx_get_dest(const dplane_ctx_h ctx);

/* Source prefix is a little special - use convention like prefix-len of zero
 * and all-zeroes address means "no src prefix"? or ... return NULL in that case?
 */
const struct prefix *dplane_ctx_get_src(const dplane_ctx_h ctx);

uint32_t dplane_ctx_get_seq(const dplane_ctx_h ctx);
vrf_id_t dplane_ctx_get_vrf(const dplane_ctx_h ctx);
int dplane_ctx_get_type(const dplane_ctx_h ctx);
afi_t dplane_ctx_get_afi(const dplane_ctx_h ctx);
safi_t dplane_ctx_get_safi(const dplane_ctx_h ctx);
uint32_t dplane_ctx_get_table(const dplane_ctx_h ctx);
route_tag_t dplane_ctx_get_tag(const dplane_ctx_h ctx);
uint16_t dplane_ctx_get_instance(const dplane_ctx_h ctx);
uint32_t dplane_ctx_get_metric(const dplane_ctx_h ctx);
uint32_t dplane_ctx_get_mtu(const dplane_ctx_h ctx);
uint32_t dplane_ctx_get_nh_mtu(const dplane_ctx_h ctx);
const struct nexthop_group *dplane_ctx_get_ng(const dplane_ctx_h ctx);
const struct zebra_ns_info *dplane_ctx_get_ns(const dplane_ctx_h ctx);

/*
 * Enqueue route operations for the dataplane.
 */
int dplane_route_add(struct route_node *rn,
		     struct route_entry *re);

int dplane_route_update(struct route_node *rn,
			struct route_entry *re);

int dplane_route_delete(struct route_node *rn,
			struct route_entry *re);

/*
 * Callback function used to return status about a dataplane operation. The
 * callback must take ownership of the context block - it must free it, using
 * the 'free' api.
 */
typedef int (*dplane_route_status_fp)(dplane_ctx_h ctx);

/*
 * Initialize the dataplane module;
 * register a callback that will receive status updates from the dataplane.
 */
int zebra_dplane_init(dplane_route_status_fp fp);


#endif	/* _ZEBRA_DPLANE_H */
