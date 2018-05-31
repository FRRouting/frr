/*
 * Zebra dataplane layer.
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

#include <zebra.h>
#include "zebra_dplane.h"
#include "lib/memory.h"
#include "zebra_memory.h"

DEFINE_MTYPE(ZEBRA, DP_CTX, "Zebra DPlane Ctx")

#ifndef AOK
#  define AOK 0
#endif

/* Validation value */
const uint32_t DPLANE_CTX_MAGIC = 0xb97a557f;

/* #define DPLANE_DEBUG */

#ifdef DPLANE_DEBUG

#  define DPLANE_CTX_VALID(p) \
    (assert((p) && ((p)->zd_magic == DPLANE_CTX_MAGIC)))

#else

#  define DPLANE_CTX_VALID(p) \
    if ((p) && ((p)->zd_magic == DPLANE_CTX_MAGIC)) { ; }

#endif	/* DPLANE_DEBUG */

/*
 * The context block used to exchange info about route updates across
 * the boundary between the zebra main context (and pthread) and the
 * dataplane layer (and pthread).
 */
struct zebra_dplane_ctx_s {
	/* Operation code */
	dplane_op_e zd_op;

	/* Status on return */
	dplane_status_e zd_status;

	/* Dest and (optional) source prefixes */
	struct prefix zd_dest;
	struct prefix zd_src;

	uint32_t zd_seq;
	vrf_id_t zd_vrf_id;
	uint32_t zd_table_id;
	int zd_type;

	afi_t zd_afi;
	safi_t zd_safi;

	route_tag_t zd_tag;
	uint32_t zd_metric;
	uint16_t zd_instance;

	uint32_t zd_mtu;
	uint32_t zd_nexthop_mtu;

	struct zebra_ns_info zd_ns_info;

	struct nexthop_group zd_ng;

	/* Magic validation value */
	uint32_t zd_magic;
};

/*
 * Public APIs
 */

/*
 * Allocate an opaque context block
 */

dplane_ctx_h dplane_ctx_alloc(void)
{
	struct zebra_dplane_ctx_s *p;

	p = XCALLOC(MTYPE_DP_CTX, sizeof(struct zebra_dplane_ctx_s));
	if (p) {
		p->zd_magic = DPLANE_CTX_MAGIC;
	}

	return (p);
}

/* Free a dataplane results context block after use; the caller's pointer will
 * be cleared on return.
 */
void dplane_ctx_free(dplane_ctx_h *pctx)
{
	if (pctx) {
		DPLANE_CTX_VALID(*pctx);

		/* Free embedded nexthops */
		if ((*pctx)->zd_ng.nexthop) {
			nexthops_free((*pctx)->zd_ng.nexthop);
		}

		/* Clear validation value */
		(*pctx)->zd_magic = 0;

		XFREE(MTYPE_DP_CTX, *pctx);
		*pctx = NULL;
	}
}

/*
 * Initialize a context block for a route update from zebra data structs:
 * a route-entry, a dest prefix, and an optional source prefix.
 */
int dplane_ctx_route_init(dplane_ctx_h ctx,
			  dplane_op_e op,
			  const struct route_node *rn,
			  const struct route_entry *re)
{
	int ret = EINVAL;

	if (!ctx || !rn || !re) {
		goto done;
	}


	ret = AOK;

done:
	return ret;
}


/*
 * Accessors for information from the context object
 */
dplane_status_e dplane_ctx_get_status(const dplane_ctx_h ctx)
{
	DPLANE_CTX_VALID(ctx);

	return (ctx->zd_status);
}

dplane_op_e dplane_ctx_get_op(const dplane_ctx_h ctx)
{
	DPLANE_CTX_VALID(ctx);

	return (ctx->zd_op);
}

const struct prefix *dplane_ctx_get_dest(const dplane_ctx_h ctx)
{
	DPLANE_CTX_VALID(ctx);

	return (&(ctx->zd_dest));
}

/* Source prefix is a little special - use convention like prefix-len of zero
 * and all-zeroes address means "no src prefix"? or ... return NULL in that case?
 */
const struct prefix *dplane_ctx_get_src(const dplane_ctx_h ctx)
{
	DPLANE_CTX_VALID(ctx);

	if (ctx->zd_src.prefixlen == 0 &&
	    IN6_IS_ADDR_UNSPECIFIED(&(ctx->zd_src.u.prefix6))) {
		return (NULL);
	} else {
		return (&(ctx->zd_src));
	}
}

uint32_t dplane_ctx_get_seq(const dplane_ctx_h ctx)
{
	DPLANE_CTX_VALID(ctx);

	return (ctx->zd_seq);
}

vrf_id_t dplane_ctx_get_vrf(const dplane_ctx_h ctx)
{
	DPLANE_CTX_VALID(ctx);

	return (ctx->zd_vrf_id);
}

int dplane_ctx_get_type(const dplane_ctx_h ctx)
{
	DPLANE_CTX_VALID(ctx);

	return (ctx->zd_type);
}

afi_t dplane_ctx_get_afi(const dplane_ctx_h ctx)
{
	DPLANE_CTX_VALID(ctx);

	return (ctx->zd_afi);
}

safi_t dplane_ctx_get_safi(const dplane_ctx_h ctx)
{
	DPLANE_CTX_VALID(ctx);

	return (ctx->zd_safi);
}

uint32_t dplane_ctx_get_table(const dplane_ctx_h ctx)
{
	DPLANE_CTX_VALID(ctx);

	return (ctx->zd_table_id);
}

route_tag_t dplane_ctx_get_tag(const dplane_ctx_h ctx)
{
	DPLANE_CTX_VALID(ctx);

	return (ctx->zd_tag);
}

uint16_t dplane_ctx_get_instance(const dplane_ctx_h ctx)
{
	DPLANE_CTX_VALID(ctx);

	return (ctx->zd_instance);
}

uint32_t dplane_ctx_get_metric(const dplane_ctx_h ctx)
{
	DPLANE_CTX_VALID(ctx);

	return (ctx->zd_metric);
}

uint32_t dplane_ctx_get_mtu(const dplane_ctx_h ctx)
{
	DPLANE_CTX_VALID(ctx);

	return (ctx->zd_mtu);
}

uint32_t dplane_ctx_get_nh_mtu(const dplane_ctx_h ctx)
{
	DPLANE_CTX_VALID(ctx);

	return (ctx->zd_nexthop_mtu);
}

const struct nexthop_group *dplane_ctx_get_ng(const dplane_ctx_h ctx)
{
	DPLANE_CTX_VALID(ctx);

	return (&(ctx->zd_ng));
}

const struct zebra_ns_info *dplane_ctx_get_ns(const dplane_ctx_h ctx)
{
	DPLANE_CTX_VALID(ctx);

	return (&(ctx->zd_ns_info));
}

/*
 * End of dplane context accessors
 */
