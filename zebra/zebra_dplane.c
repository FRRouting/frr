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

#include "zebra.h"
#include "zebra_dplane.h"
#include "lib/memory.h"
#include "zebra_memory.h"
#include "zserv.h"
#include "frr_pthread.h"
#include "queue.h"

/* Memory type for context blocks */
DEFINE_MTYPE(ZEBRA, DP_CTX, "Zebra DPlane Ctx")

#ifndef AOK
#  define AOK 0
#endif

/* Validation value for context blocks */
const uint32_t DPLANE_CTX_MAGIC = 0xb97a557f;

/* Validation check macro for context blocks */
/* #define DPLANE_DEBUG 1 */

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

	/* Embedded list linkage */
	TAILQ_ENTRY(zebra_dplane_ctx_s) zd_q_entries;

	/* Magic validation value */
	uint32_t zd_magic;
};

/*
 * Registration block for one dataplane provider.
 */
struct zebra_dplane_provider_s {
	/* Name */
	const char *dp_name;

	/* Priority, for ordering among providers */
	uint8_t dp_priority;

	/* Event pointer for use by the dplane thread */
	struct thread *dp_t_event;

	/* Embedded list linkage */
	TAILQ_ENTRY(zebra_dplane_dest_s) dp_q_providers;

};

/*
 * Globals
 */
static struct zebra_dplane_globals_s {
	/* Mutex to control access to dataplane components */
	pthread_mutex_t dg_mutex;

	/* Route-update context queue inbound to the dataplane */
	TAILQ_HEAD(zdg_ctx_q, zebra_dplane_ctx_s) dg_route_ctx_q;

	/* Ordered list of providers */
	TAILQ_HEAD(zdg_prov_q, zebra_dplane_provider_s) dg_providers_q;

	/* Event-delivery context 'master' for the dplane */
	struct thread_master *dg_master;

	/* Event/'thread' pointer for queued updates */
	struct thread *dg_t_update;

} zdplane_g;

/*
 * Lock and unlock for interactions with the zebra 'core'
 */
#define DPLANE_LOCK() pthread_mutex_lock(&zdplane_g.dg_mutex)

#define DPLANE_UNLOCK() pthread_mutex_unlock(&zdplane_g.dg_mutex)

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
			/* TODO -- deal with recursive nexthops allocations */

			nexthops_free((*pctx)->zd_ng.nexthop);
		}

		/* Clear validation value */
		(*pctx)->zd_magic = 0;

		XFREE(MTYPE_DP_CTX, *pctx);
		*pctx = NULL;
	}
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

/*
 * Initialize a context block for a route update from zebra data structs.
 */
static int dplane_ctx_route_init(dplane_ctx_h ctx,
				 dplane_op_e op,
				 struct route_node *rn,
				 struct route_entry *re)
{
	int ret = EINVAL;
	const struct route_table *table = NULL;
	const rib_table_info_t *info;
	struct prefix *p, *src_p;
	struct zebra_ns *zns;
	struct zebra_vrf *zvrf;

	if (!ctx || !rn || !re) {
		goto done;
	}

	ctx->zd_op = op;
	ctx->zd_status = DPLANE_STATUS_NONE;

	ctx->zd_type = re->type;

	/* Prefixes */
	srcdest_rnode_prefixes(rn, &p, &src_p);

	prefix_copy(&(ctx->zd_src), p);

	if (src_p) {
		prefix_copy(&(ctx->zd_src), src_p);
	} else {
		memset(&(ctx->zd_src), 0, sizeof(ctx->zd_src));
	}

	ctx->zd_metric = re->metric;
	ctx->zd_vrf_id = re->vrf_id;
	ctx->zd_mtu = re->mtu;
	ctx->zd_nexthop_mtu = re->nexthop_mtu;
	ctx->zd_instance = re->instance;
	ctx->zd_tag = re->tag;

	ctx->zd_table_id = re->table;

	table = srcdest_rnode_table(rn);
	info = table->info;

	ctx->zd_afi = info->afi;
	ctx->zd_safi = info->safi;

	/* ns info - can't use pointers to 'core' structs */
	zvrf = vrf_info_lookup(re->vrf_id);
	zns = zvrf->zns;

#if defined(HAVE_NETLINK)
	/* Increment counter before copying to context struct */
	zns->netlink_cmd.seq++;
#endif /* NETLINK*/

	zebra_ns_info_from_ns(&(ctx->zd_ns_info), zns, true /*is_cmd*/);

	/* TODO -- nexthops; include recursive info too */

	/* Trying out the sequence number idea, so we can at least detect
	 * when a result is stale.
	 */
	re->dplane_sequence++;
	ctx->zd_seq = re->dplane_sequence;

	ret = AOK;

done:
	return ret;
}

/*
 * Event handler function for routing updates
 */
static int dplane_route_process(struct thread *event)
{
	return (0);
}

/*
 * Enqueue a new route update,
 * and ensure an event is active for the dataplane thread.
 */
static int dplane_route_enqueue(dplane_ctx_h ctx)
{
	int ret = EINVAL;

	/* Enqueue for processing by the dataplane thread */
	DPLANE_LOCK();
	{
		TAILQ_INSERT_TAIL(&zdplane_g.dg_route_ctx_q, ctx, zd_q_entries);
	}
	DPLANE_UNLOCK();

	/* Ensure that an event for the dataplane thread is active */
	thread_add_event(zdplane_g.dg_master, dplane_route_process, NULL, 0,
			 &zdplane_g.dg_t_update);

	ret = AOK;

	return (ret);
}


/*
 * Utility that prepares a route update and enqueues it for processing
 */
static int dplane_route_update_internal(struct route_node *rn,
					struct route_entry *re,
					dplane_op_e op)
{
	int ret = EINVAL;
	dplane_ctx_h ctx = NULL;

	/* Obtain context block */
	ctx = dplane_ctx_alloc();
	if (ctx == NULL) {
		ret = ENOMEM;
		goto done;
	}

	/* Init context with info from zebra data structs */
	ret = dplane_ctx_route_init(ctx, op, rn, re);
	if (ret == AOK) {
		/* TODO -- Enqueue context for processing */
		ret = dplane_route_enqueue(ctx);
	}

done:
	if (ret != AOK && ctx) {
		dplane_ctx_free(&ctx);
	}

	return (ret);
}

/*
 * Enqueue a route update for the dataplane.
 */
int dplane_route_update(struct route_node *rn,
			struct route_entry *re)
{
	int ret = EINVAL;

	if (rn == NULL || re == NULL) {
		goto done;
	}

	ret = dplane_route_update_internal(rn, re, DPLANE_OP_ROUTE_UPDATE);

done:

	return (ret);
}

/*
 * Enqueue a route removal for the dataplane.
 */
int dplane_route_delete(struct route_node *rn,
			struct route_entry *re)
{
	int ret = EINVAL;

	if (rn == NULL || re == NULL) {
		goto done;
	}

	ret = dplane_route_update_internal(rn, re, DPLANE_OP_ROUTE_DELETE);

done:

	return (ret);
}
