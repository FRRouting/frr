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

#include "lib/zebra.h"
#include "lib/prefix.h"
#include "lib/nexthop.h"
#include "lib/nexthop_group.h"
#include "lib/openbsd-queue.h"
#include "zebra/zebra_ns.h"
#include "zebra/rib.h"
#include "zebra/zserv.h"


/* Key netlink info from zebra ns */
struct zebra_dplane_info {
	ns_id_t ns_id;

#if defined(HAVE_NETLINK)
	struct nlsock nls;
	bool is_cmd;
#endif
};

/* Utility to fill in zns info from main zns struct */
static inline void
zebra_dplane_info_from_zns(struct zebra_dplane_info *zns_info,
			   const struct zebra_ns *zns, bool is_cmd)
{
	zns_info->ns_id = zns->ns_id;

#if defined(HAVE_NETLINK)
	zns_info->is_cmd = is_cmd;
	if (is_cmd) {
		zns_info->nls = zns->netlink_cmd;
	} else {
		zns_info->nls = zns->netlink;
	}
#endif /* NETLINK */
}

/*
 * Result codes used when returning status back to the main zebra context.
 */

/*
 * Philosophy Note:
 *
 * Flags being SET/UNSET do not belong in the South Bound
 * Interface.  This Setting belongs at the calling level
 * because we can and will have multiple different interfaces
 * and we will have potentially multiple different
 * modules/filters to call.  As such Setting/Unsetting
 * success failure should be handled by the caller.
 */
enum zebra_dplane_status {
	ZEBRA_DPLANE_STATUS_NONE = 0,
	ZEBRA_DPLANE_INSTALL_SUCCESS,
	ZEBRA_DPLANE_INSTALL_FAILURE,
	ZEBRA_DPLANE_DELETE_SUCCESS,
	ZEBRA_DPLANE_DELETE_FAILURE,

};

enum zebra_dplane_result {
	ZEBRA_DPLANE_REQUEST_QUEUED,
	ZEBRA_DPLANE_REQUEST_SUCCESS,
	ZEBRA_DPLANE_REQUEST_FAILURE,
};

/*
 * API between the zebra dataplane system and the main zebra processing
 * context.
 */

/*
 * Enqueue a route install or update for the dataplane.
 */
enum dplane_op_e {
	DPLANE_OP_NONE = 0,

	/* Route update */
	DPLANE_OP_ROUTE_INSTALL,
	DPLANE_OP_ROUTE_UPDATE,
	DPLANE_OP_ROUTE_DELETE,

};

/*
 * Opaque context block used to exchange info between the main zebra
 * context and the dataplane module(s). If these are two independent pthreads,
 * they cannot share existing global data structures safely.
 */
typedef struct zebra_dplane_ctx_s *dplane_ctx_h;

/* Define a tailq list type for context blocks. The list is exposed/public,
 * but the internal linkage in the context struct is private, so there
 * are accessor apis that support enqueue and dequeue.
 */
TAILQ_HEAD(dplane_ctx_q_s, zebra_dplane_ctx_s);

/* Return a dataplane results context block after use; the caller's pointer will
 * be cleared.
 */
void dplane_ctx_fini(dplane_ctx_h *pctx);

/* Enqueue a context block to caller's tailq. This just exists so that the
 * context struct can remain opaque.
 */
void dplane_ctx_enqueue_tail(struct dplane_ctx_q_s *q, dplane_ctx_h ctx);

/* Dequeue a context block from the head of caller's tailq */
void dplane_ctx_dequeue(struct dplane_ctx_q_s *q, dplane_ctx_h *ctxp);

/*
 * Accessors for information from the context object
 */
enum zebra_dplane_result dplane_ctx_get_status(const dplane_ctx_h ctx);
const char *dplane_res2str(enum zebra_dplane_result res);

enum dplane_op_e dplane_ctx_get_op(const dplane_ctx_h ctx);
const char *dplane_op2str(enum dplane_op_e op);

const struct prefix *dplane_ctx_get_dest(const dplane_ctx_h ctx);

/* Source prefix is a little special - use convention to return NULL
 * to mean "no src prefix"
 */
const struct prefix *dplane_ctx_get_src(const dplane_ctx_h ctx);

bool dplane_ctx_is_update(const dplane_ctx_h ctx);
uint32_t dplane_ctx_get_seq(const dplane_ctx_h ctx);
uint32_t dplane_ctx_get_old_seq(const dplane_ctx_h ctx);
vrf_id_t dplane_ctx_get_vrf(const dplane_ctx_h ctx);
int dplane_ctx_get_type(const dplane_ctx_h ctx);
int dplane_ctx_get_old_type(const dplane_ctx_h ctx);
afi_t dplane_ctx_get_afi(const dplane_ctx_h ctx);
safi_t dplane_ctx_get_safi(const dplane_ctx_h ctx);
uint32_t dplane_ctx_get_table(const dplane_ctx_h ctx);
route_tag_t dplane_ctx_get_tag(const dplane_ctx_h ctx);
route_tag_t dplane_ctx_get_old_tag(const dplane_ctx_h ctx);
uint16_t dplane_ctx_get_instance(const dplane_ctx_h ctx);
uint16_t dplane_ctx_get_old_instance(const dplane_ctx_h ctx);
uint32_t dplane_ctx_get_metric(const dplane_ctx_h ctx);
uint32_t dplane_ctx_get_old_metric(const dplane_ctx_h ctx);
uint32_t dplane_ctx_get_mtu(const dplane_ctx_h ctx);
uint32_t dplane_ctx_get_nh_mtu(const dplane_ctx_h ctx);
uint8_t dplane_ctx_get_distance(const dplane_ctx_h ctx);
uint8_t dplane_ctx_get_old_distance(const dplane_ctx_h ctx);

const struct nexthop_group *dplane_ctx_get_ng(const dplane_ctx_h ctx);
const struct zebra_dplane_info *dplane_ctx_get_ns(const dplane_ctx_h ctx);
const struct nexthop_group *dplane_ctx_get_old_ng(const dplane_ctx_h ctx);

/* Indicates zebra shutdown/exit is in progress. Some operations may be
 * simplified or skipped during shutdown processing.
 */
bool dplane_is_in_shutdown(void);

/*
 * Enqueue route change operations for the dataplane.
 */
enum zebra_dplane_result dplane_route_add(struct route_node *rn,
					  struct route_entry *re);

enum zebra_dplane_result dplane_route_update(struct route_node *rn,
					     struct route_entry *re,
					     struct route_entry *old_re);

enum zebra_dplane_result dplane_route_delete(struct route_node *rn,
					     struct route_entry *re);

/*
 * Vty/cli apis
 */
int dplane_show_helper(struct vty *vty, bool detailed);
int dplane_show_provs_helper(struct vty *vty, bool detailed);


/*
 * Dataplane providers: modules that consume dataplane events.
 */

/* Support string name for a dataplane provider */
#define DPLANE_PROVIDER_NAMELEN 64

/* Priority or ordering values for providers. The idea is that there may be
 * some pre-processing, followed by an external or remote dataplane,
 * followed by the kernel, followed by some post-processing step (such as
 * the fpm output stream.)
 */
enum dplane_provider_prio_e {
	DPLANE_PRIO_NONE = 0,
	DPLANE_PRIO_PREPROCESS,
	DPLANE_PRIO_PRE_KERNEL,
	DPLANE_PRIO_KERNEL,
	DPLANE_PRIO_POSTPROCESS,
	DPLANE_PRIO_LAST
};

/* Provider's entry-point to process a context block */
typedef int (*dplane_provider_process_fp)(dplane_ctx_h ctx);

/* Provider's entry-point for shutdown and cleanup */
typedef int (*dplane_provider_fini_fp)(void);

/* Provider registration */
int dplane_provider_register(const char *name,
			     enum dplane_provider_prio_e prio,
			     dplane_provider_process_fp fp,
			     dplane_provider_fini_fp fini_fp);

/*
 * Results are returned to zebra core via a callback
 */
typedef int (*dplane_results_fp)(const dplane_ctx_h ctx);

/*
 * Zebra registers a results callback with the dataplane. The callback is
 * called in the dataplane thread context, so the expectation is that the
 * context is queued (or that processing is very limited).
 */
int dplane_results_register(dplane_results_fp fp);

/*
 * Initialize the dataplane modules at zebra startup. This is currently called
 * by the rib module.
 */
void zebra_dplane_init(void);

/* Finalize/cleanup apis, one called early as shutdown is starting,
 * one called late at the end of zebra shutdown, and then one called
 * from the zebra main thread to stop the dplane thread free all resources.
 *
 * Zebra expects to try to clean up all vrfs and all routes during
 * shutdown, so the dplane must be available until very late.
 */
void zebra_dplane_pre_finish(void);
void zebra_dplane_finish(void);
void zebra_dplane_shutdown(void);

#endif	/* _ZEBRA_DPLANE_H */
