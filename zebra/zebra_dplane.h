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
 * The dataplane context struct is used to exchange info between the main zebra
 * context and the dataplane module(s). If these are two independent pthreads,
 * they cannot share existing global data structures safely.
 */

/* Define a tailq list type for context blocks. The list is exposed/public,
 * but the internal linkage in the context struct is private, so there
 * are accessor apis that support enqueue and dequeue.
 */
TAILQ_HEAD(dplane_ctx_q, zebra_dplane_ctx);

/* Return a dataplane results context block after use; the caller's pointer will
 * be cleared.
 */
void dplane_ctx_fini(struct zebra_dplane_ctx **pctx);

/* Enqueue a context block to caller's tailq. This exists so that the
 * context struct can remain opaque.
 */
void dplane_ctx_enqueue_tail(struct dplane_ctx_q *q,
			     const struct zebra_dplane_ctx *ctx);

/* Append a list of context blocks to another list - again, just keeping
 * the context struct opaque.
 */
void dplane_ctx_list_append(struct dplane_ctx_q *to_list,
			    struct dplane_ctx_q *from_list);

/* Dequeue a context block from the head of caller's tailq */
struct zebra_dplane_ctx *dplane_ctx_dequeue(struct dplane_ctx_q *q);

/*
 * Accessors for information from the context object
 */
enum zebra_dplane_result dplane_ctx_get_status(
	const struct zebra_dplane_ctx *ctx);
void dplane_ctx_set_status(struct zebra_dplane_ctx *ctx,
			   enum zebra_dplane_result status);
const char *dplane_res2str(enum zebra_dplane_result res);

enum dplane_op_e dplane_ctx_get_op(const struct zebra_dplane_ctx *ctx);
const char *dplane_op2str(enum dplane_op_e op);

const struct prefix *dplane_ctx_get_dest(const struct zebra_dplane_ctx *ctx);

/* Retrieve last/current provider id */
uint32_t dplane_ctx_get_provider(const struct zebra_dplane_ctx *ctx);

/* Providers running before the kernel can control whether a kernel
 * update should be done.
 */
void dplane_ctx_set_skip_kernel(struct zebra_dplane_ctx *ctx);
bool dplane_ctx_is_skip_kernel(const struct zebra_dplane_ctx *ctx);

/* Source prefix is a little special - use convention to return NULL
 * to mean "no src prefix"
 */
const struct prefix *dplane_ctx_get_src(const struct zebra_dplane_ctx *ctx);

bool dplane_ctx_is_update(const struct zebra_dplane_ctx *ctx);
uint32_t dplane_ctx_get_seq(const struct zebra_dplane_ctx *ctx);
uint32_t dplane_ctx_get_old_seq(const struct zebra_dplane_ctx *ctx);
vrf_id_t dplane_ctx_get_vrf(const struct zebra_dplane_ctx *ctx);
int dplane_ctx_get_type(const struct zebra_dplane_ctx *ctx);
int dplane_ctx_get_old_type(const struct zebra_dplane_ctx *ctx);
afi_t dplane_ctx_get_afi(const struct zebra_dplane_ctx *ctx);
safi_t dplane_ctx_get_safi(const struct zebra_dplane_ctx *ctx);
uint32_t dplane_ctx_get_table(const struct zebra_dplane_ctx *ctx);
route_tag_t dplane_ctx_get_tag(const struct zebra_dplane_ctx *ctx);
route_tag_t dplane_ctx_get_old_tag(const struct zebra_dplane_ctx *ctx);
uint16_t dplane_ctx_get_instance(const struct zebra_dplane_ctx *ctx);
uint16_t dplane_ctx_get_old_instance(const struct zebra_dplane_ctx *ctx);
uint32_t dplane_ctx_get_metric(const struct zebra_dplane_ctx *ctx);
uint32_t dplane_ctx_get_old_metric(const struct zebra_dplane_ctx *ctx);
uint32_t dplane_ctx_get_mtu(const struct zebra_dplane_ctx *ctx);
uint32_t dplane_ctx_get_nh_mtu(const struct zebra_dplane_ctx *ctx);
uint8_t dplane_ctx_get_distance(const struct zebra_dplane_ctx *ctx);
uint8_t dplane_ctx_get_old_distance(const struct zebra_dplane_ctx *ctx);

const struct nexthop_group *dplane_ctx_get_ng(
	const struct zebra_dplane_ctx *ctx);
const struct nexthop_group *dplane_ctx_get_old_ng(
	const struct zebra_dplane_ctx *ctx);

const struct zebra_dplane_info *dplane_ctx_get_ns(
	const struct zebra_dplane_ctx *ctx);

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

/* Retrieve the limit on the number of pending, unprocessed updates. */
uint32_t dplane_get_in_queue_limit(void);

/* Configure limit on the number of pending, queued updates. If 'unset', reset
 * to default value.
 */
void dplane_set_in_queue_limit(uint32_t limit, bool set);

/* Retrieve the current queue depth of incoming, unprocessed updates */
uint32_t dplane_get_in_queue_len(void);

/*
 * Vty/cli apis
 */
int dplane_show_helper(struct vty *vty, bool detailed);
int dplane_show_provs_helper(struct vty *vty, bool detailed);


/*
 * Dataplane providers: modules that process or consume dataplane events.
 */

struct zebra_dplane_provider;

/* Support string name for a dataplane provider */
#define DPLANE_PROVIDER_NAMELEN 64

/* Priority or ordering values for providers. The idea is that there may be
 * some pre-processing, followed by an external or remote dataplane,
 * followed by the kernel, followed by some post-processing step (such as
 * the fpm output stream.)
 */
enum dplane_provider_prio {
	DPLANE_PRIO_NONE = 0,
	DPLANE_PRIO_PREPROCESS,
	DPLANE_PRIO_PRE_KERNEL,
	DPLANE_PRIO_KERNEL,
	DPLANE_PRIO_POSTPROCESS,
	DPLANE_PRIO_LAST
};

/* Provider's entry-point for incoming work, called in the context of the
 * dataplane pthread. The dataplane pthread enqueues any new work to the
 * provider's 'inbound' queue, then calls the callback. The dataplane
 * then checks the provider's outbound queue.
 */
typedef int (*dplane_provider_process_fp)(struct zebra_dplane_provider *prov);

/* Provider's entry-point for shutdown and cleanup. Called with 'early'
 * during shutdown, to indicate that the dataplane subsystem is allowing
 * work to move through the providers and finish. When called without 'early',
 * the provider should release all resources (if it has any allocated).
 */
typedef int (*dplane_provider_fini_fp)(struct zebra_dplane_provider *prov,
				       bool early);

/* Flags values used during provider registration. */
#define DPLANE_PROV_FLAGS_DEFAULT  0x0

/* Provider will be spawning its own worker thread */
#define DPLANE_PROV_FLAG_THREADED  0x1


/* Provider registration: ordering or priority value, callbacks, and optional
 * opaque data value.
 */
int dplane_provider_register(const char *name,
			     enum dplane_provider_prio prio,
			     int flags,
			     dplane_provider_process_fp fp,
			     dplane_provider_fini_fp fini_fp,
			     void *data);

/* Accessors for provider attributes */
const char *dplane_provider_get_name(const struct zebra_dplane_provider *prov);
uint32_t dplane_provider_get_id(const struct zebra_dplane_provider *prov);
void *dplane_provider_get_data(const struct zebra_dplane_provider *prov);
bool dplane_provider_is_threaded(const struct zebra_dplane_provider *prov);

/* Providers should limit number of updates per work cycle */
int dplane_provider_get_work_limit(const struct zebra_dplane_provider *prov);

/* Provider api to signal that work/events are available
 * for the dataplane pthread.
 */
int dplane_provider_work_ready(void);

/* Dequeue, maintain associated counter and locking */
struct zebra_dplane_ctx *dplane_provider_dequeue_in_ctx(
	struct zebra_dplane_provider *prov);

/* Dequeue work to a list, maintain counter and locking, return count */
int dplane_provider_dequeue_in_list(struct zebra_dplane_provider *prov,
				    struct dplane_ctx_q *listp);

/* Enqueue, maintain associated counter and locking */
void dplane_provider_enqueue_out_ctx(struct zebra_dplane_provider *prov,
				     struct zebra_dplane_ctx *ctx);

/*
 * Zebra registers a results callback with the dataplane. The callback is
 * called in the dataplane pthread context, so the expectation is that the
 * context is queued for the zebra main pthread or that processing
 * is very limited.
 */
typedef int (*dplane_results_fp)(struct zebra_dplane_ctx *ctx);

int dplane_results_register(dplane_results_fp fp);

/*
 * Initialize the dataplane modules at zebra startup. This is currently called
 * by the rib module.
 */
void zebra_dplane_init(void);

/*
 * Start the dataplane pthread. This step needs to be run later than the
 * 'init' step, in case zebra has fork-ed.
 */
void zebra_dplane_start(void);

/* Finalize/cleanup apis, one called early as shutdown is starting,
 * one called late at the end of zebra shutdown, and then one called
 * from the zebra main pthread to stop the dplane pthread and
 * free all resources.
 *
 * Zebra expects to try to clean up all vrfs and all routes during
 * shutdown, so the dplane must be available until very late.
 */
void zebra_dplane_pre_finish(void);
void zebra_dplane_finish(void);
void zebra_dplane_shutdown(void);

#endif	/* _ZEBRA_DPLANE_H */
