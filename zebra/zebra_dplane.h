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
#include "lib/queue.h"
#include "lib/vlan.h"
#include "zebra/zebra_ns.h"
#include "zebra/rib.h"
#include "zebra/zserv.h"
#include "zebra/zebra_mpls.h"
#include "zebra/zebra_nhg.h"

#ifdef __cplusplus
extern "C" {
#endif

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
	DPLANE_OP_ROUTE_NOTIFY,

	/* Nexthop update */
	DPLANE_OP_NH_INSTALL,
	DPLANE_OP_NH_UPDATE,
	DPLANE_OP_NH_DELETE,

	/* LSP update */
	DPLANE_OP_LSP_INSTALL,
	DPLANE_OP_LSP_UPDATE,
	DPLANE_OP_LSP_DELETE,
	DPLANE_OP_LSP_NOTIFY,

	/* Pseudowire update */
	DPLANE_OP_PW_INSTALL,
	DPLANE_OP_PW_UNINSTALL,

	/* System route notification */
	DPLANE_OP_SYS_ROUTE_ADD,
	DPLANE_OP_SYS_ROUTE_DELETE,

	/* Interface address update */
	DPLANE_OP_ADDR_INSTALL,
	DPLANE_OP_ADDR_UNINSTALL,

	/* MAC address update */
	DPLANE_OP_MAC_INSTALL,
	DPLANE_OP_MAC_DELETE,

	/* EVPN neighbor updates */
	DPLANE_OP_NEIGH_INSTALL,
	DPLANE_OP_NEIGH_UPDATE,
	DPLANE_OP_NEIGH_DELETE,

	/* EVPN VTEP updates */
	DPLANE_OP_VTEP_ADD,
	DPLANE_OP_VTEP_DELETE,
};

/*
 * The vxlan/evpn neighbor management code needs some values to use
 * when programming neighbor changes. Offer some platform-neutral values
 * here for use within the dplane apis and plugins.
 */

/* Neighbor cache flags */
#define DPLANE_NTF_EXT_LEARNED    0x01
#define DPLANE_NTF_ROUTER         0x02

/* Neighbor cache states */
#define DPLANE_NUD_REACHABLE      0x01
#define DPLANE_NUD_STALE          0x02
#define DPLANE_NUD_NOARP          0x04
#define DPLANE_NUD_PROBE          0x08

/* Enable system route notifications */
void dplane_enable_sys_route_notifs(void);

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

/* Allocate a context object */
struct zebra_dplane_ctx *dplane_ctx_alloc(void);

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
void dplane_ctx_set_op(struct zebra_dplane_ctx *ctx, enum dplane_op_e op);
const char *dplane_op2str(enum dplane_op_e op);

const struct prefix *dplane_ctx_get_dest(const struct zebra_dplane_ctx *ctx);
void dplane_ctx_set_dest(struct zebra_dplane_ctx *ctx,
			 const struct prefix *dest);
const char *dplane_ctx_get_ifname(const struct zebra_dplane_ctx *ctx);
ifindex_t dplane_ctx_get_ifindex(const struct zebra_dplane_ctx *ctx);

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
void dplane_ctx_set_src(struct zebra_dplane_ctx *ctx, const struct prefix *src);

bool dplane_ctx_is_update(const struct zebra_dplane_ctx *ctx);
uint32_t dplane_ctx_get_seq(const struct zebra_dplane_ctx *ctx);
uint32_t dplane_ctx_get_old_seq(const struct zebra_dplane_ctx *ctx);
void dplane_ctx_set_vrf(struct zebra_dplane_ctx *ctx, vrf_id_t vrf);
vrf_id_t dplane_ctx_get_vrf(const struct zebra_dplane_ctx *ctx);

bool dplane_ctx_is_from_notif(const struct zebra_dplane_ctx *ctx);
void dplane_ctx_set_notif_provider(struct zebra_dplane_ctx *ctx,
				   uint32_t id);
uint32_t dplane_ctx_get_notif_provider(const struct zebra_dplane_ctx *ctx);

/* Accessors for route update information */
void dplane_ctx_set_type(struct zebra_dplane_ctx *ctx, int type);
int dplane_ctx_get_type(const struct zebra_dplane_ctx *ctx);
int dplane_ctx_get_old_type(const struct zebra_dplane_ctx *ctx);
void dplane_ctx_set_afi(struct zebra_dplane_ctx *ctx, afi_t afi);
afi_t dplane_ctx_get_afi(const struct zebra_dplane_ctx *ctx);
void dplane_ctx_set_safi(struct zebra_dplane_ctx *ctx, safi_t safi);
safi_t dplane_ctx_get_safi(const struct zebra_dplane_ctx *ctx);
void dplane_ctx_set_table(struct zebra_dplane_ctx *ctx, uint32_t table);
uint32_t dplane_ctx_get_table(const struct zebra_dplane_ctx *ctx);
route_tag_t dplane_ctx_get_tag(const struct zebra_dplane_ctx *ctx);
void dplane_ctx_set_tag(struct zebra_dplane_ctx *ctx, route_tag_t tag);
route_tag_t dplane_ctx_get_old_tag(const struct zebra_dplane_ctx *ctx);
uint16_t dplane_ctx_get_instance(const struct zebra_dplane_ctx *ctx);
void dplane_ctx_set_instance(struct zebra_dplane_ctx *ctx, uint16_t instance);
uint16_t dplane_ctx_get_old_instance(const struct zebra_dplane_ctx *ctx);
uint32_t dplane_ctx_get_metric(const struct zebra_dplane_ctx *ctx);
uint32_t dplane_ctx_get_old_metric(const struct zebra_dplane_ctx *ctx);
uint32_t dplane_ctx_get_mtu(const struct zebra_dplane_ctx *ctx);
uint32_t dplane_ctx_get_nh_mtu(const struct zebra_dplane_ctx *ctx);
uint8_t dplane_ctx_get_distance(const struct zebra_dplane_ctx *ctx);
void dplane_ctx_set_distance(struct zebra_dplane_ctx *ctx, uint8_t distance);
uint8_t dplane_ctx_get_old_distance(const struct zebra_dplane_ctx *ctx);

void dplane_ctx_set_nexthops(struct zebra_dplane_ctx *ctx, struct nexthop *nh);
const struct nexthop_group *dplane_ctx_get_ng(
	const struct zebra_dplane_ctx *ctx);
const struct nexthop_group *dplane_ctx_get_old_ng(
	const struct zebra_dplane_ctx *ctx);

/* Accessors for nexthop information */
uint32_t dplane_ctx_get_nhe_id(const struct zebra_dplane_ctx *ctx);
afi_t dplane_ctx_get_nhe_afi(const struct zebra_dplane_ctx *ctx);
vrf_id_t dplane_ctx_get_nhe_vrf_id(const struct zebra_dplane_ctx *ctx);
int dplane_ctx_get_nhe_type(const struct zebra_dplane_ctx *ctx);
const struct nexthop_group *
dplane_ctx_get_nhe_ng(const struct zebra_dplane_ctx *ctx);
const struct nh_grp *
dplane_ctx_get_nhe_nh_grp(const struct zebra_dplane_ctx *ctx);
uint8_t dplane_ctx_get_nhe_nh_grp_count(const struct zebra_dplane_ctx *ctx);

/* Accessors for LSP information */
mpls_label_t dplane_ctx_get_in_label(const struct zebra_dplane_ctx *ctx);
void dplane_ctx_set_in_label(struct zebra_dplane_ctx *ctx,
			     mpls_label_t label);
uint8_t dplane_ctx_get_addr_family(const struct zebra_dplane_ctx *ctx);
void dplane_ctx_set_addr_family(struct zebra_dplane_ctx *ctx,
				uint8_t family);
uint32_t dplane_ctx_get_lsp_flags(const struct zebra_dplane_ctx *ctx);
void dplane_ctx_set_lsp_flags(struct zebra_dplane_ctx *ctx,
			      uint32_t flags);
const zebra_nhlfe_t *dplane_ctx_get_nhlfe(const struct zebra_dplane_ctx *ctx);
zebra_nhlfe_t *dplane_ctx_add_nhlfe(struct zebra_dplane_ctx *ctx,
				    enum lsp_types_t lsp_type,
				    enum nexthop_types_t nh_type,
				    union g_addr *gate,
				    ifindex_t ifindex,
				    mpls_label_t out_label);

const zebra_nhlfe_t *dplane_ctx_get_best_nhlfe(
	const struct zebra_dplane_ctx *ctx);
const zebra_nhlfe_t *dplane_ctx_set_best_nhlfe(struct zebra_dplane_ctx *ctx,
					       zebra_nhlfe_t *nhlfe);
uint32_t dplane_ctx_get_lsp_num_ecmp(const struct zebra_dplane_ctx *ctx);

/* Accessors for pseudowire information */
mpls_label_t dplane_ctx_get_pw_local_label(const struct zebra_dplane_ctx *ctx);
mpls_label_t dplane_ctx_get_pw_remote_label(const struct zebra_dplane_ctx *ctx);
int dplane_ctx_get_pw_type(const struct zebra_dplane_ctx *ctx);
int dplane_ctx_get_pw_af(const struct zebra_dplane_ctx *ctx);
uint32_t dplane_ctx_get_pw_flags(const struct zebra_dplane_ctx *ctx);
int dplane_ctx_get_pw_status(const struct zebra_dplane_ctx *ctx);
const union g_addr *dplane_ctx_get_pw_dest(
	const struct zebra_dplane_ctx *ctx);
const union pw_protocol_fields *dplane_ctx_get_pw_proto(
	const struct zebra_dplane_ctx *ctx);
const struct nexthop_group *dplane_ctx_get_pw_nhg(
	const struct zebra_dplane_ctx *ctx);

/* Accessors for interface information */
uint32_t dplane_ctx_get_intf_metric(const struct zebra_dplane_ctx *ctx);
/* Is interface addr p2p? */
bool dplane_ctx_intf_is_connected(const struct zebra_dplane_ctx *ctx);
bool dplane_ctx_intf_is_secondary(const struct zebra_dplane_ctx *ctx);
bool dplane_ctx_intf_is_broadcast(const struct zebra_dplane_ctx *ctx);
const struct prefix *dplane_ctx_get_intf_addr(
	const struct zebra_dplane_ctx *ctx);
bool dplane_ctx_intf_has_dest(const struct zebra_dplane_ctx *ctx);
const struct prefix *dplane_ctx_get_intf_dest(
	const struct zebra_dplane_ctx *ctx);
bool dplane_ctx_intf_has_label(const struct zebra_dplane_ctx *ctx);
const char *dplane_ctx_get_intf_label(const struct zebra_dplane_ctx *ctx);

/* Accessors for MAC information */
vlanid_t dplane_ctx_mac_get_vlan(const struct zebra_dplane_ctx *ctx);
bool dplane_ctx_mac_is_sticky(const struct zebra_dplane_ctx *ctx);
const struct ethaddr *dplane_ctx_mac_get_addr(
	const struct zebra_dplane_ctx *ctx);
const struct in_addr *dplane_ctx_mac_get_vtep_ip(
	const struct zebra_dplane_ctx *ctx);
ifindex_t dplane_ctx_mac_get_br_ifindex(const struct zebra_dplane_ctx *ctx);

/* Accessors for neighbor information */
const struct ipaddr *dplane_ctx_neigh_get_ipaddr(
	const struct zebra_dplane_ctx *ctx);
const struct ethaddr *dplane_ctx_neigh_get_mac(
	const struct zebra_dplane_ctx *ctx);
uint32_t dplane_ctx_neigh_get_flags(const struct zebra_dplane_ctx *ctx);
uint16_t dplane_ctx_neigh_get_state(const struct zebra_dplane_ctx *ctx);

/* Namespace info - esp. for netlink communication */
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

/* Notify the dplane when system/connected routes change */
enum zebra_dplane_result dplane_sys_route_add(struct route_node *rn,
					      struct route_entry *re);
enum zebra_dplane_result dplane_sys_route_del(struct route_node *rn,
					      struct route_entry *re);

/* Update from an async notification, to bring other fibs up-to-date */
enum zebra_dplane_result dplane_route_notif_update(
	struct route_node *rn,
	struct route_entry *re,
	enum dplane_op_e op,
	struct zebra_dplane_ctx *ctx);


/* Forward ref of nhg_hash_entry */
struct nhg_hash_entry;
/*
 * Enqueue a nexthop change operation for the dataplane.
 */
enum zebra_dplane_result dplane_nexthop_add(struct nhg_hash_entry *nhe);
enum zebra_dplane_result dplane_nexthop_update(struct nhg_hash_entry *nhe);
enum zebra_dplane_result dplane_nexthop_delete(struct nhg_hash_entry *nhe);

/*
 * Enqueue LSP change operations for the dataplane.
 */
enum zebra_dplane_result dplane_lsp_add(zebra_lsp_t *lsp);
enum zebra_dplane_result dplane_lsp_update(zebra_lsp_t *lsp);
enum zebra_dplane_result dplane_lsp_delete(zebra_lsp_t *lsp);

/* Update or un-install resulting from an async notification */
enum zebra_dplane_result dplane_lsp_notif_update(zebra_lsp_t *lsp,
						 enum dplane_op_e op,
						 struct zebra_dplane_ctx *ctx);

/*
 * Enqueue pseudowire operations for the dataplane.
 */
enum zebra_dplane_result dplane_pw_install(struct zebra_pw *pw);
enum zebra_dplane_result dplane_pw_uninstall(struct zebra_pw *pw);

/*
 * Enqueue interface address changes for the dataplane.
 */
enum zebra_dplane_result dplane_intf_addr_set(const struct interface *ifp,
					      const struct connected *ifc);
enum zebra_dplane_result dplane_intf_addr_unset(const struct interface *ifp,
						const struct connected *ifc);

/*
 * Enqueue evpn mac operations for the dataplane.
 */
enum zebra_dplane_result dplane_mac_add(const struct interface *ifp,
					const struct interface *bridge_ifp,
					vlanid_t vid,
					const struct ethaddr *mac,
					struct in_addr vtep_ip,
					bool sticky);

enum zebra_dplane_result dplane_mac_del(const struct interface *ifp,
					const struct interface *bridge_ifp,
					vlanid_t vid,
					const struct ethaddr *mac,
					struct in_addr vtep_ip);

/*
 * Enqueue evpn neighbor updates for the dataplane.
 */
enum zebra_dplane_result dplane_neigh_add(const struct interface *ifp,
					  const struct ipaddr *ip,
					  const struct ethaddr *mac,
					  uint32_t flags);
enum zebra_dplane_result dplane_neigh_update(const struct interface *ifp,
					     const struct ipaddr *ip,
					     const struct ethaddr *mac);
enum zebra_dplane_result dplane_neigh_delete(const struct interface *ifp,
					     const struct ipaddr *ip);

/*
 * Enqueue evpn VTEP updates for the dataplane.
 */
enum zebra_dplane_result dplane_vtep_add(const struct interface *ifp,
					 const struct in_addr *ip,
					 vni_t vni);
enum zebra_dplane_result dplane_vtep_delete(const struct interface *ifp,
					    const struct in_addr *ip,
					    vni_t vni);


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
int dplane_config_write_helper(struct vty *vty);

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

/* Flags values used during provider registration. */
#define DPLANE_PROV_FLAGS_DEFAULT  0x0

/* Provider will be spawning its own worker thread */
#define DPLANE_PROV_FLAG_THREADED  0x1


/* Provider registration: ordering or priority value, callbacks, and optional
 * opaque data value. If 'prov_p', return the newly-allocated provider object
 * on success.
 */

/* Providers offer an entry-point for incoming work, called in the context of
 * the dataplane pthread. The dataplane pthread enqueues any new work to the
 * provider's 'inbound' queue, then calls the callback. The dataplane
 * then checks the provider's outbound queue for completed work.
 */

/*
 * Providers can offer a 'start' callback; if present, the dataplane will
 * call it when it is starting - when its pthread and event-scheduling
 * thread_master are available.
 */

/* Providers can offer an entry-point for shutdown and cleanup. This is called
 * with 'early' during shutdown, to indicate that the dataplane subsystem
 * is allowing work to move through the providers and finish.
 * When called without 'early', the provider should release
 * all resources (if it has any allocated).
 */
int dplane_provider_register(const char *name,
			     enum dplane_provider_prio prio,
			     int flags,
			     int (*start_fp)(struct zebra_dplane_provider *),
			     int (*fp)(struct zebra_dplane_provider *),
			     int (*fini_fp)(struct zebra_dplane_provider *,
					    bool early),
			     void *data,
			     struct zebra_dplane_provider **prov_p);

/* Accessors for provider attributes */
const char *dplane_provider_get_name(const struct zebra_dplane_provider *prov);
uint32_t dplane_provider_get_id(const struct zebra_dplane_provider *prov);
void *dplane_provider_get_data(const struct zebra_dplane_provider *prov);
bool dplane_provider_is_threaded(const struct zebra_dplane_provider *prov);

/* Lock/unlock a provider's mutex - iff the provider was registered with
 * the THREADED flag.
 */
void dplane_provider_lock(struct zebra_dplane_provider *prov);
void dplane_provider_unlock(struct zebra_dplane_provider *prov);

/* Obtain thread_master for dataplane thread */
struct thread_master *dplane_get_thread_master(void);

/* Providers should (generally) limit number of updates per work cycle */
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

/* Enqueue completed work, maintain associated counter and locking */
void dplane_provider_enqueue_out_ctx(struct zebra_dplane_provider *prov,
				     struct zebra_dplane_ctx *ctx);

/* Enqueue a context directly to zebra main. */
void dplane_provider_enqueue_to_zebra(struct zebra_dplane_ctx *ctx);

/*
 * Initialize the dataplane modules at zebra startup. This is currently called
 * by the rib module. Zebra registers a results callback with the dataplane.
 * The callback is called in the dataplane pthread context,
 * so the expectation is that the contexts are queued for the zebra
 * main pthread.
 */
void zebra_dplane_init(int (*) (struct dplane_ctx_q *));

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

#ifdef __cplusplus
}
#endif

#endif	/* _ZEBRA_DPLANE_H */
