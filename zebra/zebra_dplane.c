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

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "lib/libfrr.h"
#include "lib/debug.h"
#include "lib/frratomic.h"
#include "lib/frr_pthread.h"
#include "lib/memory.h"
#include "lib/queue.h"
#include "lib/zebra.h"
#include "zebra/zebra_router.h"
#include "zebra/zebra_dplane.h"
#include "zebra/zebra_vxlan_private.h"
#include "zebra/zebra_mpls.h"
#include "zebra/rt.h"
#include "zebra/debug.h"
#include "zebra/zebra_pbr.h"
#include "printfrr.h"

/* Memory type for context blocks */
DEFINE_MTYPE_STATIC(ZEBRA, DP_CTX, "Zebra DPlane Ctx");
DEFINE_MTYPE_STATIC(ZEBRA, DP_INTF, "Zebra DPlane Intf");
DEFINE_MTYPE_STATIC(ZEBRA, DP_PROV, "Zebra DPlane Provider");
DEFINE_MTYPE_STATIC(ZEBRA, DP_NETFILTER, "Zebra Netfilter Internal Object");

#ifndef AOK
#  define AOK 0
#endif

/* Control for collection of extra interface info with route updates; a plugin
 * can enable the extra info via a dplane api.
 */
static bool dplane_collect_extra_intf_info;

/* Enable test dataplane provider */
/*#define DPLANE_TEST_PROVIDER 1 */

/* Default value for max queued incoming updates */
const uint32_t DPLANE_DEFAULT_MAX_QUEUED = 200;

/* Default value for new work per cycle */
const uint32_t DPLANE_DEFAULT_NEW_WORK = 100;

/* Validation check macro for context blocks */
/* #define DPLANE_DEBUG 1 */

#ifdef DPLANE_DEBUG

#  define DPLANE_CTX_VALID(p)	\
		assert((p) != NULL)

#else

#  define DPLANE_CTX_VALID(p)

#endif	/* DPLANE_DEBUG */

/*
 * Nexthop information captured for nexthop/nexthop group updates
 */
struct dplane_nexthop_info {
	uint32_t id;
	uint32_t old_id;
	afi_t afi;
	vrf_id_t vrf_id;
	int type;

	struct nexthop_group ng;
	struct nh_grp nh_grp[MULTIPATH_NUM];
	uint8_t nh_grp_count;
};

/*
 * Optional extra info about interfaces used in route updates' nexthops.
 */
struct dplane_intf_extra {
	vrf_id_t vrf_id;
	uint32_t ifindex;
	uint32_t flags;
	uint32_t status;

	TAILQ_ENTRY(dplane_intf_extra) link;
};

/*
 * Route information captured for route updates.
 */
struct dplane_route_info {

	/* Dest and (optional) source prefixes */
	struct prefix zd_dest;
	struct prefix zd_src;

	afi_t zd_afi;
	safi_t zd_safi;

	int zd_type;
	int zd_old_type;

	route_tag_t zd_tag;
	route_tag_t zd_old_tag;
	uint32_t zd_metric;
	uint32_t zd_old_metric;

	uint16_t zd_instance;
	uint16_t zd_old_instance;

	uint8_t zd_distance;
	uint8_t zd_old_distance;

	uint32_t zd_mtu;
	uint32_t zd_nexthop_mtu;

	/* Nexthop hash entry info */
	struct dplane_nexthop_info nhe;

	/* Nexthops */
	uint32_t zd_nhg_id;
	struct nexthop_group zd_ng;

	/* Backup nexthops (if present) */
	struct nexthop_group backup_ng;

	/* "Previous" nexthops, used only in route updates without netlink */
	struct nexthop_group zd_old_ng;
	struct nexthop_group old_backup_ng;

	/* Optional list of extra interface info */
	TAILQ_HEAD(dp_intf_extra_q, dplane_intf_extra) intf_extra_q;
};

/*
 * Pseudowire info for the dataplane
 */
struct dplane_pw_info {
	int type;
	int af;
	int status;
	uint32_t flags;
	union g_addr dest;
	mpls_label_t local_label;
	mpls_label_t remote_label;

	/* Nexthops */
	struct nexthop_group nhg;

	union pw_protocol_fields fields;
};

/*
 * Bridge port info for the dataplane
 */
struct dplane_br_port_info {
	uint32_t sph_filter_cnt;
	struct in_addr sph_filters[ES_VTEP_MAX_CNT];
	/* DPLANE_BR_PORT_XXX - see zebra_dplane.h*/
	uint32_t flags;
	uint32_t backup_nhg_id;
};

/*
 * Interface/prefix info for the dataplane
 */
struct dplane_intf_info {

	uint32_t metric;
	uint32_t flags;

#define DPLANE_INTF_CONNECTED   (1 << 0) /* Connected peer, p2p */
#define DPLANE_INTF_SECONDARY   (1 << 1)
#define DPLANE_INTF_BROADCAST   (1 << 2)
#define DPLANE_INTF_HAS_DEST    DPLANE_INTF_CONNECTED
#define DPLANE_INTF_HAS_LABEL   (1 << 4)

	/* Interface address/prefix */
	struct prefix prefix;

	/* Dest address, for p2p, or broadcast prefix */
	struct prefix dest_prefix;

	char *label;
	char label_buf[32];
};

/*
 * EVPN MAC address info for the dataplane.
 */
struct dplane_mac_info {
	vlanid_t vid;
	ifindex_t br_ifindex;
	struct ethaddr mac;
	struct in_addr vtep_ip;
	bool is_sticky;
	uint32_t nhg_id;
	uint32_t update_flags;
};

/*
 * Neighbor info for the dataplane
 */
struct dplane_neigh_info {
	struct ipaddr ip_addr;
	union {
		struct ethaddr mac;
		struct ipaddr ip_addr;
	} link;
	uint32_t flags;
	uint16_t state;
	uint32_t update_flags;
};

/*
 * Neighbor Table
 */
struct dplane_neigh_table {
	uint8_t family;
	uint32_t app_probes;
	uint32_t ucast_probes;
	uint32_t mcast_probes;
};

/*
 * Policy based routing rule info for the dataplane
 */
struct dplane_ctx_rule {
	uint32_t priority;

	/* The route table pointed by this rule */
	uint32_t table;

	/* Filter criteria */
	uint32_t filter_bm;
	uint32_t fwmark;
	uint8_t dsfield;
	struct prefix src_ip;
	struct prefix dst_ip;
	char ifname[INTERFACE_NAMSIZ + 1];
};

struct dplane_rule_info {
	/*
	 * Originating zclient sock fd, so we can know who to send
	 * back to.
	 */
	int sock;

	int unique;
	int seq;

	struct dplane_ctx_rule new;
	struct dplane_ctx_rule old;
};

struct dplane_gre_ctx {
	uint32_t link_ifindex;
};
/*
 * The context block used to exchange info about route updates across
 * the boundary between the zebra main context (and pthread) and the
 * dataplane layer (and pthread).
 */
struct zebra_dplane_ctx {

	/* Operation code */
	enum dplane_op_e zd_op;

	/* Status on return */
	enum zebra_dplane_result zd_status;

	/* Dplane provider id */
	uint32_t zd_provider;

	/* Flags - used by providers, e.g. */
	int zd_flags;

	bool zd_is_update;

	uint32_t zd_seq;
	uint32_t zd_old_seq;

	/* Some updates may be generated by notifications: allow the
	 * plugin to notice and ignore results from its own notifications.
	 */
	uint32_t zd_notif_provider;

	/* TODO -- internal/sub-operation status? */
	enum zebra_dplane_result zd_remote_status;
	enum zebra_dplane_result zd_kernel_status;

	vrf_id_t zd_vrf_id;
	uint32_t zd_table_id;

	char zd_ifname[INTERFACE_NAMSIZ];
	ifindex_t zd_ifindex;

	/* Support info for different kinds of updates */
	union {
		struct dplane_route_info rinfo;
		zebra_lsp_t lsp;
		struct dplane_pw_info pw;
		struct dplane_br_port_info br_port;
		struct dplane_intf_info intf;
		struct dplane_mac_info macinfo;
		struct dplane_neigh_info neigh;
		struct dplane_rule_info rule;
		struct zebra_pbr_iptable iptable;
		struct zebra_pbr_ipset ipset;
		union {
			struct zebra_pbr_ipset_entry entry;
			struct zebra_pbr_ipset_info info;
		} ipset_entry;
		struct dplane_neigh_table neightable;
		struct dplane_gre_ctx gre;
	} u;

	/* Namespace info, used especially for netlink kernel communication */
	struct zebra_dplane_info zd_ns_info;

	/* Embedded list linkage */
	TAILQ_ENTRY(zebra_dplane_ctx) zd_q_entries;
};

/* Flag that can be set by a pre-kernel provider as a signal that an update
 * should bypass the kernel.
 */
#define DPLANE_CTX_FLAG_NO_KERNEL 0x01


/*
 * Registration block for one dataplane provider.
 */
struct zebra_dplane_provider {
	/* Name */
	char dp_name[DPLANE_PROVIDER_NAMELEN + 1];

	/* Priority, for ordering among providers */
	uint8_t dp_priority;

	/* Id value */
	uint32_t dp_id;

	/* Mutex */
	pthread_mutex_t dp_mutex;

	/* Plugin-provided extra data */
	void *dp_data;

	/* Flags */
	int dp_flags;

	int (*dp_start)(struct zebra_dplane_provider *prov);

	int (*dp_fp)(struct zebra_dplane_provider *prov);

	int (*dp_fini)(struct zebra_dplane_provider *prov, bool early_p);

	_Atomic uint32_t dp_in_counter;
	_Atomic uint32_t dp_in_queued;
	_Atomic uint32_t dp_in_max;
	_Atomic uint32_t dp_out_counter;
	_Atomic uint32_t dp_out_queued;
	_Atomic uint32_t dp_out_max;
	_Atomic uint32_t dp_error_counter;

	/* Queue of contexts inbound to the provider */
	struct dplane_ctx_q dp_ctx_in_q;

	/* Queue of completed contexts outbound from the provider back
	 * towards the dataplane module.
	 */
	struct dplane_ctx_q dp_ctx_out_q;

	/* Embedded list linkage for provider objects */
	TAILQ_ENTRY(zebra_dplane_provider) dp_prov_link;
};

/*
 * Globals
 */
static struct zebra_dplane_globals {
	/* Mutex to control access to dataplane components */
	pthread_mutex_t dg_mutex;

	/* Results callback registered by zebra 'core' */
	int (*dg_results_cb)(struct dplane_ctx_q *ctxlist);

	/* Sentinel for beginning of shutdown */
	volatile bool dg_is_shutdown;

	/* Sentinel for end of shutdown */
	volatile bool dg_run;

	/* Update context queue inbound to the dataplane */
	TAILQ_HEAD(zdg_ctx_q, zebra_dplane_ctx) dg_update_ctx_q;

	/* Ordered list of providers */
	TAILQ_HEAD(zdg_prov_q, zebra_dplane_provider) dg_providers_q;

	/* Counter used to assign internal ids to providers */
	uint32_t dg_provider_id;

	/* Limit number of pending, unprocessed updates */
	_Atomic uint32_t dg_max_queued_updates;

	/* Control whether system route notifications should be produced. */
	bool dg_sys_route_notifs;

	/* Limit number of new updates dequeued at once, to pace an
	 * incoming burst.
	 */
	uint32_t dg_updates_per_cycle;

	_Atomic uint32_t dg_routes_in;
	_Atomic uint32_t dg_routes_queued;
	_Atomic uint32_t dg_routes_queued_max;
	_Atomic uint32_t dg_route_errors;
	_Atomic uint32_t dg_other_errors;

	_Atomic uint32_t dg_nexthops_in;
	_Atomic uint32_t dg_nexthop_errors;

	_Atomic uint32_t dg_lsps_in;
	_Atomic uint32_t dg_lsp_errors;

	_Atomic uint32_t dg_pws_in;
	_Atomic uint32_t dg_pw_errors;

	_Atomic uint32_t dg_br_port_in;
	_Atomic uint32_t dg_br_port_errors;

	_Atomic uint32_t dg_intf_addrs_in;
	_Atomic uint32_t dg_intf_addr_errors;

	_Atomic uint32_t dg_macs_in;
	_Atomic uint32_t dg_mac_errors;

	_Atomic uint32_t dg_neighs_in;
	_Atomic uint32_t dg_neigh_errors;

	_Atomic uint32_t dg_rules_in;
	_Atomic uint32_t dg_rule_errors;

	_Atomic uint32_t dg_update_yields;

	_Atomic uint32_t dg_iptable_in;
	_Atomic uint32_t dg_iptable_errors;

	_Atomic uint32_t dg_ipset_in;
	_Atomic uint32_t dg_ipset_errors;
	_Atomic uint32_t dg_ipset_entry_in;
	_Atomic uint32_t dg_ipset_entry_errors;

	_Atomic uint32_t dg_neightable_in;
	_Atomic uint32_t dg_neightable_errors;

	_Atomic uint32_t dg_gre_set_in;
	_Atomic uint32_t dg_gre_set_errors;

	/* Dataplane pthread */
	struct frr_pthread *dg_pthread;

	/* Event-delivery context 'master' for the dplane */
	struct thread_master *dg_master;

	/* Event/'thread' pointer for queued updates */
	struct thread *dg_t_update;

	/* Event pointer for pending shutdown check loop */
	struct thread *dg_t_shutdown_check;

} zdplane_info;

/*
 * Lock and unlock for interactions with the zebra 'core' pthread
 */
#define DPLANE_LOCK() pthread_mutex_lock(&zdplane_info.dg_mutex)
#define DPLANE_UNLOCK() pthread_mutex_unlock(&zdplane_info.dg_mutex)


/*
 * Lock and unlock for individual providers
 */
#define DPLANE_PROV_LOCK(p)   pthread_mutex_lock(&((p)->dp_mutex))
#define DPLANE_PROV_UNLOCK(p) pthread_mutex_unlock(&((p)->dp_mutex))

/* Prototypes */
static int dplane_thread_loop(struct thread *event);
static void dplane_info_from_zns(struct zebra_dplane_info *ns_info,
				 struct zebra_ns *zns);
static enum zebra_dplane_result lsp_update_internal(zebra_lsp_t *lsp,
						    enum dplane_op_e op);
static enum zebra_dplane_result pw_update_internal(struct zebra_pw *pw,
						   enum dplane_op_e op);
static enum zebra_dplane_result intf_addr_update_internal(
	const struct interface *ifp, const struct connected *ifc,
	enum dplane_op_e op);
static enum zebra_dplane_result mac_update_common(
	enum dplane_op_e op, const struct interface *ifp,
	const struct interface *br_ifp,
	vlanid_t vid, const struct ethaddr *mac,
	struct in_addr vtep_ip,	bool sticky, uint32_t nhg_id,
	uint32_t update_flags);
static enum zebra_dplane_result
neigh_update_internal(enum dplane_op_e op, const struct interface *ifp,
		      const void *link, int link_family,
		      const struct ipaddr *ip, uint32_t flags, uint16_t state,
		      uint32_t update_flags, int protocol);

/*
 * Public APIs
 */

/* Obtain thread_master for dataplane thread */
struct thread_master *dplane_get_thread_master(void)
{
	return zdplane_info.dg_master;
}

/*
 * Allocate a dataplane update context
 */
struct zebra_dplane_ctx *dplane_ctx_alloc(void)
{
	struct zebra_dplane_ctx *p;

	/* TODO -- just alloc'ing memory, but would like to maintain
	 * a pool
	 */
	p = XCALLOC(MTYPE_DP_CTX, sizeof(struct zebra_dplane_ctx));

	return p;
}

/* Enable system route notifications */
void dplane_enable_sys_route_notifs(void)
{
	zdplane_info.dg_sys_route_notifs = true;
}

/*
 * Clean up dependent/internal allocations inside a context object
 */
static void dplane_ctx_free_internal(struct zebra_dplane_ctx *ctx)
{
	struct dplane_intf_extra *if_extra, *if_tmp;

	/*
	 * Some internal allocations may need to be freed, depending on
	 * the type of info captured in the ctx.
	 */
	switch (ctx->zd_op) {
	case DPLANE_OP_ROUTE_INSTALL:
	case DPLANE_OP_ROUTE_UPDATE:
	case DPLANE_OP_ROUTE_DELETE:
	case DPLANE_OP_SYS_ROUTE_ADD:
	case DPLANE_OP_SYS_ROUTE_DELETE:
	case DPLANE_OP_ROUTE_NOTIFY:

		/* Free allocated nexthops */
		if (ctx->u.rinfo.zd_ng.nexthop) {
			/* This deals with recursive nexthops too */
			nexthops_free(ctx->u.rinfo.zd_ng.nexthop);

			ctx->u.rinfo.zd_ng.nexthop = NULL;
		}

		/* Free backup info also (if present) */
		if (ctx->u.rinfo.backup_ng.nexthop) {
			/* This deals with recursive nexthops too */
			nexthops_free(ctx->u.rinfo.backup_ng.nexthop);

			ctx->u.rinfo.backup_ng.nexthop = NULL;
		}

		if (ctx->u.rinfo.zd_old_ng.nexthop) {
			/* This deals with recursive nexthops too */
			nexthops_free(ctx->u.rinfo.zd_old_ng.nexthop);

			ctx->u.rinfo.zd_old_ng.nexthop = NULL;
		}

		if (ctx->u.rinfo.old_backup_ng.nexthop) {
			/* This deals with recursive nexthops too */
			nexthops_free(ctx->u.rinfo.old_backup_ng.nexthop);

			ctx->u.rinfo.old_backup_ng.nexthop = NULL;
		}

		/* Optional extra interface info */
		TAILQ_FOREACH_SAFE(if_extra, &ctx->u.rinfo.intf_extra_q,
				   link, if_tmp) {
			TAILQ_REMOVE(&ctx->u.rinfo.intf_extra_q, if_extra,
				     link);
			XFREE(MTYPE_DP_INTF, if_extra);
		}

		break;

	case DPLANE_OP_NH_INSTALL:
	case DPLANE_OP_NH_UPDATE:
	case DPLANE_OP_NH_DELETE: {
		if (ctx->u.rinfo.nhe.ng.nexthop) {
			/* This deals with recursive nexthops too */
			nexthops_free(ctx->u.rinfo.nhe.ng.nexthop);

			ctx->u.rinfo.nhe.ng.nexthop = NULL;
		}
		break;
	}

	case DPLANE_OP_LSP_INSTALL:
	case DPLANE_OP_LSP_UPDATE:
	case DPLANE_OP_LSP_DELETE:
	case DPLANE_OP_LSP_NOTIFY:
	{
		zebra_nhlfe_t *nhlfe;

		/* Unlink and free allocated NHLFEs */
		frr_each_safe(nhlfe_list, &ctx->u.lsp.nhlfe_list, nhlfe) {
			nhlfe_list_del(&ctx->u.lsp.nhlfe_list, nhlfe);
			zebra_mpls_nhlfe_free(nhlfe);
		}

		/* Unlink and free allocated backup NHLFEs, if present */
		frr_each_safe(nhlfe_list,
			      &(ctx->u.lsp.backup_nhlfe_list), nhlfe) {
			nhlfe_list_del(&ctx->u.lsp.backup_nhlfe_list,
				       nhlfe);
			zebra_mpls_nhlfe_free(nhlfe);
		}

		/* Clear pointers in lsp struct, in case we're caching
		 * free context structs.
		 */
		nhlfe_list_init(&ctx->u.lsp.nhlfe_list);
		ctx->u.lsp.best_nhlfe = NULL;
		nhlfe_list_init(&ctx->u.lsp.backup_nhlfe_list);

		break;
	}

	case DPLANE_OP_PW_INSTALL:
	case DPLANE_OP_PW_UNINSTALL:
		/* Free allocated nexthops */
		if (ctx->u.pw.nhg.nexthop) {
			/* This deals with recursive nexthops too */
			nexthops_free(ctx->u.pw.nhg.nexthop);

			ctx->u.pw.nhg.nexthop = NULL;
		}
		break;

	case DPLANE_OP_ADDR_INSTALL:
	case DPLANE_OP_ADDR_UNINSTALL:
		/* Maybe free label string, if allocated */
		if (ctx->u.intf.label != NULL &&
		    ctx->u.intf.label != ctx->u.intf.label_buf) {
			free(ctx->u.intf.label);
			ctx->u.intf.label = NULL;
		}
		break;

	case DPLANE_OP_MAC_INSTALL:
	case DPLANE_OP_MAC_DELETE:
	case DPLANE_OP_NEIGH_INSTALL:
	case DPLANE_OP_NEIGH_UPDATE:
	case DPLANE_OP_NEIGH_DELETE:
	case DPLANE_OP_VTEP_ADD:
	case DPLANE_OP_VTEP_DELETE:
	case DPLANE_OP_RULE_ADD:
	case DPLANE_OP_RULE_DELETE:
	case DPLANE_OP_RULE_UPDATE:
	case DPLANE_OP_NEIGH_DISCOVER:
	case DPLANE_OP_BR_PORT_UPDATE:
	case DPLANE_OP_NEIGH_IP_INSTALL:
	case DPLANE_OP_NEIGH_IP_DELETE:
	case DPLANE_OP_NONE:
	case DPLANE_OP_IPSET_ADD:
	case DPLANE_OP_IPSET_DELETE:
		break;

	case DPLANE_OP_IPSET_ENTRY_ADD:
	case DPLANE_OP_IPSET_ENTRY_DELETE:
		break;
	case DPLANE_OP_NEIGH_TABLE_UPDATE:
		break;
	case DPLANE_OP_IPTABLE_ADD:
	case DPLANE_OP_IPTABLE_DELETE:
		if (ctx->u.iptable.interface_name_list) {
			struct listnode *node, *nnode;
			char *ifname;

			for (ALL_LIST_ELEMENTS(
				     ctx->u.iptable.interface_name_list, node,
				     nnode, ifname)) {
				LISTNODE_DETACH(
					ctx->u.iptable.interface_name_list,
					node);
				XFREE(MTYPE_DP_NETFILTER, ifname);
			}
			list_delete(&ctx->u.iptable.interface_name_list);
		}
		break;
	case DPLANE_OP_GRE_SET:
		break;
	}
}

/*
 * Free a dataplane results context.
 */
static void dplane_ctx_free(struct zebra_dplane_ctx **pctx)
{
	if (pctx == NULL)
		return;

	DPLANE_CTX_VALID(*pctx);

	/* TODO -- just freeing memory, but would like to maintain
	 * a pool
	 */

	/* Some internal allocations may need to be freed, depending on
	 * the type of info captured in the ctx.
	 */
	dplane_ctx_free_internal(*pctx);

	XFREE(MTYPE_DP_CTX, *pctx);
}

/*
 * Reset an allocated context object for re-use. All internal allocations are
 * freed and the context is memset.
 */
void dplane_ctx_reset(struct zebra_dplane_ctx *ctx)
{
	dplane_ctx_free_internal(ctx);
	memset(ctx, 0, sizeof(*ctx));
}

/*
 * Return a context block to the dplane module after processing
 */
void dplane_ctx_fini(struct zebra_dplane_ctx **pctx)
{
	/* TODO -- maintain pool; for now, just free */
	dplane_ctx_free(pctx);
}

/* Enqueue a context block */
void dplane_ctx_enqueue_tail(struct dplane_ctx_q *q,
			     const struct zebra_dplane_ctx *ctx)
{
	TAILQ_INSERT_TAIL(q, (struct zebra_dplane_ctx *)ctx, zd_q_entries);
}

/* Append a list of context blocks to another list */
void dplane_ctx_list_append(struct dplane_ctx_q *to_list,
			    struct dplane_ctx_q *from_list)
{
	if (TAILQ_FIRST(from_list)) {
		TAILQ_CONCAT(to_list, from_list, zd_q_entries);

		/* And clear 'from' list */
		TAILQ_INIT(from_list);
	}
}

/* Dequeue a context block from the head of a list */
struct zebra_dplane_ctx *dplane_ctx_dequeue(struct dplane_ctx_q *q)
{
	struct zebra_dplane_ctx *ctx = TAILQ_FIRST(q);

	if (ctx)
		TAILQ_REMOVE(q, ctx, zd_q_entries);

	return ctx;
}

/*
 * Accessors for information from the context object
 */
enum zebra_dplane_result dplane_ctx_get_status(
	const struct zebra_dplane_ctx *ctx)
{
	DPLANE_CTX_VALID(ctx);

	return ctx->zd_status;
}

void dplane_ctx_set_status(struct zebra_dplane_ctx *ctx,
			   enum zebra_dplane_result status)
{
	DPLANE_CTX_VALID(ctx);

	ctx->zd_status = status;
}

/* Retrieve last/current provider id */
uint32_t dplane_ctx_get_provider(const struct zebra_dplane_ctx *ctx)
{
	DPLANE_CTX_VALID(ctx);
	return ctx->zd_provider;
}

/* Providers run before the kernel can control whether a kernel
 * update should be done.
 */
void dplane_ctx_set_skip_kernel(struct zebra_dplane_ctx *ctx)
{
	DPLANE_CTX_VALID(ctx);

	SET_FLAG(ctx->zd_flags, DPLANE_CTX_FLAG_NO_KERNEL);
}

bool dplane_ctx_is_skip_kernel(const struct zebra_dplane_ctx *ctx)
{
	DPLANE_CTX_VALID(ctx);

	return CHECK_FLAG(ctx->zd_flags, DPLANE_CTX_FLAG_NO_KERNEL);
}

void dplane_ctx_set_op(struct zebra_dplane_ctx *ctx, enum dplane_op_e op)
{
	DPLANE_CTX_VALID(ctx);
	ctx->zd_op = op;
}

enum dplane_op_e dplane_ctx_get_op(const struct zebra_dplane_ctx *ctx)
{
	DPLANE_CTX_VALID(ctx);

	return ctx->zd_op;
}

const char *dplane_op2str(enum dplane_op_e op)
{
	const char *ret = "UNKNOWN";

	switch (op) {
	case DPLANE_OP_NONE:
		ret = "NONE";
		break;

	/* Route update */
	case DPLANE_OP_ROUTE_INSTALL:
		ret = "ROUTE_INSTALL";
		break;
	case DPLANE_OP_ROUTE_UPDATE:
		ret = "ROUTE_UPDATE";
		break;
	case DPLANE_OP_ROUTE_DELETE:
		ret = "ROUTE_DELETE";
		break;
	case DPLANE_OP_ROUTE_NOTIFY:
		ret = "ROUTE_NOTIFY";
		break;

	/* Nexthop update */
	case DPLANE_OP_NH_INSTALL:
		ret = "NH_INSTALL";
		break;
	case DPLANE_OP_NH_UPDATE:
		ret = "NH_UPDATE";
		break;
	case DPLANE_OP_NH_DELETE:
		ret = "NH_DELETE";
		break;

	case DPLANE_OP_LSP_INSTALL:
		ret = "LSP_INSTALL";
		break;
	case DPLANE_OP_LSP_UPDATE:
		ret = "LSP_UPDATE";
		break;
	case DPLANE_OP_LSP_DELETE:
		ret = "LSP_DELETE";
		break;
	case DPLANE_OP_LSP_NOTIFY:
		ret = "LSP_NOTIFY";
		break;

	case DPLANE_OP_PW_INSTALL:
		ret = "PW_INSTALL";
		break;
	case DPLANE_OP_PW_UNINSTALL:
		ret = "PW_UNINSTALL";
		break;

	case DPLANE_OP_SYS_ROUTE_ADD:
		ret = "SYS_ROUTE_ADD";
		break;
	case DPLANE_OP_SYS_ROUTE_DELETE:
		ret = "SYS_ROUTE_DEL";
		break;

	case DPLANE_OP_BR_PORT_UPDATE:
		ret = "BR_PORT_UPDATE";
		break;

	case DPLANE_OP_ADDR_INSTALL:
		ret = "ADDR_INSTALL";
		break;
	case DPLANE_OP_ADDR_UNINSTALL:
		ret = "ADDR_UNINSTALL";
		break;

	case DPLANE_OP_MAC_INSTALL:
		ret = "MAC_INSTALL";
		break;
	case DPLANE_OP_MAC_DELETE:
		ret = "MAC_DELETE";
		break;

	case DPLANE_OP_NEIGH_INSTALL:
		ret = "NEIGH_INSTALL";
		break;
	case DPLANE_OP_NEIGH_UPDATE:
		ret = "NEIGH_UPDATE";
		break;
	case DPLANE_OP_NEIGH_DELETE:
		ret = "NEIGH_DELETE";
		break;
	case DPLANE_OP_VTEP_ADD:
		ret = "VTEP_ADD";
		break;
	case DPLANE_OP_VTEP_DELETE:
		ret = "VTEP_DELETE";
		break;

	case DPLANE_OP_RULE_ADD:
		ret = "RULE_ADD";
		break;
	case DPLANE_OP_RULE_DELETE:
		ret = "RULE_DELETE";
		break;
	case DPLANE_OP_RULE_UPDATE:
		ret = "RULE_UPDATE";
		break;

	case DPLANE_OP_NEIGH_DISCOVER:
		ret = "NEIGH_DISCOVER";
		break;

	case DPLANE_OP_IPTABLE_ADD:
		ret = "IPTABLE_ADD";
		break;
	case DPLANE_OP_IPTABLE_DELETE:
		ret = "IPTABLE_DELETE";
		break;
	case DPLANE_OP_IPSET_ADD:
		ret = "IPSET_ADD";
		break;
	case DPLANE_OP_IPSET_DELETE:
		ret = "IPSET_DELETE";
		break;
	case DPLANE_OP_IPSET_ENTRY_ADD:
		ret = "IPSET_ENTRY_ADD";
		break;
	case DPLANE_OP_IPSET_ENTRY_DELETE:
		ret = "IPSET_ENTRY_DELETE";
		break;
	case DPLANE_OP_NEIGH_IP_INSTALL:
		ret = "NEIGH_IP_INSTALL";
		break;
	case DPLANE_OP_NEIGH_IP_DELETE:
		ret = "NEIGH_IP_DELETE";
		break;
	case DPLANE_OP_NEIGH_TABLE_UPDATE:
		ret = "NEIGH_TABLE_UPDATE";
		break;

	case DPLANE_OP_GRE_SET:
		ret = "GRE_SET";
		break;
	}

	return ret;
}

const char *dplane_res2str(enum zebra_dplane_result res)
{
	const char *ret = "<Unknown>";

	switch (res) {
	case ZEBRA_DPLANE_REQUEST_FAILURE:
		ret = "FAILURE";
		break;
	case ZEBRA_DPLANE_REQUEST_QUEUED:
		ret = "QUEUED";
		break;
	case ZEBRA_DPLANE_REQUEST_SUCCESS:
		ret = "SUCCESS";
		break;
	}

	return ret;
}

void dplane_ctx_set_dest(struct zebra_dplane_ctx *ctx,
			 const struct prefix *dest)
{
	DPLANE_CTX_VALID(ctx);

	prefix_copy(&(ctx->u.rinfo.zd_dest), dest);
}

const struct prefix *dplane_ctx_get_dest(const struct zebra_dplane_ctx *ctx)
{
	DPLANE_CTX_VALID(ctx);

	return &(ctx->u.rinfo.zd_dest);
}

void dplane_ctx_set_src(struct zebra_dplane_ctx *ctx, const struct prefix *src)
{
	DPLANE_CTX_VALID(ctx);

	if (src)
		prefix_copy(&(ctx->u.rinfo.zd_src), src);
	else
		memset(&(ctx->u.rinfo.zd_src), 0, sizeof(struct prefix));
}

/* Source prefix is a little special - return NULL for "no src prefix" */
const struct prefix *dplane_ctx_get_src(const struct zebra_dplane_ctx *ctx)
{
	DPLANE_CTX_VALID(ctx);

	if (ctx->u.rinfo.zd_src.prefixlen == 0 &&
	    IN6_IS_ADDR_UNSPECIFIED(&(ctx->u.rinfo.zd_src.u.prefix6))) {
		return NULL;
	} else {
		return &(ctx->u.rinfo.zd_src);
	}
}

bool dplane_ctx_is_update(const struct zebra_dplane_ctx *ctx)
{
	DPLANE_CTX_VALID(ctx);

	return ctx->zd_is_update;
}

uint32_t dplane_ctx_get_seq(const struct zebra_dplane_ctx *ctx)
{
	DPLANE_CTX_VALID(ctx);

	return ctx->zd_seq;
}

uint32_t dplane_ctx_get_old_seq(const struct zebra_dplane_ctx *ctx)
{
	DPLANE_CTX_VALID(ctx);

	return ctx->zd_old_seq;
}

void dplane_ctx_set_vrf(struct zebra_dplane_ctx *ctx, vrf_id_t vrf)
{
	DPLANE_CTX_VALID(ctx);

	ctx->zd_vrf_id = vrf;
}

vrf_id_t dplane_ctx_get_vrf(const struct zebra_dplane_ctx *ctx)
{
	DPLANE_CTX_VALID(ctx);

	return ctx->zd_vrf_id;
}

bool dplane_ctx_is_from_notif(const struct zebra_dplane_ctx *ctx)
{
	DPLANE_CTX_VALID(ctx);

	return (ctx->zd_notif_provider != 0);
}

uint32_t dplane_ctx_get_notif_provider(const struct zebra_dplane_ctx *ctx)
{
	DPLANE_CTX_VALID(ctx);

	return ctx->zd_notif_provider;
}

void dplane_ctx_set_notif_provider(struct zebra_dplane_ctx *ctx,
				       uint32_t id)
{
	DPLANE_CTX_VALID(ctx);

	ctx->zd_notif_provider = id;
}

const char *dplane_ctx_get_ifname(const struct zebra_dplane_ctx *ctx)
{
	DPLANE_CTX_VALID(ctx);

	return ctx->zd_ifname;
}

void dplane_ctx_set_ifname(struct zebra_dplane_ctx *ctx, const char *ifname)
{
	DPLANE_CTX_VALID(ctx);

	if (!ifname)
		return;

	strlcpy(ctx->zd_ifname, ifname, sizeof(ctx->zd_ifname));
}

ifindex_t dplane_ctx_get_ifindex(const struct zebra_dplane_ctx *ctx)
{
	DPLANE_CTX_VALID(ctx);

	return ctx->zd_ifindex;
}

void dplane_ctx_set_type(struct zebra_dplane_ctx *ctx, int type)
{
	DPLANE_CTX_VALID(ctx);

	ctx->u.rinfo.zd_type = type;
}

int dplane_ctx_get_type(const struct zebra_dplane_ctx *ctx)
{
	DPLANE_CTX_VALID(ctx);

	return ctx->u.rinfo.zd_type;
}

int dplane_ctx_get_old_type(const struct zebra_dplane_ctx *ctx)
{
	DPLANE_CTX_VALID(ctx);

	return ctx->u.rinfo.zd_old_type;
}

void dplane_ctx_set_afi(struct zebra_dplane_ctx *ctx, afi_t afi)
{
	DPLANE_CTX_VALID(ctx);

	ctx->u.rinfo.zd_afi = afi;
}

afi_t dplane_ctx_get_afi(const struct zebra_dplane_ctx *ctx)
{
	DPLANE_CTX_VALID(ctx);

	return ctx->u.rinfo.zd_afi;
}

void dplane_ctx_set_safi(struct zebra_dplane_ctx *ctx, safi_t safi)
{
	DPLANE_CTX_VALID(ctx);

	ctx->u.rinfo.zd_safi = safi;
}

safi_t dplane_ctx_get_safi(const struct zebra_dplane_ctx *ctx)
{
	DPLANE_CTX_VALID(ctx);

	return ctx->u.rinfo.zd_safi;
}

void dplane_ctx_set_table(struct zebra_dplane_ctx *ctx, uint32_t table)
{
	DPLANE_CTX_VALID(ctx);

	ctx->zd_table_id = table;
}

uint32_t dplane_ctx_get_table(const struct zebra_dplane_ctx *ctx)
{
	DPLANE_CTX_VALID(ctx);

	return ctx->zd_table_id;
}

route_tag_t dplane_ctx_get_tag(const struct zebra_dplane_ctx *ctx)
{
	DPLANE_CTX_VALID(ctx);

	return ctx->u.rinfo.zd_tag;
}

void dplane_ctx_set_tag(struct zebra_dplane_ctx *ctx, route_tag_t tag)
{
	DPLANE_CTX_VALID(ctx);

	ctx->u.rinfo.zd_tag = tag;
}

route_tag_t dplane_ctx_get_old_tag(const struct zebra_dplane_ctx *ctx)
{
	DPLANE_CTX_VALID(ctx);

	return ctx->u.rinfo.zd_old_tag;
}

uint16_t dplane_ctx_get_instance(const struct zebra_dplane_ctx *ctx)
{
	DPLANE_CTX_VALID(ctx);

	return ctx->u.rinfo.zd_instance;
}

void dplane_ctx_set_instance(struct zebra_dplane_ctx *ctx, uint16_t instance)
{
	DPLANE_CTX_VALID(ctx);

	ctx->u.rinfo.zd_instance = instance;
}

uint16_t dplane_ctx_get_old_instance(const struct zebra_dplane_ctx *ctx)
{
	DPLANE_CTX_VALID(ctx);

	return ctx->u.rinfo.zd_old_instance;
}

uint32_t dplane_ctx_get_metric(const struct zebra_dplane_ctx *ctx)
{
	DPLANE_CTX_VALID(ctx);

	return ctx->u.rinfo.zd_metric;
}

uint32_t dplane_ctx_get_old_metric(const struct zebra_dplane_ctx *ctx)
{
	DPLANE_CTX_VALID(ctx);

	return ctx->u.rinfo.zd_old_metric;
}

uint32_t dplane_ctx_get_mtu(const struct zebra_dplane_ctx *ctx)
{
	DPLANE_CTX_VALID(ctx);

	return ctx->u.rinfo.zd_mtu;
}

uint32_t dplane_ctx_get_nh_mtu(const struct zebra_dplane_ctx *ctx)
{
	DPLANE_CTX_VALID(ctx);

	return ctx->u.rinfo.zd_nexthop_mtu;
}

uint8_t dplane_ctx_get_distance(const struct zebra_dplane_ctx *ctx)
{
	DPLANE_CTX_VALID(ctx);

	return ctx->u.rinfo.zd_distance;
}

void dplane_ctx_set_distance(struct zebra_dplane_ctx *ctx, uint8_t distance)
{
	DPLANE_CTX_VALID(ctx);

	ctx->u.rinfo.zd_distance = distance;
}

uint8_t dplane_ctx_get_old_distance(const struct zebra_dplane_ctx *ctx)
{
	DPLANE_CTX_VALID(ctx);

	return ctx->u.rinfo.zd_old_distance;
}

/*
 * Set the nexthops associated with a context: note that processing code
 * may well expect that nexthops are in canonical (sorted) order, so we
 * will enforce that here.
 */
void dplane_ctx_set_nexthops(struct zebra_dplane_ctx *ctx, struct nexthop *nh)
{
	DPLANE_CTX_VALID(ctx);

	if (ctx->u.rinfo.zd_ng.nexthop) {
		nexthops_free(ctx->u.rinfo.zd_ng.nexthop);
		ctx->u.rinfo.zd_ng.nexthop = NULL;
	}
	nexthop_group_copy_nh_sorted(&(ctx->u.rinfo.zd_ng), nh);
}

/*
 * Set the list of backup nexthops; their ordering is preserved (they're not
 * re-sorted.)
 */
void dplane_ctx_set_backup_nhg(struct zebra_dplane_ctx *ctx,
			       const struct nexthop_group *nhg)
{
	struct nexthop *nh, *last_nh, *nexthop;

	DPLANE_CTX_VALID(ctx);

	if (ctx->u.rinfo.backup_ng.nexthop) {
		nexthops_free(ctx->u.rinfo.backup_ng.nexthop);
		ctx->u.rinfo.backup_ng.nexthop = NULL;
	}

	last_nh = NULL;

	/* Be careful to preserve the order of the backup list */
	for (nh = nhg->nexthop; nh; nh = nh->next) {
		nexthop = nexthop_dup(nh, NULL);

		if (last_nh)
			NEXTHOP_APPEND(last_nh, nexthop);
		else
			ctx->u.rinfo.backup_ng.nexthop = nexthop;

		last_nh = nexthop;
	}
}

uint32_t dplane_ctx_get_nhg_id(const struct zebra_dplane_ctx *ctx)
{
	DPLANE_CTX_VALID(ctx);
	return ctx->u.rinfo.zd_nhg_id;
}

const struct nexthop_group *dplane_ctx_get_ng(
	const struct zebra_dplane_ctx *ctx)
{
	DPLANE_CTX_VALID(ctx);

	return &(ctx->u.rinfo.zd_ng);
}

const struct nexthop_group *
dplane_ctx_get_backup_ng(const struct zebra_dplane_ctx *ctx)
{
	DPLANE_CTX_VALID(ctx);

	return &(ctx->u.rinfo.backup_ng);
}

const struct nexthop_group *
dplane_ctx_get_old_ng(const struct zebra_dplane_ctx *ctx)
{
	DPLANE_CTX_VALID(ctx);

	return &(ctx->u.rinfo.zd_old_ng);
}

const struct nexthop_group *
dplane_ctx_get_old_backup_ng(const struct zebra_dplane_ctx *ctx)
{
	DPLANE_CTX_VALID(ctx);

	return &(ctx->u.rinfo.old_backup_ng);
}

const struct zebra_dplane_info *dplane_ctx_get_ns(
	const struct zebra_dplane_ctx *ctx)
{
	DPLANE_CTX_VALID(ctx);

	return &(ctx->zd_ns_info);
}

/* Accessors for nexthop information */
uint32_t dplane_ctx_get_nhe_id(const struct zebra_dplane_ctx *ctx)
{
	DPLANE_CTX_VALID(ctx);
	return ctx->u.rinfo.nhe.id;
}

uint32_t dplane_ctx_get_old_nhe_id(const struct zebra_dplane_ctx *ctx)
{
	DPLANE_CTX_VALID(ctx);
	return ctx->u.rinfo.nhe.old_id;
}

afi_t dplane_ctx_get_nhe_afi(const struct zebra_dplane_ctx *ctx)
{
	DPLANE_CTX_VALID(ctx);
	return ctx->u.rinfo.nhe.afi;
}

vrf_id_t dplane_ctx_get_nhe_vrf_id(const struct zebra_dplane_ctx *ctx)
{
	DPLANE_CTX_VALID(ctx);
	return ctx->u.rinfo.nhe.vrf_id;
}

int dplane_ctx_get_nhe_type(const struct zebra_dplane_ctx *ctx)
{
	DPLANE_CTX_VALID(ctx);
	return ctx->u.rinfo.nhe.type;
}

const struct nexthop_group *
dplane_ctx_get_nhe_ng(const struct zebra_dplane_ctx *ctx)
{
	DPLANE_CTX_VALID(ctx);
	return &(ctx->u.rinfo.nhe.ng);
}

const struct nh_grp *
dplane_ctx_get_nhe_nh_grp(const struct zebra_dplane_ctx *ctx)
{
	DPLANE_CTX_VALID(ctx);
	return ctx->u.rinfo.nhe.nh_grp;
}

uint8_t dplane_ctx_get_nhe_nh_grp_count(const struct zebra_dplane_ctx *ctx)
{
	DPLANE_CTX_VALID(ctx);
	return ctx->u.rinfo.nhe.nh_grp_count;
}

/* Accessors for LSP information */

mpls_label_t dplane_ctx_get_in_label(const struct zebra_dplane_ctx *ctx)
{
	DPLANE_CTX_VALID(ctx);

	return ctx->u.lsp.ile.in_label;
}

void dplane_ctx_set_in_label(struct zebra_dplane_ctx *ctx, mpls_label_t label)
{
	DPLANE_CTX_VALID(ctx);

	ctx->u.lsp.ile.in_label = label;
}

uint8_t dplane_ctx_get_addr_family(const struct zebra_dplane_ctx *ctx)
{
	DPLANE_CTX_VALID(ctx);

	return ctx->u.lsp.addr_family;
}

void dplane_ctx_set_addr_family(struct zebra_dplane_ctx *ctx,
				uint8_t family)
{
	DPLANE_CTX_VALID(ctx);

	ctx->u.lsp.addr_family = family;
}

uint32_t dplane_ctx_get_lsp_flags(const struct zebra_dplane_ctx *ctx)
{
	DPLANE_CTX_VALID(ctx);

	return ctx->u.lsp.flags;
}

void dplane_ctx_set_lsp_flags(struct zebra_dplane_ctx *ctx,
			      uint32_t flags)
{
	DPLANE_CTX_VALID(ctx);

	ctx->u.lsp.flags = flags;
}

const struct nhlfe_list_head *dplane_ctx_get_nhlfe_list(
	const struct zebra_dplane_ctx *ctx)
{
	DPLANE_CTX_VALID(ctx);
	return &(ctx->u.lsp.nhlfe_list);
}

const struct nhlfe_list_head *dplane_ctx_get_backup_nhlfe_list(
	const struct zebra_dplane_ctx *ctx)
{
	DPLANE_CTX_VALID(ctx);
	return &(ctx->u.lsp.backup_nhlfe_list);
}

zebra_nhlfe_t *dplane_ctx_add_nhlfe(struct zebra_dplane_ctx *ctx,
				    enum lsp_types_t lsp_type,
				    enum nexthop_types_t nh_type,
				    const union g_addr *gate,
				    ifindex_t ifindex,
				    uint8_t num_labels,
				    mpls_label_t *out_labels)
{
	zebra_nhlfe_t *nhlfe;

	DPLANE_CTX_VALID(ctx);

	nhlfe = zebra_mpls_lsp_add_nhlfe(&(ctx->u.lsp),
					 lsp_type, nh_type, gate,
					 ifindex, num_labels, out_labels);

	return nhlfe;
}

zebra_nhlfe_t *dplane_ctx_add_backup_nhlfe(struct zebra_dplane_ctx *ctx,
					   enum lsp_types_t lsp_type,
					   enum nexthop_types_t nh_type,
					   const union g_addr *gate,
					   ifindex_t ifindex,
					   uint8_t num_labels,
					   mpls_label_t *out_labels)
{
	zebra_nhlfe_t *nhlfe;

	DPLANE_CTX_VALID(ctx);

	nhlfe = zebra_mpls_lsp_add_backup_nhlfe(&(ctx->u.lsp),
						lsp_type, nh_type, gate,
						ifindex, num_labels,
						out_labels);

	return nhlfe;
}

const zebra_nhlfe_t *
dplane_ctx_get_best_nhlfe(const struct zebra_dplane_ctx *ctx)
{
	DPLANE_CTX_VALID(ctx);

	return ctx->u.lsp.best_nhlfe;
}

const zebra_nhlfe_t *
dplane_ctx_set_best_nhlfe(struct zebra_dplane_ctx *ctx,
			  zebra_nhlfe_t *nhlfe)
{
	DPLANE_CTX_VALID(ctx);

	ctx->u.lsp.best_nhlfe = nhlfe;
	return ctx->u.lsp.best_nhlfe;
}

uint32_t dplane_ctx_get_lsp_num_ecmp(const struct zebra_dplane_ctx *ctx)
{
	DPLANE_CTX_VALID(ctx);

	return ctx->u.lsp.num_ecmp;
}

mpls_label_t dplane_ctx_get_pw_local_label(const struct zebra_dplane_ctx *ctx)
{
	DPLANE_CTX_VALID(ctx);

	return ctx->u.pw.local_label;
}

mpls_label_t dplane_ctx_get_pw_remote_label(const struct zebra_dplane_ctx *ctx)
{
	DPLANE_CTX_VALID(ctx);

	return ctx->u.pw.remote_label;
}

int dplane_ctx_get_pw_type(const struct zebra_dplane_ctx *ctx)
{
	DPLANE_CTX_VALID(ctx);

	return ctx->u.pw.type;
}

int dplane_ctx_get_pw_af(const struct zebra_dplane_ctx *ctx)
{
	DPLANE_CTX_VALID(ctx);

	return ctx->u.pw.af;
}

uint32_t dplane_ctx_get_pw_flags(const struct zebra_dplane_ctx *ctx)
{
	DPLANE_CTX_VALID(ctx);

	return ctx->u.pw.flags;
}

int dplane_ctx_get_pw_status(const struct zebra_dplane_ctx *ctx)
{
	DPLANE_CTX_VALID(ctx);

	return ctx->u.pw.status;
}

void dplane_ctx_set_pw_status(struct zebra_dplane_ctx *ctx, int status)
{
	DPLANE_CTX_VALID(ctx);

	ctx->u.pw.status = status;
}

const union g_addr *dplane_ctx_get_pw_dest(
	const struct zebra_dplane_ctx *ctx)
{
	DPLANE_CTX_VALID(ctx);

	return &(ctx->u.pw.dest);
}

const union pw_protocol_fields *dplane_ctx_get_pw_proto(
	const struct zebra_dplane_ctx *ctx)
{
	DPLANE_CTX_VALID(ctx);

	return &(ctx->u.pw.fields);
}

const struct nexthop_group *
dplane_ctx_get_pw_nhg(const struct zebra_dplane_ctx *ctx)
{
	DPLANE_CTX_VALID(ctx);

	return &(ctx->u.pw.nhg);
}

/* Accessors for interface information */
uint32_t dplane_ctx_get_intf_metric(const struct zebra_dplane_ctx *ctx)
{
	DPLANE_CTX_VALID(ctx);

	return ctx->u.intf.metric;
}

/* Is interface addr p2p? */
bool dplane_ctx_intf_is_connected(const struct zebra_dplane_ctx *ctx)
{
	DPLANE_CTX_VALID(ctx);

	return (ctx->u.intf.flags & DPLANE_INTF_CONNECTED);
}

bool dplane_ctx_intf_is_secondary(const struct zebra_dplane_ctx *ctx)
{
	DPLANE_CTX_VALID(ctx);

	return (ctx->u.intf.flags & DPLANE_INTF_SECONDARY);
}

bool dplane_ctx_intf_is_broadcast(const struct zebra_dplane_ctx *ctx)
{
	DPLANE_CTX_VALID(ctx);

	return (ctx->u.intf.flags & DPLANE_INTF_BROADCAST);
}

const struct prefix *dplane_ctx_get_intf_addr(
	const struct zebra_dplane_ctx *ctx)
{
	DPLANE_CTX_VALID(ctx);

	return &(ctx->u.intf.prefix);
}

bool dplane_ctx_intf_has_dest(const struct zebra_dplane_ctx *ctx)
{
	DPLANE_CTX_VALID(ctx);

	return (ctx->u.intf.flags & DPLANE_INTF_HAS_DEST);
}

const struct prefix *dplane_ctx_get_intf_dest(
	const struct zebra_dplane_ctx *ctx)
{
	DPLANE_CTX_VALID(ctx);

	if (ctx->u.intf.flags & DPLANE_INTF_HAS_DEST)
		return &(ctx->u.intf.dest_prefix);
	else
		return NULL;
}

bool dplane_ctx_intf_has_label(const struct zebra_dplane_ctx *ctx)
{
	DPLANE_CTX_VALID(ctx);

	return (ctx->u.intf.flags & DPLANE_INTF_HAS_LABEL);
}

const char *dplane_ctx_get_intf_label(const struct zebra_dplane_ctx *ctx)
{
	DPLANE_CTX_VALID(ctx);

	return ctx->u.intf.label;
}

/* Accessors for MAC information */
vlanid_t dplane_ctx_mac_get_vlan(const struct zebra_dplane_ctx *ctx)
{
	DPLANE_CTX_VALID(ctx);
	return ctx->u.macinfo.vid;
}

bool dplane_ctx_mac_is_sticky(const struct zebra_dplane_ctx *ctx)
{
	DPLANE_CTX_VALID(ctx);
	return ctx->u.macinfo.is_sticky;
}

uint32_t dplane_ctx_mac_get_nhg_id(const struct zebra_dplane_ctx *ctx)
{
	DPLANE_CTX_VALID(ctx);
	return ctx->u.macinfo.nhg_id;
}

uint32_t dplane_ctx_mac_get_update_flags(const struct zebra_dplane_ctx *ctx)
{
	DPLANE_CTX_VALID(ctx);
	return ctx->u.macinfo.update_flags;
}

const struct ethaddr *dplane_ctx_mac_get_addr(
	const struct zebra_dplane_ctx *ctx)
{
	DPLANE_CTX_VALID(ctx);
	return &(ctx->u.macinfo.mac);
}

const struct in_addr *dplane_ctx_mac_get_vtep_ip(
	const struct zebra_dplane_ctx *ctx)
{
	DPLANE_CTX_VALID(ctx);
	return &(ctx->u.macinfo.vtep_ip);
}

ifindex_t dplane_ctx_mac_get_br_ifindex(const struct zebra_dplane_ctx *ctx)
{
	DPLANE_CTX_VALID(ctx);
	return ctx->u.macinfo.br_ifindex;
}

/* Accessors for neighbor information */
const struct ipaddr *dplane_ctx_neigh_get_ipaddr(
	const struct zebra_dplane_ctx *ctx)
{
	DPLANE_CTX_VALID(ctx);
	return &(ctx->u.neigh.ip_addr);
}

const struct ipaddr *
dplane_ctx_neigh_get_link_ip(const struct zebra_dplane_ctx *ctx)
{
	DPLANE_CTX_VALID(ctx);
	return &(ctx->u.neigh.link.ip_addr);
}

const struct ethaddr *dplane_ctx_neigh_get_mac(
	const struct zebra_dplane_ctx *ctx)
{
	DPLANE_CTX_VALID(ctx);
	return &(ctx->u.neigh.link.mac);
}

uint32_t dplane_ctx_neigh_get_flags(const struct zebra_dplane_ctx *ctx)
{
	DPLANE_CTX_VALID(ctx);
	return ctx->u.neigh.flags;
}

uint16_t dplane_ctx_neigh_get_state(const struct zebra_dplane_ctx *ctx)
{
	DPLANE_CTX_VALID(ctx);
	return ctx->u.neigh.state;
}

uint32_t dplane_ctx_neigh_get_update_flags(const struct zebra_dplane_ctx *ctx)
{
	DPLANE_CTX_VALID(ctx);
	return ctx->u.neigh.update_flags;
}

/* Accessor for GRE set */
uint32_t
dplane_ctx_gre_get_link_ifindex(const struct zebra_dplane_ctx *ctx)
{
	DPLANE_CTX_VALID(ctx);

	return ctx->u.gre.link_ifindex;
}

/* Accessors for PBR rule information */
int dplane_ctx_rule_get_sock(const struct zebra_dplane_ctx *ctx)
{
	DPLANE_CTX_VALID(ctx);

	return ctx->u.rule.sock;
}

const char *dplane_ctx_rule_get_ifname(const struct zebra_dplane_ctx *ctx)
{
	DPLANE_CTX_VALID(ctx);

	return ctx->u.rule.new.ifname;
}

int dplane_ctx_rule_get_unique(const struct zebra_dplane_ctx *ctx)
{
	DPLANE_CTX_VALID(ctx);

	return ctx->u.rule.unique;
}

int dplane_ctx_rule_get_seq(const struct zebra_dplane_ctx *ctx)
{
	DPLANE_CTX_VALID(ctx);

	return ctx->u.rule.seq;
}

uint32_t dplane_ctx_rule_get_priority(const struct zebra_dplane_ctx *ctx)
{
	DPLANE_CTX_VALID(ctx);

	return ctx->u.rule.new.priority;
}

uint32_t dplane_ctx_rule_get_old_priority(const struct zebra_dplane_ctx *ctx)
{
	DPLANE_CTX_VALID(ctx);

	return ctx->u.rule.old.priority;
}

uint32_t dplane_ctx_rule_get_table(const struct zebra_dplane_ctx *ctx)
{
	DPLANE_CTX_VALID(ctx);

	return ctx->u.rule.new.table;
}

uint32_t dplane_ctx_rule_get_old_table(const struct zebra_dplane_ctx *ctx)
{
	DPLANE_CTX_VALID(ctx);

	return ctx->u.rule.old.table;
}

uint32_t dplane_ctx_rule_get_filter_bm(const struct zebra_dplane_ctx *ctx)
{
	DPLANE_CTX_VALID(ctx);

	return ctx->u.rule.new.filter_bm;
}

uint32_t dplane_ctx_rule_get_old_filter_bm(const struct zebra_dplane_ctx *ctx)
{
	DPLANE_CTX_VALID(ctx);

	return ctx->u.rule.old.filter_bm;
}

uint32_t dplane_ctx_rule_get_fwmark(const struct zebra_dplane_ctx *ctx)
{
	DPLANE_CTX_VALID(ctx);

	return ctx->u.rule.new.fwmark;
}

uint32_t dplane_ctx_rule_get_old_fwmark(const struct zebra_dplane_ctx *ctx)
{
	DPLANE_CTX_VALID(ctx);

	return ctx->u.rule.old.fwmark;
}

uint8_t dplane_ctx_rule_get_dsfield(const struct zebra_dplane_ctx *ctx)
{
	DPLANE_CTX_VALID(ctx);

	return ctx->u.rule.new.dsfield;
}

uint8_t dplane_ctx_rule_get_old_dsfield(const struct zebra_dplane_ctx *ctx)
{
	DPLANE_CTX_VALID(ctx);

	return ctx->u.rule.old.dsfield;
}

const struct prefix *
dplane_ctx_rule_get_src_ip(const struct zebra_dplane_ctx *ctx)
{
	DPLANE_CTX_VALID(ctx);

	return &(ctx->u.rule.new.src_ip);
}

const struct prefix *
dplane_ctx_rule_get_old_src_ip(const struct zebra_dplane_ctx *ctx)
{
	DPLANE_CTX_VALID(ctx);

	return &(ctx->u.rule.old.src_ip);
}

const struct prefix *
dplane_ctx_rule_get_dst_ip(const struct zebra_dplane_ctx *ctx)
{
	DPLANE_CTX_VALID(ctx);

	return &(ctx->u.rule.new.dst_ip);
}

const struct prefix *
dplane_ctx_rule_get_old_dst_ip(const struct zebra_dplane_ctx *ctx)
{
	DPLANE_CTX_VALID(ctx);

	return &(ctx->u.rule.old.dst_ip);
}

uint32_t dplane_ctx_get_br_port_flags(const struct zebra_dplane_ctx *ctx)
{
	DPLANE_CTX_VALID(ctx);

	return ctx->u.br_port.flags;
}

uint32_t
dplane_ctx_get_br_port_sph_filter_cnt(const struct zebra_dplane_ctx *ctx)
{
	DPLANE_CTX_VALID(ctx);

	return ctx->u.br_port.sph_filter_cnt;
}

const struct in_addr *
dplane_ctx_get_br_port_sph_filters(const struct zebra_dplane_ctx *ctx)
{
	DPLANE_CTX_VALID(ctx);

	return ctx->u.br_port.sph_filters;
}

uint32_t
dplane_ctx_get_br_port_backup_nhg_id(const struct zebra_dplane_ctx *ctx)
{
	DPLANE_CTX_VALID(ctx);

	return ctx->u.br_port.backup_nhg_id;
}

/* Accessors for PBR iptable information */
bool
dplane_ctx_get_pbr_iptable(const struct zebra_dplane_ctx *ctx,
			   struct zebra_pbr_iptable *table)
{
	DPLANE_CTX_VALID(ctx);

	memcpy(table, &ctx->u.iptable, sizeof(struct zebra_pbr_iptable));
	return true;
}

bool dplane_ctx_get_pbr_ipset(const struct zebra_dplane_ctx *ctx,
			      struct zebra_pbr_ipset *ipset)
{
	DPLANE_CTX_VALID(ctx);

	if (!ipset)
		return false;
	if (ctx->zd_op == DPLANE_OP_IPSET_ENTRY_ADD ||
	    ctx->zd_op == DPLANE_OP_IPSET_ENTRY_DELETE) {
		memset(ipset, 0, sizeof(struct zebra_pbr_ipset));
		ipset->type = ctx->u.ipset_entry.info.type;
		memcpy(&ipset->ipset_name, &ctx->u.ipset_entry.info.ipset_name,
		       ZEBRA_IPSET_NAME_SIZE);
	} else
		memcpy(ipset, &ctx->u.ipset, sizeof(struct zebra_pbr_ipset));
	return true;
}

bool dplane_ctx_get_pbr_ipset_entry(const struct zebra_dplane_ctx *ctx,
				    struct zebra_pbr_ipset_entry *entry)
{
	DPLANE_CTX_VALID(ctx);

	if (!entry)
		return false;
	memcpy(entry, &ctx->u.ipset_entry.entry, sizeof(struct zebra_pbr_ipset_entry));
	return true;
}

/*
 * End of dplane context accessors
 */

/* Optional extra info about interfaces in nexthops - a plugin must enable
 * this extra info.
 */
const struct dplane_intf_extra *
dplane_ctx_get_intf_extra(const struct zebra_dplane_ctx *ctx)
{
	return TAILQ_FIRST(&ctx->u.rinfo.intf_extra_q);
}

const struct dplane_intf_extra *
dplane_ctx_intf_extra_next(const struct zebra_dplane_ctx *ctx,
			   const struct dplane_intf_extra *ptr)
{
	return TAILQ_NEXT(ptr, link);
}

vrf_id_t dplane_intf_extra_get_vrfid(const struct dplane_intf_extra *ptr)
{
	return ptr->vrf_id;
}

uint32_t dplane_intf_extra_get_ifindex(const struct dplane_intf_extra *ptr)
{
	return ptr->ifindex;
}

uint32_t dplane_intf_extra_get_flags(const struct dplane_intf_extra *ptr)
{
	return ptr->flags;
}

uint32_t dplane_intf_extra_get_status(const struct dplane_intf_extra *ptr)
{
	return ptr->status;
}

uint8_t dplane_ctx_neightable_get_family(const struct zebra_dplane_ctx *ctx)
{
	DPLANE_CTX_VALID(ctx);

	return ctx->u.neightable.family;
}

uint32_t
dplane_ctx_neightable_get_app_probes(const struct zebra_dplane_ctx *ctx)
{
	DPLANE_CTX_VALID(ctx);

	return ctx->u.neightable.app_probes;
}

uint32_t
dplane_ctx_neightable_get_ucast_probes(const struct zebra_dplane_ctx *ctx)
{
	DPLANE_CTX_VALID(ctx);

	return ctx->u.neightable.ucast_probes;
}

uint32_t
dplane_ctx_neightable_get_mcast_probes(const struct zebra_dplane_ctx *ctx)
{
	DPLANE_CTX_VALID(ctx);

	return ctx->u.neightable.mcast_probes;
}

/*
 * End of interface extra info accessors
 */

/*
 * Retrieve the limit on the number of pending, unprocessed updates.
 */
uint32_t dplane_get_in_queue_limit(void)
{
	return atomic_load_explicit(&zdplane_info.dg_max_queued_updates,
				    memory_order_relaxed);
}

/*
 * Configure limit on the number of pending, queued updates.
 */
void dplane_set_in_queue_limit(uint32_t limit, bool set)
{
	/* Reset to default on 'unset' */
	if (!set)
		limit = DPLANE_DEFAULT_MAX_QUEUED;

	atomic_store_explicit(&zdplane_info.dg_max_queued_updates, limit,
			      memory_order_relaxed);
}

/*
 * Retrieve the current queue depth of incoming, unprocessed updates
 */
uint32_t dplane_get_in_queue_len(void)
{
	return atomic_load_explicit(&zdplane_info.dg_routes_queued,
				    memory_order_seq_cst);
}

/*
 * Common dataplane context init with zebra namespace info.
 */
static int dplane_ctx_ns_init(struct zebra_dplane_ctx *ctx,
			      struct zebra_ns *zns,
			      bool is_update)
{
	dplane_info_from_zns(&(ctx->zd_ns_info), zns);

#if defined(HAVE_NETLINK)
	/* Increment message counter after copying to context struct - may need
	 * two messages in some 'update' cases.
	 */
	if (is_update)
		zns->netlink_dplane.seq += 2;
	else
		zns->netlink_dplane.seq++;
#endif	/* HAVE_NETLINK */

	return AOK;
}

/*
 * Initialize a context block for a route update from zebra data structs.
 */
int dplane_ctx_route_init(struct zebra_dplane_ctx *ctx, enum dplane_op_e op,
			  struct route_node *rn, struct route_entry *re)
{
	int ret = EINVAL;
	const struct route_table *table = NULL;
	const struct rib_table_info *info;
	const struct prefix *p, *src_p;
	struct zebra_ns *zns;
	struct zebra_vrf *zvrf;
	struct nexthop *nexthop;
	zebra_l3vni_t *zl3vni;
	const struct interface *ifp;
	struct dplane_intf_extra *if_extra;

	if (!ctx || !rn || !re)
		goto done;

	TAILQ_INIT(&ctx->u.rinfo.intf_extra_q);

	ctx->zd_op = op;
	ctx->zd_status = ZEBRA_DPLANE_REQUEST_SUCCESS;

	ctx->u.rinfo.zd_type = re->type;
	ctx->u.rinfo.zd_old_type = re->type;

	/* Prefixes: dest, and optional source */
	srcdest_rnode_prefixes(rn, &p, &src_p);

	prefix_copy(&(ctx->u.rinfo.zd_dest), p);

	if (src_p)
		prefix_copy(&(ctx->u.rinfo.zd_src), src_p);
	else
		memset(&(ctx->u.rinfo.zd_src), 0, sizeof(ctx->u.rinfo.zd_src));

	ctx->zd_table_id = re->table;

	ctx->u.rinfo.zd_metric = re->metric;
	ctx->u.rinfo.zd_old_metric = re->metric;
	ctx->zd_vrf_id = re->vrf_id;
	ctx->u.rinfo.zd_mtu = re->mtu;
	ctx->u.rinfo.zd_nexthop_mtu = re->nexthop_mtu;
	ctx->u.rinfo.zd_instance = re->instance;
	ctx->u.rinfo.zd_tag = re->tag;
	ctx->u.rinfo.zd_old_tag = re->tag;
	ctx->u.rinfo.zd_distance = re->distance;

	table = srcdest_rnode_table(rn);
	info = table->info;

	ctx->u.rinfo.zd_afi = info->afi;
	ctx->u.rinfo.zd_safi = info->safi;

	/* Copy nexthops; recursive info is included too */
	copy_nexthops(&(ctx->u.rinfo.zd_ng.nexthop),
		      re->nhe->nhg.nexthop, NULL);
	ctx->u.rinfo.zd_nhg_id = re->nhe->id;

	/* Copy backup nexthop info, if present */
	if (re->nhe->backup_info && re->nhe->backup_info->nhe) {
		copy_nexthops(&(ctx->u.rinfo.backup_ng.nexthop),
			      re->nhe->backup_info->nhe->nhg.nexthop, NULL);
	}

	/*
	 * Ensure that the dplane nexthops' flags are clear and copy
	 * encapsulation information.
	 */
	for (ALL_NEXTHOPS(ctx->u.rinfo.zd_ng, nexthop)) {
		UNSET_FLAG(nexthop->flags, NEXTHOP_FLAG_FIB);

		/* Optionally capture extra interface info while we're in the
		 * main zebra pthread - a plugin has to ask for this info.
		 */
		if (dplane_collect_extra_intf_info) {
			ifp = if_lookup_by_index(nexthop->ifindex,
						 nexthop->vrf_id);

			if (ifp) {
				if_extra = XCALLOC(
					MTYPE_DP_INTF,
					sizeof(struct dplane_intf_extra));
				if_extra->vrf_id = nexthop->vrf_id;
				if_extra->ifindex = nexthop->ifindex;
				if_extra->flags = ifp->flags;
				if_extra->status = ifp->status;

				TAILQ_INSERT_TAIL(&ctx->u.rinfo.intf_extra_q,
						  if_extra, link);
			}
		}

		/* Check for available evpn encapsulations. */
		if (!CHECK_FLAG(re->flags, ZEBRA_FLAG_EVPN_ROUTE))
			continue;

		zl3vni = zl3vni_from_vrf(nexthop->vrf_id);
		if (zl3vni && is_l3vni_oper_up(zl3vni)) {
			nexthop->nh_encap_type = NET_VXLAN;
			nexthop->nh_encap.vni = zl3vni->vni;
		}
	}

	/* Don't need some info when capturing a system notification */
	if (op == DPLANE_OP_SYS_ROUTE_ADD ||
	    op == DPLANE_OP_SYS_ROUTE_DELETE) {
		ret = AOK;
		goto done;
	}

	/* Extract ns info - can't use pointers to 'core' structs */
	zvrf = vrf_info_lookup(re->vrf_id);
	zns = zvrf->zns;
	dplane_ctx_ns_init(ctx, zns, (op == DPLANE_OP_ROUTE_UPDATE));

#ifdef HAVE_NETLINK
	{
		struct nhg_hash_entry *nhe = zebra_nhg_resolve(re->nhe);

		ctx->u.rinfo.nhe.id = nhe->id;
		ctx->u.rinfo.nhe.old_id = 0;
		/*
		 * Check if the nhe is installed/queued before doing anything
		 * with this route.
		 *
		 * If its a delete we only use the prefix anyway, so this only
		 * matters for INSTALL/UPDATE.
		 */
		if (zebra_nhg_kernel_nexthops_enabled()
		    && (((op == DPLANE_OP_ROUTE_INSTALL)
			 || (op == DPLANE_OP_ROUTE_UPDATE))
			&& !CHECK_FLAG(nhe->flags, NEXTHOP_GROUP_INSTALLED)
			&& !CHECK_FLAG(nhe->flags, NEXTHOP_GROUP_QUEUED))) {
			ret = ENOENT;
			goto done;
		}
	}
#endif /* HAVE_NETLINK */

	/* Trying out the sequence number idea, so we can try to detect
	 * when a result is stale.
	 */
	re->dplane_sequence = zebra_router_get_next_sequence();
	ctx->zd_seq = re->dplane_sequence;

	ret = AOK;

done:
	return ret;
}

/**
 * dplane_ctx_nexthop_init() - Initialize a context block for a nexthop update
 *
 * @ctx:	Dataplane context to init
 * @op:		Operation being performed
 * @nhe:	Nexthop group hash entry
 *
 * Return:	Result status
 */
int dplane_ctx_nexthop_init(struct zebra_dplane_ctx *ctx, enum dplane_op_e op,
			    struct nhg_hash_entry *nhe)
{
	struct zebra_vrf *zvrf = NULL;
	struct zebra_ns *zns = NULL;
	int ret = EINVAL;

	if (!ctx || !nhe)
		goto done;

	ctx->zd_op = op;
	ctx->zd_status = ZEBRA_DPLANE_REQUEST_SUCCESS;

	/* Copy over nhe info */
	ctx->u.rinfo.nhe.id = nhe->id;
	ctx->u.rinfo.nhe.afi = nhe->afi;
	ctx->u.rinfo.nhe.vrf_id = nhe->vrf_id;
	ctx->u.rinfo.nhe.type = nhe->type;

	nexthop_group_copy(&(ctx->u.rinfo.nhe.ng), &(nhe->nhg));

	/* If this is a group, convert it to a grp array of ids */
	if (!zebra_nhg_depends_is_empty(nhe)
	    && !CHECK_FLAG(nhe->flags, NEXTHOP_GROUP_RECURSIVE))
		ctx->u.rinfo.nhe.nh_grp_count = zebra_nhg_nhe2grp(
			ctx->u.rinfo.nhe.nh_grp, nhe, MULTIPATH_NUM);

	zvrf = vrf_info_lookup(nhe->vrf_id);

	/*
	 * Fallback to default namespace if the vrf got ripped out from under
	 * us.
	 */
	zns = zvrf ? zvrf->zns : zebra_ns_lookup(NS_DEFAULT);

	/*
	 * TODO: Might not need to mark this as an update, since
	 * it probably won't require two messages
	 */
	dplane_ctx_ns_init(ctx, zns, (op == DPLANE_OP_NH_UPDATE));
	ctx->zd_is_update = (op == DPLANE_OP_NH_UPDATE);

	ret = AOK;

done:
	return ret;
}

/*
 * Capture information for an LSP update in a dplane context.
 */
int dplane_ctx_lsp_init(struct zebra_dplane_ctx *ctx, enum dplane_op_e op,
			zebra_lsp_t *lsp)
{
	int ret = AOK;
	zebra_nhlfe_t *nhlfe, *new_nhlfe;

	ctx->zd_op = op;
	ctx->zd_status = ZEBRA_DPLANE_REQUEST_SUCCESS;

	/* Capture namespace info */
	dplane_ctx_ns_init(ctx, zebra_ns_lookup(NS_DEFAULT),
			   (op == DPLANE_OP_LSP_UPDATE));
	ctx->zd_is_update = (op == DPLANE_OP_LSP_UPDATE);

	memset(&ctx->u.lsp, 0, sizeof(ctx->u.lsp));

	nhlfe_list_init(&(ctx->u.lsp.nhlfe_list));
	nhlfe_list_init(&(ctx->u.lsp.backup_nhlfe_list));

	/* This may be called to create/init a dplane context, not necessarily
	 * to copy an lsp object.
	 */
	if (lsp == NULL) {
		ret = AOK;
		goto done;
	}

	if (IS_ZEBRA_DEBUG_DPLANE_DETAIL)
		zlog_debug("init dplane ctx %s: in-label %u ecmp# %d",
			   dplane_op2str(op), lsp->ile.in_label,
			   lsp->num_ecmp);

	ctx->u.lsp.ile = lsp->ile;
	ctx->u.lsp.addr_family = lsp->addr_family;
	ctx->u.lsp.num_ecmp = lsp->num_ecmp;
	ctx->u.lsp.flags = lsp->flags;

	/* Copy source LSP's nhlfes, and capture 'best' nhlfe */
	frr_each(nhlfe_list, &lsp->nhlfe_list, nhlfe) {
		/* Not sure if this is meaningful... */
		if (nhlfe->nexthop == NULL)
			continue;

		new_nhlfe = zebra_mpls_lsp_add_nh(&(ctx->u.lsp), nhlfe->type,
						  nhlfe->nexthop);
		if (new_nhlfe == NULL || new_nhlfe->nexthop == NULL) {
			ret = ENOMEM;
			break;
		}

		/* Need to copy flags and backup info too */
		new_nhlfe->flags = nhlfe->flags;
		new_nhlfe->nexthop->flags = nhlfe->nexthop->flags;

		if (CHECK_FLAG(new_nhlfe->nexthop->flags,
			       NEXTHOP_FLAG_HAS_BACKUP)) {
			new_nhlfe->nexthop->backup_num =
				nhlfe->nexthop->backup_num;
			memcpy(new_nhlfe->nexthop->backup_idx,
			       nhlfe->nexthop->backup_idx,
			       new_nhlfe->nexthop->backup_num);
		}

		if (nhlfe == lsp->best_nhlfe)
			ctx->u.lsp.best_nhlfe = new_nhlfe;
	}

	if (ret != AOK)
		goto done;

	/* Capture backup nhlfes/nexthops */
	frr_each(nhlfe_list, &lsp->backup_nhlfe_list, nhlfe) {
		/* Not sure if this is meaningful... */
		if (nhlfe->nexthop == NULL)
			continue;

		new_nhlfe = zebra_mpls_lsp_add_backup_nh(&(ctx->u.lsp),
							 nhlfe->type,
							 nhlfe->nexthop);
		if (new_nhlfe == NULL || new_nhlfe->nexthop == NULL) {
			ret = ENOMEM;
			break;
		}

		/* Need to copy flags too */
		new_nhlfe->flags = nhlfe->flags;
		new_nhlfe->nexthop->flags = nhlfe->nexthop->flags;
	}

	/* On error the ctx will be cleaned-up, so we don't need to
	 * deal with any allocated nhlfe or nexthop structs here.
	 */
done:

	return ret;
}

/*
 * Capture information for an LSP update in a dplane context.
 */
static int dplane_ctx_pw_init(struct zebra_dplane_ctx *ctx,
			      enum dplane_op_e op,
			      struct zebra_pw *pw)
{
	struct prefix p;
	afi_t afi;
	struct route_table *table;
	struct route_node *rn;
	struct route_entry *re;
	const struct nexthop_group *nhg;

	if (IS_ZEBRA_DEBUG_DPLANE_DETAIL)
		zlog_debug("init dplane ctx %s: pw '%s', loc %u, rem %u",
			   dplane_op2str(op), pw->ifname, pw->local_label,
			   pw->remote_label);

	ctx->zd_op = op;
	ctx->zd_status = ZEBRA_DPLANE_REQUEST_SUCCESS;

	/* Capture namespace info: no netlink support as of 12/18,
	 * but just in case...
	 */
	dplane_ctx_ns_init(ctx, zebra_ns_lookup(NS_DEFAULT), false);

	memset(&ctx->u.pw, 0, sizeof(ctx->u.pw));

	/* This name appears to be c-string, so we use string copy. */
	strlcpy(ctx->zd_ifname, pw->ifname, sizeof(ctx->zd_ifname));

	ctx->zd_vrf_id = pw->vrf_id;
	ctx->zd_ifindex = pw->ifindex;
	ctx->u.pw.type = pw->type;
	ctx->u.pw.af = pw->af;
	ctx->u.pw.local_label = pw->local_label;
	ctx->u.pw.remote_label = pw->remote_label;
	ctx->u.pw.flags = pw->flags;

	ctx->u.pw.dest = pw->nexthop;

	ctx->u.pw.fields = pw->data;

	/* Capture nexthop info for the pw destination. We need to look
	 * up and use zebra datastructs, but we're running in the zebra
	 * pthread here so that should be ok.
	 */
	memcpy(&p.u, &pw->nexthop, sizeof(pw->nexthop));
	p.family = pw->af;
	p.prefixlen = ((pw->af == AF_INET) ?
		       IPV4_MAX_PREFIXLEN : IPV6_MAX_PREFIXLEN);

	afi = (pw->af == AF_INET) ? AFI_IP : AFI_IP6;
	table = zebra_vrf_table(afi, SAFI_UNICAST, pw->vrf_id);
	if (table) {
		rn = route_node_match(table, &p);
		if (rn) {
			RNODE_FOREACH_RE(rn, re) {
				if (CHECK_FLAG(re->flags, ZEBRA_FLAG_SELECTED))
					break;
			}

			if (re) {
				nhg = rib_get_fib_nhg(re);
				if (nhg && nhg->nexthop)
					copy_nexthops(&(ctx->u.pw.nhg.nexthop),
						      nhg->nexthop, NULL);

				/* Include any installed backup nexthops */
				nhg = rib_get_fib_backup_nhg(re);
				if (nhg && nhg->nexthop)
					copy_nexthops(&(ctx->u.pw.nhg.nexthop),
						      nhg->nexthop, NULL);
			}
			route_unlock_node(rn);
		}
	}

	return AOK;
}

/**
 * dplane_ctx_rule_init_single() - Initialize a dataplane representation of a
 * PBR rule.
 *
 * @dplane_rule:	Dataplane internal representation of a rule
 * @rule:			PBR rule
 */
static void dplane_ctx_rule_init_single(struct dplane_ctx_rule *dplane_rule,
					struct zebra_pbr_rule *rule)
{
	dplane_rule->priority = rule->rule.priority;
	dplane_rule->table = rule->rule.action.table;

	dplane_rule->filter_bm = rule->rule.filter.filter_bm;
	dplane_rule->fwmark = rule->rule.filter.fwmark;
	dplane_rule->dsfield = rule->rule.filter.dsfield;
	prefix_copy(&(dplane_rule->dst_ip), &rule->rule.filter.dst_ip);
	prefix_copy(&(dplane_rule->src_ip), &rule->rule.filter.src_ip);
	strlcpy(dplane_rule->ifname, rule->ifname, INTERFACE_NAMSIZ);
}

/**
 * dplane_ctx_rule_init() - Initialize a context block for a PBR rule update.
 *
 * @ctx:		Dataplane context to init
 * @op:			Operation being performed
 * @new_rule:	PBR rule
 *
 * Return:	Result status
 */
static int dplane_ctx_rule_init(struct zebra_dplane_ctx *ctx,
				enum dplane_op_e op,
				struct zebra_pbr_rule *new_rule,
				struct zebra_pbr_rule *old_rule)
{
	if (IS_ZEBRA_DEBUG_DPLANE_DETAIL)
		zlog_debug(
			"init dplane ctx %s: IF %s Prio %u Fwmark %u Src %pFX Dst %pFX Table %u",
			dplane_op2str(op), new_rule->ifname,
			new_rule->rule.priority, new_rule->rule.filter.fwmark,
			&new_rule->rule.filter.src_ip,
			&new_rule->rule.filter.dst_ip,
			new_rule->rule.action.table);

	ctx->zd_op = op;
	ctx->zd_status = ZEBRA_DPLANE_REQUEST_SUCCESS;

	dplane_ctx_ns_init(ctx, zebra_ns_lookup(NS_DEFAULT),
			   op == DPLANE_OP_RULE_UPDATE);
	ctx->zd_is_update = (op == DPLANE_OP_RULE_UPDATE);

	ctx->zd_vrf_id = new_rule->vrf_id;
	memcpy(ctx->zd_ifname, new_rule->ifname, sizeof(new_rule->ifname));

	ctx->u.rule.sock = new_rule->sock;
	ctx->u.rule.unique = new_rule->rule.unique;
	ctx->u.rule.seq = new_rule->rule.seq;

	dplane_ctx_rule_init_single(&ctx->u.rule.new, new_rule);
	if (op == DPLANE_OP_RULE_UPDATE)
		dplane_ctx_rule_init_single(&ctx->u.rule.old, old_rule);

	return AOK;
}

/**
 * dplane_ctx_iptable_init() - Initialize a context block for a PBR iptable
 * update.
 *
 * @ctx:		Dataplane context to init
 * @op:			Operation being performed
 * @new_rule:	PBR iptable
 *
 * Return:	Result status
 */
static int dplane_ctx_iptable_init(struct zebra_dplane_ctx *ctx,
				   enum dplane_op_e op,
				   struct zebra_pbr_iptable *iptable)
{
	char *ifname;
	struct listnode *node;

	if (IS_ZEBRA_DEBUG_DPLANE_DETAIL) {
		zlog_debug(
			"init dplane ctx %s: Unique %u Fwmark %u Family %s Action %s",
			dplane_op2str(op), iptable->unique, iptable->fwmark,
			family2str(iptable->family),
			iptable->action == ZEBRA_IPTABLES_DROP ? "Drop"
							       : "Forward");
	}

	ctx->zd_op = op;
	ctx->zd_status = ZEBRA_DPLANE_REQUEST_SUCCESS;

	dplane_ctx_ns_init(ctx, zebra_ns_lookup(NS_DEFAULT), false);
	ctx->zd_is_update = false;

	ctx->zd_vrf_id = iptable->vrf_id;
	memcpy(&ctx->u.iptable, iptable, sizeof(struct zebra_pbr_iptable));
	ctx->u.iptable.interface_name_list = NULL;
	if (iptable->nb_interface > 0) {
		ctx->u.iptable.interface_name_list = list_new();
		for (ALL_LIST_ELEMENTS_RO(iptable->interface_name_list, node,
					  ifname)) {
			listnode_add(ctx->u.iptable.interface_name_list,
				     XSTRDUP(MTYPE_DP_NETFILTER, ifname));
		}
	}
	return AOK;
}

/**
 * dplane_ctx_ipset_init() - Initialize a context block for a PBR ipset update.
 *
 * @ctx:		Dataplane context to init
 * @op:			Operation being performed
 * @new_rule:		PBR ipset
 *
 * Return:	Result status
 */
static int dplane_ctx_ipset_init(struct zebra_dplane_ctx *ctx,
				 enum dplane_op_e op,
				 struct zebra_pbr_ipset *ipset)
{
	if (IS_ZEBRA_DEBUG_DPLANE_DETAIL) {
		zlog_debug("init dplane ctx %s: %s Unique %u Family %s Type %s",
			   dplane_op2str(op), ipset->ipset_name, ipset->unique,
			   family2str(ipset->family),
			   zebra_pbr_ipset_type2str(ipset->type));
	}

	ctx->zd_op = op;
	ctx->zd_status = ZEBRA_DPLANE_REQUEST_SUCCESS;

	dplane_ctx_ns_init(ctx, zebra_ns_lookup(NS_DEFAULT), false);
	ctx->zd_is_update = false;

	ctx->zd_vrf_id = ipset->vrf_id;

	memcpy(&ctx->u.ipset, ipset, sizeof(struct zebra_pbr_ipset));
	return AOK;
}

/**
 * dplane_ctx_ipset_entry_init() - Initialize a context block for a PBR ipset
 * update.
 *
 * @ctx:		Dataplane context to init
 * @op:			Operation being performed
 * @new_rule:	PBR ipset
 *
 * Return:	Result status
 */
static int
dplane_ctx_ipset_entry_init(struct zebra_dplane_ctx *ctx, enum dplane_op_e op,
			    struct zebra_pbr_ipset_entry *ipset_entry)
{
	struct zebra_pbr_ipset *ipset;

	ipset = ipset_entry->backpointer;
	if (IS_ZEBRA_DEBUG_DPLANE_DETAIL) {
		zlog_debug("init dplane ctx %s: %s Unique %u filter %u",
			   dplane_op2str(op), ipset->ipset_name,
			   ipset_entry->unique, ipset_entry->filter_bm);
	}

	ctx->zd_op = op;
	ctx->zd_status = ZEBRA_DPLANE_REQUEST_SUCCESS;

	dplane_ctx_ns_init(ctx, zebra_ns_lookup(NS_DEFAULT), false);
	ctx->zd_is_update = false;

	ctx->zd_vrf_id = ipset->vrf_id;

	memcpy(&ctx->u.ipset_entry.entry, ipset_entry,
	       sizeof(struct zebra_pbr_ipset_entry));
	ctx->u.ipset_entry.entry.backpointer = NULL;
	ctx->u.ipset_entry.info.type = ipset->type;
	memcpy(&ctx->u.ipset_entry.info.ipset_name, &ipset->ipset_name,
	       ZEBRA_IPSET_NAME_SIZE);

	return AOK;
}


/*
 * Enqueue a new update,
 * and ensure an event is active for the dataplane pthread.
 */
static int dplane_update_enqueue(struct zebra_dplane_ctx *ctx)
{
	int ret = EINVAL;
	uint32_t high, curr;

	/* Enqueue for processing by the dataplane pthread */
	DPLANE_LOCK();
	{
		TAILQ_INSERT_TAIL(&zdplane_info.dg_update_ctx_q, ctx,
				  zd_q_entries);
	}
	DPLANE_UNLOCK();

	curr = atomic_fetch_add_explicit(
		&(zdplane_info.dg_routes_queued),
		1, memory_order_seq_cst);

	curr++;	/* We got the pre-incremented value */

	/* Maybe update high-water counter also */
	high = atomic_load_explicit(&zdplane_info.dg_routes_queued_max,
				    memory_order_seq_cst);
	while (high < curr) {
		if (atomic_compare_exchange_weak_explicit(
			    &zdplane_info.dg_routes_queued_max,
			    &high, curr,
			    memory_order_seq_cst,
			    memory_order_seq_cst))
			break;
	}

	/* Ensure that an event for the dataplane thread is active */
	ret = dplane_provider_work_ready();

	return ret;
}

/*
 * Utility that prepares a route update and enqueues it for processing
 */
static enum zebra_dplane_result
dplane_route_update_internal(struct route_node *rn,
			     struct route_entry *re,
			     struct route_entry *old_re,
			     enum dplane_op_e op)
{
	enum zebra_dplane_result result = ZEBRA_DPLANE_REQUEST_FAILURE;
	int ret = EINVAL;
	struct zebra_dplane_ctx *ctx = NULL;

	/* Obtain context block */
	ctx = dplane_ctx_alloc();

	/* Init context with info from zebra data structs */
	ret = dplane_ctx_route_init(ctx, op, rn, re);
	if (ret == AOK) {
		/* Capture some extra info for update case
		 * where there's a different 'old' route.
		 */
		if ((op == DPLANE_OP_ROUTE_UPDATE) &&
		    old_re && (old_re != re)) {
			ctx->zd_is_update = true;

			old_re->dplane_sequence =
				zebra_router_get_next_sequence();
			ctx->zd_old_seq = old_re->dplane_sequence;

			ctx->u.rinfo.zd_old_tag = old_re->tag;
			ctx->u.rinfo.zd_old_type = old_re->type;
			ctx->u.rinfo.zd_old_instance = old_re->instance;
			ctx->u.rinfo.zd_old_distance = old_re->distance;
			ctx->u.rinfo.zd_old_metric = old_re->metric;
			ctx->u.rinfo.nhe.old_id = old_re->nhe->id;

#ifndef HAVE_NETLINK
			/* For bsd, capture previous re's nexthops too, sigh.
			 * We'll need these to do per-nexthop deletes.
			 */
			copy_nexthops(&(ctx->u.rinfo.zd_old_ng.nexthop),
				      old_re->nhe->nhg.nexthop, NULL);

			if (zebra_nhg_get_backup_nhg(old_re->nhe) != NULL) {
				struct nexthop_group *nhg;
				struct nexthop **nh;

				nhg = zebra_nhg_get_backup_nhg(old_re->nhe);
				nh = &(ctx->u.rinfo.old_backup_ng.nexthop);

				if (nhg->nexthop)
					copy_nexthops(nh, nhg->nexthop, NULL);
			}
#endif	/* !HAVE_NETLINK */
		}

		/*
		 * If the old and new context type, and nexthop group id
		 * are the same there is no need to send down a route replace
		 * as that we know we have sent a nexthop group replace
		 * or an upper level protocol has sent us the exact
		 * same route again.
		 */
		if ((dplane_ctx_get_type(ctx) == dplane_ctx_get_old_type(ctx))
		    && (dplane_ctx_get_nhe_id(ctx)
			== dplane_ctx_get_old_nhe_id(ctx))
		    && (dplane_ctx_get_nhe_id(ctx) >= ZEBRA_NHG_PROTO_LOWER)) {
			struct nexthop *nexthop;

			if (IS_ZEBRA_DEBUG_DPLANE)
				zlog_debug(
					"%s: Ignoring Route exactly the same",
					__func__);

			for (ALL_NEXTHOPS_PTR(dplane_ctx_get_ng(ctx),
					      nexthop)) {
				if (CHECK_FLAG(nexthop->flags,
					       NEXTHOP_FLAG_RECURSIVE))
					continue;

				if (CHECK_FLAG(nexthop->flags,
					       NEXTHOP_FLAG_ACTIVE))
					SET_FLAG(nexthop->flags,
						 NEXTHOP_FLAG_FIB);
			}

			dplane_ctx_free(&ctx);
			return ZEBRA_DPLANE_REQUEST_SUCCESS;
		}

		/* Enqueue context for processing */
		ret = dplane_update_enqueue(ctx);
	}

	/* Update counter */
	atomic_fetch_add_explicit(&zdplane_info.dg_routes_in, 1,
				  memory_order_relaxed);

	if (ret == AOK)
		result = ZEBRA_DPLANE_REQUEST_QUEUED;
	else {
		atomic_fetch_add_explicit(&zdplane_info.dg_route_errors, 1,
					  memory_order_relaxed);
		if (ctx)
			dplane_ctx_free(&ctx);
	}

	return result;
}

/**
 * dplane_nexthop_update_internal() - Helper for enqueuing nexthop changes
 *
 * @nhe:	Nexthop group hash entry where the change occured
 * @op:		The operation to be enqued
 *
 * Return:	Result of the change
 */
static enum zebra_dplane_result
dplane_nexthop_update_internal(struct nhg_hash_entry *nhe, enum dplane_op_e op)
{
	enum zebra_dplane_result result = ZEBRA_DPLANE_REQUEST_FAILURE;
	int ret = EINVAL;
	struct zebra_dplane_ctx *ctx = NULL;

	/* Obtain context block */
	ctx = dplane_ctx_alloc();
	if (!ctx) {
		ret = ENOMEM;
		goto done;
	}

	ret = dplane_ctx_nexthop_init(ctx, op, nhe);
	if (ret == AOK)
		ret = dplane_update_enqueue(ctx);

done:
	/* Update counter */
	atomic_fetch_add_explicit(&zdplane_info.dg_nexthops_in, 1,
				  memory_order_relaxed);

	if (ret == AOK)
		result = ZEBRA_DPLANE_REQUEST_QUEUED;
	else {
		atomic_fetch_add_explicit(&zdplane_info.dg_nexthop_errors, 1,
					  memory_order_relaxed);
		if (ctx)
			dplane_ctx_free(&ctx);
	}

	return result;
}

/*
 * Enqueue a route 'add' for the dataplane.
 */
enum zebra_dplane_result dplane_route_add(struct route_node *rn,
					  struct route_entry *re)
{
	enum zebra_dplane_result ret = ZEBRA_DPLANE_REQUEST_FAILURE;

	if (rn == NULL || re == NULL)
		goto done;

	ret = dplane_route_update_internal(rn, re, NULL,
					   DPLANE_OP_ROUTE_INSTALL);

done:
	return ret;
}

/*
 * Enqueue a route update for the dataplane.
 */
enum zebra_dplane_result dplane_route_update(struct route_node *rn,
					     struct route_entry *re,
					     struct route_entry *old_re)
{
	enum zebra_dplane_result ret = ZEBRA_DPLANE_REQUEST_FAILURE;

	if (rn == NULL || re == NULL)
		goto done;

	ret = dplane_route_update_internal(rn, re, old_re,
					   DPLANE_OP_ROUTE_UPDATE);
done:
	return ret;
}

/*
 * Enqueue a route removal for the dataplane.
 */
enum zebra_dplane_result dplane_route_delete(struct route_node *rn,
					     struct route_entry *re)
{
	enum zebra_dplane_result ret = ZEBRA_DPLANE_REQUEST_FAILURE;

	if (rn == NULL || re == NULL)
		goto done;

	ret = dplane_route_update_internal(rn, re, NULL,
					   DPLANE_OP_ROUTE_DELETE);

done:
	return ret;
}

/*
 * Notify the dplane when system/connected routes change.
 */
enum zebra_dplane_result dplane_sys_route_add(struct route_node *rn,
					      struct route_entry *re)
{
	enum zebra_dplane_result ret = ZEBRA_DPLANE_REQUEST_FAILURE;

	/* Ignore this event unless a provider plugin has requested it. */
	if (!zdplane_info.dg_sys_route_notifs) {
		ret = ZEBRA_DPLANE_REQUEST_SUCCESS;
		goto done;
	}

	if (rn == NULL || re == NULL)
		goto done;

	ret = dplane_route_update_internal(rn, re, NULL,
					   DPLANE_OP_SYS_ROUTE_ADD);

done:
	return ret;
}

/*
 * Notify the dplane when system/connected routes are deleted.
 */
enum zebra_dplane_result dplane_sys_route_del(struct route_node *rn,
					      struct route_entry *re)
{
	enum zebra_dplane_result ret = ZEBRA_DPLANE_REQUEST_FAILURE;

	/* Ignore this event unless a provider plugin has requested it. */
	if (!zdplane_info.dg_sys_route_notifs) {
		ret = ZEBRA_DPLANE_REQUEST_SUCCESS;
		goto done;
	}

	if (rn == NULL || re == NULL)
		goto done;

	ret = dplane_route_update_internal(rn, re, NULL,
					   DPLANE_OP_SYS_ROUTE_DELETE);

done:
	return ret;
}

/*
 * Update from an async notification, to bring other fibs up-to-date.
 */
enum zebra_dplane_result
dplane_route_notif_update(struct route_node *rn,
			  struct route_entry *re,
			  enum dplane_op_e op,
			  struct zebra_dplane_ctx *ctx)
{
	enum zebra_dplane_result result = ZEBRA_DPLANE_REQUEST_FAILURE;
	int ret = EINVAL;
	struct zebra_dplane_ctx *new_ctx = NULL;
	struct nexthop *nexthop;
	struct nexthop_group *nhg;

	if (rn == NULL || re == NULL)
		goto done;

	new_ctx = dplane_ctx_alloc();
	if (new_ctx == NULL)
		goto done;

	/* Init context with info from zebra data structs */
	dplane_ctx_route_init(new_ctx, op, rn, re);

	/* For add/update, need to adjust the nexthops so that we match
	 * the notification state, which may not be the route-entry/RIB
	 * state.
	 */
	if (op == DPLANE_OP_ROUTE_UPDATE ||
	    op == DPLANE_OP_ROUTE_INSTALL) {

		nexthops_free(new_ctx->u.rinfo.zd_ng.nexthop);
		new_ctx->u.rinfo.zd_ng.nexthop = NULL;

		nhg = rib_get_fib_nhg(re);
		if (nhg && nhg->nexthop)
			copy_nexthops(&(new_ctx->u.rinfo.zd_ng.nexthop),
				      nhg->nexthop, NULL);

		/* Check for installed backup nexthops also */
		nhg = rib_get_fib_backup_nhg(re);
		if (nhg && nhg->nexthop) {
			copy_nexthops(&(new_ctx->u.rinfo.zd_ng.nexthop),
				      nhg->nexthop, NULL);
		}

		for (ALL_NEXTHOPS(new_ctx->u.rinfo.zd_ng, nexthop))
			UNSET_FLAG(nexthop->flags, NEXTHOP_FLAG_FIB);

	}

	/* Capture info about the source of the notification, in 'ctx' */
	dplane_ctx_set_notif_provider(new_ctx,
				      dplane_ctx_get_notif_provider(ctx));

	ret = dplane_update_enqueue(new_ctx);

done:
	if (ret == AOK)
		result = ZEBRA_DPLANE_REQUEST_QUEUED;
	else if (new_ctx)
		dplane_ctx_free(&new_ctx);

	return result;
}

/*
 * Enqueue a nexthop add for the dataplane.
 */
enum zebra_dplane_result dplane_nexthop_add(struct nhg_hash_entry *nhe)
{
	enum zebra_dplane_result ret = ZEBRA_DPLANE_REQUEST_FAILURE;

	if (nhe)
		ret = dplane_nexthop_update_internal(nhe, DPLANE_OP_NH_INSTALL);
	return ret;
}

/*
 * Enqueue a nexthop update for the dataplane.
 *
 * Might not need this func since zebra's nexthop objects should be immutable?
 */
enum zebra_dplane_result dplane_nexthop_update(struct nhg_hash_entry *nhe)
{
	enum zebra_dplane_result ret = ZEBRA_DPLANE_REQUEST_FAILURE;

	if (nhe)
		ret = dplane_nexthop_update_internal(nhe, DPLANE_OP_NH_UPDATE);
	return ret;
}

/*
 * Enqueue a nexthop removal for the dataplane.
 */
enum zebra_dplane_result dplane_nexthop_delete(struct nhg_hash_entry *nhe)
{
	enum zebra_dplane_result ret = ZEBRA_DPLANE_REQUEST_FAILURE;

	if (nhe)
		ret = dplane_nexthop_update_internal(nhe, DPLANE_OP_NH_DELETE);

	return ret;
}

/*
 * Enqueue LSP add for the dataplane.
 */
enum zebra_dplane_result dplane_lsp_add(zebra_lsp_t *lsp)
{
	enum zebra_dplane_result ret =
		lsp_update_internal(lsp, DPLANE_OP_LSP_INSTALL);

	return ret;
}

/*
 * Enqueue LSP update for the dataplane.
 */
enum zebra_dplane_result dplane_lsp_update(zebra_lsp_t *lsp)
{
	enum zebra_dplane_result ret =
		lsp_update_internal(lsp, DPLANE_OP_LSP_UPDATE);

	return ret;
}

/*
 * Enqueue LSP delete for the dataplane.
 */
enum zebra_dplane_result dplane_lsp_delete(zebra_lsp_t *lsp)
{
	enum zebra_dplane_result ret =
		lsp_update_internal(lsp, DPLANE_OP_LSP_DELETE);

	return ret;
}

/* Update or un-install resulting from an async notification */
enum zebra_dplane_result
dplane_lsp_notif_update(zebra_lsp_t *lsp,
			enum dplane_op_e op,
			struct zebra_dplane_ctx *notif_ctx)
{
	enum zebra_dplane_result result = ZEBRA_DPLANE_REQUEST_FAILURE;
	int ret = EINVAL;
	struct zebra_dplane_ctx *ctx = NULL;
	struct nhlfe_list_head *head;
	zebra_nhlfe_t *nhlfe, *new_nhlfe;

	/* Obtain context block */
	ctx = dplane_ctx_alloc();
	if (ctx == NULL) {
		ret = ENOMEM;
		goto done;
	}

	/* Copy info from zebra LSP */
	ret = dplane_ctx_lsp_init(ctx, op, lsp);
	if (ret != AOK)
		goto done;

	/* Add any installed backup nhlfes */
	head = &(ctx->u.lsp.backup_nhlfe_list);
	frr_each(nhlfe_list, head, nhlfe) {

		if (CHECK_FLAG(nhlfe->flags, NHLFE_FLAG_INSTALLED) &&
		    CHECK_FLAG(nhlfe->nexthop->flags, NEXTHOP_FLAG_FIB)) {
			new_nhlfe = zebra_mpls_lsp_add_nh(&(ctx->u.lsp),
							  nhlfe->type,
							  nhlfe->nexthop);

			/* Need to copy flags too */
			new_nhlfe->flags = nhlfe->flags;
			new_nhlfe->nexthop->flags = nhlfe->nexthop->flags;
		}
	}

	/* Capture info about the source of the notification */
	dplane_ctx_set_notif_provider(
		ctx,
		dplane_ctx_get_notif_provider(notif_ctx));

	ret = dplane_update_enqueue(ctx);

done:
	/* Update counter */
	atomic_fetch_add_explicit(&zdplane_info.dg_lsps_in, 1,
				  memory_order_relaxed);

	if (ret == AOK)
		result = ZEBRA_DPLANE_REQUEST_QUEUED;
	else {
		atomic_fetch_add_explicit(&zdplane_info.dg_lsp_errors, 1,
					  memory_order_relaxed);
		if (ctx)
			dplane_ctx_free(&ctx);
	}
	return result;
}

/*
 * Enqueue pseudowire install for the dataplane.
 */
enum zebra_dplane_result dplane_pw_install(struct zebra_pw *pw)
{
	return pw_update_internal(pw, DPLANE_OP_PW_INSTALL);
}

/*
 * Enqueue pseudowire un-install for the dataplane.
 */
enum zebra_dplane_result dplane_pw_uninstall(struct zebra_pw *pw)
{
	return pw_update_internal(pw, DPLANE_OP_PW_UNINSTALL);
}

/*
 * Common internal LSP update utility
 */
static enum zebra_dplane_result lsp_update_internal(zebra_lsp_t *lsp,
						    enum dplane_op_e op)
{
	enum zebra_dplane_result result = ZEBRA_DPLANE_REQUEST_FAILURE;
	int ret = EINVAL;
	struct zebra_dplane_ctx *ctx = NULL;

	/* Obtain context block */
	ctx = dplane_ctx_alloc();

	ret = dplane_ctx_lsp_init(ctx, op, lsp);
	if (ret != AOK)
		goto done;

	ret = dplane_update_enqueue(ctx);

done:
	/* Update counter */
	atomic_fetch_add_explicit(&zdplane_info.dg_lsps_in, 1,
				  memory_order_relaxed);

	if (ret == AOK)
		result = ZEBRA_DPLANE_REQUEST_QUEUED;
	else {
		atomic_fetch_add_explicit(&zdplane_info.dg_lsp_errors, 1,
					  memory_order_relaxed);
		dplane_ctx_free(&ctx);
	}

	return result;
}

/*
 * Internal, common handler for pseudowire updates.
 */
static enum zebra_dplane_result pw_update_internal(struct zebra_pw *pw,
						   enum dplane_op_e op)
{
	enum zebra_dplane_result result = ZEBRA_DPLANE_REQUEST_FAILURE;
	int ret;
	struct zebra_dplane_ctx *ctx = NULL;

	ctx = dplane_ctx_alloc();

	ret = dplane_ctx_pw_init(ctx, op, pw);
	if (ret != AOK)
		goto done;

	ret = dplane_update_enqueue(ctx);

done:
	/* Update counter */
	atomic_fetch_add_explicit(&zdplane_info.dg_pws_in, 1,
				  memory_order_relaxed);

	if (ret == AOK)
		result = ZEBRA_DPLANE_REQUEST_QUEUED;
	else {
		atomic_fetch_add_explicit(&zdplane_info.dg_pw_errors, 1,
					  memory_order_relaxed);
		dplane_ctx_free(&ctx);
	}

	return result;
}

/*
 * Enqueue access br_port update.
 */
enum zebra_dplane_result
dplane_br_port_update(const struct interface *ifp, bool non_df,
		      uint32_t sph_filter_cnt,
		      const struct in_addr *sph_filters, uint32_t backup_nhg_id)
{
	enum zebra_dplane_result result = ZEBRA_DPLANE_REQUEST_FAILURE;
	uint32_t flags = 0;
	int ret;
	struct zebra_dplane_ctx *ctx = NULL;
	struct zebra_ns *zns;
	enum dplane_op_e op = DPLANE_OP_BR_PORT_UPDATE;

	if (non_df)
		flags |= DPLANE_BR_PORT_NON_DF;

	if (IS_ZEBRA_DEBUG_DPLANE_DETAIL || IS_ZEBRA_DEBUG_EVPN_MH_ES) {
		uint32_t i;
		char vtep_str[ES_VTEP_LIST_STR_SZ];

		vtep_str[0] = '\0';
		for (i = 0; i < sph_filter_cnt; ++i) {
			snprintfrr(vtep_str + strlen(vtep_str),
				   sizeof(vtep_str) - strlen(vtep_str), "%pI4 ",
				   &sph_filters[i]);
		}
		zlog_debug(
			"init br_port ctx %s: ifp %s, flags 0x%x backup_nhg 0x%x sph %s",
			dplane_op2str(op), ifp->name, flags, backup_nhg_id,
			vtep_str);
	}

	ctx = dplane_ctx_alloc();

	ctx->zd_op = op;
	ctx->zd_status = ZEBRA_DPLANE_REQUEST_SUCCESS;
	ctx->zd_vrf_id = ifp->vrf_id;

	zns = zebra_ns_lookup(ifp->vrf_id);
	dplane_ctx_ns_init(ctx, zns, false);

	ctx->zd_ifindex = ifp->ifindex;
	strlcpy(ctx->zd_ifname, ifp->name, sizeof(ctx->zd_ifname));

	/* Init the br-port-specific data area */
	memset(&ctx->u.br_port, 0, sizeof(ctx->u.br_port));

	ctx->u.br_port.flags = flags;
	ctx->u.br_port.backup_nhg_id = backup_nhg_id;
	ctx->u.br_port.sph_filter_cnt = sph_filter_cnt;
	memcpy(ctx->u.br_port.sph_filters, sph_filters,
	       sizeof(ctx->u.br_port.sph_filters[0]) * sph_filter_cnt);

	/* Enqueue for processing on the dplane pthread */
	ret = dplane_update_enqueue(ctx);

	/* Increment counter */
	atomic_fetch_add_explicit(&zdplane_info.dg_br_port_in, 1,
				  memory_order_relaxed);

	if (ret == AOK) {
		result = ZEBRA_DPLANE_REQUEST_QUEUED;
	} else {
		/* Error counter */
		atomic_fetch_add_explicit(&zdplane_info.dg_br_port_errors, 1,
					  memory_order_relaxed);
		dplane_ctx_free(&ctx);
	}

	return result;
}

/*
 * Enqueue interface address add for the dataplane.
 */
enum zebra_dplane_result dplane_intf_addr_set(const struct interface *ifp,
					      const struct connected *ifc)
{
#if !defined(HAVE_NETLINK) && defined(HAVE_STRUCT_IFALIASREQ)
	/* Extra checks for this OS path. */

	/* Don't configure PtP addresses on broadcast ifs or reverse */
	if (!(ifp->flags & IFF_POINTOPOINT) != !CONNECTED_PEER(ifc)) {
		if (IS_ZEBRA_DEBUG_KERNEL || IS_ZEBRA_DEBUG_DPLANE)
			zlog_debug("Failed to set intf addr: mismatch p2p and connected");

		return ZEBRA_DPLANE_REQUEST_FAILURE;
	}

	/* Ensure that no existing installed v4 route conflicts with
	 * the new interface prefix. This check must be done in the
	 * zebra pthread context, and any route delete (if needed)
	 * is enqueued before the interface address programming attempt.
	 */
	if (ifc->address->family == AF_INET) {
		struct prefix_ipv4 *p;

		p = (struct prefix_ipv4 *)ifc->address;
		rib_lookup_and_pushup(p, ifp->vrf_id);
	}
#endif

	return intf_addr_update_internal(ifp, ifc, DPLANE_OP_ADDR_INSTALL);
}

/*
 * Enqueue interface address remove/uninstall for the dataplane.
 */
enum zebra_dplane_result dplane_intf_addr_unset(const struct interface *ifp,
						const struct connected *ifc)
{
	return intf_addr_update_internal(ifp, ifc, DPLANE_OP_ADDR_UNINSTALL);
}

static enum zebra_dplane_result intf_addr_update_internal(
	const struct interface *ifp, const struct connected *ifc,
	enum dplane_op_e op)
{
	enum zebra_dplane_result result = ZEBRA_DPLANE_REQUEST_FAILURE;
	int ret = EINVAL;
	struct zebra_dplane_ctx *ctx = NULL;
	struct zebra_ns *zns;

	if (IS_ZEBRA_DEBUG_DPLANE_DETAIL)
		zlog_debug("init intf ctx %s: idx %d, addr %u:%pFX",
			   dplane_op2str(op), ifp->ifindex, ifp->vrf_id,
			   ifc->address);

	ctx = dplane_ctx_alloc();

	ctx->zd_op = op;
	ctx->zd_status = ZEBRA_DPLANE_REQUEST_SUCCESS;
	ctx->zd_vrf_id = ifp->vrf_id;

	zns = zebra_ns_lookup(ifp->vrf_id);
	dplane_ctx_ns_init(ctx, zns, false);

	/* Init the interface-addr-specific area */
	memset(&ctx->u.intf, 0, sizeof(ctx->u.intf));

	strlcpy(ctx->zd_ifname, ifp->name, sizeof(ctx->zd_ifname));
	ctx->zd_ifindex = ifp->ifindex;
	ctx->u.intf.prefix = *(ifc->address);

	if (if_is_broadcast(ifp))
		ctx->u.intf.flags |= DPLANE_INTF_BROADCAST;

	if (CONNECTED_PEER(ifc)) {
		ctx->u.intf.dest_prefix = *(ifc->destination);
		ctx->u.intf.flags |=
			(DPLANE_INTF_CONNECTED | DPLANE_INTF_HAS_DEST);
	}

	if (CHECK_FLAG(ifc->flags, ZEBRA_IFA_SECONDARY))
		ctx->u.intf.flags |= DPLANE_INTF_SECONDARY;

	if (ifc->label) {
		size_t len;

		ctx->u.intf.flags |= DPLANE_INTF_HAS_LABEL;

		/* Use embedded buffer if it's adequate; else allocate. */
		len = strlen(ifc->label);

		if (len < sizeof(ctx->u.intf.label_buf)) {
			strlcpy(ctx->u.intf.label_buf, ifc->label,
				sizeof(ctx->u.intf.label_buf));
			ctx->u.intf.label = ctx->u.intf.label_buf;
		} else {
			ctx->u.intf.label = strdup(ifc->label);
		}
	}

	ret = dplane_update_enqueue(ctx);

	/* Increment counter */
	atomic_fetch_add_explicit(&zdplane_info.dg_intf_addrs_in, 1,
				  memory_order_relaxed);

	if (ret == AOK)
		result = ZEBRA_DPLANE_REQUEST_QUEUED;
	else {
		/* Error counter */
		atomic_fetch_add_explicit(&zdplane_info.dg_intf_addr_errors,
					  1, memory_order_relaxed);
		dplane_ctx_free(&ctx);
	}

	return result;
}

/*
 * Enqueue vxlan/evpn mac add (or update).
 */
enum zebra_dplane_result dplane_rem_mac_add(const struct interface *ifp,
					const struct interface *bridge_ifp,
					vlanid_t vid,
					const struct ethaddr *mac,
					struct in_addr vtep_ip,
					bool sticky,
					uint32_t nhg_id,
					bool was_static)
{
	enum zebra_dplane_result result;
	uint32_t update_flags = 0;

	update_flags |= DPLANE_MAC_REMOTE;
	if (was_static)
		update_flags |= DPLANE_MAC_WAS_STATIC;

	/* Use common helper api */
	result = mac_update_common(DPLANE_OP_MAC_INSTALL, ifp, bridge_ifp,
				   vid, mac, vtep_ip, sticky, nhg_id, update_flags);
	return result;
}

/*
 * Enqueue vxlan/evpn mac delete.
 */
enum zebra_dplane_result dplane_rem_mac_del(const struct interface *ifp,
					const struct interface *bridge_ifp,
					vlanid_t vid,
					const struct ethaddr *mac,
					struct in_addr vtep_ip)
{
	enum zebra_dplane_result result;
	uint32_t update_flags = 0;

	update_flags |= DPLANE_MAC_REMOTE;

	/* Use common helper api */
	result = mac_update_common(DPLANE_OP_MAC_DELETE, ifp, bridge_ifp,
				   vid, mac, vtep_ip, false, 0, update_flags);
	return result;
}

/*
 * API to configure link local with either MAC address or IP information
 */
enum zebra_dplane_result dplane_neigh_ip_update(enum dplane_op_e op,
						const struct interface *ifp,
						struct ipaddr *link_ip,
						struct ipaddr *ip,
						uint32_t ndm_state, int protocol)
{
	enum zebra_dplane_result result = ZEBRA_DPLANE_REQUEST_FAILURE;
	uint16_t state = 0;
	uint32_t update_flags;

	if (IS_ZEBRA_DEBUG_DPLANE_DETAIL) {
		char buf1[PREFIX_STRLEN], buf2[PREFIX_STRLEN];

		ipaddr2str(link_ip, buf1, sizeof(buf1));
		ipaddr2str(ip, buf2, sizeof(buf2));
		zlog_debug("init link ctx %s: ifp %s, ip %s link %s",
			   dplane_op2str(op), ifp->name, buf1, buf2);
	}
	if (ndm_state == ZEBRA_NEIGH_STATE_REACHABLE)
		state = DPLANE_NUD_REACHABLE;
	else if (ndm_state == ZEBRA_NEIGH_STATE_FAILED)
		state = DPLANE_NUD_FAILED;

	update_flags = DPLANE_NEIGH_NO_EXTENSION;

	result = neigh_update_internal(op, ifp, (const void *)link_ip,
				       ipaddr_family(link_ip), ip, 0, state,
				       update_flags, protocol);

	return result;
}

/*
 * Enqueue local mac add (or update).
 */
enum zebra_dplane_result dplane_local_mac_add(const struct interface *ifp,
					const struct interface *bridge_ifp,
					vlanid_t vid,
					const struct ethaddr *mac,
					bool sticky,
					uint32_t set_static,
					uint32_t set_inactive)
{
	enum zebra_dplane_result result;
	uint32_t update_flags = 0;
	struct in_addr vtep_ip;

	if (set_static)
		update_flags |= DPLANE_MAC_SET_STATIC;

	if (set_inactive)
		update_flags |= DPLANE_MAC_SET_INACTIVE;

	vtep_ip.s_addr = 0;

	/* Use common helper api */
	result = mac_update_common(DPLANE_OP_MAC_INSTALL, ifp, bridge_ifp,
				     vid, mac, vtep_ip, sticky, 0,
				     update_flags);
	return result;
}

/*
 * Enqueue local mac del
 */
enum zebra_dplane_result
dplane_local_mac_del(const struct interface *ifp,
		     const struct interface *bridge_ifp, vlanid_t vid,
		     const struct ethaddr *mac)
{
	enum zebra_dplane_result result;
	struct in_addr vtep_ip;

	vtep_ip.s_addr = 0;

	/* Use common helper api */
	result = mac_update_common(DPLANE_OP_MAC_DELETE, ifp, bridge_ifp, vid,
				   mac, vtep_ip, false, 0, 0);
	return result;
}
/*
 * Public api to init an empty context - either newly-allocated or
 * reset/cleared - for a MAC update.
 */
void dplane_mac_init(struct zebra_dplane_ctx *ctx,
		     const struct interface *ifp,
		     const struct interface *br_ifp,
		     vlanid_t vid,
		     const struct ethaddr *mac,
		     struct in_addr vtep_ip,
		     bool sticky,
		     uint32_t nhg_id,
		     uint32_t update_flags)
{
	struct zebra_ns *zns;

	ctx->zd_status = ZEBRA_DPLANE_REQUEST_SUCCESS;
	ctx->zd_vrf_id = ifp->vrf_id;

	zns = zebra_ns_lookup(ifp->vrf_id);
	dplane_ctx_ns_init(ctx, zns, false);

	strlcpy(ctx->zd_ifname, ifp->name, sizeof(ctx->zd_ifname));
	ctx->zd_ifindex = ifp->ifindex;

	/* Init the mac-specific data area */
	memset(&ctx->u.macinfo, 0, sizeof(ctx->u.macinfo));

	ctx->u.macinfo.br_ifindex = br_ifp->ifindex;
	ctx->u.macinfo.vtep_ip = vtep_ip;
	ctx->u.macinfo.mac = *mac;
	ctx->u.macinfo.vid = vid;
	ctx->u.macinfo.is_sticky = sticky;
	ctx->u.macinfo.nhg_id = nhg_id;
	ctx->u.macinfo.update_flags = update_flags;
}

/*
 * Common helper api for MAC address/vxlan updates
 */
static enum zebra_dplane_result
mac_update_common(enum dplane_op_e op,
		  const struct interface *ifp,
		  const struct interface *br_ifp,
		  vlanid_t vid,
		  const struct ethaddr *mac,
		  struct in_addr vtep_ip,
		  bool sticky,
		  uint32_t nhg_id,
		  uint32_t update_flags)
{
	enum zebra_dplane_result result = ZEBRA_DPLANE_REQUEST_FAILURE;
	int ret;
	struct zebra_dplane_ctx *ctx = NULL;

	if (IS_ZEBRA_DEBUG_DPLANE_DETAIL)
		zlog_debug("init mac ctx %s: mac %pEA, ifp %s, vtep %pI4",
			   dplane_op2str(op), mac, ifp->name, &vtep_ip);

	ctx = dplane_ctx_alloc();
	ctx->zd_op = op;

	/* Common init for the ctx */
	dplane_mac_init(ctx, ifp, br_ifp, vid, mac, vtep_ip, sticky,
			nhg_id, update_flags);

	/* Enqueue for processing on the dplane pthread */
	ret = dplane_update_enqueue(ctx);

	/* Increment counter */
	atomic_fetch_add_explicit(&zdplane_info.dg_macs_in, 1,
				  memory_order_relaxed);

	if (ret == AOK)
		result = ZEBRA_DPLANE_REQUEST_QUEUED;
	else {
		/* Error counter */
		atomic_fetch_add_explicit(&zdplane_info.dg_mac_errors, 1,
					  memory_order_relaxed);
		dplane_ctx_free(&ctx);
	}

	return result;
}

/*
 * Enqueue evpn neighbor add for the dataplane.
 */
enum zebra_dplane_result dplane_rem_neigh_add(const struct interface *ifp,
					  const struct ipaddr *ip,
					  const struct ethaddr *mac,
					  uint32_t flags, bool was_static)
{
	enum zebra_dplane_result result = ZEBRA_DPLANE_REQUEST_FAILURE;
	uint32_t update_flags = 0;

	update_flags |= DPLANE_NEIGH_REMOTE;

	if (was_static)
		update_flags |= DPLANE_NEIGH_WAS_STATIC;

	result = neigh_update_internal(
		DPLANE_OP_NEIGH_INSTALL, ifp, (const void *)mac, AF_ETHERNET,
		ip, flags, DPLANE_NUD_NOARP, update_flags, 0);

	return result;
}

/*
 * Enqueue local neighbor add for the dataplane.
 */
enum zebra_dplane_result dplane_local_neigh_add(const struct interface *ifp,
					  const struct ipaddr *ip,
					  const struct ethaddr *mac,
					  bool set_router, bool set_static,
					  bool set_inactive)
{
	enum zebra_dplane_result result = ZEBRA_DPLANE_REQUEST_FAILURE;
	uint32_t update_flags = 0;
	uint32_t ntf = 0;
	uint16_t state;

	if (set_static)
		update_flags |= DPLANE_NEIGH_SET_STATIC;

	if (set_inactive) {
		update_flags |= DPLANE_NEIGH_SET_INACTIVE;
		state = DPLANE_NUD_STALE;
	} else {
		state = DPLANE_NUD_REACHABLE;
	}

	if (set_router)
		ntf |= DPLANE_NTF_ROUTER;

	result = neigh_update_internal(DPLANE_OP_NEIGH_INSTALL, ifp,
				       (const void *)mac, AF_ETHERNET, ip, ntf,
				       state, update_flags, 0);

	return result;
}

/*
 * Enqueue evpn neighbor delete for the dataplane.
 */
enum zebra_dplane_result dplane_rem_neigh_delete(const struct interface *ifp,
					     const struct ipaddr *ip)
{
	enum zebra_dplane_result result;
	uint32_t update_flags = 0;

	update_flags |= DPLANE_NEIGH_REMOTE;

	result = neigh_update_internal(DPLANE_OP_NEIGH_DELETE, ifp, NULL,
				       AF_ETHERNET, ip, 0, 0, update_flags, 0);

	return result;
}

/*
 * Enqueue evpn VTEP add for the dataplane.
 */
enum zebra_dplane_result dplane_vtep_add(const struct interface *ifp,
					 const struct in_addr *ip,
					 vni_t vni)
{
	enum zebra_dplane_result result;
	struct ethaddr mac = { {0, 0, 0, 0, 0, 0} };
	struct ipaddr addr;

	if (IS_ZEBRA_DEBUG_VXLAN)
		zlog_debug("Install %pI4 into flood list for VNI %u intf %s(%u)",
			   ip, vni, ifp->name, ifp->ifindex);

	SET_IPADDR_V4(&addr);
	addr.ipaddr_v4 = *ip;

	result = neigh_update_internal(DPLANE_OP_VTEP_ADD, ifp, &mac,
				       AF_ETHERNET, &addr, 0, 0, 0, 0);

	return result;
}

/*
 * Enqueue evpn VTEP add for the dataplane.
 */
enum zebra_dplane_result dplane_vtep_delete(const struct interface *ifp,
					    const struct in_addr *ip,
					    vni_t vni)
{
	enum zebra_dplane_result result;
	struct ethaddr mac = { {0, 0, 0, 0, 0, 0} };
	struct ipaddr addr;

	if (IS_ZEBRA_DEBUG_VXLAN)
		zlog_debug(
			"Uninstall %pI4 from flood list for VNI %u intf %s(%u)",
			ip, vni, ifp->name, ifp->ifindex);

	SET_IPADDR_V4(&addr);
	addr.ipaddr_v4 = *ip;

	result = neigh_update_internal(DPLANE_OP_VTEP_DELETE, ifp,
				       (const void *)&mac, AF_ETHERNET, &addr,
				       0, 0, 0, 0);

	return result;
}

enum zebra_dplane_result dplane_neigh_discover(const struct interface *ifp,
					       const struct ipaddr *ip)
{
	enum zebra_dplane_result result;

	result = neigh_update_internal(DPLANE_OP_NEIGH_DISCOVER, ifp, NULL,
				       AF_ETHERNET, ip, DPLANE_NTF_USE,
				       DPLANE_NUD_INCOMPLETE, 0, 0);

	return result;
}

enum zebra_dplane_result dplane_neigh_table_update(const struct interface *ifp,
						   const uint8_t family,
						   const uint32_t app_probes,
						   const uint32_t ucast_probes,
						   const uint32_t mcast_probes)
{
	enum zebra_dplane_result result = ZEBRA_DPLANE_REQUEST_FAILURE;
	int ret;
	struct zebra_dplane_ctx *ctx = NULL;
	struct zebra_ns *zns;
	enum dplane_op_e op = DPLANE_OP_NEIGH_TABLE_UPDATE;

	if (IS_ZEBRA_DEBUG_DPLANE_DETAIL) {
		zlog_debug("set neigh ctx %s: ifp %s, family %s",
			   dplane_op2str(op), ifp->name, family2str(family));
	}

	ctx = dplane_ctx_alloc();

	ctx->zd_op = op;
	ctx->zd_status = ZEBRA_DPLANE_REQUEST_SUCCESS;
	ctx->zd_vrf_id = ifp->vrf_id;

	zns = zebra_ns_lookup(ifp->vrf_id);
	dplane_ctx_ns_init(ctx, zns, false);

	strlcpy(ctx->zd_ifname, ifp->name, sizeof(ctx->zd_ifname));
	ctx->zd_ifindex = ifp->ifindex;

	/* Init the neighbor-specific data area */
	memset(&ctx->u.neightable, 0, sizeof(ctx->u.neightable));

	ctx->u.neightable.family = family;
	ctx->u.neightable.app_probes = app_probes;
	ctx->u.neightable.ucast_probes = ucast_probes;
	ctx->u.neightable.mcast_probes = mcast_probes;

	/* Enqueue for processing on the dplane pthread */
	ret = dplane_update_enqueue(ctx);

	/* Increment counter */
	atomic_fetch_add_explicit(&zdplane_info.dg_neightable_in, 1,
				  memory_order_relaxed);

	if (ret == AOK)
		result = ZEBRA_DPLANE_REQUEST_QUEUED;
	else {
		/* Error counter */
		atomic_fetch_add_explicit(&zdplane_info.dg_neightable_errors, 1,
					  memory_order_relaxed);
		dplane_ctx_free(&ctx);
	}

	return result;
}

/*
 * Common helper api for neighbor updates
 */
static enum zebra_dplane_result
neigh_update_internal(enum dplane_op_e op, const struct interface *ifp,
		      const void *link, const int link_family,
		      const struct ipaddr *ip, uint32_t flags, uint16_t state,
		      uint32_t update_flags, int protocol)
{
	enum zebra_dplane_result result = ZEBRA_DPLANE_REQUEST_FAILURE;
	int ret;
	struct zebra_dplane_ctx *ctx = NULL;
	struct zebra_ns *zns;
	const struct ethaddr *mac = NULL;
	const struct ipaddr *link_ip = NULL;

	if (link_family == AF_ETHERNET)
		mac = (const struct ethaddr *)link;
	else
		link_ip = (const struct ipaddr *)link;

	if (IS_ZEBRA_DEBUG_DPLANE_DETAIL) {
		char buf1[PREFIX_STRLEN];

		buf1[0] = '\0';
		if (link_family == AF_ETHERNET)
			prefix_mac2str(mac, buf1, sizeof(buf1));
		else
			ipaddr2str(link_ip, buf1, sizeof(buf1));
		zlog_debug("init neigh ctx %s: ifp %s, %s %s, ip %pIA",
			   dplane_op2str(op), ifp->name,
			   link_family == AF_ETHERNET ? "mac " : "link ",
			   buf1, ip);
	}

	ctx = dplane_ctx_alloc();

	ctx->zd_op = op;
	ctx->zd_status = ZEBRA_DPLANE_REQUEST_SUCCESS;
	ctx->zd_vrf_id = ifp->vrf_id;
	dplane_ctx_set_type(ctx, protocol);

	zns = zebra_ns_lookup(ifp->vrf_id);
	dplane_ctx_ns_init(ctx, zns, false);

	strlcpy(ctx->zd_ifname, ifp->name, sizeof(ctx->zd_ifname));
	ctx->zd_ifindex = ifp->ifindex;

	/* Init the neighbor-specific data area */
	memset(&ctx->u.neigh, 0, sizeof(ctx->u.neigh));

	ctx->u.neigh.ip_addr = *ip;
	if (mac)
		ctx->u.neigh.link.mac = *mac;
	else if (link_ip)
		ctx->u.neigh.link.ip_addr = *link_ip;

	ctx->u.neigh.flags = flags;
	ctx->u.neigh.state = state;
	ctx->u.neigh.update_flags = update_flags;

	/* Enqueue for processing on the dplane pthread */
	ret = dplane_update_enqueue(ctx);

	/* Increment counter */
	atomic_fetch_add_explicit(&zdplane_info.dg_neighs_in, 1,
				  memory_order_relaxed);

	if (ret == AOK)
		result = ZEBRA_DPLANE_REQUEST_QUEUED;
	else {
		/* Error counter */
		atomic_fetch_add_explicit(&zdplane_info.dg_neigh_errors, 1,
					  memory_order_relaxed);
		dplane_ctx_free(&ctx);
	}

	return result;
}

/*
 * Common helper api for PBR rule updates
 */
static enum zebra_dplane_result
rule_update_internal(enum dplane_op_e op, struct zebra_pbr_rule *new_rule,
		     struct zebra_pbr_rule *old_rule)
{
	enum zebra_dplane_result result = ZEBRA_DPLANE_REQUEST_FAILURE;
	struct zebra_dplane_ctx *ctx;
	int ret;

	ctx = dplane_ctx_alloc();

	ret = dplane_ctx_rule_init(ctx, op, new_rule, old_rule);
	if (ret != AOK)
		goto done;

	ret = dplane_update_enqueue(ctx);

done:
	atomic_fetch_add_explicit(&zdplane_info.dg_rules_in, 1,
				  memory_order_relaxed);

	if (ret == AOK)
		result = ZEBRA_DPLANE_REQUEST_QUEUED;
	else {
		atomic_fetch_add_explicit(&zdplane_info.dg_rule_errors, 1,
					  memory_order_relaxed);
		dplane_ctx_free(&ctx);
	}

	return result;
}

enum zebra_dplane_result dplane_pbr_rule_add(struct zebra_pbr_rule *rule)
{
	return rule_update_internal(DPLANE_OP_RULE_ADD, rule, NULL);
}

enum zebra_dplane_result dplane_pbr_rule_delete(struct zebra_pbr_rule *rule)
{
	return rule_update_internal(DPLANE_OP_RULE_DELETE, rule, NULL);
}

enum zebra_dplane_result dplane_pbr_rule_update(struct zebra_pbr_rule *old_rule,
						struct zebra_pbr_rule *new_rule)
{
	return rule_update_internal(DPLANE_OP_RULE_UPDATE, new_rule, old_rule);
}
/*
 * Common helper api for iptable updates
 */
static enum zebra_dplane_result
iptable_update_internal(enum dplane_op_e op, struct zebra_pbr_iptable *iptable)
{
	enum zebra_dplane_result result = ZEBRA_DPLANE_REQUEST_FAILURE;
	struct zebra_dplane_ctx *ctx;
	int ret;

	ctx = dplane_ctx_alloc();

	ret = dplane_ctx_iptable_init(ctx, op, iptable);
	if (ret != AOK)
		goto done;

	ret = dplane_update_enqueue(ctx);

done:
	atomic_fetch_add_explicit(&zdplane_info.dg_iptable_in, 1,
				  memory_order_relaxed);

	if (ret == AOK)
		result = ZEBRA_DPLANE_REQUEST_QUEUED;
	else {
		atomic_fetch_add_explicit(&zdplane_info.dg_iptable_errors, 1,
					  memory_order_relaxed);
		dplane_ctx_free(&ctx);
	}

	return result;
}

enum zebra_dplane_result
dplane_pbr_iptable_add(struct zebra_pbr_iptable *iptable)
{
	return iptable_update_internal(DPLANE_OP_IPTABLE_ADD, iptable);
}

enum zebra_dplane_result
dplane_pbr_iptable_delete(struct zebra_pbr_iptable *iptable)
{
	return iptable_update_internal(DPLANE_OP_IPTABLE_DELETE, iptable);
}

/*
 * Common helper api for ipset updates
 */
static enum zebra_dplane_result
ipset_update_internal(enum dplane_op_e op, struct zebra_pbr_ipset *ipset)
{
	enum zebra_dplane_result result = ZEBRA_DPLANE_REQUEST_FAILURE;
	struct zebra_dplane_ctx *ctx;
	int ret;

	ctx = dplane_ctx_alloc();

	ret = dplane_ctx_ipset_init(ctx, op, ipset);
	if (ret != AOK)
		goto done;

	ret = dplane_update_enqueue(ctx);

done:
	atomic_fetch_add_explicit(&zdplane_info.dg_ipset_in, 1,
				  memory_order_relaxed);

	if (ret == AOK)
		result = ZEBRA_DPLANE_REQUEST_QUEUED;
	else {
		atomic_fetch_add_explicit(&zdplane_info.dg_ipset_errors, 1,
					  memory_order_relaxed);
		dplane_ctx_free(&ctx);
	}

	return result;
}

enum zebra_dplane_result dplane_pbr_ipset_add(struct zebra_pbr_ipset *ipset)
{
	return ipset_update_internal(DPLANE_OP_IPSET_ADD, ipset);
}

enum zebra_dplane_result dplane_pbr_ipset_delete(struct zebra_pbr_ipset *ipset)
{
	return ipset_update_internal(DPLANE_OP_IPSET_DELETE, ipset);
}

/*
 * Common helper api for ipset updates
 */
static enum zebra_dplane_result
ipset_entry_update_internal(enum dplane_op_e op,
			    struct zebra_pbr_ipset_entry *ipset_entry)
{
	enum zebra_dplane_result result = ZEBRA_DPLANE_REQUEST_FAILURE;
	struct zebra_dplane_ctx *ctx;
	int ret;

	ctx = dplane_ctx_alloc();

	ret = dplane_ctx_ipset_entry_init(ctx, op, ipset_entry);
	if (ret != AOK)
		goto done;

	ret = dplane_update_enqueue(ctx);

done:
	atomic_fetch_add_explicit(&zdplane_info.dg_ipset_entry_in, 1,
				  memory_order_relaxed);

	if (ret == AOK)
		result = ZEBRA_DPLANE_REQUEST_QUEUED;
	else {
		atomic_fetch_add_explicit(&zdplane_info.dg_ipset_entry_errors,
					  1, memory_order_relaxed);
		dplane_ctx_free(&ctx);
	}

	return result;
}

enum zebra_dplane_result
dplane_pbr_ipset_entry_add(struct zebra_pbr_ipset_entry *ipset)
{
	return ipset_entry_update_internal(DPLANE_OP_IPSET_ENTRY_ADD, ipset);
}

enum zebra_dplane_result
dplane_pbr_ipset_entry_delete(struct zebra_pbr_ipset_entry *ipset)
{
	return ipset_entry_update_internal(DPLANE_OP_IPSET_ENTRY_DELETE, ipset);
}

/*
 * Common helper api for GRE set
 */
enum zebra_dplane_result
dplane_gre_set(struct interface *ifp, struct interface *ifp_link)
{
	enum zebra_dplane_result result = ZEBRA_DPLANE_REQUEST_FAILURE;
	struct zebra_dplane_ctx *ctx;
	enum dplane_op_e op = DPLANE_OP_GRE_SET;
	int ret;
	struct zebra_ns *zns;

	ctx = dplane_ctx_alloc();

	if (!ifp)
		return result;

	if (IS_ZEBRA_DEBUG_DPLANE_DETAIL) {
		zlog_debug("init dplane ctx %s: if %s link %s%s",
			   dplane_op2str(op), ifp->name,
			   ifp_link ? "set" : "unset", ifp_link ?
			   ifp_link->name : "");
	}

	ctx->zd_op = op;
	ctx->zd_status = ZEBRA_DPLANE_REQUEST_SUCCESS;
	zns = zebra_ns_lookup(ifp->vrf_id);
	if (!zns)
		return result;
	dplane_ctx_ns_init(ctx, zns, false);

	dplane_ctx_set_ifname(ctx, ifp->name);
	ctx->zd_vrf_id = ifp->vrf_id;
	ctx->zd_ifindex = ifp->ifindex;
	if (ifp_link)
		ctx->u.gre.link_ifindex = ifp_link->ifindex;
	else
		ctx->u.gre.link_ifindex = 0;

	ctx->zd_status = ZEBRA_DPLANE_REQUEST_SUCCESS;

	/* Enqueue context for processing */
	ret = dplane_update_enqueue(ctx);

	/* Update counter */
	atomic_fetch_add_explicit(&zdplane_info.dg_gre_set_in, 1,
				  memory_order_relaxed);

	if (ret == AOK)
		result = ZEBRA_DPLANE_REQUEST_QUEUED;
	else {
		atomic_fetch_add_explicit(
			&zdplane_info.dg_gre_set_errors, 1,
			memory_order_relaxed);
		if (ctx)
			dplane_ctx_free(&ctx);
		result = ZEBRA_DPLANE_REQUEST_FAILURE;
	}
	return result;
}

/*
 * Handler for 'show dplane'
 */
int dplane_show_helper(struct vty *vty, bool detailed)
{
	uint64_t queued, queue_max, limit, errs, incoming, yields,
		other_errs;

	/* Using atomics because counters are being changed in different
	 * pthread contexts.
	 */
	incoming = atomic_load_explicit(&zdplane_info.dg_routes_in,
					memory_order_relaxed);
	limit = atomic_load_explicit(&zdplane_info.dg_max_queued_updates,
				     memory_order_relaxed);
	queued = atomic_load_explicit(&zdplane_info.dg_routes_queued,
				      memory_order_relaxed);
	queue_max = atomic_load_explicit(&zdplane_info.dg_routes_queued_max,
					 memory_order_relaxed);
	errs = atomic_load_explicit(&zdplane_info.dg_route_errors,
				    memory_order_relaxed);
	yields = atomic_load_explicit(&zdplane_info.dg_update_yields,
				      memory_order_relaxed);
	other_errs = atomic_load_explicit(&zdplane_info.dg_other_errors,
					  memory_order_relaxed);

	vty_out(vty, "Zebra dataplane:\nRoute updates:            %"PRIu64"\n",
		incoming);
	vty_out(vty, "Route update errors:      %"PRIu64"\n", errs);
	vty_out(vty, "Other errors       :      %"PRIu64"\n", other_errs);
	vty_out(vty, "Route update queue limit: %"PRIu64"\n", limit);
	vty_out(vty, "Route update queue depth: %"PRIu64"\n", queued);
	vty_out(vty, "Route update queue max:   %"PRIu64"\n", queue_max);
	vty_out(vty, "Dplane update yields:     %"PRIu64"\n", yields);

	incoming = atomic_load_explicit(&zdplane_info.dg_lsps_in,
					memory_order_relaxed);
	errs = atomic_load_explicit(&zdplane_info.dg_lsp_errors,
				    memory_order_relaxed);
	vty_out(vty, "LSP updates:              %"PRIu64"\n", incoming);
	vty_out(vty, "LSP update errors:        %"PRIu64"\n", errs);

	incoming = atomic_load_explicit(&zdplane_info.dg_pws_in,
					memory_order_relaxed);
	errs = atomic_load_explicit(&zdplane_info.dg_pw_errors,
				    memory_order_relaxed);
	vty_out(vty, "PW updates:               %"PRIu64"\n", incoming);
	vty_out(vty, "PW update errors:         %"PRIu64"\n", errs);

	incoming = atomic_load_explicit(&zdplane_info.dg_intf_addrs_in,
					memory_order_relaxed);
	errs = atomic_load_explicit(&zdplane_info.dg_intf_addr_errors,
				    memory_order_relaxed);
	vty_out(vty, "Intf addr updates:        %"PRIu64"\n", incoming);
	vty_out(vty, "Intf addr errors:         %"PRIu64"\n", errs);

	incoming = atomic_load_explicit(&zdplane_info.dg_macs_in,
					memory_order_relaxed);
	errs = atomic_load_explicit(&zdplane_info.dg_mac_errors,
				    memory_order_relaxed);
	vty_out(vty, "EVPN MAC updates:         %"PRIu64"\n", incoming);
	vty_out(vty, "EVPN MAC errors:          %"PRIu64"\n", errs);

	incoming = atomic_load_explicit(&zdplane_info.dg_neighs_in,
					memory_order_relaxed);
	errs = atomic_load_explicit(&zdplane_info.dg_neigh_errors,
				    memory_order_relaxed);
	vty_out(vty, "EVPN neigh updates:       %"PRIu64"\n", incoming);
	vty_out(vty, "EVPN neigh errors:        %"PRIu64"\n", errs);

	incoming = atomic_load_explicit(&zdplane_info.dg_rules_in,
					memory_order_relaxed);
	errs = atomic_load_explicit(&zdplane_info.dg_rule_errors,
				    memory_order_relaxed);
	vty_out(vty, "Rule updates:             %" PRIu64 "\n", incoming);
	vty_out(vty, "Rule errors:              %" PRIu64 "\n", errs);

	incoming = atomic_load_explicit(&zdplane_info.dg_br_port_in,
					memory_order_relaxed);
	errs = atomic_load_explicit(&zdplane_info.dg_br_port_errors,
				    memory_order_relaxed);
	vty_out(vty, "Bridge port updates:      %" PRIu64 "\n", incoming);
	vty_out(vty, "Bridge port errors:       %" PRIu64 "\n", errs);

	incoming = atomic_load_explicit(&zdplane_info.dg_iptable_in,
					memory_order_relaxed);
	errs = atomic_load_explicit(&zdplane_info.dg_iptable_errors,
				    memory_order_relaxed);
	vty_out(vty, "IPtable updates:             %" PRIu64 "\n", incoming);
	vty_out(vty, "IPtable errors:              %" PRIu64 "\n", errs);
	incoming = atomic_load_explicit(&zdplane_info.dg_ipset_in,
					memory_order_relaxed);
	errs = atomic_load_explicit(&zdplane_info.dg_ipset_errors,
				    memory_order_relaxed);
	vty_out(vty, "IPset updates:             %" PRIu64 "\n", incoming);
	vty_out(vty, "IPset errors:              %" PRIu64 "\n", errs);
	incoming = atomic_load_explicit(&zdplane_info.dg_ipset_entry_in,
					memory_order_relaxed);
	errs = atomic_load_explicit(&zdplane_info.dg_ipset_entry_errors,
				    memory_order_relaxed);
	vty_out(vty, "IPset entry updates:             %" PRIu64 "\n", incoming);
	vty_out(vty, "IPset entry errors:              %" PRIu64 "\n", errs);

	incoming = atomic_load_explicit(&zdplane_info.dg_neightable_in,
					memory_order_relaxed);
	errs = atomic_load_explicit(&zdplane_info.dg_neightable_errors,
				    memory_order_relaxed);
	vty_out(vty, "Neighbor Table updates:       %"PRIu64"\n", incoming);
	vty_out(vty, "Neighbor Table errors:        %"PRIu64"\n", errs);

	incoming = atomic_load_explicit(&zdplane_info.dg_gre_set_in,
					memory_order_relaxed);
	errs = atomic_load_explicit(&zdplane_info.dg_gre_set_errors,
				    memory_order_relaxed);
	vty_out(vty, "GRE set updates:       %"PRIu64"\n", incoming);
	vty_out(vty, "GRE set errors:        %"PRIu64"\n", errs);
	return CMD_SUCCESS;
}

/*
 * Handler for 'show dplane providers'
 */
int dplane_show_provs_helper(struct vty *vty, bool detailed)
{
	struct zebra_dplane_provider *prov;
	uint64_t in, in_q, in_max, out, out_q, out_max;

	vty_out(vty, "Zebra dataplane providers:\n");

	DPLANE_LOCK();
	prov = TAILQ_FIRST(&zdplane_info.dg_providers_q);
	DPLANE_UNLOCK();

	/* Show counters, useful info from each registered provider */
	while (prov) {

		in = atomic_load_explicit(&prov->dp_in_counter,
					  memory_order_relaxed);
		in_q = atomic_load_explicit(&prov->dp_in_queued,
					    memory_order_relaxed);
		in_max = atomic_load_explicit(&prov->dp_in_max,
					      memory_order_relaxed);
		out = atomic_load_explicit(&prov->dp_out_counter,
					   memory_order_relaxed);
		out_q = atomic_load_explicit(&prov->dp_out_queued,
					     memory_order_relaxed);
		out_max = atomic_load_explicit(&prov->dp_out_max,
					       memory_order_relaxed);

		vty_out(vty, "%s (%u): in: %"PRIu64", q: %"PRIu64", q_max: %"PRIu64", out: %"PRIu64", q: %"PRIu64", q_max: %"PRIu64"\n",
			prov->dp_name, prov->dp_id, in, in_q, in_max,
			out, out_q, out_max);

		DPLANE_LOCK();
		prov = TAILQ_NEXT(prov, dp_prov_link);
		DPLANE_UNLOCK();
	}

	return CMD_SUCCESS;
}

/*
 * Helper for 'show run' etc.
 */
int dplane_config_write_helper(struct vty *vty)
{
	if (zdplane_info.dg_max_queued_updates != DPLANE_DEFAULT_MAX_QUEUED)
		vty_out(vty, "zebra dplane limit %u\n",
			zdplane_info.dg_max_queued_updates);

	return 0;
}

/*
 * Provider registration
 */
int dplane_provider_register(const char *name,
			     enum dplane_provider_prio prio,
			     int flags,
			     int (*start_fp)(struct zebra_dplane_provider *),
			     int (*fp)(struct zebra_dplane_provider *),
			     int (*fini_fp)(struct zebra_dplane_provider *,
					    bool early),
			     void *data,
			     struct zebra_dplane_provider **prov_p)
{
	int ret = 0;
	struct zebra_dplane_provider *p = NULL, *last;

	/* Validate */
	if (fp == NULL) {
		ret = EINVAL;
		goto done;
	}

	if (prio <= DPLANE_PRIO_NONE ||
	    prio > DPLANE_PRIO_LAST) {
		ret = EINVAL;
		goto done;
	}

	/* Allocate and init new provider struct */
	p = XCALLOC(MTYPE_DP_PROV, sizeof(struct zebra_dplane_provider));

	pthread_mutex_init(&(p->dp_mutex), NULL);
	TAILQ_INIT(&(p->dp_ctx_in_q));
	TAILQ_INIT(&(p->dp_ctx_out_q));

	p->dp_flags = flags;
	p->dp_priority = prio;
	p->dp_fp = fp;
	p->dp_start = start_fp;
	p->dp_fini = fini_fp;
	p->dp_data = data;

	/* Lock - the dplane pthread may be running */
	DPLANE_LOCK();

	p->dp_id = ++zdplane_info.dg_provider_id;

	if (name)
		strlcpy(p->dp_name, name, DPLANE_PROVIDER_NAMELEN);
	else
		snprintf(p->dp_name, DPLANE_PROVIDER_NAMELEN,
			 "provider-%u", p->dp_id);

	/* Insert into list ordered by priority */
	TAILQ_FOREACH(last, &zdplane_info.dg_providers_q, dp_prov_link) {
		if (last->dp_priority > p->dp_priority)
			break;
	}

	if (last)
		TAILQ_INSERT_BEFORE(last, p, dp_prov_link);
	else
		TAILQ_INSERT_TAIL(&zdplane_info.dg_providers_q, p,
				  dp_prov_link);

	/* And unlock */
	DPLANE_UNLOCK();

	if (IS_ZEBRA_DEBUG_DPLANE)
		zlog_debug("dplane: registered new provider '%s' (%u), prio %d",
			   p->dp_name, p->dp_id, p->dp_priority);

done:
	if (prov_p)
		*prov_p = p;

	return ret;
}

/* Accessors for provider attributes */
const char *dplane_provider_get_name(const struct zebra_dplane_provider *prov)
{
	return prov->dp_name;
}

uint32_t dplane_provider_get_id(const struct zebra_dplane_provider *prov)
{
	return prov->dp_id;
}

void *dplane_provider_get_data(const struct zebra_dplane_provider *prov)
{
	return prov->dp_data;
}

int dplane_provider_get_work_limit(const struct zebra_dplane_provider *prov)
{
	return zdplane_info.dg_updates_per_cycle;
}

/* Lock/unlock a provider's mutex - iff the provider was registered with
 * the THREADED flag.
 */
void dplane_provider_lock(struct zebra_dplane_provider *prov)
{
	if (dplane_provider_is_threaded(prov))
		DPLANE_PROV_LOCK(prov);
}

void dplane_provider_unlock(struct zebra_dplane_provider *prov)
{
	if (dplane_provider_is_threaded(prov))
		DPLANE_PROV_UNLOCK(prov);
}

/*
 * Dequeue and maintain associated counter
 */
struct zebra_dplane_ctx *dplane_provider_dequeue_in_ctx(
	struct zebra_dplane_provider *prov)
{
	struct zebra_dplane_ctx *ctx = NULL;

	dplane_provider_lock(prov);

	ctx = TAILQ_FIRST(&(prov->dp_ctx_in_q));
	if (ctx) {
		TAILQ_REMOVE(&(prov->dp_ctx_in_q), ctx, zd_q_entries);

		atomic_fetch_sub_explicit(&prov->dp_in_queued, 1,
					  memory_order_relaxed);
	}

	dplane_provider_unlock(prov);

	return ctx;
}

/*
 * Dequeue work to a list, return count
 */
int dplane_provider_dequeue_in_list(struct zebra_dplane_provider *prov,
				    struct dplane_ctx_q *listp)
{
	int limit, ret;
	struct zebra_dplane_ctx *ctx;

	limit = zdplane_info.dg_updates_per_cycle;

	dplane_provider_lock(prov);

	for (ret = 0; ret < limit; ret++) {
		ctx = TAILQ_FIRST(&(prov->dp_ctx_in_q));
		if (ctx) {
			TAILQ_REMOVE(&(prov->dp_ctx_in_q), ctx, zd_q_entries);

			TAILQ_INSERT_TAIL(listp, ctx, zd_q_entries);
		} else {
			break;
		}
	}

	if (ret > 0)
		atomic_fetch_sub_explicit(&prov->dp_in_queued, ret,
					  memory_order_relaxed);

	dplane_provider_unlock(prov);

	return ret;
}

uint32_t dplane_provider_out_ctx_queue_len(struct zebra_dplane_provider *prov)
{
	return atomic_load_explicit(&(prov->dp_out_counter),
				    memory_order_relaxed);
}

/*
 * Enqueue and maintain associated counter
 */
void dplane_provider_enqueue_out_ctx(struct zebra_dplane_provider *prov,
				     struct zebra_dplane_ctx *ctx)
{
	uint64_t curr, high;

	dplane_provider_lock(prov);

	TAILQ_INSERT_TAIL(&(prov->dp_ctx_out_q), ctx,
			  zd_q_entries);

	/* Maintain out-queue counters */
	atomic_fetch_add_explicit(&(prov->dp_out_queued), 1,
				  memory_order_relaxed);
	curr = atomic_load_explicit(&prov->dp_out_queued,
				    memory_order_relaxed);
	high = atomic_load_explicit(&prov->dp_out_max,
				    memory_order_relaxed);
	if (curr > high)
		atomic_store_explicit(&prov->dp_out_max, curr,
				      memory_order_relaxed);

	dplane_provider_unlock(prov);

	atomic_fetch_add_explicit(&(prov->dp_out_counter), 1,
				  memory_order_relaxed);
}

/*
 * Accessor for provider object
 */
bool dplane_provider_is_threaded(const struct zebra_dplane_provider *prov)
{
	return (prov->dp_flags & DPLANE_PROV_FLAG_THREADED);
}

/*
 * Internal helper that copies information from a zebra ns object; this is
 * called in the zebra main pthread context as part of dplane ctx init.
 */
static void dplane_info_from_zns(struct zebra_dplane_info *ns_info,
				 struct zebra_ns *zns)
{
	ns_info->ns_id = zns->ns_id;

#if defined(HAVE_NETLINK)
	ns_info->is_cmd = true;
	ns_info->nls = zns->netlink_dplane;
#endif /* NETLINK */
}

/*
 * Provider api to signal that work/events are available
 * for the dataplane pthread.
 */
int dplane_provider_work_ready(void)
{
	/* Note that during zebra startup, we may be offered work before
	 * the dataplane pthread (and thread-master) are ready. We want to
	 * enqueue the work, but the event-scheduling machinery may not be
	 * available.
	 */
	if (zdplane_info.dg_run) {
		thread_add_event(zdplane_info.dg_master,
				 dplane_thread_loop, NULL, 0,
				 &zdplane_info.dg_t_update);
	}

	return AOK;
}

/*
 * Enqueue a context directly to zebra main.
 */
void dplane_provider_enqueue_to_zebra(struct zebra_dplane_ctx *ctx)
{
	struct dplane_ctx_q temp_list;

	/* Zebra's api takes a list, so we need to use a temporary list */
	TAILQ_INIT(&temp_list);

	TAILQ_INSERT_TAIL(&temp_list, ctx, zd_q_entries);
	(zdplane_info.dg_results_cb)(&temp_list);
}

/*
 * Kernel dataplane provider
 */

static void kernel_dplane_log_detail(struct zebra_dplane_ctx *ctx)
{
	char buf[PREFIX_STRLEN];

	switch (dplane_ctx_get_op(ctx)) {

	case DPLANE_OP_ROUTE_INSTALL:
	case DPLANE_OP_ROUTE_UPDATE:
	case DPLANE_OP_ROUTE_DELETE:
		zlog_debug("%u:%pFX Dplane route update ctx %p op %s",
			   dplane_ctx_get_vrf(ctx), dplane_ctx_get_dest(ctx),
			   ctx, dplane_op2str(dplane_ctx_get_op(ctx)));
		break;

	case DPLANE_OP_NH_INSTALL:
	case DPLANE_OP_NH_UPDATE:
	case DPLANE_OP_NH_DELETE:
		zlog_debug("ID (%u) Dplane nexthop update ctx %p op %s",
			   dplane_ctx_get_nhe_id(ctx), ctx,
			   dplane_op2str(dplane_ctx_get_op(ctx)));
		break;

	case DPLANE_OP_LSP_INSTALL:
	case DPLANE_OP_LSP_UPDATE:
	case DPLANE_OP_LSP_DELETE:
		break;

	case DPLANE_OP_PW_INSTALL:
	case DPLANE_OP_PW_UNINSTALL:
		zlog_debug("Dplane pw %s: op %s af %d loc: %u rem: %u",
			   dplane_ctx_get_ifname(ctx),
			   dplane_op2str(ctx->zd_op), dplane_ctx_get_pw_af(ctx),
			   dplane_ctx_get_pw_local_label(ctx),
			   dplane_ctx_get_pw_remote_label(ctx));
		break;

	case DPLANE_OP_ADDR_INSTALL:
	case DPLANE_OP_ADDR_UNINSTALL:
		zlog_debug("Dplane intf %s, idx %u, addr %pFX",
			   dplane_op2str(dplane_ctx_get_op(ctx)),
			   dplane_ctx_get_ifindex(ctx),
			   dplane_ctx_get_intf_addr(ctx));
		break;

	case DPLANE_OP_MAC_INSTALL:
	case DPLANE_OP_MAC_DELETE:
		prefix_mac2str(dplane_ctx_mac_get_addr(ctx), buf,
			       sizeof(buf));

		zlog_debug("Dplane %s, mac %s, ifindex %u",
			   dplane_op2str(dplane_ctx_get_op(ctx)),
			   buf, dplane_ctx_get_ifindex(ctx));
		break;

	case DPLANE_OP_NEIGH_INSTALL:
	case DPLANE_OP_NEIGH_UPDATE:
	case DPLANE_OP_NEIGH_DELETE:
	case DPLANE_OP_VTEP_ADD:
	case DPLANE_OP_VTEP_DELETE:
	case DPLANE_OP_NEIGH_DISCOVER:
	case DPLANE_OP_NEIGH_IP_INSTALL:
	case DPLANE_OP_NEIGH_IP_DELETE:
		ipaddr2str(dplane_ctx_neigh_get_ipaddr(ctx), buf,
			   sizeof(buf));

		zlog_debug("Dplane %s, ip %s, ifindex %u",
			   dplane_op2str(dplane_ctx_get_op(ctx)),
			   buf, dplane_ctx_get_ifindex(ctx));
		break;

	case DPLANE_OP_RULE_ADD:
	case DPLANE_OP_RULE_DELETE:
	case DPLANE_OP_RULE_UPDATE:
		zlog_debug("Dplane rule update op %s, if %s(%u), ctx %p",
			   dplane_op2str(dplane_ctx_get_op(ctx)),
			   dplane_ctx_get_ifname(ctx),
			   dplane_ctx_get_ifindex(ctx), ctx);
		break;

	case DPLANE_OP_SYS_ROUTE_ADD:
	case DPLANE_OP_SYS_ROUTE_DELETE:
	case DPLANE_OP_ROUTE_NOTIFY:
	case DPLANE_OP_LSP_NOTIFY:
	case DPLANE_OP_BR_PORT_UPDATE:

	case DPLANE_OP_NONE:
		break;

	case DPLANE_OP_IPTABLE_ADD:
	case DPLANE_OP_IPTABLE_DELETE: {
		struct zebra_pbr_iptable ipt;

		if (dplane_ctx_get_pbr_iptable(ctx, &ipt))
			zlog_debug("Dplane iptable update op %s, unique(%u), ctx %p",
				   dplane_op2str(dplane_ctx_get_op(ctx)), ipt.unique, ctx);
	} break;
	case DPLANE_OP_IPSET_ADD:
	case DPLANE_OP_IPSET_DELETE: {
		struct zebra_pbr_ipset ipset;

		if (dplane_ctx_get_pbr_ipset(ctx, &ipset))
			zlog_debug("Dplane ipset update op %s, unique(%u), ctx %p",
				   dplane_op2str(dplane_ctx_get_op(ctx)),
				   ipset.unique, ctx);
	} break;
	case DPLANE_OP_IPSET_ENTRY_ADD:
	case DPLANE_OP_IPSET_ENTRY_DELETE: {
		struct zebra_pbr_ipset_entry ipent;

		if (dplane_ctx_get_pbr_ipset_entry(ctx, &ipent))
			zlog_debug("Dplane ipset entry update op %s, unique(%u), ctx %p",
				   dplane_op2str(dplane_ctx_get_op(ctx)),
				   ipent.unique, ctx);
	} break;

	case DPLANE_OP_NEIGH_TABLE_UPDATE:
		zlog_debug("Dplane neigh table op %s, ifp %s, family %s",
			   dplane_op2str(dplane_ctx_get_op(ctx)),
			   dplane_ctx_get_ifname(ctx),
			   family2str(dplane_ctx_neightable_get_family(ctx)));
		break;
	case DPLANE_OP_GRE_SET:
		zlog_debug("Dplane gre set op %s, ifp %s, link %u",
			   dplane_op2str(dplane_ctx_get_op(ctx)),
			   dplane_ctx_get_ifname(ctx),
			   ctx->u.gre.link_ifindex);
		break;
	}
}

static void kernel_dplane_handle_result(struct zebra_dplane_ctx *ctx)
{
	enum zebra_dplane_result res = dplane_ctx_get_status(ctx);

	switch (dplane_ctx_get_op(ctx)) {

	case DPLANE_OP_ROUTE_INSTALL:
	case DPLANE_OP_ROUTE_UPDATE:
	case DPLANE_OP_ROUTE_DELETE:
		if (res != ZEBRA_DPLANE_REQUEST_SUCCESS)
			atomic_fetch_add_explicit(&zdplane_info.dg_route_errors,
						  1, memory_order_relaxed);

		if ((dplane_ctx_get_op(ctx) != DPLANE_OP_ROUTE_DELETE)
		    && (res == ZEBRA_DPLANE_REQUEST_SUCCESS)) {
			struct nexthop *nexthop;

			/* Update installed nexthops to signal which have been
			 * installed.
			 */
			for (ALL_NEXTHOPS_PTR(dplane_ctx_get_ng(ctx),
					      nexthop)) {
				if (CHECK_FLAG(nexthop->flags,
					       NEXTHOP_FLAG_RECURSIVE))
					continue;

				if (CHECK_FLAG(nexthop->flags,
					       NEXTHOP_FLAG_ACTIVE)) {
					SET_FLAG(nexthop->flags,
						 NEXTHOP_FLAG_FIB);
				}
			}
		}
		break;

	case DPLANE_OP_NH_INSTALL:
	case DPLANE_OP_NH_UPDATE:
	case DPLANE_OP_NH_DELETE:
		if (res != ZEBRA_DPLANE_REQUEST_SUCCESS)
			atomic_fetch_add_explicit(
				&zdplane_info.dg_nexthop_errors, 1,
				memory_order_relaxed);
		break;

	case DPLANE_OP_LSP_INSTALL:
	case DPLANE_OP_LSP_UPDATE:
	case DPLANE_OP_LSP_DELETE:
		if (res != ZEBRA_DPLANE_REQUEST_SUCCESS)
			atomic_fetch_add_explicit(&zdplane_info.dg_lsp_errors,
						  1, memory_order_relaxed);
		break;

	case DPLANE_OP_PW_INSTALL:
	case DPLANE_OP_PW_UNINSTALL:
		if (res != ZEBRA_DPLANE_REQUEST_SUCCESS)
			atomic_fetch_add_explicit(&zdplane_info.dg_pw_errors, 1,
						  memory_order_relaxed);
		break;

	case DPLANE_OP_ADDR_INSTALL:
	case DPLANE_OP_ADDR_UNINSTALL:
		if (res != ZEBRA_DPLANE_REQUEST_SUCCESS)
			atomic_fetch_add_explicit(
				&zdplane_info.dg_intf_addr_errors, 1,
				memory_order_relaxed);
		break;

	case DPLANE_OP_MAC_INSTALL:
	case DPLANE_OP_MAC_DELETE:
		if (res != ZEBRA_DPLANE_REQUEST_SUCCESS)
			atomic_fetch_add_explicit(&zdplane_info.dg_mac_errors,
						  1, memory_order_relaxed);
		break;

	case DPLANE_OP_NEIGH_INSTALL:
	case DPLANE_OP_NEIGH_UPDATE:
	case DPLANE_OP_NEIGH_DELETE:
	case DPLANE_OP_VTEP_ADD:
	case DPLANE_OP_VTEP_DELETE:
	case DPLANE_OP_NEIGH_DISCOVER:
	case DPLANE_OP_NEIGH_IP_INSTALL:
	case DPLANE_OP_NEIGH_IP_DELETE:
		if (res != ZEBRA_DPLANE_REQUEST_SUCCESS)
			atomic_fetch_add_explicit(&zdplane_info.dg_neigh_errors,
						  1, memory_order_relaxed);
		break;

	case DPLANE_OP_RULE_ADD:
	case DPLANE_OP_RULE_DELETE:
	case DPLANE_OP_RULE_UPDATE:
		if (res != ZEBRA_DPLANE_REQUEST_SUCCESS)
			atomic_fetch_add_explicit(&zdplane_info.dg_rule_errors,
						  1, memory_order_relaxed);
		break;

	case DPLANE_OP_IPTABLE_ADD:
	case DPLANE_OP_IPTABLE_DELETE:
		if (res != ZEBRA_DPLANE_REQUEST_SUCCESS)
			atomic_fetch_add_explicit(
				&zdplane_info.dg_iptable_errors, 1,
				memory_order_relaxed);
		break;

	case DPLANE_OP_IPSET_ADD:
	case DPLANE_OP_IPSET_DELETE:
		if (res != ZEBRA_DPLANE_REQUEST_SUCCESS)
			atomic_fetch_add_explicit(&zdplane_info.dg_ipset_errors,
						  1, memory_order_relaxed);
		break;

	case DPLANE_OP_IPSET_ENTRY_ADD:
	case DPLANE_OP_IPSET_ENTRY_DELETE:
		if (res != ZEBRA_DPLANE_REQUEST_SUCCESS)
			atomic_fetch_add_explicit(
				&zdplane_info.dg_ipset_entry_errors, 1,
				memory_order_relaxed);
		break;

	case DPLANE_OP_NEIGH_TABLE_UPDATE:
		if (res != ZEBRA_DPLANE_REQUEST_SUCCESS)
			atomic_fetch_add_explicit(
				&zdplane_info.dg_neightable_errors, 1,
				memory_order_relaxed);
		break;

	case DPLANE_OP_GRE_SET:
		if (res != ZEBRA_DPLANE_REQUEST_SUCCESS)
			atomic_fetch_add_explicit(
				&zdplane_info.dg_gre_set_errors, 1,
				memory_order_relaxed);
		break;
	/* Ignore 'notifications' - no-op */
	case DPLANE_OP_SYS_ROUTE_ADD:
	case DPLANE_OP_SYS_ROUTE_DELETE:
	case DPLANE_OP_ROUTE_NOTIFY:
	case DPLANE_OP_LSP_NOTIFY:
	case DPLANE_OP_BR_PORT_UPDATE:
		break;

	case DPLANE_OP_NONE:
		if (res != ZEBRA_DPLANE_REQUEST_SUCCESS)
			atomic_fetch_add_explicit(&zdplane_info.dg_other_errors,
						  1, memory_order_relaxed);
		break;
	}
}

static void kernel_dplane_process_iptable(struct zebra_dplane_provider *prov,
					  struct zebra_dplane_ctx *ctx)
{
	zebra_pbr_process_iptable(ctx);
	dplane_provider_enqueue_out_ctx(prov, ctx);
}

static void kernel_dplane_process_ipset(struct zebra_dplane_provider *prov,
					struct zebra_dplane_ctx *ctx)
{
	zebra_pbr_process_ipset(ctx);
	dplane_provider_enqueue_out_ctx(prov, ctx);
}

static void
kernel_dplane_process_ipset_entry(struct zebra_dplane_provider *prov,
				  struct zebra_dplane_ctx *ctx)
{
	zebra_pbr_process_ipset_entry(ctx);
	dplane_provider_enqueue_out_ctx(prov, ctx);
}

/*
 * Kernel provider callback
 */
static int kernel_dplane_process_func(struct zebra_dplane_provider *prov)
{
	struct zebra_dplane_ctx *ctx, *tctx;
	struct dplane_ctx_q work_list;
	int counter, limit;

	TAILQ_INIT(&work_list);

	limit = dplane_provider_get_work_limit(prov);

	if (IS_ZEBRA_DEBUG_DPLANE_DETAIL)
		zlog_debug("dplane provider '%s': processing",
			   dplane_provider_get_name(prov));

	for (counter = 0; counter < limit; counter++) {
		ctx = dplane_provider_dequeue_in_ctx(prov);
		if (ctx == NULL)
			break;
		if (IS_ZEBRA_DEBUG_DPLANE_DETAIL)
			kernel_dplane_log_detail(ctx);

		if ((dplane_ctx_get_op(ctx) == DPLANE_OP_IPTABLE_ADD
		     || dplane_ctx_get_op(ctx) == DPLANE_OP_IPTABLE_DELETE))
			kernel_dplane_process_iptable(prov, ctx);
		else if ((dplane_ctx_get_op(ctx) == DPLANE_OP_IPSET_ADD
			  || dplane_ctx_get_op(ctx) == DPLANE_OP_IPSET_DELETE))
			kernel_dplane_process_ipset(prov, ctx);
		else if ((dplane_ctx_get_op(ctx) == DPLANE_OP_IPSET_ENTRY_ADD
			  || dplane_ctx_get_op(ctx)
				     == DPLANE_OP_IPSET_ENTRY_DELETE))
			kernel_dplane_process_ipset_entry(prov, ctx);
		else
			TAILQ_INSERT_TAIL(&work_list, ctx, zd_q_entries);
	}

	kernel_update_multi(&work_list);

	TAILQ_FOREACH_SAFE (ctx, &work_list, zd_q_entries, tctx) {
		kernel_dplane_handle_result(ctx);

		TAILQ_REMOVE(&work_list, ctx, zd_q_entries);
		dplane_provider_enqueue_out_ctx(prov, ctx);
	}

	/* Ensure that we'll run the work loop again if there's still
	 * more work to do.
	 */
	if (counter >= limit) {
		if (IS_ZEBRA_DEBUG_DPLANE_DETAIL)
			zlog_debug("dplane provider '%s' reached max updates %d",
				   dplane_provider_get_name(prov), counter);

		atomic_fetch_add_explicit(&zdplane_info.dg_update_yields,
					  1, memory_order_relaxed);

		dplane_provider_work_ready();
	}

	return 0;
}

#ifdef DPLANE_TEST_PROVIDER

/*
 * Test dataplane provider plugin
 */

/*
 * Test provider process callback
 */
static int test_dplane_process_func(struct zebra_dplane_provider *prov)
{
	struct zebra_dplane_ctx *ctx;
	int counter, limit;

	/* Just moving from 'in' queue to 'out' queue */

	if (IS_ZEBRA_DEBUG_DPLANE_DETAIL)
		zlog_debug("dplane provider '%s': processing",
			   dplane_provider_get_name(prov));

	limit = dplane_provider_get_work_limit(prov);

	for (counter = 0; counter < limit; counter++) {
		ctx = dplane_provider_dequeue_in_ctx(prov);
		if (ctx == NULL)
			break;

		if (IS_ZEBRA_DEBUG_DPLANE_DETAIL)
			zlog_debug("dplane provider '%s': op %s",
				   dplane_provider_get_name(prov),
				   dplane_op2str(dplane_ctx_get_op(ctx)));

		dplane_ctx_set_status(ctx, ZEBRA_DPLANE_REQUEST_SUCCESS);

		dplane_provider_enqueue_out_ctx(prov, ctx);
	}

	if (IS_ZEBRA_DEBUG_DPLANE_DETAIL)
		zlog_debug("dplane provider '%s': processed %d",
			   dplane_provider_get_name(prov), counter);

	/* Ensure that we'll run the work loop again if there's still
	 * more work to do.
	 */
	if (counter >= limit)
		dplane_provider_work_ready();

	return 0;
}

/*
 * Test provider shutdown/fini callback
 */
static int test_dplane_shutdown_func(struct zebra_dplane_provider *prov,
				     bool early)
{
	if (IS_ZEBRA_DEBUG_DPLANE)
		zlog_debug("dplane provider '%s': %sshutdown",
			   dplane_provider_get_name(prov),
			   early ? "early " : "");

	return 0;
}
#endif	/* DPLANE_TEST_PROVIDER */

/*
 * Register default kernel provider
 */
static void dplane_provider_init(void)
{
	int ret;

	ret = dplane_provider_register("Kernel",
				       DPLANE_PRIO_KERNEL,
				       DPLANE_PROV_FLAGS_DEFAULT, NULL,
				       kernel_dplane_process_func,
				       NULL,
				       NULL, NULL);

	if (ret != AOK)
		zlog_err("Unable to register kernel dplane provider: %d",
			 ret);

#ifdef DPLANE_TEST_PROVIDER
	/* Optional test provider ... */
	ret = dplane_provider_register("Test",
				       DPLANE_PRIO_PRE_KERNEL,
				       DPLANE_PROV_FLAGS_DEFAULT, NULL,
				       test_dplane_process_func,
				       test_dplane_shutdown_func,
				       NULL /* data */, NULL);

	if (ret != AOK)
		zlog_err("Unable to register test dplane provider: %d",
			 ret);
#endif	/* DPLANE_TEST_PROVIDER */
}

/*
 * Allow zebra code to walk the queue of pending contexts, evaluate each one
 * using a callback function. If the function returns 'true', the context
 * will be dequeued and freed without being processed.
 */
int dplane_clean_ctx_queue(bool (*context_cb)(struct zebra_dplane_ctx *ctx,
					      void *arg), void *val)
{
	struct zebra_dplane_ctx *ctx, *temp;
	struct dplane_ctx_q work_list;

	TAILQ_INIT(&work_list);

	if (context_cb == NULL)
		goto done;

	/* Walk the pending context queue under the dplane lock. */
	DPLANE_LOCK();

	TAILQ_FOREACH_SAFE(ctx, &zdplane_info.dg_update_ctx_q, zd_q_entries,
			   temp) {
		if (context_cb(ctx, val)) {
			TAILQ_REMOVE(&zdplane_info.dg_update_ctx_q, ctx,
				     zd_q_entries);
			TAILQ_INSERT_TAIL(&work_list, ctx, zd_q_entries);
		}
	}

	DPLANE_UNLOCK();

	/* Now free any contexts selected by the caller, without holding
	 * the lock.
	 */
	TAILQ_FOREACH_SAFE(ctx, &work_list, zd_q_entries, temp) {
		TAILQ_REMOVE(&work_list, ctx, zd_q_entries);
		dplane_ctx_fini(&ctx);
	}

done:

	return 0;
}

/* Indicates zebra shutdown/exit is in progress. Some operations may be
 * simplified or skipped during shutdown processing.
 */
bool dplane_is_in_shutdown(void)
{
	return zdplane_info.dg_is_shutdown;
}

/*
 * Enable collection of extra info about interfaces in route updates.
 */
void dplane_enable_intf_extra_info(void)
{
	dplane_collect_extra_intf_info = true;
}

/*
 * Early or pre-shutdown, de-init notification api. This runs pretty
 * early during zebra shutdown, as a signal to stop new work and prepare
 * for updates generated by shutdown/cleanup activity, as zebra tries to
 * remove everything it's responsible for.
 * NB: This runs in the main zebra pthread context.
 */
void zebra_dplane_pre_finish(void)
{
	struct zebra_dplane_provider *prov;

	if (IS_ZEBRA_DEBUG_DPLANE)
		zlog_debug("Zebra dataplane pre-finish called");

	zdplane_info.dg_is_shutdown = true;

	/* Notify provider(s) of pending shutdown. */
	TAILQ_FOREACH(prov, &zdplane_info.dg_providers_q, dp_prov_link) {
		if (prov->dp_fini == NULL)
			continue;

		prov->dp_fini(prov, true /* early */);
	}
}

/*
 * Utility to determine whether work remains enqueued within the dplane;
 * used during system shutdown processing.
 */
static bool dplane_work_pending(void)
{
	bool ret = false;
	struct zebra_dplane_ctx *ctx;
	struct zebra_dplane_provider *prov;

	/* TODO -- just checking incoming/pending work for now, must check
	 * providers
	 */
	DPLANE_LOCK();
	{
		ctx = TAILQ_FIRST(&zdplane_info.dg_update_ctx_q);
		prov = TAILQ_FIRST(&zdplane_info.dg_providers_q);
	}
	DPLANE_UNLOCK();

	if (ctx != NULL) {
		ret = true;
		goto done;
	}

	while (prov) {

		dplane_provider_lock(prov);

		ctx = TAILQ_FIRST(&(prov->dp_ctx_in_q));
		if (ctx == NULL)
			ctx = TAILQ_FIRST(&(prov->dp_ctx_out_q));

		dplane_provider_unlock(prov);

		if (ctx != NULL)
			break;

		DPLANE_LOCK();
		prov = TAILQ_NEXT(prov, dp_prov_link);
		DPLANE_UNLOCK();
	}

	if (ctx != NULL)
		ret = true;

done:
	return ret;
}

/*
 * Shutdown-time intermediate callback, used to determine when all pending
 * in-flight updates are done. If there's still work to do, reschedules itself.
 * If all work is done, schedules an event to the main zebra thread for
 * final zebra shutdown.
 * This runs in the dplane pthread context.
 */
static int dplane_check_shutdown_status(struct thread *event)
{
	if (IS_ZEBRA_DEBUG_DPLANE)
		zlog_debug("Zebra dataplane shutdown status check called");

	if (dplane_work_pending()) {
		/* Reschedule dplane check on a short timer */
		thread_add_timer_msec(zdplane_info.dg_master,
				      dplane_check_shutdown_status,
				      NULL, 100,
				      &zdplane_info.dg_t_shutdown_check);

		/* TODO - give up and stop waiting after a short time? */

	} else {
		/* We appear to be done - schedule a final callback event
		 * for the zebra main pthread.
		 */
		thread_add_event(zrouter.master, zebra_finalize, NULL, 0, NULL);
	}

	return 0;
}

/*
 * Shutdown, de-init api. This runs pretty late during shutdown,
 * after zebra has tried to free/remove/uninstall all routes during shutdown.
 * At this point, dplane work may still remain to be done, so we can't just
 * blindly terminate. If there's still work to do, we'll periodically check
 * and when done, we'll enqueue a task to the zebra main thread for final
 * termination processing.
 *
 * NB: This runs in the main zebra thread context.
 */
void zebra_dplane_finish(void)
{
	if (IS_ZEBRA_DEBUG_DPLANE)
		zlog_debug("Zebra dataplane fini called");

	thread_add_event(zdplane_info.dg_master,
			 dplane_check_shutdown_status, NULL, 0,
			 &zdplane_info.dg_t_shutdown_check);
}

/*
 * Main dataplane pthread event loop. The thread takes new incoming work
 * and offers it to the first provider. It then iterates through the
 * providers, taking complete work from each one and offering it
 * to the next in order. At each step, a limited number of updates are
 * processed during a cycle in order to provide some fairness.
 *
 * This loop through the providers is only run once, so that the dataplane
 * pthread can look for other pending work - such as i/o work on behalf of
 * providers.
 */
static int dplane_thread_loop(struct thread *event)
{
	struct dplane_ctx_q work_list;
	struct dplane_ctx_q error_list;
	struct zebra_dplane_provider *prov;
	struct zebra_dplane_ctx *ctx, *tctx;
	int limit, counter, error_counter;
	uint64_t curr, high;
	bool reschedule = false;

	/* Capture work limit per cycle */
	limit = zdplane_info.dg_updates_per_cycle;

	/* Init temporary lists used to move contexts among providers */
	TAILQ_INIT(&work_list);
	TAILQ_INIT(&error_list);
	error_counter = 0;

	/* Check for zebra shutdown */
	if (!zdplane_info.dg_run)
		goto done;

	/* Dequeue some incoming work from zebra (if any) onto the temporary
	 * working list.
	 */
	DPLANE_LOCK();

	/* Locate initial registered provider */
	prov = TAILQ_FIRST(&zdplane_info.dg_providers_q);

	/* Move new work from incoming list to temp list */
	for (counter = 0; counter < limit; counter++) {
		ctx = TAILQ_FIRST(&zdplane_info.dg_update_ctx_q);
		if (ctx) {
			TAILQ_REMOVE(&zdplane_info.dg_update_ctx_q, ctx,
				     zd_q_entries);

			ctx->zd_provider = prov->dp_id;

			TAILQ_INSERT_TAIL(&work_list, ctx, zd_q_entries);
		} else {
			break;
		}
	}

	DPLANE_UNLOCK();

	atomic_fetch_sub_explicit(&zdplane_info.dg_routes_queued, counter,
				  memory_order_relaxed);

	if (IS_ZEBRA_DEBUG_DPLANE_DETAIL)
		zlog_debug("dplane: incoming new work counter: %d", counter);

	/* Iterate through the registered providers, offering new incoming
	 * work. If the provider has outgoing work in its queue, take that
	 * work for the next provider
	 */
	while (prov) {

		/* At each iteration, the temporary work list has 'counter'
		 * items.
		 */
		if (IS_ZEBRA_DEBUG_DPLANE_DETAIL)
			zlog_debug("dplane enqueues %d new work to provider '%s'",
				   counter, dplane_provider_get_name(prov));

		/* Capture current provider id in each context; check for
		 * error status.
		 */
		TAILQ_FOREACH_SAFE(ctx, &work_list, zd_q_entries, tctx) {
			if (dplane_ctx_get_status(ctx) ==
			    ZEBRA_DPLANE_REQUEST_SUCCESS) {
				ctx->zd_provider = prov->dp_id;
			} else {
				/*
				 * TODO -- improve error-handling: recirc
				 * errors backwards so that providers can
				 * 'undo' their work (if they want to)
				 */

				/* Move to error list; will be returned
				 * zebra main.
				 */
				TAILQ_REMOVE(&work_list, ctx, zd_q_entries);
				TAILQ_INSERT_TAIL(&error_list,
						  ctx, zd_q_entries);
				error_counter++;
			}
		}

		/* Enqueue new work to the provider */
		dplane_provider_lock(prov);

		if (TAILQ_FIRST(&work_list))
			TAILQ_CONCAT(&(prov->dp_ctx_in_q), &work_list,
				     zd_q_entries);

		atomic_fetch_add_explicit(&prov->dp_in_counter, counter,
					  memory_order_relaxed);
		atomic_fetch_add_explicit(&prov->dp_in_queued, counter,
					  memory_order_relaxed);
		curr = atomic_load_explicit(&prov->dp_in_queued,
					    memory_order_relaxed);
		high = atomic_load_explicit(&prov->dp_in_max,
					    memory_order_relaxed);
		if (curr > high)
			atomic_store_explicit(&prov->dp_in_max, curr,
					      memory_order_relaxed);

		dplane_provider_unlock(prov);

		/* Reset the temp list (though the 'concat' may have done this
		 * already), and the counter
		 */
		TAILQ_INIT(&work_list);
		counter = 0;

		/* Call into the provider code. Note that this is
		 * unconditional: we offer to do work even if we don't enqueue
		 * any _new_ work.
		 */
		(*prov->dp_fp)(prov);

		/* Check for zebra shutdown */
		if (!zdplane_info.dg_run)
			break;

		/* Dequeue completed work from the provider */
		dplane_provider_lock(prov);

		while (counter < limit) {
			ctx = TAILQ_FIRST(&(prov->dp_ctx_out_q));
			if (ctx) {
				TAILQ_REMOVE(&(prov->dp_ctx_out_q), ctx,
					     zd_q_entries);

				TAILQ_INSERT_TAIL(&work_list,
						  ctx, zd_q_entries);
				counter++;
			} else
				break;
		}

		dplane_provider_unlock(prov);

		if (counter >= limit)
			reschedule = true;

		if (IS_ZEBRA_DEBUG_DPLANE_DETAIL)
			zlog_debug("dplane dequeues %d completed work from provider %s",
				   counter, dplane_provider_get_name(prov));

		/* Locate next provider */
		DPLANE_LOCK();
		prov = TAILQ_NEXT(prov, dp_prov_link);
		DPLANE_UNLOCK();
	}

	/*
	 * We hit the work limit while processing at least one provider's
	 * output queue - ensure we come back and finish it.
	 */
	if (reschedule)
		dplane_provider_work_ready();

	/* After all providers have been serviced, enqueue any completed
	 * work and any errors back to zebra so it can process the results.
	 */
	if (IS_ZEBRA_DEBUG_DPLANE_DETAIL)
		zlog_debug("dplane has %d completed, %d errors, for zebra main",
			   counter, error_counter);

	/*
	 * Hand lists through the api to zebra main,
	 * to reduce the number of lock/unlock cycles
	 */

	/* Call through to zebra main */
	(zdplane_info.dg_results_cb)(&error_list);

	TAILQ_INIT(&error_list);

	/* Call through to zebra main */
	(zdplane_info.dg_results_cb)(&work_list);

	TAILQ_INIT(&work_list);

done:
	return 0;
}

/*
 * Final phase of shutdown, after all work enqueued to dplane has been
 * processed. This is called from the zebra main pthread context.
 */
void zebra_dplane_shutdown(void)
{
	struct zebra_dplane_provider *dp;

	if (IS_ZEBRA_DEBUG_DPLANE)
		zlog_debug("Zebra dataplane shutdown called");

	/* Stop dplane thread, if it's running */

	zdplane_info.dg_run = false;

	if (zdplane_info.dg_t_update)
		thread_cancel_async(zdplane_info.dg_t_update->master,
				    &zdplane_info.dg_t_update, NULL);

	frr_pthread_stop(zdplane_info.dg_pthread, NULL);

	/* Destroy pthread */
	frr_pthread_destroy(zdplane_info.dg_pthread);
	zdplane_info.dg_pthread = NULL;
	zdplane_info.dg_master = NULL;

	/* Notify provider(s) of final shutdown.
	 * Note that this call is in the main pthread, so providers must
	 * be prepared for that.
	 */
	TAILQ_FOREACH(dp, &zdplane_info.dg_providers_q, dp_prov_link) {
		if (dp->dp_fini == NULL)
			continue;

		dp->dp_fini(dp, false);
	}

	/* TODO -- Clean-up provider objects */

	/* TODO -- Clean queue(s), free memory */
}

/*
 * Initialize the dataplane module during startup, internal/private version
 */
static void zebra_dplane_init_internal(void)
{
	memset(&zdplane_info, 0, sizeof(zdplane_info));

	pthread_mutex_init(&zdplane_info.dg_mutex, NULL);

	TAILQ_INIT(&zdplane_info.dg_update_ctx_q);
	TAILQ_INIT(&zdplane_info.dg_providers_q);

	zdplane_info.dg_updates_per_cycle = DPLANE_DEFAULT_NEW_WORK;

	zdplane_info.dg_max_queued_updates = DPLANE_DEFAULT_MAX_QUEUED;

	/* Register default kernel 'provider' during init */
	dplane_provider_init();
}

/*
 * Start the dataplane pthread. This step needs to be run later than the
 * 'init' step, in case zebra has fork-ed.
 */
void zebra_dplane_start(void)
{
	struct zebra_dplane_provider *prov;
	struct frr_pthread_attr pattr = {
		.start = frr_pthread_attr_default.start,
		.stop = frr_pthread_attr_default.stop
	};

	/* Start dataplane pthread */

	zdplane_info.dg_pthread = frr_pthread_new(&pattr, "Zebra dplane thread",
						  "zebra_dplane");

	zdplane_info.dg_master = zdplane_info.dg_pthread->master;

	zdplane_info.dg_run = true;

	/* Enqueue an initial event for the dataplane pthread */
	thread_add_event(zdplane_info.dg_master, dplane_thread_loop, NULL, 0,
			 &zdplane_info.dg_t_update);

	/* Call start callbacks for registered providers */

	DPLANE_LOCK();
	prov = TAILQ_FIRST(&zdplane_info.dg_providers_q);
	DPLANE_UNLOCK();

	while (prov) {

		if (prov->dp_start)
			(prov->dp_start)(prov);

		/* Locate next provider */
		DPLANE_LOCK();
		prov = TAILQ_NEXT(prov, dp_prov_link);
		DPLANE_UNLOCK();
	}

	frr_pthread_run(zdplane_info.dg_pthread, NULL);
}

/*
 * Initialize the dataplane module at startup; called by zebra rib_init()
 */
void zebra_dplane_init(int (*results_fp)(struct dplane_ctx_q *))
{
	zebra_dplane_init_internal();
	zdplane_info.dg_results_cb = results_fp;
}
