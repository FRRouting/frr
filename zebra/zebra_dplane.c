// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Zebra dataplane layer.
 * Copyright (c) 2018 Volta Networks, Inc.
 * Portions:
 *		Copyright (c) 2021 The MITRE Corporation.
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "lib/libfrr.h"
#include "lib/debug.h"
#include "lib/frratomic.h"
#include "lib/frr_pthread.h"
#include "lib/memory.h"
#include "lib/zebra.h"
#include "zebra/netconf_netlink.h"
#include "zebra/zebra_router.h"
#include "zebra/zebra_dplane.h"
#include "zebra/zebra_vxlan_private.h"
#include "zebra/zebra_mpls.h"
#include "zebra/rt.h"
#include "zebra/debug.h"
#include "zebra/zebra_pbr.h"
#include "zebra/zebra_neigh.h"
#include "zebra/zebra_tc.h"
#include "printfrr.h"

/* Memory types */
DEFINE_MTYPE_STATIC(ZEBRA, DP_CTX, "Zebra DPlane Ctx");
DEFINE_MTYPE_STATIC(ZEBRA, DP_INTF, "Zebra DPlane Intf");
DEFINE_MTYPE_STATIC(ZEBRA, DP_PROV, "Zebra DPlane Provider");
DEFINE_MTYPE_STATIC(ZEBRA, DP_NETFILTER, "Zebra Netfilter Internal Object");
DEFINE_MTYPE_STATIC(ZEBRA, DP_NS, "DPlane NSes");

DEFINE_MTYPE(ZEBRA, VLAN_CHANGE_ARR, "Vlan Change Array");

#ifndef AOK
#  define AOK 0
#endif

/*
 * Dataplane API version. This must be updated when any incompatible changes
 * are made. The minor version (at least) should be updated when new APIs
 * are introduced.
 */
static uint32_t zdplane_version = MAKE_FRRVERSION(2, 0, 0);

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
	uint32_t pic_nhe_id;
	afi_t afi;
	vrf_id_t vrf_id;
	int type;

	struct nexthop_group ng;
	struct nh_grp nh_grp[MULTIPATH_NUM];
	uint16_t nh_grp_count;
};

/*
 * Optional extra info about interfaces used in route updates' nexthops.
 */
struct dplane_intf_extra {
	vrf_id_t vrf_id;
	uint32_t ifindex;
	uint32_t flags;
	uint32_t status;

	struct dplane_intf_extra_list_item dlink;
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

	uint32_t zd_flags;

	/* Nexthop hash entry info */
	struct dplane_nexthop_info nhe;
	struct dplane_nexthop_info unresolved_nhe;

	/* Nexthops */
	uint32_t zd_nhg_id;
	struct nexthop_group zd_ng;

	/* Backup nexthops (if present) */
	struct nexthop_group backup_ng;

	/* "Previous" nexthops, used only in route updates without netlink */
	struct nexthop_group zd_old_ng;
	struct nexthop_group old_backup_ng;

	/* Optional list of extra interface info */
	struct dplane_intf_extra_list_head intf_extra_list;
};

/*
 * Pseudowire info for the dataplane
 */
struct dplane_pw_info {
	int type;
	int af;
	int status;
	uint32_t flags;
	uint32_t nhg_id;
	union g_addr dest;
	mpls_label_t local_label;
	mpls_label_t remote_label;

	/* Nexthops that are valid and installed */
	struct nexthop_group fib_nhg;

	/* Primary and backup nexthop sets, copied from the resolving route. */
	struct nexthop_group primary_nhg;
	struct nexthop_group backup_nhg;

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

	enum zebra_iftype zif_type;
	ifindex_t bond_ifindex;
	ifindex_t link_ifindex;
	int32_t mtu;
	vrf_id_t vrf_id;
	enum zebra_slave_iftype zif_slave_type;
	ifindex_t master_ifindex;
	ifindex_t bridge_ifindex;
	ns_id_t link_nsid;
	enum zebra_slave_iftype zslave_type;
	uint8_t bypass;
	enum zebra_link_type zltype;
	bool startup;
	uint8_t family;
	struct zebra_vxlan_vni_array *vniarray;
	bool no_bvinfo_avail;
	bool no_afspec_avail;
	struct zebra_dplane_bridge_vlan_info bvinfo;
	struct zebra_dplane_bridge_vlan_info_array *bvarray;

	char desc[128];

	int32_t hw_addr_len;
	uint8_t hw_addr[INTERFACE_HWADDR_MAX];

	uint32_t table_id;

	struct zebra_l2info_bridge binfo;
	struct zebra_l2info_vlan vinfo;
	struct zebra_l2info_vxlan vxinfo;
	struct zebra_l2info_gre grinfo;

	uint32_t rc_bitfield;

	uint32_t txqlen;

	uint32_t metric;
	uint32_t flags;

	bool protodown;
	bool protodown_set;
	bool pd_reason_val;

#define DPLANE_INTF_CONNECTED   (1 << 0) /* Connected peer, p2p */
#define DPLANE_INTF_SECONDARY   (1 << 1)
#define DPLANE_INTF_BROADCAST   (1 << 2)
#define DPLANE_INTF_HAS_DEST    DPLANE_INTF_CONNECTED
#define DPLANE_INTF_HAS_LABEL   (1 << 4)
#define DPLANE_INTF_NOPREFIXROUTE (1 << 5)

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
	vni_t vni;
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
	vni_t vni;
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
	struct pbr_rule prule;

	struct ethaddr smac;
	struct ethaddr dmac;
	int out_ifindex;
	intptr_t dp_flow_ptr;
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
	unsigned int mtu;
	struct zebra_l2info_gre info;
};


/*
 * Network interface configuration info - aligned with netlink's NETCONF
 * info. The flags values are public, in the dplane.h file...
 */
struct dplane_netconf_info {
	enum dplane_netconf_status_e mpls_val;
	enum dplane_netconf_status_e mcast_val;
	enum dplane_netconf_status_e linkdown_val;
};

struct dplane_tc_qdisc_info {
	enum tc_qdisc_kind kind;
	const char *kind_str;
};

struct dplane_tc_class_info {
	uint32_t handle;
	enum tc_qdisc_kind kind;
	const char *kind_str;
	uint64_t rate;
	uint64_t ceil;
};

struct dplane_tc_filter_info {
	uint32_t handle;
	uint16_t priority;
	enum tc_filter_kind kind;
	const char *kind_str;
	uint32_t filter_bm;
	uint16_t eth_proto;
	uint8_t ip_proto;
	struct prefix src_ip;
	struct prefix dst_ip;
	uint16_t src_port_min;
	uint16_t src_port_max;
	uint16_t dst_port_min;
	uint16_t dst_port_max;
	uint8_t dsfield;
	uint8_t dsfield_mask;
	uint32_t classid;
};

/*
 * SRv6 encapsulation params context for the dataplane
 */
struct dplane_srv6_encap_ctx {
	struct in6_addr srcaddr;
};

/*
 * VLAN info for the dataplane
 */
struct dplane_vlan_info {
	ifindex_t ifindex;
	struct zebra_vxlan_vlan_array *vlan_array;
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

	char zd_ifname[IFNAMSIZ];
	ifindex_t zd_ifindex;

	/* Support info for different kinds of updates */
	union {
		struct dplane_route_info rinfo;
		struct zebra_lsp lsp;
		struct dplane_pw_info pw;
		struct dplane_br_port_info br_port;
		struct dplane_intf_info intf;
		struct dplane_vlan_info vlan_info;
		struct dplane_mac_info macinfo;
		struct dplane_neigh_info neigh;
		struct dplane_rule_info rule;
		struct dplane_tc_qdisc_info tc_qdisc;
		struct dplane_tc_class_info tc_class;
		struct dplane_tc_filter_info tc_filter;
		struct zebra_pbr_iptable iptable;
		struct zebra_pbr_ipset ipset;
		struct {
			struct zebra_pbr_ipset_entry entry;
			struct zebra_pbr_ipset_info info;
		} ipset_entry;
		struct dplane_neigh_table neightable;
		struct dplane_gre_ctx gre;
		struct dplane_netconf_info netconf;
		enum zebra_dplane_startup_notifications spot;
		struct dplane_srv6_encap_ctx srv6_encap;
	} u;

	/* Namespace info, used especially for netlink kernel communication */
	struct zebra_dplane_info zd_ns_info;

	/* Embedded list linkage */
	struct dplane_ctx_list_item zd_entries;
};

/* Flag that can be set by a pre-kernel provider as a signal that an update
 * should bypass the kernel.
 */
#define DPLANE_CTX_FLAG_NO_KERNEL 0x01

/* List types declared now that the structs involved are defined. */
DECLARE_DLIST(dplane_ctx_list, struct zebra_dplane_ctx, zd_entries);
DECLARE_DLIST(dplane_intf_extra_list, struct dplane_intf_extra, dlink);

/* List for dplane plugins/providers */
PREDECL_DLIST(dplane_prov_list);

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
	_Atomic uint32_t dp_in_max;
	_Atomic uint32_t dp_out_counter;
	_Atomic uint32_t dp_out_max;
	_Atomic uint32_t dp_error_counter;

	/* Queue of contexts inbound to the provider */
	struct dplane_ctx_list_head dp_ctx_in_list;

	/* Queue of completed contexts outbound from the provider back
	 * towards the dataplane module.
	 */
	struct dplane_ctx_list_head dp_ctx_out_list;

	/* Embedded list linkage for provider objects */
	struct dplane_prov_list_item dp_link;
};

/* Declare list of providers/plugins */
DECLARE_DLIST(dplane_prov_list, struct zebra_dplane_provider, dp_link);

/* Declare types for list of zns info objects */
PREDECL_DLIST(zns_info_list);

struct dplane_zns_info {
	struct zebra_dplane_info info;

	/* Request data from the OS */
	struct event *t_request;

	/* Read event */
	struct event *t_read;

	/* List linkage */
	struct zns_info_list_item link;
};

/*
 * Globals
 */
static struct zebra_dplane_globals {
	/* Mutex to control access to dataplane components */
	pthread_mutex_t dg_mutex;

	/* Results callback registered by zebra 'core' */
	int (*dg_results_cb)(struct dplane_ctx_list_head *ctxlist);

	/* Sentinel for beginning of shutdown */
	volatile bool dg_is_shutdown;

	/* Sentinel for end of shutdown */
	volatile bool dg_run;

	/* Update context queue inbound to the dataplane */
	struct dplane_ctx_list_head dg_update_list;

	/* Ordered list of providers */
	struct dplane_prov_list_head dg_providers;

	/* List of info about each zns */
	struct zns_info_list_head dg_zns_list;

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
	_Atomic uint32_t dg_intf_changes;
	_Atomic uint32_t dg_intf_changes_errors;

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

	_Atomic uint32_t dg_intfs_in;
	_Atomic uint32_t dg_intf_errors;

	_Atomic uint32_t dg_tcs_in;
	_Atomic uint32_t dg_tcs_errors;

	_Atomic uint32_t dg_srv6_encap_srcaddr_set_in;
	_Atomic uint32_t dg_srv6_encap_srcaddr_set_errors;

	/* Dataplane pthread */
	struct frr_pthread *dg_pthread;

	/* Event-delivery context 'master' for the dplane */
	struct event_loop *dg_master;

	/* Event/'thread' pointer for queued updates */
	struct event *dg_t_update;

	/* Event pointer for pending shutdown check loop */
	struct event *dg_t_shutdown_check;

} zdplane_info;

/* Instantiate zns list type */
DECLARE_DLIST(zns_info_list, struct dplane_zns_info, link);

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
static void dplane_thread_loop(struct event *event);
static enum zebra_dplane_result lsp_update_internal(struct zebra_lsp *lsp,
						    enum dplane_op_e op);
static enum zebra_dplane_result pw_update_internal(struct zebra_pw *pw,
						   enum dplane_op_e op);
static enum zebra_dplane_result intf_addr_update_internal(
	const struct interface *ifp, const struct connected *ifc,
	enum dplane_op_e op);
static enum zebra_dplane_result
mac_update_common(enum dplane_op_e op, const struct interface *ifp,
		  const struct interface *br_ifp, vlanid_t vid,
		  const struct ethaddr *mac, vni_t vni, struct in_addr vtep_ip,
		  bool sticky, uint32_t nhg_id, uint32_t update_flags);
static enum zebra_dplane_result
neigh_update_internal(enum dplane_op_e op, const struct interface *ifp,
		      const void *link, int link_family,
		      const struct ipaddr *ip, vni_t vni, uint32_t flags,
		      uint16_t state, uint32_t update_flags, int protocol);

/*
 * Public APIs
 */

/* Access the dplane API version */
uint32_t zebra_dplane_get_version(void)
{
	return zdplane_version;
}

/* Obtain thread_master for dataplane thread */
struct event_loop *dplane_get_thread_master(void)
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
	struct dplane_intf_extra *if_extra;

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
		while ((if_extra = dplane_intf_extra_list_pop(
				&ctx->u.rinfo.intf_extra_list)))
			XFREE(MTYPE_DP_INTF, if_extra);

		break;

	case DPLANE_OP_NH_INSTALL:
	case DPLANE_OP_NH_UPDATE:
	case DPLANE_OP_NH_DELETE:
	case DPLANE_OP_PIC_NH_INSTALL:
	case DPLANE_OP_PIC_NH_UPDATE:
	case DPLANE_OP_PIC_NH_DELETE: {
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
		struct zebra_nhlfe *nhlfe;

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
		if (ctx->u.pw.fib_nhg.nexthop) {
			/* This deals with recursive nexthops too */
			nexthops_free(ctx->u.pw.fib_nhg.nexthop);

			ctx->u.pw.fib_nhg.nexthop = NULL;
		}
		if (ctx->u.pw.primary_nhg.nexthop) {
			nexthops_free(ctx->u.pw.primary_nhg.nexthop);

			ctx->u.pw.primary_nhg.nexthop = NULL;
		}
		if (ctx->u.pw.backup_nhg.nexthop) {
			nexthops_free(ctx->u.pw.backup_nhg.nexthop);

			ctx->u.pw.backup_nhg.nexthop = NULL;
		}
		break;

	case DPLANE_OP_ADDR_INSTALL:
	case DPLANE_OP_ADDR_UNINSTALL:
	case DPLANE_OP_INTF_ADDR_ADD:
	case DPLANE_OP_INTF_ADDR_DEL:
		/* Maybe free label string, if allocated */
		if (ctx->u.intf.label != NULL &&
		    ctx->u.intf.label != ctx->u.intf.label_buf) {
			XFREE(MTYPE_DP_CTX, ctx->u.intf.label);
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
	case DPLANE_OP_INTF_INSTALL:
	case DPLANE_OP_INTF_UPDATE:
		if (ctx->u.intf.vniarray)
			XFREE(MTYPE_TMP, ctx->u.intf.vniarray);
		if (ctx->u.intf.bvarray)
			XFREE(MTYPE_TMP, ctx->u.intf.bvarray);
		break;
	case DPLANE_OP_INTF_DELETE:
	case DPLANE_OP_TC_QDISC_INSTALL:
	case DPLANE_OP_TC_QDISC_UNINSTALL:
	case DPLANE_OP_TC_CLASS_ADD:
	case DPLANE_OP_TC_CLASS_DELETE:
	case DPLANE_OP_TC_CLASS_UPDATE:
	case DPLANE_OP_TC_FILTER_ADD:
	case DPLANE_OP_TC_FILTER_DELETE:
	case DPLANE_OP_TC_FILTER_UPDATE:
		break;

	case DPLANE_OP_IPSET_ENTRY_ADD:
	case DPLANE_OP_IPSET_ENTRY_DELETE:
		break;
	case DPLANE_OP_NEIGH_TABLE_UPDATE:
		break;
	case DPLANE_OP_IPTABLE_ADD:
	case DPLANE_OP_IPTABLE_DELETE:
		if (ctx->u.iptable.interface_name_list)
			list_delete(&ctx->u.iptable.interface_name_list);
		break;
	case DPLANE_OP_GRE_SET:
	case DPLANE_OP_INTF_NETCONFIG:
	case DPLANE_OP_STARTUP_STAGE:
	case DPLANE_OP_SRV6_ENCAP_SRCADDR_SET:
		break;
	case DPLANE_OP_VLAN_INSTALL:
		if (ctx->u.vlan_info.vlan_array)
			XFREE(MTYPE_VLAN_CHANGE_ARR,
			      ctx->u.vlan_info.vlan_array);
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

/* Init a list of contexts */
void dplane_ctx_q_init(struct dplane_ctx_list_head *q)
{
	dplane_ctx_list_init(q);
}

/* Enqueue a context block */
void dplane_ctx_enqueue_tail(struct dplane_ctx_list_head *list,
			     const struct zebra_dplane_ctx *ctx)
{
	dplane_ctx_list_add_tail(list, (struct zebra_dplane_ctx *)ctx);
}

/* Append a list of context blocks to another list */
void dplane_ctx_list_append(struct dplane_ctx_list_head *to_list,
			    struct dplane_ctx_list_head *from_list)
{
	struct zebra_dplane_ctx *ctx;

	while ((ctx = dplane_ctx_list_pop(from_list)) != NULL)
		dplane_ctx_list_add_tail(to_list, ctx);
}

struct zebra_dplane_ctx *dplane_ctx_get_head(struct dplane_ctx_list_head *q)
{
	struct zebra_dplane_ctx *ctx = dplane_ctx_list_first(q);

	return ctx;
}

/* Dequeue a context block from the head of a list */
struct zebra_dplane_ctx *dplane_ctx_dequeue(struct dplane_ctx_list_head *q)
{
	struct zebra_dplane_ctx *ctx = dplane_ctx_list_pop(q);

	return ctx;
}

uint32_t dplane_ctx_queue_count(struct dplane_ctx_list_head *q)
{
	return dplane_ctx_list_count(q);
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
	switch (op) {
	case DPLANE_OP_NONE:
		return "NONE";

	/* Route update */
	case DPLANE_OP_ROUTE_INSTALL:
		return "ROUTE_INSTALL";
	case DPLANE_OP_ROUTE_UPDATE:
		return "ROUTE_UPDATE";
	case DPLANE_OP_ROUTE_DELETE:
		return "ROUTE_DELETE";
	case DPLANE_OP_ROUTE_NOTIFY:
		return "ROUTE_NOTIFY";

	/* Nexthop update */
	case DPLANE_OP_NH_INSTALL:
		return "NH_INSTALL";
	case DPLANE_OP_NH_UPDATE:
		return "NH_UPDATE";
	case DPLANE_OP_NH_DELETE:
		return "NH_DELETE";
	case DPLANE_OP_PIC_NH_INSTALL:
		return "PIC_NH_INSTALL";
	case DPLANE_OP_PIC_NH_UPDATE:
		return "PIC_NH_UPDATE";
	case DPLANE_OP_PIC_NH_DELETE:
		return "PIC_NH_DELETE";

	case DPLANE_OP_LSP_INSTALL:
		return "LSP_INSTALL";
	case DPLANE_OP_LSP_UPDATE:
		return "LSP_UPDATE";
	case DPLANE_OP_LSP_DELETE:
		return "LSP_DELETE";
	case DPLANE_OP_LSP_NOTIFY:
		return "LSP_NOTIFY";

	case DPLANE_OP_PW_INSTALL:
		return "PW_INSTALL";
	case DPLANE_OP_PW_UNINSTALL:
		return "PW_UNINSTALL";

	case DPLANE_OP_SYS_ROUTE_ADD:
		return "SYS_ROUTE_ADD";
	case DPLANE_OP_SYS_ROUTE_DELETE:
		return "SYS_ROUTE_DEL";

	case DPLANE_OP_BR_PORT_UPDATE:
		return "BR_PORT_UPDATE";

	case DPLANE_OP_ADDR_INSTALL:
		return "ADDR_INSTALL";
	case DPLANE_OP_ADDR_UNINSTALL:
		return "ADDR_UNINSTALL";

	case DPLANE_OP_MAC_INSTALL:
		return "MAC_INSTALL";
	case DPLANE_OP_MAC_DELETE:
		return "MAC_DELETE";

	case DPLANE_OP_NEIGH_INSTALL:
		return "NEIGH_INSTALL";
	case DPLANE_OP_NEIGH_UPDATE:
		return "NEIGH_UPDATE";
	case DPLANE_OP_NEIGH_DELETE:
		return "NEIGH_DELETE";
	case DPLANE_OP_VTEP_ADD:
		return "VTEP_ADD";
	case DPLANE_OP_VTEP_DELETE:
		return "VTEP_DELETE";

	case DPLANE_OP_RULE_ADD:
		return "RULE_ADD";
	case DPLANE_OP_RULE_DELETE:
		return "RULE_DELETE";
	case DPLANE_OP_RULE_UPDATE:
		return "RULE_UPDATE";

	case DPLANE_OP_NEIGH_DISCOVER:
		return "NEIGH_DISCOVER";

	case DPLANE_OP_IPTABLE_ADD:
		return "IPTABLE_ADD";
	case DPLANE_OP_IPTABLE_DELETE:
		return "IPTABLE_DELETE";
	case DPLANE_OP_IPSET_ADD:
		return "IPSET_ADD";
	case DPLANE_OP_IPSET_DELETE:
		return "IPSET_DELETE";
	case DPLANE_OP_IPSET_ENTRY_ADD:
		return "IPSET_ENTRY_ADD";
	case DPLANE_OP_IPSET_ENTRY_DELETE:
		return "IPSET_ENTRY_DELETE";
	case DPLANE_OP_NEIGH_IP_INSTALL:
		return "NEIGH_IP_INSTALL";
	case DPLANE_OP_NEIGH_IP_DELETE:
		return "NEIGH_IP_DELETE";
	case DPLANE_OP_NEIGH_TABLE_UPDATE:
		return "NEIGH_TABLE_UPDATE";

	case DPLANE_OP_GRE_SET:
		return "GRE_SET";

	case DPLANE_OP_INTF_ADDR_ADD:
		return "INTF_ADDR_ADD";

	case DPLANE_OP_INTF_ADDR_DEL:
		return "INTF_ADDR_DEL";

	case DPLANE_OP_INTF_NETCONFIG:
		return "INTF_NETCONFIG";

	case DPLANE_OP_INTF_INSTALL:
		return "INTF_INSTALL";
	case DPLANE_OP_INTF_UPDATE:
		return "INTF_UPDATE";
	case DPLANE_OP_INTF_DELETE:
		return "INTF_DELETE";

	case DPLANE_OP_TC_QDISC_INSTALL:
		return "TC_QDISC_INSTALL";
	case DPLANE_OP_TC_QDISC_UNINSTALL:
		return "TC_QDISC_UNINSTALL";
	case DPLANE_OP_TC_CLASS_ADD:
		return "TC_CLASS_ADD";
	case DPLANE_OP_TC_CLASS_DELETE:
		return "TC_CLASS_DELETE";
	case DPLANE_OP_TC_CLASS_UPDATE:
		return "TC_CLASS_UPDATE";
	case DPLANE_OP_TC_FILTER_ADD:
		return "TC_FILTER_ADD";
	case DPLANE_OP_TC_FILTER_DELETE:
		return "TC_FILTER_DELETE";
	case DPLANE_OP_TC_FILTER_UPDATE:
		return "TC__FILTER_UPDATE";
	case DPLANE_OP_STARTUP_STAGE:
		return "STARTUP_STAGE";

	case DPLANE_OP_SRV6_ENCAP_SRCADDR_SET:
		return "SRV6_ENCAP_SRCADDR_SET";

	case DPLANE_OP_VLAN_INSTALL:
		return "NEW_VLAN";
	}

	return "UNKNOWN";
}

const char *dplane_res2str(enum zebra_dplane_result res)
{
	switch (res) {
	case ZEBRA_DPLANE_REQUEST_FAILURE:
		return "FAILURE";
	case ZEBRA_DPLANE_REQUEST_QUEUED:
		return "QUEUED";
	case ZEBRA_DPLANE_REQUEST_SUCCESS:
		return "SUCCESS";
	}

	return "<Unknown>";
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

/* In some paths we have only a namespace id */
void dplane_ctx_set_ns_id(struct zebra_dplane_ctx *ctx, ns_id_t nsid)
{
	DPLANE_CTX_VALID(ctx);

	ctx->zd_ns_info.ns_id = nsid;
}

ns_id_t dplane_ctx_get_ns_id(const struct zebra_dplane_ctx *ctx)
{
	DPLANE_CTX_VALID(ctx);

	return ctx->zd_ns_info.ns_id;
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

void dplane_ctx_set_ifp_bridge_vlan_info_array(
	struct zebra_dplane_ctx *ctx,
	struct zebra_dplane_bridge_vlan_info_array *bvarray)
{
	DPLANE_CTX_VALID(ctx);

	ctx->u.intf.bvarray = bvarray;
}

const struct zebra_dplane_bridge_vlan_info_array *
dplane_ctx_get_ifp_bridge_vlan_info_array(const struct zebra_dplane_ctx *ctx)
{
	DPLANE_CTX_VALID(ctx);

	return ctx->u.intf.bvarray;
}

void dplane_ctx_set_ifp_vxlan_vni_array(struct zebra_dplane_ctx *ctx,
					struct zebra_vxlan_vni_array *vniarray)
{
	DPLANE_CTX_VALID(ctx);

	ctx->u.intf.vniarray = vniarray;
}

const struct zebra_vxlan_vni_array *
dplane_ctx_get_ifp_vxlan_vni_array(const struct zebra_dplane_ctx *ctx)
{
	DPLANE_CTX_VALID(ctx);

	return ctx->u.intf.vniarray;
}

void dplane_ctx_set_ifp_no_afspec(struct zebra_dplane_ctx *ctx)
{
	DPLANE_CTX_VALID(ctx);

	ctx->u.intf.no_afspec_avail = true;
}

bool dplane_ctx_get_ifp_no_afspec(const struct zebra_dplane_ctx *ctx)
{
	DPLANE_CTX_VALID(ctx);

	return ctx->u.intf.no_afspec_avail;
}

void dplane_ctx_set_ifp_no_bridge_vlan_info(struct zebra_dplane_ctx *ctx)
{
	DPLANE_CTX_VALID(ctx);

	ctx->u.intf.no_bvinfo_avail = true;
}

bool dplane_ctx_get_ifp_no_bridge_vlan_info(struct zebra_dplane_ctx *ctx)
{
	DPLANE_CTX_VALID(ctx);

	return ctx->u.intf.no_bvinfo_avail;
}

void dplane_ctx_set_ifp_bridge_vlan_info(
	struct zebra_dplane_ctx *ctx,
	struct zebra_dplane_bridge_vlan_info *bvinfo)
{
	DPLANE_CTX_VALID(ctx);

	ctx->u.intf.bvinfo = *bvinfo;
}

const struct zebra_dplane_bridge_vlan_info *
dplane_ctx_get_ifp_bridge_vlan_info(const struct zebra_dplane_ctx *ctx)
{
	DPLANE_CTX_VALID(ctx);

	return &ctx->u.intf.bvinfo;
}

void dplane_ctx_set_ifp_family(struct zebra_dplane_ctx *ctx, uint8_t family)
{
	DPLANE_CTX_VALID(ctx);

	ctx->u.intf.family = family;
}

uint8_t dplane_ctx_get_ifp_family(const struct zebra_dplane_ctx *ctx)
{
	DPLANE_CTX_VALID(ctx);

	return ctx->u.intf.family;
}

void dplane_ctx_set_ifp_zltype(struct zebra_dplane_ctx *ctx,
			       enum zebra_link_type zltype)
{
	DPLANE_CTX_VALID(ctx);

	ctx->u.intf.zltype = zltype;
}

enum zebra_link_type
dplane_ctx_get_ifp_zltype(const struct zebra_dplane_ctx *ctx)
{
	DPLANE_CTX_VALID(ctx);

	return ctx->u.intf.zltype;
}

void dplane_ctx_set_ifp_link_ifindex(struct zebra_dplane_ctx *ctx,
				     ifindex_t link_ifindex)
{
	DPLANE_CTX_VALID(ctx);

	ctx->u.intf.link_ifindex = link_ifindex;
}

ifindex_t dplane_ctx_get_ifp_link_ifindex(const struct zebra_dplane_ctx *ctx)
{
	DPLANE_CTX_VALID(ctx);

	return ctx->u.intf.link_ifindex;
}

void dplane_ctx_set_ifp_desc(struct zebra_dplane_ctx *ctx, const char *desc)
{
	DPLANE_CTX_VALID(ctx);

	strlcpy(ctx->u.intf.desc, desc, sizeof(ctx->u.intf.desc));
}

char *dplane_ctx_get_ifp_desc(struct zebra_dplane_ctx *ctx)
{
	DPLANE_CTX_VALID(ctx);

	return ctx->u.intf.desc;
}

void dplane_ctx_set_ifp_flags(struct zebra_dplane_ctx *ctx, uint64_t flags)
{
	DPLANE_CTX_VALID(ctx);

	ctx->u.intf.flags = flags;
}

uint64_t dplane_ctx_get_ifp_flags(const struct zebra_dplane_ctx *ctx)
{
	DPLANE_CTX_VALID(ctx);

	return ctx->u.intf.flags;
}

void dplane_ctx_set_ifp_bypass(struct zebra_dplane_ctx *ctx, uint8_t bypass)
{
	DPLANE_CTX_VALID(ctx);

	ctx->u.intf.bypass = bypass;
}

uint8_t dplane_ctx_get_ifp_bypass(const struct zebra_dplane_ctx *ctx)
{
	DPLANE_CTX_VALID(ctx);

	return ctx->u.intf.bypass;
}

void dplane_ctx_set_ifp_bridge_ifindex(struct zebra_dplane_ctx *ctx,
				       ifindex_t bridge_ifindex)
{
	DPLANE_CTX_VALID(ctx);

	ctx->u.intf.bridge_ifindex = bridge_ifindex;
}

ifindex_t dplane_ctx_get_ifp_bridge_ifindex(const struct zebra_dplane_ctx *ctx)
{
	DPLANE_CTX_VALID(ctx);

	return ctx->u.intf.bridge_ifindex;
}

void dplane_ctx_set_ifp_zif_slave_type(struct zebra_dplane_ctx *ctx,
				       enum zebra_slave_iftype zslave_type)
{
	DPLANE_CTX_VALID(ctx);

	ctx->u.intf.zslave_type = zslave_type;
}

enum zebra_slave_iftype
dplane_ctx_get_ifp_zif_slave_type(const struct zebra_dplane_ctx *ctx)
{
	DPLANE_CTX_VALID(ctx);

	return ctx->u.intf.zslave_type;
}

void dplane_ctx_set_ifp_master_ifindex(struct zebra_dplane_ctx *ctx,
				       ifindex_t master_ifindex)
{
	DPLANE_CTX_VALID(ctx);

	ctx->u.intf.master_ifindex = master_ifindex;
}

ifindex_t dplane_ctx_get_ifp_master_ifindex(const struct zebra_dplane_ctx *ctx)
{
	DPLANE_CTX_VALID(ctx);

	return ctx->u.intf.master_ifindex;
}

void dplane_ctx_set_ifp_mtu(struct zebra_dplane_ctx *ctx, uint32_t mtu)
{
	DPLANE_CTX_VALID(ctx);

	ctx->u.intf.mtu = mtu;
}

uint32_t dplane_ctx_get_ifp_mtu(const struct zebra_dplane_ctx *ctx)
{
	DPLANE_CTX_VALID(ctx);

	return ctx->u.intf.mtu;
}

void dplane_ctx_set_ifp_vrf_id(struct zebra_dplane_ctx *ctx, vrf_id_t vrf_id)
{
	DPLANE_CTX_VALID(ctx);

	ctx->u.intf.vrf_id = vrf_id;
}

vrf_id_t dplane_ctx_get_ifp_vrf_id(const struct zebra_dplane_ctx *ctx)
{
	DPLANE_CTX_VALID(ctx);

	return ctx->u.intf.vrf_id;
}

void dplane_ctx_set_ifp_link_nsid(struct zebra_dplane_ctx *ctx,
				  ns_id_t link_nsid)
{
	DPLANE_CTX_VALID(ctx);

	ctx->u.intf.link_nsid = link_nsid;
}

ns_id_t dplane_ctx_get_ifp_link_nsid(const struct zebra_dplane_ctx *ctx)
{
	DPLANE_CTX_VALID(ctx);

	return ctx->u.intf.link_nsid;
}

void dplane_ctx_set_ifp_startup(struct zebra_dplane_ctx *ctx, bool startup)
{
	DPLANE_CTX_VALID(ctx);

	ctx->u.intf.startup = startup;
}

bool dplane_ctx_get_ifp_startup(const struct zebra_dplane_ctx *ctx)
{
	DPLANE_CTX_VALID(ctx);

	return ctx->u.intf.startup;
}

void dplane_ctx_set_ifp_protodown_set(struct zebra_dplane_ctx *ctx, bool set)
{
	DPLANE_CTX_VALID(ctx);

	ctx->u.intf.protodown_set = set;
}

bool dplane_ctx_get_ifp_protodown_set(const struct zebra_dplane_ctx *ctx)
{
	DPLANE_CTX_VALID(ctx);

	return ctx->u.intf.protodown_set;
}

void dplane_ctx_set_ifp_protodown(struct zebra_dplane_ctx *ctx, bool protodown)
{
	DPLANE_CTX_VALID(ctx);

	ctx->u.intf.protodown = protodown;
}

bool dplane_ctx_get_ifp_protodown(const struct zebra_dplane_ctx *ctx)
{
	DPLANE_CTX_VALID(ctx);

	return ctx->u.intf.protodown;
}

ifindex_t dplane_ctx_get_ifp_bond_ifindex(const struct zebra_dplane_ctx *ctx)
{
	DPLANE_CTX_VALID(ctx);

	return ctx->u.intf.bond_ifindex;
}

void dplane_ctx_set_ifp_rc_bitfield(struct zebra_dplane_ctx *ctx,
				    uint32_t rc_bitfield)
{
	DPLANE_CTX_VALID(ctx);

	ctx->u.intf.rc_bitfield = rc_bitfield;
}

uint32_t dplane_ctx_get_ifp_rc_bitfield(const struct zebra_dplane_ctx *ctx)
{
	DPLANE_CTX_VALID(ctx);

	return ctx->u.intf.rc_bitfield;
}

void dplane_ctx_set_ifp_gre_info(struct zebra_dplane_ctx *ctx,
				 struct zebra_l2info_gre *grinfo)
{
	DPLANE_CTX_VALID(ctx);

	ctx->u.intf.grinfo = *grinfo;
}

const struct zebra_l2info_gre *
dplane_ctx_get_ifp_gre_info(const struct zebra_dplane_ctx *ctx)
{
	DPLANE_CTX_VALID(ctx);

	return &ctx->u.intf.grinfo;
}

void dplane_ctx_set_ifp_vxlan_info(struct zebra_dplane_ctx *ctx,
				   struct zebra_l2info_vxlan *vxinfo)
{
	DPLANE_CTX_VALID(ctx);

	ctx->u.intf.vxinfo = *vxinfo;
}

const struct zebra_l2info_vxlan *
dplane_ctx_get_ifp_vxlan_info(const struct zebra_dplane_ctx *ctx)
{
	DPLANE_CTX_VALID(ctx);

	return &ctx->u.intf.vxinfo;
}

void dplane_ctx_set_ifp_vlan_info(struct zebra_dplane_ctx *ctx,
				  struct zebra_l2info_vlan *vinfo)
{
	DPLANE_CTX_VALID(ctx);

	ctx->u.intf.vinfo = *vinfo;
}

const struct zebra_l2info_vlan *
dplane_ctx_get_ifp_vlan_info(const struct zebra_dplane_ctx *ctx)
{
	DPLANE_CTX_VALID(ctx);

	return &ctx->u.intf.vinfo;
}

void dplane_ctx_set_ifp_bridge_info(struct zebra_dplane_ctx *ctx,
				    struct zebra_l2info_bridge *binfo)
{
	DPLANE_CTX_VALID(ctx);

	ctx->u.intf.binfo = *binfo;
}

const struct zebra_l2info_bridge *
dplane_ctx_get_ifp_bridge_info(const struct zebra_dplane_ctx *ctx)
{
	DPLANE_CTX_VALID(ctx);

	return &ctx->u.intf.binfo;
}

void dplane_ctx_set_ifp_table_id(struct zebra_dplane_ctx *ctx,
				 uint32_t table_id)
{
	DPLANE_CTX_VALID(ctx);

	ctx->u.intf.table_id = table_id;
}

uint32_t dplane_ctx_get_ifp_table_id(const struct zebra_dplane_ctx *ctx)
{
	DPLANE_CTX_VALID(ctx);

	return ctx->u.intf.table_id;
}

void dplane_ctx_set_ifp_hw_addr(struct zebra_dplane_ctx *ctx,
				int32_t hw_addr_len, uint8_t *hw_addr)
{
	DPLANE_CTX_VALID(ctx);

	ctx->u.intf.hw_addr_len = hw_addr_len;
	memcpy(ctx->u.intf.hw_addr, hw_addr, hw_addr_len);
}

int32_t dplane_ctx_get_ifp_hw_addr_len(const struct zebra_dplane_ctx *ctx)
{
	DPLANE_CTX_VALID(ctx);

	return ctx->u.intf.hw_addr_len;
}

const uint8_t *dplane_ctx_get_ifp_hw_addr(const struct zebra_dplane_ctx *ctx)
{
	DPLANE_CTX_VALID(ctx);

	return ctx->u.intf.hw_addr;
}

void dplane_ctx_set_ifp_bond_ifindex(struct zebra_dplane_ctx *ctx,
				     ifindex_t bond_ifindex)
{
	DPLANE_CTX_VALID(ctx);

	ctx->u.intf.bond_ifindex = bond_ifindex;
}

enum zebra_iftype
dplane_ctx_get_ifp_zif_type(const struct zebra_dplane_ctx *ctx)
{
	DPLANE_CTX_VALID(ctx);

	return ctx->u.intf.zif_type;
}

void dplane_ctx_set_ifp_zif_type(struct zebra_dplane_ctx *ctx,
				 enum zebra_iftype zif_type)
{
	DPLANE_CTX_VALID(ctx);

	ctx->u.intf.zif_type = zif_type;
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

void dplane_ctx_set_ifindex(struct zebra_dplane_ctx *ctx, ifindex_t ifindex)
{
	DPLANE_CTX_VALID(ctx);

	ctx->zd_ifindex = ifindex;
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

uint32_t dplane_ctx_get_flags(const struct zebra_dplane_ctx *ctx)
{
	DPLANE_CTX_VALID(ctx);

	return ctx->u.rinfo.zd_flags;
}

void dplane_ctx_set_flags(struct zebra_dplane_ctx *ctx, uint32_t flags)
{
	DPLANE_CTX_VALID(ctx);

	ctx->u.rinfo.zd_flags = flags;
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

int dplane_ctx_tc_qdisc_get_kind(const struct zebra_dplane_ctx *ctx)
{
	DPLANE_CTX_VALID(ctx);

	return ctx->u.tc_qdisc.kind;
}

const char *dplane_ctx_tc_qdisc_get_kind_str(const struct zebra_dplane_ctx *ctx)
{
	DPLANE_CTX_VALID(ctx);

	return ctx->u.tc_qdisc.kind_str;
}

uint32_t dplane_ctx_tc_class_get_handle(const struct zebra_dplane_ctx *ctx)
{
	DPLANE_CTX_VALID(ctx);

	return ctx->u.tc_class.handle;
}

int dplane_ctx_tc_class_get_kind(const struct zebra_dplane_ctx *ctx)
{
	DPLANE_CTX_VALID(ctx);

	return ctx->u.tc_class.kind;
}

const char *dplane_ctx_tc_class_get_kind_str(const struct zebra_dplane_ctx *ctx)
{
	DPLANE_CTX_VALID(ctx);

	return ctx->u.tc_class.kind_str;
}

uint64_t dplane_ctx_tc_class_get_rate(const struct zebra_dplane_ctx *ctx)
{
	DPLANE_CTX_VALID(ctx);

	return ctx->u.tc_class.rate;
}

uint64_t dplane_ctx_tc_class_get_ceil(const struct zebra_dplane_ctx *ctx)
{
	DPLANE_CTX_VALID(ctx);

	return ctx->u.tc_class.ceil;
}

int dplane_ctx_tc_filter_get_kind(const struct zebra_dplane_ctx *ctx)
{
	DPLANE_CTX_VALID(ctx);

	return ctx->u.tc_filter.kind;
}

const char *
dplane_ctx_tc_filter_get_kind_str(const struct zebra_dplane_ctx *ctx)
{
	DPLANE_CTX_VALID(ctx);

	return ctx->u.tc_filter.kind_str;
}

uint32_t dplane_ctx_tc_filter_get_priority(const struct zebra_dplane_ctx *ctx)
{
	DPLANE_CTX_VALID(ctx);

	return ctx->u.tc_filter.priority;
}

uint32_t dplane_ctx_tc_filter_get_handle(const struct zebra_dplane_ctx *ctx)
{
	DPLANE_CTX_VALID(ctx);

	return ctx->u.tc_filter.handle;
}

uint16_t dplane_ctx_tc_filter_get_eth_proto(const struct zebra_dplane_ctx *ctx)
{
	DPLANE_CTX_VALID(ctx);

	return ctx->u.tc_filter.eth_proto;
}

uint32_t dplane_ctx_tc_filter_get_filter_bm(const struct zebra_dplane_ctx *ctx)
{
	DPLANE_CTX_VALID(ctx);

	return ctx->u.tc_filter.filter_bm;
}

const struct prefix *
dplane_ctx_tc_filter_get_src_ip(const struct zebra_dplane_ctx *ctx)
{
	DPLANE_CTX_VALID(ctx);

	return &ctx->u.tc_filter.src_ip;
}

uint16_t
dplane_ctx_tc_filter_get_src_port_min(const struct zebra_dplane_ctx *ctx)
{
	DPLANE_CTX_VALID(ctx);

	return ctx->u.tc_filter.src_port_min;
}


uint16_t
dplane_ctx_tc_filter_get_src_port_max(const struct zebra_dplane_ctx *ctx)
{
	DPLANE_CTX_VALID(ctx);

	return ctx->u.tc_filter.src_port_max;
}

const struct prefix *
dplane_ctx_tc_filter_get_dst_ip(const struct zebra_dplane_ctx *ctx)
{
	DPLANE_CTX_VALID(ctx);

	return &ctx->u.tc_filter.dst_ip;
}

uint16_t
dplane_ctx_tc_filter_get_dst_port_min(const struct zebra_dplane_ctx *ctx)
{
	DPLANE_CTX_VALID(ctx);

	return ctx->u.tc_filter.dst_port_min;
}


uint16_t
dplane_ctx_tc_filter_get_dst_port_max(const struct zebra_dplane_ctx *ctx)
{
	DPLANE_CTX_VALID(ctx);

	return ctx->u.tc_filter.dst_port_max;
}

uint8_t dplane_ctx_tc_filter_get_ip_proto(const struct zebra_dplane_ctx *ctx)
{
	DPLANE_CTX_VALID(ctx);

	return ctx->u.tc_filter.ip_proto;
}

uint8_t dplane_ctx_tc_filter_get_dsfield(const struct zebra_dplane_ctx *ctx)
{
	DPLANE_CTX_VALID(ctx);

	return ctx->u.tc_filter.dsfield;
}

uint8_t
dplane_ctx_tc_filter_get_dsfield_mask(const struct zebra_dplane_ctx *ctx)
{
	DPLANE_CTX_VALID(ctx);

	return ctx->u.tc_filter.dsfield_mask;
}

uint32_t dplane_ctx_tc_filter_get_classid(const struct zebra_dplane_ctx *ctx)
{
	DPLANE_CTX_VALID(ctx);

	return ctx->u.tc_filter.classid;
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

int dplane_ctx_get_ns_sock(const struct zebra_dplane_ctx *ctx)
{
	DPLANE_CTX_VALID(ctx);

#ifdef HAVE_NETLINK
	return ctx->zd_ns_info.sock;
#else
	return -1;
#endif
}

/* Accessors for nexthop information */
uint32_t dplane_ctx_get_nhe_id(const struct zebra_dplane_ctx *ctx)
{
	DPLANE_CTX_VALID(ctx);
	return ctx->u.rinfo.nhe.id;
}

uint32_t dplane_ctx_get_pic_nhe_id(const struct zebra_dplane_ctx *ctx)
{
	DPLANE_CTX_VALID(ctx);
	return ctx->u.rinfo.nhe.pic_nhe_id;
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

uint16_t dplane_ctx_get_nhe_nh_grp_count(const struct zebra_dplane_ctx *ctx)
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

struct zebra_nhlfe *dplane_ctx_add_nhlfe(struct zebra_dplane_ctx *ctx,
					 enum lsp_types_t lsp_type,
					 enum nexthop_types_t nh_type,
					 const union g_addr *gate,
					 ifindex_t ifindex, uint8_t num_labels,
					 mpls_label_t *out_labels)
{
	struct zebra_nhlfe *nhlfe;

	DPLANE_CTX_VALID(ctx);

	nhlfe = zebra_mpls_lsp_add_nhlfe(&(ctx->u.lsp),
					 lsp_type, nh_type, gate,
					 ifindex, num_labels, out_labels);

	return nhlfe;
}

struct zebra_nhlfe *dplane_ctx_add_backup_nhlfe(
	struct zebra_dplane_ctx *ctx, enum lsp_types_t lsp_type,
	enum nexthop_types_t nh_type, const union g_addr *gate,
	ifindex_t ifindex, uint8_t num_labels, mpls_label_t *out_labels)
{
	struct zebra_nhlfe *nhlfe;

	DPLANE_CTX_VALID(ctx);

	nhlfe = zebra_mpls_lsp_add_backup_nhlfe(&(ctx->u.lsp),
						lsp_type, nh_type, gate,
						ifindex, num_labels,
						out_labels);

	return nhlfe;
}

const struct zebra_nhlfe *
dplane_ctx_get_best_nhlfe(const struct zebra_dplane_ctx *ctx)
{
	DPLANE_CTX_VALID(ctx);

	return ctx->u.lsp.best_nhlfe;
}

const struct zebra_nhlfe *
dplane_ctx_set_best_nhlfe(struct zebra_dplane_ctx *ctx,
			  struct zebra_nhlfe *nhlfe)
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

	return &(ctx->u.pw.fib_nhg);
}

const struct nexthop_group *
dplane_ctx_get_pw_primary_nhg(const struct zebra_dplane_ctx *ctx)
{
	DPLANE_CTX_VALID(ctx);

	return &(ctx->u.pw.primary_nhg);
}

const struct nexthop_group *
dplane_ctx_get_pw_backup_nhg(const struct zebra_dplane_ctx *ctx)
{
	DPLANE_CTX_VALID(ctx);

	return &(ctx->u.pw.backup_nhg);
}

/* Accessors for interface information */
uint32_t dplane_ctx_get_intf_metric(const struct zebra_dplane_ctx *ctx)
{
	DPLANE_CTX_VALID(ctx);

	return ctx->u.intf.metric;
}

void dplane_ctx_set_intf_metric(struct zebra_dplane_ctx *ctx, uint32_t metric)
{
	DPLANE_CTX_VALID(ctx);

	ctx->u.intf.metric = metric;
}

uint32_t dplane_ctx_get_intf_pd_reason_val(const struct zebra_dplane_ctx *ctx)
{
	DPLANE_CTX_VALID(ctx);

	return ctx->u.intf.pd_reason_val;
}

void dplane_ctx_set_intf_pd_reason_val(struct zebra_dplane_ctx *ctx, bool val)
{
	DPLANE_CTX_VALID(ctx);

	ctx->u.intf.pd_reason_val = val;
}

bool dplane_ctx_intf_is_protodown(const struct zebra_dplane_ctx *ctx)
{
	DPLANE_CTX_VALID(ctx);

	return ctx->u.intf.protodown;
}

/* Is interface addr p2p? */
bool dplane_ctx_intf_is_connected(const struct zebra_dplane_ctx *ctx)
{
	DPLANE_CTX_VALID(ctx);

	return (ctx->u.intf.flags & DPLANE_INTF_CONNECTED);
}

bool dplane_ctx_intf_is_noprefixroute(const struct zebra_dplane_ctx *ctx)
{
	DPLANE_CTX_VALID(ctx);

	return (ctx->u.intf.flags & DPLANE_INTF_NOPREFIXROUTE);
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

void dplane_ctx_intf_set_connected(struct zebra_dplane_ctx *ctx)
{
	DPLANE_CTX_VALID(ctx);

	ctx->u.intf.flags |= DPLANE_INTF_CONNECTED;
}

void dplane_ctx_intf_set_secondary(struct zebra_dplane_ctx *ctx)
{
	DPLANE_CTX_VALID(ctx);

	ctx->u.intf.flags |= DPLANE_INTF_SECONDARY;
}

void dplane_ctx_intf_set_noprefixroute(struct zebra_dplane_ctx *ctx)
{
	DPLANE_CTX_VALID(ctx);

	ctx->u.intf.flags |= DPLANE_INTF_NOPREFIXROUTE;
}

void dplane_ctx_intf_set_broadcast(struct zebra_dplane_ctx *ctx)
{
	DPLANE_CTX_VALID(ctx);

	ctx->u.intf.flags |= DPLANE_INTF_BROADCAST;
}

const struct prefix *dplane_ctx_get_intf_addr(
	const struct zebra_dplane_ctx *ctx)
{
	DPLANE_CTX_VALID(ctx);

	return &(ctx->u.intf.prefix);
}


/* Accessors for SRv6 encapsulation source address information */
const struct in6_addr *
dplane_ctx_get_srv6_encap_srcaddr(const struct zebra_dplane_ctx *ctx)
{
	DPLANE_CTX_VALID(ctx);

	return &(ctx->u.srv6_encap.srcaddr);
}

void dplane_ctx_set_intf_addr(struct zebra_dplane_ctx *ctx,
			      const struct prefix *p)
{
	DPLANE_CTX_VALID(ctx);

	prefix_copy(&(ctx->u.intf.prefix), p);
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

	return &(ctx->u.intf.dest_prefix);
}

void dplane_ctx_set_intf_dest(struct zebra_dplane_ctx *ctx,
			      const struct prefix *p)
{
	DPLANE_CTX_VALID(ctx);

	prefix_copy(&(ctx->u.intf.dest_prefix), p);
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

void dplane_ctx_set_intf_label(struct zebra_dplane_ctx *ctx, const char *label)
{
	size_t len;

	DPLANE_CTX_VALID(ctx);

	if (ctx->u.intf.label && ctx->u.intf.label != ctx->u.intf.label_buf)
		XFREE(MTYPE_DP_CTX, ctx->u.intf.label);

	ctx->u.intf.label = NULL;

	if (label) {
		ctx->u.intf.flags |= DPLANE_INTF_HAS_LABEL;

		/* Use embedded buffer if it's adequate; else allocate. */
		len = strlen(label);

		if (len < sizeof(ctx->u.intf.label_buf)) {
			strlcpy(ctx->u.intf.label_buf, label,
				sizeof(ctx->u.intf.label_buf));
			ctx->u.intf.label = ctx->u.intf.label_buf;
		} else {
			ctx->u.intf.label = XSTRDUP(MTYPE_DP_CTX, label);
		}
	} else {
		ctx->u.intf.flags &= ~DPLANE_INTF_HAS_LABEL;
	}
}

void dplane_ctx_set_intf_txqlen(struct zebra_dplane_ctx *ctx, uint32_t txqlen)
{
	DPLANE_CTX_VALID(ctx);

	ctx->u.intf.txqlen = txqlen;
}

uint32_t dplane_ctx_get_intf_txqlen(const struct zebra_dplane_ctx *ctx)
{
	DPLANE_CTX_VALID(ctx);

	return ctx->u.intf.txqlen;
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

vni_t dplane_ctx_mac_get_vni(const struct zebra_dplane_ctx *ctx)
{
	DPLANE_CTX_VALID(ctx);
	return ctx->u.macinfo.vni;
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

vni_t dplane_ctx_neigh_get_vni(const struct zebra_dplane_ctx *ctx)
{
	DPLANE_CTX_VALID(ctx);
	return ctx->u.neigh.vni;
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

unsigned int
dplane_ctx_gre_get_mtu(const struct zebra_dplane_ctx *ctx)
{
	DPLANE_CTX_VALID(ctx);

	return ctx->u.gre.mtu;
}

const struct zebra_l2info_gre *
dplane_ctx_gre_get_info(const struct zebra_dplane_ctx *ctx)
{
	DPLANE_CTX_VALID(ctx);

	return &ctx->u.gre.info;
}

/***********************************************************************
 *		PBR RULE ACCESSORS - start
 **********************************************************************/

/*
 * This accessor fills one or two lib/pbr structs from the PBR context.
 * New dataplane modules should use this interface where possible instead
 * of adding more accessors that return fields from 'struct pbr_rule'.
 */
void dplane_ctx_rule_get(const struct zebra_dplane_ctx *ctx,
	struct pbr_rule *pNew, struct pbr_rule *pOld)
{
	DPLANE_CTX_VALID(ctx);
	if (pNew)
		*pNew = ctx->u.rule.new.prule;
	if (pOld)
		*pOld = ctx->u.rule.old.prule;
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

	return ctx->u.rule.new.prule.ifname;
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

	return ctx->u.rule.new.prule.priority;
}

uint32_t dplane_ctx_rule_get_old_priority(const struct zebra_dplane_ctx *ctx)
{
	DPLANE_CTX_VALID(ctx);

	return ctx->u.rule.old.prule.priority;
}

uint32_t dplane_ctx_rule_get_table(const struct zebra_dplane_ctx *ctx)
{
	DPLANE_CTX_VALID(ctx);

	return ctx->u.rule.new.prule.action.table;
}

uint32_t dplane_ctx_rule_get_old_table(const struct zebra_dplane_ctx *ctx)
{
	DPLANE_CTX_VALID(ctx);

	return ctx->u.rule.old.prule.action.table;
}

uint32_t dplane_ctx_rule_get_filter_bm(const struct zebra_dplane_ctx *ctx)
{
	DPLANE_CTX_VALID(ctx);

	return ctx->u.rule.new.prule.filter.filter_bm;
}

uint32_t dplane_ctx_rule_get_old_filter_bm(const struct zebra_dplane_ctx *ctx)
{
	DPLANE_CTX_VALID(ctx);

	return ctx->u.rule.old.prule.filter.filter_bm;
}

uint32_t dplane_ctx_rule_get_fwmark(const struct zebra_dplane_ctx *ctx)
{
	DPLANE_CTX_VALID(ctx);

	return ctx->u.rule.new.prule.filter.fwmark;
}

uint32_t dplane_ctx_rule_get_old_fwmark(const struct zebra_dplane_ctx *ctx)
{
	DPLANE_CTX_VALID(ctx);

	return ctx->u.rule.old.prule.filter.fwmark;
}

uint8_t dplane_ctx_rule_get_ipproto(const struct zebra_dplane_ctx *ctx)
{
	DPLANE_CTX_VALID(ctx);

	return ctx->u.rule.new.prule.filter.ip_proto;
}

uint8_t dplane_ctx_rule_get_old_ipproto(const struct zebra_dplane_ctx *ctx)
{
	DPLANE_CTX_VALID(ctx);

	return ctx->u.rule.old.prule.filter.ip_proto;
}

uint16_t dplane_ctx_rule_get_src_port(const struct zebra_dplane_ctx *ctx)
{
	DPLANE_CTX_VALID(ctx);

	return ctx->u.rule.new.prule.filter.src_port;
}

uint16_t dplane_ctx_rule_get_old_src_port(const struct zebra_dplane_ctx *ctx)
{
	DPLANE_CTX_VALID(ctx);

	return ctx->u.rule.old.prule.filter.src_port;
}

uint16_t dplane_ctx_rule_get_dst_port(const struct zebra_dplane_ctx *ctx)
{
	DPLANE_CTX_VALID(ctx);

	return ctx->u.rule.new.prule.filter.dst_port;
}

uint16_t dplane_ctx_rule_get_old_dst_port(const struct zebra_dplane_ctx *ctx)
{
	DPLANE_CTX_VALID(ctx);

	return ctx->u.rule.old.prule.filter.dst_port;
}

uint8_t dplane_ctx_rule_get_dsfield(const struct zebra_dplane_ctx *ctx)
{
	DPLANE_CTX_VALID(ctx);

	return ctx->u.rule.new.prule.filter.dsfield;
}

uint8_t dplane_ctx_rule_get_old_dsfield(const struct zebra_dplane_ctx *ctx)
{
	DPLANE_CTX_VALID(ctx);

	return ctx->u.rule.old.prule.filter.dsfield;
}

const struct prefix *
dplane_ctx_rule_get_src_ip(const struct zebra_dplane_ctx *ctx)
{
	DPLANE_CTX_VALID(ctx);

	return &(ctx->u.rule.new.prule.filter.src_ip);
}

const struct prefix *
dplane_ctx_rule_get_old_src_ip(const struct zebra_dplane_ctx *ctx)
{
	DPLANE_CTX_VALID(ctx);

	return &(ctx->u.rule.old.prule.filter.src_ip);
}

const struct prefix *
dplane_ctx_rule_get_dst_ip(const struct zebra_dplane_ctx *ctx)
{
	DPLANE_CTX_VALID(ctx);

	return &(ctx->u.rule.new.prule.filter.dst_ip);
}

const struct prefix *
dplane_ctx_rule_get_old_dst_ip(const struct zebra_dplane_ctx *ctx)
{
	DPLANE_CTX_VALID(ctx);

	return &(ctx->u.rule.old.prule.filter.dst_ip);
}

const struct ethaddr *
dplane_ctx_rule_get_smac(const struct zebra_dplane_ctx *ctx)
{
	DPLANE_CTX_VALID(ctx);

	return &(ctx->u.rule.new.smac);
}

const struct ethaddr *
dplane_ctx_rule_get_dmac(const struct zebra_dplane_ctx *ctx)
{
	DPLANE_CTX_VALID(ctx);

	return &(ctx->u.rule.new.dmac);
}

int dplane_ctx_rule_get_out_ifindex(const struct zebra_dplane_ctx *ctx)
{
	DPLANE_CTX_VALID(ctx);

	return ctx->u.rule.new.out_ifindex;
}

intptr_t dplane_ctx_rule_get_old_dp_flow_ptr(const struct zebra_dplane_ctx *ctx)
{
	DPLANE_CTX_VALID(ctx);

	return ctx->u.rule.old.dp_flow_ptr;
}

intptr_t dplane_ctx_rule_get_dp_flow_ptr(const struct zebra_dplane_ctx *ctx)
{
	DPLANE_CTX_VALID(ctx);

	return ctx->u.rule.new.dp_flow_ptr;
}

void dplane_ctx_rule_set_dp_flow_ptr(struct zebra_dplane_ctx *ctx,
				     intptr_t dp_flow_ptr)
{
	DPLANE_CTX_VALID(ctx);

	ctx->u.rule.new.dp_flow_ptr = dp_flow_ptr;
}

vrf_id_t dplane_ctx_rule_get_vrfid(const struct zebra_dplane_ctx *ctx)
{
	DPLANE_CTX_VALID(ctx);

	return ctx->u.rule.new.prule.vrf_id;
}

/***********************************************************************
 *		PBR RULE ACCESSORS - end
 **********************************************************************/

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
void dplane_ctx_get_pbr_iptable(const struct zebra_dplane_ctx *ctx,
				struct zebra_pbr_iptable *table)
{
	DPLANE_CTX_VALID(ctx);

	memcpy(table, &ctx->u.iptable, sizeof(struct zebra_pbr_iptable));
}

void dplane_ctx_get_pbr_ipset(const struct zebra_dplane_ctx *ctx,
			      struct zebra_pbr_ipset *ipset)
{
	DPLANE_CTX_VALID(ctx);

	assert(ipset);

	if (ctx->zd_op == DPLANE_OP_IPSET_ENTRY_ADD ||
	    ctx->zd_op == DPLANE_OP_IPSET_ENTRY_DELETE) {
		memset(ipset, 0, sizeof(struct zebra_pbr_ipset));
		ipset->type = ctx->u.ipset_entry.info.type;
		ipset->family = ctx->u.ipset_entry.info.family;
		memcpy(&ipset->ipset_name, &ctx->u.ipset_entry.info.ipset_name,
		       ZEBRA_IPSET_NAME_SIZE);
	} else
		memcpy(ipset, &ctx->u.ipset, sizeof(struct zebra_pbr_ipset));
}

void dplane_ctx_get_pbr_ipset_entry(const struct zebra_dplane_ctx *ctx,
				    struct zebra_pbr_ipset_entry *entry)
{
	DPLANE_CTX_VALID(ctx);

	assert(entry);

	memcpy(entry, &ctx->u.ipset_entry.entry, sizeof(struct zebra_pbr_ipset_entry));
}

/* Optional extra info about interfaces in nexthops - a plugin must enable
 * this extra info.
 */
const struct dplane_intf_extra *
dplane_ctx_get_intf_extra(const struct zebra_dplane_ctx *ctx)
{
	return dplane_intf_extra_list_const_first(
		&ctx->u.rinfo.intf_extra_list);
}

const struct dplane_intf_extra *
dplane_ctx_intf_extra_next(const struct zebra_dplane_ctx *ctx,
			   const struct dplane_intf_extra *ptr)
{
	return dplane_intf_extra_list_const_next(&ctx->u.rinfo.intf_extra_list,
						 ptr);
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

/*
 * End of interface extra info accessors
 */

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

enum dplane_netconf_status_e
dplane_ctx_get_netconf_mpls(const struct zebra_dplane_ctx *ctx)
{
	DPLANE_CTX_VALID(ctx);

	return ctx->u.netconf.mpls_val;
}

enum dplane_netconf_status_e
dplane_ctx_get_netconf_mcast(const struct zebra_dplane_ctx *ctx)
{
	DPLANE_CTX_VALID(ctx);

	return ctx->u.netconf.mcast_val;
}

enum dplane_netconf_status_e
dplane_ctx_get_netconf_linkdown(const struct zebra_dplane_ctx *ctx)
{
	DPLANE_CTX_VALID(ctx);

	return ctx->u.netconf.linkdown_val;
}

void dplane_ctx_set_netconf_mpls(struct zebra_dplane_ctx *ctx,
				 enum dplane_netconf_status_e val)
{
	DPLANE_CTX_VALID(ctx);

	ctx->u.netconf.mpls_val = val;
}

void dplane_ctx_set_netconf_mcast(struct zebra_dplane_ctx *ctx,
				  enum dplane_netconf_status_e val)
{
	DPLANE_CTX_VALID(ctx);

	ctx->u.netconf.mcast_val = val;
}

void dplane_ctx_set_netconf_linkdown(struct zebra_dplane_ctx *ctx,
				     enum dplane_netconf_status_e val)
{
	DPLANE_CTX_VALID(ctx);

	ctx->u.netconf.linkdown_val = val;
}


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

void dplane_ctx_set_vlan_ifindex(struct zebra_dplane_ctx *ctx, ifindex_t ifindex)
{
	DPLANE_CTX_VALID(ctx);
	ctx->u.vlan_info.ifindex = ifindex;
}

ifindex_t dplane_ctx_get_vlan_ifindex(struct zebra_dplane_ctx *ctx)
{
	DPLANE_CTX_VALID(ctx);

	return ctx->u.vlan_info.ifindex;
}

void dplane_ctx_set_vxlan_vlan_array(struct zebra_dplane_ctx *ctx,
				     struct zebra_vxlan_vlan_array *vlan_array)
{
	DPLANE_CTX_VALID(ctx);

	ctx->u.vlan_info.vlan_array = vlan_array;
}

const struct zebra_vxlan_vlan_array *
dplane_ctx_get_vxlan_vlan_array(struct zebra_dplane_ctx *ctx)
{
	DPLANE_CTX_VALID(ctx);

	return ctx->u.vlan_info.vlan_array;
}

/*
 * Internal helper that copies information from a zebra ns object; this is
 * called in the zebra main pthread context as part of dplane ctx init.
 */
static void ctx_info_from_zns(struct zebra_dplane_info *ns_info,
			      struct zebra_ns *zns)
{
	ns_info->ns_id = zns->ns_id;

#if defined(HAVE_NETLINK)
	ns_info->is_cmd = true;
	ns_info->sock = zns->netlink_dplane_out.sock;
	ns_info->seq = zns->netlink_dplane_out.seq;
#endif /* NETLINK */
}

/*
 * Common dataplane context init with zebra namespace info.
 */
static int dplane_ctx_ns_init(struct zebra_dplane_ctx *ctx,
			      struct zebra_ns *zns,
			      bool is_update)
{
	ctx_info_from_zns(&(ctx->zd_ns_info), zns); /*  */

	ctx->zd_is_update = is_update;

#if defined(HAVE_NETLINK)
	/* Increment message counter after copying to context struct - may need
	 * two messages in some 'update' cases.
	 */
	if (is_update)
		zns->netlink_dplane_out.seq += 2;
	else
		zns->netlink_dplane_out.seq++;
#endif	/* HAVE_NETLINK */

	return AOK;
}

int dplane_ctx_route_init_basic(struct zebra_dplane_ctx *ctx,
				enum dplane_op_e op, struct route_entry *re,
				const struct prefix *p,
				const struct prefix_ipv6 *src_p, afi_t afi,
				safi_t safi)
{
	int ret = EINVAL;

	if (!ctx)
		return ret;

	dplane_intf_extra_list_init(&ctx->u.rinfo.intf_extra_list);

	ctx->zd_op = op;
	ctx->zd_status = ZEBRA_DPLANE_REQUEST_SUCCESS;

	/* This function may be called to create/init a dplane context, not
	 * necessarily to copy a route object. Let's return if there is no route
	 * object to copy.
	 */
	if (!re)
		return AOK;

	ctx->u.rinfo.zd_type = re->type;
	ctx->u.rinfo.zd_old_type = re->type;

	prefix_copy(&(ctx->u.rinfo.zd_dest), p);

	if (src_p)
		prefix_copy(&(ctx->u.rinfo.zd_src), src_p);
	else
		memset(&(ctx->u.rinfo.zd_src), 0, sizeof(ctx->u.rinfo.zd_src));

	ctx->zd_table_id = re->table;

	ctx->u.rinfo.zd_flags = re->flags;
	ctx->u.rinfo.zd_metric = re->metric;
	ctx->u.rinfo.zd_old_metric = re->metric;
	ctx->zd_vrf_id = re->vrf_id;
	ctx->u.rinfo.zd_mtu = re->mtu;
	ctx->u.rinfo.zd_nexthop_mtu = re->nexthop_mtu;
	ctx->u.rinfo.zd_instance = re->instance;
	ctx->u.rinfo.zd_tag = re->tag;
	ctx->u.rinfo.zd_old_tag = re->tag;
	ctx->u.rinfo.zd_distance = re->distance;

	ctx->u.rinfo.zd_afi = afi;
	ctx->u.rinfo.zd_safi = safi;

	return AOK;
}

/*
 * Initialize a context block for a route update from zebra data structs.
 * If the `rn` or `re` parameters are NULL, this function only initializes the
 * dplane context without copying a route object into it.
 */
int dplane_ctx_route_init(struct zebra_dplane_ctx *ctx, enum dplane_op_e op,
			  struct route_node *rn, struct route_entry *re)
{
	int ret = EINVAL;
	const struct route_table *table = NULL;
	const struct rib_table_info *info;
	const struct prefix *p;
	const struct prefix_ipv6 *src_p;
	struct zebra_ns *zns;
	struct zebra_vrf *zvrf;
	struct nexthop *nexthop;
	struct zebra_l3vni *zl3vni;
	const struct interface *ifp;
	struct dplane_intf_extra *if_extra;

	if (!ctx)
		return ret;

	/*
	 * Initialize the dplane context and return, if there is no route
	 * object to copy
	 */
	if (!re || !rn)
		return dplane_ctx_route_init_basic(ctx, op, NULL, NULL, NULL,
						   AFI_UNSPEC, SAFI_UNSPEC);

	/*
	 * Let's grab the data from the route_node
	 * so that we can call a helper function
	 */

	/* Prefixes: dest, and optional source */
	srcdest_rnode_prefixes(rn, &p, (const struct prefix **)&src_p);
	table = srcdest_rnode_table(rn);
	info = table->info;

	if (dplane_ctx_route_init_basic(ctx, op, re, p, src_p, info->afi,
					info->safi) != AOK)
		return ret;

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

				dplane_intf_extra_list_add_tail(
					&ctx->u.rinfo.intf_extra_list,
					if_extra);
			}
		}

		/* Check for available evpn encapsulations. */
		if (!CHECK_FLAG(nexthop->flags, NEXTHOP_FLAG_EVPN))
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
		return AOK;
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
		if (nhe->pic_nhe)
			ctx->u.rinfo.nhe.pic_nhe_id = nhe->pic_nhe->id;
		ctx->u.rinfo.unresolved_nhe.id = re->nhe->id;
		ctx->u.rinfo.unresolved_nhe.old_id = 0;
		/*
		 * Check if the nhe is installed/queued before doing anything
		 * with this route.
		 *
		 * If its a delete we only use the prefix anyway, so this only
		 * matters for INSTALL/UPDATE.
		 */
		if (zebra_nhg_kernel_nexthops_enabled() &&
		    (((op == DPLANE_OP_ROUTE_INSTALL) ||
		      (op == DPLANE_OP_ROUTE_UPDATE)) &&
		     !CHECK_FLAG(nhe->flags, NEXTHOP_GROUP_INSTALLED) &&
		     !CHECK_FLAG(nhe->flags, NEXTHOP_GROUP_QUEUED)))
			return ENOENT;

		re->nhe_installed_id = nhe->id;
		if (nhe->pic_nhe)
			re->pic_nhe_installed_id = nhe->pic_nhe->id;
	}
#endif /* HAVE_NETLINK */

	/* Trying out the sequence number idea, so we can try to detect
	 * when a result is stale.
	 */
	re->dplane_sequence = zebra_router_get_next_sequence();
	ctx->zd_seq = re->dplane_sequence;

	return AOK;
}

static int dplane_ctx_tc_qdisc_init(struct zebra_dplane_ctx *ctx,
				    enum dplane_op_e op,
				    const struct zebra_tc_qdisc *qdisc)
{
	int ret = EINVAL;

	struct zebra_ns *zns = NULL;

	ctx->zd_op = op;
	ctx->zd_status = ZEBRA_DPLANE_REQUEST_SUCCESS;
	ctx->zd_ifindex = qdisc->qdisc.ifindex;
	ctx->u.tc_qdisc.kind = qdisc->qdisc.kind;
	ctx->u.tc_qdisc.kind_str = tc_qdisc_kind2str(qdisc->qdisc.kind);

	/* TODO: init traffic control qdisc */
	zns = zebra_ns_lookup(NS_DEFAULT);

	dplane_ctx_ns_init(ctx, zns, true);

	ret = AOK;

	return ret;
}

static int dplane_ctx_tc_class_init(struct zebra_dplane_ctx *ctx,
				    enum dplane_op_e op,
				    struct zebra_tc_class *class)
{
	int ret = EINVAL;

	struct zebra_ns *zns = NULL;

	ctx->zd_op = op;
	ctx->zd_status = ZEBRA_DPLANE_REQUEST_SUCCESS;
	ctx->zd_ifindex = class->class.ifindex;

	ctx->u.tc_class.handle = class->class.handle;
	ctx->u.tc_class.kind = class->class.kind;
	ctx->u.tc_class.kind_str = tc_qdisc_kind2str(class->class.kind);
	ctx->u.tc_class.rate = class->class.u.htb.rate;
	ctx->u.tc_class.ceil = class->class.u.htb.ceil;

	zns = zebra_ns_lookup(NS_DEFAULT);

	dplane_ctx_ns_init(ctx, zns, true);

	ret = AOK;

	return ret;
}

static int dplane_ctx_tc_filter_init(struct zebra_dplane_ctx *ctx,
				     enum dplane_op_e op,
				     struct zebra_tc_filter *filter)
{
	int ret = EINVAL;

	struct zebra_ns *zns = NULL;

	ctx->zd_op = op;
	ctx->zd_status = ZEBRA_DPLANE_REQUEST_SUCCESS;
	ctx->zd_ifindex = filter->filter.ifindex;

	ctx->u.tc_filter.eth_proto = filter->filter.protocol;
	ctx->u.tc_filter.ip_proto = filter->filter.u.flower.ip_proto;

	ctx->u.tc_filter.kind = filter->filter.kind;
	ctx->u.tc_filter.kind_str = tc_filter_kind2str(filter->filter.kind);

	ctx->u.tc_filter.filter_bm = filter->filter.u.flower.filter_bm;
	prefix_copy(&ctx->u.tc_filter.src_ip, &filter->filter.u.flower.src_ip);
	ctx->u.tc_filter.src_port_min = filter->filter.u.flower.src_port_min;
	ctx->u.tc_filter.src_port_max = filter->filter.u.flower.src_port_max;
	prefix_copy(&ctx->u.tc_filter.dst_ip, &filter->filter.u.flower.dst_ip);
	ctx->u.tc_filter.dst_port_min = filter->filter.u.flower.dst_port_min;
	ctx->u.tc_filter.dst_port_max = filter->filter.u.flower.dst_port_max;
	ctx->u.tc_filter.dsfield = filter->filter.u.flower.dsfield;
	ctx->u.tc_filter.dsfield_mask = filter->filter.u.flower.dsfield_mask;
	ctx->u.tc_filter.classid = filter->filter.u.flower.classid;

	ctx->u.tc_filter.priority = filter->filter.priority;
	ctx->u.tc_filter.handle = filter->filter.handle;

	zns = zebra_ns_lookup(NS_DEFAULT);

	dplane_ctx_ns_init(ctx, zns, true);

	ret = AOK;

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
		return ret;

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

	ret = AOK;

	return ret;
}

/**
 * dplane_ctx_intf_init() - Initialize a context block for a interface update
 *
 * @ctx:	Dataplane context to init
 * @op:		Operation being performed
 * @ifp:	Interface
 *
 * Return:	Result status
 */
int dplane_ctx_intf_init(struct zebra_dplane_ctx *ctx, enum dplane_op_e op,
			 const struct interface *ifp)
{
	struct zebra_ns *zns;
	struct zebra_if *zif;
	int ret = EINVAL;
	bool set_pdown, unset_pdown;

	if (!ctx || !ifp)
		return ret;

	ctx->zd_op = op;
	ctx->zd_status = ZEBRA_DPLANE_REQUEST_SUCCESS;
	ctx->zd_vrf_id = ifp->vrf->vrf_id;

	strlcpy(ctx->zd_ifname, ifp->name, sizeof(ctx->zd_ifname));
	ctx->zd_ifindex = ifp->ifindex;

	zns = zebra_ns_lookup(ifp->vrf->vrf_id);
	dplane_ctx_ns_init(ctx, zns, false);


	/* Copy over ifp info */
	ctx->u.intf.metric = ifp->metric;
	ctx->u.intf.flags = ifp->flags;

	/* Copy over extra zebra info, if available */
	zif = (struct zebra_if *)ifp->info;

	if (zif) {
		set_pdown = !!(zif->flags & ZIF_FLAG_SET_PROTODOWN);
		unset_pdown = !!(zif->flags & ZIF_FLAG_UNSET_PROTODOWN);

		if (zif->protodown_rc &&
		    ZEBRA_IF_IS_PROTODOWN_ONLY_EXTERNAL(zif) == false)
			ctx->u.intf.pd_reason_val = true;

		/*
		 * See if we have new protodown state to set, otherwise keep
		 * current state
		 */
		if (set_pdown)
			ctx->u.intf.protodown = true;
		else if (unset_pdown)
			ctx->u.intf.protodown = false;
		else
			ctx->u.intf.protodown = !!ZEBRA_IF_IS_PROTODOWN(zif);
	}

	dplane_ctx_ns_init(ctx, zns, (op == DPLANE_OP_INTF_UPDATE));
	ctx->zd_is_update = (op == DPLANE_OP_INTF_UPDATE);

	ret = AOK;

	return ret;
}

/*
 * Capture information for an LSP update in a dplane context.
 */
int dplane_ctx_lsp_init(struct zebra_dplane_ctx *ctx, enum dplane_op_e op,
			struct zebra_lsp *lsp)
{
	int ret = AOK;
	struct zebra_nhlfe *nhlfe, *new_nhlfe;

	ctx->zd_op = op;
	ctx->zd_status = ZEBRA_DPLANE_REQUEST_SUCCESS;

	/* Capture namespace info */
	dplane_ctx_ns_init(ctx, zebra_ns_lookup(NS_DEFAULT),
			   (op == DPLANE_OP_LSP_UPDATE));

	memset(&ctx->u.lsp, 0, sizeof(ctx->u.lsp));

	nhlfe_list_init(&(ctx->u.lsp.nhlfe_list));
	nhlfe_list_init(&(ctx->u.lsp.backup_nhlfe_list));

	/* This may be called to create/init a dplane context, not necessarily
	 * to copy an lsp object.
	 */
	if (lsp == NULL)
		return ret;

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
		return ret;

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

	return ret;
}

/*
 * Capture information for an LSP update in a dplane context.
 */
static int dplane_ctx_pw_init(struct zebra_dplane_ctx *ctx,
			      enum dplane_op_e op,
			      struct zebra_pw *pw)
{
	int ret = EINVAL;
	struct prefix p;
	afi_t afi;
	struct route_table *table;
	struct route_node *rn;
	struct route_entry *re;
	const struct nexthop_group *nhg;
	struct nexthop *nh, *newnh, *last_nh;

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
	p.prefixlen = ((pw->af == AF_INET) ? IPV4_MAX_BITLEN : IPV6_MAX_BITLEN);

	afi = (pw->af == AF_INET) ? AFI_IP : AFI_IP6;
	table = zebra_vrf_table(afi, SAFI_UNICAST, pw->vrf_id);
	if (table == NULL)
		return ret;

	rn = route_node_match(table, &p);
	if (rn == NULL)
		return ret;

	re = NULL;
	RNODE_FOREACH_RE(rn, re) {
		if (CHECK_FLAG(re->flags, ZEBRA_FLAG_SELECTED))
			break;
	}

	if (re) {
		/* We'll capture a 'fib' list of nexthops that meet our
		 * criteria: installed, and labelled.
		 */
		nhg = rib_get_fib_nhg(re);
		last_nh = NULL;

		if (nhg && nhg->nexthop) {
			for (ALL_NEXTHOPS_PTR(nhg, nh)) {
				if (!CHECK_FLAG(nh->flags, NEXTHOP_FLAG_ACTIVE)
				    || CHECK_FLAG(nh->flags,
						  NEXTHOP_FLAG_RECURSIVE)
				    || nh->nh_label == NULL)
					continue;

				newnh = nexthop_dup(nh, NULL);

				if (last_nh)
					NEXTHOP_APPEND(last_nh, newnh);
				else
					ctx->u.pw.fib_nhg.nexthop = newnh;
				last_nh = newnh;
			}
		}

		/* Include any installed backup nexthops also. */
		nhg = rib_get_fib_backup_nhg(re);
		if (nhg && nhg->nexthop) {
			for (ALL_NEXTHOPS_PTR(nhg, nh)) {
				if (!CHECK_FLAG(nh->flags, NEXTHOP_FLAG_ACTIVE)
				    || CHECK_FLAG(nh->flags,
						  NEXTHOP_FLAG_RECURSIVE)
				    || nh->nh_label == NULL)
					continue;

				newnh = nexthop_dup(nh, NULL);

				if (last_nh)
					NEXTHOP_APPEND(last_nh, newnh);
				else
					ctx->u.pw.fib_nhg.nexthop = newnh;
				last_nh = newnh;
			}
		}

		/* Copy primary nexthops; recursive info is included too */
		assert(re->nhe != NULL); /* SA warning */
		copy_nexthops(&(ctx->u.pw.primary_nhg.nexthop),
			      re->nhe->nhg.nexthop, NULL);
		ctx->u.pw.nhg_id = re->nhe->id;

		/* Copy backup nexthop info, if present */
		if (re->nhe->backup_info && re->nhe->backup_info->nhe) {
			copy_nexthops(&(ctx->u.pw.backup_nhg.nexthop),
				      re->nhe->backup_info->nhe->nhg.nexthop,
				      NULL);
		}
	}
	route_unlock_node(rn);

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
	struct zebra_neigh_ent *n;

	dplane_rule->prule = rule->rule;

	dplane_rule->dp_flow_ptr = rule->action.dp_flow_ptr;
	n = rule->action.neigh;
	if (n && (n->flags & ZEBRA_NEIGH_ENT_ACTIVE)) {
		struct interface *ifp = if_lookup_by_index_per_ns(
			zebra_ns_lookup(NS_DEFAULT), n->ifindex);
		if (ifp) {
			dplane_rule->out_ifindex = n->ifindex;
			memcpy(&dplane_rule->dmac, &n->mac, ETH_ALEN);
			memcpy(&dplane_rule->smac, ifp->hw_addr, ETH_ALEN);
		} else {
			dplane_rule->out_ifindex = 0;
		}
	}
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

	ctx->zd_vrf_id = new_rule->vrf_id;
	strlcpy(ctx->zd_ifname, new_rule->ifname, sizeof(ctx->zd_ifname));

	ctx->u.rule.sock = new_rule->sock;
	ctx->u.rule.unique = new_rule->rule.unique;
	ctx->u.rule.seq = new_rule->rule.seq;

	dplane_ctx_rule_init_single(&ctx->u.rule.new, new_rule);
	if (op == DPLANE_OP_RULE_UPDATE) {
		dplane_ctx_rule_init_single(&ctx->u.rule.old, old_rule);
		/* clear the dp_flow_ptr in the old_rule - it is about to be
		 * deleted
		 */
		old_rule->action.dp_flow_ptr = (intptr_t)NULL;
	}

	return AOK;
}

static void zebra_dplane_interface_name_list_deletion(void *data)
{
	XFREE(MTYPE_DP_NETFILTER, data);
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

	ctx->zd_vrf_id = iptable->vrf_id;
	memcpy(&ctx->u.iptable, iptable, sizeof(struct zebra_pbr_iptable));
	ctx->u.iptable.interface_name_list = NULL;
	if (iptable->nb_interface > 0) {
		ctx->u.iptable.interface_name_list = list_new();
		ctx->u.iptable.interface_name_list->del =
			zebra_dplane_interface_name_list_deletion;
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

	ctx->zd_vrf_id = ipset->vrf_id;

	memcpy(&ctx->u.ipset_entry.entry, ipset_entry,
	       sizeof(struct zebra_pbr_ipset_entry));
	ctx->u.ipset_entry.entry.backpointer = NULL;
	ctx->u.ipset_entry.info.type = ipset->type;
	ctx->u.ipset_entry.info.family = ipset->family;
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
		dplane_ctx_list_add_tail(&zdplane_info.dg_update_list, ctx);
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
					       NEXTHOP_FLAG_DUPLICATE))
					continue;

				if (CHECK_FLAG(nexthop->flags,
					       NEXTHOP_FLAG_ACTIVE))
					SET_FLAG(nexthop->flags,
						 NEXTHOP_FLAG_FIB);
			}

			if ((op == DPLANE_OP_ROUTE_UPDATE) && old_re && re &&
			    (old_re != re) &&
			    !CHECK_FLAG(re->status, ROUTE_ENTRY_INSTALLED))
				SET_FLAG(re->status, ROUTE_ENTRY_INSTALLED);

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

static enum zebra_dplane_result
tc_qdisc_update_internal(enum dplane_op_e op,
			 const struct zebra_tc_qdisc *qdisc)
{
	enum zebra_dplane_result result = ZEBRA_DPLANE_REQUEST_FAILURE;
	int ret;
	struct zebra_dplane_ctx *ctx = NULL;

	/* Obtain context block */
	ctx = dplane_ctx_alloc();

	/* Init context with info from zebra data structs */
	ret = dplane_ctx_tc_qdisc_init(ctx, op, qdisc);

	if (ret == AOK)
		ret = dplane_update_enqueue(ctx);

	/* Update counter */
	atomic_fetch_add_explicit(&zdplane_info.dg_tcs_in, 1,
				  memory_order_relaxed);
	if (ret == AOK) {
		result = ZEBRA_DPLANE_REQUEST_QUEUED;
	} else {
		atomic_fetch_add_explicit(&zdplane_info.dg_tcs_errors, 1,
					  memory_order_relaxed);
		dplane_ctx_free(&ctx);
	}

	return result;
}

static enum zebra_dplane_result
tc_class_update_internal(enum dplane_op_e op, struct zebra_tc_class *class)
{
	enum zebra_dplane_result result = ZEBRA_DPLANE_REQUEST_FAILURE;
	int ret;
	struct zebra_dplane_ctx *ctx = NULL;

	/* Obtain context block */
	ctx = dplane_ctx_alloc();

	/* Init context with info from zebra data structs */
	ret = dplane_ctx_tc_class_init(ctx, op, class);

	if (ret == AOK)
		ret = dplane_update_enqueue(ctx);

	/* Update counter */
	atomic_fetch_add_explicit(&zdplane_info.dg_tcs_in, 1,
				  memory_order_relaxed);
	if (ret == AOK) {
		result = ZEBRA_DPLANE_REQUEST_QUEUED;
	} else {
		atomic_fetch_add_explicit(&zdplane_info.dg_tcs_errors, 1,
					  memory_order_relaxed);
		dplane_ctx_free(&ctx);
	}

	return result;
}

static enum zebra_dplane_result
tc_filter_update_internal(enum dplane_op_e op, struct zebra_tc_filter *filter)
{
	enum zebra_dplane_result result = ZEBRA_DPLANE_REQUEST_FAILURE;
	int ret;
	struct zebra_dplane_ctx *ctx = NULL;

	/* Obtain context block */
	ctx = dplane_ctx_alloc();

	/* Init context with info from zebra data structs */
	ret = dplane_ctx_tc_filter_init(ctx, op, filter);

	if (ret == AOK)
		ret = dplane_update_enqueue(ctx);

	/* Update counter */
	atomic_fetch_add_explicit(&zdplane_info.dg_tcs_in, 1,
				  memory_order_relaxed);
	if (ret == AOK) {
		result = ZEBRA_DPLANE_REQUEST_QUEUED;
	} else {
		atomic_fetch_add_explicit(&zdplane_info.dg_tcs_errors, 1,
					  memory_order_relaxed);
		dplane_ctx_free(&ctx);
	}

	return result;
}

enum zebra_dplane_result dplane_tc_qdisc_install(struct zebra_tc_qdisc *qdisc)
{
	return tc_qdisc_update_internal(DPLANE_OP_TC_QDISC_INSTALL, qdisc);
}

enum zebra_dplane_result dplane_tc_qdisc_uninstall(struct zebra_tc_qdisc *qdisc)
{
	return tc_qdisc_update_internal(DPLANE_OP_TC_QDISC_UNINSTALL, qdisc);
}

enum zebra_dplane_result dplane_tc_class_add(struct zebra_tc_class *class)
{
	return tc_class_update_internal(DPLANE_OP_TC_CLASS_ADD, class);
}

enum zebra_dplane_result dplane_tc_class_delete(struct zebra_tc_class *class)
{
	return tc_class_update_internal(DPLANE_OP_TC_CLASS_DELETE, class);
}

enum zebra_dplane_result dplane_tc_class_update(struct zebra_tc_class *class)
{
	return tc_class_update_internal(DPLANE_OP_TC_CLASS_UPDATE, class);
}

enum zebra_dplane_result dplane_tc_filter_add(struct zebra_tc_filter *filter)
{
	return tc_filter_update_internal(DPLANE_OP_TC_FILTER_ADD, filter);
}

enum zebra_dplane_result dplane_tc_filter_delete(struct zebra_tc_filter *filter)
{
	return tc_filter_update_internal(DPLANE_OP_TC_FILTER_DELETE, filter);
}

enum zebra_dplane_result dplane_tc_filter_update(struct zebra_tc_filter *filter)
{
	return tc_filter_update_internal(DPLANE_OP_TC_FILTER_UPDATE, filter);
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
	int ret;
	struct zebra_dplane_ctx *ctx = NULL;

	/* Obtain context block */
	ctx = dplane_ctx_alloc();

	ret = dplane_ctx_nexthop_init(ctx, op, nhe);
	if (ret == AOK) {
		if (CHECK_FLAG(nhe->flags, NEXTHOP_GROUP_INITIAL_DELAY_INSTALL)) {
			UNSET_FLAG(nhe->flags, NEXTHOP_GROUP_QUEUED);
			UNSET_FLAG(nhe->flags, NEXTHOP_GROUP_REINSTALL);
			SET_FLAG(nhe->flags, NEXTHOP_GROUP_INSTALLED);

			dplane_ctx_free(&ctx);
			atomic_fetch_add_explicit(&zdplane_info.dg_nexthops_in,
						  1, memory_order_relaxed);

			return ZEBRA_DPLANE_REQUEST_SUCCESS;
		}

		ret = dplane_update_enqueue(ctx);
	}

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
		return ret;

	ret = dplane_route_update_internal(rn, re, NULL,
					   DPLANE_OP_ROUTE_INSTALL);

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
		return ret;

	ret = dplane_route_update_internal(rn, re, old_re,
					   DPLANE_OP_ROUTE_UPDATE);

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
		return ret;

	ret = dplane_route_update_internal(rn, re, NULL,
					   DPLANE_OP_ROUTE_DELETE);

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
	if (!zdplane_info.dg_sys_route_notifs)
		return ZEBRA_DPLANE_REQUEST_SUCCESS;


	if (rn == NULL || re == NULL)
		return ret;

	ret = dplane_route_update_internal(rn, re, NULL,
					   DPLANE_OP_SYS_ROUTE_ADD);

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
	if (!zdplane_info.dg_sys_route_notifs)
		return ZEBRA_DPLANE_REQUEST_SUCCESS;

	if (rn == NULL || re == NULL)
		return ret;

	ret = dplane_route_update_internal(rn, re, NULL,
					   DPLANE_OP_SYS_ROUTE_DELETE);

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

enum zebra_dplane_result dplane_pic_nh_add(struct nhg_hash_entry *nhe)
{
	enum zebra_dplane_result ret = ZEBRA_DPLANE_REQUEST_FAILURE;

	if (nhe)
		ret = dplane_nexthop_update_internal(nhe, DPLANE_OP_PIC_NH_INSTALL);
	return ret;
}

enum zebra_dplane_result dplane_pic_nh_delete(struct nhg_hash_entry *nhe)
{
	enum zebra_dplane_result ret = ZEBRA_DPLANE_REQUEST_FAILURE;

	if (nhe)
		ret = dplane_nexthop_update_internal(nhe, DPLANE_OP_PIC_NH_DELETE);

	return ret;
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
enum zebra_dplane_result dplane_lsp_add(struct zebra_lsp *lsp)
{
	enum zebra_dplane_result ret =
		lsp_update_internal(lsp, DPLANE_OP_LSP_INSTALL);

	return ret;
}

/*
 * Enqueue LSP update for the dataplane.
 */
enum zebra_dplane_result dplane_lsp_update(struct zebra_lsp *lsp)
{
	enum zebra_dplane_result ret =
		lsp_update_internal(lsp, DPLANE_OP_LSP_UPDATE);

	return ret;
}

/*
 * Enqueue LSP delete for the dataplane.
 */
enum zebra_dplane_result dplane_lsp_delete(struct zebra_lsp *lsp)
{
	enum zebra_dplane_result ret =
		lsp_update_internal(lsp, DPLANE_OP_LSP_DELETE);

	return ret;
}

/* Update or un-install resulting from an async notification */
enum zebra_dplane_result
dplane_lsp_notif_update(struct zebra_lsp *lsp, enum dplane_op_e op,
			struct zebra_dplane_ctx *notif_ctx)
{
	enum zebra_dplane_result result = ZEBRA_DPLANE_REQUEST_FAILURE;
	int ret;
	struct zebra_dplane_ctx *ctx = NULL;
	struct nhlfe_list_head *head;
	struct zebra_nhlfe *nhlfe, *new_nhlfe;

	/* Obtain context block */
	ctx = dplane_ctx_alloc();

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
static enum zebra_dplane_result lsp_update_internal(struct zebra_lsp *lsp,
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
	ctx->zd_vrf_id = ifp->vrf->vrf_id;

	zns = zebra_ns_lookup(ifp->vrf->vrf_id);
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

enum zebra_dplane_result
dplane_intf_mpls_modify_state(const struct interface *ifp, bool set)
{
	enum zebra_dplane_result result = ZEBRA_DPLANE_REQUEST_FAILURE;
	struct zebra_dplane_ctx *ctx;
	struct zebra_ns *zns;
	int ret = EINVAL;

	ctx = dplane_ctx_alloc();
	ctx->zd_op = DPLANE_OP_INTF_NETCONFIG;
	ctx->zd_status = ZEBRA_DPLANE_REQUEST_SUCCESS;
	ctx->zd_vrf_id = ifp->vrf->vrf_id;
	strlcpy(ctx->zd_ifname, ifp->name, sizeof(ctx->zd_ifname));

	zns = zebra_ns_lookup(ifp->vrf->vrf_id);
	dplane_ctx_ns_init(ctx, zns, false);

	ctx->zd_ifindex = ifp->ifindex;
	if (set)
		dplane_ctx_set_netconf_mpls(ctx, DPLANE_NETCONF_STATUS_ENABLED);
	else
		dplane_ctx_set_netconf_mpls(ctx,
					    DPLANE_NETCONF_STATUS_DISABLED);
	/* Increment counter */
	atomic_fetch_add_explicit(&zdplane_info.dg_intf_changes, 1,
				  memory_order_relaxed);

	ret = dplane_update_enqueue(ctx);

	if (ret == AOK)
		result = ZEBRA_DPLANE_REQUEST_QUEUED;
	else {
		/* Error counter */
		atomic_fetch_add_explicit(&zdplane_info.dg_intf_changes_errors,
					  1, memory_order_relaxed);
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
			   dplane_op2str(op), ifp->ifindex, ifp->vrf->vrf_id,
			   ifc->address);

	ctx = dplane_ctx_alloc();

	ctx->zd_op = op;
	ctx->zd_status = ZEBRA_DPLANE_REQUEST_SUCCESS;
	ctx->zd_vrf_id = ifp->vrf->vrf_id;

	zns = zebra_ns_lookup(ifp->vrf->vrf_id);
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
			ctx->u.intf.label = XSTRDUP(MTYPE_DP_CTX, ifc->label);
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

/**
 * dplane_intf_update_internal() - Helper for enqueuing interface changes
 *
 * @ifp:	Interface where the change occured
 * @op:		The operation to be enqued
 *
 * Return:	Result of the change
 */
static enum zebra_dplane_result
dplane_intf_update_internal(const struct interface *ifp, enum dplane_op_e op)
{
	enum zebra_dplane_result result = ZEBRA_DPLANE_REQUEST_FAILURE;
	int ret;
	struct zebra_dplane_ctx *ctx = NULL;

	/* Obtain context block */
	ctx = dplane_ctx_alloc();

	ret = dplane_ctx_intf_init(ctx, op, ifp);
	if (ret == AOK)
		ret = dplane_update_enqueue(ctx);

	/* Update counter */
	atomic_fetch_add_explicit(&zdplane_info.dg_intfs_in, 1,
				  memory_order_relaxed);

	if (ret == AOK)
		result = ZEBRA_DPLANE_REQUEST_QUEUED;
	else {
		atomic_fetch_add_explicit(&zdplane_info.dg_intf_errors, 1,
					  memory_order_relaxed);
		if (ctx)
			dplane_ctx_free(&ctx);
	}

	return result;
}

/*
 * Enqueue a interface add for the dataplane.
 */
enum zebra_dplane_result dplane_intf_add(const struct interface *ifp)
{
	enum zebra_dplane_result ret = ZEBRA_DPLANE_REQUEST_FAILURE;

	if (ifp)
		ret = dplane_intf_update_internal(ifp, DPLANE_OP_INTF_INSTALL);
	return ret;
}

/*
 * Enqueue a interface update for the dataplane.
 */
enum zebra_dplane_result dplane_intf_update(const struct interface *ifp)
{
	enum zebra_dplane_result ret = ZEBRA_DPLANE_REQUEST_FAILURE;

	if (ifp)
		ret = dplane_intf_update_internal(ifp, DPLANE_OP_INTF_UPDATE);
	return ret;
}

/*
 * Enqueue vxlan/evpn mac add (or update).
 */
enum zebra_dplane_result
dplane_rem_mac_add(const struct interface *ifp,
		   const struct interface *bridge_ifp, vlanid_t vid,
		   const struct ethaddr *mac, vni_t vni, struct in_addr vtep_ip,
		   bool sticky, uint32_t nhg_id, bool was_static)
{
	enum zebra_dplane_result result;
	uint32_t update_flags = 0;

	update_flags |= DPLANE_MAC_REMOTE;
	if (was_static)
		update_flags |= DPLANE_MAC_WAS_STATIC;

	/* Use common helper api */
	result = mac_update_common(DPLANE_OP_MAC_INSTALL, ifp, bridge_ifp, vid,
				   mac, vni, vtep_ip, sticky, nhg_id,
				   update_flags);
	return result;
}

/*
 * Enqueue vxlan/evpn mac delete.
 */
enum zebra_dplane_result dplane_rem_mac_del(const struct interface *ifp,
					    const struct interface *bridge_ifp,
					    vlanid_t vid,
					    const struct ethaddr *mac,
					    vni_t vni, struct in_addr vtep_ip)
{
	enum zebra_dplane_result result;
	uint32_t update_flags = 0;

	update_flags |= DPLANE_MAC_REMOTE;

	/* Use common helper api */
	result = mac_update_common(DPLANE_OP_MAC_DELETE, ifp, bridge_ifp, vid,
				   mac, vni, vtep_ip, false, 0, update_flags);
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

	if (IS_ZEBRA_DEBUG_DPLANE_DETAIL)
		zlog_debug("%s: init link ctx %s: ifp %s, link_ip %pIA ip %pIA",
			   __func__, dplane_op2str(op), ifp->name, link_ip, ip);

	if (ndm_state == ZEBRA_NEIGH_STATE_REACHABLE)
		state = DPLANE_NUD_REACHABLE;
	else if (ndm_state == ZEBRA_NEIGH_STATE_FAILED)
		state = DPLANE_NUD_FAILED;

	update_flags = DPLANE_NEIGH_NO_EXTENSION;

	result = neigh_update_internal(op, ifp, (const void *)link_ip,
				       ipaddr_family(link_ip), ip, 0, 0, state,
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
	result = mac_update_common(DPLANE_OP_MAC_INSTALL, ifp, bridge_ifp, vid,
				   mac, 0, vtep_ip, sticky, 0, update_flags);
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
				   mac, 0, vtep_ip, false, 0, 0);
	return result;
}
/*
 * Public api to init an empty context - either newly-allocated or
 * reset/cleared - for a MAC update.
 */
void dplane_mac_init(struct zebra_dplane_ctx *ctx, const struct interface *ifp,
		     const struct interface *br_ifp, vlanid_t vid,
		     const struct ethaddr *mac, vni_t vni,
		     struct in_addr vtep_ip, bool sticky, uint32_t nhg_id,
		     uint32_t update_flags)
{
	struct zebra_ns *zns;

	ctx->zd_status = ZEBRA_DPLANE_REQUEST_SUCCESS;
	ctx->zd_vrf_id = ifp->vrf->vrf_id;

	zns = zebra_ns_lookup(ifp->vrf->vrf_id);
	dplane_ctx_ns_init(ctx, zns, false);

	strlcpy(ctx->zd_ifname, ifp->name, sizeof(ctx->zd_ifname));
	ctx->zd_ifindex = ifp->ifindex;

	/* Init the mac-specific data area */
	memset(&ctx->u.macinfo, 0, sizeof(ctx->u.macinfo));

	ctx->u.macinfo.br_ifindex = br_ifp->ifindex;
	ctx->u.macinfo.vtep_ip = vtep_ip;
	ctx->u.macinfo.mac = *mac;
	ctx->u.macinfo.vni = vni;
	ctx->u.macinfo.vid = vid;
	ctx->u.macinfo.is_sticky = sticky;
	ctx->u.macinfo.nhg_id = nhg_id;
	ctx->u.macinfo.update_flags = update_flags;
}

/*
 * Common helper api for MAC address/vxlan updates
 */
static enum zebra_dplane_result
mac_update_common(enum dplane_op_e op, const struct interface *ifp,
		  const struct interface *br_ifp, vlanid_t vid,
		  const struct ethaddr *mac, vni_t vni, struct in_addr vtep_ip,
		  bool sticky, uint32_t nhg_id, uint32_t update_flags)
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
	dplane_mac_init(ctx, ifp, br_ifp, vid, mac, vni, vtep_ip, sticky,
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
		ip, 0, flags, DPLANE_NUD_NOARP, update_flags, 0);

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
				       (const void *)mac, AF_ETHERNET, ip, 0,
				       ntf, state, update_flags, 0);

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
				       AF_ETHERNET, ip, 0, 0, 0, update_flags,
				       0);

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
				       AF_ETHERNET, &addr, vni, 0, 0, 0, 0);

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
				       vni, 0, 0, 0, 0);

	return result;
}

enum zebra_dplane_result dplane_neigh_discover(const struct interface *ifp,
					       const struct ipaddr *ip)
{
	enum zebra_dplane_result result;

	result = neigh_update_internal(DPLANE_OP_NEIGH_DISCOVER, ifp, NULL,
				       AF_ETHERNET, ip, 0, DPLANE_NTF_USE,
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
	ctx->zd_vrf_id = ifp->vrf->vrf_id;

	zns = zebra_ns_lookup(ifp->vrf->vrf_id);
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
		      const struct ipaddr *ip, vni_t vni, uint32_t flags,
		      uint16_t state, uint32_t update_flags, int protocol)
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
			   link_family == AF_ETHERNET ? "mac" : "link", buf1,
			   ip);
	}

	ctx = dplane_ctx_alloc();

	ctx->zd_op = op;
	ctx->zd_status = ZEBRA_DPLANE_REQUEST_SUCCESS;
	ctx->zd_vrf_id = ifp->vrf->vrf_id;
	dplane_ctx_set_type(ctx, protocol);

	zns = zebra_ns_lookup(ifp->vrf->vrf_id);
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
	ctx->u.neigh.vni = vni;
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

	if ((op == DPLANE_OP_IPTABLE_ADD &&
	     CHECK_FLAG(iptable->internal_flags, IPTABLE_INSTALL_QUEUED)) ||
	    (op == DPLANE_OP_IPTABLE_DELETE &&
	     CHECK_FLAG(iptable->internal_flags, IPTABLE_UNINSTALL_QUEUED))) {
		if (IS_ZEBRA_DEBUG_DPLANE_DETAIL)
			zlog_debug(
				"update dplane ctx %s: iptable %s already in progress",
				dplane_op2str(op), iptable->ipset_name);
		return result;
	}

	ctx = dplane_ctx_alloc();

	ret = dplane_ctx_iptable_init(ctx, op, iptable);
	if (ret != AOK)
		goto done;

	ret = dplane_update_enqueue(ctx);

done:
	atomic_fetch_add_explicit(&zdplane_info.dg_iptable_in, 1,
				  memory_order_relaxed);

	if (ret == AOK) {
		result = ZEBRA_DPLANE_REQUEST_QUEUED;
		if (op == DPLANE_OP_IPTABLE_ADD)
			SET_FLAG(iptable->internal_flags,
				 IPTABLE_INSTALL_QUEUED);
		else
			SET_FLAG(iptable->internal_flags,
				 IPTABLE_UNINSTALL_QUEUED);
	} else {
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
dplane_gre_set(struct interface *ifp, struct interface *ifp_link,
	       unsigned int mtu, const struct zebra_l2info_gre *gre_info)
{
	enum zebra_dplane_result result = ZEBRA_DPLANE_REQUEST_FAILURE;
	struct zebra_dplane_ctx *ctx;
	enum dplane_op_e op = DPLANE_OP_GRE_SET;
	int ret;
	struct zebra_ns *zns;

	ctx = dplane_ctx_alloc();

	if (!ifp) {
		ret = EINVAL;
		goto done;
	}

	if (IS_ZEBRA_DEBUG_DPLANE_DETAIL) {
		zlog_debug("init dplane ctx %s: if %s link %s%s",
			   dplane_op2str(op), ifp->name,
			   ifp_link ? "set" : "unset", ifp_link ?
			   ifp_link->name : "");
	}

	ctx->zd_op = op;
	ctx->zd_status = ZEBRA_DPLANE_REQUEST_SUCCESS;
	zns = zebra_ns_lookup(ifp->vrf->vrf_id);
	if (!zns) {
		ret = EINVAL;
		goto done;
	}

	dplane_ctx_ns_init(ctx, zns, false);

	dplane_ctx_set_ifname(ctx, ifp->name);
	ctx->zd_vrf_id = ifp->vrf->vrf_id;
	ctx->zd_ifindex = ifp->ifindex;
	if (ifp_link)
		ctx->u.gre.link_ifindex = ifp_link->ifindex;
	else
		ctx->u.gre.link_ifindex = 0;
	if (gre_info)
		memcpy(&ctx->u.gre.info, gre_info, sizeof(ctx->u.gre.info));
	ctx->u.gre.mtu = mtu;

	ctx->zd_status = ZEBRA_DPLANE_REQUEST_SUCCESS;

	/* Enqueue context for processing */
	ret = dplane_update_enqueue(ctx);

done:
	/* Update counter */
	atomic_fetch_add_explicit(&zdplane_info.dg_gre_set_in, 1,
				  memory_order_relaxed);

	if (ret == AOK)
		result = ZEBRA_DPLANE_REQUEST_QUEUED;
	else {
		atomic_fetch_add_explicit(
			&zdplane_info.dg_gre_set_errors, 1,
			memory_order_relaxed);
		dplane_ctx_free(&ctx);
		result = ZEBRA_DPLANE_REQUEST_FAILURE;
	}
	return result;
}

/*
 * Common helper api for SRv6 encapsulation source address set
 */
enum zebra_dplane_result
dplane_srv6_encap_srcaddr_set(const struct in6_addr *addr, ns_id_t ns_id)
{
	enum zebra_dplane_result result = ZEBRA_DPLANE_REQUEST_FAILURE;
	struct zebra_dplane_ctx *ctx = NULL;
	enum dplane_op_e op = DPLANE_OP_SRV6_ENCAP_SRCADDR_SET;
	int ret;
	struct zebra_ns *zns;

	if (!addr)
		return result;

	if (IS_ZEBRA_DEBUG_DPLANE_DETAIL) {
		zlog_debug("init dplane ctx %s: addr %pI6", dplane_op2str(op),
			   addr);
	}

	zns = zebra_ns_lookup(ns_id);
	if (!zns)
		return result;

	ctx = dplane_ctx_alloc();

	ctx->zd_op = op;
	ctx->zd_status = ZEBRA_DPLANE_REQUEST_SUCCESS;

	dplane_ctx_ns_init(ctx, zns, false);

	/* Init the SRv6 encap source address specific data area */
	memcpy(&ctx->u.srv6_encap.srcaddr, addr,
	       sizeof(ctx->u.srv6_encap.srcaddr));

	/* Update counter */
	atomic_fetch_add_explicit(&zdplane_info.dg_srv6_encap_srcaddr_set_in, 1,
				  memory_order_relaxed);

	/* Enqueue context for processing */
	ret = dplane_update_enqueue(ctx);

	if (ret == AOK)
		result = ZEBRA_DPLANE_REQUEST_QUEUED;
	else {
		atomic_fetch_add_explicit(&zdplane_info
						   .dg_srv6_encap_srcaddr_set_errors,
					  1, memory_order_relaxed);
		dplane_ctx_free(&ctx);
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

	incoming = atomic_load_explicit(&zdplane_info.dg_nexthops_in,
					memory_order_relaxed);
	errs = atomic_load_explicit(&zdplane_info.dg_nexthop_errors,
				    memory_order_relaxed);
	vty_out(vty, "Nexthop updates:          %" PRIu64 "\n", incoming);
	vty_out(vty, "Nexthop update errors:    %" PRIu64 "\n", errs);

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

	incoming = atomic_load_explicit(&zdplane_info.dg_intf_changes,
					memory_order_relaxed);
	errs = atomic_load_explicit(&zdplane_info.dg_intf_changes_errors,
				    memory_order_relaxed);
	vty_out(vty, "Intf change updates:        %" PRIu64 "\n", incoming);
	vty_out(vty, "Intf change errors:         %" PRIu64 "\n", errs);

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

	DPLANE_LOCK();
	prov = dplane_prov_list_first(&zdplane_info.dg_providers);
	in = dplane_ctx_queue_count(&zdplane_info.dg_update_list);
	DPLANE_UNLOCK();

	vty_out(vty, "dataplane Incoming Queue from Zebra: %" PRIu64 "\n", in);
	vty_out(vty, "Zebra dataplane providers:\n");

	/* Show counters, useful info from each registered provider */
	while (prov) {
		dplane_provider_lock(prov);
		in_q = dplane_ctx_queue_count(&prov->dp_ctx_in_list);
		out_q = dplane_ctx_queue_count(&prov->dp_ctx_out_list);
		dplane_provider_unlock(prov);

		in = atomic_load_explicit(&prov->dp_in_counter,
					  memory_order_relaxed);

		in_max = atomic_load_explicit(&prov->dp_in_max,
					      memory_order_relaxed);
		out = atomic_load_explicit(&prov->dp_out_counter,
					   memory_order_relaxed);

		out_max = atomic_load_explicit(&prov->dp_out_max,
					       memory_order_relaxed);

		vty_out(vty,
			"  %s (%u): in: %" PRIu64 ", q: %" PRIu64
			", q_max: %" PRIu64 ", out: %" PRIu64 ", q: %" PRIu64
			", q_max: %" PRIu64 "\n",
			prov->dp_name, prov->dp_id, in, in_q, in_max, out,
			out_q, out_max);

		prov = dplane_prov_list_next(&zdplane_info.dg_providers, prov);
	}

	out = zebra_rib_dplane_results_count();
	vty_out(vty, "dataplane Outgoing Queue to Zebra: %" PRIu64 "\n", out);

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
	struct zebra_dplane_provider *p = NULL, *last, *prev = NULL;

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
	dplane_ctx_list_init(&p->dp_ctx_in_list);
	dplane_ctx_list_init(&p->dp_ctx_out_list);

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
	frr_each (dplane_prov_list, &zdplane_info.dg_providers, last) {
		if (last->dp_priority > p->dp_priority)
			break;
		prev = last;
	}

	if (last)
		dplane_prov_list_add_after(&zdplane_info.dg_providers, prev, p);
	else
		dplane_prov_list_add_tail(&zdplane_info.dg_providers, p);

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

	ctx = dplane_ctx_list_pop(&(prov->dp_ctx_in_list));

	dplane_provider_unlock(prov);

	return ctx;
}

/*
 * Dequeue work to a list, return count
 */
int dplane_provider_dequeue_in_list(struct zebra_dplane_provider *prov,
				    struct dplane_ctx_list_head *listp)
{
	int limit, ret;
	struct zebra_dplane_ctx *ctx;

	limit = zdplane_info.dg_updates_per_cycle;

	dplane_provider_lock(prov);

	for (ret = 0; ret < limit; ret++) {
		ctx = dplane_ctx_list_pop(&(prov->dp_ctx_in_list));
		if (ctx)
			dplane_ctx_list_add_tail(listp, ctx);
		else
			break;
	}

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

	dplane_ctx_list_add_tail(&(prov->dp_ctx_out_list), ctx);

	/* Maintain out-queue counters */
	curr = dplane_ctx_queue_count(&prov->dp_ctx_out_list);
	high = atomic_load_explicit(&prov->dp_out_max,
				    memory_order_relaxed);
	if (curr > high)
		atomic_store_explicit(&prov->dp_out_max, curr,
				      memory_order_relaxed);

	dplane_provider_unlock(prov);

	atomic_fetch_add_explicit(&(prov->dp_out_counter), 1,
				  memory_order_relaxed);
}

static struct zebra_dplane_ctx *
dplane_provider_dequeue_out_ctx(struct zebra_dplane_provider *prov)
{
	struct zebra_dplane_ctx *ctx;

	ctx = dplane_ctx_list_pop(&(prov->dp_ctx_out_list));
	if (!ctx)
		return NULL;

	return ctx;
}

/*
 * Accessor for provider object
 */
bool dplane_provider_is_threaded(const struct zebra_dplane_provider *prov)
{
	return CHECK_FLAG(prov->dp_flags, DPLANE_PROV_FLAG_THREADED);
}

#ifdef HAVE_NETLINK
/*
 * Callback when an OS (netlink) incoming event read is ready. This runs
 * in the dplane pthread.
 */
static void dplane_incoming_read(struct event *event)
{
	struct dplane_zns_info *zi = EVENT_ARG(event);

	kernel_dplane_read(&zi->info);

	/* Re-start read task */
	event_add_read(zdplane_info.dg_master, dplane_incoming_read, zi,
		       zi->info.sock, &zi->t_read);
}

/*
 * Callback in the dataplane pthread that requests info from the OS and
 * initiates netlink reads.
 */
static void dplane_incoming_request(struct event *event)
{
	struct dplane_zns_info *zi = EVENT_ARG(event);

	/* Start read task */
	event_add_read(zdplane_info.dg_master, dplane_incoming_read, zi,
		       zi->info.sock, &zi->t_read);

	/* Send requests */
	netlink_request_netconf(zi->info.sock);
}

/*
 * Initiate requests for existing info from the OS. This is called by the
 * main pthread, but we want all activity on the dplane netlink socket to
 * take place on the dplane pthread, so we schedule an event to accomplish
 * that.
 */
static void dplane_kernel_info_request(struct dplane_zns_info *zi)
{
	/* If we happen to encounter an enabled zns before the dplane
	 * pthread is running, we'll initiate this later on.
	 */
	if (zdplane_info.dg_master)
		event_add_event(zdplane_info.dg_master, dplane_incoming_request,
				zi, 0, &zi->t_request);
}

#endif /* HAVE_NETLINK */

/*
 * Notify dplane when namespaces are enabled and disabled. The dplane
 * needs to start and stop reading incoming events from the zns. In the
 * common case where vrfs are _not_ namespaces, there will only be one
 * of these.
 *
 * This is called in the main pthread.
 */
void zebra_dplane_ns_enable(struct zebra_ns *zns, bool enabled)
{
	struct dplane_zns_info *zi;

	if (IS_ZEBRA_DEBUG_DPLANE)
		zlog_debug("%s: %s for nsid %u", __func__,
			   (enabled ? "ENABLED" : "DISABLED"), zns->ns_id);

	/* Search for an existing zns info entry */
	frr_each (zns_info_list, &zdplane_info.dg_zns_list, zi) {
		if (zi->info.ns_id == zns->ns_id)
			break;
	}

	if (enabled) {
		/* Create a new entry if necessary; start reading. */
		if (zi == NULL) {
			zi = XCALLOC(MTYPE_DP_NS, sizeof(*zi));

			zi->info.ns_id = zns->ns_id;

			zns_info_list_add_tail(&zdplane_info.dg_zns_list, zi);

			if (IS_ZEBRA_DEBUG_DPLANE)
				zlog_debug("%s: nsid %u, new zi %p", __func__,
					   zns->ns_id, zi);
		}

		/* Make sure we're up-to-date with the zns object */
#if defined(HAVE_NETLINK)
		zi->info.is_cmd = false;
		zi->info.sock = zns->netlink_dplane_in.sock;

		/* Initiate requests for existing info from the OS, and
		 * begin reading from the netlink socket.
		 */
		dplane_kernel_info_request(zi);
#endif
	} else if (zi) {
		if (IS_ZEBRA_DEBUG_DPLANE)
			zlog_debug("%s: nsid %u, deleting zi %p", __func__,
				   zns->ns_id, zi);

		/* Stop reading, free memory */
		zns_info_list_del(&zdplane_info.dg_zns_list, zi);

		/* Stop any outstanding tasks */
		if (zdplane_info.dg_master) {
			event_cancel_async(zdplane_info.dg_master,
					   &zi->t_request, NULL);

			event_cancel_async(zdplane_info.dg_master, &zi->t_read,
					   NULL);
		}

		XFREE(MTYPE_DP_NS, zi);
	}
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
		event_add_event(zdplane_info.dg_master, dplane_thread_loop,
				NULL, 0, &zdplane_info.dg_t_update);
	}

	return AOK;
}

/*
 * Enqueue a context directly to zebra main.
 */
void dplane_provider_enqueue_to_zebra(struct zebra_dplane_ctx *ctx)
{
	struct dplane_ctx_list_head temp_list;

	/* Zebra's api takes a list, so we need to use a temporary list */
	dplane_ctx_list_init(&temp_list);

	dplane_ctx_list_add_tail(&temp_list, ctx);
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
	case DPLANE_OP_PIC_NH_INSTALL:
	case DPLANE_OP_PIC_NH_UPDATE:
	case DPLANE_OP_PIC_NH_DELETE:
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

		dplane_ctx_get_pbr_iptable(ctx, &ipt);
		zlog_debug("Dplane iptable update op %s, unique(%u), ctx %p",
			   dplane_op2str(dplane_ctx_get_op(ctx)), ipt.unique,
			   ctx);
	} break;
	case DPLANE_OP_IPSET_ADD:
	case DPLANE_OP_IPSET_DELETE: {
		struct zebra_pbr_ipset ipset;

		dplane_ctx_get_pbr_ipset(ctx, &ipset);
		zlog_debug("Dplane ipset update op %s, unique(%u), ctx %p",
			   dplane_op2str(dplane_ctx_get_op(ctx)), ipset.unique,
			   ctx);
	} break;
	case DPLANE_OP_IPSET_ENTRY_ADD:
	case DPLANE_OP_IPSET_ENTRY_DELETE: {
		struct zebra_pbr_ipset_entry ipent;

		dplane_ctx_get_pbr_ipset_entry(ctx, &ipent);
		zlog_debug(
			"Dplane ipset entry update op %s, unique(%u), ctx %p",
			dplane_op2str(dplane_ctx_get_op(ctx)), ipent.unique,
			ctx);
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

	case DPLANE_OP_INTF_ADDR_ADD:
	case DPLANE_OP_INTF_ADDR_DEL:
		zlog_debug("Dplane incoming op %s, intf %s, addr %pFX",
			   dplane_op2str(dplane_ctx_get_op(ctx)),
			   dplane_ctx_get_ifname(ctx),
			   dplane_ctx_get_intf_addr(ctx));
		break;

	case DPLANE_OP_INTF_NETCONFIG:
		zlog_debug("%s: ifindex %d, mpls %d, mcast %d",
			   dplane_op2str(dplane_ctx_get_op(ctx)),
			   dplane_ctx_get_ifindex(ctx),
			   dplane_ctx_get_netconf_mpls(ctx),
			   dplane_ctx_get_netconf_mcast(ctx));
		break;

	case DPLANE_OP_INTF_INSTALL:
	case DPLANE_OP_INTF_UPDATE:
	case DPLANE_OP_INTF_DELETE:
		zlog_debug("Dplane intf %s, idx %u, protodown %d",
			   dplane_op2str(dplane_ctx_get_op(ctx)),
			   dplane_ctx_get_ifindex(ctx),
			   dplane_ctx_intf_is_protodown(ctx));
		break;

	/* TODO: more detailed log */
	case DPLANE_OP_TC_QDISC_INSTALL:
	case DPLANE_OP_TC_QDISC_UNINSTALL:
		zlog_debug("Dplane tc qdisc ifidx %u",
			   dplane_ctx_get_ifindex(ctx));
		break;
	case DPLANE_OP_TC_CLASS_ADD:
	case DPLANE_OP_TC_CLASS_DELETE:
	case DPLANE_OP_TC_CLASS_UPDATE:
		break;
	case DPLANE_OP_TC_FILTER_ADD:
	case DPLANE_OP_TC_FILTER_DELETE:
	case DPLANE_OP_TC_FILTER_UPDATE:
	case DPLANE_OP_STARTUP_STAGE:
		break;

	case DPLANE_OP_SRV6_ENCAP_SRCADDR_SET:
		zlog_debug("Dplane SRv6 encap source address set op %s, addr %pI6",
			   dplane_op2str(dplane_ctx_get_op(ctx)),
			   &ctx->u.srv6_encap.srcaddr);
		break;

	case DPLANE_OP_VLAN_INSTALL:
		zlog_debug("Dplane %s on idx %u",
			   dplane_op2str(dplane_ctx_get_op(ctx)),
			   dplane_ctx_get_vlan_ifindex(ctx));
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
	case DPLANE_OP_PIC_NH_INSTALL:
	case DPLANE_OP_PIC_NH_UPDATE:
	case DPLANE_OP_PIC_NH_DELETE:
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

	case DPLANE_OP_INTF_INSTALL:
	case DPLANE_OP_INTF_UPDATE:
	case DPLANE_OP_INTF_DELETE:
		if (res != ZEBRA_DPLANE_REQUEST_SUCCESS)
			atomic_fetch_add_explicit(&zdplane_info.dg_intf_errors,
						  1, memory_order_relaxed);
		break;

	case DPLANE_OP_TC_QDISC_INSTALL:
	case DPLANE_OP_TC_QDISC_UNINSTALL:
	case DPLANE_OP_TC_CLASS_ADD:
	case DPLANE_OP_TC_CLASS_DELETE:
	case DPLANE_OP_TC_CLASS_UPDATE:
	case DPLANE_OP_TC_FILTER_ADD:
	case DPLANE_OP_TC_FILTER_DELETE:
	case DPLANE_OP_TC_FILTER_UPDATE:
		if (res != ZEBRA_DPLANE_REQUEST_SUCCESS)
			atomic_fetch_add_explicit(&zdplane_info.dg_tcs_errors,
						  1, memory_order_relaxed);
		break;

	/* Ignore 'notifications' - no-op */
	case DPLANE_OP_SYS_ROUTE_ADD:
	case DPLANE_OP_SYS_ROUTE_DELETE:
	case DPLANE_OP_ROUTE_NOTIFY:
	case DPLANE_OP_LSP_NOTIFY:
	case DPLANE_OP_BR_PORT_UPDATE:
		break;

	/* TODO -- error counters for incoming events? */
	case DPLANE_OP_INTF_ADDR_ADD:
	case DPLANE_OP_INTF_ADDR_DEL:
	case DPLANE_OP_INTF_NETCONFIG:
	case DPLANE_OP_VLAN_INSTALL:
		break;

	case DPLANE_OP_SRV6_ENCAP_SRCADDR_SET:
		if (res != ZEBRA_DPLANE_REQUEST_SUCCESS)
			atomic_fetch_add_explicit(&zdplane_info
							   .dg_srv6_encap_srcaddr_set_errors,
						  1, memory_order_relaxed);
		break;

	case DPLANE_OP_NONE:
	case DPLANE_OP_STARTUP_STAGE:
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

void dplane_rib_add_multipath(afi_t afi, safi_t safi, struct prefix *p,
			      struct prefix_ipv6 *src_p, struct route_entry *re,
			      struct nexthop_group *ng, int startup,
			      struct zebra_dplane_ctx *ctx)
{
	if (!ctx)
		rib_add_multipath(afi, safi, p, src_p, re, ng, startup);
	else {
		dplane_ctx_route_init_basic(ctx, dplane_ctx_get_op(ctx), re, p,
					    src_p, afi, safi);
		dplane_provider_enqueue_to_zebra(ctx);
	}
}

/*
 * Kernel provider callback
 */
static int kernel_dplane_process_func(struct zebra_dplane_provider *prov)
{
	struct zebra_dplane_ctx *ctx;
	struct dplane_ctx_list_head work_list;
	int counter, limit;

	dplane_ctx_list_init(&work_list);

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
			dplane_ctx_list_add_tail(&work_list, ctx);
	}

	kernel_update_multi(&work_list);

	while ((ctx = dplane_ctx_list_pop(&work_list)) != NULL) {
		kernel_dplane_handle_result(ctx);

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

static int kernel_dplane_shutdown_func(struct zebra_dplane_provider *prov,
				       bool early)
{
	struct zebra_dplane_ctx *ctx;

	if (early)
		return 1;

	ctx = dplane_provider_dequeue_in_ctx(prov);
	while (ctx) {
		dplane_ctx_free(&ctx);

		ctx = dplane_provider_dequeue_in_ctx(prov);
	}

	ctx = dplane_provider_dequeue_out_ctx(prov);
	while (ctx) {
		dplane_ctx_free(&ctx);

		ctx = dplane_provider_dequeue_out_ctx(prov);
	}

	return 1;
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

	ret = dplane_provider_register("Kernel", DPLANE_PRIO_KERNEL,
				       DPLANE_PROV_FLAGS_DEFAULT, NULL,
				       kernel_dplane_process_func,
				       kernel_dplane_shutdown_func, NULL, NULL);

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
	struct zebra_dplane_ctx *ctx;
	struct dplane_ctx_list_head work_list;

	dplane_ctx_list_init(&work_list);

	if (context_cb == NULL)
		return AOK;

	/* Walk the pending context queue under the dplane lock. */
	DPLANE_LOCK();

	frr_each_safe (dplane_ctx_list, &zdplane_info.dg_update_list, ctx) {
		if (context_cb(ctx, val)) {
			dplane_ctx_list_del(&zdplane_info.dg_update_list, ctx);
			dplane_ctx_list_add_tail(&work_list, ctx);
		}
	}

	DPLANE_UNLOCK();

	/* Now free any contexts selected by the caller, without holding
	 * the lock.
	 */
	while ((ctx = dplane_ctx_list_pop(&work_list)) != NULL)
		dplane_ctx_fini(&ctx);

	return AOK;
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
	frr_each (dplane_prov_list, &zdplane_info.dg_providers, prov) {
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
		ctx = dplane_ctx_list_first(&zdplane_info.dg_update_list);
		prov = dplane_prov_list_first(&zdplane_info.dg_providers);
	}
	DPLANE_UNLOCK();

	if (ctx != NULL)
		return true;

	while (prov) {

		dplane_provider_lock(prov);

		ctx = dplane_ctx_list_first(&(prov->dp_ctx_in_list));
		if (ctx == NULL)
			ctx = dplane_ctx_list_first(&(prov->dp_ctx_out_list));

		dplane_provider_unlock(prov);

		if (ctx != NULL)
			break;

		prov = dplane_prov_list_next(&zdplane_info.dg_providers, prov);
	}

	if (ctx != NULL)
		ret = true;

	return ret;
}

/*
 * Shutdown-time intermediate callback, used to determine when all pending
 * in-flight updates are done. If there's still work to do, reschedules itself.
 * If all work is done, schedules an event to the main zebra thread for
 * final zebra shutdown.
 * This runs in the dplane pthread context.
 */
static void dplane_check_shutdown_status(struct event *event)
{
	struct dplane_zns_info *zi;

	if (IS_ZEBRA_DEBUG_DPLANE)
		zlog_debug("Zebra dataplane shutdown status check called");

	/* Remove any zns info entries as we stop the dplane pthread. */
	frr_each_safe (zns_info_list, &zdplane_info.dg_zns_list, zi) {
		zns_info_list_del(&zdplane_info.dg_zns_list, zi);

		if (zdplane_info.dg_master) {
			EVENT_OFF(zi->t_read);
			EVENT_OFF(zi->t_request);
		}

		XFREE(MTYPE_DP_NS, zi);
	}

	if (dplane_work_pending()) {
		/* Reschedule dplane check on a short timer */
		event_add_timer_msec(zdplane_info.dg_master,
				     dplane_check_shutdown_status, NULL, 100,
				     &zdplane_info.dg_t_shutdown_check);

		/* TODO - give up and stop waiting after a short time? */

	} else {
		/* We appear to be done - schedule a final callback event
		 * for the zebra main pthread.
		 */
		event_add_event(zrouter.master, zebra_finalize, NULL, 0, NULL);
	}
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

	event_add_event(zdplane_info.dg_master, dplane_check_shutdown_status,
			NULL, 0, &zdplane_info.dg_t_shutdown_check);
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
static void dplane_thread_loop(struct event *event)
{
	struct dplane_ctx_list_head work_list;
	struct dplane_ctx_list_head error_list;
	struct zebra_dplane_provider *prov, *next_prov;
	struct zebra_dplane_ctx *ctx;
	int limit, counter, error_counter;
	uint64_t curr, out_curr, high;
	bool reschedule = false;

	/* Capture work limit per cycle */
	limit = zdplane_info.dg_updates_per_cycle;

	/* Init temporary lists used to move contexts among providers */
	dplane_ctx_list_init(&work_list);
	dplane_ctx_list_init(&error_list);

	error_counter = 0;

	/* Check for zebra shutdown */
	if (!zdplane_info.dg_run)
		return;

	/* Dequeue some incoming work from zebra (if any) onto the temporary
	 * working list.
	 */
	DPLANE_LOCK();

	/* Locate initial registered provider */
	prov = dplane_prov_list_first(&zdplane_info.dg_providers);

	curr = dplane_ctx_queue_count(&prov->dp_ctx_in_list);
	out_curr = dplane_ctx_queue_count(&prov->dp_ctx_out_list);

	if (curr >= (uint64_t)limit) {
		if (IS_ZEBRA_DEBUG_DPLANE_DETAIL)
			zlog_debug("%s: Current first provider(%s) Input queue is %" PRIu64
				   ", holding off work",
				   __func__, prov->dp_name, curr);
		counter = 0;
	} else if (out_curr >= (uint64_t)limit) {
		if (IS_ZEBRA_DEBUG_DPLANE_DETAIL)
			zlog_debug("%s: Current first provider(%s) Output queue is %" PRIu64
				   ", holding off work",
				   __func__, prov->dp_name, out_curr);
		counter = 0;
	} else {
		int tlimit;
		/*
		 * Let's limit the work to how what can be put on the
		 * in or out queue without going over
		 */
		tlimit = limit - MAX(curr, out_curr);
		/* Move new work from incoming list to temp list */
		for (counter = 0; counter < tlimit; counter++) {
			ctx = dplane_ctx_list_pop(&zdplane_info.dg_update_list);
			if (ctx) {
				ctx->zd_provider = prov->dp_id;

				dplane_ctx_list_add_tail(&work_list, ctx);
			} else {
				break;
			}
		}
	}

	/*
	 * If there is anything still on the two input queues reschedule
	 */
	if (dplane_ctx_queue_count(&prov->dp_ctx_in_list) > 0 ||
	    dplane_ctx_queue_count(&zdplane_info.dg_update_list) > 0)
		reschedule = true;

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
			zlog_debug("dplane enqueues %d new work to provider '%s' curr is %" PRIu64,
				   counter, dplane_provider_get_name(prov),
				   curr);

		/* Capture current provider id in each context; check for
		 * error status.
		 */
		frr_each_safe (dplane_ctx_list, &work_list, ctx) {
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
				dplane_ctx_list_del(&work_list, ctx);
				dplane_ctx_list_add_tail(&error_list, ctx);
				error_counter++;
			}
		}

		/* Enqueue new work to the provider */
		dplane_provider_lock(prov);

		while ((ctx = dplane_ctx_list_pop(&work_list)) != NULL)
			dplane_ctx_list_add_tail(&(prov->dp_ctx_in_list), ctx);

		atomic_fetch_add_explicit(&prov->dp_in_counter, counter,
					  memory_order_relaxed);
		curr = dplane_ctx_queue_count(&prov->dp_ctx_in_list);
		high = atomic_load_explicit(&prov->dp_in_max,
					    memory_order_relaxed);
		if (curr > high)
			atomic_store_explicit(&prov->dp_in_max, curr,
					      memory_order_relaxed);

		dplane_provider_unlock(prov);

		/* Reset the temp list (though the 'concat' may have done this
		 * already), and the counter
		 */
		dplane_ctx_list_init(&work_list);
		counter = 0;

		/* Call into the provider code. Note that this is
		 * unconditional: we offer to do work even if we don't enqueue
		 * any _new_ work.
		 */
		(*prov->dp_fp)(prov);

		/* Check for zebra shutdown */
		if (!zdplane_info.dg_run)
			break;

		/* Locate next provider */
		next_prov = dplane_prov_list_next(&zdplane_info.dg_providers,
						  prov);
		if (next_prov) {
			curr = dplane_ctx_queue_count(
				&next_prov->dp_ctx_in_list);
			out_curr = dplane_ctx_queue_count(
				&next_prov->dp_ctx_out_list);
		} else
			out_curr = curr = 0;

		/* Dequeue completed work from the provider */
		dplane_provider_lock(prov);

		if (curr >= (uint64_t)limit) {
			if (IS_ZEBRA_DEBUG_DPLANE_DETAIL)
				zlog_debug("%s: Next Provider(%s) Input queue is %" PRIu64
					   ", holding off work",
					   __func__, next_prov->dp_name, curr);
			counter = 0;
		} else if (out_curr >= (uint64_t)limit) {
			if (IS_ZEBRA_DEBUG_DPLANE_DETAIL)
				zlog_debug("%s: Next Provider(%s) Output queue is %" PRIu64
					   ", holding off work",
					   __func__, next_prov->dp_name,
					   out_curr);
			counter = 0;
		} else {
			int tlimit;

			/*
			 * Let's limit the work to how what can be put on the
			 * in or out queue without going over
			 */
			tlimit = limit - MAX(curr, out_curr);
			while (counter < tlimit) {
				ctx = dplane_provider_dequeue_out_ctx(prov);
				if (ctx) {
					dplane_ctx_list_add_tail(&work_list,
								 ctx);
					counter++;
				} else
					break;
			}
		}

		/*
		 * Let's check if there are still any items on the
		 * input or output queus of the current provider
		 * if so then we know we need to reschedule.
		 */
		if (dplane_ctx_queue_count(&prov->dp_ctx_in_list) > 0 ||
		    dplane_ctx_queue_count(&prov->dp_ctx_out_list) > 0)
			reschedule = true;

		dplane_provider_unlock(prov);

		if (counter >= limit)
			reschedule = true;

		if (IS_ZEBRA_DEBUG_DPLANE_DETAIL)
			zlog_debug("dplane dequeues %d completed work from provider %s",
				   counter, dplane_provider_get_name(prov));

		if (event_should_yield(event)) {
			reschedule = true;
			break;
		}

		/* Locate next provider */
		prov = next_prov;
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

	dplane_ctx_list_init(&error_list);

	/* Call through to zebra main */
	(zdplane_info.dg_results_cb)(&work_list);

	dplane_ctx_list_init(&work_list);
}

/*
 * Final phase of shutdown, after all work enqueued to dplane has been
 * processed. This is called from the zebra main pthread context.
 */
void zebra_dplane_shutdown(void)
{
	struct zebra_dplane_provider *dp;
	struct zebra_dplane_ctx *ctx;

	if (IS_ZEBRA_DEBUG_DPLANE)
		zlog_debug("Zebra dataplane shutdown called");

	/* Stop dplane thread, if it's running */

	zdplane_info.dg_run = false;

	frr_pthread_stop(zdplane_info.dg_pthread, NULL);

	/* Destroy pthread */
	frr_pthread_destroy(zdplane_info.dg_pthread);
	zdplane_info.dg_pthread = NULL;
	zdplane_info.dg_master = NULL;

	/* Notify provider(s) of final shutdown.
	 * Note that this call is in the main pthread, so providers must
	 * be prepared for that.
	 */
	frr_each (dplane_prov_list, &zdplane_info.dg_providers, dp) {
		if (dp->dp_fini == NULL)
			continue;

		dp->dp_fini(dp, false);
	}

	/* TODO -- Clean-up provider objects */
	dp = dplane_prov_list_first(&zdplane_info.dg_providers);
	while (dp) {
		dplane_prov_list_del(&zdplane_info.dg_providers, dp);
		XFREE(MTYPE_DP_PROV, dp);

		dp = dplane_prov_list_first(&zdplane_info.dg_providers);
	}

	/* TODO -- Clean queue(s), free memory */
	DPLANE_LOCK();
	{
		ctx = dplane_ctx_list_pop(&zdplane_info.dg_update_list);
		while (ctx) {
			dplane_ctx_free(&ctx);

			ctx = dplane_ctx_list_pop(&zdplane_info.dg_update_list);
		}
	}
	DPLANE_UNLOCK();
}

/*
 * Initialize the dataplane module during startup, internal/private version
 */
static void zebra_dplane_init_internal(void)
{
	memset(&zdplane_info, 0, sizeof(zdplane_info));

	pthread_mutex_init(&zdplane_info.dg_mutex, NULL);

	dplane_prov_list_init(&zdplane_info.dg_providers);

	dplane_ctx_list_init(&zdplane_info.dg_update_list);
	zns_info_list_init(&zdplane_info.dg_zns_list);

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
	struct dplane_zns_info *zi;
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
	event_add_event(zdplane_info.dg_master, dplane_thread_loop, NULL, 0,
			&zdplane_info.dg_t_update);

	/* Enqueue requests and reads if necessary */
	frr_each (zns_info_list, &zdplane_info.dg_zns_list, zi) {
#if defined(HAVE_NETLINK)
		event_add_read(zdplane_info.dg_master, dplane_incoming_read, zi,
			       zi->info.sock, &zi->t_read);
		dplane_kernel_info_request(zi);
#endif
	}

	/* Call start callbacks for registered providers */

	DPLANE_LOCK();
	prov = dplane_prov_list_first(&zdplane_info.dg_providers);
	DPLANE_UNLOCK();

	while (prov) {

		if (prov->dp_start)
			(prov->dp_start)(prov);

		/* Locate next provider */
		prov = dplane_prov_list_next(&zdplane_info.dg_providers, prov);
	}

	frr_pthread_run(zdplane_info.dg_pthread, NULL);
}

enum zebra_dplane_startup_notifications
dplane_ctx_get_startup_spot(struct zebra_dplane_ctx *ctx)
{
	return ctx->u.spot;
}

void zebra_dplane_startup_stage(struct zebra_ns *zns,
				enum zebra_dplane_startup_notifications spot)
{
	struct zebra_dplane_ctx *ctx = dplane_ctx_alloc();

	ctx->zd_op = DPLANE_OP_STARTUP_STAGE;
	ctx->zd_status = ZEBRA_DPLANE_REQUEST_QUEUED;

	ctx->u.spot = spot;
	dplane_ctx_set_ns_id(ctx, zns->ns_id);

	dplane_provider_enqueue_to_zebra(ctx);
}
/*
 * Initialize the dataplane module at startup; called by zebra rib_init()
 */
void zebra_dplane_init(int (*results_fp)(struct dplane_ctx_list_head *))
{
	zebra_dplane_init_internal();
	zdplane_info.dg_results_cb = results_fp;
}
