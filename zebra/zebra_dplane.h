// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Zebra dataplane layer api interfaces.
 * Copyright (c) 2018 Volta Networks, Inc.
 */

#ifndef _ZEBRA_DPLANE_H
#define _ZEBRA_DPLANE_H 1

#include "lib/zebra.h"
#include "lib/prefix.h"
#include "lib/nexthop.h"
#include "lib/nexthop_group.h"
#include "lib/pbr.h"
#include "lib/vlan.h"
#include "zebra/zebra_ns.h"
#include "zebra/rib.h"
#include "zebra/zserv.h"
#include "zebra/zebra_mpls.h"
#include "zebra/zebra_nhg.h"
#include "zebra/ge_netlink.h"

#ifdef __cplusplus
extern "C" {
#endif

DECLARE_MTYPE(VLAN_CHANGE_ARR);

/* Retrieve the dataplane API version number; see libfrr.h to decode major,
 * minor, sub version values.
 * Plugins should pay attention to the major version number, at least, to
 * be able to detect API changes that may not be backward-compatible.
 */
uint32_t zebra_dplane_get_version(void);

/* Key netlink info from zebra ns */
struct zebra_dplane_info {
	ns_id_t ns_id;

#if defined(HAVE_NETLINK)
	int sock;
	int seq;
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
		zns_info->sock = zns->netlink_cmd.sock;
		zns_info->seq = zns->netlink_cmd.seq;
	} else {
		zns_info->sock = zns->netlink.sock;
		zns_info->seq = zns->netlink.seq;
	}
#endif /* NETLINK */
}

/*
 * Notify dplane when namespaces are enabled and disabled. The dplane
 * needs to start and stop reading incoming events from the ns.
 */
void zebra_dplane_ns_enable(struct zebra_ns *zns, bool enabled);

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

enum zebra_dplane_startup_notifications {
	ZEBRA_DPLANE_INTERFACES_READ,
	ZEBRA_DPLANE_TUNNELS_READ,
	ZEBRA_DPLANE_ADDRESSES_READ,
};
/*
 * API between the zebra dataplane system and the main zebra processing
 * context.
 */

/*
 * Operations that the dataplane can process.
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

	/* Pic Context update*/
	DPLANE_OP_PIC_NH_INSTALL,
	DPLANE_OP_PIC_NH_UPDATE,
	DPLANE_OP_PIC_NH_DELETE,

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

	/* Policy based routing rule update */
	DPLANE_OP_RULE_ADD,
	DPLANE_OP_RULE_DELETE,
	DPLANE_OP_RULE_UPDATE,

	/* Link layer address discovery */
	DPLANE_OP_NEIGH_DISCOVER,

	/* bridge port update */
	DPLANE_OP_BR_PORT_UPDATE,

	/* Policy based routing iptable update */
	DPLANE_OP_IPTABLE_ADD,
	DPLANE_OP_IPTABLE_DELETE,

	/* Policy based routing ipset update */
	DPLANE_OP_IPSET_ADD,
	DPLANE_OP_IPSET_DELETE,
	DPLANE_OP_IPSET_ENTRY_ADD,
	DPLANE_OP_IPSET_ENTRY_DELETE,

	/* LINK LAYER IP address update */
	DPLANE_OP_NEIGH_IP_INSTALL,
	DPLANE_OP_NEIGH_IP_DELETE,

	DPLANE_OP_NEIGH_TABLE_UPDATE,
	DPLANE_OP_GRE_SET,

	/* Incoming interface address events */
	DPLANE_OP_INTF_ADDR_ADD,
	DPLANE_OP_INTF_ADDR_DEL,

	/* Incoming interface config events */
	DPLANE_OP_INTF_NETCONFIG,

	/* Interface update */
	DPLANE_OP_INTF_INSTALL,
	DPLANE_OP_INTF_UPDATE,
	DPLANE_OP_INTF_DELETE,

	/* Traffic control */
	DPLANE_OP_TC_QDISC_INSTALL,
	DPLANE_OP_TC_QDISC_UNINSTALL,
	DPLANE_OP_TC_CLASS_ADD,
	DPLANE_OP_TC_CLASS_DELETE,
	DPLANE_OP_TC_CLASS_UPDATE,
	DPLANE_OP_TC_FILTER_ADD,
	DPLANE_OP_TC_FILTER_DELETE,
	DPLANE_OP_TC_FILTER_UPDATE,

	/* VLAN update */
	DPLANE_OP_VLAN_INSTALL,

	/* Startup Control */
	DPLANE_OP_STARTUP_STAGE,

	/* Source address for SRv6 encapsulation */
	DPLANE_OP_SRV6_ENCAP_SRCADDR_SET,
};

/* Operational status of Bridge Ports */
#define ZEBRA_DPLANE_BR_STATE_DISABLED	 0x01
#define ZEBRA_DPLANE_BR_STATE_LISTENING	 0x02
#define ZEBRA_DPLANE_BR_STATE_LEARNING	 0x04
#define ZEBRA_DPLANE_BR_STATE_FORWARDING 0x08
#define ZEBRA_DPLANE_BR_STATE_BLOCKING	 0x10

/*
 * The vxlan/evpn neighbor management code needs some values to use
 * when programming neighbor changes. Offer some platform-neutral values
 * here for use within the dplane apis and plugins.
 */

/* Neighbor cache flags */
#define DPLANE_NTF_EXT_LEARNED    0x01
#define DPLANE_NTF_ROUTER         0x02
#define DPLANE_NTF_USE            0x04

/* Neighbor cache states */
#define DPLANE_NUD_REACHABLE      0x01
#define DPLANE_NUD_STALE          0x02
#define DPLANE_NUD_NOARP          0x04
#define DPLANE_NUD_PROBE          0x08
#define DPLANE_NUD_INCOMPLETE     0x10
#define DPLANE_NUD_PERMANENT      0x20
#define DPLANE_NUD_FAILED         0x40

/* MAC update flags - dplane_mac_info.update_flags */
#define DPLANE_MAC_REMOTE       (1 << 0)
#define DPLANE_MAC_WAS_STATIC   (1 << 1)
#define DPLANE_MAC_SET_STATIC   (1 << 2)
#define DPLANE_MAC_SET_INACTIVE (1 << 3)

/* Neigh update flags - dplane_neigh_info.update_flags */
#define DPLANE_NEIGH_REMOTE       (1 << 0)
#define DPLANE_NEIGH_WAS_STATIC   (1 << 1)
#define DPLANE_NEIGH_SET_STATIC   (1 << 2)
#define DPLANE_NEIGH_SET_INACTIVE (1 << 3)
#define DPLANE_NEIGH_NO_EXTENSION (1 << 4)

#define DPLANE_BR_PORT_NON_DF (1 << 0)

/* Definitions for the dplane 'netconf' apis, corresponding to the netlink
 * NETCONF api.
 * Sadly, netlink sends incremental updates, so its messages may contain
 * just a single changed attribute, and not necessarily
 * a complete snapshot of the attributes.
 */
enum dplane_netconf_status_e {
	DPLANE_NETCONF_STATUS_UNKNOWN = 0,
	DPLANE_NETCONF_STATUS_ENABLED,
	DPLANE_NETCONF_STATUS_DISABLED
};

/* Some special ifindex values that may be part of the dplane netconf api. */
#define DPLANE_NETCONF_IFINDEX_ALL     -1
#define DPLANE_NETCONF_IFINDEX_DEFAULT -2

/* Enable system route notifications */
void dplane_enable_sys_route_notifs(void);

/*
 * The dataplane context struct is used to exchange info between the main zebra
 * context and the dataplane module(s). If these are two independent pthreads,
 * they cannot share existing global data structures safely.
 */

/* Define a list type for context blocks. The list is exposed/public,
 * but the internal linkage in the context struct is private, so there
 * are accessor apis that support enqueue and dequeue.
 */

PREDECL_DLIST(dplane_ctx_list);

/* Declare a type for (optional) extended interface info objects. */
PREDECL_DLIST(dplane_intf_extra_list);

/* Allocate a context object */
struct zebra_dplane_ctx *dplane_ctx_alloc(void);

/*
 * Reset an allocated context object for re-use. All internal allocations are
 * freed.
 */
void dplane_ctx_reset(struct zebra_dplane_ctx *ctx);

/*
 * Allow zebra code to walk the queue of pending contexts, evaluate each one
 * using a callback function. The caller can supply an optional void* arg also.
 * If the function returns 'true', the context will be dequeued and freed
 * without being processed.
 */
int dplane_clean_ctx_queue(bool (*context_cb)(struct zebra_dplane_ctx *ctx,
					      void *arg), void *val);

/* Return a dataplane results context block after use; the caller's pointer will
 * be cleared.
 */
void dplane_ctx_fini(struct zebra_dplane_ctx **pctx);

/* Enqueue a context block to caller's tailq. This exists so that the
 * context struct can remain opaque.
 */
void dplane_ctx_enqueue_tail(struct dplane_ctx_list_head *q,
			     const struct zebra_dplane_ctx *ctx);

/* Append a list of context blocks to another list - again, just keeping
 * the context struct opaque.
 */
void dplane_ctx_list_append(struct dplane_ctx_list_head *to_list,
			    struct dplane_ctx_list_head *from_list);

/* Dequeue a context block from the head of caller's tailq */
struct zebra_dplane_ctx *dplane_ctx_dequeue(struct dplane_ctx_list_head *q);
struct zebra_dplane_ctx *dplane_ctx_get_head(struct dplane_ctx_list_head *q);

/* Init a list of contexts */
void dplane_ctx_q_init(struct dplane_ctx_list_head *q);

uint32_t dplane_ctx_queue_count(struct dplane_ctx_list_head *q);

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
void dplane_ctx_set_ifname(struct zebra_dplane_ctx *ctx, const char *ifname);
ifindex_t dplane_ctx_get_ifindex(const struct zebra_dplane_ctx *ctx);
void dplane_ctx_set_ifindex(struct zebra_dplane_ctx *ctx, ifindex_t ifindex);
void dplane_ctx_set_ifp_bond_ifindex(struct zebra_dplane_ctx *ctx,
				     ifindex_t ifindex);
ifindex_t dplane_ctx_get_ifp_bond_ifindex(const struct zebra_dplane_ctx *ctx);
enum zebra_iftype
dplane_ctx_get_ifp_zif_type(const struct zebra_dplane_ctx *ctx);
void dplane_ctx_set_ifp_zif_type(struct zebra_dplane_ctx *ctx,
				 enum zebra_iftype zif_type);
void dplane_ctx_set_ifp_table_id(struct zebra_dplane_ctx *ctx,
				 uint32_t table_id);
uint32_t dplane_ctx_get_ifp_table_id(const struct zebra_dplane_ctx *ctx);
void dplane_ctx_set_ifp_hw_addr(struct zebra_dplane_ctx *ctx,
				int32_t hw_addr_len, uint8_t *hw_addr);
int32_t dplane_ctx_get_ifp_hw_addr_len(const struct zebra_dplane_ctx *ctx);
const uint8_t *dplane_ctx_get_ifp_hw_addr(const struct zebra_dplane_ctx *ctx);
struct zebra_l2info_bridge;
void dplane_ctx_set_ifp_bridge_info(struct zebra_dplane_ctx *ctx,
				    struct zebra_l2info_bridge *binfo);
const struct zebra_l2info_bridge *
dplane_ctx_get_ifp_bridge_info(const struct zebra_dplane_ctx *ctx);
struct zebra_l2info_vlan;
void dplane_ctx_set_ifp_vlan_info(struct zebra_dplane_ctx *ctx,
				  struct zebra_l2info_vlan *vinfo);
const struct zebra_l2info_vlan *
dplane_ctx_get_ifp_vlan_info(const struct zebra_dplane_ctx *ctx);
struct zebra_l2info_vxlan;
void dplane_ctx_set_ifp_vxlan_info(struct zebra_dplane_ctx *ctx,
				   struct zebra_l2info_vxlan *vxinfo);
const struct zebra_l2info_vxlan *
dplane_ctx_get_ifp_vxlan_info(const struct zebra_dplane_ctx *ctx);
struct zebra_l2info_gre;
void dplane_ctx_set_ifp_gre_info(struct zebra_dplane_ctx *ctx,
				 struct zebra_l2info_gre *greinfo);
const struct zebra_l2info_gre *
dplane_ctx_get_ifp_gre_info(const struct zebra_dplane_ctx *ctx);
void dplane_ctx_set_ifp_zltype(struct zebra_dplane_ctx *ctx,
			       enum zebra_link_type zlt);
enum zebra_link_type
dplane_ctx_get_ifp_zltype(const struct zebra_dplane_ctx *ctx);
void dplane_ctx_set_ifp_link_nsid(struct zebra_dplane_ctx *ctx, ns_id_t ns_id);
ns_id_t dplane_ctx_get_ifp_link_nsid(const struct zebra_dplane_ctx *ctx);
void dplane_ctx_set_ifp_desc(struct zebra_dplane_ctx *ctx, const char *desc);
char *dplane_ctx_get_ifp_desc(struct zebra_dplane_ctx *ctx);
void dplane_ctx_set_ifp_mtu(struct zebra_dplane_ctx *ctx, uint32_t mtu);
uint32_t dplane_ctx_get_ifp_mtu(const struct zebra_dplane_ctx *ctx);
void dplane_ctx_set_ifp_vrf_id(struct zebra_dplane_ctx *ctx, vrf_id_t vrf_id);
vrf_id_t dplane_ctx_get_ifp_vrf_id(const struct zebra_dplane_ctx *ctx);
enum zebra_slave_iftype;
void dplane_ctx_set_ifp_zif_slave_type(struct zebra_dplane_ctx *ctx,
				       enum zebra_slave_iftype zslave_type);
enum zebra_slave_iftype
dplane_ctx_get_ifp_zif_slave_type(const struct zebra_dplane_ctx *ctx);
void dplane_ctx_set_ifp_master_ifindex(struct zebra_dplane_ctx *ctx,
				       ifindex_t master_ifindex);
ifindex_t dplane_ctx_get_ifp_master_ifindex(const struct zebra_dplane_ctx *ctx);
void dplane_ctx_set_ifp_bridge_ifindex(struct zebra_dplane_ctx *ctx,
				       ifindex_t bridge_ifindex);
ifindex_t dplane_ctx_get_ifp_bridge_ifindex(const struct zebra_dplane_ctx *ctx);
void dplane_ctx_set_ifp_bypass(struct zebra_dplane_ctx *ctx, uint8_t bypass);
uint8_t dplane_ctx_get_ifp_bypass(const struct zebra_dplane_ctx *ctx);
void dplane_ctx_set_ifp_flags(struct zebra_dplane_ctx *ctx, uint64_t flags);
uint64_t dplane_ctx_get_ifp_flags(const struct zebra_dplane_ctx *ctx);
void dplane_ctx_set_ifp_protodown(struct zebra_dplane_ctx *ctx, bool protodown);
bool dplane_ctx_get_ifp_protodown(const struct zebra_dplane_ctx *ctx);
void dplane_ctx_set_ifp_startup(struct zebra_dplane_ctx *ctx, bool startup);
bool dplane_ctx_get_ifp_startup(const struct zebra_dplane_ctx *ctx);
void dplane_ctx_set_ifp_protodown_set(struct zebra_dplane_ctx *ctx, bool set);
bool dplane_ctx_get_ifp_protodown_set(const struct zebra_dplane_ctx *ctx);
void dplane_ctx_set_ifp_rc_bitfield(struct zebra_dplane_ctx *ctx,
				    uint32_t rc_bitfield);
uint32_t dplane_ctx_get_ifp_rc_bitfield(const struct zebra_dplane_ctx *ctx);
void dplane_ctx_set_ifp_link_ifindex(struct zebra_dplane_ctx *ctx,
				     ifindex_t link_ifindex);
ifindex_t dplane_ctx_get_ifp_link_ifindex(const struct zebra_dplane_ctx *ctx);
void dplane_ctx_set_ifp_family(struct zebra_dplane_ctx *ctx, uint8_t family);
uint8_t dplane_ctx_get_ifp_family(const struct zebra_dplane_ctx *ctx);
struct zebra_vxlan_vni_array;
void dplane_ctx_set_ifp_vxlan_vni_array(struct zebra_dplane_ctx *ctx,
					struct zebra_vxlan_vni_array *vniarray);

/*
 * These defines mirror the values for bridge values in linux
 * at this point since we only have a linux implementation
 * we don't need to do any type of translation.  Let's just
 * pass these through and use them
 */
#define DPLANE_BRIDGE_VLAN_INFO_PVID                                           \
	(1 << 1) /* VLAN is PVID, ingress untagged */
#define DPLANE_BRIDGE_VLAN_INFO_RANGE_BEGIN                                    \
	(1 << 3) /* VLAN is start of vlan range */
#define DPLANE_BRIDGE_VLAN_INFO_RANGE_END                                      \
	(1 << 4) /* VLAN is end of vlan range */
const struct zebra_vxlan_vni_array *
dplane_ctx_get_ifp_vxlan_vni_array(const struct zebra_dplane_ctx *ctx);
struct zebra_dplane_bridge_vlan_info {
	uint16_t flags;
	uint16_t vid;
};
void dplane_ctx_set_ifp_no_afspec(struct zebra_dplane_ctx *ctx);
bool dplane_ctx_get_ifp_no_afspec(const struct zebra_dplane_ctx *ctx);
void dplane_ctx_set_ifp_no_bridge_vlan_info(struct zebra_dplane_ctx *ctx);
bool dplane_ctx_get_ifp_no_bridge_vlan_info(struct zebra_dplane_ctx *ctx);
void dplane_ctx_set_ifp_bridge_vlan_info(
	struct zebra_dplane_ctx *ctx,
	struct zebra_dplane_bridge_vlan_info *bvinfo);
const struct zebra_dplane_bridge_vlan_info *
dplane_ctx_get_ifp_bridge_vlan_info(const struct zebra_dplane_ctx *ctx);

struct zebra_dplane_bridge_vlan_info_array {
	int count;
	struct zebra_dplane_bridge_vlan_info array[0];
};
void dplane_ctx_set_ifp_bridge_vlan_info_array(
	struct zebra_dplane_ctx *ctx,
	struct zebra_dplane_bridge_vlan_info_array *bvarray);
const struct zebra_dplane_bridge_vlan_info_array *
dplane_ctx_get_ifp_bridge_vlan_info_array(const struct zebra_dplane_ctx *ctx);

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

/* In some paths we have only a namespace id */
void dplane_ctx_set_ns_id(struct zebra_dplane_ctx *ctx, ns_id_t nsid);
ns_id_t dplane_ctx_get_ns_id(const struct zebra_dplane_ctx *ctx);

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
uint32_t dplane_ctx_get_flags(const struct zebra_dplane_ctx *ctx);
void dplane_ctx_set_flags(struct zebra_dplane_ctx *ctx, uint32_t flags);
uint32_t dplane_ctx_get_metric(const struct zebra_dplane_ctx *ctx);
uint32_t dplane_ctx_get_old_metric(const struct zebra_dplane_ctx *ctx);
uint32_t dplane_ctx_get_mtu(const struct zebra_dplane_ctx *ctx);
uint32_t dplane_ctx_get_nh_mtu(const struct zebra_dplane_ctx *ctx);
uint8_t dplane_ctx_get_distance(const struct zebra_dplane_ctx *ctx);
void dplane_ctx_set_distance(struct zebra_dplane_ctx *ctx, uint8_t distance);
uint8_t dplane_ctx_get_old_distance(const struct zebra_dplane_ctx *ctx);

/* Accessors for traffic control context */
int dplane_ctx_tc_qdisc_get_kind(const struct zebra_dplane_ctx *ctx);
const char *
dplane_ctx_tc_qdisc_get_kind_str(const struct zebra_dplane_ctx *ctx);

uint32_t dplane_ctx_tc_class_get_handle(const struct zebra_dplane_ctx *ctx);
int dplane_ctx_tc_class_get_kind(const struct zebra_dplane_ctx *ctx);
const char *
dplane_ctx_tc_class_get_kind_str(const struct zebra_dplane_ctx *ctx);
uint64_t dplane_ctx_tc_class_get_rate(const struct zebra_dplane_ctx *ctx);
uint64_t dplane_ctx_tc_class_get_ceil(const struct zebra_dplane_ctx *ctx);

int dplane_ctx_tc_filter_get_kind(const struct zebra_dplane_ctx *ctx);
const char *
dplane_ctx_tc_filter_get_kind_str(const struct zebra_dplane_ctx *ctx);
uint32_t dplane_ctx_tc_filter_get_priority(const struct zebra_dplane_ctx *ctx);
uint32_t dplane_ctx_tc_filter_get_handle(const struct zebra_dplane_ctx *ctx);
uint16_t dplane_ctx_tc_filter_get_minor(const struct zebra_dplane_ctx *ctx);
uint16_t dplane_ctx_tc_filter_get_eth_proto(const struct zebra_dplane_ctx *ctx);
uint32_t dplane_ctx_tc_filter_get_filter_bm(const struct zebra_dplane_ctx *ctx);
const struct prefix *
dplane_ctx_tc_filter_get_src_ip(const struct zebra_dplane_ctx *ctx);
uint16_t
dplane_ctx_tc_filter_get_src_port_min(const struct zebra_dplane_ctx *ctx);
uint16_t
dplane_ctx_tc_filter_get_src_port_max(const struct zebra_dplane_ctx *ctx);
const struct prefix *
dplane_ctx_tc_filter_get_dst_ip(const struct zebra_dplane_ctx *ctx);
uint16_t
dplane_ctx_tc_filter_get_dst_port_min(const struct zebra_dplane_ctx *ctx);
uint16_t
dplane_ctx_tc_filter_get_dst_port_max(const struct zebra_dplane_ctx *ctx);
uint8_t dplane_ctx_tc_filter_get_ip_proto(const struct zebra_dplane_ctx *ctx);
uint8_t dplane_ctx_tc_filter_get_dsfield(const struct zebra_dplane_ctx *ctx);
uint8_t
dplane_ctx_tc_filter_get_dsfield_mask(const struct zebra_dplane_ctx *ctx);
uint32_t dplane_ctx_tc_filter_get_classid(const struct zebra_dplane_ctx *ctx);

void dplane_ctx_set_nexthops(struct zebra_dplane_ctx *ctx, struct nexthop *nh);
void dplane_ctx_set_backup_nhg(struct zebra_dplane_ctx *ctx,
			       const struct nexthop_group *nhg);

uint32_t dplane_ctx_get_nhg_id(const struct zebra_dplane_ctx *ctx);
const struct nexthop_group *dplane_ctx_get_ng(
	const struct zebra_dplane_ctx *ctx);
const struct nexthop_group *dplane_ctx_get_old_ng(
	const struct zebra_dplane_ctx *ctx);

/* Optional extra info about interfaces in nexthops - a plugin must enable
 * this extra info.
 */
const struct dplane_intf_extra *
dplane_ctx_get_intf_extra(const struct zebra_dplane_ctx *ctx);

const struct dplane_intf_extra *
dplane_ctx_intf_extra_next(const struct zebra_dplane_ctx *ctx,
			   const struct dplane_intf_extra *ptr);

vrf_id_t dplane_intf_extra_get_vrfid(const struct dplane_intf_extra *ptr);
uint32_t dplane_intf_extra_get_ifindex(const struct dplane_intf_extra *ptr);
uint32_t dplane_intf_extra_get_flags(const struct dplane_intf_extra *ptr);
uint32_t dplane_intf_extra_get_status(const struct dplane_intf_extra *ptr);

/* Backup nexthop information (list of nexthops) if present. */
const struct nexthop_group *
dplane_ctx_get_backup_ng(const struct zebra_dplane_ctx *ctx);
const struct nexthop_group *
dplane_ctx_get_old_backup_ng(const struct zebra_dplane_ctx *ctx);

/* Accessors for nexthop information */
uint32_t dplane_ctx_get_nhe_id(const struct zebra_dplane_ctx *ctx);
uint32_t dplane_ctx_get_pic_nhe_id(const struct zebra_dplane_ctx *ctx);
uint32_t dplane_ctx_get_old_nhe_id(const struct zebra_dplane_ctx *ctx);
afi_t dplane_ctx_get_nhe_afi(const struct zebra_dplane_ctx *ctx);
vrf_id_t dplane_ctx_get_nhe_vrf_id(const struct zebra_dplane_ctx *ctx);
int dplane_ctx_get_nhe_type(const struct zebra_dplane_ctx *ctx);
const struct nexthop_group *
dplane_ctx_get_nhe_ng(const struct zebra_dplane_ctx *ctx);
const struct nh_grp *
dplane_ctx_get_nhe_nh_grp(const struct zebra_dplane_ctx *ctx);
uint16_t dplane_ctx_get_nhe_nh_grp_count(const struct zebra_dplane_ctx *ctx);

/* Accessors for LSP information */

/* Init the internal LSP data struct - necessary before adding to it.
 * If 'lsp' is non-NULL, info will be copied from it to the internal
 * context data area.
 */
int dplane_ctx_lsp_init(struct zebra_dplane_ctx *ctx, enum dplane_op_e op,
			struct zebra_lsp *lsp);

mpls_label_t dplane_ctx_get_in_label(const struct zebra_dplane_ctx *ctx);
void dplane_ctx_set_in_label(struct zebra_dplane_ctx *ctx,
			     mpls_label_t label);
uint8_t dplane_ctx_get_addr_family(const struct zebra_dplane_ctx *ctx);
void dplane_ctx_set_addr_family(struct zebra_dplane_ctx *ctx,
				uint8_t family);
uint32_t dplane_ctx_get_lsp_flags(const struct zebra_dplane_ctx *ctx);
void dplane_ctx_set_lsp_flags(struct zebra_dplane_ctx *ctx,
			      uint32_t flags);
const struct nhlfe_list_head *dplane_ctx_get_nhlfe_list(
	const struct zebra_dplane_ctx *ctx);
const struct nhlfe_list_head *dplane_ctx_get_backup_nhlfe_list(
	const struct zebra_dplane_ctx *ctx);

struct zebra_nhlfe *dplane_ctx_add_nhlfe(struct zebra_dplane_ctx *ctx,
					 enum lsp_types_t lsp_type,
					 enum nexthop_types_t nh_type,
					 const union g_addr *gate,
					 ifindex_t ifindex, uint8_t num_labels,
					 mpls_label_t *out_labels);

struct zebra_nhlfe *dplane_ctx_add_backup_nhlfe(
	struct zebra_dplane_ctx *ctx, enum lsp_types_t lsp_type,
	enum nexthop_types_t nh_type, const union g_addr *gate,
	ifindex_t ifindex, uint8_t num_labels, mpls_label_t *out_labels);

const struct zebra_nhlfe *
dplane_ctx_get_best_nhlfe(const struct zebra_dplane_ctx *ctx);
const struct zebra_nhlfe *
dplane_ctx_set_best_nhlfe(struct zebra_dplane_ctx *ctx,
			  struct zebra_nhlfe *nhlfe);
uint32_t dplane_ctx_get_lsp_num_ecmp(const struct zebra_dplane_ctx *ctx);

/* Accessors for pseudowire information */
mpls_label_t dplane_ctx_get_pw_local_label(const struct zebra_dplane_ctx *ctx);
mpls_label_t dplane_ctx_get_pw_remote_label(const struct zebra_dplane_ctx *ctx);
int dplane_ctx_get_pw_type(const struct zebra_dplane_ctx *ctx);
int dplane_ctx_get_pw_af(const struct zebra_dplane_ctx *ctx);
uint32_t dplane_ctx_get_pw_flags(const struct zebra_dplane_ctx *ctx);
int dplane_ctx_get_pw_status(const struct zebra_dplane_ctx *ctx);
void dplane_ctx_set_pw_status(struct zebra_dplane_ctx *ctx, int status);
const union g_addr *dplane_ctx_get_pw_dest(
	const struct zebra_dplane_ctx *ctx);
const union pw_protocol_fields *dplane_ctx_get_pw_proto(
	const struct zebra_dplane_ctx *ctx);
const struct nexthop_group *dplane_ctx_get_pw_nhg(
	const struct zebra_dplane_ctx *ctx);
const struct nexthop_group *
dplane_ctx_get_pw_primary_nhg(const struct zebra_dplane_ctx *ctx);
const struct nexthop_group *
dplane_ctx_get_pw_backup_nhg(const struct zebra_dplane_ctx *ctx);

/* Accessors for interface information */
uint32_t dplane_ctx_get_intf_metric(const struct zebra_dplane_ctx *ctx);
void dplane_ctx_set_intf_metric(struct zebra_dplane_ctx *ctx, uint32_t metric);
uint32_t dplane_ctx_get_intf_pd_reason_val(const struct zebra_dplane_ctx *ctx);
void dplane_ctx_set_intf_pd_reason_val(struct zebra_dplane_ctx *ctx, bool val);
bool dplane_ctx_intf_is_protodown(const struct zebra_dplane_ctx *ctx);
/* Is interface addr p2p? */
bool dplane_ctx_intf_is_connected(const struct zebra_dplane_ctx *ctx);
void dplane_ctx_intf_set_connected(struct zebra_dplane_ctx *ctx);
bool dplane_ctx_intf_is_secondary(const struct zebra_dplane_ctx *ctx);
void dplane_ctx_intf_set_secondary(struct zebra_dplane_ctx *ctx);
bool dplane_ctx_intf_is_noprefixroute(const struct zebra_dplane_ctx *ctx);
void dplane_ctx_intf_set_noprefixroute(struct zebra_dplane_ctx *ctx);
bool dplane_ctx_intf_is_broadcast(const struct zebra_dplane_ctx *ctx);
void dplane_ctx_intf_set_broadcast(struct zebra_dplane_ctx *ctx);
const struct prefix *dplane_ctx_get_intf_addr(
	const struct zebra_dplane_ctx *ctx);
const struct in6_addr *
dplane_ctx_get_srv6_encap_srcaddr(const struct zebra_dplane_ctx *ctx);
void dplane_ctx_set_intf_addr(struct zebra_dplane_ctx *ctx,
			      const struct prefix *p);
bool dplane_ctx_intf_has_dest(const struct zebra_dplane_ctx *ctx);
const struct prefix *dplane_ctx_get_intf_dest(
	const struct zebra_dplane_ctx *ctx);
void dplane_ctx_set_intf_dest(struct zebra_dplane_ctx *ctx,
			      const struct prefix *p);
bool dplane_ctx_intf_has_label(const struct zebra_dplane_ctx *ctx);
const char *dplane_ctx_get_intf_label(const struct zebra_dplane_ctx *ctx);
void dplane_ctx_set_intf_label(struct zebra_dplane_ctx *ctx, const char *label);
void dplane_ctx_set_intf_txqlen(struct zebra_dplane_ctx *ctx, uint32_t txqlen);
uint32_t dplane_ctx_get_intf_txqlen(const struct zebra_dplane_ctx *ctx);

/* Accessors for MAC information */
vlanid_t dplane_ctx_mac_get_vlan(const struct zebra_dplane_ctx *ctx);
bool dplane_ctx_mac_is_sticky(const struct zebra_dplane_ctx *ctx);
uint32_t dplane_ctx_mac_get_update_flags(const struct zebra_dplane_ctx *ctx);
uint32_t dplane_ctx_mac_get_nhg_id(const struct zebra_dplane_ctx *ctx);
const struct ethaddr *dplane_ctx_mac_get_addr(
	const struct zebra_dplane_ctx *ctx);
vni_t dplane_ctx_mac_get_vni(const struct zebra_dplane_ctx *ctx);
const struct in_addr *dplane_ctx_mac_get_vtep_ip(
	const struct zebra_dplane_ctx *ctx);
ifindex_t dplane_ctx_mac_get_br_ifindex(const struct zebra_dplane_ctx *ctx);

/* Accessors for neighbor information */
const struct ipaddr *dplane_ctx_neigh_get_ipaddr(
	const struct zebra_dplane_ctx *ctx);
const struct ethaddr *dplane_ctx_neigh_get_mac(
	const struct zebra_dplane_ctx *ctx);
vni_t dplane_ctx_neigh_get_vni(const struct zebra_dplane_ctx *ctx);
const struct ipaddr *
dplane_ctx_neigh_get_link_ip(const struct zebra_dplane_ctx *ctx);
uint32_t dplane_ctx_neigh_get_flags(const struct zebra_dplane_ctx *ctx);
uint16_t dplane_ctx_neigh_get_state(const struct zebra_dplane_ctx *ctx);
uint32_t dplane_ctx_neigh_get_update_flags(const struct zebra_dplane_ctx *ctx);

/* Accessors for policy based routing rule information */
void dplane_ctx_rule_get(const struct zebra_dplane_ctx *ctx,
	struct pbr_rule *pNew, struct pbr_rule *pOld);
int dplane_ctx_rule_get_sock(const struct zebra_dplane_ctx *ctx);
int dplane_ctx_rule_get_unique(const struct zebra_dplane_ctx *ctx);
int dplane_ctx_rule_get_seq(const struct zebra_dplane_ctx *ctx);
const char *dplane_ctx_rule_get_ifname(const struct zebra_dplane_ctx *ctx);
uint32_t dplane_ctx_rule_get_priority(const struct zebra_dplane_ctx *ctx);
uint32_t dplane_ctx_rule_get_old_priority(const struct zebra_dplane_ctx *ctx);
uint32_t dplane_ctx_rule_get_table(const struct zebra_dplane_ctx *ctx);
uint32_t dplane_ctx_rule_get_old_table(const struct zebra_dplane_ctx *ctx);
uint32_t dplane_ctx_rule_get_filter_bm(const struct zebra_dplane_ctx *ctx);
uint32_t dplane_ctx_rule_get_old_filter_bm(const struct zebra_dplane_ctx *ctx);
uint32_t dplane_ctx_rule_get_fwmark(const struct zebra_dplane_ctx *ctx);
uint32_t dplane_ctx_rule_get_old_fwmark(const struct zebra_dplane_ctx *ctx);
uint8_t dplane_ctx_rule_get_dsfield(const struct zebra_dplane_ctx *ctx);
uint8_t dplane_ctx_rule_get_old_dsfield(const struct zebra_dplane_ctx *ctx);
uint8_t dplane_ctx_rule_get_ipproto(const struct zebra_dplane_ctx *ctx);
uint8_t dplane_ctx_rule_get_old_ipproto(const struct zebra_dplane_ctx *ctx);
uint16_t dplane_ctx_rule_get_src_port(const struct zebra_dplane_ctx *ctx);
uint16_t dplane_ctx_rule_get_old_src_port(const struct zebra_dplane_ctx *ctx);
uint16_t dplane_ctx_rule_get_dst_port(const struct zebra_dplane_ctx *ctx);
uint16_t dplane_ctx_rule_get_old_dst_port(const struct zebra_dplane_ctx *ctx);
const struct prefix *
dplane_ctx_rule_get_src_ip(const struct zebra_dplane_ctx *ctx);
const struct prefix *
dplane_ctx_rule_get_old_src_ip(const struct zebra_dplane_ctx *ctx);
const struct prefix *
dplane_ctx_rule_get_dst_ip(const struct zebra_dplane_ctx *ctx);
const struct prefix *
dplane_ctx_rule_get_old_dst_ip(const struct zebra_dplane_ctx *ctx);
const struct ethaddr *
dplane_ctx_rule_get_smac(const struct zebra_dplane_ctx *ctx);
const struct ethaddr *
dplane_ctx_rule_get_dmac(const struct zebra_dplane_ctx *ctx);
int dplane_ctx_rule_get_out_ifindex(const struct zebra_dplane_ctx *ctx);
intptr_t dplane_ctx_rule_get_dp_flow_ptr(const struct zebra_dplane_ctx *ctx);
intptr_t
dplane_ctx_rule_get_old_dp_flow_ptr(const struct zebra_dplane_ctx *ctx);
void dplane_ctx_rule_set_dp_flow_ptr(struct zebra_dplane_ctx *ctx,
				     intptr_t dp_flow_ptr);
vrf_id_t dplane_ctx_rule_get_vrfid(const struct zebra_dplane_ctx *ctx);

/* Accessors for policy based routing iptable information */
struct zebra_pbr_iptable;
void dplane_ctx_get_pbr_iptable(const struct zebra_dplane_ctx *ctx,
				struct zebra_pbr_iptable *table);
struct zebra_pbr_ipset;
void dplane_ctx_get_pbr_ipset(const struct zebra_dplane_ctx *ctx,
			      struct zebra_pbr_ipset *ipset);
struct zebra_pbr_ipset_entry;
void dplane_ctx_get_pbr_ipset_entry(const struct zebra_dplane_ctx *ctx,
				    struct zebra_pbr_ipset_entry *entry);
/* Accessors for bridge port information */
uint32_t dplane_ctx_get_br_port_flags(const struct zebra_dplane_ctx *ctx);
uint32_t
dplane_ctx_get_br_port_sph_filter_cnt(const struct zebra_dplane_ctx *ctx);
const struct in_addr *
dplane_ctx_get_br_port_sph_filters(const struct zebra_dplane_ctx *ctx);
uint32_t
dplane_ctx_get_br_port_backup_nhg_id(const struct zebra_dplane_ctx *ctx);

/* Accessors for neighbor table information */
uint8_t dplane_ctx_neightable_get_family(const struct zebra_dplane_ctx *ctx);
uint32_t
dplane_ctx_neightable_get_app_probes(const struct zebra_dplane_ctx *ctx);
uint32_t
dplane_ctx_neightable_get_mcast_probes(const struct zebra_dplane_ctx *ctx);
uint32_t
dplane_ctx_neightable_get_ucast_probes(const struct zebra_dplane_ctx *ctx);

/* Accessor for GRE set */
uint32_t
dplane_ctx_gre_get_link_ifindex(const struct zebra_dplane_ctx *ctx);
unsigned int
dplane_ctx_gre_get_mtu(const struct zebra_dplane_ctx *ctx);
const struct zebra_l2info_gre *
dplane_ctx_gre_get_info(const struct zebra_dplane_ctx *ctx);

/* Interface netconf info */
enum dplane_netconf_status_e
dplane_ctx_get_netconf_mpls(const struct zebra_dplane_ctx *ctx);
enum dplane_netconf_status_e
dplane_ctx_get_netconf_mcast(const struct zebra_dplane_ctx *ctx);
enum dplane_netconf_status_e
dplane_ctx_get_netconf_linkdown(const struct zebra_dplane_ctx *ctx);

void dplane_ctx_set_netconf_mpls(struct zebra_dplane_ctx *ctx,
				 enum dplane_netconf_status_e val);
void dplane_ctx_set_netconf_mcast(struct zebra_dplane_ctx *ctx,
				  enum dplane_netconf_status_e val);
void dplane_ctx_set_netconf_linkdown(struct zebra_dplane_ctx *ctx,
				     enum dplane_netconf_status_e val);

/* Namespace fd info - esp. for netlink communication */
const struct zebra_dplane_info *dplane_ctx_get_ns(
	const struct zebra_dplane_ctx *ctx);
int dplane_ctx_get_ns_sock(const struct zebra_dplane_ctx *ctx);

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

/*
 * Enqueue bridge port changes for the dataplane.
 */
enum zebra_dplane_result dplane_br_port_update(
	const struct interface *ifp, bool non_df, uint32_t sph_filter_cnt,
	const struct in_addr *sph_filters, uint32_t backup_nhg_id);

/* Forward ref of nhg_hash_entry */
struct nhg_hash_entry;
/*
 * Enqueue a nexthop change operation for the dataplane.
 */
enum zebra_dplane_result dplane_pic_nh_add(struct nhg_hash_entry *nhe);
enum zebra_dplane_result dplane_pic_nh_delete(struct nhg_hash_entry *nhe);
enum zebra_dplane_result dplane_nexthop_add(struct nhg_hash_entry *nhe);
enum zebra_dplane_result dplane_nexthop_update(struct nhg_hash_entry *nhe);
enum zebra_dplane_result dplane_nexthop_delete(struct nhg_hash_entry *nhe);

/*
 * Enqueue LSP change operations for the dataplane.
 */
enum zebra_dplane_result dplane_lsp_add(struct zebra_lsp *lsp);
enum zebra_dplane_result dplane_lsp_update(struct zebra_lsp *lsp);
enum zebra_dplane_result dplane_lsp_delete(struct zebra_lsp *lsp);

/* Update or un-install resulting from an async notification */
enum zebra_dplane_result dplane_lsp_notif_update(struct zebra_lsp *lsp,
						 enum dplane_op_e op,
						 struct zebra_dplane_ctx *ctx);

/*
 * Enqueue pseudowire operations for the dataplane.
 */
enum zebra_dplane_result dplane_pw_install(struct zebra_pw *pw);
enum zebra_dplane_result dplane_pw_uninstall(struct zebra_pw *pw);

enum zebra_dplane_result
dplane_intf_mpls_modify_state(const struct interface *ifp, const bool set);
/*
 * Enqueue interface address changes for the dataplane.
 */
enum zebra_dplane_result dplane_intf_addr_set(const struct interface *ifp,
					      const struct connected *ifc);
enum zebra_dplane_result dplane_intf_addr_unset(const struct interface *ifp,
						const struct connected *ifc);

/*
 * Enqueue interface link changes for the dataplane.
 */
enum zebra_dplane_result dplane_intf_add(const struct interface *ifp);
enum zebra_dplane_result dplane_intf_update(const struct interface *ifp);

/*
 * Enqueue tc link changes for the dataplane.
 */

struct zebra_tc_qdisc;
struct zebra_tc_class;
struct zebra_tc_filter;
enum zebra_dplane_result dplane_tc_qdisc_install(struct zebra_tc_qdisc *qdisc);
enum zebra_dplane_result
dplane_tc_qdisc_uninstall(struct zebra_tc_qdisc *qdisc);
enum zebra_dplane_result dplane_tc_class_add(struct zebra_tc_class *class);
enum zebra_dplane_result dplane_tc_class_delete(struct zebra_tc_class *class);
enum zebra_dplane_result dplane_tc_class_update(struct zebra_tc_class *class);
enum zebra_dplane_result dplane_tc_filter_add(struct zebra_tc_filter *filter);
enum zebra_dplane_result
dplane_tc_filter_delete(struct zebra_tc_filter *filter);
enum zebra_dplane_result
dplane_tc_filter_update(struct zebra_tc_filter *filter);

/*
 * Link layer operations for the dataplane.
 */
enum zebra_dplane_result dplane_neigh_ip_update(enum dplane_op_e op,
						const struct interface *ifp,
						struct ipaddr *link_ip,
						struct ipaddr *ip,
						uint32_t ndm_state,
						int protocol);

/*
 * Enqueue evpn mac operations for the dataplane.
 */
enum zebra_dplane_result
dplane_rem_mac_add(const struct interface *ifp,
		   const struct interface *bridge_ifp, vlanid_t vid,
		   const struct ethaddr *mac, vni_t vni, struct in_addr vtep_ip,
		   bool sticky, uint32_t nhg_id, bool was_static);

enum zebra_dplane_result dplane_local_mac_add(const struct interface *ifp,
					const struct interface *bridge_ifp,
					vlanid_t vid,
					const struct ethaddr *mac,
					bool sticky,
					uint32_t set_static,
					uint32_t set_inactive);

enum zebra_dplane_result
dplane_local_mac_del(const struct interface *ifp,
		     const struct interface *bridge_ifp, vlanid_t vid,
		     const struct ethaddr *mac);

enum zebra_dplane_result dplane_rem_mac_del(const struct interface *ifp,
					    const struct interface *bridge_ifp,
					    vlanid_t vid,
					    const struct ethaddr *mac,
					    vni_t vni, struct in_addr vtep_ip);

/* Helper api to init an empty or new context for a MAC update */
void dplane_mac_init(struct zebra_dplane_ctx *ctx, const struct interface *ifp,
		     const struct interface *br_ifp, vlanid_t vid,
		     const struct ethaddr *mac, vni_t vni,
		     struct in_addr vtep_ip, bool sticky, uint32_t nhg_id,
		     uint32_t update_flags);

/*
 * Enqueue evpn neighbor updates for the dataplane.
 */
enum zebra_dplane_result dplane_rem_neigh_add(const struct interface *ifp,
					  const struct ipaddr *ip,
					  const struct ethaddr *mac,
					  uint32_t flags, bool was_static);
enum zebra_dplane_result dplane_local_neigh_add(const struct interface *ifp,
					  const struct ipaddr *ip,
					  const struct ethaddr *mac,
					  bool set_router, bool set_static,
					  bool set_inactive);
enum zebra_dplane_result dplane_rem_neigh_delete(const struct interface *ifp,
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

/*
 * Enqueue a neighbour discovery request for the dataplane.
 */
enum zebra_dplane_result dplane_neigh_discover(const struct interface *ifp,
					       const struct ipaddr *ip);

/*
 * Enqueue a neighbor table parameter set
 */
enum zebra_dplane_result dplane_neigh_table_update(const struct interface *ifp,
						   const uint8_t family,
						   const uint32_t app_probes,
						   const uint32_t ucast_probes,
						   const uint32_t mcast_probes);

/*
 * Enqueue a GRE set
 */
enum zebra_dplane_result
dplane_gre_set(struct interface *ifp, struct interface *ifp_link,
	       unsigned int mtu, const struct zebra_l2info_gre *gre_info);

/*
 * Enqueue an SRv6 encap source address set
 */
enum zebra_dplane_result
dplane_srv6_encap_srcaddr_set(const struct in6_addr *addr, ns_id_t ns_id);


/* Forward ref of zebra_pbr_rule */
struct zebra_pbr_rule;

/*
 * Enqueue policy based routing rule for the dataplane.
 * It is possible that the user-defined sequence number and the one in the
 * forwarding plane may not coincide, hence the API requires a separate
 * rule priority - maps to preference/FRA_PRIORITY on Linux.
 */
enum zebra_dplane_result dplane_pbr_rule_add(struct zebra_pbr_rule *rule);
enum zebra_dplane_result dplane_pbr_rule_delete(struct zebra_pbr_rule *rule);
enum zebra_dplane_result
dplane_pbr_rule_update(struct zebra_pbr_rule *old_rule,
		       struct zebra_pbr_rule *new_rule);
/* iptable */
enum zebra_dplane_result
dplane_pbr_iptable_add(struct zebra_pbr_iptable *iptable);
enum zebra_dplane_result
dplane_pbr_iptable_delete(struct zebra_pbr_iptable *iptable);

/* ipset */
struct zebra_pbr_ipset;
enum zebra_dplane_result dplane_pbr_ipset_add(struct zebra_pbr_ipset *ipset);
enum zebra_dplane_result dplane_pbr_ipset_delete(struct zebra_pbr_ipset *ipset);

/* ipset entry */
struct zebra_pbr_ipset_entry;
enum zebra_dplane_result
dplane_pbr_ipset_entry_add(struct zebra_pbr_ipset_entry *ipset);
enum zebra_dplane_result
dplane_pbr_ipset_entry_delete(struct zebra_pbr_ipset_entry *ipset);

/* Encode route information into data plane context. */
int dplane_ctx_route_init(struct zebra_dplane_ctx *ctx, enum dplane_op_e op,
			  struct route_node *rn, struct route_entry *re);

int dplane_ctx_route_init_basic(struct zebra_dplane_ctx *ctx,
				enum dplane_op_e op, struct route_entry *re,
				const struct prefix *p,
				const struct prefix_ipv6 *src_p, afi_t afi,
				safi_t safi);

/* Encode next hop information into data plane context. */
int dplane_ctx_nexthop_init(struct zebra_dplane_ctx *ctx, enum dplane_op_e op,
			    struct nhg_hash_entry *nhe);

/* Encode interface information into data plane context. */
int dplane_ctx_intf_init(struct zebra_dplane_ctx *ctx, enum dplane_op_e op,
			 const struct interface *ifp);

/* Encode traffic control information into data plane context. */
int dplane_ctx_tc_init(struct zebra_dplane_ctx *ctx, enum dplane_op_e op);

/* Retrieve the limit on the number of pending, unprocessed updates. */
uint32_t dplane_get_in_queue_limit(void);

/* Configure limit on the number of pending, queued updates. If 'unset', reset
 * to default value.
 */
void dplane_set_in_queue_limit(uint32_t limit, bool set);

/* Retrieve the current queue depth of incoming, unprocessed updates */
uint32_t dplane_get_in_queue_len(void);

void dplane_ctx_set_vlan_ifindex(struct zebra_dplane_ctx *ctx,
				 ifindex_t ifindex);
ifindex_t dplane_ctx_get_vlan_ifindex(struct zebra_dplane_ctx *ctx);
struct zebra_vxlan_vlan_array;

/*
 * In netlink_vlan_change(), the memory allocated for vlan_array is freed
 * in two cases
 *  1) Inline free in netlink_vlan_change() when there are no new
 *     vlans to process i.e. nothing is enqueued to main thread.
 *  2) Dplane-ctx takes over the vlan memory which gets freed in
 *     rib_process_dplane_results() after handling the vlan install
 *
 * Note: MTYPE of interest for this purpose is MTYPE_VLAN_CHANGE_ARR
 */
void dplane_ctx_set_vxlan_vlan_array(struct zebra_dplane_ctx *ctx,
				     struct zebra_vxlan_vlan_array *vlan_array);
const struct zebra_vxlan_vlan_array *
dplane_ctx_get_vxlan_vlan_array(struct zebra_dplane_ctx *ctx);

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
struct event_loop *dplane_get_thread_master(void);

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
				    struct dplane_ctx_list_head *listp);

/* Current completed work queue length */
uint32_t dplane_provider_out_ctx_queue_len(struct zebra_dplane_provider *prov);

/* Enqueue completed work, maintain associated counter and locking */
void dplane_provider_enqueue_out_ctx(struct zebra_dplane_provider *prov,
				     struct zebra_dplane_ctx *ctx);

/* Enqueue a context directly to zebra main. */
void dplane_provider_enqueue_to_zebra(struct zebra_dplane_ctx *ctx);

/* Enable collection of extra info about interfaces in route updates;
 * this allows a provider/plugin to see some extra info in route update
 * context objects.
 */
void dplane_enable_intf_extra_info(void);

/*
 * Initialize the dataplane modules at zebra startup. This is currently called
 * by the rib module. Zebra registers a results callback with the dataplane.
 * The callback is called in the dataplane pthread context,
 * so the expectation is that the contexts are queued for the zebra
 * main pthread.
 */
void zebra_dplane_init(int (*)(struct dplane_ctx_list_head *));

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

void zebra_dplane_startup_stage(struct zebra_ns *zns,
				enum zebra_dplane_startup_notifications spot);

/*
 * decision point for sending a routing update through the old
 * straight to zebra master pthread or through the dplane to
 * the master pthread for handling
 */
void dplane_rib_add_multipath(afi_t afi, safi_t safi, struct prefix *p,
			      struct prefix_ipv6 *src_p, struct route_entry *re,
			      struct nexthop_group *ng, int startup,
			      struct zebra_dplane_ctx *ctx);

enum zebra_dplane_startup_notifications
dplane_ctx_get_startup_spot(struct zebra_dplane_ctx *ctx);

#ifdef __cplusplus
}
#endif

#endif	/* _ZEBRA_DPLANE_H */
