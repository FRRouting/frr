// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Zebra Policy Based Routing (PBR) Data structures and definitions
 * These are public definitions referenced by multiple files.
 * Copyright (C) 2018 Cumulus Networks, Inc.
 */

#ifndef _ZEBRA_PBR_H
#define _ZEBRA_PBR_H

#include <zebra.h>

#include "prefix.h"
#include "if.h"

#include "rt.h"
#include "pbr.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Memory type for PBR objects. */
DECLARE_MTYPE(PBR_OBJ);

struct zebra_pbr_action {
	afi_t afi;

	/* currently only one nexthop is supported */
	union g_addr gate;

	/* dest-interface */
	ifindex_t ifindex;

	/* dataplane info */
	intptr_t dp_flow_ptr;

	/* neigh */
	struct zebra_neigh_ent *neigh;
	/* zebra_pbr_rule is linked to neigh via neigh_listnode */
	struct listnode neigh_listnode;
};

struct zebra_pbr_rule {
	int sock;

	struct pbr_rule rule;

	char ifname[INTERFACE_NAMSIZ];

	struct zebra_pbr_action action;

	vrf_id_t vrf_id;
};

#define IS_RULE_FILTERING_ON_SRC_IP(r) \
	(r->rule.filter.filter_bm & PBR_FILTER_SRC_IP)
#define IS_RULE_FILTERING_ON_DST_IP(r) \
	(r->rule.filter.filter_bm & PBR_FILTER_DST_IP)
#define IS_RULE_FILTERING_ON_SRC_PORT(r) \
	(r->rule.filter.filter_bm & PBR_FILTER_SRC_PORT)
#define IS_RULE_FILTERING_ON_DST_PORT(r) \
	(r->rule.filter.filter_bm & PBR_FILTER_DST_PORT)
#define IS_RULE_FILTERING_ON_FWMARK(r) \
	(r->rule.filter.filter_bm & PBR_FILTER_FWMARK)

/*
 * An IPSet Entry Filter
 *
 * This is a filter mapped on ipset entries
 */
struct zebra_pbr_ipset_info {
	/* type is encoded as uint32_t
	 * but value is an enum ipset_type
	 */
	uint32_t type;

	uint8_t family;

	char ipset_name[ZEBRA_IPSET_NAME_SIZE];
};

struct zebra_pbr_ipset {
	/*
	 * Originating zclient sock fd, so we can know who to send
	 * back to.
	 */
	int sock;

	vrf_id_t vrf_id;

	uint32_t unique;

	/* type is encoded as uint32_t
	 * but value is an enum ipset_type
	 */
	uint32_t type;

	uint8_t family;

	char ipset_name[ZEBRA_IPSET_NAME_SIZE];
};


/*
 * An IPSet Entry Filter
 *
 * This is a filter mapped on ipset entries
 */
struct zebra_pbr_ipset_entry {
	/*
	 * Originating zclient sock fd, so we can know who to send
	 * back to.
	 */
	int sock;

	uint32_t unique;

	struct prefix src;
	struct prefix dst;

	/* udp/tcp src port or icmp type */
	uint16_t src_port_min;
	uint16_t src_port_max;
	/* udp/tcp dst port or icmp code */
	uint16_t dst_port_min;
	uint16_t dst_port_max;

	uint8_t proto;

	uint32_t filter_bm;

	struct zebra_pbr_ipset *backpointer;
};

/*
 * An IPTables Action
 *
 * This is a filter mapped on ipset entries
 */
struct zebra_pbr_iptable {
	/*
	 * Originating zclient sock fd, so we can know who to send
	 * back to.
	 */
	int sock;

	vrf_id_t vrf_id;

	uint32_t unique;

	/* include ipset type
	 */
	uint32_t type;

	/* include which IP is to be filtered
	 */
	uint32_t filter_bm;

	uint32_t fwmark;

	uint32_t action;

	uint16_t pkt_len_min;
	uint16_t pkt_len_max;
	uint16_t tcp_flags;
	uint16_t tcp_mask_flags;
	uint8_t dscp_value;
	uint8_t fragment;
	uint8_t protocol;

	uint32_t nb_interface;
	uint16_t flow_label;

	uint8_t family;

	struct list *interface_name_list;

#define IPTABLE_INSTALL_QUEUED 1 << 1
#define IPTABLE_UNINSTALL_QUEUED 1 << 2
	uint8_t internal_flags;
	char ipset_name[ZEBRA_IPSET_NAME_SIZE];
};

extern const struct message icmp_typecode_str[];
extern const struct message icmpv6_typecode_str[];

const char *zebra_pbr_ipset_type2str(uint32_t type);

void zebra_pbr_add_rule(struct zebra_pbr_rule *rule);
void zebra_pbr_del_rule(struct zebra_pbr_rule *rule);
void zebra_pbr_create_ipset(struct zebra_pbr_ipset *ipset);
void zebra_pbr_destroy_ipset(struct zebra_pbr_ipset *ipset);
struct zebra_pbr_ipset *zebra_pbr_lookup_ipset_pername(char *ipsetname);
void zebra_pbr_add_ipset_entry(struct zebra_pbr_ipset_entry *ipset);
void zebra_pbr_del_ipset_entry(struct zebra_pbr_ipset_entry *ipset);

void zebra_pbr_add_iptable(struct zebra_pbr_iptable *iptable);
void zebra_pbr_del_iptable(struct zebra_pbr_iptable *iptable);
void zebra_pbr_process_iptable(struct zebra_dplane_ctx *ctx);
void zebra_pbr_process_ipset(struct zebra_dplane_ctx *ctx);
void zebra_pbr_process_ipset_entry(struct zebra_dplane_ctx *ctx);

/*
 * Get to know existing PBR rules in the kernel - typically called at startup.
 */
extern void kernel_read_pbr_rules(struct zebra_ns *zns);

/*
 * Handle success or failure of rule (un)install in the kernel.
 */
extern void zebra_pbr_dplane_result(struct zebra_dplane_ctx *ctx);

/*
 * Handle success or failure of ipset kinds (un)install in the kernel.
 */
extern void kernel_pbr_ipset_add_del_status(struct zebra_pbr_ipset *ipset,
					   enum zebra_dplane_status res);

extern void kernel_pbr_ipset_entry_add_del_status(
				struct zebra_pbr_ipset_entry *ipset,
				enum zebra_dplane_status res);

/*
 * Handle rule delete notification from kernel.
 */
extern int kernel_pbr_rule_del(struct zebra_pbr_rule *rule);

extern void zebra_pbr_rules_free(void *arg);
extern uint32_t zebra_pbr_rules_hash_key(const void *arg);
extern bool zebra_pbr_rules_hash_equal(const void *arg1, const void *arg2);

/* has operates on 32bit pointer
 * and field is a string of 8bit
 */
#define ZEBRA_IPSET_NAME_HASH_SIZE (ZEBRA_IPSET_NAME_SIZE / 4)

extern void zebra_pbr_ipset_free(void *arg);
extern uint32_t zebra_pbr_ipset_hash_key(const void *arg);
extern bool zebra_pbr_ipset_hash_equal(const void *arg1, const void *arg2);

extern void zebra_pbr_ipset_entry_free(void *arg);
extern uint32_t zebra_pbr_ipset_entry_hash_key(const void *arg);
extern bool zebra_pbr_ipset_entry_hash_equal(const void *arg1,
					     const void *arg2);

extern void zebra_pbr_iptable_free(void *arg);
extern uint32_t zebra_pbr_iptable_hash_key(const void *arg);
extern bool zebra_pbr_iptable_hash_equal(const void *arg1, const void *arg2);

extern void zebra_pbr_config_write(struct vty *vty);
extern void zebra_pbr_expand_action_update(bool enable);
extern void zebra_pbr_init(void);
extern void zebra_pbr_show_ipset_list(struct vty *vty, char *ipsetname);
extern void zebra_pbr_show_iptable(struct vty *vty, char *iptable);
extern void zebra_pbr_iptable_update_interfacelist(struct stream *s,
				   struct zebra_pbr_iptable *zpi);
size_t zebra_pbr_tcpflags_snprintf(char *buffer, size_t len,
				   uint16_t tcp_val);
extern void zebra_pbr_show_rule(struct vty *vty);
extern void zebra_pbr_show_rule_unit(struct zebra_pbr_rule *rule,
				     struct vty *vty);

DECLARE_HOOK(zebra_pbr_ipset_entry_get_stat,
	     (struct zebra_pbr_ipset_entry *ipset, uint64_t *pkts,
	      uint64_t *bytes),
	     (ipset, pkts, bytes));
DECLARE_HOOK(zebra_pbr_iptable_get_stat,
	     (struct zebra_pbr_iptable *iptable, uint64_t *pkts,
	      uint64_t *bytes),
	     (iptable, pkts, bytes));
DECLARE_HOOK(zebra_pbr_iptable_update,
	     (int cmd, struct zebra_pbr_iptable *iptable), (cmd, iptable));

DECLARE_HOOK(zebra_pbr_ipset_entry_update,
	     (int cmd, struct zebra_pbr_ipset_entry *ipset), (cmd, ipset));
DECLARE_HOOK(zebra_pbr_ipset_update,
	     (int cmd, struct zebra_pbr_ipset *ipset), (cmd, ipset));

#ifdef __cplusplus
}
#endif

#endif /* _ZEBRA_PBR_H */
