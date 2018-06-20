/*
 * Zebra Policy Based Routing (PBR) Data structures and definitions
 * These are public definitions referenced by multiple files.
 * Copyright (C) 2018 Cumulus Networks, Inc.
 *
 * This file is part of FRR.
 *
 * FRR is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2, or (at your option) any
 * later version.
 *
 * FRR is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with FRR; see the file COPYING.  If not, write to the Free
 * Software Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA
 * 02111-1307, USA.
 */

#ifndef _ZEBRA_PBR_H
#define _ZEBRA_PBR_H

#include <zebra.h>

#include "prefix.h"
#include "if.h"

#include "rt.h"
#include "pbr.h"

struct zebra_pbr_rule {
	int sock;

	struct pbr_rule rule;

	struct interface *ifp;
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

	uint32_t nb_interface;

	struct list *interface_name_list;

	char ipset_name[ZEBRA_IPSET_NAME_SIZE];
};

extern const struct message icmp_typecode_str[];

const char *zebra_pbr_ipset_type2str(uint32_t type);

void zebra_pbr_add_rule(struct zebra_ns *zns, struct zebra_pbr_rule *rule);
void zebra_pbr_del_rule(struct zebra_ns *zns, struct zebra_pbr_rule *rule);
void zebra_pbr_create_ipset(struct zebra_ns *zns,
			    struct zebra_pbr_ipset *ipset);
void zebra_pbr_destroy_ipset(struct zebra_ns *zns,
			     struct zebra_pbr_ipset *ipset);
struct zebra_pbr_ipset *zebra_pbr_lookup_ipset_pername(struct zebra_ns *zns,
						       char *ipsetname);
void zebra_pbr_add_ipset_entry(struct zebra_ns *zns,
			       struct zebra_pbr_ipset_entry *ipset);
void zebra_pbr_del_ipset_entry(struct zebra_ns *zns,
			       struct zebra_pbr_ipset_entry *ipset);

void zebra_pbr_add_iptable(struct zebra_ns *zns,
			   struct zebra_pbr_iptable *iptable);
void zebra_pbr_del_iptable(struct zebra_ns *zns,
			   struct zebra_pbr_iptable *iptable);

/*
 * Install specified rule for a specific interface.
 * It is possible that the user-defined sequence number and the one in the
 * forwarding plane may not coincide, hence the API requires a separate
 * rule priority - maps to preference/FRA_PRIORITY on Linux.
 */
extern enum dp_req_result kernel_add_pbr_rule(struct zebra_pbr_rule *rule);

/*
 * Uninstall specified rule for a specific interface.
 */
extern enum dp_req_result kernel_del_pbr_rule(struct zebra_pbr_rule *rule);

/*
 * Get to know existing PBR rules in the kernel - typically called at startup.
 */
extern void kernel_read_pbr_rules(struct zebra_ns *zns);

enum dp_results;
/*
 * Handle success or failure of rule (un)install in the kernel.
 */
extern void kernel_pbr_rule_add_del_status(struct zebra_pbr_rule *rule,
					   enum dp_results res);

/*
 * Handle success or failure of ipset kinds (un)install in the kernel.
 */
extern void kernel_pbr_ipset_add_del_status(struct zebra_pbr_ipset *ipset,
					   enum dp_results res);

extern void kernel_pbr_ipset_entry_add_del_status(
				struct zebra_pbr_ipset_entry *ipset,
				enum dp_results res);

extern void kernel_pbr_iptable_add_del_status(struct zebra_pbr_iptable *iptable,
			      enum dp_results res);

/*
 * Handle rule delete notification from kernel.
 */
extern int kernel_pbr_rule_del(struct zebra_pbr_rule *rule);

extern void zebra_pbr_rules_free(void *arg);
extern uint32_t zebra_pbr_rules_hash_key(void *arg);
extern int zebra_pbr_rules_hash_equal(const void *arg1, const void *arg2);

/* has operates on 32bit pointer
 * and field is a string of 8bit
 */
#define ZEBRA_IPSET_NAME_HASH_SIZE (ZEBRA_IPSET_NAME_SIZE / 4)

extern void zebra_pbr_ipset_free(void *arg);
extern uint32_t zebra_pbr_ipset_hash_key(void *arg);
extern int zebra_pbr_ipset_hash_equal(const void *arg1, const void *arg2);

extern void zebra_pbr_ipset_entry_free(void *arg);
extern uint32_t zebra_pbr_ipset_entry_hash_key(void *arg);
extern int zebra_pbr_ipset_entry_hash_equal(const void *arg1, const void *arg2);

extern void zebra_pbr_iptable_free(void *arg);
extern uint32_t zebra_pbr_iptable_hash_key(void *arg);
extern int zebra_pbr_iptable_hash_equal(const void *arg1, const void *arg2);

extern void zebra_pbr_init(void);
extern void zebra_pbr_show_ipset_list(struct vty *vty, char *ipsetname);
extern void zebra_pbr_show_iptable(struct vty *vty);
extern void zebra_pbr_iptable_update_interfacelist(struct stream *s,
				   struct zebra_pbr_iptable *zpi);
size_t zebra_pbr_tcpflags_snprintf(char *buffer, size_t len,
				   uint16_t tcp_val);

DECLARE_HOOK(zebra_pbr_ipset_entry_wrap_script_get_stat, (struct zebra_ns *zns,
				    struct zebra_pbr_ipset_entry *ipset,
				    uint64_t *pkts, uint64_t *bytes),
				     (zns, ipset, pkts, bytes))
DECLARE_HOOK(zebra_pbr_iptable_wrap_script_get_stat, (struct zebra_ns *zns,
				    struct zebra_pbr_iptable *iptable,
				    uint64_t *pkts, uint64_t *bytes),
				     (zns, iptable, pkts, bytes))
DECLARE_HOOK(zebra_pbr_iptable_wrap_script_update, (struct zebra_ns *zns,
					     int cmd,
					     struct zebra_pbr_iptable *iptable),
					     (zns, cmd, iptable));

DECLARE_HOOK(zebra_pbr_ipset_entry_wrap_script_update, (struct zebra_ns *zns,
				  int cmd,
				  struct zebra_pbr_ipset_entry *ipset),
				     (zns, cmd, ipset));
DECLARE_HOOK(zebra_pbr_ipset_wrap_script_update, (struct zebra_ns *zns,
				  int cmd,
				  struct zebra_pbr_ipset *ipset),
				     (zns, cmd, ipset));

#endif /* _ZEBRA_PBR_H */
