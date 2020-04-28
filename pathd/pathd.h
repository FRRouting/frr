/*
 * Copyright (C) 2019  NetDEF, Inc.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the Free
 * Software Foundation; either version 2 of the License, or (at your option)
 * any later version.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; see the file COPYING; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA
 */

#ifndef _FRR_PATHD_H_
#define _FRR_PATHD_H_

#include "lib/mpls.h"
#include "lib/ipaddr.h"
#include "lib/srte.h"
#include "lib/hook.h"

enum srte_protocol_origin {
	SRTE_ORIGIN_UNDEFINED = 0,
	SRTE_ORIGIN_PCEP = 1,
	SRTE_ORIGIN_BGP = 2,
	SRTE_ORIGIN_LOCAL = 3,
};

enum srte_policy_status {
	SRTE_POLICY_STATUS_UNKNOWN = 0,
	SRTE_POLICY_STATUS_DOWN = 1,
	SRTE_POLICY_STATUS_UP = 2,
	SRTE_POLICY_STATUS_GOING_DOWN = 3,
	SRTE_POLICY_STATUS_GOING_UP = 4
};

enum srte_candidate_type {
	SRTE_CANDIDATE_TYPE_UNDEFINED = 0,
	SRTE_CANDIDATE_TYPE_EXPLICIT = 1,
	SRTE_CANDIDATE_TYPE_DYNAMIC = 2,
};

enum srte_candidate_metric_type {
	SRTE_CANDIDATE_METRIC_TYPE_ABC = 1,
	SRTE_CANDIDATE_METRIC_TYPE_TE = 2
};

enum srte_segment_nai_type {
	SRTE_SEGMENT_NAI_TYPE_NONE = 0,
	SRTE_SEGMENT_NAI_TYPE_IPV4_NODE = 1,
	SRTE_SEGMENT_NAI_TYPE_IPV6_NODE = 2,
	SRTE_SEGMENT_NAI_TYPE_IPV4_ADJACENCY = 3,
	SRTE_SEGMENT_NAI_TYPE_IPV6_ADJACENCY = 4,
	SRTE_SEGMENT_NAI_TYPE_IPV4_UNNUMBERED_ADJACENCY = 5
};

struct srte_segment_list;

struct srte_segment_entry {
	RB_ENTRY(srte_segment_entry) entry;

	/* The segment list the entry belong to */
	struct srte_segment_list *segment_list;

	/* Index of the Label. */
	uint32_t index;

	/* Label Value. */
	mpls_label_t sid_value;

	/* NAI Type */
	enum srte_segment_nai_type nai_type;
	/* NAI local address when nai type is not NONE */
	struct ipaddr nai_local_addr;
	/* NAI local interface when nai type is not IPv4 unnumbered adjacency */
	uint32_t nai_local_iface;
	/* NAI local interface when nai type is IPv4 or IPv6 adjacency */
	struct ipaddr nai_remote_addr;
	/* NAI remote interface when nai type is not IPv4 unnumbered adjacency
	 */
	uint32_t nai_remote_iface;
};
RB_HEAD(srte_segment_entry_head, srte_segment_entry);
RB_PROTOTYPE(srte_segment_entry_head, srte_segment_entry, entry,
	     srte_segment_entry_compare)

struct srte_segment_list {
	RB_ENTRY(srte_segment_list) entry;

	/* Name of the Segment List. */
	char name[64];

	/* The Protocol-Origin. */
	enum srte_protocol_origin protocol_origin;

	/* The Originator */
	char originator[64];

	/* Nexthops. */
	struct srte_segment_entry_head segments;

	/* Status flags. */
	uint16_t flags;
#define F_SEGMENT_LIST_NEW 0x0002
#define F_SEGMENT_LIST_MODIFIED 0x0004
#define F_SEGMENT_LIST_DELETED 0x0008
};
RB_HEAD(srte_segment_list_head, srte_segment_list);
RB_PROTOTYPE(srte_segment_list_head, srte_segment_list, entry,
	     srte_segment_list_compare)

struct srte_candidate {
	RB_ENTRY(srte_candidate) entry;

	/* Backpointer to SR Policy */
	struct srte_policy *policy;

	/* Administrative preference. */
	uint32_t preference;

	/* Symbolic Name. */
	char name[64];

	/* The associated Segment List. */
	struct srte_segment_list *segment_list;

	/* The Protocol-Origin. */
	enum srte_protocol_origin protocol_origin;

	/* The Originator */
	char originator[64];

	/* The Discriminator */
	uint32_t discriminator;

	/* The Type (explicit or dynamic) */
	enum srte_candidate_type type;

	/* Flags. */
	uint32_t flags;
#define F_CANDIDATE_BEST 0x0001
#define F_CANDIDATE_NEW 0x0002
#define F_CANDIDATE_MODIFIED 0x0004
#define F_CANDIDATE_DELETED 0x0008
#define F_CANDIDATE_HAS_METRIC_ABC 0x0100
#define F_CANDIDATE_METRIC_ABC_BOUND 0x200
#define F_CANDIDATE_METRIC_ABC_COMPUTED 0x400
#define F_CANDIDATE_HAS_METRIC_TE 0x0800
#define F_CANDIDATE_METRIC_TE_BOUND 0x1000
#define F_CANDIDATE_METRIC_TE_COMPUTED 0x2000

	/* Metrics */
	float metric_abc; /* Agreggate Bandwidth Consumption */
	float metric_te;
};

uint32_t attributes;
float metric_abc;
float metric_te;
float bandwidth_whatever;

RB_HEAD(srte_candidate_head, srte_candidate);
RB_PROTOTYPE(srte_candidate_head, srte_candidate, entry, srte_candidate_compare)

struct srte_policy {
	RB_ENTRY(srte_policy) entry;

	/* Color */
	uint32_t color;

	/* Endpoint */
	struct ipaddr endpoint;

	/* Name */
	char name[64];

	/* Binding SID */
	mpls_label_t binding_sid;

	/* Operational Status of the policy */
	enum srte_policy_status status;

	/* Best candidate path. */
	struct srte_candidate *best_candidate;

	/* Candidate Paths */
	struct srte_candidate_head candidate_paths;
	/* Status flags. */
	uint16_t flags;
#define F_POLICY_NEW 0x0002
#define F_POLICY_MODIFIED 0x0004
#define F_POLICY_DELETED 0x0008
};
RB_HEAD(srte_policy_head, srte_policy);
RB_PROTOTYPE(srte_policy_head, srte_policy, entry, srte_policy_compare)

DECLARE_HOOK(pathd_candidate_created, (struct srte_candidate * candidate),
	     (candidate))
DECLARE_HOOK(pathd_candidate_updated, (struct srte_candidate * candidate),
	     (candidate))
DECLARE_HOOK(pathd_candidate_removed, (struct srte_candidate * candidate),
	     (candidate))

extern struct srte_segment_list_head srte_segment_lists;
extern struct srte_policy_head srte_policies;
extern struct zebra_privs_t pathd_privs;

/* master thread, defined in path_main.c */
extern struct thread_master *master;

/* pathd.c */
struct srte_segment_list *srte_segment_list_add(const char *name);
void srte_segment_list_del(struct srte_segment_list *segment_list);
struct srte_segment_list *srte_segment_list_find(const char *name);
struct srte_segment_entry *
srte_segment_entry_add(struct srte_segment_list *segment_list, uint32_t index);
void srte_segment_entry_del(struct srte_segment_entry *segment);
struct srte_policy *srte_policy_add(uint32_t color, struct ipaddr *endpoint);
void srte_policy_del(struct srte_policy *policy);
struct srte_policy *srte_policy_find(uint32_t color, struct ipaddr *endpoint);
void srte_policy_update_binding_sid(struct srte_policy *policy,
				    uint32_t binding_sid);
void srte_apply_changes(void);
void srte_policy_apply_changes(struct srte_policy *policy);
struct srte_candidate *srte_candidate_add(struct srte_policy *policy,
					  uint32_t preference);
void srte_candidate_del(struct srte_candidate *candidate);
void srte_candidate_set_metric(struct srte_candidate *candidate,
			       enum srte_candidate_metric_type type,
			       float value, bool is_cound, bool is_computed);
void srte_candidate_unset_metric(struct srte_candidate *candidate,
				 enum srte_candidate_metric_type type);
struct srte_candidate *srte_candidate_find(struct srte_policy *policy,
					   uint32_t preference);
void srte_candidate_status_update(struct srte_policy *policy,
				  struct srte_candidate *candidate, int status);
const char *srte_origin2str(enum srte_protocol_origin origin);

/* path_zebra.c */
void path_zebra_add_sr_policy(struct srte_policy *policy,
			      struct srte_segment_list *segment_list);
void path_zebra_delete_sr_policy(struct srte_policy *policy);
int path_zebra_request_label(mpls_label_t label);
void path_zebra_release_label(mpls_label_t label);
void path_zebra_init(struct thread_master *master);

/* path_cli.c */
void path_cli_init(void);

#endif /* _FRR_PATHD_H_ */
