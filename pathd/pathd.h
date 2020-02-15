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
	SRTE_CANDIDATE_TYPE_EXPLICIT = 0,
	SRTE_CANDIDATE_TYPE_DYNAMIC = 1,
};

struct srte_segment_entry {
	RB_ENTRY(srte_segment_entry) entry;

	/* Index of the Label. */
	uint32_t index;

	/* Label Value. */
	mpls_label_t sid_value;
};
RB_HEAD(srte_segment_entry_head, srte_segment_entry);
RB_PROTOTYPE(srte_segment_entry_head, srte_segment_entry, entry,
	     srte_segment_entry_compare)

struct srte_segment_list {
	RB_ENTRY(srte_segment_list) entry;

	/* Name of the Segment List. */
	char name[64];

	/* Nexthops. */
	struct srte_segment_entry_head segments;
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

	/* true when created, false after triggering the "created" hook. */
	bool created;

	/* Symbolic Name. */
	char name[64];

	/* The associated Segment List. */
	struct srte_segment_list *segment_list;

	/* The Protocol-Origin. */
	enum srte_protocol_origin protocol_origin;

	/* The Originator */
	struct ipaddr originator;

	/* The Discriminator */
	uint32_t discriminator;

	/* Flag for best Candidate Path */
	bool is_best_candidate_path;

	/* The Type (explicit or dynamic) */
	enum srte_candidate_type type;
};
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

/* pathd.c */
struct srte_segment_list *srte_segment_list_add(const char *name);
void srte_segment_list_del(struct srte_segment_list *segment_list);
struct srte_segment_list *srte_segment_list_find(const char *name);
struct srte_segment_entry *
srte_segment_entry_add(struct srte_segment_list *segment_list, uint32_t index);
void srte_segment_entry_del(struct srte_segment_list *segment_list,
			    struct srte_segment_entry *segment);
struct srte_policy *srte_policy_add(uint32_t color, struct ipaddr *endpoint);
void srte_policy_del(struct srte_policy *policy);
struct srte_policy *srte_policy_find(uint32_t color, struct ipaddr *endpoint);
void srte_policy_update_binding_sid(struct srte_policy *policy,
				    uint32_t binding_sid);
struct srte_candidate *srte_candidate_add(struct srte_policy *policy,
					  uint32_t preference);
void srte_candidate_del(struct srte_candidate *candidate);
struct srte_candidate *srte_candidate_find(struct srte_policy *policy,
					   uint32_t preference);
void srte_candidate_set_active(struct srte_policy *policy,
			       struct srte_candidate *changed_candidate);
void srte_candidate_updated(struct srte_candidate *candidate);
const char *srte_origin2str(enum srte_protocol_origin origin);

/* path_zebra.c */
void path_zebra_init(struct thread_master *master);
void path_zebra_add_sr_policy(struct srte_policy *policy,
			      struct srte_segment_list *segment_list);
void path_zebra_delete_sr_policy(struct srte_policy *policy);

/* path_cli.c */
void path_cli_init(void);

#endif /* _FRR_PATHD_H_ */
