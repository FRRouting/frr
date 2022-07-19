/*
 * Copyright 2022 6WIND S.A.
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

#ifndef _FRR_PATH_TEMPLATE_H_
#define _FRR_PATH_TEMPLATE_H_

#include "lib/mpls.h"
#include "lib/ipaddr.h"
#include "lib/srte.h"
#include "lib/debug.h"

extern struct debug path_template_debug;

#define PATH_TEMPLATE_DEBUG_BASIC 0x01

#define PATH_TEMPLATE_DEBUG(fmt, ...)                                          \
	do {                                                                   \
		if (DEBUG_FLAGS_CHECK(&path_template_debug,                    \
				      PATH_TEMPLATE_DEBUG_BASIC))              \
			DEBUGD(&path_template_debug, "template: " fmt,         \
			       ##__VA_ARGS__);                                 \
	} while (0)

/* Configured candidate path */
struct srte_candidate_template {
	RB_ENTRY(srte_candidate_template) entry;

	/* Backpointer to SR Policy */
	struct srte_policy_template *policy;

	/* Administrative preference. */
	uint32_t preference;

	/* Symbolic Name. */
	char name[64];

	/* The Protocol-Origin. */
	enum srte_protocol_origin protocol_origin;

	/* The Originator */
	char originator[64];

	/* The Type (explicit or dynamic) */
	enum srte_candidate_type type;

	/* Flags. */
	uint32_t flags;

	/* Hooks delaying timer */
	struct thread *hook_timer;

	/* Flex-algo number for flex-algo type */
	uint8_t flex_algo_number;
};

RB_HEAD(srte_candidate_template_head, srte_candidate_template);
RB_PROTOTYPE(srte_candidate_template_head, srte_candidate_template, entry,
	     srte_candidate_compare)

RB_HEAD(srte_policy_template_head, srte_policy_template);
RB_PROTOTYPE(srte_policy_template_head, srte_policy_template, entry,
	     srte_policy_template_compare)

struct srte_policy_template {
	RB_ENTRY(srte_policy_template) entry;

	/* Color */
	uint32_t color;

	/* Name */
	char name[53];

	/* Candidate Paths */
	struct srte_candidate_template_head candidate_paths;
	/* Status flags. */
	uint16_t flags;

	/* when template is instantiated, used for policy naming */
	uint16_t counter;
};

extern struct srte_policy_template_head srte_policies_template;

struct srte_policy_template *srte_policy_template_add(uint32_t color);
void srte_policy_template_del(struct srte_policy_template *policy);
struct srte_policy_template *srte_policy_template_find(uint32_t color);
void srte_policy_template_apply_changes(struct srte_policy_template *policy);
struct srte_candidate_template *
srte_candidate_template_add(struct srte_policy_template *policy,
			    uint32_t preference);
void srte_candidate_template_del(struct srte_candidate_template *candidate);
struct srte_candidate_template *
srte_candidate_template_find(struct srte_policy_template *policy,
			     uint32_t preference);

void srte_template_clean_zebra(void);
void srte_template_apply_changes(void);
void srte_template_show_debugging(struct vty *vty);

void srte_template_update_tsrte(void);
enum srte_protocol_origin srte_template_get_protocol_origin(void);

#endif
