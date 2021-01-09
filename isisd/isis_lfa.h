/*
 * Copyright (C) 2020  NetDEF, Inc.
 *                     Renato Westphal
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

#ifndef _FRR_ISIS_LFA_H
#define _FRR_ISIS_LFA_H

#include "lib/typesafe.h"

PREDECL_RBTREE_UNIQ(lfa_tiebreaker_tree)

enum lfa_tiebreaker_type {
	LFA_TIEBREAKER_DOWNSTREAM = 0,
	LFA_TIEBREAKER_LOWEST_METRIC,
	LFA_TIEBREAKER_NODE_PROTECTING,
};

struct lfa_tiebreaker {
	struct lfa_tiebreaker_tree_item entry;
	uint8_t index;
	enum lfa_tiebreaker_type type;
	struct isis_area *area;
};
int lfa_tiebreaker_cmp(const struct lfa_tiebreaker *a,
		       const struct lfa_tiebreaker *b);
DECLARE_RBTREE_UNIQ(lfa_tiebreaker_tree, struct lfa_tiebreaker, entry,
		    lfa_tiebreaker_cmp)

enum isis_tilfa_sid_type {
	TILFA_SID_PREFIX = 1,
	TILFA_SID_ADJ,
};

struct isis_tilfa_sid {
	enum isis_tilfa_sid_type type;
	union {
		struct {
			uint32_t value;
			bool remote;
			uint8_t remote_sysid[ISIS_SYS_ID_LEN];
		} index;
		mpls_label_t label;
	} value;
};

enum spf_prefix_priority {
	SPF_PREFIX_PRIO_CRITICAL = 0,
	SPF_PREFIX_PRIO_HIGH,
	SPF_PREFIX_PRIO_MEDIUM,
	SPF_PREFIX_PRIO_LOW,
	SPF_PREFIX_PRIO_MAX,
};

struct spf_prefix_priority_acl {
	char *name;
	struct access_list *list_v4;
	struct access_list *list_v6;
};

RB_HEAD(isis_spf_nodes, isis_spf_node);
RB_PROTOTYPE(isis_spf_nodes, isis_spf_node, entry, isis_spf_node_compare)
struct isis_spf_node {
	RB_ENTRY(isis_spf_node) entry;

	/* Node's System ID. */
	uint8_t sysid[ISIS_SYS_ID_LEN];

	/* Local adjacencies over which this node is reachable. */
	struct list *adjacencies;

	/* Best metric of all adjacencies used to reach this node. */
	uint32_t best_metric;

	struct {
		/* Node's forward SPT. */
		struct isis_spftree *spftree;

		/* Node's reverse SPT. */
		struct isis_spftree *spftree_reverse;

		/* Node's P-space. */
		struct isis_spf_nodes p_space;
	} lfa;
};

enum lfa_protection_type {
	LFA_LINK_PROTECTION = 1,
	LFA_NODE_PROTECTION,
};

struct lfa_protected_resource {
	/* The protection type. */
	enum lfa_protection_type type;

	/* The protected adjacency (might be a pseudonode). */
	uint8_t adjacency[ISIS_SYS_ID_LEN + 1];

	/* List of nodes reachable over the protected interface. */
	struct isis_spf_nodes nodes;
};

/* Forward declaration(s). */
struct isis_vertex;

/* Prototypes. */
void isis_spf_node_list_init(struct isis_spf_nodes *nodes);
void isis_spf_node_list_clear(struct isis_spf_nodes *nodes);
struct isis_spf_node *isis_spf_node_new(struct isis_spf_nodes *nodes,
					const uint8_t *sysid);
struct isis_spf_node *isis_spf_node_find(const struct isis_spf_nodes *nodes,
					 const uint8_t *sysid);
void isis_lfa_tiebreakers_init(struct isis_area *area, int level);
void isis_lfa_tiebreakers_clear(struct isis_area *area, int level);
struct lfa_tiebreaker *isis_lfa_tiebreaker_add(struct isis_area *area,
					       int level, uint8_t index,
					       enum lfa_tiebreaker_type type);
void isis_lfa_tiebreaker_delete(struct isis_area *area, int level,
				struct lfa_tiebreaker *tie_b);
void isis_lfa_excluded_ifaces_init(struct isis_circuit *circuit, int level);
void isis_lfa_excluded_ifaces_clear(struct isis_circuit *circuit, int level);
void isis_lfa_excluded_iface_add(struct isis_circuit *circuit, int level,
				 const char *ifname);
void isis_lfa_excluded_iface_delete(struct isis_circuit *circuit, int level,
				    const char *ifname);
bool isis_lfa_excluded_iface_check(struct isis_circuit *circuit, int level,
				   const char *ifname);
bool isis_lfa_excise_adj_check(const struct isis_spftree *spftree,
			       const uint8_t *id);
bool isis_lfa_excise_node_check(const struct isis_spftree *spftree,
				const uint8_t *id);
struct isis_spftree *isis_spf_reverse_run(const struct isis_spftree *spftree);
int isis_spf_run_neighbors(struct isis_spftree *spftree);
void isis_lfa_compute(struct isis_area *area, struct isis_circuit *circuit,
		      struct isis_spftree *spftree,
		      struct lfa_protected_resource *resource);
void isis_spf_run_lfa(struct isis_area *area, struct isis_spftree *spftree);
int isis_tilfa_check(struct isis_spftree *spftree, struct isis_vertex *vertex);
struct isis_spftree *
isis_tilfa_compute(struct isis_area *area, struct isis_spftree *spftree,
		   struct isis_spftree *spftree_reverse,
		   struct lfa_protected_resource *protected_resource);

#endif /* _FRR_ISIS_LFA_H */
