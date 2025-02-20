// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * IS-IS Rout(e)ing protocol - isis_spf.h
 *                             IS-IS Shortest Path First algorithm
 *
 * Copyright (C) 2001,2002   Sampo Saaristo
 *                           Tampere University of Technology
 *                           Institute of Communications Engineering
 */

#ifndef _ZEBRA_ISIS_SPF_H
#define _ZEBRA_ISIS_SPF_H

#include "isisd/isis_lfa.h"
#include "lib/json.h"

struct isis_spftree;

enum spf_type {
	SPF_TYPE_FORWARD = 1,
	SPF_TYPE_REVERSE,
	SPF_TYPE_RLFA,
	SPF_TYPE_TI_LFA,
};

struct isis_spf_adj {
	uint8_t id[ISIS_SYS_ID_LEN + 1];
	struct isis_adjacency *adj;
	uint32_t metric;
	struct isis_ext_subtlvs *subtlvs;
	struct isis_lsp *lsp;
	struct {
		uint8_t desig_is_id[ISIS_SYS_ID_LEN + 1];
	} lan;
	uint8_t flags;
#define F_ISIS_SPF_ADJ_BROADCAST 0x01
#define F_ISIS_SPF_ADJ_OLDMETRIC 0x02
#define F_ISIS_SPF_ADJ_METRIC_INFINITY 0x04
};

struct isis_spftree *
isis_spftree_new(struct isis_area *area, struct lspdb_head *lspdb,
		 const uint8_t *sysid, int level, enum spf_tree_id tree_id,
		 enum spf_type type, uint8_t flags, uint8_t algorithm);
struct isis_vertex *isis_spf_prefix_sid_lookup(struct isis_spftree *spftree,
					       struct isis_prefix_sid *psid);
void isis_spf_invalidate_routes(struct isis_spftree *tree);
void isis_spf_verify_routes(struct isis_area *area, struct isis_spftree **trees,
			    int tree);
void isis_spf_switchover_routes(struct isis_area *area,
				struct isis_spftree **trees, int family,
				union g_addr *nexthop_ip, ifindex_t ifindex,
				int level);
void isis_spftree_del(struct isis_spftree *spftree);
void spftree_area_init(struct isis_area *area);
void spftree_area_del(struct isis_area *area);
struct isis_lsp *isis_root_system_lsp(struct lspdb_head *lspdb,
				      const uint8_t *sysid);
#define isis_spf_schedule(area, level) \
	_isis_spf_schedule((area), (level), __func__, \
			   __FILE__, __LINE__)
int _isis_spf_schedule(struct isis_area *area, int level,
		       const char *func, const char *file, int line);
void isis_print_spftree(struct vty *vty, struct isis_spftree *spftree,
			struct json_object **json);
void isis_print_routes(struct vty *vty, struct isis_spftree *spftree,
		       json_object **json, bool prefix_sid, bool backup);
void isis_spf_init(void);
void isis_spf_print(struct isis_spftree *spftree, struct vty *vty);
void isis_spf_print_json(struct isis_spftree *spftree,
			 struct json_object *json);
void isis_run_spf(struct isis_spftree *spftree);
struct isis_spftree *isis_run_hopcount_spf(struct isis_area *area,
					   uint8_t *sysid,
					   struct isis_spftree *spftree);

void isis_spf_timer_free(void *run);
#endif /* _ZEBRA_ISIS_SPF_H */
