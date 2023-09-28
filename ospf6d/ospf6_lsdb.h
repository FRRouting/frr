// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright (C) 2003 Yasuhiro Ohara
 */

#ifndef OSPF6_LSDB_H
#define OSPF6_LSDB_H

#include "prefix.h"
#include "table.h"
#include "ospf6_route.h"

struct ospf6_lsdb {
	void *data; /* data structure that holds this lsdb */
	struct route_table *table;
	uint32_t count;
	uint32_t stats[OSPF6_LSTYPE_SIZE];
	void (*hook_add)(struct ospf6_lsa *);
	void (*hook_remove)(struct ospf6_lsa *);
};

/* Function Prototypes */
extern struct ospf6_lsdb *ospf6_lsdb_create(void *data);
extern void ospf6_lsdb_delete(struct ospf6_lsdb *lsdb);

extern struct ospf6_lsa *ospf6_lsdb_lookup(uint16_t type, uint32_t id,
					   uint32_t adv_router,
					   struct ospf6_lsdb *lsdb);
extern struct ospf6_lsa *ospf6_lsdb_lookup_next(uint16_t type, uint32_t id,
						uint32_t adv_router,
						struct ospf6_lsdb *lsdb);
extern struct ospf6_lsa *ospf6_find_inter_prefix_lsa(struct ospf6 *ospf6,
						     struct ospf6_area *area,
						     struct prefix *p);

extern void ospf6_lsdb_add(struct ospf6_lsa *lsa, struct ospf6_lsdb *lsdb);
extern void ospf6_lsdb_remove(struct ospf6_lsa *lsa, struct ospf6_lsdb *lsdb);

extern const struct route_node *ospf6_lsdb_head(struct ospf6_lsdb *lsdb,
						int argmode, uint16_t type,
						uint32_t adv_router,
						struct ospf6_lsa **lsa);
extern struct ospf6_lsa *ospf6_lsdb_next(const struct route_node *iterend,
					 struct ospf6_lsa *lsa);

#define ALL_LSDB_TYPED_ADVRTR(lsdb, type, adv_router, lsa)                     \
	const struct route_node *iterend =                                     \
		ospf6_lsdb_head(lsdb, 2, type, adv_router, &lsa);              \
	lsa;                                                                   \
	lsa = ospf6_lsdb_next(iterend, lsa)

#define ALL_LSDB_TYPED(lsdb, type, lsa)                                        \
	const struct route_node *iterend =                                     \
		ospf6_lsdb_head(lsdb, 1, type, 0, &lsa);                       \
	lsa;                                                                   \
	lsa = ospf6_lsdb_next(iterend, lsa)

/*
 * Since we are locking the lsa in ospf6_lsdb_head
 * and then unlocking it in ospf6_lsa_unlock, when
 * we cache the next pointer we need to increment
 * the lock for the lsa so we don't accidentally free
 * it really early.
 */
#define ALL_LSDB(lsdb, lsa, lsanext)                                           \
	const struct route_node *iterend = ospf6_lsdb_head(lsdb, 0, 0, 0,      \
							   &lsa);              \
	(lsa) != NULL && ospf6_lsa_lock(lsa) &&                                \
		((lsanext) = ospf6_lsdb_next(iterend, (lsa)), 1);              \
	ospf6_lsa_unlock(&lsa), (lsa) = (lsanext)

extern void ospf6_lsdb_remove_all(struct ospf6_lsdb *lsdb);
extern void ospf6_lsdb_lsa_unlock(struct ospf6_lsa *lsa);

enum ospf_lsdb_show_level {
	OSPF6_LSDB_SHOW_LEVEL_NORMAL = 0,
	OSPF6_LSDB_SHOW_LEVEL_DETAIL,
	OSPF6_LSDB_SHOW_LEVEL_INTERNAL,
	OSPF6_LSDB_SHOW_LEVEL_DUMP,
};

extern void ospf6_lsdb_show(struct vty *vty, enum ospf_lsdb_show_level level,
			    uint16_t *type, uint32_t *id, uint32_t *adv_router,
			    struct ospf6_lsdb *lsdb, json_object *json,
			    bool use_json);

extern uint32_t ospf6_new_ls_id(uint16_t type, uint32_t adv_router,
				struct ospf6_lsdb *lsdb);
extern uint32_t ospf6_new_ls_seqnum(uint16_t type, uint32_t id,
				    uint32_t adv_router,
				    struct ospf6_lsdb *lsdb);
extern int ospf6_lsdb_maxage_remover(struct ospf6_lsdb *lsdb);

#endif /* OSPF6_LSDB_H */
