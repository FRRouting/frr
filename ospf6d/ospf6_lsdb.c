/*
 * Copyright (C) 2003 Yasuhiro Ohara
 *
 * This file is part of GNU Zebra.
 *
 * GNU Zebra is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2, or (at your option) any
 * later version.
 *
 * GNU Zebra is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; see the file COPYING; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA
 */

#include <zebra.h>

#include "memory.h"
#include "log.h"
#include "command.h"
#include "prefix.h"
#include "table.h"
#include "vty.h"

#include "ospf6_proto.h"
#include "ospf6_lsa.h"
#include "ospf6_lsdb.h"
#include "ospf6_route.h"
#include "ospf6d.h"
#include "bitfield.h"

struct ospf6_lsdb *ospf6_lsdb_create(void *data)
{
	struct ospf6_lsdb *lsdb;

	lsdb = XCALLOC(MTYPE_OSPF6_LSDB, sizeof(struct ospf6_lsdb));
	if (lsdb == NULL) {
		zlog_warn("Can't malloc lsdb");
		return NULL;
	}
	memset(lsdb, 0, sizeof(struct ospf6_lsdb));

	lsdb->data = data;
	lsdb->table = route_table_init();
	return lsdb;
}

void ospf6_lsdb_delete(struct ospf6_lsdb *lsdb)
{
	if (lsdb != NULL) {
		ospf6_lsdb_remove_all(lsdb);
		route_table_finish(lsdb->table);
		XFREE(MTYPE_OSPF6_LSDB, lsdb);
	}
}

static void ospf6_lsdb_set_key(struct prefix_ipv6 *key, const void *value,
			       int len)
{
	assert(key->prefixlen % 8 == 0);

	memcpy((caddr_t)&key->prefix + key->prefixlen / 8, (caddr_t)value, len);
	key->family = AF_INET6;
	key->prefixlen += len * 8;
}

#ifdef DEBUG
static void _lsdb_count_assert(struct ospf6_lsdb *lsdb)
{
	struct ospf6_lsa *debug;
	unsigned int num = 0;
	for (ALL_LSDB(lsdb, debug))
		num++;

	if (num == lsdb->count)
		return;

	zlog_debug("PANIC !! lsdb[%p]->count = %d, real = %d", lsdb,
		   lsdb->count, num);
	for (ALL_LSDB(lsdb, debug))
		zlog_debug("%s lsdb[%p]", debug->name, debug->lsdb);
	zlog_debug("DUMP END");

	assert(num == lsdb->count);
}
#define ospf6_lsdb_count_assert(t) (_lsdb_count_assert (t))
#else  /*DEBUG*/
#define ospf6_lsdb_count_assert(t) ((void) 0)
#endif /*DEBUG*/

void ospf6_lsdb_add(struct ospf6_lsa *lsa, struct ospf6_lsdb *lsdb)
{
	struct prefix_ipv6 key;
	struct route_node *current;
	struct ospf6_lsa *old = NULL;

	memset(&key, 0, sizeof(key));
	ospf6_lsdb_set_key(&key, &lsa->header->type, sizeof(lsa->header->type));
	ospf6_lsdb_set_key(&key, &lsa->header->adv_router,
			   sizeof(lsa->header->adv_router));
	ospf6_lsdb_set_key(&key, &lsa->header->id, sizeof(lsa->header->id));

	current = route_node_get(lsdb->table, (struct prefix *)&key);
	old = current->info;
	current->info = lsa;
	lsa->rn = current;
	ospf6_lsa_lock(lsa);

	if (!old) {
		lsdb->count++;

		if (OSPF6_LSA_IS_MAXAGE(lsa)) {
			if (lsdb->hook_remove)
				(*lsdb->hook_remove)(lsa);
		} else {
			if (lsdb->hook_add)
				(*lsdb->hook_add)(lsa);
		}
	} else {
		if (OSPF6_LSA_IS_CHANGED(old, lsa)) {
			if (OSPF6_LSA_IS_MAXAGE(lsa)) {
				if (lsdb->hook_remove) {
					(*lsdb->hook_remove)(old);
					(*lsdb->hook_remove)(lsa);
				}
			} else if (OSPF6_LSA_IS_MAXAGE(old)) {
				if (lsdb->hook_add)
					(*lsdb->hook_add)(lsa);
			} else {
				if (lsdb->hook_remove)
					(*lsdb->hook_remove)(old);
				if (lsdb->hook_add)
					(*lsdb->hook_add)(lsa);
			}
		}
		/* to free the lookup lock in node get*/
		route_unlock_node(current);
		ospf6_lsa_unlock(old);
	}

	ospf6_lsdb_count_assert(lsdb);
}

void ospf6_lsdb_remove(struct ospf6_lsa *lsa, struct ospf6_lsdb *lsdb)
{
	struct route_node *node;
	struct prefix_ipv6 key;

	memset(&key, 0, sizeof(key));
	ospf6_lsdb_set_key(&key, &lsa->header->type, sizeof(lsa->header->type));
	ospf6_lsdb_set_key(&key, &lsa->header->adv_router,
			   sizeof(lsa->header->adv_router));
	ospf6_lsdb_set_key(&key, &lsa->header->id, sizeof(lsa->header->id));

	node = route_node_lookup(lsdb->table, (struct prefix *)&key);
	assert(node && node->info == lsa);

	node->info = NULL;
	lsdb->count--;

	if (lsdb->hook_remove)
		(*lsdb->hook_remove)(lsa);

	route_unlock_node(node); /* to free the lookup lock */
	route_unlock_node(node); /* to free the original lock */
	ospf6_lsa_unlock(lsa);

	ospf6_lsdb_count_assert(lsdb);
}

struct ospf6_lsa *ospf6_lsdb_lookup(uint16_t type, uint32_t id,
				    uint32_t adv_router,
				    struct ospf6_lsdb *lsdb)
{
	struct route_node *node;
	struct prefix_ipv6 key;

	if (lsdb == NULL)
		return NULL;

	memset(&key, 0, sizeof(key));
	ospf6_lsdb_set_key(&key, &type, sizeof(type));
	ospf6_lsdb_set_key(&key, &adv_router, sizeof(adv_router));
	ospf6_lsdb_set_key(&key, &id, sizeof(id));

	node = route_node_lookup(lsdb->table, (struct prefix *)&key);
	if (node == NULL || node->info == NULL)
		return NULL;

	route_unlock_node(node);
	return (struct ospf6_lsa *)node->info;
}

struct ospf6_lsa *ospf6_lsdb_lookup_next(uint16_t type, uint32_t id,
					 uint32_t adv_router,
					 struct ospf6_lsdb *lsdb)
{
	struct route_node *node;
	struct prefix_ipv6 key;

	if (lsdb == NULL)
		return NULL;

	memset(&key, 0, sizeof(key));
	ospf6_lsdb_set_key(&key, &type, sizeof(type));
	ospf6_lsdb_set_key(&key, &adv_router, sizeof(adv_router));
	ospf6_lsdb_set_key(&key, &id, sizeof(id));

	{
		char buf[PREFIX2STR_BUFFER];
		prefix2str(&key, buf, sizeof(buf));
		zlog_debug("lsdb_lookup_next: key: %s", buf);
	}

	node = route_table_get_next(lsdb->table, &key);

	/* skip to real existing entry */
	while (node && node->info == NULL)
		node = route_next(node);

	if (!node)
		return NULL;

	route_unlock_node(node);
	if (!node->info)
		return NULL;

	return (struct ospf6_lsa *)node->info;
}

const struct route_node *ospf6_lsdb_head(struct ospf6_lsdb *lsdb, int argmode,
					 uint16_t type, uint32_t adv_router,
					 struct ospf6_lsa **lsa)
{
	struct route_node *node, *end;

	*lsa = NULL;

	if (argmode > 0) {
		struct prefix_ipv6 key = {.family = AF_INET6, .prefixlen = 0};

		ospf6_lsdb_set_key(&key, &type, sizeof(type));
		if (argmode > 1)
			ospf6_lsdb_set_key(&key, &adv_router,
					   sizeof(adv_router));

		node = route_table_get_next(lsdb->table, &key);
		if (!node || !prefix_match((struct prefix *)&key, &node->p))
			return NULL;

		for (end = node; end && end->parent
				 && end->parent->p.prefixlen >= key.prefixlen;
		     end = end->parent)
			;
	} else {
		node = route_top(lsdb->table);
		end = NULL;
	}

	while (node && !node->info)
		node = route_next_until(node, end);

	if (!node)
		return NULL;
	if (!node->info) {
		route_unlock_node(node);
		return NULL;
	}

	*lsa = node->info;
	ospf6_lsa_lock(*lsa);

	return end;
}

struct ospf6_lsa *ospf6_lsdb_next(const struct route_node *iterend,
				  struct ospf6_lsa *lsa)
{
	struct route_node *node = lsa->rn;

	ospf6_lsa_unlock(lsa);

	do
		node = route_next_until(node, iterend);
	while (node && !node->info);

	if (node && node->info) {
		struct ospf6_lsa *next = node->info;
		ospf6_lsa_lock(next);
		return next;
	}

	if (node)
		route_unlock_node(node);
	return NULL;
}

void ospf6_lsdb_remove_all(struct ospf6_lsdb *lsdb)
{
	struct ospf6_lsa *lsa;

	if (lsdb == NULL)
		return;

	for (ALL_LSDB(lsdb, lsa))
		ospf6_lsdb_remove(lsa, lsdb);
}

void ospf6_lsdb_lsa_unlock(struct ospf6_lsa *lsa)
{
	if (lsa != NULL) {
		if (lsa->rn != NULL)
			route_unlock_node(lsa->rn);
		ospf6_lsa_unlock(lsa);
	}
}

int ospf6_lsdb_maxage_remover(struct ospf6_lsdb *lsdb)
{
	int reschedule = 0;
	struct ospf6_lsa *lsa;

	for (ALL_LSDB(lsdb, lsa)) {
		if (!OSPF6_LSA_IS_MAXAGE(lsa))
			continue;
		if (lsa->retrans_count != 0) {
			reschedule = 1;
			continue;
		}
		if (IS_OSPF6_DEBUG_LSA_TYPE(lsa->header->type))
			zlog_debug("Remove MaxAge %s", lsa->name);

		if (CHECK_FLAG(lsa->flag, OSPF6_LSA_SEQWRAPPED)) {
			UNSET_FLAG(lsa->flag, OSPF6_LSA_SEQWRAPPED);
			/*
			 * lsa->header->age = 0;
			 */
			lsa->header->seqnum =
				htonl(OSPF_MAX_SEQUENCE_NUMBER + 1);
			ospf6_lsa_checksum(lsa->header);

			THREAD_OFF(lsa->refresh);
			thread_execute(master, ospf6_lsa_refresh, lsa, 0);
		} else {
			ospf6_lsdb_remove(lsa, lsdb);
		}
	}

	return (reschedule);
}

void ospf6_lsdb_show(struct vty *vty, enum ospf_lsdb_show_level level,
		     uint16_t *type, uint32_t *id, uint32_t *adv_router,
		     struct ospf6_lsdb *lsdb)
{
	struct ospf6_lsa *lsa;
	const struct route_node *end = NULL;
	void (*showfunc)(struct vty *, struct ospf6_lsa *) = NULL;

	switch (level) {
	case OSPF6_LSDB_SHOW_LEVEL_DETAIL:
		showfunc = ospf6_lsa_show;
		break;
	case OSPF6_LSDB_SHOW_LEVEL_INTERNAL:
		showfunc = ospf6_lsa_show_internal;
		break;
	case OSPF6_LSDB_SHOW_LEVEL_DUMP:
		showfunc = ospf6_lsa_show_dump;
		break;
	case OSPF6_LSDB_SHOW_LEVEL_NORMAL:
	default:
		showfunc = ospf6_lsa_show_summary;
	}

	if (type && id && adv_router) {
		lsa = ospf6_lsdb_lookup(*type, *id, *adv_router, lsdb);
		if (lsa) {
			if (level == OSPF6_LSDB_SHOW_LEVEL_NORMAL)
				ospf6_lsa_show(vty, lsa);
			else
				(*showfunc)(vty, lsa);
		}
		return;
	}

	if (level == OSPF6_LSDB_SHOW_LEVEL_NORMAL)
		ospf6_lsa_show_summary_header(vty);

	end = ospf6_lsdb_head(lsdb, !!type + !!(type && adv_router),
			      type ? *type : 0, adv_router ? *adv_router : 0,
			      &lsa);
	while (lsa) {
		if ((!adv_router || lsa->header->adv_router == *adv_router)
		    && (!id || lsa->header->id == *id))
			(*showfunc)(vty, lsa);

		lsa = ospf6_lsdb_next(end, lsa);
	}
}

uint32_t ospf6_new_ls_id(uint16_t type, uint32_t adv_router,
			 struct ospf6_lsdb *lsdb)
{
	struct ospf6_lsa *lsa;
	uint32_t id = 1, tmp_id;

	/* This routine is curently invoked only for Inter-Prefix LSAs for
	 * non-summarized routes (no area/range).
	 */
	for (ALL_LSDB_TYPED_ADVRTR(lsdb, type, adv_router, lsa)) {
		tmp_id = ntohl(lsa->header->id);
		if (tmp_id < id)
			continue;

		if (tmp_id > id) {
			ospf6_lsdb_lsa_unlock(lsa);
			break;
		}
		id++;
	}

	return ((uint32_t)htonl(id));
}

/* Decide new LS sequence number to originate.
   note return value is network byte order */
uint32_t ospf6_new_ls_seqnum(uint16_t type, uint32_t id, uint32_t adv_router,
			     struct ospf6_lsdb *lsdb)
{
	struct ospf6_lsa *lsa;
	signed long seqnum = 0;

	/* if current database copy not found, return InitialSequenceNumber */
	lsa = ospf6_lsdb_lookup(type, id, adv_router, lsdb);
	if (lsa == NULL)
		seqnum = OSPF_INITIAL_SEQUENCE_NUMBER;
	else
		seqnum = (signed long)ntohl(lsa->header->seqnum) + 1;

	return ((uint32_t)htonl(seqnum));
}
