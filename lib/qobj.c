/*
 * Copyright (c) 2015-16  David Lamparter, for NetDEF, Inc.
 *
 * This file is part of Quagga
 *
 * Quagga is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2, or (at your option) any
 * later version.
 *
 * Quagga is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; see the file COPYING; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA
 */

#include <zebra.h>

#include "thread.h"
#include "memory.h"
#include "hash.h"
#include "log.h"
#include "qobj.h"
#include "jhash.h"

static pthread_rwlock_t nodes_lock;
static struct hash *nodes = NULL;

static unsigned int qobj_key(void *data)
{
	struct qobj_node *node = data;
	return (unsigned int)node->nid;
}

static int qobj_cmp(const void *a, const void *b)
{
	const struct qobj_node *na = a, *nb = b;
	return na->nid == nb->nid;
}

void qobj_reg(struct qobj_node *node, struct qobj_nodetype *type)
{
	node->type = type;
	pthread_rwlock_wrlock(&nodes_lock);
	do {
		node->nid = (uint64_t)random();
		node->nid ^= (uint64_t)random() << 32;
	} while (!node->nid
		 || hash_get(nodes, node, hash_alloc_intern) != node);
	pthread_rwlock_unlock(&nodes_lock);
}

void qobj_unreg(struct qobj_node *node)
{
	pthread_rwlock_wrlock(&nodes_lock);
	hash_release(nodes, node);
	pthread_rwlock_unlock(&nodes_lock);
}

struct qobj_node *qobj_get(uint64_t id)
{
	struct qobj_node dummy = {.nid = id}, *rv;
	pthread_rwlock_rdlock(&nodes_lock);
	rv = hash_lookup(nodes, &dummy);
	pthread_rwlock_unlock(&nodes_lock);
	return rv;
}

void *qobj_get_typed(uint64_t id, struct qobj_nodetype *type)
{
	struct qobj_node dummy = {.nid = id};
	struct qobj_node *node;
	void *rv;

	pthread_rwlock_rdlock(&nodes_lock);
	node = hash_lookup(nodes, &dummy);

	/* note: we explicitly hold the lock until after we have checked the
	 * type.
	 * if the caller holds a lock that for example prevents the deletion of
	 * route-maps, we can still race against a delete of something that
	 * isn't
	 * a route-map. */
	if (!node || node->type != type)
		rv = NULL;
	else
		rv = (char *)node - node->type->node_member_offset;

	pthread_rwlock_unlock(&nodes_lock);
	return rv;
}

void qobj_init(void)
{
	if (!nodes) {
		pthread_rwlock_init(&nodes_lock, NULL);
		nodes = hash_create_size(16, qobj_key, qobj_cmp, "QOBJ Hash");
	}
}

void qobj_finish(void)
{
	hash_clean(nodes, NULL);
	hash_free(nodes);
	nodes = NULL;
	pthread_rwlock_destroy(&nodes_lock);
}
