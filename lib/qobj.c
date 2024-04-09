// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright (c) 2015-16  David Lamparter, for NetDEF, Inc.
 *
 * This file is part of Quagga
 */

#include <zebra.h>

#include "frrevent.h"
#include "memory.h"
#include "hash.h"
#include "log.h"
#include "qobj.h"
#include "jhash.h"
#include "network.h"

static uint32_t qobj_hash(const struct qobj_node *node)
{
	return (uint32_t)node->nid;
}

static int qobj_cmp(const struct qobj_node *na, const struct qobj_node *nb)
{
	if (na->nid < nb->nid)
		return -1;
	if (na->nid > nb->nid)
		return 1;
	return 0;
}

DECLARE_HASH(qobj_nodes, struct qobj_node, nodehash,
			qobj_cmp, qobj_hash);

static pthread_rwlock_t nodes_lock;
static struct qobj_nodes_head nodes = { };


void qobj_reg(struct qobj_node *node, const struct qobj_nodetype *type)
{
	node->type = type;
	pthread_rwlock_wrlock(&nodes_lock);
	do {
		node->nid = (uint64_t)frr_weak_random();
		node->nid ^= (uint64_t)frr_weak_random() << 32;
	} while (!node->nid || qobj_nodes_find(&nodes, node));
	qobj_nodes_add(&nodes, node);
	pthread_rwlock_unlock(&nodes_lock);
}

void qobj_unreg(struct qobj_node *node)
{
	pthread_rwlock_wrlock(&nodes_lock);
	qobj_nodes_del(&nodes, node);
	pthread_rwlock_unlock(&nodes_lock);
}

struct qobj_node *qobj_get(uint64_t id)
{
	struct qobj_node dummy = {.nid = id}, *rv;
	pthread_rwlock_rdlock(&nodes_lock);
	rv = qobj_nodes_find(&nodes, &dummy);
	pthread_rwlock_unlock(&nodes_lock);
	return rv;
}

void *qobj_get_typed(uint64_t id, const struct qobj_nodetype *type)
{
	struct qobj_node dummy = {.nid = id};
	struct qobj_node *node;
	void *rv;

	pthread_rwlock_rdlock(&nodes_lock);
	node = qobj_nodes_find(&nodes, &dummy);

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
	pthread_rwlock_init(&nodes_lock, NULL);
	qobj_nodes_init(&nodes);
}

void qobj_finish(void)
{
	struct qobj_node *node;
	while ((node = qobj_nodes_pop(&nodes)))
		qobj_nodes_del(&nodes, node);
	pthread_rwlock_destroy(&nodes_lock);
}
