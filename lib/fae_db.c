/* Flex-Algo IGP Endpoint Tracking Database
 *
 * Copyright 2022 6WIND S.A.
 *
 * This file is part of FRRouting.
 *
 * FRRouting is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2, or (at your option) any
 * later version.
 *
 * FRRouting is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; see the file COPYING; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA
 */

#include <zebra.h>
#include "ipaddr.h"
#include "segment_routing.h"
#include "fae_db.h"

DEFINE_MTYPE_STATIC(LIB, FAE_DB_TABLE, "Flex-Algo Endpoint Tracking Table");
DEFINE_MTYPE_STATIC(LIB, FAE_DB_NODE,
		    "Flex-Algo Endpoint Tracking Registration Node");

static int fae_db_entry_cmp_func(const struct fae_db_node *,
				 const struct fae_db_node *);

RB_GENERATE(fae_db_head, fae_db_node, entry, fae_db_entry_cmp_func);

/* Allocate an array of SR_ALGORITHM_COUNT struct 'fae_db_head's and
 * initialize.  These store Flex-Algo endpoint-tracking registrations.
 */
struct fae_db_head *fae_db_init(void)
{
	struct fae_db_head *db;

	db = XCALLOC(MTYPE_FAE_DB_TABLE,
		     SR_ALGORITHM_COUNT * sizeof(struct fae_db_head));
	return db;
}

/* Insert an endpoint-tracking registration.  If a matching entry
 * is found, return that entry.  Otherwise, add this registration to
 * the table.
 *
 * @param table		endpoint tracking database
 * @param endpoint	endpoint IP address from registration zapi message
 * @param client	numeric identifier for a particular client
 *			daemon/session IDs
 * @param dup		set to 1 if an existing registration was found, set to
 *			0 if new registration.
 *
 * @return		pointer to new or existing node, or NULL on error.
 *			If returning NULL, dup is not changed.
 */
struct fae_db_node *fae_db_insert(struct fae_db_head *table,
				  const struct ipaddr *const endpoint,
				  unsigned char client, int *dup)
{
	/* Look for entry with this (id, address).  If found,
	 * check if this particular client has already registered.
	 * If not, append this registration.  Return pointer to the node.
	 */

	struct fae_db_node tmp;
	struct fae_db_node *node;

	tmp.endpoint = *endpoint;
	node = RB_FIND(fae_db_head, table, &tmp);
	if (node) {
		if (node->num_clients >= FAE_DB_MAX_CLIENTS)
			/* No room for more clients */
			goto err;
		for (unsigned i = 0; i < node->num_clients; i++) {
			if (node->client[i] == client) {
				*dup = 1;
				return node;
			}
		}
	} else {
		node = XCALLOC(MTYPE_FAE_DB_NODE, sizeof(*node));
		node->num_clients = 0;
		node->endpoint = *endpoint;
		RB_INSERT(fae_db_head, table, node);
	}

	node->client[node->num_clients++] = client;
	*dup = 0;

	return node;
err:
	zlog_err("Unable to add FAE registration");
	return NULL;
}

/* Move an endpoint-tracking registration to a different table.
 *
 * @param dst		destination endpoint tracking database.  Move to
 *			this table.
 * @param src		source endpoint tracking database.  Move from
 *			this table.
 * @param node		item to move
 *
 * @return		pointer to node parameter on success, pointer
 *			to an existing node in the target tree matching
 *			the contents of the node parameter.
 */
struct fae_db_node *fae_db_move(struct fae_db_head *dst,
				struct fae_db_head *src,
				struct fae_db_node *node)
{
	struct fae_db_node *conflict;

	conflict = RB_FIND(fae_db_head, dst, node);
	if (conflict)
		return conflict;

	RB_REMOVE(fae_db_head, src, node);
	RB_INSERT(fae_db_head, dst, node);
	return node;
}

struct fae_db_node *fae_db_node_delete(struct fae_db_head *table,
				       struct fae_db_node *node,
				       unsigned char client)
{
	unsigned i;

	for (i = 0; i < node->num_clients; i++) {
		if (node->client[i] == client)
			break;
	}
	if (i == node->num_clients)
		return NULL;

	/* Shift the remaining values down */
	node->num_clients--;
	for (; i < node->num_clients; i++)
		node->client[i] = node->client[i + 1];

	if (node->num_clients == 0)
		RB_REMOVE(fae_db_head, table, node);

	return node;
}

/* Remove an endpoint-tracking registration.
 *
 * @param table		endpoint tracking database
 * @param endpoint	endpoint IP address from registration zapi message
 * @param client	numeric identifier for a particular client
 *			daemon/session IDs
 *
 * @return		pointer to node if updated/removed, NULL if not found
 */
struct fae_db_node *fae_db_delete(struct fae_db_head *table,
				  const struct ipaddr *const endpoint,
				  unsigned char client)
{
	struct fae_db_node tmp;
	struct fae_db_node *node;

	tmp.endpoint = *endpoint;
	node = RB_FIND(fae_db_head, table, &tmp);
	if (node == NULL)
		return NULL;

	return fae_db_node_delete(table, node, client);
}

/* Find a registration node
 *
 * @param table	endpoint tracking database
 * @param addr	IP address of tracked endpoint
 *
 * @return	pointer to the registration node
 */
struct fae_db_node *fae_db_find(struct fae_db_head *table,
				const struct ipaddr *const endpoint)
{
	struct fae_db_node tmp;

	tmp.endpoint = *endpoint;
	return RB_FIND(fae_db_head, table, &tmp);
}

/* Free a registration database node.  The node must first be removed
 * from the RB-tree with fae_db_node_delete().
 *
 * @param node	Database node to free
 */
void fae_db_node_free(struct fae_db_node *node, bool check_assert)
{
	if (check_assert)
		assert(node->num_clients == 0);
	else if (node->num_clients != 0)
		zlog_warn("%s(): node %p freed whereas num clients=%d",
			  __func__, node, node->num_clients);
	XFREE(MTYPE_FAE_DB_NODE, node);
}

/* Free the registration database.  This will free all nodes first,
 * then free the array of per-algo trees.  Note that the table
 * parameter will no longer be a valid pointer after calling this
 * function.
 *
 * @param table	The registration database to free.
 */
void fae_db_free(struct fae_db_head *table)
{
	for (int algo = 0; algo < SR_ALGORITHM_COUNT; algo++) {
		struct fae_db_node *node;
		struct fae_db_node *tmp;

		RB_FOREACH_SAFE (node, fae_db_head, &table[algo], tmp) {
			fae_db_node_free(node, false);
		}
	}
	XFREE(MTYPE_FAE_DB_TABLE, table);
}

/* Compare two FAE node structures.  The tree is ordered by the
 * endpoint IP address.
 *
 * @param a	node to compare
 * @param b	node to compare
 *
 * @return	0 if nodes are equal, -1 if a < b, 1 if a > b.
 */
static int fae_db_entry_cmp_func(const struct fae_db_node *a,
				 const struct fae_db_node *b)
{
	return ipaddr_cmp(&a->endpoint, &b->endpoint);
}
