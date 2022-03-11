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

#ifndef __FAE_DB_H
#define __FAE_DB_H

#include <zebra.h>
#include "ipaddr.h"
#include "queue.h"
#include "zclient.h"
#include "zapi_fae.h"

#define FAE_DB_MAX_CLIENTS 4

struct fae_db_node {
	RB_ENTRY(fae_db_entry) entry;
	struct ipaddr endpoint;

	/* Indices into a list of client daemon/session IDs */
	unsigned num_clients;
	unsigned char client[FAE_DB_MAX_CLIENTS];
};

RB_HEAD(fae_db_head, fae_db_node);
RB_PROTOTYPE(fae_db_head, fae_db_node, entry, fae_db_entry_cmp_func);

struct fae_db_head *fae_db_init(void);

struct fae_db_node *fae_db_insert(struct fae_db_head *,
				  const struct ipaddr *const, unsigned char,
				  int *);

struct fae_db_node *fae_db_move(struct fae_db_head *, struct fae_db_head *,
				struct fae_db_node *);

struct fae_db_node *fae_db_node_delete(struct fae_db_head *table,
				       struct fae_db_node *node,
				       unsigned char client);

struct fae_db_node *fae_db_delete(struct fae_db_head *,
				  const struct ipaddr *const, unsigned char);

struct fae_db_node *fae_db_find(struct fae_db_head *,
				const struct ipaddr *const addr);

void fae_db_node_free(struct fae_db_node *, bool check_assert);

void fae_db_free(struct fae_db_head *);

#endif
