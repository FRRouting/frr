/*
 * BGPd - Mac hash code
 * Copyright (C) 2018 Cumulus Networks, Inc.
 *               Donald Sharp
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
#include <zebra.h>

#include <jhash.h>
#include <hash.h>
#include <prefix.h>
#include <memory.h>

#include "bgpd/bgpd.h"
#include "bgpd/bgp_mac.h"
#include "bgpd/bgp_memory.h"
#include "bgpd/bgp_route.h"
#include "bgpd/bgp_packet.h"
#include "bgpd/bgp_debug.h"

DEFINE_MTYPE_STATIC(BGPD, BSM, "Mac Hash Entry");

struct bgp_self_mac {
	struct ethaddr macaddr;
	struct list *ifp_list;
};

static unsigned int bgp_mac_hash_key_make(void *data)
{
	struct bgp_self_mac *bsm = data;

	return jhash(&bsm->macaddr, ETH_ALEN, 0xa5a5dead);
}

static bool bgp_mac_hash_cmp(const void *d1, const void *d2)
{
	const struct bgp_self_mac *bsm1 = d1;
	const struct bgp_self_mac *bsm2 = d2;

	if (memcmp(&bsm1->macaddr, &bsm2->macaddr, ETH_ALEN) == 0)
		return true;

	return false;
}

void bgp_mac_init(void)
{
	bm->self_mac_hash = hash_create(bgp_mac_hash_key_make, bgp_mac_hash_cmp,
					"BGP MAC Hash");
}

static void bgp_mac_hash_free(void *data)
{
	struct bgp_self_mac *bsm = data;

	list_delete(&bsm->ifp_list);
	XFREE(MTYPE_BSM, bsm);
}

void bgp_mac_finish(void)
{
	hash_clean(bm->self_mac_hash, bgp_mac_hash_free);
	hash_free(bm->self_mac_hash);
}

static void bgp_mac_show_mac_entry(struct hash_backet *backet, void *arg)
{
	struct vty *vty = arg;
	struct bgp_self_mac *bsm = backet->data;
	struct listnode *node;
	char *name;
	char buf_mac[ETHER_ADDR_STRLEN];

	vty_out(vty, "Mac Address: %s ",
		prefix_mac2str(&bsm->macaddr, buf_mac, sizeof(buf_mac)));

	for (ALL_LIST_ELEMENTS_RO(bsm->ifp_list, node, name))
		vty_out(vty, "%s ", name);

	vty_out(vty, "\n");
}

void bgp_mac_dump_table(struct vty *vty)
{
	hash_iterate(bm->self_mac_hash, bgp_mac_show_mac_entry, vty);
}
