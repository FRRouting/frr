/* BGP community, large-community aliasing.
 *
 * Copyright (C) 2021 Donatas Abraitis <donatas.abraitis@gmail.com>
 *
 * This file is part of FRRouting (FRR).
 *
 * FRR is free software; you can redistribute it and/or modify it under the
 * terms of the GNU General Public License as published by the Free Software
 * Foundation; either version 2, or (at your option) any later version.
 *
 * FRR is distributed in the hope that it will be useful, but WITHOUT ANY
 * WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
 * FOR A PARTICULAR PURPOSE.  See the GNU General Public License for more
 * details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; see the file COPYING; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA
 */

#include "memory.h"
#include "lib/jhash.h"

#include "bgpd/bgpd.h"
#include "bgpd/bgp_community_alias.h"

static struct hash *bgp_ca_alias_hash;
static struct hash *bgp_ca_community_hash;

static unsigned int bgp_ca_community_hash_key(const void *p)
{
	const struct community_alias *ca = p;

	return jhash(ca->community, sizeof(ca->community), 0);
}

static bool bgp_ca_community_hash_cmp(const void *p1, const void *p2)
{
	const struct community_alias *ca1 = p1;
	const struct community_alias *ca2 = p2;

	return (strncmp(ca1->community, ca2->community,
			sizeof(struct community_alias))
		== 0);
}

static unsigned int bgp_ca_alias_hash_key(const void *p)
{
	const struct community_alias *ca = p;

	return jhash(ca->alias, sizeof(ca->alias), 0);
}

static bool bgp_ca_alias_hash_cmp(const void *p1, const void *p2)
{
	const struct community_alias *ca1 = p1;
	const struct community_alias *ca2 = p2;

	return (strncmp(ca1->alias, ca2->alias, sizeof(struct community_alias))
		== 0);
}

static void *bgp_community_alias_alloc(void *p)
{
	const struct community_alias *ca = p;
	struct communtiy_alias *new;

	new = XCALLOC(MTYPE_COMMUNITY_ALIAS, sizeof(struct community_alias));
	memcpy(new, ca, sizeof(struct community_alias));

	return new;
}

void bgp_community_alias_init(void)
{
	bgp_ca_community_hash = hash_create(bgp_ca_community_hash_key,
					       bgp_ca_community_hash_cmp,
					       "BGP community alias (community)");
	bgp_ca_alias_hash =
		hash_create(bgp_ca_alias_hash_key, bgp_ca_alias_hash_cmp,
			    "BGP community alias (alias)");
}

void bgp_community_alias_finish(void)
{
	hash_free(bgp_ca_community_hash);
	hash_free(bgp_ca_alias_hash);
}

static void bgp_community_alias_show_iterator(struct hash_bucket *hb,
					      struct vty *vty)
{
	struct community_alias *ca = hb->data;

	vty_out(vty, "bgp community alias %s %s\n", ca->community, ca->alias);
}

int bgp_community_alias_write(struct vty *vty)
{
	hash_iterate(bgp_ca_community_hash,
		     (void (*)(struct hash_bucket *,
			       void *))bgp_community_alias_show_iterator,
		     vty);
	return 1;
}

void bgp_ca_community_insert(struct community_alias *ca)
{
	hash_get(bgp_ca_community_hash, ca, bgp_community_alias_alloc);
}

void bgp_ca_alias_insert(struct community_alias *ca)
{
	hash_get(bgp_ca_alias_hash, ca, bgp_community_alias_alloc);
}

void bgp_ca_community_delete(struct community_alias *ca)
{
	struct community_alias *data = hash_release(bgp_ca_community_hash, ca);

	XFREE(MTYPE_COMMUNITY_ALIAS, data);
}

void bgp_ca_alias_delete(struct community_alias *ca)
{
	struct community_alias *data = hash_release(bgp_ca_alias_hash, ca);

	XFREE(MTYPE_COMMUNITY_ALIAS, data);
}

struct community_alias *bgp_ca_community_lookup(struct community_alias *ca)
{
	return hash_lookup(bgp_ca_community_hash, ca);
}

struct community_alias *bgp_ca_alias_lookup(struct community_alias *ca)
{
	return hash_lookup(bgp_ca_alias_hash, ca);
}

const char *bgp_community2alias(char *community)
{
	struct community_alias ca;
	struct community_alias *find;

	memset(&ca, 0, sizeof(ca));
	strlcpy(ca.community, community, sizeof(ca.community));

	find = bgp_ca_community_lookup(&ca);
	if (find)
		return find->alias;

	return community;
}
