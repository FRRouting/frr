// SPDX-License-Identifier: GPL-2.0-or-later
/* BGP community, large-community aliasing.
 *
 * Copyright (C) 2021 Donatas Abraitis <donatas.abraitis@gmail.com>
 */

#include "zebra.h"

#include "memory.h"
#include "lib/jhash.h"
#include "frrstr.h"

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

	return (strcmp(ca1->community, ca2->community) == 0);
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

	return (strcmp(ca1->alias, ca2->alias) == 0);
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

static void bgp_ca_free(void *ca)
{
	XFREE(MTYPE_COMMUNITY_ALIAS, ca);
}

void bgp_community_alias_finish(void)
{
	hash_clean_and_free(&bgp_ca_community_hash, bgp_ca_free);
	hash_clean_and_free(&bgp_ca_alias_hash, bgp_ca_free);
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
	(void)hash_get(bgp_ca_community_hash, ca, bgp_community_alias_alloc);
}

void bgp_ca_alias_insert(struct community_alias *ca)
{
	(void)hash_get(bgp_ca_alias_hash, ca, bgp_community_alias_alloc);
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

const char *bgp_alias2community(char *alias)
{
	struct community_alias ca;
	struct community_alias *find;

	memset(&ca, 0, sizeof(ca));
	strlcpy(ca.alias, alias, sizeof(ca.alias));

	find = bgp_ca_alias_lookup(&ca);
	if (find)
		return find->community;

	return alias;
}

/* Communities structs have `->str` which is used
 * for vty outputs and extended BGP community lists
 * with regexp.
 * This is a helper to convert already aliased version
 * of communities into numerical-only format.
 */
char *bgp_alias2community_str(const char *str)
{
	char **aliases;
	char *comstr;
	int num, i;

	frrstr_split(str, " ", &aliases, &num);
	const char *communities[num];

	for (i = 0; i < num; i++)
		communities[i] = bgp_alias2community(aliases[i]);

	comstr = frrstr_join(communities, num, " ");

	for (i = 0; i < num; i++)
		XFREE(MTYPE_TMP, aliases[i]);
	XFREE(MTYPE_TMP, aliases);

	return comstr;
}

static int bgp_community_alias_vector_walker(struct hash_bucket *bucket,
					     void *data)
{
	vector *comps = data;
	struct community_alias *alias = bucket->data;

	vector_set(*comps, XSTRDUP(MTYPE_COMPLETION, alias->alias));

	return 1;
}

static void bgp_community_alias_cmd_completion(vector comps,
					       struct cmd_token *token)
{
	hash_walk(bgp_ca_alias_hash, bgp_community_alias_vector_walker, &comps);
}

static const struct cmd_variable_handler community_alias_handlers[] = {
	{.varname = "alias_name",
	 .completions = bgp_community_alias_cmd_completion},
	{.tokenname = "ALIAS_NAME",
	 .completions = bgp_community_alias_cmd_completion},
	{.completions = NULL}};

void bgp_community_alias_command_completion_setup(void)
{
	cmd_variable_handler_register(community_alias_handlers);
}
