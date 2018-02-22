/* route-map for interface.
 * Copyright (C) 1999 Kunihiro Ishiguro
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

#include "hash.h"
#include "command.h"
#include "memory.h"
#include "if.h"
#include "if_rmap.h"

DEFINE_MTYPE_STATIC(LIB, IF_RMAP, "Interface route map")
DEFINE_MTYPE_STATIC(LIB, IF_RMAP_NAME, "I.f. route map name")

struct hash *ifrmaphash;

/* Hook functions. */
static void (*if_rmap_add_hook)(struct if_rmap *) = NULL;
static void (*if_rmap_delete_hook)(struct if_rmap *) = NULL;

static struct if_rmap *if_rmap_new(void)
{
	struct if_rmap *new;

	new = XCALLOC(MTYPE_IF_RMAP, sizeof(struct if_rmap));

	return new;
}

static void if_rmap_free(struct if_rmap *if_rmap)
{
	if (if_rmap->ifname)
		XFREE(MTYPE_IF_RMAP_NAME, if_rmap->ifname);

	if (if_rmap->routemap[IF_RMAP_IN])
		XFREE(MTYPE_IF_RMAP_NAME, if_rmap->routemap[IF_RMAP_IN]);
	if (if_rmap->routemap[IF_RMAP_OUT])
		XFREE(MTYPE_IF_RMAP_NAME, if_rmap->routemap[IF_RMAP_OUT]);

	XFREE(MTYPE_IF_RMAP, if_rmap);
}

struct if_rmap *if_rmap_lookup(const char *ifname)
{
	struct if_rmap key;
	struct if_rmap *if_rmap;

	/* temporary copy */
	key.ifname = (ifname) ? XSTRDUP(MTYPE_IF_RMAP_NAME, ifname) : NULL;

	if_rmap = hash_lookup(ifrmaphash, &key);

	if (key.ifname)
		XFREE(MTYPE_IF_RMAP_NAME, key.ifname);

	return if_rmap;
}

void if_rmap_hook_add(void (*func)(struct if_rmap *))
{
	if_rmap_add_hook = func;
}

void if_rmap_hook_delete(void (*func)(struct if_rmap *))
{
	if_rmap_delete_hook = func;
}

static void *if_rmap_hash_alloc(void *arg)
{
	struct if_rmap *ifarg = (struct if_rmap *)arg;
	struct if_rmap *if_rmap;

	if_rmap = if_rmap_new();
	if_rmap->ifname = XSTRDUP(MTYPE_IF_RMAP_NAME, ifarg->ifname);

	return if_rmap;
}

static struct if_rmap *if_rmap_get(const char *ifname)
{
	struct if_rmap key;
	struct if_rmap *ret;

	/* temporary copy */
	key.ifname = (ifname) ? XSTRDUP(MTYPE_IF_RMAP_NAME, ifname) : NULL;

	ret = hash_get(ifrmaphash, &key, if_rmap_hash_alloc);

	if (key.ifname)
		XFREE(MTYPE_IF_RMAP_NAME, key.ifname);

	return ret;
}

static unsigned int if_rmap_hash_make(void *data)
{
	const struct if_rmap *if_rmap = data;

	return string_hash_make(if_rmap->ifname);
}

static int if_rmap_hash_cmp(const void *arg1, const void *arg2)
{
	const struct if_rmap *if_rmap1 = arg1;
	const struct if_rmap *if_rmap2 = arg2;

	return strcmp(if_rmap1->ifname, if_rmap2->ifname) == 0;
}

static struct if_rmap *if_rmap_set(const char *ifname, enum if_rmap_type type,
				   const char *routemap_name)
{
	struct if_rmap *if_rmap;

	if_rmap = if_rmap_get(ifname);

	if (type == IF_RMAP_IN) {
		if (if_rmap->routemap[IF_RMAP_IN])
			XFREE(MTYPE_IF_RMAP_NAME,
			      if_rmap->routemap[IF_RMAP_IN]);
		if_rmap->routemap[IF_RMAP_IN] =
			XSTRDUP(MTYPE_IF_RMAP_NAME, routemap_name);
	}
	if (type == IF_RMAP_OUT) {
		if (if_rmap->routemap[IF_RMAP_OUT])
			XFREE(MTYPE_IF_RMAP_NAME,
			      if_rmap->routemap[IF_RMAP_OUT]);
		if_rmap->routemap[IF_RMAP_OUT] =
			XSTRDUP(MTYPE_IF_RMAP_NAME, routemap_name);
	}

	if (if_rmap_add_hook)
		(*if_rmap_add_hook)(if_rmap);

	return if_rmap;
}

static int if_rmap_unset(const char *ifname, enum if_rmap_type type,
			 const char *routemap_name)
{
	struct if_rmap *if_rmap;

	if_rmap = if_rmap_lookup(ifname);
	if (!if_rmap)
		return 0;

	if (type == IF_RMAP_IN) {
		if (!if_rmap->routemap[IF_RMAP_IN])
			return 0;
		if (strcmp(if_rmap->routemap[IF_RMAP_IN], routemap_name) != 0)
			return 0;

		XFREE(MTYPE_IF_RMAP_NAME, if_rmap->routemap[IF_RMAP_IN]);
		if_rmap->routemap[IF_RMAP_IN] = NULL;
	}

	if (type == IF_RMAP_OUT) {
		if (!if_rmap->routemap[IF_RMAP_OUT])
			return 0;
		if (strcmp(if_rmap->routemap[IF_RMAP_OUT], routemap_name) != 0)
			return 0;

		XFREE(MTYPE_IF_RMAP_NAME, if_rmap->routemap[IF_RMAP_OUT]);
		if_rmap->routemap[IF_RMAP_OUT] = NULL;
	}

	if (if_rmap_delete_hook)
		(*if_rmap_delete_hook)(if_rmap);

	if (if_rmap->routemap[IF_RMAP_IN] == NULL
	    && if_rmap->routemap[IF_RMAP_OUT] == NULL) {
		hash_release(ifrmaphash, if_rmap);
		if_rmap_free(if_rmap);
	}

	return 1;
}

DEFUN (if_rmap,
       if_rmap_cmd,
       "route-map RMAP_NAME <in|out> IFNAME",
       "Route map set\n"
       "Route map name\n"
       "Route map set for input filtering\n"
       "Route map set for output filtering\n"
       "Route map interface name\n")
{
	int idx_rmap_name = 1;
	int idx_in_out = 2;
	int idx_ifname = 3;
	enum if_rmap_type type;

	if (strncmp(argv[idx_in_out]->text, "in", 1) == 0)
		type = IF_RMAP_IN;
	else if (strncmp(argv[idx_in_out]->text, "out", 1) == 0)
		type = IF_RMAP_OUT;
	else {
		vty_out(vty, "route-map direction must be [in|out]\n");
		return CMD_WARNING_CONFIG_FAILED;
	}

	if_rmap_set(argv[idx_ifname]->arg, type, argv[idx_rmap_name]->arg);

	return CMD_SUCCESS;
}

DEFUN (no_if_rmap,
       no_if_rmap_cmd,
       "no route-map ROUTEMAP_NAME <in|out> IFNAME",
       NO_STR
       "Route map unset\n"
       "Route map name\n"
       "Route map for input filtering\n"
       "Route map for output filtering\n"
       "Route map interface name\n")
{
	int idx_routemap_name = 2;
	int idx_in_out = 3;
	int idx_ifname = 4;
	int ret;
	enum if_rmap_type type;

	if (strncmp(argv[idx_in_out]->arg, "i", 1) == 0)
		type = IF_RMAP_IN;
	else if (strncmp(argv[idx_in_out]->arg, "o", 1) == 0)
		type = IF_RMAP_OUT;
	else {
		vty_out(vty, "route-map direction must be [in|out]\n");
		return CMD_WARNING_CONFIG_FAILED;
	}

	ret = if_rmap_unset(argv[idx_ifname]->arg, type,
			    argv[idx_routemap_name]->arg);
	if (!ret) {
		vty_out(vty, "route-map doesn't exist\n");
		return CMD_WARNING_CONFIG_FAILED;
	}
	return CMD_SUCCESS;
}


/* Configuration write function. */
int config_write_if_rmap(struct vty *vty)
{
	unsigned int i;
	struct hash_backet *mp;
	int write = 0;

	for (i = 0; i < ifrmaphash->size; i++)
		for (mp = ifrmaphash->index[i]; mp; mp = mp->next) {
			struct if_rmap *if_rmap;

			if_rmap = mp->data;

			if (if_rmap->routemap[IF_RMAP_IN]) {
				vty_out(vty, " route-map %s in %s\n",
					if_rmap->routemap[IF_RMAP_IN],
					if_rmap->ifname);
				write++;
			}

			if (if_rmap->routemap[IF_RMAP_OUT]) {
				vty_out(vty, " route-map %s out %s\n",
					if_rmap->routemap[IF_RMAP_OUT],
					if_rmap->ifname);
				write++;
			}
		}
	return write;
}

void if_rmap_reset()
{
	hash_clean(ifrmaphash, (void (*)(void *))if_rmap_free);
}

void if_rmap_init(int node)
{
	ifrmaphash = hash_create_size(4, if_rmap_hash_make, if_rmap_hash_cmp,
				      "Interface Route-Map Hash");
	if (node == RIPNG_NODE) {
	} else if (node == RIP_NODE) {
		install_element(RIP_NODE, &if_rmap_cmd);
		install_element(RIP_NODE, &no_if_rmap_cmd);
	}
}
