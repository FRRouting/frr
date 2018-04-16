/*
 * CLI/command dummy handling tester
 *
 * Copyright (C) 2015 by David Lamparter,
 *                   for Open Source Routing / NetDEF, Inc.
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

#include "prefix.h"
#include "vector.h"
#include "vty.h"

#include "ospf6d/ospf6_lsa.h"
#include "ospf6d/ospf6_lsdb.h"

#include "tests/lib/cli/common_cli.h"
#include "ospf6d/test_lsdb_clippy.c"

static struct ospf6_lsdb *lsdb;

static struct ospf6_lsa **lsas = NULL;
static size_t lsa_count = 0;

static void lsa_check_resize(size_t len)
{
	struct ospf6_lsa **templsas;

	if (lsa_count >= len)
		return;
	templsas = realloc(lsas, len * sizeof(lsas[0]));
	if (templsas)
		lsas = templsas;
	else
		return;
	memset(lsas + lsa_count, 0, sizeof(lsas[0]) * (len - lsa_count));

	lsa_count = len;
}

DEFPY(lsa_set, lsa_set_cmd,
      "lsa set (0-999999)$idx {type (0-65535)|id A.B.C.D|adv A.B.C.D}",
      "LSA\n"
      "set\n"
      "LSA index in array\n"
      "OSPF6 type code\n"
      "OSPF6 type code\n"
      "LS-ID\n"
      "LS-ID\n"
      "Advertising router\n"
      "Advertising router\n")
{
	struct ospf6_lsa_header hdr;
	memset(&hdr, 0, sizeof(hdr));
	hdr.type = htons(type);
	hdr.id = id.s_addr;
	hdr.adv_router = adv.s_addr;

	lsa_check_resize(idx + 1);
	if (lsas[idx])
		ospf6_lsa_unlock(lsas[idx]);
	lsas[idx] = ospf6_lsa_create_headeronly(&hdr);
	ospf6_lsa_lock(lsas[idx]);
	return CMD_SUCCESS;
}

DEFPY(lsa_drop, lsa_drop_cmd,
      "lsa drop (0-999999)$idx",
      "LSA\n"
      "drop reference\n"
      "LSA index in array\n")
{
	if ((size_t)idx >= lsa_count)
		return CMD_SUCCESS;
	if (lsas[idx]->lock != 1)
		vty_out(vty, "refcount at %u\n", lsas[idx]->lock);
	ospf6_lsa_unlock(lsas[idx]);
	lsas[idx] = NULL;
	return CMD_SUCCESS;
}


DEFPY(lsdb_add, lsdb_add_cmd,
      "lsdb add (0-999999)$idx",
      "LSDB\n"
      "insert LSA into LSDB\n"
      "LSA index in array\n")
{
	ospf6_lsdb_add(lsas[idx], lsdb);
	return CMD_SUCCESS;
}

DEFPY(lsdb_remove, lsdb_remove_cmd,
      "lsdb remove (0-999999)$idx",
      "LSDB\n"
      "remove LSA from LSDB\n"
      "LSA index in array\n")
{
	ospf6_lsdb_remove(lsas[idx], lsdb);
	return CMD_SUCCESS;
}

static void lsa_show_oneline(struct vty *vty, struct ospf6_lsa *lsa)
{
	char adv_router[64], id[64];

	if (!lsa) {
		vty_out(vty, "lsa = NULL\n");
		return;
	}
	inet_ntop(AF_INET, &lsa->header->id, id, sizeof(id));
	inet_ntop(AF_INET, &lsa->header->adv_router, adv_router,
		  sizeof(adv_router));
	vty_out(vty, "type %u adv %s id %s\n", ntohs(lsa->header->type),
		adv_router, id);
}

DEFPY(lsdb_walk, lsdb_walk_cmd,
      "lsdb walk",
      "LSDB\n"
      "walk entries\n")
{
	struct ospf6_lsa *lsa;
	unsigned cnt = 0;
	for (ALL_LSDB(lsdb, lsa)) {
		lsa_show_oneline(vty, lsa);
		cnt++;
	}
	vty_out(vty, "%u entries.\n", cnt);
	return CMD_SUCCESS;
}

DEFPY(lsdb_walk_type, lsdb_walk_type_cmd,
      "lsdb walk type (0-65535)",
      "LSDB\n"
      "walk entries\n"
      "entry type\n"
      "entry type\n")
{
	struct ospf6_lsa *lsa;
	unsigned cnt = 0;
	type = htons(type);
	for (ALL_LSDB_TYPED(lsdb, type, lsa)) {
		lsa_show_oneline(vty, lsa);
		cnt++;
	}
	vty_out(vty, "%u entries.\n", cnt);
	return CMD_SUCCESS;
}

DEFPY(lsdb_walk_type_adv, lsdb_walk_type_adv_cmd,
      "lsdb walk type (0-65535) adv A.B.C.D",
      "LSDB\n"
      "walk entries\n"
      "entry type\n"
      "entry type\n"
      "advertising router ID\n"
      "advertising router ID\n")
{
	struct ospf6_lsa *lsa;
	unsigned cnt = 0;
	type = htons(type);
	for (ALL_LSDB_TYPED_ADVRTR(lsdb, type, adv.s_addr, lsa)) {
		lsa_show_oneline(vty, lsa);
		cnt++;
	}
	vty_out(vty, "%u entries.\n", cnt);
	return CMD_SUCCESS;
}

DEFPY(lsdb_get, lsdb_get_cmd,
      "lsdb <get-next|get> type (0-65535) adv A.B.C.D id A.B.C.D",
      "LSDB\n"
      "get entry's successor\n"
      "entry type\n"
      "entry type\n"
      "advertising router ID\n"
      "advertising router ID\n"
      "LS-ID\n"
      "LS-ID\n")
{
	struct ospf6_lsa *lsa;
	type = htons(type);
	if (!strcmp(argv[1]->text, "get-next"))
		lsa = ospf6_lsdb_lookup_next(type, id.s_addr, adv.s_addr, lsdb);
	else
		lsa = ospf6_lsdb_lookup(type, id.s_addr, adv.s_addr, lsdb);
	lsa_show_oneline(vty, lsa);
	return CMD_SUCCESS;
}

DEFPY(lsa_refcounts, lsa_refcounts_cmd,
      "lsa refcounts",
      "LSA\n"
      "show reference counts\n")
{
	for (size_t i = 0; i < lsa_count; i++)
		if (lsas[i])
			vty_out(vty, "[%zu] %u\n", i, lsas[i]->lock);
	return CMD_SUCCESS;
}

DEFPY(lsdb_create, lsdb_create_cmd,
      "lsdb create",
      "LSDB\n"
      "create LSDB\n")
{
	if (lsdb)
		ospf6_lsdb_delete(lsdb);
	lsdb = ospf6_lsdb_create(NULL);
	return CMD_SUCCESS;
}

DEFPY(lsdb_delete, lsdb_delete_cmd,
      "lsdb delete",
      "LSDB\n"
      "delete LSDB\n")
{
	ospf6_lsdb_delete(lsdb);
	lsdb = NULL;
	return CMD_SUCCESS;
}


struct zebra_privs_t ospf6d_privs;

void test_init(int argc, char **argv)
{
	ospf6_lsa_init();

	install_element(ENABLE_NODE, &lsa_set_cmd);
	install_element(ENABLE_NODE, &lsa_refcounts_cmd);
	install_element(ENABLE_NODE, &lsa_drop_cmd);

	install_element(ENABLE_NODE, &lsdb_create_cmd);
	install_element(ENABLE_NODE, &lsdb_delete_cmd);

	install_element(ENABLE_NODE, &lsdb_add_cmd);
	install_element(ENABLE_NODE, &lsdb_remove_cmd);
	install_element(ENABLE_NODE, &lsdb_walk_cmd);
	install_element(ENABLE_NODE, &lsdb_walk_type_cmd);
	install_element(ENABLE_NODE, &lsdb_walk_type_adv_cmd);
	install_element(ENABLE_NODE, &lsdb_get_cmd);
}
