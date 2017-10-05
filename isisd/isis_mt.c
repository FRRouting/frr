/*
 * IS-IS Rout(e)ing protocol - Multi Topology Support
 *
 * Copyright (C) 2017 Christian Franke
 *
 * This file is part of FreeRangeRouting (FRR)
 *
 * FRR is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2, or (at your option) any
 * later version.
 *
 * FRR is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; see the file COPYING; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA
 */
#include <zebra.h>
#include "isisd/isisd.h"
#include "isisd/isis_memory.h"
#include "isisd/isis_circuit.h"
#include "isisd/isis_adjacency.h"
#include "isisd/isis_misc.h"
#include "isisd/isis_lsp.h"
#include "isisd/isis_mt.h"
#include "isisd/isis_tlvs.h"

DEFINE_MTYPE_STATIC(ISISD, MT_AREA_SETTING, "ISIS MT Area Setting")
DEFINE_MTYPE_STATIC(ISISD, MT_CIRCUIT_SETTING, "ISIS MT Circuit Setting")
DEFINE_MTYPE_STATIC(ISISD, MT_ADJ_INFO, "ISIS MT Adjacency Info")

uint16_t isis_area_ipv6_topology(struct isis_area *area)
{
	struct isis_area_mt_setting *area_mt_setting;
	area_mt_setting = area_lookup_mt_setting(area, ISIS_MT_IPV6_UNICAST);

	if (area_mt_setting && area_mt_setting->enabled)
		return ISIS_MT_IPV6_UNICAST;
	return ISIS_MT_IPV4_UNICAST;
}

/* MT naming api */
const char *isis_mtid2str(uint16_t mtid)
{
	static char buf[sizeof("65535")];

	switch (mtid) {
	case ISIS_MT_IPV4_UNICAST:
		return "ipv4-unicast";
	case ISIS_MT_IPV4_MGMT:
		return "ipv4-mgmt";
	case ISIS_MT_IPV6_UNICAST:
		return "ipv6-unicast";
	case ISIS_MT_IPV4_MULTICAST:
		return "ipv4-multicast";
	case ISIS_MT_IPV6_MULTICAST:
		return "ipv6-multicast";
	case ISIS_MT_IPV6_MGMT:
		return "ipv6-mgmt";
	default:
		snprintf(buf, sizeof(buf), "%" PRIu16, mtid);
		return buf;
	}
}

uint16_t isis_str2mtid(const char *name)
{
	if (!strcmp(name, "ipv4-unicast"))
		return ISIS_MT_IPV4_UNICAST;
	if (!strcmp(name, "ipv4-mgmt"))
		return ISIS_MT_IPV4_MGMT;
	if (!strcmp(name, "ipv6-unicast"))
		return ISIS_MT_IPV6_UNICAST;
	if (!strcmp(name, "ipv4-multicast"))
		return ISIS_MT_IPV4_MULTICAST;
	if (!strcmp(name, "ipv6-multicast"))
		return ISIS_MT_IPV6_MULTICAST;
	if (!strcmp(name, "ipv6-mgmt"))
		return ISIS_MT_IPV6_MGMT;
	return -1;
}

/* General MT settings api */

struct mt_setting {
	ISIS_MT_INFO_FIELDS;
};

static void *lookup_mt_setting(struct list *mt_list, uint16_t mtid)
{
	struct listnode *node;
	struct mt_setting *setting;

	for (ALL_LIST_ELEMENTS_RO(mt_list, node, setting)) {
		if (setting->mtid == mtid)
			return setting;
	}
	return NULL;
}

static void add_mt_setting(struct list **mt_list, void *setting)
{
	if (!*mt_list)
		*mt_list = list_new();
	listnode_add(*mt_list, setting);
}

/* Area specific MT settings api */

struct isis_area_mt_setting *area_lookup_mt_setting(struct isis_area *area,
						    uint16_t mtid)
{
	return lookup_mt_setting(area->mt_settings, mtid);
}

struct isis_area_mt_setting *area_new_mt_setting(struct isis_area *area,
						 uint16_t mtid)
{
	struct isis_area_mt_setting *setting;

	setting = XCALLOC(MTYPE_MT_AREA_SETTING, sizeof(*setting));
	setting->mtid = mtid;
	return setting;
}

static void area_free_mt_setting(void *setting)
{
	XFREE(MTYPE_MT_AREA_SETTING, setting);
}

void area_add_mt_setting(struct isis_area *area,
			 struct isis_area_mt_setting *setting)
{
	add_mt_setting(&area->mt_settings, setting);
}

void area_mt_init(struct isis_area *area)
{
	struct isis_area_mt_setting *v4_unicast_setting;

	/* MTID 0 is always enabled */
	v4_unicast_setting = area_new_mt_setting(area, ISIS_MT_IPV4_UNICAST);
	v4_unicast_setting->enabled = true;
	add_mt_setting(&area->mt_settings, v4_unicast_setting);
	area->mt_settings->del = area_free_mt_setting;
}

void area_mt_finish(struct isis_area *area)
{
	list_delete_and_null(&area->mt_settings);
}

struct isis_area_mt_setting *area_get_mt_setting(struct isis_area *area,
						 uint16_t mtid)
{
	struct isis_area_mt_setting *setting;

	setting = area_lookup_mt_setting(area, mtid);
	if (!setting) {
		setting = area_new_mt_setting(area, mtid);
		area_add_mt_setting(area, setting);
	}
	return setting;
}

int area_write_mt_settings(struct isis_area *area, struct vty *vty)
{
	int written = 0;
	struct listnode *node;
	struct isis_area_mt_setting *setting;

	for (ALL_LIST_ELEMENTS_RO(area->mt_settings, node, setting)) {
		const char *name = isis_mtid2str(setting->mtid);
		if (name && setting->enabled) {
			if (setting->mtid == ISIS_MT_IPV4_UNICAST)
				continue; /* always enabled, no need to write
					     out config */
			vty_out(vty, " topology %s%s\n", name,
				setting->overload ? " overload" : "");
			written++;
		}
	}
	return written;
}

bool area_is_mt(struct isis_area *area)
{
	struct listnode *node, *node2;
	struct isis_area_mt_setting *setting;
	struct isis_circuit *circuit;
	struct isis_circuit_mt_setting *csetting;

	for (ALL_LIST_ELEMENTS_RO(area->mt_settings, node, setting)) {
		if (setting->enabled && setting->mtid != ISIS_MT_IPV4_UNICAST)
			return true;
	}
	for (ALL_LIST_ELEMENTS_RO(area->circuit_list, node, circuit)) {
		for (ALL_LIST_ELEMENTS_RO(circuit->mt_settings, node2,
					  csetting)) {
			if (!csetting->enabled
			    && csetting->mtid == ISIS_MT_IPV4_UNICAST)
				return true;
		}
	}

	return false;
}

struct isis_area_mt_setting **area_mt_settings(struct isis_area *area,
					       unsigned int *mt_count)
{
	static unsigned int size = 0;
	static struct isis_area_mt_setting **rv = NULL;

	unsigned int count = 0;
	struct listnode *node;
	struct isis_area_mt_setting *setting;

	for (ALL_LIST_ELEMENTS_RO(area->mt_settings, node, setting)) {
		if (!setting->enabled)
			continue;

		count++;
		if (count > size) {
			rv = XREALLOC(MTYPE_TMP, rv, count * sizeof(*rv));
			size = count;
		}
		rv[count - 1] = setting;
	}

	*mt_count = count;
	return rv;
}

/* Circuit specific MT settings api */

struct isis_circuit_mt_setting *
circuit_lookup_mt_setting(struct isis_circuit *circuit, uint16_t mtid)
{
	return lookup_mt_setting(circuit->mt_settings, mtid);
}

struct isis_circuit_mt_setting *
circuit_new_mt_setting(struct isis_circuit *circuit, uint16_t mtid)
{
	struct isis_circuit_mt_setting *setting;

	setting = XCALLOC(MTYPE_MT_CIRCUIT_SETTING, sizeof(*setting));
	setting->mtid = mtid;
	setting->enabled = true; /* Enabled is default for circuit */
	return setting;
}

static void circuit_free_mt_setting(void *setting)
{
	XFREE(MTYPE_MT_CIRCUIT_SETTING, setting);
}

void circuit_add_mt_setting(struct isis_circuit *circuit,
			    struct isis_circuit_mt_setting *setting)
{
	add_mt_setting(&circuit->mt_settings, setting);
}

void circuit_mt_init(struct isis_circuit *circuit)
{
	circuit->mt_settings = list_new();
	circuit->mt_settings->del = circuit_free_mt_setting;
}

void circuit_mt_finish(struct isis_circuit *circuit)
{
	list_delete_and_null(&circuit->mt_settings);
}

struct isis_circuit_mt_setting *
circuit_get_mt_setting(struct isis_circuit *circuit, uint16_t mtid)
{
	struct isis_circuit_mt_setting *setting;

	setting = circuit_lookup_mt_setting(circuit, mtid);
	if (!setting) {
		setting = circuit_new_mt_setting(circuit, mtid);
		circuit_add_mt_setting(circuit, setting);
	}
	return setting;
}

int circuit_write_mt_settings(struct isis_circuit *circuit, struct vty *vty)
{
	int written = 0;
	struct listnode *node;
	struct isis_circuit_mt_setting *setting;

	for (ALL_LIST_ELEMENTS_RO(circuit->mt_settings, node, setting)) {
		const char *name = isis_mtid2str(setting->mtid);
		if (name && !setting->enabled) {
			vty_out(vty, " no isis topology %s\n", name);
			written++;
		}
	}
	return written;
}

struct isis_circuit_mt_setting **
circuit_mt_settings(struct isis_circuit *circuit, unsigned int *mt_count)
{
	static unsigned int size = 0;
	static struct isis_circuit_mt_setting **rv = NULL;

	struct isis_area_mt_setting **area_settings;
	unsigned int area_count;

	unsigned int count = 0;

	struct listnode *node;
	struct isis_circuit_mt_setting *setting;

	area_settings = area_mt_settings(circuit->area, &area_count);

	for (unsigned int i = 0; i < area_count; i++) {
		for (ALL_LIST_ELEMENTS_RO(circuit->mt_settings, node,
					  setting)) {
			if (setting->mtid != area_settings[i]->mtid)
				continue;
			break;
		}
		if (!setting)
			setting = circuit_get_mt_setting(
				circuit, area_settings[i]->mtid);

		if (!setting->enabled)
			continue;

		count++;
		if (count > size) {
			rv = XREALLOC(MTYPE_TMP, rv, count * sizeof(*rv));
			size = count;
		}
		rv[count - 1] = setting;
	}

	*mt_count = count;
	return rv;
}

/* ADJ specific MT API */
static void adj_mt_set(struct isis_adjacency *adj, unsigned int index,
		       uint16_t mtid)
{
	if (adj->mt_count < index + 1) {
		adj->mt_set = XREALLOC(MTYPE_MT_ADJ_INFO, adj->mt_set,
				       (index + 1) * sizeof(*adj->mt_set));
		adj->mt_count = index + 1;
	}
	adj->mt_set[index] = mtid;
}

bool tlvs_to_adj_mt_set(struct isis_tlvs *tlvs, bool v4_usable, bool v6_usable,
			struct isis_adjacency *adj)
{
	struct isis_circuit_mt_setting **mt_settings;
	unsigned int circuit_mt_count;

	unsigned int intersect_count = 0;

	uint16_t *old_mt_set = NULL;
	unsigned int old_mt_count;

	old_mt_count = adj->mt_count;
	if (old_mt_count) {
		old_mt_set =
			XCALLOC(MTYPE_TMP, old_mt_count * sizeof(*old_mt_set));
		memcpy(old_mt_set, adj->mt_set,
		       old_mt_count * sizeof(*old_mt_set));
	}

	mt_settings = circuit_mt_settings(adj->circuit, &circuit_mt_count);
	for (unsigned int i = 0; i < circuit_mt_count; i++) {
		if (!tlvs->mt_router_info.count
		    && !tlvs->mt_router_info_empty) {
			/* Other end does not have MT enabled */
			if (mt_settings[i]->mtid == ISIS_MT_IPV4_UNICAST
			    && v4_usable)
				adj_mt_set(adj, intersect_count++,
					   ISIS_MT_IPV4_UNICAST);
		} else {
			struct isis_mt_router_info *info_head;

			info_head = (struct isis_mt_router_info *)
					    tlvs->mt_router_info.head;
			for (struct isis_mt_router_info *info = info_head; info;
			     info = info->next) {
				if (mt_settings[i]->mtid == info->mtid) {
					bool usable;
					switch (info->mtid) {
					case ISIS_MT_IPV4_UNICAST:
					case ISIS_MT_IPV4_MGMT:
					case ISIS_MT_IPV4_MULTICAST:
						usable = v4_usable;
						break;
					case ISIS_MT_IPV6_UNICAST:
					case ISIS_MT_IPV6_MGMT:
					case ISIS_MT_IPV6_MULTICAST:
						usable = v6_usable;
						break;
					default:
						usable = true;
						break;
					}
					if (usable)
						adj_mt_set(adj,
							   intersect_count++,
							   info->mtid);
				}
			}
		}
	}
	adj->mt_count = intersect_count;

	bool changed = false;

	if (adj->mt_count != old_mt_count)
		changed = true;

	if (!changed && old_mt_count
	    && memcmp(adj->mt_set, old_mt_set,
		      old_mt_count * sizeof(*old_mt_set)))
		changed = true;

	if (old_mt_count)
		XFREE(MTYPE_TMP, old_mt_set);

	return changed;
}

bool adj_has_mt(struct isis_adjacency *adj, uint16_t mtid)
{
	for (unsigned int i = 0; i < adj->mt_count; i++)
		if (adj->mt_set[i] == mtid)
			return true;
	return false;
}

void adj_mt_finish(struct isis_adjacency *adj)
{
	XFREE(MTYPE_MT_ADJ_INFO, adj->mt_set);
	adj->mt_count = 0;
}

static void mt_set_add(uint16_t **mt_set, unsigned int *size,
		       unsigned int *index, uint16_t mtid)
{
	for (unsigned int i = 0; i < *index; i++) {
		if ((*mt_set)[i] == mtid)
			return;
	}

	if (*index >= *size) {
		*mt_set = XREALLOC(MTYPE_TMP, *mt_set,
				   sizeof(**mt_set) * ((*index) + 1));
		*size = (*index) + 1;
	}

	(*mt_set)[*index] = mtid;
	*index = (*index) + 1;
}

static uint16_t *circuit_bcast_mt_set(struct isis_circuit *circuit, int level,
				      unsigned int *mt_count)
{
	static uint16_t *rv;
	static unsigned int size;
	struct listnode *node;
	struct isis_adjacency *adj;

	unsigned int count = 0;

	if (circuit->circ_type != CIRCUIT_T_BROADCAST) {
		*mt_count = 0;
		return NULL;
	}

	for (ALL_LIST_ELEMENTS_RO(circuit->u.bc.adjdb[level - 1], node, adj)) {
		if (adj->adj_state != ISIS_ADJ_UP)
			continue;
		for (unsigned int i = 0; i < adj->mt_count; i++)
			mt_set_add(&rv, &size, &count, adj->mt_set[i]);
	}

	*mt_count = count;
	return rv;
}

static void tlvs_add_mt_set(struct isis_area *area, struct isis_tlvs *tlvs,
			    unsigned int mt_count, uint16_t *mt_set,
			    uint8_t *id, uint32_t metric, uint8_t *subtlvs,
			    uint8_t subtlv_len)
{
	for (unsigned int i = 0; i < mt_count; i++) {
		uint16_t mtid = mt_set[i];
		if (mt_set[i] == ISIS_MT_IPV4_UNICAST) {
			lsp_debug(
				"ISIS (%s): Adding %s.%02x as te-style neighbor",
				area->area_tag, sysid_print(id),
				LSP_PSEUDO_ID(id));
		} else {
			lsp_debug(
				"ISIS (%s): Adding %s.%02x as mt-style neighbor for %s",
				area->area_tag, sysid_print(id),
				LSP_PSEUDO_ID(id), isis_mtid2str(mtid));
		}
		isis_tlvs_add_extended_reach(tlvs, mtid, id, metric, subtlvs,
					     subtlv_len);
	}
}

void tlvs_add_mt_bcast(struct isis_tlvs *tlvs, struct isis_circuit *circuit,
		       int level, uint8_t *id, uint32_t metric,
		       uint8_t *subtlvs, uint8_t subtlv_len)
{
	unsigned int mt_count;
	uint16_t *mt_set = circuit_bcast_mt_set(circuit, level, &mt_count);

	tlvs_add_mt_set(circuit->area, tlvs, mt_count, mt_set, id, metric,
			subtlvs, subtlv_len);
}

void tlvs_add_mt_p2p(struct isis_tlvs *tlvs, struct isis_circuit *circuit,
		     uint8_t *id, uint32_t metric, uint8_t *subtlvs,
		     uint8_t subtlv_len)
{
	struct isis_adjacency *adj = circuit->u.p2p.neighbor;

	tlvs_add_mt_set(circuit->area, tlvs, adj->mt_count, adj->mt_set, id,
			metric, subtlvs, subtlv_len);
}
