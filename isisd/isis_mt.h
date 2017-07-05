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
#ifndef ISIS_MT_H
#define ISIS_MT_H

#define ISIS_MT_MASK           0x0fff
#define ISIS_MT_OL_MASK        0x8000
#define ISIS_MT_AT_MASK        0x4000

#define ISIS_MT_IPV4_UNICAST   0
#define ISIS_MT_IPV4_MGMT      1
#define ISIS_MT_IPV6_UNICAST   2
#define ISIS_MT_IPV4_MULTICAST 3
#define ISIS_MT_IPV6_MULTICAST 4
#define ISIS_MT_IPV6_MGMT      5

#define ISIS_MT_NAMES                                                          \
	"<ipv4-unicast"                                                        \
	"|ipv4-mgmt"                                                           \
	"|ipv6-unicast"                                                        \
	"|ipv4-multicast"                                                      \
	"|ipv6-multicast"                                                      \
	"|ipv6-mgmt"                                                           \
	">"

#define ISIS_MT_DESCRIPTIONS                                                   \
	"IPv4 unicast topology\n"                                              \
	"IPv4 management topology\n"                                           \
	"IPv6 unicast topology\n"                                              \
	"IPv4 multicast topology\n"                                            \
	"IPv6 multicast topology\n"                                            \
	"IPv6 management topology\n"

#define ISIS_MT_INFO_FIELDS uint16_t mtid;

struct list;

struct isis_area_mt_setting {
	ISIS_MT_INFO_FIELDS
	bool enabled;
	bool overload;
};

struct isis_circuit_mt_setting {
	ISIS_MT_INFO_FIELDS
	bool enabled;
};

const char *isis_mtid2str(uint16_t mtid);
uint16_t isis_str2mtid(const char *name);

struct isis_adjacency;
struct isis_area;
struct isis_circuit;
struct tlvs;
struct te_is_neigh;
struct isis_tlvs;

uint16_t isis_area_ipv6_topology(struct isis_area *area);

struct isis_area_mt_setting *area_lookup_mt_setting(struct isis_area *area,
						    uint16_t mtid);
struct isis_area_mt_setting *area_new_mt_setting(struct isis_area *area,
						 uint16_t mtid);
void area_add_mt_setting(struct isis_area *area,
			 struct isis_area_mt_setting *setting);

void area_mt_init(struct isis_area *area);
void area_mt_finish(struct isis_area *area);
struct isis_area_mt_setting *area_get_mt_setting(struct isis_area *area,
						 uint16_t mtid);
int area_write_mt_settings(struct isis_area *area, struct vty *vty);
bool area_is_mt(struct isis_area *area);
struct isis_area_mt_setting **area_mt_settings(struct isis_area *area,
					       unsigned int *mt_count);

struct isis_circuit_mt_setting *
circuit_lookup_mt_setting(struct isis_circuit *circuit, uint16_t mtid);
struct isis_circuit_mt_setting *
circuit_new_mt_setting(struct isis_circuit *circuit, uint16_t mtid);
void circuit_add_mt_setting(struct isis_circuit *circuit,
			    struct isis_circuit_mt_setting *setting);
void circuit_mt_init(struct isis_circuit *circuit);
void circuit_mt_finish(struct isis_circuit *circuit);
struct isis_circuit_mt_setting *
circuit_get_mt_setting(struct isis_circuit *circuit, uint16_t mtid);
int circuit_write_mt_settings(struct isis_circuit *circuit, struct vty *vty);
struct isis_circuit_mt_setting **
circuit_mt_settings(struct isis_circuit *circuit, unsigned int *mt_count);
bool tlvs_to_adj_mt_set(struct isis_tlvs *tlvs, bool v4_usable, bool v6_usable,
			struct isis_adjacency *adj);
bool adj_has_mt(struct isis_adjacency *adj, uint16_t mtid);
void adj_mt_finish(struct isis_adjacency *adj);
void tlvs_add_mt_bcast(struct isis_tlvs *tlvs, struct isis_circuit *circuit,
		       int level, uint8_t *id, uint32_t metric,
		       uint8_t *subtlvs, uint8_t subtlv_len);
void tlvs_add_mt_p2p(struct isis_tlvs *tlvs, struct isis_circuit *circuit,
		     uint8_t *id, uint32_t metric, uint8_t *subtlvs,
		     uint8_t subtlv_len);
#endif
