/*
 * Copyright (C) 2018  NetDEF, Inc.
 *                     Sebastien Merle
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

#ifndef _PATH_PCEP_LIB_H_
#define _PATH_PCEP_LIB_H_

#include <stdbool.h>
#include <pcep_pcc_api.h>

/* Should be in pceplib */
#define GET_SR_ERO_SID_LABEL(SID)   ((SID & 0xfffff000) >> 12)
#define GET_SR_ERO_SID_TC(SID)      ((SID & 0x00000e00) >> 9)
#define GET_SR_ERO_SID_S(SID)       ((SID & 0x00000100) >> 8)
#define GET_SR_ERO_SID_TTL(SID)     ((SID & 0x000000ff))


typedef struct sid_mpls_t_ {
	uint16_t label;
	uint8_t traffic_class;
	bool is_bottom;
	uint8_t ttl;
} sid_mpls_t;

typedef union sid_t_ {
	uint32_t value;
	sid_mpls_t mpls;
} sid_t;

typedef struct nai_ipv4_node_t_ {
	struct in_addr addr;
} nai_ipv4_node_t;

typedef union nai_t_ {
	nai_ipv4_node_t ipv4_node;
} nai_t;

typedef struct path_hop_t_ {
	struct path_hop_t_ *next;
	bool is_loose;
	bool has_sid;
	bool is_mpls;
	bool has_attribs;
	sid_t sid;
	bool has_nai;
	enum pcep_sr_subobj_nai nai_type;
	nai_t nai;
} path_hop_t;

typedef struct path_t_ {
	char *name;
	uint32_t srp_id;
	uint32_t plsp_id;
	enum pcep_lsp_operational_status status;
	bool do_remove;
	bool go_active;
	bool was_created;
	bool was_removed;
	bool is_synching;
	bool is_delegated;
	path_hop_t *first;
} path_t;


int pcep_lib_connect(pcc_state_t *pcc_state);
void pcep_lib_disconnect(pcc_state_t *pcc_state);
double_linked_list *pcep_lib_format_path(path_t *path);
path_t *pcep_lib_parse_path(double_linked_list *objs);
void pcep_lib_free_path(path_t *path);


#endif // _PATH_PCEP_LIB_H_