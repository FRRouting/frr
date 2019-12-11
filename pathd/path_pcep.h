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

#ifndef _PATH_PCEP_H_
#define _PATH_PCEP_H_

#include <stdbool.h>
#include <debug.h>
#include <pcep_pcc_api.h>
#include <pcep_pcc_api.h>
#include "typesafe.h"
#include "pathd/path_memory.h"

#define MAX_PCC 1
#define CLASS_TYPE(CLASS, TYPE) (((CLASS) << 16) | (TYPE))
#define PCEP_DEBUG(fmt, ...) DEBUGD(&pcep_g->dbg, fmt, ##__VA_ARGS__)

typedef struct pcep_glob_t_ {
	struct debug dbg;
	struct thread_master *master;
	struct frr_pthread *fpt;
} pcep_glob_t;

typedef struct pcc_opts_t_ {
	struct in_addr addr;
	short port;
} pcc_opts_t;

typedef enum {
	INITIALIZED = 0,
	DISCONNECTED,
	CONNECTING,
	SYNCHRONIZING,
	OPERATING
} pcc_status_t;

typedef struct lsp_nb_key_t_ {
	uint32_t color;
	struct ipaddr endpoint;
	uint32_t preference;
} lsp_nb_key_t;

PREDECL_HASH(plspid_map)
PREDECL_HASH(nbkey_map)

typedef struct plspid_map_t_ {
	struct plspid_map_item mi;
	lsp_nb_key_t nbkey;
	uint32_t plspid;
} plspid_map_t;

typedef struct nbkey_map_t_ {
	struct nbkey_map_item mi;
	lsp_nb_key_t nbkey;
	uint32_t plspid;
} nbkey_map_t;

typedef struct pcc_state_t_ {
	int id;
	pcc_status_t status;
	pcc_opts_t *opts;
	pcep_configuration * config;
	pcep_session *sess;
	struct plspid_map_head plspid_map;
	struct nbkey_map_head nbkey_map;
} pcc_state_t;

typedef struct ctrl_state_t_ {
	struct thread_master *main;
	struct thread_master *self;
	struct thread *t_poll;
	int pcc_count;
	pcc_state_t *pcc[MAX_PCC];
} ctrl_state_t;

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
	lsp_nb_key_t nbkey;
	uint32_t plsp_id;
	uint32_t srp_id;
	char *name;
	enum pcep_lsp_operational_status status;
	bool do_remove;
	bool go_active;
	bool was_created;
	bool was_removed;
	bool is_synching;
	bool is_delegated;
	path_hop_t *first;
} path_t;

typedef struct event_pcc_update_t_ {
	ctrl_state_t *ctrl_state;
	int pcc_id;
	pcc_opts_t *pcc_opts;
} event_pcc_update_t;

typedef struct event_pcc_path_t_ {
	ctrl_state_t *ctrl_state;
	int pcc_id;
	path_t *path;
} event_pcc_path_t;

extern pcep_glob_t *pcep_g;

DECLARE_MTYPE(PCEP)

#endif // _PATH_PCEP_H_