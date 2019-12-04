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
#include <pcep_pcc_api.h>
#include "pathd/path_memory.h"

#define MAX_PCC 1
#define CLASS_TYPE(CLASS, TYPE) (((CLASS) << 16) | (TYPE))

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

typedef struct pcc_state_t_ {
	int index;
	pcc_status_t status;
	pcc_opts_t *opts;
	pcep_configuration * config;
	pcep_session *sess;
} pcc_state_t;

typedef struct ctrl_state_t_ {
	struct thread_master *main;
	struct thread_master *self;
	struct thread *t_poll;
	int pcc_count;
	pcc_state_t *pcc[MAX_PCC];
} ctrl_state_t;

typedef struct event_pcc_update_t_ {
	ctrl_state_t *ctrl_state;
	int pcc_index;
	pcc_opts_t *pcc_opts;
} event_pcc_update_t;


/* Should be in path_pcep_lib.h */

typedef struct sid_mpls_t_ {
	uint16_t label;
	uint8_t traffic_class;
	bool is_bottom;
	uint8_t ttl;
} sid_mpls_t;

typedef union sid_t_ {
	sid_mpls_t mpls;
} sid_t;

typedef struct nai_ipv4_node_t_ {
	struct in_addr local;
} nai_ipv4_node_t;

typedef union nai_t_ {
	nai_ipv4_node_t ipv4_node;
} nai_t;

typedef struct path_hop_t_ {
	struct path_hop_t_ *next;
	enum pcep_sr_subobj_nai type;
	bool is_loose;
	bool has_sid;
	bool has_attribs;
	bool is_mpls;
	bool has_nai;
	sid_t sid;
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


DECLARE_MTYPE(PCEP)

#endif // _PATH_PCEP_H_