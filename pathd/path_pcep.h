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
#include "mpls.h"
#include "typesafe.h"
#include "pathd/path_memory.h"

#define MAX_PCC 1
#define CLASS_TYPE(CLASS, TYPE) (((CLASS) << 16) | (TYPE))
#define PCEP_DEBUG(fmt, ...) DEBUGD(&pcep_g->dbg, fmt, ##__VA_ARGS__)

typedef enum {
	INITIALIZED = 0,
	DISCONNECTED,
	CONNECTING,
	SYNCHRONIZING,
	OPERATING
} pcc_status_t;

typedef enum {
	CANDIDATE_CREATED = 0,
	CANDIDATE_UPDATED,
	CANDIDATE_REMOVED
} pathd_event_t;

typedef struct pcep_glob_t_ {
	struct debug dbg;
	struct thread_master *master;
	struct frr_pthread *fpt;
} pcep_glob_t;

typedef struct pce_opts_t_ {
	struct in_addr addr;
	short port;
} pce_opts_t;

typedef struct pcc_opts_t_ {
	struct in_addr addr;
	short port;
} pcc_opts_t;

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
	pcc_opts_t *pcc_opts;
	pce_opts_t *pce_opts;
	pcep_configuration * config;
	pcep_session *sess;
	uint32_t retry_count;
	bool synchronized;
	struct thread *t_reconnect;
	struct thread *t_update_opts;
	uint32_t next_plspid;
	struct plspid_map_head plspid_map;
	struct nbkey_map_head nbkey_map;
} pcc_state_t;

typedef struct ctrl_state_t_ {
	struct thread_master *main;
	struct thread_master *self;
	struct thread *t_poll;
	pcc_opts_t *pcc_opts;
	int pcc_count;
	pcc_state_t *pcc[MAX_PCC];
} ctrl_state_t;

typedef struct sid_mpls_t_ {
	mpls_label_t label;
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
	/* Pointer to the next hop in the path */
	struct path_hop_t_ *next;
	/* Indicateif this ia a loose or strict hop */
	bool is_loose;
	/* Indicate if there is an SID for the hop */
	bool has_sid;
	/* Indicate if the hop as a MPLS label */
	bool is_mpls;
	/* Indicate if the MPLS label has extra attributes (TTL, class..)*/
	bool has_attribs;
	/* Hop's SID if available */
	sid_t sid;
	/* Indicate if there ia a NAI for this hop */
	bool has_nai;
	/* Indicate Hop's NAI type if available */
	enum pcep_sr_subobj_nai nai_type;
	/* Hop's NAI if available */
	nai_t nai;
} path_hop_t;

typedef struct path_t_ {
	/* The address the path is comming from (only work for the PCE for now) */
	struct ipaddr sender;
	/* The northbound key identifying this path */
	lsp_nb_key_t nbkey;
	/* The generated unique PLSP identifier for this path.
	   See draft-ietf-pce-stateful-pce */
	uint32_t plsp_id;
	/* The request identifier from the PCE, when getting a path from the PCE.
	   See draft-ietf-pce-stateful-pce */
	uint32_t srp_id;
	/* The name of the path */
	char *name;
	/* The operational status of the path */
	enum pcep_lsp_operational_status status;
	/* If true, the receiver (PCC) must remove the path.
	   See draft-ietf-pce-pce-initiated-lsp */
	bool do_remove;
	/* Indicate if the PCE wants the path to get active.
	   See draft-ietf-pce-stateful-pce, section-7.3, flag A */
	bool go_active;
	/* Indicate the given path was created by the PCE,
	   See draft-ietf-pce-pce-initiated-lsp, section-5.3.1, flag C */
	bool was_created;
	/* Indicate the given path was removed by the PCC.
	   See draft-ietf-pce-stateful-pce, section-7.3, flag R */
	bool was_removed;
	/* Indicate the path is part of the synchronization process.
	   See draft-ietf-pce-stateful-pce, section-7.3, flag S */
	bool is_synching;
	/* Indicate the path is delegated to the PCE.
	   See draft-ietf-pce-stateful-pce, section-7.3, flag D */
	bool is_delegated;
	/* Specify the list of hop defining the path */
	path_hop_t *first;
} path_t;

typedef struct event_pcc_update_t_ {
	ctrl_state_t *ctrl_state;
	pcc_opts_t *pcc_opts;
} event_pcc_update_t;

typedef struct event_pce_update_t_ {
	ctrl_state_t *ctrl_state;
	int pcc_id;
	pce_opts_t *pce_opts;
} event_pce_update_t;

typedef int (*pcc_cb_t)(ctrl_state_t *ctrl_state,
                        pcc_state_t *pcc_state);

typedef struct event_pcc_cb_t_ {
	ctrl_state_t *ctrl_state;
	int pcc_id;
	pcc_cb_t cb;
} event_pcc_cb_t;

typedef struct event_pcc_path_t_ {
	ctrl_state_t *ctrl_state;
	int pcc_id;
	path_t *path;
} event_pcc_path_t;

typedef struct event_pathd_t_ {
	ctrl_state_t *ctrl_state;
	pathd_event_t type;
	path_t *path;
} event_pathd_t;

extern pcep_glob_t *pcep_g;

DECLARE_MTYPE(PCEP)

#endif // _PATH_PCEP_H_