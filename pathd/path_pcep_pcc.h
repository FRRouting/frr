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

#ifndef _PATH_PCEP_PCC_H_
#define _PATH_PCEP_PCC_H_

#include "typesafe.h"
#include "pathd/path_pcep.h"

enum pcc_status {
	PCEP_PCC_INITIALIZED = 0,
	PCEP_PCC_DISCONNECTED,
	PCEP_PCC_CONNECTING,
	PCEP_PCC_SYNCHRONIZING,
	PCEP_PCC_OPERATING
};

PREDECL_HASH(plspid_map)
PREDECL_HASH(nbkey_map)
PREDECL_HASH(req_map)

struct plspid_map_data {
	struct plspid_map_item mi;
	struct lsp_nb_key nbkey;
	uint32_t plspid;
	uint16_t tid;
	uint16_t lspid;
};

struct nbkey_map_data {
	struct nbkey_map_item mi;
	struct lsp_nb_key nbkey;
	uint32_t plspid;
	uint16_t tid;
	uint16_t lspid;
};

struct req_map_data {
	struct req_map_item mi;
	uint32_t reqid;
	struct lsp_nb_key nbkey;
};

struct pcc_state {
	int id;
	char tag[MAX_TAG_SIZE];
	enum pcc_status status;
	struct pcc_opts *pcc_opts;
	struct pce_opts *pce_opts;
	pcep_session *sess;
	uint32_t retry_count;
	bool synchronized;
	struct thread *t_reconnect;
	struct thread *t_update_opts;
	uint32_t next_reqid;
	uint32_t next_plspid;
	uint16_t next_tid;
	uint16_t next_lspid;
	struct plspid_map_head plspid_map;
	struct nbkey_map_head nbkey_map;
	struct req_map_head req_map;
	struct pcep_caps caps;
};

struct pcc_state *pcep_pcc_initialize(struct ctrl_state *ctrl_state,
				      int pcc_id);
void pcep_pcc_finalize(struct ctrl_state *ctrl_state,
		       struct pcc_state *pcc_state);
int pcep_pcc_enable(struct ctrl_state *ctrl_state, struct pcc_state *pcc_state);
int pcep_pcc_disable(struct ctrl_state *ctrl_state,
		     struct pcc_state *pcc_state);
int pcep_pcc_update(struct ctrl_state *ctrl_state, struct pcc_state *pcc_state,
		    struct pcc_opts *pcc_opts, struct pce_opts *pce_opts);
void pcep_pcc_reconnect(struct ctrl_state *ctrl_state,
			struct pcc_state *pcc_state);
void pcep_pcc_pcep_event_handler(struct ctrl_state *ctrl_state,
				 struct pcc_state *pcc_state,
				 pcep_event *event);
void pcep_pcc_pathd_event_handler(struct ctrl_state *ctrl_state,
				  struct pcc_state *pcc_state,
				  enum pcep_pathd_event_type type,
				  struct path *path);
void pcep_pcc_sync_path(struct ctrl_state *ctrl_state,
			struct pcc_state *pcc_state, struct path *path);
void pcep_pcc_sync_done(struct ctrl_state *ctrl_state,
			struct pcc_state *pcc_state);

#endif // _PATH_PCEP_PCC_H_
