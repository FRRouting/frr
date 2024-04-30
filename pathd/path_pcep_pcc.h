// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright (C) 2020  NetDEF, Inc.
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

PREDECL_HASH(plspid_map);
PREDECL_HASH(nbkey_map);
PREDECL_HASH(req_map);

struct plspid_map_data {
	struct plspid_map_item mi;
	struct lsp_nb_key nbkey;
	uint32_t plspid;
};

struct nbkey_map_data {
	struct nbkey_map_item mi;
	struct lsp_nb_key nbkey;
	uint32_t plspid;
};

struct req_map_data {
	struct req_map_item mi;
	struct lsp_nb_key nbkey;
	uint32_t reqid;
};

struct req_entry {
	RB_ENTRY(req_entry) entry;
	struct event *t_retry;
	int retry_count;
	bool was_sent;
	struct path *path;
};
RB_HEAD(req_entry_head, req_entry);
RB_PROTOTYPE(req_entry_head, req_entry, entry, req_entry_compare);

struct pcc_state {
	int id;
	char tag[MAX_TAG_SIZE];
	enum pcc_status status;
	uint16_t flags;
#define F_PCC_STATE_HAS_IPV4 0x0002
#define F_PCC_STATE_HAS_IPV6 0x0004
	struct pcc_opts *pcc_opts;
	struct pce_opts *pce_opts;
	struct in_addr pcc_addr_v4;
	struct in6_addr pcc_addr_v6;
	/* PCC transport source address */
	struct ipaddr pcc_addr_tr;
	char *originator;
	pcep_session *sess;
	uint32_t retry_count;
	bool synchronized;
	struct event *t_reconnect;
	struct event *t_update_best;
	struct event *t_session_timeout;
	uint32_t next_reqid;
	uint32_t next_plspid;
	struct plspid_map_head plspid_map;
	struct nbkey_map_head nbkey_map;
	struct req_map_head req_map;
	struct req_entry_head requests;
	struct pcep_caps caps;
	bool is_best;
	bool previous_best;
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
void pcep_pcc_timeout_handler(struct ctrl_state *ctrl_state,
			      struct pcc_state *pcc_state,
			      enum pcep_ctrl_timeout_type type, void *param);
void pcep_pcc_sync_path(struct ctrl_state *ctrl_state,
			struct pcc_state *pcc_state, struct path *path);
void pcep_pcc_sync_done(struct ctrl_state *ctrl_state,
			struct pcc_state *pcc_state);
/* Send a report explicitly. When doing so the PCC may send multiple reports
 * due to expectations from vendors for the first report to be with a DOWN
 * status. The parameter is_stable is used for that purpose as a hint wheter
 * to expect an update for the report */
void pcep_pcc_send_report(struct ctrl_state *ctrl_state,
			  struct pcc_state *pcc_state, struct path *path,
			  bool is_stable);
void pcep_pcc_send_error(struct ctrl_state *ctrl_state,
			 struct pcc_state *pcc_state, struct pcep_error *path,
			 bool is_stable);
int pcep_pcc_multi_pce_sync_path(struct ctrl_state *ctrl_state, int pcc_id,
				 struct pcc_state **pcc_state_list);
int pcep_pcc_multi_pce_remove_pcc(struct ctrl_state *ctrl_state,
				  struct pcc_state **pcc_state_list);
int pcep_pcc_timer_update_best_pce(struct ctrl_state *ctrl_state, int pcc_id);
int pcep_pcc_calculate_best_pce(struct pcc_state **pcc);
int pcep_pcc_get_pcc_id_by_ip_port(struct pcc_state **pcc,
				   struct pce_opts *pce_opts);
int pcep_pcc_get_pcc_id_by_idx(struct pcc_state **pcc, int idx);
struct pcc_state *pcep_pcc_get_pcc_by_id(struct pcc_state **pcc, int id);
struct pcc_state *pcep_pcc_get_pcc_by_name(struct pcc_state **pcc,
					   const char *pce_name);
int pcep_pcc_get_pcc_idx_by_id(struct pcc_state **pcc, int id);
int pcep_pcc_get_free_pcc_idx(struct pcc_state **pcc);
int pcep_pcc_get_pcc_id(struct pcc_state *pcc);
void pcep_pcc_copy_pcc_info(struct pcc_state **pcc,
			    struct pcep_pcc_info *pcc_info);

#endif // _PATH_PCEP_PCC_H_
