// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright (C) 2020  NetDEF, Inc.
 */

#ifndef _PATH_PCEP_CONTROLLER_H_
#define _PATH_PCEP_CONTROLLER_H_

#include "pathd/path_pcep.h"

struct ctrl_state;
struct pcc_state;

enum pcep_main_event_type {
	PCEP_MAIN_EVENT_UNDEFINED = 0,
	PCEP_MAIN_EVENT_START_SYNC,
	PCEP_MAIN_EVENT_INITIATE_CANDIDATE,
	PCEP_MAIN_EVENT_UPDATE_CANDIDATE,
	PCEP_MAIN_EVENT_REMOVE_CANDIDATE_LSP,
};

typedef int (*pcep_main_event_handler_t)(enum pcep_main_event_type type,
					 int pcc_id, void *payload);
typedef void (*pcep_refine_callback_t)(struct ctrl_state *ctrl_state,
				       struct pcc_state *pcc_state,
				       struct path *path, void *payload);

enum pcep_pathd_event_type {
	PCEP_PATH_UNDEFINED = 0,
	PCEP_PATH_CREATED,
	PCEP_PATH_UPDATED,
	PCEP_PATH_REMOVED
};

struct ctrl_state {
	struct event_loop *main;
	struct event_loop *self;
	pcep_main_event_handler_t main_event_handler;
	struct pcc_opts *pcc_opts;
	int pcc_count;
	int pcc_last_id;
	struct pcc_state *pcc[MAX_PCC];
};

/* Timer handling data structures */

enum pcep_ctrl_timeout_type { TO_UNDEFINED, TO_COMPUTATION_REQUEST, TO_MAX };

enum pcep_ctrl_timer_type {
	TM_UNDEFINED,
	TM_RECONNECT_PCC,
	TM_PCEPLIB_TIMER,
	TM_TIMEOUT,
	TM_CALCULATE_BEST_PCE,
	TM_SESSION_TIMEOUT_PCC,
	TM_MAX
};

struct pcep_ctrl_timer_data {
	struct ctrl_state *ctrl_state;
	enum pcep_ctrl_timer_type timer_type;
	enum pcep_ctrl_timeout_type timeout_type;
	int pcc_id;
	void *payload;
};

/* Socket handling data structures */

enum pcep_ctrl_socket_type { SOCK_PCEPLIB = 1 };

struct pcep_ctrl_socket_data {
	struct ctrl_state *ctrl_state;
	enum pcep_ctrl_socket_type type;
	bool is_read;
	int fd;
	int pcc_id;
	void *payload;
};

typedef void (*pcep_ctrl_thread_callback)(struct event *);

/* PCC connection information, populated in a thread-safe
 * manner with pcep_ctrl_get_pcc_info() */
struct pcep_pcc_info {
	struct ctrl_state *ctrl_state; /* will be NULL when returned */
	char pce_name[64];
	int pcc_id;
	struct ipaddr pcc_addr;
	uint16_t pcc_port;
	int status;
	short msd;
	uint32_t next_reqid;
	uint32_t next_plspid;
	bool is_best_multi_pce;
	bool previous_best;
	uint8_t precedence;
};

/* Functions called from the main thread */
int pcep_ctrl_initialize(struct event_loop *main_thread,
			 struct frr_pthread **fpt,
			 pcep_main_event_handler_t event_handler);
int pcep_ctrl_finalize(struct frr_pthread **fpt);
int pcep_ctrl_update_pcc_options(struct frr_pthread *fpt,
				 struct pcc_opts *opts);
int pcep_ctrl_update_pce_options(struct frr_pthread *fpt,
				 struct pce_opts *opts);
int pcep_ctrl_remove_pcc(struct frr_pthread *fpt, struct pce_opts *pce_opts);
int pcep_ctrl_reset_pcc_session(struct frr_pthread *fpt, char *pce_name);
int pcep_ctrl_pathd_event(struct frr_pthread *fpt,
			  enum pcep_pathd_event_type type, struct path *path);
int pcep_ctrl_sync_path(struct frr_pthread *fpt, int pcc_id, struct path *path);
int pcep_ctrl_sync_done(struct frr_pthread *fpt, int pcc_id);
struct counters_group *pcep_ctrl_get_counters(struct frr_pthread *fpt,
					      int pcc_id);
pcep_session *pcep_ctrl_get_pcep_session(struct frr_pthread *fpt, int pcc_id);
struct pcep_pcc_info *pcep_ctrl_get_pcc_info(struct frr_pthread *fpt,
					     const char *pce_name);

/* Asynchronously send a report. The caller is giving away the path structure,
 * it shouldn't be allocated on the stack. If `pcc_id` is `0` the report is
 * sent by all PCCs.  The parameter is_stable is used to hint whether the status
 * will soon change, this is used to ensure all report updates are sent even
 * when missing status update events */
int pcep_ctrl_send_report(struct frr_pthread *fpt, int pcc_id,
			  struct path *path, bool is_stable);

int pcep_ctrl_send_error(struct frr_pthread *fpt, int pcc_id,
			 struct pcep_error *error);

/* Functions called from the controller thread */
void pcep_thread_start_sync(struct ctrl_state *ctrl_state, int pcc_id);
void pcep_thread_update_path(struct ctrl_state *ctrl_state, int pcc_id,
			     struct path *path);
void pcep_thread_initiate_path(struct ctrl_state *ctrl_state, int pcc_id,
			       struct path *path);
void pcep_thread_cancel_timer(struct event **thread);
void pcep_thread_schedule_reconnect(struct ctrl_state *ctrl_state, int pcc_id,
				    int retry_count, struct event **thread);
void pcep_thread_schedule_timeout(struct ctrl_state *ctrl_state, int pcc_id,
				  enum pcep_ctrl_timeout_type type,
				  uint32_t delay, void *param,
				  struct event **thread);
void pcep_thread_schedule_session_timeout(struct ctrl_state *ctrl_state,
					  int pcc_id, int delay,
					  struct event **thread);
void pcep_thread_remove_candidate_path_segments(struct ctrl_state *ctrl_state,
						struct pcc_state *pcc_state);

void pcep_thread_schedule_sync_best_pce(struct ctrl_state *ctrl_state,
					int pcc_id, int delay,
					struct event **thread);
void pcep_thread_schedule_pceplib_timer(struct ctrl_state *ctrl_state,
					int delay, void *payload,
					struct event **thread,
					pcep_ctrl_thread_callback cb);
int pcep_thread_socket_read(void *fpt, void **thread, int fd, void *payload,
			    pcep_ctrl_thread_callback cb);
int pcep_thread_socket_write(void *fpt, void **thread, int fd, void *payload,
			     pcep_ctrl_thread_callback cb);

int pcep_thread_send_ctrl_event(void *fpt, void *payload,
				pcep_ctrl_thread_callback cb);
void pcep_thread_pcep_event(struct event *thread);
int pcep_thread_pcc_count(struct ctrl_state *ctrl_state);
/* Called by the PCC to refine a path in the main thread */
int pcep_thread_refine_path(struct ctrl_state *ctrl_state, int pcc_id,
			    pcep_refine_callback_t cb, struct path *path,
			    void *payload);

#endif // _PATH_PCEP_CONTROLLER_H_
