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

#ifndef _PATH_PCEP_CONTROLLER_H_
#define _PATH_PCEP_CONTROLLER_H_

#include "pathd/path_pcep.h"


enum pcep_main_event_type {
	PCEP_MAIN_EVENT_UNDEFINED = 0,
	PCEP_MAIN_EVENT_START_SYNC,
	PCEP_MAIN_EVENT_UPDATE_CANDIDATE
};

typedef int (*pcep_main_event_handler_t)(enum pcep_main_event_type type,
					 int pcc_id, void *payload);

enum pcep_pathd_event_type {
	PCEP_PATH_UNDEFINED = 0,
	PCEP_PATH_CREATED,
	PCEP_PATH_UPDATED,
	PCEP_PATH_REMOVED
};

struct ctrl_state {
	struct thread_master *main;
	struct thread_master *self;
	pcep_main_event_handler_t main_event_handler;
	struct pcc_opts *pcc_opts;
	int pcc_count;
	struct pcc_state *pcc[MAX_PCC];
};

/* Timer handling data structures */

enum pcep_ctrl_timer_type { TM_RECONNECT_PCC, TM_PCEPLIB_TIMER };

struct pcep_ctrl_timer_data {
    struct ctrl_state *ctrl_state;
    enum pcep_ctrl_timer_type type;
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

typedef int (*pcep_ctrl_thread_callback)(struct thread *);

/* Functions called from the main thread */
int pcep_ctrl_initialize(struct thread_master *main_thread,
			 struct frr_pthread **fpt,
			 pcep_main_event_handler_t event_handler);
int pcep_ctrl_finalize(struct frr_pthread **fpt);
int pcep_ctrl_update_pcc_options(struct frr_pthread *fpt,
				 struct pcc_opts *opts);
int pcep_ctrl_update_pce_options(struct frr_pthread *fpt, int pcc_id,
				 struct pce_opts *opts);
int pcep_ctrl_remove_pcc(struct frr_pthread *fpt, int pcc_id);
int pcep_ctrl_pathd_event(struct frr_pthread *fpt,
			  enum pcep_pathd_event_type type, struct path *path);
int pcep_ctrl_sync_path(struct frr_pthread *fpt, int pcc_id, struct path *path);
int pcep_ctrl_sync_done(struct frr_pthread *fpt, int pcc_id);
struct counters_group *pcep_ctrl_get_counters(struct frr_pthread *fpt,
					      int pcc_id);
/* Synchronously send a report, the caller is responsible to free the path,
 * If `pcc_id` is `0` the report is sent by all PCCs */
void pcep_ctrl_send_report(struct frr_pthread *fpt, int pcc_id,
                           struct path *path);

/* Functions called from the controller thread */
void pcep_thread_start_sync(struct ctrl_state *ctrl_state, int pcc_id);
void pcep_thread_update_path(struct ctrl_state *ctrl_state, int pcc_id,
			     struct path *path);
void pcep_thread_schedule_reconnect(struct ctrl_state *ctrl_state, int pcc_id,
				    int retry_count, struct thread **thread);

void pcep_thread_schedule_pceplib_timer(struct ctrl_state *ctrl_state,
        int delay, void *payload, struct thread **thread,
        pcep_ctrl_thread_callback cb);
void pcep_thread_cancel_pceplib_timer(struct thread **thread);
int pcep_thread_socket_read(void *fpt, void **thread, int fd,
        void *payload, pcep_ctrl_thread_callback cb);
int pcep_thread_socket_write(void *fpt, void **thread, int fd,
        void *payload, pcep_ctrl_thread_callback cb);

int pcep_thread_send_ctrl_event(void *fpt, void *payload,
				pcep_ctrl_thread_callback cb);
int pcep_thread_pcep_event(struct thread *thread);

#endif // _PATH_PCEP_CONTROLLER_H_
