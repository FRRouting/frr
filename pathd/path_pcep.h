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

#define MAX_PCC 1

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


#endif // _PATH_PCEP_H_