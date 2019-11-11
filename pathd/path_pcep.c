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

#include <zebra.h>
#include <pcep_pcc_api.h>

#include "log.h"
#include "command.h"
#include "debug.h"
#include "libfrr.h"
#include "version.h"
#include "northbound.h"
#include "frr_pthread.h"

#include "pathd/path_errors.h"
#include "pathd/path_memory.h"

#define PCEP_DEFAULT_PORT 4189

#define PCEP_DEBUG(fmt, ...) DEBUGD(&pcep_g->dbg, fmt, ##__VA_ARGS__);

DEFINE_MTYPE_STATIC(PATHD, PCEP, "PCEP module")

typedef struct pcep_opts_t_ {
	struct in_addr addr;
	int port;
} pcep_opts_t;

typedef struct pcep_state_t_ {
	struct thread_master *main;
	struct thread_master *self;
	struct thread *t_poll;
	pcep_opts_t *opts;
} pcep_state_t;

/*
 * Globals.
 */
typedef struct pcep_glob_t_ {
	struct debug dbg;
	struct thread_master *master;
	struct frr_pthread *fpt;
} pcep_glob_t;

static pcep_glob_t pcep_glob_space = { .dbg = {0, "pathd module: pcep"} };
static pcep_glob_t *pcep_g = &pcep_glob_space;

static int pcep_pcc_init(pcep_state_t *pcep_state);
static void pcep_pcc_finish(pcep_state_t *pcep_state);
static void pcep_pcc_schedule_poll(pcep_state_t *pcep_state);
static void pcep_pcc_update_lsp(pcep_state_t *pcep_state);

static int pcep_pcc_poll_timer(struct thread *thread);

static int pcep_main_update_lsp_event(struct thread *thread);

static int pcep_start(pcep_opts_t *opts);
static int pcep_stop(void);
static int pcep_halt_cb(struct frr_pthread *fpt, void **res);

static int pcep_thread_init_event(struct thread *thread);
static int pcep_thread_finish_event(struct thread *thread);

static int pcep_cli_debug_config_write(struct vty *vty);
static int pcep_cli_debug_set_all(uint32_t flags, bool set);
static void pcep_cli_init(void);

static int pcep_module_finish(void);
static int pcep_module_late_init(struct thread_master *tm);
static int pcep_module_init(void);


//TODO: Proper PCC error handling

/* ------------ Utils ------------ */

/* ------------ PCC Thread Functions ------------ */

int pcep_pcc_init(pcep_state_t *pcep_state)
{
	PCEP_DEBUG("PCC controller thread initializing...");

    	if (!initialize_pcc())
    	{
        	flog_err(EC_PATH_PCEP_PCC_INIT,
			 "failed to initialize PCC");
		return 1;
    	}

	pcep_pcc_schedule_poll(pcep_state);

	return 0;
}

void pcep_pcc_finish(pcep_state_t *pcep_state)
{
	PCEP_DEBUG("PCC controller thread finalizing...");

	if (!destroy_pcc())
    	{
        	flog_err(EC_PATH_PCEP_PCC_FINI,
			 "failed to finalize PCC");
    	}
}

void pcep_pcc_schedule_poll(pcep_state_t *pcep_state)
{
	assert(NULL == pcep_state->t_poll);
	thread_add_timer(pcep_state->self, pcep_pcc_poll_timer,
		         pcep_state, 1, &pcep_state->t_poll);
}

void pcep_pcc_update_lsp(pcep_state_t *pcep_state)
{
	thread_add_event(pcep_state->main,
		         pcep_main_update_lsp_event,
		         NULL, 0, NULL);
}

int pcep_pcc_poll_timer(struct thread *thread)
{
	pcep_state_t *pcep_state = THREAD_ARG(thread);

	pcep_state->t_poll = NULL;

	PCEP_DEBUG("Polling PCEP lib for notification...");

	pcep_pcc_update_lsp(pcep_state);

	pcep_pcc_schedule_poll(pcep_state);

	return 0;
}


/* ------------ Main Thread Functions ------------ */

int pcep_main_update_lsp_event(struct thread *thread)
{
	PCEP_DEBUG("Updating LSP...");
	return 0;
}


/* ------------ Thread Management Functions ------------ */

int pcep_start(pcep_opts_t *opts)
{
	int ret;
	pcep_state_t *pcep_state;
	struct frr_pthread *fpt;
	struct frr_pthread_attr attr = {
		.start = frr_pthread_attr_default.start,
		.stop = pcep_halt_cb,
	};

	/* If the PCEP thread is already running, stop it and start it again */
	if (NULL != pcep_g->fpt) {
		pcep_stop();
	}

	assert(!pcep_g->fpt);

	/* Create and start the FRR pthread */
	fpt = frr_pthread_new(&attr, "PCEP thread", "pcep");
	if (NULL == fpt) {
		flog_err(EC_PATH_PCEP_INIT,
			 "failed to initialize PCEP thread");
		return 1;
	}
	ret = frr_pthread_run(fpt, NULL);
	if (ret < 0) {
		flog_err(EC_PATH_PCEP_INIT,
			 "failed to create PCEP thread");
		return ret;
	}
	frr_pthread_wait_running(fpt);

	/* Initialise the thread state */
	pcep_state = XCALLOC(MTYPE_PCEP, sizeof(*pcep_state));
	pcep_state->main = pcep_g->master;
	pcep_state->self = fpt->master;
	pcep_state->t_poll = NULL;
	pcep_state->opts = opts;

	/* Keep the state reference for halting the thread */
	fpt->data = pcep_state;
	pcep_g->fpt = fpt;

	/* Initialize the PCEP thread */
	thread_add_event(fpt->master,
		         pcep_thread_init_event,
		         (void*)pcep_state, 0, NULL);

	return 0;
}

int pcep_halt_cb(struct frr_pthread *fpt, void **res)
{
	thread_add_event(fpt->master,
		         &pcep_thread_finish_event, fpt, 0, NULL);
	pthread_join(fpt->thread, res);

	return 0;
}

int pcep_stop(void)
{
	int ret = 0;

	if (NULL != pcep_g->fpt) {
		frr_pthread_stop(pcep_g->fpt, NULL);
		pcep_g->fpt = NULL;
	}

	return ret;
}

int pcep_thread_init_event(struct thread *thread)
{
	pcep_state_t *pcep_state = THREAD_ARG(thread);
	int ret = 0;

	pcep_pcc_init(pcep_state);

	return ret;
}

int pcep_thread_finish_event(struct thread *thread)
{
	struct frr_pthread *fpt = THREAD_ARG(thread);
	pcep_state_t *pcep_state = fpt->data;

	assert(NULL != pcep_state);
	assert(NULL != pcep_state->opts);

	pcep_pcc_finish(pcep_state);

	XFREE(MTYPE_PCEP, pcep_state->opts);
	XFREE(MTYPE_PCEP, pcep_state);
	fpt->data = NULL;

	atomic_store_explicit(&fpt->running, false, memory_order_relaxed);
	return 0;
}


/* ------------ CLI ------------ */

DEFUN (pcep_cli_pce_ip,
       pcep_cli_pce_ip_cmd,
        "pce ip A.B.C.D [port (1024-65535)]",
        "PCE remote ip and port\n"
        "Remote PCE server ip A.B.C.D\n"
        "Remote PCE server port")
{
	struct in_addr pce_addr;
	uint32_t pce_port = PCEP_DEFAULT_PORT;
	pcep_opts_t *opts;

	int ip_idx = 2;
	int port_idx = 4;

	if (!inet_pton(AF_INET, argv[ip_idx]->arg, &(pce_addr.s_addr)))
		return CMD_ERR_INCOMPLETE;

	if (argc > port_idx)
		pce_port = atoi(argv[port_idx]->arg);

	opts = XCALLOC(MTYPE_PCEP, sizeof(*opts));
	opts->addr = pce_addr;
	opts->port = pce_port;

	if (pcep_start(opts))
		return CMD_WARNING;

	return CMD_SUCCESS;
}

DEFUN (pcep_cli_no_pce,
       pcep_cli_no_pce_cmd,
        "no pce",
        NO_STR
        "Disable pce\n")
{
	pcep_stop();
	return CMD_SUCCESS;
}

DEFUN (pcep_cli_debug,
       pcep_cli_debug_cmd,
       "[no] debug pathd pcep",
       NO_STR
       DEBUG_STR
       "Pathd debugging\n"
       "pcep\n")
{
	uint32_t mode = DEBUG_NODE2MODE(vty->node);
	bool no = strmatch(argv[0]->text, "no");

	DEBUG_MODE_SET(&pcep_g->dbg, mode, !no);

	return CMD_SUCCESS;
}

int pcep_cli_debug_config_write(struct vty *vty)
{
	if (DEBUG_MODE_CHECK(&pcep_g->dbg, DEBUG_MODE_CONF))
		vty_out(vty, "debug pathd pcep\n");

	return 0;
}

int pcep_cli_debug_set_all(uint32_t flags, bool set)
{
	DEBUG_FLAGS_SET(&pcep_g->dbg, flags, set);

	/* If all modes have been turned off, don't preserve options. */
	if (!DEBUG_MODE_CHECK(&pcep_g->dbg, DEBUG_MODE_ALL))
		DEBUG_CLEAR(&pcep_g->dbg);

	return 0;
}

void pcep_cli_init(void)
{
	hook_register(nb_client_debug_config_write,
		      pcep_cli_debug_config_write);
	hook_register(nb_client_debug_set_all,
		      pcep_cli_debug_set_all);

	install_element(ENABLE_NODE, &pcep_cli_debug_cmd);
	install_element(CONFIG_NODE, &pcep_cli_debug_cmd);
	install_element(CONFIG_NODE, &pcep_cli_pce_ip_cmd);
	install_element(CONFIG_NODE, &pcep_cli_no_pce_cmd);

}

/* ------------ Module Functions ------------ */

int pcep_module_finish(void)
{
	pcep_stop();
	return 0;
}

int pcep_module_late_init(struct thread_master *tm)
{
	pcep_g->master = tm;
	hook_register(frr_fini, pcep_module_finish);
	pcep_cli_init();
	return 0;
}

int pcep_module_init(void)
{
	hook_register(frr_late_init, pcep_module_late_init);
	return 0;
}

FRR_MODULE_SETUP(.name = "frr_pathd_pcep", .version = FRR_VERSION,
		 .description = "FRR pathd PCEP module",
		 .init = pcep_module_init)
