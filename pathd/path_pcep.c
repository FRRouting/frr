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

#include "log.h"
#include "command.h"
#include "libfrr.h"
#include "printfrr.h"
#include "version.h"
#include "northbound.h"
#include "frr_pthread.h"
#include "jhash.h"

#include "pathd/pathd.h"
#include "pathd/path_errors.h"
#include "pathd/path_pcep_memory.h"
#include "pathd/path_pcep.h"
#include "pathd/path_pcep_controller.h"
#include "pathd/path_pcep_lib.h"
#include "pathd/path_pcep_nb.h"


/*
 * Globals.
 */
static struct pcep_glob pcep_glob_space = {.dbg = {0, "pathd module: pcep"}};
struct pcep_glob *pcep_g = &pcep_glob_space;

static struct cmd_node pcc_node = {
        .name = "pcc",
        .node = PCC_NODE,
        .parent_node = CONFIG_NODE,
        .prompt = "%s(config-pcc)# ",
};

/* Main Thread Even Handler */
static int pcep_main_event_handler(enum pcep_main_event_type type, int pcc_id,
				   void *payload);
static int pcep_main_event_start_sync(int pcc_id);
static int pcep_main_event_start_sync_cb(struct path *path, void *arg);

/* Hook Handlers called from the Main Thread */
static int pathd_candidate_created_handler(struct srte_candidate *candidate);
static int pathd_candidate_updated_handler(struct srte_candidate *candidate);
static int pathd_candidate_removed_handler(struct srte_candidate *candidate);

/* CLI Functions */
static int pcep_cli_debug_config_write(struct vty *vty);
static int pcep_cli_debug_set_all(uint32_t flags, bool set);
static void pcep_cli_init(void);


/* Module Functions */
static int pcep_module_finish(void);
static int pcep_module_late_init(struct thread_master *tm);
static int pcep_module_init(void);

/* ------------ Path Helper Functions ------------ */

struct path *pcep_new_path(void)
{
	struct path *path;
	path = XCALLOC(MTYPE_PCEP, sizeof(*path));
	memset(path, 0, sizeof(*path));
	return path;
}

struct path_hop *pcep_new_hop(void)
{
	struct path_hop *hop;
	hop = XCALLOC(MTYPE_PCEP, sizeof(*hop));
	memset(hop, 0, sizeof(*hop));
	return hop;
}

void pcep_free_path(struct path *path)
{
	struct path_hop *hop;

	hop = path->first;
	while (NULL != hop) {
		struct path_hop *next = hop->next;
		XFREE(MTYPE_PCEP, hop);
		hop = next;
	}
	if (NULL != path->name) {
		XFREE(MTYPE_PCEP, path->name);
	}
	XFREE(MTYPE_PCEP, path);
}


/* ------------ Main Thread Even Handler ------------ */

int pcep_main_event_handler(enum pcep_main_event_type type, int pcc_id,
			    void *payload)
{
	int ret = 0;

	/* Possible payload values */
	struct path *path = NULL;

	switch (type) {
	case PCEP_MAIN_EVENT_START_SYNC:
		ret = pcep_main_event_start_sync(pcc_id);
		break;
	case PCEP_MAIN_EVENT_UPDATE_CANDIDATE:
		assert(NULL != payload);
		path = (struct path *)payload;
		path_nb_update_path(path);
		break;
	default:
		flog_warn(EC_PATH_PCEP_RECOVERABLE_INTERNAL_ERROR,
			  "Unexpected event received in the main thread: %u",
			  type);
		break;
	}

	return ret;
}

int pcep_main_event_start_sync(int pcc_id)
{
	path_nb_list_path(pcep_main_event_start_sync_cb, &pcc_id);
	pcep_ctrl_sync_done(pcep_g->fpt, pcc_id);
	return 0;
}

int pcep_main_event_start_sync_cb(struct path *path, void *arg)
{
	int *pcc_id = (int *)arg;
	path->is_synching = true;
	pcep_ctrl_sync_path(pcep_g->fpt, *pcc_id, path);
	return 1;
}


/* ------------ Hook Handlers Functions Called From Main Thread ------------ */

int pathd_candidate_created_handler(struct srte_candidate *candidate)
{
	struct path *path = candidate_to_path(candidate);
	int ret = pcep_ctrl_pathd_event(pcep_g->fpt, PCEP_PATH_CREATED, path);
	return ret;
}

int pathd_candidate_updated_handler(struct srte_candidate *candidate)
{
	struct path *path = candidate_to_path(candidate);
	int ret = pcep_ctrl_pathd_event(pcep_g->fpt, PCEP_PATH_UPDATED, path);
	return ret;
}

int pathd_candidate_removed_handler(struct srte_candidate *candidate)
{
	struct path *path = candidate_to_path(candidate);
	int ret = pcep_ctrl_pathd_event(pcep_g->fpt, PCEP_PATH_REMOVED, path);
	return ret;
}


/* ------------ CLI Functions ------------ */

DEFUN_NOSH(pcep_cli_pcc, pcep_cli_pcc_cmd,
	   "pcc [ip A.B.C.D] [port (1024-65535)] [force_stateless]",
	   "PCC source ip and port\n"
	   "PCC source ip A.B.C.D\n"
	   "PCC source port port")
{
	struct in_addr pcc_addr;
	uint32_t pcc_port = PCEP_DEFAULT_PORT;
	struct pcc_opts *opts;
	bool force_stateless = false;
	int i = 1;

	pcc_addr.s_addr = INADDR_ANY;

	while (i < argc) {
		if (0 == strcmp("ip", argv[i]->arg)) {
			i++;
			if (i >= argc)
				return CMD_ERR_NO_MATCH;
			if (!inet_pton(AF_INET, argv[i]->arg, &pcc_addr.s_addr))
				return CMD_ERR_INCOMPLETE;
			i++;
			continue;
		}
		if (0 == strcmp("port", argv[i]->arg)) {
			i++;
			if (i >= argc)
				return CMD_ERR_NO_MATCH;
			pcc_port = atoi(argv[4]->arg);
			if (0 == pcc_port)
				return CMD_ERR_INCOMPLETE;
			i++;
			continue;
		}
		if (0 == strcmp("force_stateless", argv[i]->arg)) {
			force_stateless = true;
			i++;
			continue;
		}
		return CMD_ERR_NO_MATCH;
	}

	opts = XCALLOC(MTYPE_PCEP, sizeof(*opts));
	opts->addr = pcc_addr;
	opts->port = pcc_port;
	opts->force_stateless = force_stateless;

	if (pcep_ctrl_update_pcc_options(pcep_g->fpt, opts))
		return CMD_WARNING;

	VTY_PUSH_CONTEXT_NULL(PCC_NODE);

	return CMD_SUCCESS;
}

DEFUN(pcep_cli_pce_opts, pcep_cli_pce_opts_cmd,
      "pce ip A.B.C.D [port (1024-65535)]",
      "PCE remote ip and port\n"
      "Remote PCE server ip A.B.C.D\n"
      "Remote PCE server port")
{
	struct in_addr pce_addr;
	uint32_t pce_port = PCEP_DEFAULT_PORT;
	struct pce_opts *pce_opts;

	int ip_idx = 2;
	int port_idx = 4;

	if (!inet_pton(AF_INET, argv[ip_idx]->arg, &pce_addr.s_addr))
		return CMD_ERR_INCOMPLETE;

	if (argc > port_idx)
		pce_port = atoi(argv[port_idx]->arg);

	pce_opts = XCALLOC(MTYPE_PCEP, sizeof(*pce_opts));
	pce_opts->addr = pce_addr;
	pce_opts->port = pce_port;

	if (pcep_ctrl_update_pce_options(pcep_g->fpt, 1, pce_opts))
		return CMD_WARNING;

	return CMD_SUCCESS;
}

DEFUN(pcep_cli_no_pce, pcep_cli_no_pce_cmd, "no pce", NO_STR "Disable pce\n")
{
	pcep_ctrl_disconnect_pcc(pcep_g->fpt, 1);
	return CMD_SUCCESS;
}

DEFUN(pcep_cli_debug, pcep_cli_debug_cmd,
      "[no] debug pathd pcep [path] [message] [pceplib]",
      NO_STR DEBUG_STR
      "pathd debugging\n"
      "pcep basic debugging\n"
      "path structures debugging\n"
      "pcep message debugging\n"
      "pceplib debugging\n")
{
	uint32_t mode = DEBUG_NODE2MODE(vty->node);
	bool no = strmatch(argv[0]->text, "no");
	int i;

	DEBUG_MODE_SET(&pcep_g->dbg, mode, !no);
	DEBUG_FLAGS_SET(&pcep_g->dbg, PCEP_DEBUG_MODE_BASIC, !no);
	DEBUG_FLAGS_SET(&pcep_g->dbg, PCEP_DEBUG_MODE_PATH, false);
	DEBUG_FLAGS_SET(&pcep_g->dbg, PCEP_DEBUG_MODE_PCEP, false);
	DEBUG_FLAGS_SET(&pcep_g->dbg, PCEP_DEBUG_MODE_PCEPLIB, false);

	if (no)
		return CMD_SUCCESS;

	if (3 < argc) {
		for (i = (3 + no); i < argc; i++) {
			if (0 == strcmp("path", argv[i]->arg)) {
				DEBUG_FLAGS_SET(&pcep_g->dbg,
						PCEP_DEBUG_MODE_PATH, true);
			} else if (0 == strcmp("message", argv[i]->arg)) {
				DEBUG_FLAGS_SET(&pcep_g->dbg,
						PCEP_DEBUG_MODE_PCEP, true);
			} else if (0 == strcmp("pceplib", argv[i]->arg)) {
				DEBUG_FLAGS_SET(&pcep_g->dbg,
						PCEP_DEBUG_MODE_PCEPLIB, true);
			}
		}
	}

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
	hook_register(nb_client_debug_set_all, pcep_cli_debug_set_all);

	install_node(&pcc_node);
	install_default(PCC_NODE);
	install_element(CONFIG_NODE, &pcep_cli_debug_cmd);
	install_element(ENABLE_NODE, &pcep_cli_debug_cmd);
	install_element(CONFIG_NODE, &pcep_cli_pcc_cmd);
	install_element(PCC_NODE, &pcep_cli_pce_opts_cmd);
	install_element(PCC_NODE, &pcep_cli_no_pce_cmd);
}

/* ------------ Module Functions ------------ */

int pcep_module_late_init(struct thread_master *tm)
{
	assert(NULL == pcep_g->fpt);
	assert(NULL == pcep_g->master);

	struct frr_pthread *fpt;

	if (pcep_lib_initialize())
		return 1;

	if (pcep_ctrl_initialize(tm, &fpt, pcep_main_event_handler))
		return 1;

	pcep_g->master = tm;
	pcep_g->fpt = fpt;

	hook_register(pathd_candidate_created, pathd_candidate_created_handler);
	hook_register(pathd_candidate_updated, pathd_candidate_updated_handler);
	hook_register(pathd_candidate_removed, pathd_candidate_removed_handler);

	hook_register(frr_fini, pcep_module_finish);

	pcep_cli_init();

	return 0;
}

int pcep_module_finish(void)
{
	pcep_ctrl_finalize(&pcep_g->fpt);
	pcep_lib_finalize();

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
