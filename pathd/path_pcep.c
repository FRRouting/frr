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
#include <pcep_utils_counters.h>

#include "log.h"
#include "command.h"
#include "libfrr.h"
#include "printfrr.h"
#include "version.h"
#include "northbound.h"
#include "frr_pthread.h"
#include "jhash.h"
#include "termtable.h"

#include "pathd/pathd.h"
#include "pathd/path_util.h"
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
static int pcep_cli_pcc_config_write(struct vty *vty);
static void pcep_cli_init(void);

/* Module Functions */
static int pcep_module_finish(void);
static int pcep_module_late_init(struct thread_master *tm);
static int pcep_module_init(void);

static struct cmd_node pcc_node = {
        .name = "pcc",
        .node = PCC_NODE,
        .parent_node = CONFIG_NODE,
        .prompt = "%s(config-pcc)# ",
        .config_write = pcep_cli_pcc_config_write,
};

/* ------------ Path Helper Functions ------------ */

struct path *pcep_new_path(void)
{
	struct path *path;
	path = XCALLOC(MTYPE_PCEP, sizeof(*path));
	path->binding_sid = MPLS_LABEL_NONE;
	return path;
}

struct path_hop *pcep_new_hop(void)
{
	struct path_hop *hop;
	hop = XCALLOC(MTYPE_PCEP, sizeof(*hop));
	return hop;
}

struct path_metric *pcep_new_metric(void)
{
	struct path_metric *metric;
	metric = XCALLOC(MTYPE_PCEP, sizeof(*metric));
	return metric;
}

void pcep_free_path(struct path *path)
{
	struct path_hop *hop;
	struct path_metric *metric;
	char *tmp;

	metric = path->first_metric;
	while (metric != NULL) {
		struct path_metric *next = metric->next;
		XFREE(MTYPE_PCEP, metric);
		metric = next;
	}
	hop = path->first_hop;
	while (hop != NULL) {
		struct path_hop *next = hop->next;
		XFREE(MTYPE_PCEP, hop);
		hop = next;
	}
	if (path->originator != NULL) {
		/* The path own the memory, it is const so it is clear it
		shouldn't be modified. XFREE macro do not support type casting
		so we need a temporary variable */
		tmp = (char *)path->originator;
		XFREE(MTYPE_PCEP, tmp);
		path->originator = NULL;
	}
	if (path->name != NULL) {
		/* The path own the memory, it is const so it is clear it
		shouldn't be modified. XFREE macro do not support type casting
		so we need a temporary variable */
		tmp = (char *)path->name;
		XFREE(MTYPE_PCEP, tmp);
		path->name = NULL;
	}
	XFREE(MTYPE_PCEP, path);
}


/* ------------ Main Thread Even Handler ------------ */

int pcep_main_event_handler(enum pcep_main_event_type type, int pcc_id,
			    void *payload)
{
	int ret = 0;

	/* Possible payload values */
	struct path *path = NULL, *resp = NULL;

	switch (type) {
	case PCEP_MAIN_EVENT_START_SYNC:
		ret = pcep_main_event_start_sync(pcc_id);
		break;
	case PCEP_MAIN_EVENT_UPDATE_CANDIDATE:
		assert(payload != NULL);
		path = (struct path *)payload;
		ret = path_nb_update_path(path);
		if (path->srp_id != 0) {
			/* ODL and Cisco requires the first reported
			 * LSP to have a DOWN status, the later status changes
			 * will be comunicated through hook calls.
			 */
			enum pcep_lsp_operational_status real_status;
			resp = path_nb_get_path(&path->nbkey);
			resp->srp_id = path->srp_id;
			real_status = resp->status;
			resp->status = PCEP_LSP_OPERATIONAL_DOWN;
			pcep_ctrl_send_report(pcep_g->fpt, path->pcc_id, resp);
			/* If the update did not have any effect and the real
			 * status is not DOWN, we need to send a second report
			 * so the PCE is aware of the real status. This is due
			 * to the fact that NO notification will be received
			 * if the update did not apply any changes */
			if ((ret == PATH_NB_NO_CHANGE)
			    && (real_status != PCEP_LSP_OPERATIONAL_DOWN)) {
				resp->status = real_status;
				resp->srp_id = 0;
				pcep_ctrl_send_report(pcep_g->fpt, path->pcc_id, resp);
			}
			pcep_free_path(resp);
		}
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
	path->go_active = true;
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

DEFUN(show_pcep_counters, show_pcep_counters_cmd, "show pcep counters",
      SHOW_STR
      "PCEP info\n"
      "PCEP counters\n")
{
	int i, j, row;
	time_t diff_time;
	struct tm *tm_info;
	char tm_buffer[26];
	struct counters_group *group;
	struct counters_subgroup *subgroup;
	struct counter *counter;
	const char *group_name, *empty_string = "";
	struct ttable *tt;
	char *table;

	group = pcep_ctrl_get_counters(pcep_g->fpt, 1);

	if (group == NULL) {
		vty_out(vty, "No counters to display.\n\n");
		return CMD_SUCCESS;
	}

	diff_time = time(NULL) - group->start_time;
	tm_info = localtime(&group->start_time);
	strftime(tm_buffer, sizeof(tm_buffer), "%Y-%m-%d %H:%M:%S", tm_info);

	vty_out(vty, "PCEP counters since %s (%luh %lum %lus):\n", tm_buffer,
		diff_time / 3600, (diff_time / 60) % 60, diff_time % 60);

	/* Prepare table. */
	tt = ttable_new(&ttable_styles[TTSTYLE_BLANK]);
	ttable_add_row(tt, "Group|Name|Value");
	tt->style.cell.rpad = 2;
	tt->style.corner = '+';
	ttable_restyle(tt);
	ttable_rowseps(tt, 0, BOTTOM, true, '-');

	for (row = 0, i = 0; i <= group->num_subgroups; i++) {
		subgroup = group->subgroups[i];
		if (subgroup != NULL) {
			group_name = subgroup->counters_subgroup_name;
			for (j = 0; j <= subgroup->num_counters; j++) {
				counter = subgroup->counters[j];
				if (counter != NULL) {
					ttable_add_row(tt, "%s|%s|%u",
						       group_name,
						       counter->counter_name,
						       counter->counter_value);
					row++;
					group_name = empty_string;
				}
			}
			ttable_rowseps(tt, row, BOTTOM, true, '-');
		}
	}

	/* Dump the generated table. */
	table = ttable_dump(tt, "\n");
	vty_out(vty, "%s\n", table);
	XFREE(MTYPE_TMP, table);

	ttable_del(tt);

	pcep_lib_free_counters(group);

	return CMD_SUCCESS;
}

DEFUN_NOSH(pcep_cli_pcc, pcep_cli_pcc_cmd,
	   "pcc [<ip A.B.C.D | ipv6 X:X::X:X>] [port (1024-65535)] [msd (1-16)]",
	   "PCC configuration\n"
	   "PCC source ip\n"
	   "PCC source IPv4 address\n"
	   "PCC source ip\n"
	   "PCC source IPv6 address\n"
	   "PCC source port\n"
	   "PCC source port value\n"
	   "PCC maximum SID depth \n"
	   "PCC maximum SID depth value\n")
{

	struct ipaddr pcc_addr;
	uint32_t pcc_port = PCEP_DEFAULT_PORT;
	uint32_t pcc_msd = PCC_DEFAULT_MSD;
	struct pcc_opts *opts, *opts_copy;
	int i = 1;

	pcc_addr.ipa_type = IPADDR_NONE;

	/* Handle the rest of the arguments */
	while (i < argc) {
		if (strcmp("ip", argv[i]->arg) == 0) {
			pcc_addr.ipa_type = IPADDR_V4;
			i++;
			if (i >= argc)
				return CMD_ERR_NO_MATCH;
			if (!inet_pton(AF_INET, argv[i]->arg,
			               &pcc_addr.ipaddr_v4))
				return CMD_ERR_INCOMPLETE;
			i++;
			continue;

		}

		if (strcmp("ipv6", argv[i]->arg) == 0) {
			pcc_addr.ipa_type = IPADDR_V6;
			i++;
			if (i >= argc)
				return CMD_ERR_NO_MATCH;
			if (!inet_pton(AF_INET6, argv[i]->arg,
			               &pcc_addr.ipaddr_v6))
				return CMD_ERR_INCOMPLETE;
			i++;
			continue;
		}

		if (strcmp("port", argv[i]->arg) == 0) {
			i++;
			if (i >= argc)
				return CMD_ERR_NO_MATCH;
			pcc_port = atoi(argv[i]->arg);
			if (pcc_port == 0)
				return CMD_ERR_INCOMPLETE;
			i++;
			continue;
		}
		if (strcmp("msd", argv[i]->arg) == 0) {
			i++;
			if (i >= argc)
				return CMD_ERR_NO_MATCH;
			pcc_msd = atoi(argv[i]->arg);
			if (pcc_msd <= 0 || pcc_msd >= 16)
				return CMD_ERR_INCOMPLETE;
			i++;
			continue;
		}
		return CMD_ERR_NO_MATCH;
	}

	opts = XCALLOC(MTYPE_PCEP, sizeof(*opts));
	IPADDR_COPY(&opts->addr, &pcc_addr);
	opts->port = pcc_port;
  opts->msd = pcc_msd;

	if (pcep_ctrl_update_pcc_options(pcep_g->fpt, opts))
		return CMD_WARNING;

	if (pcep_g->pcc_opts != NULL)
		XFREE(MTYPE_PCEP, pcep_g->pcc_opts);
	opts_copy = XCALLOC(MTYPE_PCEP, sizeof(*opts));
	opts_copy = memcpy(opts_copy, opts, sizeof(*opts));
	pcep_g->pcc_opts = opts_copy;

	VTY_PUSH_CONTEXT_NULL(PCC_NODE);

	return CMD_SUCCESS;
}

DEFUN(pcep_cli_no_pcc, pcep_cli_no_pcc_cmd, "no pcc",
      NO_STR "PCC configuration\n")
{
	pcep_ctrl_remove_pcc(pcep_g->fpt, 1);
	if (pcep_g->pce_opts[0] != NULL) {
		XFREE(MTYPE_PCEP, pcep_g->pce_opts[0]);
		pcep_g->pce_opts[0] = NULL;
	}
	if (pcep_g->pcc_opts != NULL) {
		XFREE(MTYPE_PCEP, pcep_g->pcc_opts);
		pcep_g->pcc_opts = NULL;
	}
	return CMD_SUCCESS;
}

DEFUN(pcep_cli_pce, pcep_cli_pce_cmd,
      "pce <ip A.B.C.D | ipv6 X:X::X:X> [port (1024-65535)] [sr-draft07]",
      "PCE configuration\n"
      "PCE IPv4 address\n"
      "Remote PCE server IPv4 address\n"
      "PCE IPv6 address\n"
      "Remote PCE server IPv6 address\n"
      "Remote PCE server port\n"
      "Remote PCE server port value\n"
      "Use the draft 07 of PCEP segemnt routing\n")
{
	/* TODO: Add support for multiple PCE */

	struct ipaddr pce_addr;
	uint32_t pce_port = PCEP_DEFAULT_PORT;
	struct pce_opts *pce_opts, *pce_opts_copy;
	bool draft07 = false;
	int i = 1;

	/* Get the first argument, should be either ip or ipv6 */
	pce_addr.ipa_type = IPADDR_V4;
	if (strcmp("ipv6", argv[i]->arg) == 0) {
		pce_addr.ipa_type = IPADDR_V6;
	} else if (strcmp("ip", argv[i]->arg) != 0) {
		return CMD_ERR_NO_MATCH;
	}

	/* Get the first argument value */
	i++;
	if (i >= argc) {
		return CMD_ERR_NO_MATCH;
	}
	if (IS_IPADDR_V6(&pce_addr)) {
		if (!inet_pton(AF_INET6, argv[i]->arg, &pce_addr.ipaddr_v6)) {
			return CMD_ERR_INCOMPLETE;
		}
	} else {
		if (!inet_pton(AF_INET, argv[i]->arg, &pce_addr.ipaddr_v4)) {
			return CMD_ERR_INCOMPLETE;
		}
	}

	/* Handle the rest of the arguments */
	i++;
	while (i < argc) {
		if (strcmp("port", argv[i]->arg) == 0) {
			i++;
			if (i >= argc)
				return CMD_ERR_NO_MATCH;
			pce_port = atoi(argv[i]->arg);
			if (pce_port == 0)
				return CMD_ERR_INCOMPLETE;
			i++;
			continue;
		}
		if (strcmp("sr-draft07", argv[i]->arg) == 0) {
			draft07 = true;
			i++;
			continue;
		}
		return CMD_ERR_NO_MATCH;
	}

	pce_opts = XCALLOC(MTYPE_PCEP, sizeof(*pce_opts));
	IPADDR_COPY(&pce_opts->addr, &pce_addr);
	pce_opts->port = pce_port;
	pce_opts->draft07 = draft07;

	if (pcep_ctrl_update_pce_options(pcep_g->fpt, 1, pce_opts))
		return CMD_WARNING;

	if (pcep_g->pce_opts[0] != NULL)
		XFREE(MTYPE_PCEP, pcep_g->pce_opts[0]);
	pce_opts_copy = XCALLOC(MTYPE_PCEP, sizeof(*pce_opts));
	pce_opts_copy = memcpy(pce_opts_copy, pce_opts, sizeof(*pce_opts));
	pcep_g->pce_opts[0] = pce_opts_copy;

	return CMD_SUCCESS;
}

DEFUN(pcep_cli_no_pce, pcep_cli_no_pce_cmd,
      "no pce <ip A.B.C.D | ipv6 X:X::X:X> [port (1024-65535)]",
      NO_STR
      "PCE configuration\n"
      "PCE IPv4 address\n"
      "Remote PCE server IPv4 address\n"
      "PCE IPv6 address\n"
      "Remote PCE server IPv6 address\n"
      "Remote PCE server port\n"
      "Remote PCE server port value\n")
{
	/* TODO: Add support for multiple PCE */

	pcep_ctrl_remove_pcc(pcep_g->fpt, 1);
	if (pcep_g->pce_opts[0] != NULL) {
		XFREE(MTYPE_PCEP, pcep_g->pce_opts[0]);
		pcep_g->pce_opts[0] = NULL;
	}
	return CMD_SUCCESS;
}

DEFUN(pcep_cli_debug, pcep_cli_debug_cmd,
      "[no] debug pathd pcep [basic] [path] [message] [pceplib]",
      NO_STR DEBUG_STR
      "pathd debugging\n"
      "pcep module debugging\n"
      "module basic debugging\n"
      "path structures debugging\n"
      "pcep message debugging\n"
      "pceplib debugging\n")
{
	uint32_t mode = DEBUG_NODE2MODE(vty->node);
	bool no = strmatch(argv[0]->text, "no");
	int i;

	DEBUG_MODE_SET(&pcep_g->dbg, mode, !no);

	if (3 < argc) {
		for (i = (3 + no); i < argc; i++) {
			if (strcmp("basic", argv[i]->arg) == 0) {
				DEBUG_FLAGS_SET(&pcep_g->dbg,
						PCEP_DEBUG_MODE_BASIC, !no);
			} else if (strcmp("path", argv[i]->arg) == 0) {
				DEBUG_FLAGS_SET(&pcep_g->dbg,
						PCEP_DEBUG_MODE_PATH, !no);
			} else if (strcmp("message", argv[i]->arg) == 0) {
				DEBUG_FLAGS_SET(&pcep_g->dbg,
						PCEP_DEBUG_MODE_PCEP, !no);
			} else if (strcmp("pceplib", argv[i]->arg) == 0) {
				DEBUG_FLAGS_SET(&pcep_g->dbg,
						PCEP_DEBUG_MODE_PCEPLIB, !no);
			}
		}
	}

	return CMD_SUCCESS;
}

int pcep_cli_debug_config_write(struct vty *vty)
{
	char buff[128] = "";

	if (DEBUG_MODE_CHECK(&pcep_g->dbg, DEBUG_MODE_CONF)) {
		if (DEBUG_FLAGS_CHECK(&pcep_g->dbg, PCEP_DEBUG_MODE_BASIC))
			csnprintfrr(buff, sizeof(buff), " basic");
		if (DEBUG_FLAGS_CHECK(&pcep_g->dbg, PCEP_DEBUG_MODE_PATH))
			csnprintfrr(buff, sizeof(buff), " path");
		if (DEBUG_FLAGS_CHECK(&pcep_g->dbg, PCEP_DEBUG_MODE_PCEP))
			csnprintfrr(buff, sizeof(buff), " message");
		if (DEBUG_FLAGS_CHECK(&pcep_g->dbg, PCEP_DEBUG_MODE_PCEPLIB))
			csnprintfrr(buff, sizeof(buff), " pceplib");
		vty_out(vty, "debug pathd pcep%s\n", buff);
		buff[0] = 0;
		return 1;
	}

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

int pcep_cli_pcc_config_write(struct vty *vty)
{
	char buff[128] = "";
	int lines = 0;

	if (pcep_g->pcc_opts != NULL) {
		if (IS_IPADDR_V6(&pcep_g->pcc_opts->addr)) {
			if (memcmp(&in6addr_any,
				   &pcep_g->pcc_opts->addr.ipaddr_v6,
				   sizeof(struct in6_addr))
			    != 0) {
				csnprintfrr(buff, sizeof(buff), " ip %pI6",
					    &pcep_g->pcc_opts->addr.ipaddr_v6);
			}
		} else {
			if (pcep_g->pcc_opts->addr.ipaddr_v4.s_addr
			    != INADDR_ANY) {
				csnprintfrr(buff, sizeof(buff), " ip %pI4",
					    &pcep_g->pcc_opts->addr.ipaddr_v4);
			}
		}
		if (pcep_g->pcc_opts->port != PCEP_DEFAULT_PORT)
			csnprintfrr(buff, sizeof(buff), " port %d",
				    pcep_g->pcc_opts->port);
		if (pcep_g->pcc_opts->msd != PCC_DEFAULT_MSD)
			csnprintfrr(buff, sizeof(buff), " msd %d",
				    pcep_g->pcc_opts->msd);
		vty_out(vty, "pcc%s\n", buff);
		buff[0] = 0;
		lines++;

		for (int i = 0; i < MAX_PCC; i++) {
			struct pce_opts *pce_opts = pcep_g->pce_opts[i];
			if (pce_opts != NULL) {
				if (pce_opts->port != PCEP_DEFAULT_PORT) {
					csnprintfrr(buff, sizeof(buff),
						    " port %d", pce_opts->port);
				}
				if (pce_opts->draft07 == true) {
					csnprintfrr(buff, sizeof(buff),
						    " sr-draft07");
				}
				if (IS_IPADDR_V6(&pce_opts->addr)) {
					vty_out(vty, " pce ipv6 %pI6%s\n",
						&pce_opts->addr.ipaddr_v6,
						buff);
				} else {
					vty_out(vty, " pce ip %pI4%s\n",
						&pce_opts->addr.ipaddr_v4,
						buff);
				}
				buff[0] = 0;
				lines++;
			}
		}
	}

	return lines;
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
	install_element(ENABLE_NODE, &show_pcep_counters_cmd);
	install_element(CONFIG_NODE, &pcep_cli_pcc_cmd);
	install_element(CONFIG_NODE, &pcep_cli_no_pcc_cmd);
	install_element(PCC_NODE, &pcep_cli_pce_cmd);
	install_element(PCC_NODE, &pcep_cli_no_pce_cmd);
}

/* ------------ Module Functions ------------ */

int pcep_module_late_init(struct thread_master *tm)
{
	assert(pcep_g->fpt == NULL);
	assert(pcep_g->master == NULL);

	struct frr_pthread *fpt;

	if (pcep_ctrl_initialize(tm, &fpt, pcep_main_event_handler))
		return 1;

	if (pcep_lib_initialize(fpt))
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

	if (pcep_g->pcc_opts != NULL)
		XFREE(MTYPE_PCEP, pcep_g->pcc_opts);
	for (int i = 0; i < MAX_PCC; i++)
		if (pcep_g->pce_opts[i] != NULL)
			XFREE(MTYPE_PCEP, pcep_g->pce_opts[i]);

	return 0;
}

int pcep_module_init(void)
{
	pcep_g->pcc_opts = NULL;
	for (int i = 0; i < MAX_PCC; i++)
		pcep_g->pce_opts[i] = NULL;

	hook_register(frr_late_init, pcep_module_late_init);
	return 0;
}

FRR_MODULE_SETUP(.name = "frr_pathd_pcep", .version = FRR_VERSION,
		 .description = "FRR pathd PCEP module",
		 .init = pcep_module_init)
