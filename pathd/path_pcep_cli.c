// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright (C) 2020 Volta Networks, Inc
 *                     Brady Johnson
 */

#include <zebra.h>
#include "pceplib/pcep_utils_counters.h"
#include "pceplib/pcep_session_logic.h"

#include "log.h"
#include "command.h"
#include "libfrr.h"
#include "printfrr.h"
#include "lib/version.h"
#include "northbound.h"
#include "frr_pthread.h"
#include "jhash.h"
#include "termtable.h"

#include "pathd/pathd.h"
#include "pathd/path_errors.h"
#include "pathd/path_pcep.h"
#include "pathd/path_pcep_cli.h"
#include "pathd/path_pcep_controller.h"
#include "pathd/path_pcep_debug.h"
#include "pathd/path_pcep_lib.h"
#include "pathd/path_pcep_pcc.h"

#include "pathd/path_pcep_cli_clippy.c"

#define DEFAULT_PCE_PRECEDENCE 255
#define DEFAULT_PCC_MSD 4
#define DEFAULT_SR_DRAFT07 false
#define DEFAULT_PCE_INITIATED false
#define DEFAULT_TIMER_KEEP_ALIVE 30
#define DEFAULT_TIMER_KEEP_ALIVE_MIN 1
#define DEFAULT_TIMER_KEEP_ALIVE_MAX 255
#define DEFAULT_TIMER_DEADTIMER 120
#define DEFAULT_TIMER_DEADTIMER_MIN 4
#define DEFAULT_TIMER_DEADTIMER_MAX 255
#define DEFAULT_TIMER_PCEP_REQUEST 30
#define DEFAULT_TIMER_SESSION_TIMEOUT_INTERVAL 30
#define DEFAULT_DELEGATION_TIMEOUT_INTERVAL 10

#define BUFFER_PCC_PCE_SIZE 1024

/* CLI Function declarations */
static int pcep_cli_debug_config_write(struct vty *vty);
static int pcep_cli_debug_set_all(uint32_t flags, bool set);
static int pcep_cli_pcep_config_write(struct vty *vty);
static int pcep_cli_pcc_config_write(struct vty *vty);
static int pcep_cli_pce_config_write(struct vty *vty);
static int pcep_cli_pcep_pce_config_write(struct vty *vty);

/* Internal Util Function declarations */
static void reset_pcc_peer(const char *peer_name);
static struct pce_opts_cli *pcep_cli_find_pce(const char *pce_name);
static bool pcep_cli_add_pce(struct pce_opts_cli *pce_opts_cli);
static struct pce_opts_cli *pcep_cli_create_pce_opts(const char *name);
static void pcep_cli_delete_pce(const char *pce_name);
static void
pcep_cli_merge_pcep_pce_config_options(struct pce_opts_cli *pce_opts_cli);
static struct pcep_config_group_opts *
pcep_cli_find_pcep_pce_config(const char *group_name);
static bool
pcep_cli_add_pcep_pce_config(struct pcep_config_group_opts *config_group_opts);
static struct pcep_config_group_opts *
pcep_cli_create_pcep_pce_config(const char *group_name);
static bool pcep_cli_is_pcep_pce_config_used(const char *group_name);
static void pcep_cli_delete_pcep_pce_config(const char *group_name);
static int pcep_cli_print_pce_config(struct pcep_config_group_opts *group_opts,
				     char *buf, size_t buf_len);
static void print_pcep_capabilities(char *buf, size_t buf_len,
				    pcep_configuration *config);
static void print_pcep_session(struct vty *vty, struct pce_opts *pce_opts,
			       struct pcep_pcc_info *pcc_info);
static void print_pcep_session_json(struct vty *vty, struct pce_opts *pce_opts,
				    struct pcep_pcc_info *pcc_info,
				    json_object *json);
static bool pcep_cli_pcc_has_pce(const char *pce_name);
static void pcep_cli_add_pce_connection(struct pce_opts *pce_opts);
static void pcep_cli_remove_pce_connection(struct pce_opts *pce_opts);
static int path_pcep_cli_pcc_pcc_peer_delete(struct vty *vty,
					     const char *peer_name,
					     const char *precedence_str,
					     long precedence);

/*
 * Globals.
 */

static const char PCEP_VTYSH_ARG_ADDRESS[] = "address";
static const char PCEP_VTYSH_ARG_SOURCE_ADDRESS[] = "source-address";
static const char PCEP_VTYSH_ARG_IP[] = "ip";
static const char PCEP_VTYSH_ARG_IPV6[] = "ipv6";
static const char PCEP_VTYSH_ARG_PORT[] = "port";
static const char PCEP_VTYSH_ARG_PRECEDENCE[] = "precedence";
static const char PCEP_VTYSH_ARG_MSD[] = "msd";
static const char PCEP_VTYSH_ARG_KEEP_ALIVE[] = "keep-alive";
static const char PCEP_VTYSH_ARG_TIMER[] = "timer";
static const char PCEP_VTYSH_ARG_KEEP_ALIVE_MIN[] = "min-peer-keep-alive";
static const char PCEP_VTYSH_ARG_KEEP_ALIVE_MAX[] = "max-peer-keep-alive";
static const char PCEP_VTYSH_ARG_DEAD_TIMER[] = "dead-timer";
static const char PCEP_VTYSH_ARG_DEAD_TIMER_MIN[] = "min-peer-dead-timer";
static const char PCEP_VTYSH_ARG_DEAD_TIMER_MAX[] = "max-peer-dead-timer";
static const char PCEP_VTYSH_ARG_PCEP_REQUEST[] = "pcep-request";
static const char PCEP_VTYSH_ARG_SESSION_TIMEOUT[] = "session-timeout-interval";
static const char PCEP_VTYSH_ARG_DELEGATION_TIMEOUT[] = "delegation-timeout";
static const char PCEP_VTYSH_ARG_SR_DRAFT07[] = "sr-draft07";
static const char PCEP_VTYSH_ARG_PCE_INIT[] = "pce-initiated";
static const char PCEP_VTYSH_ARG_TCP_MD5[] = "tcp-md5-auth";
static const char PCEP_VTYSH_ARG_BASIC[] = "basic";
static const char PCEP_VTYSH_ARG_PATH[] = "path";
static const char PCEP_VTYSH_ARG_MESSAGE[] = "message";
static const char PCEP_VTYSH_ARG_PCEPLIB[] = "pceplib";
static const char PCEP_CLI_CAP_STATEFUL[] = " [Stateful PCE]";
static const char PCEP_CLI_CAP_INCL_DB_VER[] = " [Include DB version]";
static const char PCEP_CLI_CAP_LSP_TRIGGERED[] = " [LSP Triggered Resync]";
static const char PCEP_CLI_CAP_LSP_DELTA[] = " [LSP Delta Sync]";
static const char PCEP_CLI_CAP_PCE_TRIGGERED[] =
	" [PCE triggered Initial Sync]";
static const char PCEP_CLI_CAP_SR_TE_PST[] = " [SR TE PST]";
static const char PCEP_CLI_CAP_PCC_RESOLVE_NAI[] =
	" [PCC can resolve NAI to SID]";
static const char PCEP_CLI_CAP_PCC_INITIATED[] = " [PCC Initiated LSPs]";
static const char PCEP_CLI_CAP_PCC_PCE_INITIATED[] =
	" [PCC and PCE Initiated LSPs]";

struct pce_connections {
	int num_connections;
	struct pce_opts *connections[MAX_PCC];
};

struct pce_connections pce_connections_g = {.num_connections = 0};

/* Default PCE group that all PCE-Groups and PCEs will inherit from */
struct pcep_config_group_opts default_pcep_config_group_opts_g = {
	.name = "default",
	.tcp_md5_auth = "\0",
	.draft07 = DEFAULT_SR_DRAFT07,
	.pce_initiated = DEFAULT_PCE_INITIATED,
	.keep_alive_seconds = DEFAULT_TIMER_KEEP_ALIVE,
	.min_keep_alive_seconds = DEFAULT_TIMER_KEEP_ALIVE_MIN,
	.max_keep_alive_seconds = DEFAULT_TIMER_KEEP_ALIVE_MAX,
	.dead_timer_seconds = DEFAULT_TIMER_DEADTIMER,
	.min_dead_timer_seconds = DEFAULT_TIMER_DEADTIMER_MIN,
	.max_dead_timer_seconds = DEFAULT_TIMER_DEADTIMER_MAX,
	.pcep_request_time_seconds = DEFAULT_TIMER_PCEP_REQUEST,
	.session_timeout_inteval_seconds =
		DEFAULT_TIMER_SESSION_TIMEOUT_INTERVAL,
	.delegation_timeout_seconds = DEFAULT_DELEGATION_TIMEOUT_INTERVAL,
	.source_port = DEFAULT_PCEP_TCP_PORT,
	.source_ip.ipa_type = IPADDR_NONE,
};

/* Used by PCEP_PCE_CONFIG_NODE sub-commands to operate on the current pce group
 */
struct pcep_config_group_opts *current_pcep_config_group_opts_g = NULL;
/* Used by PCEP_PCE_NODE sub-commands to operate on the current pce opts */
struct pce_opts_cli *current_pce_opts_g = NULL;
short pcc_msd_g = DEFAULT_PCC_MSD;
bool pcc_msd_configured_g = false;

static struct cmd_node pcep_node = {
	.name = "srte pcep",
	.node = PCEP_NODE,
	.parent_node = SR_TRAFFIC_ENG_NODE,
	.prompt = "%s(config-sr-te-pcep)# "
};

static struct cmd_node pcep_pcc_node = {
	.name = "srte pcep pcc",
	.node = PCEP_PCC_NODE,
	.parent_node = PCEP_NODE,
	.prompt = "%s(config-sr-te-pcep-pcc)# "
};

static struct cmd_node pcep_pce_node = {
	.name = "srte pcep pce",
	.node = PCEP_PCE_NODE,
	.parent_node = PCEP_NODE,
	.prompt = "%s(config-sr-te-pcep-pce)# "
};

static struct cmd_node pcep_pce_config_node = {
	.name = "srte pcep pce-config",
	.node = PCEP_PCE_CONFIG_NODE,
	.parent_node = PCEP_NODE,
	.prompt = "%s(pce-sr-te-pcep-pce-config)# "
};

/* Common code used in VTYSH processing for int values */
#define PCEP_VTYSH_INT_ARG_CHECK(arg_str, arg_val, arg_store, min_value,       \
				 max_value)                                    \
	if (arg_str != NULL) {                                                 \
		if (arg_val <= min_value || arg_val >= max_value) {            \
			vty_out(vty,                                           \
				"%% Invalid value %ld in range [%d - %d]",     \
				arg_val, min_value, max_value);                \
			return CMD_WARNING;                                    \
		}                                                              \
		arg_store = arg_val;                                           \
	}

#define MERGE_COMPARE_CONFIG_GROUP_VALUE(config_param, not_set_value)          \
	pce_opts_cli->pce_opts.config_opts.config_param =                      \
		pce_opts_cli->pce_config_group_opts.config_param;              \
	if (pce_opts_cli->pce_config_group_opts.config_param                   \
	    == not_set_value) {                                                \
		pce_opts_cli->pce_opts.config_opts.config_param =              \
			((pce_config != NULL                                   \
			  && pce_config->config_param != not_set_value)        \
				 ? pce_config->config_param                    \
				 : default_pcep_config_group_opts_g            \
					   .config_param);                     \
	}

/*
 * Internal Util functions
 */

/* Check if a pce_opts_cli already exists based on its name and return it,
 * return NULL otherwise */
static struct pce_opts_cli *pcep_cli_find_pce(const char *pce_name)
{
	for (int i = 0; i < MAX_PCE; i++) {
		struct pce_opts_cli *pce_rhs_cli = pcep_g->pce_opts_cli[i];
		if (pce_rhs_cli != NULL) {
			if (strcmp(pce_name, pce_rhs_cli->pce_opts.pce_name)
			    == 0) {
				return pce_rhs_cli;
			}
		}
	}

	return NULL;
}

/* Add a new pce_opts_cli to pcep_g, return false if MAX_PCES, true otherwise */
static bool pcep_cli_add_pce(struct pce_opts_cli *pce_opts_cli)
{
	for (int i = 0; i < MAX_PCE; i++) {
		if (pcep_g->pce_opts_cli[i] == NULL) {
			pcep_g->pce_opts_cli[i] = pce_opts_cli;
			pcep_g->num_pce_opts_cli++;
			return true;
		}
	}

	return false;
}

/* Create a new pce opts_cli */
static struct pce_opts_cli *pcep_cli_create_pce_opts(const char *name)
{
	struct pce_opts_cli *pce_opts_cli =
		XCALLOC(MTYPE_PCEP, sizeof(struct pce_opts_cli));
	strlcpy(pce_opts_cli->pce_opts.pce_name, name,
		sizeof(pce_opts_cli->pce_opts.pce_name));
	pce_opts_cli->pce_opts.port = PCEP_DEFAULT_PORT;

	return pce_opts_cli;
}

static void pcep_cli_delete_pce(const char *pce_name)
{
	for (int i = 0; i < MAX_PCE; i++) {
		if (pcep_g->pce_opts_cli[i] != NULL) {
			if (strcmp(pcep_g->pce_opts_cli[i]->pce_opts.pce_name,
				   pce_name)
			    == 0) {
				XFREE(MTYPE_PCEP, pcep_g->pce_opts_cli[i]);
				pcep_g->pce_opts_cli[i] = NULL;
				pcep_g->num_pce_opts_cli--;
				return;
			}
		}
	}
}

static void
pcep_cli_merge_pcep_pce_config_options(struct pce_opts_cli *pce_opts_cli)
{
	if (pce_opts_cli->merged == true) {
		return;
	}

	struct pcep_config_group_opts *pce_config =
		pcep_cli_find_pcep_pce_config(pce_opts_cli->config_group_name);

	/* Configuration priorities:
	 * 1) pce_opts->config_opts, if present, overwrite pce_config
	 * config_opts 2) pce_config config_opts, if present, overwrite
	 * default config_opts 3) If neither pce_opts->config_opts nor
	 * pce_config config_opts are set, then the default config_opts value
	 * will be used.
	 */

	const char *tcp_md5_auth_str =
		pce_opts_cli->pce_config_group_opts.tcp_md5_auth;
	if (pce_opts_cli->pce_config_group_opts.tcp_md5_auth[0] == '\0') {
		if (pce_config != NULL && pce_config->tcp_md5_auth[0] != '\0') {
			tcp_md5_auth_str = pce_config->tcp_md5_auth;
		} else {
			tcp_md5_auth_str =
				default_pcep_config_group_opts_g.tcp_md5_auth;
		}
	}
	strlcpy(pce_opts_cli->pce_opts.config_opts.tcp_md5_auth,
		tcp_md5_auth_str,
		sizeof(pce_opts_cli->pce_opts.config_opts.tcp_md5_auth));

	struct ipaddr *source_ip =
		&pce_opts_cli->pce_config_group_opts.source_ip;
	if (pce_opts_cli->pce_config_group_opts.source_ip.ipa_type
	    == IPADDR_NONE) {
		if (pce_config != NULL
		    && pce_config->source_ip.ipa_type != IPADDR_NONE) {
			source_ip = &pce_config->source_ip;
		} else {
			source_ip = &default_pcep_config_group_opts_g.source_ip;
		}
	}
	memcpy(&pce_opts_cli->pce_opts.config_opts.source_ip, source_ip,
	       sizeof(struct ipaddr));

	MERGE_COMPARE_CONFIG_GROUP_VALUE(draft07, false);
	MERGE_COMPARE_CONFIG_GROUP_VALUE(pce_initiated, false);
	MERGE_COMPARE_CONFIG_GROUP_VALUE(keep_alive_seconds, 0);
	MERGE_COMPARE_CONFIG_GROUP_VALUE(min_keep_alive_seconds, 0);
	MERGE_COMPARE_CONFIG_GROUP_VALUE(max_keep_alive_seconds, 0);
	MERGE_COMPARE_CONFIG_GROUP_VALUE(dead_timer_seconds, 0);
	MERGE_COMPARE_CONFIG_GROUP_VALUE(min_dead_timer_seconds, 0);
	MERGE_COMPARE_CONFIG_GROUP_VALUE(max_dead_timer_seconds, 0);
	MERGE_COMPARE_CONFIG_GROUP_VALUE(pcep_request_time_seconds, 0);
	MERGE_COMPARE_CONFIG_GROUP_VALUE(session_timeout_inteval_seconds, 0);
	MERGE_COMPARE_CONFIG_GROUP_VALUE(delegation_timeout_seconds, 0);
	MERGE_COMPARE_CONFIG_GROUP_VALUE(source_port, 0);

	pce_opts_cli->merged = true;
}

/* Check if a pcep_config_group_opts already exists based on its name and return
 * it, return NULL otherwise */
static struct pcep_config_group_opts *
pcep_cli_find_pcep_pce_config(const char *group_name)
{
	for (int i = 0; i < MAX_PCE; i++) {
		struct pcep_config_group_opts *pcep_pce_config_rhs =
			pcep_g->config_group_opts[i];
		if (pcep_pce_config_rhs != NULL) {
			if (strcmp(group_name, pcep_pce_config_rhs->name)
			    == 0) {
				return pcep_pce_config_rhs;
			}
		}
	}

	return NULL;
}

/* Add a new pcep_config_group_opts to pcep_g, return false if MAX_PCE,
 * true otherwise */
static bool pcep_cli_add_pcep_pce_config(
	struct pcep_config_group_opts *pcep_config_group_opts)
{
	for (int i = 0; i < MAX_PCE; i++) {
		if (pcep_g->config_group_opts[i] == NULL) {
			pcep_g->config_group_opts[i] = pcep_config_group_opts;
			pcep_g->num_config_group_opts++;
			return true;
		}
	}

	return false;
}

/* Create a new pce group, inheriting its values from the default pce group */
static struct pcep_config_group_opts *
pcep_cli_create_pcep_pce_config(const char *group_name)
{
	struct pcep_config_group_opts *pcep_config_group_opts =
		XCALLOC(MTYPE_PCEP, sizeof(struct pcep_config_group_opts));
	strlcpy(pcep_config_group_opts->name, group_name,
		sizeof(pcep_config_group_opts->name));

	return pcep_config_group_opts;
}

/* Iterate the pce_opts and return true if the pce-group-name is referenced,
 * false otherwise. */
static bool pcep_cli_is_pcep_pce_config_used(const char *group_name)
{
	for (int i = 0; i < MAX_PCE; i++) {
		if (pcep_g->pce_opts_cli[i] != NULL) {
			if (strcmp(pcep_g->pce_opts_cli[i]->config_group_name,
				   group_name)
			    == 0) {
				return true;
			}
		}
	}

	return false;
}

static void pcep_cli_delete_pcep_pce_config(const char *group_name)
{
	for (int i = 0; i < MAX_PCE; i++) {
		if (pcep_g->config_group_opts[i] != NULL) {
			if (strcmp(pcep_g->config_group_opts[i]->name,
				   group_name)
			    == 0) {
				XFREE(MTYPE_PCEP, pcep_g->config_group_opts[i]);
				pcep_g->config_group_opts[i] = NULL;
				pcep_g->num_config_group_opts--;
				return;
			}
		}
	}
}

static bool pcep_cli_pcc_has_pce(const char *pce_name)
{
	for (int i = 0; i < MAX_PCC; i++) {
		struct pce_opts *pce_opts = pce_connections_g.connections[i];
		if (pce_opts == NULL) {
			continue;
		}

		if (strcmp(pce_opts->pce_name, pce_name) == 0) {
			return true;
		}
	}

	return false;
}

static void pcep_cli_add_pce_connection(struct pce_opts *pce_opts)
{
	for (int i = 0; i < MAX_PCC; i++) {
		if (pce_connections_g.connections[i] == NULL) {
			pce_connections_g.num_connections++;
			pce_connections_g.connections[i] = pce_opts;
			return;
		}
	}
}

static void pcep_cli_remove_pce_connection(struct pce_opts *pce_opts)
{
	for (int i = 0; i < MAX_PCC; i++) {
		if (pce_connections_g.connections[i] == pce_opts) {
			pce_connections_g.num_connections--;
			pce_connections_g.connections[i] = NULL;
			return;
		}
	}
}

/*
 * VTY command implementations
 */

static int path_pcep_cli_debug(struct vty *vty, const char *debug_type, bool set)
{
	uint32_t mode = DEBUG_NODE2MODE(vty->node);

	/* Global Set */
	if (debug_type == NULL) {
		DEBUG_MODE_SET(&pcep_g->dbg, mode, set);
		DEBUG_FLAGS_SET(&pcep_g->dbg, PCEP_DEBUG_MODE_ALL, set);
		return CMD_SUCCESS;
	}

	DEBUG_MODE_SET(&pcep_g->dbg, mode, true);

	if (strcmp(debug_type, "basic") == 0)
		DEBUG_FLAGS_SET(&pcep_g->dbg, PCEP_DEBUG_MODE_BASIC, set);
	else if (strcmp(debug_type, "path") == 0)
		DEBUG_FLAGS_SET(&pcep_g->dbg, PCEP_DEBUG_MODE_PATH, set);
	else if (strcmp(debug_type, "message") == 0)
		DEBUG_FLAGS_SET(&pcep_g->dbg, PCEP_DEBUG_MODE_PCEP, set);
	else if (strcmp(debug_type, "pceplib") == 0)
		DEBUG_FLAGS_SET(&pcep_g->dbg, PCEP_DEBUG_MODE_PCEPLIB, set);

	/* Unset the pcep debug mode if there is no flag at least set*/
	if (!DEBUG_FLAGS_CHECK(&pcep_g->dbg, PCEP_DEBUG_MODE_ALL))
		DEBUG_MODE_SET(&pcep_g->dbg, mode, false);

	return CMD_SUCCESS;
}

static int path_pcep_cli_show_srte_pcep_counters(struct vty *vty)
{
	int i, j, row;
	time_t diff_time;
	struct tm tm_info;
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
	localtime_r(&group->start_time, &tm_info);
	strftime(tm_buffer, sizeof(tm_buffer), "%Y-%m-%d %H:%M:%S", &tm_info);

	vty_out(vty, "PCEP counters since %s (%uh %um %us):\n", tm_buffer,
		(uint32_t)(diff_time / 3600), (uint32_t)((diff_time / 60) % 60),
		(uint32_t)(diff_time % 60));

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

static int path_pcep_cli_pcep_pce_config(struct vty *vty,
					 const char *pcep_pce_config)
{
	struct pcep_config_group_opts *pce_config =
		pcep_cli_find_pcep_pce_config(pcep_pce_config);
	if (pce_config == NULL) {
		pce_config = pcep_cli_create_pcep_pce_config(pcep_pce_config);
		if (pcep_cli_add_pcep_pce_config(pce_config) == false) {
			vty_out(vty,
				"%% Cannot create pce-config, as the Maximum limit of %d pce-config has been reached.\n",
				MAX_PCE);
			XFREE(MTYPE_PCEP, pce_config);
			return CMD_WARNING;
		}
	} else {
		vty_out(vty,
			"Notice: changes to this pce-config will not affect PCEs already configured with this group\n");
	}

	current_pcep_config_group_opts_g = pce_config;
	vty->node = PCEP_PCE_CONFIG_NODE;

	return CMD_SUCCESS;
}

static int path_pcep_cli_pcep_pce_config_delete(struct vty *vty,
						const char *pcep_pce_config)
{
	struct pcep_config_group_opts *pce_config =
		pcep_cli_find_pcep_pce_config(pcep_pce_config);
	if (pce_config == NULL) {
		vty_out(vty,
			"%% Cannot delete pce-config, since it does not exist.\n");
		return CMD_WARNING;
	}

	if (pcep_cli_is_pcep_pce_config_used(pce_config->name)) {
		vty_out(vty,
			"%% Cannot delete pce-config, since it is in use by a peer.\n");
		return CMD_WARNING;
	}

	pcep_cli_delete_pcep_pce_config(pce_config->name);

	return CMD_SUCCESS;
}

static int path_pcep_cli_show_srte_pcep_pce_config(struct vty *vty,
						   const char *pcep_pce_config)
{
	char buf[1024] = "";

	/* Only show 1 Peer config group */
	struct pcep_config_group_opts *group_opts;
	if (pcep_pce_config != NULL) {
		if (strcmp(pcep_pce_config, "default") == 0) {
			group_opts = &default_pcep_config_group_opts_g;
		} else {
			group_opts =
				pcep_cli_find_pcep_pce_config(pcep_pce_config);
		}
		if (group_opts == NULL) {
			vty_out(vty, "%% pce-config [%s] does not exist.\n",
				pcep_pce_config);
			return CMD_WARNING;
		}

		vty_out(vty, "pce-config: %s\n", group_opts->name);
		pcep_cli_print_pce_config(group_opts, buf, sizeof(buf));
		vty_out(vty, "%s", buf);
		return CMD_SUCCESS;
	}

	/* Show all Peer config groups */
	for (int i = 0; i < MAX_PCE; i++) {
		group_opts = pcep_g->config_group_opts[i];
		if (group_opts == NULL) {
			continue;
		}

		vty_out(vty, "pce-config: %s\n", group_opts->name);
		pcep_cli_print_pce_config(group_opts, buf, sizeof(buf));
		vty_out(vty, "%s", buf);
		buf[0] = 0;
	}

	return CMD_SUCCESS;
}

static int path_pcep_cli_pce(struct vty *vty, const char *pce_peer_name)
{
	/* If it already exists, it will be updated in the sub-commands */
	struct pce_opts_cli *pce_opts_cli = pcep_cli_find_pce(pce_peer_name);
	if (pce_opts_cli == NULL) {
		pce_opts_cli = pcep_cli_create_pce_opts(pce_peer_name);

		if (!pcep_cli_add_pce(pce_opts_cli)) {
			vty_out(vty,
				"%% Cannot create PCE, as the Maximum limit of %d PCEs has been reached.\n",
				MAX_PCE);
			XFREE(MTYPE_PCEP, pce_opts_cli);
			return CMD_WARNING;
		}
	}

	current_pce_opts_g = pce_opts_cli;
	vty->node = PCEP_PCE_NODE;

	return CMD_SUCCESS;
}

static int path_pcep_cli_pce_delete(struct vty *vty, const char *pce_peer_name)
{
	struct pce_opts_cli *pce_opts_cli = pcep_cli_find_pce(pce_peer_name);
	if (pce_opts_cli == NULL) {
		vty_out(vty, "%% PCC peer does not exist.\n");
		return CMD_WARNING;
	}

	/* To better work with frr-reload, go ahead and delete it if its in use
	 */
	if (pcep_cli_pcc_has_pce(pce_peer_name)) {
		vty_out(vty,
			"%% Notice: the pce is in use by a PCC, also disconnecting.\n");
		path_pcep_cli_pcc_pcc_peer_delete(vty, pce_peer_name, NULL, 0);
	}

	pcep_cli_delete_pce(pce_peer_name);

	return CMD_SUCCESS;
}

/* Internal Util func to show an individual PCE,
 * only used by path_pcep_cli_show_srte_pcep_pce() */
static void show_pce_peer(struct vty *vty, struct pce_opts_cli *pce_opts_cli)
{
	struct pce_opts *pce_opts = &pce_opts_cli->pce_opts;
	vty_out(vty, "PCE: %s\n", pce_opts->pce_name);

	/* Remote PCE IP address */
	if (IS_IPADDR_V6(&pce_opts->addr)) {
		vty_out(vty, "  %s %s %pI6 %s %d\n", PCEP_VTYSH_ARG_ADDRESS,
			PCEP_VTYSH_ARG_IPV6, &pce_opts->addr.ipaddr_v6,
			PCEP_VTYSH_ARG_PORT, pce_opts->port);
	} else {
		vty_out(vty, "  %s %s %pI4 %s %d\n", PCEP_VTYSH_ARG_ADDRESS,
			PCEP_VTYSH_ARG_IP, &pce_opts->addr.ipaddr_v4,
			PCEP_VTYSH_ARG_PORT, pce_opts->port);
	}

	if (pce_opts_cli->config_group_name[0] != '\0') {
		vty_out(vty, "  pce-config: %s\n",
			pce_opts_cli->config_group_name);
	}

	char buf[1024] = "";
	pcep_cli_print_pce_config(&pce_opts->config_opts, buf, sizeof(buf));
	vty_out(vty, "%s", buf);
}

static int path_pcep_cli_show_srte_pcep_pce(struct vty *vty,
					    const char *pce_peer)
{
	/* Only show 1 PCE */
	struct pce_opts_cli *pce_opts_cli;
	if (pce_peer != NULL) {
		pce_opts_cli = pcep_cli_find_pce(pce_peer);
		if (pce_opts_cli == NULL) {
			vty_out(vty, "%% PCE [%s] does not exist.\n", pce_peer);
			return CMD_WARNING;
		}

		pcep_cli_merge_pcep_pce_config_options(pce_opts_cli);
		show_pce_peer(vty, pce_opts_cli);

		return CMD_SUCCESS;
	}

	/* Show all PCEs */
	for (int i = 0; i < MAX_PCE; i++) {
		pce_opts_cli = pcep_g->pce_opts_cli[i];
		if (pce_opts_cli == NULL) {
			continue;
		}

		pcep_cli_merge_pcep_pce_config_options(pce_opts_cli);
		show_pce_peer(vty, pce_opts_cli);
	}

	return CMD_SUCCESS;
}

static int path_pcep_cli_peer_sr_draft07(struct vty *vty, bool reset)
{
	struct pcep_config_group_opts *pce_config = NULL;
	struct pce_opts *pce_opts = &current_pce_opts_g->pce_opts;
	bool pce_in_use = false;

	if (vty->node == PCEP_PCE_NODE) {
		pce_config = &current_pce_opts_g->pce_config_group_opts;
		current_pce_opts_g->merged = false;
		pce_in_use = pcep_cli_pcc_has_pce(pce_opts->pce_name);
	} else if (vty->node == PCEP_PCE_CONFIG_NODE) {
		pce_config = current_pcep_config_group_opts_g;
	} else {
		return CMD_ERR_NO_MATCH;
	}

	pce_config->draft07 = reset ? DEFAULT_SR_DRAFT07 : true;

	if (pce_in_use) {
		vty_out(vty, "%% PCE in use, resetting pcc peer session...\n");
		reset_pcc_peer(pce_opts->pce_name);
	}

	return CMD_SUCCESS;
}

static int path_pcep_cli_peer_pce_initiated(struct vty *vty, bool reset)
{
	struct pcep_config_group_opts *pce_config = NULL;
	struct pce_opts *pce_opts = &current_pce_opts_g->pce_opts;
	bool pce_in_use = false;

	if (vty->node == PCEP_PCE_NODE) {
		pce_config = &current_pce_opts_g->pce_config_group_opts;
		current_pce_opts_g->merged = false;
		pce_in_use = pcep_cli_pcc_has_pce(pce_opts->pce_name);
	} else if (vty->node == PCEP_PCE_CONFIG_NODE) {
		pce_config = current_pcep_config_group_opts_g;
	} else {
		return CMD_ERR_NO_MATCH;
	}

	pce_config->pce_initiated = reset ? DEFAULT_PCE_INITIATED : true;

	if (pce_in_use) {
		vty_out(vty, "%% PCE in use, resetting pcc peer session...\n");
		reset_pcc_peer(pce_opts->pce_name);
	}

	return CMD_SUCCESS;
}

static int path_pcep_cli_peer_tcp_md5_auth(struct vty *vty,
					   const char *tcp_md5_auth,
					   bool reset)
{
	struct pcep_config_group_opts *pce_config = NULL;
	struct pce_opts *pce_opts = &current_pce_opts_g->pce_opts;
	bool pce_in_use = false;

	if (vty->node == PCEP_PCE_NODE) {
		pce_config = &current_pce_opts_g->pce_config_group_opts;
		current_pce_opts_g->merged = false;
		pce_in_use = pcep_cli_pcc_has_pce(pce_opts->pce_name);
	} else if (vty->node == PCEP_PCE_CONFIG_NODE) {
		pce_config = current_pcep_config_group_opts_g;
	} else {
		return CMD_ERR_NO_MATCH;
	}

	if (reset)
		pce_config->tcp_md5_auth[0] = '\0';
	else
		strlcpy(pce_config->tcp_md5_auth, tcp_md5_auth,
			sizeof(pce_config->tcp_md5_auth));

	if (pce_in_use) {
		vty_out(vty, "%% PCE in use, resetting pcc peer session...\n");
		reset_pcc_peer(pce_opts->pce_name);
	}

	return CMD_SUCCESS;
}

static int path_pcep_cli_peer_address(struct vty *vty, const char *ip_str,
				      struct in_addr *ip, const char *ipv6_str,
				      struct in6_addr *ipv6,
				      const char *port_str, long port)
{
	struct pce_opts *pce_opts = NULL;
	if (vty->node == PCEP_PCE_NODE) {
		/* TODO need to see if the pce is in use, and reset the
		 * connection */
		pce_opts = &current_pce_opts_g->pce_opts;
		current_pce_opts_g->merged = false;
	} else {
		return CMD_ERR_NO_MATCH;
	}

	if (ipv6_str != NULL) {
		pce_opts->addr.ipa_type = IPADDR_V6;
		memcpy(&pce_opts->addr.ipaddr_v6, ipv6,
		       sizeof(struct in6_addr));
	} else if (ip_str != NULL) {
		pce_opts->addr.ipa_type = IPADDR_V4;
		memcpy(&pce_opts->addr.ipaddr_v4, ip, sizeof(struct in_addr));
	} else {
		return CMD_ERR_NO_MATCH;
	}

	/* Handle the optional port */
	pce_opts->port = PCEP_DEFAULT_PORT;
	PCEP_VTYSH_INT_ARG_CHECK(port_str, port, pce_opts->port, 0, 65535);

	return CMD_SUCCESS;
}

static int path_pcep_cli_peer_source_address(struct vty *vty,
					     const char *ip_str,
					     struct in_addr *ip,
					     const char *ipv6_str,
					     struct in6_addr *ipv6,
					     const char *port_str, long port,
					     bool reset)
{
	struct pcep_config_group_opts *pce_config = NULL;
	struct pce_opts *pce_opts = &current_pce_opts_g->pce_opts;
	bool pce_in_use = false;

	if (vty->node == PCEP_PCE_NODE) {
		pce_config = &current_pce_opts_g->pce_config_group_opts;
		current_pce_opts_g->merged = false;
		pce_in_use = pcep_cli_pcc_has_pce(pce_opts->pce_name);
	} else if (vty->node == PCEP_PCE_CONFIG_NODE) {
		pce_config = current_pcep_config_group_opts_g;
	} else {
		return CMD_ERR_NO_MATCH;
	}

	if (reset) {
		pce_config->source_ip.ipa_type = IPADDR_NONE;
		pce_config->source_port = 0;
		return CMD_SUCCESS;
	}

	/* Handle the optional source IP */
	if (ipv6_str != NULL) {
		pce_config->source_ip.ipa_type = IPADDR_V6;
		memcpy(&pce_config->source_ip.ipaddr_v6, ipv6,
		       sizeof(struct in6_addr));
	} else if (ip_str != NULL) {
		pce_config->source_ip.ipa_type = IPADDR_V4;
		memcpy(&pce_config->source_ip.ipaddr_v4, ip,
		       sizeof(struct in_addr));
	}

	/* Handle the optional port */
	PCEP_VTYSH_INT_ARG_CHECK(port_str, port, pce_config->source_port, 0,
				 65535);

	if (pce_in_use) {
		vty_out(vty, "%% PCE in use, resetting pcc peer session...\n");
		reset_pcc_peer(pce_opts->pce_name);
	}

	return CMD_SUCCESS;
}

static int path_pcep_cli_peer_pcep_pce_config_ref(struct vty *vty,
						  const char *config_group_name)
{
	if (vty->node == PCEP_PCE_NODE) {
		/* TODO need to see if the pce is in use, and reset the
		 * connection */
		current_pce_opts_g->merged = false;
	} else {
		return CMD_ERR_NO_MATCH;
	}

	struct pcep_config_group_opts *pce_config =
		pcep_cli_find_pcep_pce_config(config_group_name);
	if (pce_config == NULL) {
		vty_out(vty, "%% pce-config [%s] does not exist.\n",
			config_group_name);
		return CMD_WARNING;
	}

	strlcpy(current_pce_opts_g->config_group_name, config_group_name,
		sizeof(current_pce_opts_g->config_group_name));

	return CMD_SUCCESS;
}

static int path_pcep_cli_peer_timers(
	struct vty *vty, const char *keep_alive_str, long keep_alive,
	const char *min_peer_keep_alive_str, long min_peer_keep_alive,
	const char *max_peer_keep_alive_str, long max_peer_keep_alive,
	const char *dead_timer_str, long dead_timer,
	const char *min_peer_dead_timer_str, long min_peer_dead_timer,
	const char *max_peer_dead_timer_str, long max_peer_dead_timer,
	const char *pcep_request_str, long pcep_request,
	const char *session_timeout_interval_str, long session_timeout_interval,
	const char *delegation_timeout_str, long delegation_timeout)
{
	struct pcep_config_group_opts *pce_config = NULL;
	struct pce_opts *pce_opts = &current_pce_opts_g->pce_opts;
	bool pce_in_use = false;

	if (vty->node == PCEP_PCE_NODE) {
		pce_config = &current_pce_opts_g->pce_config_group_opts;
		current_pce_opts_g->merged = false;
		pce_in_use = pcep_cli_pcc_has_pce(pce_opts->pce_name);
	} else if (vty->node == PCEP_PCE_CONFIG_NODE) {
		pce_config = current_pcep_config_group_opts_g;
	} else {
		return CMD_ERR_NO_MATCH;
	}

	if (min_peer_keep_alive && max_peer_keep_alive)
		if (min_peer_keep_alive >= max_peer_keep_alive) {
			return CMD_ERR_NO_MATCH;
		}

	if (min_peer_dead_timer && max_peer_dead_timer)
		if (min_peer_dead_timer >= max_peer_dead_timer) {
			return CMD_ERR_NO_MATCH;
		}

	/* Handle the arguments */
	PCEP_VTYSH_INT_ARG_CHECK(keep_alive_str, keep_alive,
				 pce_config->keep_alive_seconds, 0, 64);
	PCEP_VTYSH_INT_ARG_CHECK(min_peer_keep_alive_str, min_peer_keep_alive,
				 pce_config->min_keep_alive_seconds, 0, 256);
	PCEP_VTYSH_INT_ARG_CHECK(max_peer_keep_alive_str, max_peer_keep_alive,
				 pce_config->max_keep_alive_seconds, 0, 256);
	PCEP_VTYSH_INT_ARG_CHECK(dead_timer_str, dead_timer,
				 pce_config->dead_timer_seconds, 3, 256);
	PCEP_VTYSH_INT_ARG_CHECK(min_peer_dead_timer_str, min_peer_dead_timer,
				 pce_config->min_dead_timer_seconds, 3, 256);
	PCEP_VTYSH_INT_ARG_CHECK(max_peer_dead_timer_str, max_peer_dead_timer,
				 pce_config->max_dead_timer_seconds, 3, 256);
	PCEP_VTYSH_INT_ARG_CHECK(pcep_request_str, pcep_request,
				 pce_config->pcep_request_time_seconds, 0, 121);
	PCEP_VTYSH_INT_ARG_CHECK(
		session_timeout_interval_str, session_timeout_interval,
		pce_config->session_timeout_inteval_seconds, 0, 121);
	PCEP_VTYSH_INT_ARG_CHECK(delegation_timeout_str, delegation_timeout,
				 pce_config->delegation_timeout_seconds, 0, 61);

	if (pce_in_use) {
		vty_out(vty, "%% PCE in use, resetting pcc peer session...\n");
		reset_pcc_peer(pce_opts->pce_name);
	}

	return CMD_SUCCESS;
}

static int path_pcep_cli_pcc(struct vty *vty)
{
	VTY_PUSH_CONTEXT_NULL(PCEP_PCC_NODE);

	return CMD_SUCCESS;
}

static int path_pcep_cli_pcc_delete(struct vty *vty)
{
	/* Clear the pce_connections */
	memset(&pce_connections_g, 0, sizeof(pce_connections_g));
	pcc_msd_configured_g = false;

	pcep_ctrl_remove_pcc(pcep_g->fpt, NULL);

	return CMD_SUCCESS;
}

static int path_pcep_cli_pcc_pcc_msd(struct vty *vty, const char *msd_str,
				     long msd, bool reset)
{
	if (reset)
		pcc_msd_configured_g = false;
	else if (msd_str) {
		pcc_msd_configured_g = true;
		PCEP_VTYSH_INT_ARG_CHECK(msd_str, msd, pcc_msd_g, 0, 33);
	}

	return CMD_SUCCESS;
}

void reset_pcc_peer(const char *peer_name)
{
	struct pce_opts_cli *pce_opts_cli = pcep_cli_find_pce(peer_name);

	/* Remove the pcc peer */
	pcep_cli_remove_pce_connection(&pce_opts_cli->pce_opts);
	struct pce_opts *pce_opts_copy =
		XMALLOC(MTYPE_PCEP, sizeof(struct pce_opts));
	memcpy(pce_opts_copy, &pce_opts_cli->pce_opts, sizeof(struct pce_opts));
	pcep_ctrl_remove_pcc(pcep_g->fpt, pce_opts_copy);

	/* Re-add the pcc peer */
	pcep_cli_merge_pcep_pce_config_options(pce_opts_cli);
	pcep_cli_add_pce_connection(&pce_opts_cli->pce_opts);

	/* Update the pcc_opts */
	struct pcc_opts *pcc_opts_copy =
		XMALLOC(MTYPE_PCEP, sizeof(struct pcc_opts));
	memcpy(&pcc_opts_copy->addr,
	       &pce_opts_cli->pce_opts.config_opts.source_ip,
	       sizeof(pcc_opts_copy->addr));
	pcc_opts_copy->msd = pcc_msd_g;
	pcc_opts_copy->port = pce_opts_cli->pce_opts.config_opts.source_port;
	pcep_ctrl_update_pcc_options(pcep_g->fpt, pcc_opts_copy);

	/* Update the pce_opts */
	pce_opts_copy = XMALLOC(MTYPE_PCEP, sizeof(struct pce_opts));
	memcpy(pce_opts_copy, &pce_opts_cli->pce_opts, sizeof(struct pce_opts));
	pcep_ctrl_update_pce_options(pcep_g->fpt, pce_opts_copy);
}

static int path_pcep_cli_pcc_pcc_peer(struct vty *vty, const char *peer_name,
				      const char *precedence_str,
				      long precedence)
{
	/* Check if the pcc-peer exists */
	struct pce_opts_cli *pce_opts_cli = pcep_cli_find_pce(peer_name);
	if (pce_opts_cli == NULL) {
		vty_out(vty, "%% PCE [%s] does not exist.\n", peer_name);
		return CMD_WARNING;
	}
	struct pce_opts *pce_opts = &pce_opts_cli->pce_opts;

	/* Check if the pcc-peer is duplicated */
	if (pcep_cli_pcc_has_pce(peer_name)) {
		vty_out(vty, "%% The peer [%s] has already been configured.\n",
			peer_name);
		return CMD_WARNING;
	}

	/* Get the optional precedence argument */
	pce_opts->precedence = DEFAULT_PCE_PRECEDENCE;
	PCEP_VTYSH_INT_ARG_CHECK(precedence_str, precedence,
				 pce_opts->precedence, 0, 256);

	/* Finalize the pce_opts config values */
	pcep_cli_merge_pcep_pce_config_options(pce_opts_cli);
	pcep_cli_add_pce_connection(&pce_opts_cli->pce_opts);

	/* Verify the PCE has the IP set */
	struct in6_addr zero_v6_addr;
	memset(&zero_v6_addr, 0, sizeof(zero_v6_addr));
	if (memcmp(&pce_opts->addr.ip, &zero_v6_addr, IPADDRSZ(&pce_opts->addr))
	    == 0) {
		vty_out(vty,
			"%% The peer [%s] does not have an IP set and cannot be used until it does.\n",
			peer_name);
		return CMD_WARNING;
	}

	/* Update the pcc_opts with the source ip, port, and msd */
	struct pcc_opts *pcc_opts_copy =
		XMALLOC(MTYPE_PCEP, sizeof(struct pcc_opts));
	memcpy(&pcc_opts_copy->addr,
	       &pce_opts_cli->pce_opts.config_opts.source_ip,
	       sizeof(pcc_opts_copy->addr));
	pcc_opts_copy->msd = pcc_msd_g;
	pcc_opts_copy->port = pce_opts_cli->pce_opts.config_opts.source_port;
	if (pcep_ctrl_update_pcc_options(pcep_g->fpt, pcc_opts_copy)) {
		return CMD_WARNING;
	}

	/* Send a copy of the pce_opts, this one is only used for the CLI */
	struct pce_opts *pce_opts_copy =
		XMALLOC(MTYPE_PCEP, sizeof(struct pce_opts));
	memcpy(pce_opts_copy, pce_opts, sizeof(struct pce_opts));
	if (pcep_ctrl_update_pce_options(pcep_g->fpt, pce_opts_copy)) {
		return CMD_WARNING;
	}

	return CMD_SUCCESS;
}

static int path_pcep_cli_pcc_pcc_peer_delete(struct vty *vty,
					     const char *peer_name,
					     const char *precedence_str,
					     long precedence)
{
	/* Check if the pcc-peer is connected to the PCC */
	if (!pcep_cli_pcc_has_pce(peer_name)) {
		vty_out(vty,
			"%% WARN: The peer [%s] is not connected to the PCC.\n",
			peer_name);
		return CMD_WARNING;
	}

	struct pce_opts_cli *pce_opts_cli = pcep_cli_find_pce(peer_name);
	pcep_cli_remove_pce_connection(&pce_opts_cli->pce_opts);

	/* Send a copy of the pce_opts, this one is used for CLI only */
	struct pce_opts *pce_opts_copy =
		XMALLOC(MTYPE_PCEP, sizeof(struct pce_opts));
	memcpy(pce_opts_copy, &pce_opts_cli->pce_opts, sizeof(struct pce_opts));
	pcep_ctrl_remove_pcc(pcep_g->fpt, pce_opts_copy);

	return CMD_SUCCESS;
}

static int path_pcep_cli_show_srte_pcep_pcc(struct vty *vty)
{
	vty_out(vty, "pcc msd %d\n", pcc_msd_g);

	return CMD_SUCCESS;
}

/* Internal util function to print pcep capabilities to a buffer */
static void print_pcep_capabilities(char *buf, size_t buf_len,
				    pcep_configuration *config)
{
	if (config->support_stateful_pce_lsp_update) {
		csnprintfrr(buf, buf_len, "%s", PCEP_CLI_CAP_STATEFUL);
	}
	if (config->support_include_db_version) {
		csnprintfrr(buf, buf_len, "%s", PCEP_CLI_CAP_INCL_DB_VER);
	}
	if (config->support_lsp_triggered_resync) {
		csnprintfrr(buf, buf_len, "%s", PCEP_CLI_CAP_LSP_TRIGGERED);
	}
	if (config->support_lsp_delta_sync) {
		csnprintfrr(buf, buf_len, "%s", PCEP_CLI_CAP_LSP_DELTA);
	}
	if (config->support_pce_triggered_initial_sync) {
		csnprintfrr(buf, buf_len, "%s", PCEP_CLI_CAP_PCE_TRIGGERED);
	}
	if (config->support_sr_te_pst) {
		csnprintfrr(buf, buf_len, "%s", PCEP_CLI_CAP_SR_TE_PST);
	}
	if (config->pcc_can_resolve_nai_to_sid) {
		csnprintfrr(buf, buf_len, "%s", PCEP_CLI_CAP_PCC_RESOLVE_NAI);
	}
}

/* Internal util function to print a pcep session */
static void print_pcep_session_json(struct vty *vty, struct pce_opts *pce_opts,
				    struct pcep_pcc_info *pcc_info,
				    json_object *json)
{
	char buf[BUFFER_PCC_PCE_SIZE] = {};
	int index = 0;
	pcep_session *session;
	struct pcep_config_group_opts *config_opts;
	struct counters_group *group;

	/* PCE IP */
	if (IS_IPADDR_V4(&pce_opts->addr))
		json_object_string_addf(json, "pceAddress", "%pI4",
					&pce_opts->addr.ipaddr_v4);
	else if (IS_IPADDR_V6(&pce_opts->addr))
		json_object_string_addf(json, "pceAddress", "%pI6",
					&pce_opts->addr.ipaddr_v6);
	json_object_int_add(json, "pcePort", pce_opts->port);

	/* PCC IP */
	if (IS_IPADDR_V4(&pcc_info->pcc_addr))
		json_object_string_addf(json, "pccAddress", "%pI4",
					&pcc_info->pcc_addr.ipaddr_v4);
	else if (IS_IPADDR_V6(&pcc_info->pcc_addr))
		json_object_string_addf(json, "pccAddress", "%pI6",
					&pcc_info->pcc_addr.ipaddr_v6);

	json_object_int_add(json, "pccPort", pcc_info->pcc_port);
	json_object_int_add(json, "pccMsd", pcc_info->msd);

	if (pcc_info->status == PCEP_PCC_OPERATING)
		json_object_string_add(json, "sessionStatus", "UP");
	else
		json_object_string_add(json, "sessionStatus",
				       pcc_status_name(pcc_info->status));

	json_object_boolean_add(json, "bestMultiPce",
				pcc_info->is_best_multi_pce);
	json_object_int_add(json, "precedence",
			    pcc_info->precedence > 0 ? pcc_info->precedence
						     : DEFAULT_PCE_PRECEDENCE);
	json_object_string_add(json, "confidence",
			       pcc_info->previous_best ? "low" : "normal");

	/* PCEPlib pcep session values, get a thread safe copy of the counters
	 */
	session = pcep_ctrl_get_pcep_session(pcep_g->fpt, pcc_info->pcc_id);

	/* Config Options values */
	config_opts = &pce_opts->config_opts;
	json_object_int_add(json, "keepaliveConfig",
			    config_opts->keep_alive_seconds);
	json_object_int_add(json, "deadTimerConfig",
			    config_opts->dead_timer_seconds);
	json_object_int_add(json, "pccPcepRequestTimerConfig",
			    config_opts->pcep_request_time_seconds);
	json_object_int_add(json, "sessionTimeoutIntervalSec",
			    config_opts->session_timeout_inteval_seconds);
	json_object_int_add(json, "delegationTimeout",
			    config_opts->delegation_timeout_seconds);
	json_object_boolean_add(json, "tcpMd5Authentication",
				(strlen(config_opts->tcp_md5_auth) > 0));
	if (strlen(config_opts->tcp_md5_auth) > 0)
		json_object_string_add(json, "tcpMd5AuthenticationString",
				       config_opts->tcp_md5_auth);
	json_object_boolean_add(json, "draft07", !!config_opts->draft07);
	json_object_boolean_add(json, "draft16AndRfc8408",
				!config_opts->draft07);

	json_object_int_add(json, "nextPcRequestId", pcc_info->next_reqid);
	/* original identifier used by the PCC for LSP instantiation */
	json_object_int_add(json, "nextPLspId", pcc_info->next_plspid);

	if (session != NULL) {
		json_object_int_add(json, "sessionKeepalivePceNegotiatedSec",
				    session->pcc_config
					    .keep_alive_pce_negotiated_timer_seconds);
		json_object_int_add(json, "sessionDeadTimerPceNegotiatedSec",
				    session->pcc_config
					    .dead_timer_pce_negotiated_seconds);
		if (pcc_info->status == PCEP_PCC_SYNCHRONIZING ||
		    pcc_info->status == PCEP_PCC_OPERATING) {
			time_t current_time = time(NULL);
			struct tm lt = { 0 };
			/* Just for the timezone */
			localtime_r(&current_time, &lt);
			gmtime_r(&session->time_connected, &lt);
			json_object_int_add(json, "sessionConnectionDurationSec",
					    (uint32_t)(current_time -
						       session->time_connected));
			json_object_string_addf(json,
						"sessionConnectionStartTimeUTC",
						"%d-%02d-%02d %02d:%02d:%02d",
						lt.tm_year + 1900, lt.tm_mon + 1,
						lt.tm_mday, lt.tm_hour,
						lt.tm_min, lt.tm_sec);
		}

		/* PCC capabilities */
		buf[0] = '\0';

		if (config_opts->pce_initiated)
			index += csnprintfrr(buf, sizeof(buf), "%s",
					     PCEP_CLI_CAP_PCC_PCE_INITIATED);
		else
			index += csnprintfrr(buf, sizeof(buf), "%s",
					     PCEP_CLI_CAP_PCC_INITIATED);
		print_pcep_capabilities(buf, sizeof(buf) - index,
					&session->pcc_config);
		json_object_string_add(json, "pccCapabilities", buf);

		/* PCE capabilities */
		buf[0] = '\0';
		print_pcep_capabilities(buf, sizeof(buf), &session->pce_config);
		if (buf[0] != '\0')
			json_object_string_add(json, "pceCapabilities", buf);
		XFREE(MTYPE_PCEP, session);
	} else {
		json_object_string_add(json, "warningSession",
				       "Detailed session information not available.");
	}

	/* Message Counters, get a thread safe copy of the counters */
	group = pcep_ctrl_get_counters(pcep_g->fpt, pcc_info->pcc_id);

	if (group != NULL) {
		struct counters_subgroup *rx_msgs =
			find_subgroup(group, COUNTER_SUBGROUP_ID_RX_MSG);
		struct counters_subgroup *tx_msgs =
			find_subgroup(group, COUNTER_SUBGROUP_ID_TX_MSG);
		json_object *json_counter;
		struct counter *tx_counter, *rx_counter;

		if (rx_msgs != NULL) {
			json_counter = json_object_new_object();
			for (int i = 0; i < rx_msgs->max_counters; i++) {
				rx_counter = rx_msgs->counters[i];

				if (rx_counter &&
				    rx_counter->counter_name_json[0] != '\0')
					json_object_int_add(
						json_counter,
						rx_counter->counter_name_json,
						rx_counter->counter_value);
			}
			json_object_int_add(json_counter, "total",
					    subgroup_counters_total(rx_msgs));
			json_object_object_add(json, "messageStatisticsReceived",
					       json_counter);
		}
		if (tx_msgs != NULL) {
			json_counter = json_object_new_object();
			for (int i = 0; i < tx_msgs->max_counters; i++) {
				tx_counter = tx_msgs->counters[i];

				if (tx_counter &&
				    tx_counter->counter_name_json[0] != '\0')
					json_object_int_add(
						json_counter,
						tx_counter->counter_name_json,
						tx_counter->counter_value);
			}
			json_object_int_add(json_counter, "total",
					    subgroup_counters_total(tx_msgs));
			json_object_object_add(json, "messageStatisticsSent",
					       json_counter);
		}
		pcep_lib_free_counters(group);
	} else {
		json_object_string_add(json, "messageStatisticsWarning",
				       "Counters not available.");
	}

	XFREE(MTYPE_PCEP, pcc_info);
}

/* Internal util function to print a pcep session */
static void print_pcep_session(struct vty *vty, struct pce_opts *pce_opts,
			       struct pcep_pcc_info *pcc_info)
{
	char buf[1024];

	buf[0] = '\0';

	vty_out(vty, "\nPCE %s\n", pce_opts->pce_name);

	/* PCE IP */
	if (IS_IPADDR_V4(&pce_opts->addr)) {
		vty_out(vty, " PCE IP %pI4 port %d\n",
			&pce_opts->addr.ipaddr_v4, pce_opts->port);
	} else if (IS_IPADDR_V6(&pce_opts->addr)) {
		vty_out(vty, " PCE IPv6 %pI6 port %d\n",
			&pce_opts->addr.ipaddr_v6, pce_opts->port);
	}

	/* PCC IP */
	if (IS_IPADDR_V4(&pcc_info->pcc_addr)) {
		vty_out(vty, " PCC IP %pI4 port %d\n",
			&pcc_info->pcc_addr.ipaddr_v4, pcc_info->pcc_port);
	} else if (IS_IPADDR_V6(&pcc_info->pcc_addr)) {
		vty_out(vty, " PCC IPv6 %pI6 port %d\n",
			&pcc_info->pcc_addr.ipaddr_v6, pcc_info->pcc_port);
	}
	vty_out(vty, " PCC MSD %d\n", pcc_info->msd);

	if (pcc_info->status == PCEP_PCC_OPERATING) {
		vty_out(vty, " Session Status UP\n");
	} else {
		vty_out(vty, " Session Status %s\n",
			pcc_status_name(pcc_info->status));
	}

	if (pcc_info->is_best_multi_pce) {
		vty_out(vty, " Precedence %d, best candidate\n",
			((pcc_info->precedence > 0) ? pcc_info->precedence
						    : DEFAULT_PCE_PRECEDENCE));
	} else {
		vty_out(vty, " Precedence %d\n",
			((pcc_info->precedence > 0) ? pcc_info->precedence
						    : DEFAULT_PCE_PRECEDENCE));
	}
	vty_out(vty, " Confidence %s\n",
		((pcc_info->previous_best) ? "low"
		 : "normal"));

	/* PCEPlib pcep session values, get a thread safe copy of the counters
	 */
	pcep_session *session =
		pcep_ctrl_get_pcep_session(pcep_g->fpt, pcc_info->pcc_id);

	/* Config Options values */
	struct pcep_config_group_opts *config_opts = &pce_opts->config_opts;

	if (session != NULL) {
		vty_out(vty, " Timer: KeepAlive config %d, pce-negotiated %d\n",
			config_opts->keep_alive_seconds,
			session->pcc_config
				.keep_alive_pce_negotiated_timer_seconds);
		vty_out(vty, " Timer: DeadTimer config %d, pce-negotiated %d\n",
			config_opts->dead_timer_seconds,
			session->pcc_config.dead_timer_pce_negotiated_seconds);
	} else {
		vty_out(vty, " Timer: KeepAlive %d\n",
			config_opts->keep_alive_seconds);
		vty_out(vty, " Timer: DeadTimer %d\n",
			config_opts->dead_timer_seconds);
	}
	vty_out(vty, " Timer: PcRequest %d\n",
		config_opts->pcep_request_time_seconds);
	vty_out(vty, " Timer: SessionTimeout Interval %d\n",
		config_opts->session_timeout_inteval_seconds);
	vty_out(vty, " Timer: Delegation Timeout %d\n",
		config_opts->delegation_timeout_seconds);
	if (strlen(config_opts->tcp_md5_auth) > 0) {
		vty_out(vty, " TCP MD5 Auth Str: %s\n",
			config_opts->tcp_md5_auth);
	} else {
		vty_out(vty, " No TCP MD5 Auth\n");
	}

	if (config_opts->draft07) {
		vty_out(vty, " PCE SR Version draft07\n");
	} else {
		vty_out(vty, " PCE SR Version draft16 and RFC8408\n");
	}

	vty_out(vty, " Next PcReq ID %d\n", pcc_info->next_reqid);
	vty_out(vty, " Next PLSP  ID %d\n", pcc_info->next_plspid);

	if (session != NULL) {
		if (pcc_info->status == PCEP_PCC_SYNCHRONIZING
		    || pcc_info->status == PCEP_PCC_OPERATING) {
			time_t current_time = time(NULL);
			struct tm lt = {0};
			/* Just for the timezone */
			localtime_r(&current_time, &lt);
			gmtime_r(&session->time_connected, &lt);
			vty_out(vty,
				" Connected for %u seconds, since %d-%02d-%02d %02d:%02d:%02d UTC\n",
				(uint32_t)(current_time
					   - session->time_connected),
				lt.tm_year + 1900, lt.tm_mon + 1, lt.tm_mday,
				lt.tm_hour, lt.tm_min, lt.tm_sec);
		}

		/* PCC capabilities */
		buf[0] = '\0';
		int index = 0;
		if (config_opts->pce_initiated) {
			index += csnprintfrr(buf, sizeof(buf), "%s",
					     PCEP_CLI_CAP_PCC_PCE_INITIATED);
		} else {
			index += csnprintfrr(buf, sizeof(buf), "%s",
					     PCEP_CLI_CAP_PCC_INITIATED);
		}
		print_pcep_capabilities(buf, sizeof(buf) - index,
					&session->pcc_config);
		vty_out(vty, " PCC Capabilities:%s\n", buf);

		/* PCE capabilities */
		buf[0] = '\0';
		print_pcep_capabilities(buf, sizeof(buf), &session->pce_config);
		if (buf[0] != '\0') {
			vty_out(vty, " PCE Capabilities:%s\n", buf);
		}
		XFREE(MTYPE_PCEP, session);
	} else {
		vty_out(vty, " Detailed session information not available\n");
	}

	/* Message Counters, get a thread safe copy of the counters */
	struct counters_group *group =
		pcep_ctrl_get_counters(pcep_g->fpt, pcc_info->pcc_id);

	if (group != NULL) {
		struct counters_subgroup *rx_msgs =
			find_subgroup(group, COUNTER_SUBGROUP_ID_RX_MSG);
		struct counters_subgroup *tx_msgs =
			find_subgroup(group, COUNTER_SUBGROUP_ID_TX_MSG);

		if (rx_msgs != NULL && tx_msgs != NULL) {
			vty_out(vty, " PCEP Message Statistics\n");
			vty_out(vty, " %27s %6s\n", "Sent", "Rcvd");
			for (int i = 0; i < rx_msgs->max_counters; i++) {
				struct counter *rx_counter =
					rx_msgs->counters[i];
				struct counter *tx_counter =
					tx_msgs->counters[i];
				if (rx_counter != NULL && tx_counter != NULL) {
					vty_out(vty, " %20s: %5d  %5d\n",
						tx_counter->counter_name,
						tx_counter->counter_value,
						rx_counter->counter_value);
				}
			}
			vty_out(vty, " %20s: %5d  %5d\n", "Total",
				subgroup_counters_total(tx_msgs),
				subgroup_counters_total(rx_msgs));
		}
		pcep_lib_free_counters(group);
	} else {
		vty_out(vty, " Counters not available\n");
	}

	XFREE(MTYPE_PCEP, pcc_info);
}

static int path_pcep_cli_show_srte_pcep_session(struct vty *vty,
						const char *pcc_peer, bool uj)
{
	struct pce_opts_cli *pce_opts_cli;
	struct pcep_pcc_info *pcc_info;
	json_object *json = NULL;

	if (uj)
		json = json_object_new_object();

	/* Only show 1 PCEP session */
	if (pcc_peer != NULL) {
		if (json)
			json_object_string_add(json, "pceName", pcc_peer);
		pce_opts_cli = pcep_cli_find_pce(pcc_peer);
		if (pce_opts_cli == NULL) {
			if (json) {
				json_object_string_addf(json, "warning",
							"PCE [%s] does not exist.",
							pcc_peer);
				vty_json(vty, json);
			} else
				vty_out(vty, "%% PCE [%s] does not exist.\n",
					pcc_peer);
			return CMD_WARNING;
		}

		if (!pcep_cli_pcc_has_pce(pcc_peer)) {
			if (json) {
				json_object_string_addf(json, "warning",
							"PCC is not connected to PCE [%s].",
							pcc_peer);
				vty_json(vty, json);
			} else
				vty_out(vty,
					"%% PCC is not connected to PCE [%s].\n",
					pcc_peer);
			return CMD_WARNING;
		}

		pcc_info = pcep_ctrl_get_pcc_info(pcep_g->fpt, pcc_peer);
		if (pcc_info == NULL) {
			if (json) {
				json_object_string_addf(json, "warning",
							"Cannot retrieve PCEP session info for PCE [%s].",
							pcc_peer);
				vty_json(vty, json);
			} else
				vty_out(vty,
					"%% Cannot retrieve PCEP session info for PCE [%s]\n",
					pcc_peer);
			return CMD_WARNING;
		}

		if (json) {
			print_pcep_session_json(vty, &pce_opts_cli->pce_opts,
						pcc_info, json);
			vty_json(vty, json);
		} else
			print_pcep_session(vty, &pce_opts_cli->pce_opts,
					   pcc_info);

		return CMD_SUCCESS;
	}

	/* Show all PCEP sessions */
	struct pce_opts *pce_opts;
	int num_pcep_sessions_conf = 0;
	int num_pcep_sessions_conn = 0;
	json_object *json_array = NULL, *json_entry = NULL;

	if (json)
		json_array = json_object_new_array();
	for (int i = 0; i < MAX_PCC; i++) {
		pce_opts = pce_connections_g.connections[i];
		if (pce_opts == NULL) {
			continue;
		}

		if (json) {
			json_entry = json_object_new_object();
			json_object_string_add(json_entry, "pceName",
					       pce_opts->pce_name);
		}
		pcc_info =
			pcep_ctrl_get_pcc_info(pcep_g->fpt, pce_opts->pce_name);
		if (pcc_info == NULL) {
			if (json_entry) {
				json_object_string_addf(json_entry, "warning",
							"Cannot retrieve PCEP session info for PCE [%s].",
							pce_opts->pce_name);
				json_object_array_add(json_array, json_entry);
			} else
				vty_out(vty,
					"%% Cannot retrieve PCEP session info for PCE [%s]\n",
					pce_opts->pce_name);
			continue;
		}

		num_pcep_sessions_conn +=
			pcc_info->status == PCEP_PCC_OPERATING ? 1 : 0;
		num_pcep_sessions_conf++;
		if (json_entry) {
			print_pcep_session_json(vty, pce_opts, pcc_info,
						json_entry);
			json_object_array_add(json_array, json_entry);
		} else
			print_pcep_session(vty, pce_opts, pcc_info);
	}
	if (json) {
		json_object_object_add(json, "pcepSessions", json_array);
		json_object_int_add(json, "pcepSessionsConfigured",
				    num_pcep_sessions_conf);
		json_object_int_add(json, "pcepSessionsConnected",
				    num_pcep_sessions_conn);
		vty_json(vty, json);
	} else
		vty_out(vty, "PCEP Sessions => Configured %d ; Connected %d\n",
			num_pcep_sessions_conf, num_pcep_sessions_conn);

	return CMD_SUCCESS;
}

static int path_pcep_cli_clear_srte_pcep_session(struct vty *vty,
						 const char *pcc_peer)
{
	struct pce_opts_cli *pce_opts_cli;

	/* Only clear 1 PCEP session */
	if (pcc_peer != NULL) {
		pce_opts_cli = pcep_cli_find_pce(pcc_peer);
		if (pce_opts_cli == NULL) {
			vty_out(vty, "%% PCE [%s] does not exist.\n", pcc_peer);
			return CMD_WARNING;
		}

		if (!pcep_cli_pcc_has_pce(pcc_peer)) {
			vty_out(vty, "%% PCC is not connected to PCE [%s].\n",
				pcc_peer);
			return CMD_WARNING;
		}

		pcep_ctrl_reset_pcc_session(pcep_g->fpt,
					    pce_opts_cli->pce_opts.pce_name);
		vty_out(vty, "PCEP session cleared for peer %s\n", pcc_peer);

		return CMD_SUCCESS;
	}

	/* Clear all PCEP sessions */
	struct pce_opts *pce_opts;
	int num_pcep_sessions = 0;
	for (int i = 0; i < MAX_PCC; i++) {
		pce_opts = pce_connections_g.connections[i];
		if (pce_opts == NULL) {
			continue;
		}

		num_pcep_sessions++;
		pcep_ctrl_reset_pcc_session(pcep_g->fpt, pce_opts->pce_name);
		vty_out(vty, "PCEP session cleared for peer %s\n",
			pce_opts->pce_name);
	}

	vty_out(vty, "Cleared [%d] PCEP sessions\n", num_pcep_sessions);

	return CMD_SUCCESS;
}

/*
 * Config Write functions
 */

int pcep_cli_debug_config_write(struct vty *vty)
{
	char buff[128] = "";

	if (DEBUG_MODE_CHECK(&pcep_g->dbg, DEBUG_MODE_CONF)) {
		if (DEBUG_FLAGS_CHECK(&pcep_g->dbg, PCEP_DEBUG_MODE_BASIC))
			csnprintfrr(buff, sizeof(buff), " %s",
				    PCEP_VTYSH_ARG_BASIC);
		if (DEBUG_FLAGS_CHECK(&pcep_g->dbg, PCEP_DEBUG_MODE_PATH))
			csnprintfrr(buff, sizeof(buff), " %s",
				    PCEP_VTYSH_ARG_PATH);
		if (DEBUG_FLAGS_CHECK(&pcep_g->dbg, PCEP_DEBUG_MODE_PCEP))
			csnprintfrr(buff, sizeof(buff), " %s",
				    PCEP_VTYSH_ARG_MESSAGE);
		if (DEBUG_FLAGS_CHECK(&pcep_g->dbg, PCEP_DEBUG_MODE_PCEPLIB))
			csnprintfrr(buff, sizeof(buff), " %s",
				    PCEP_VTYSH_ARG_PCEPLIB);
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

int pcep_cli_pcep_config_write(struct vty *vty)
{
	vty_out(vty, "  pcep\n");
	pcep_cli_pcep_pce_config_write(vty);
	pcep_cli_pce_config_write(vty);
	pcep_cli_pcc_config_write(vty);
	vty_out(vty, "  exit\n");
	return 1;
}

int pcep_cli_pcc_config_write(struct vty *vty)
{
	struct pce_opts *pce_opts;
	char buf[128] = "";
	int lines = 0;

	/* The MSD, nor any PCE peers have been configured on the PCC */
	if (!pcc_msd_configured_g && pce_connections_g.num_connections == 0) {
		return lines;
	}

	vty_out(vty, "   pcc\n");
	lines++;

	/* Prepare the MSD, if present */
	if (pcc_msd_configured_g) {
		vty_out(vty, "    %s %d\n", PCEP_VTYSH_ARG_MSD, pcc_msd_g);
		lines++;
	}

	if (pce_connections_g.num_connections == 0) {
		goto exit;
	}

	buf[0] = 0;
	for (int i = 0; i < MAX_PCC; i++) {
		pce_opts = pce_connections_g.connections[i];
		if (pce_opts == NULL) {
			continue;
		}

		/* Only show the PCEs configured in the pcc sub-command */
		if (!pcep_cli_pcc_has_pce(pce_opts->pce_name)) {
			continue;
		}

		csnprintfrr(buf, sizeof(buf), "    peer %s",
			    pce_opts->pce_name);
		if (pce_opts->precedence > 0
		    && pce_opts->precedence != DEFAULT_PCE_PRECEDENCE) {
			csnprintfrr(buf, sizeof(buf), " %s %d",
				    PCEP_VTYSH_ARG_PRECEDENCE,
				    pce_opts->precedence);
		}
		vty_out(vty, "%s\n", buf);
		lines++;
		buf[0] = 0;
	}
exit:
	vty_out(vty, "   exit\n");

	return lines;
}

/* Internal function used by pcep_cli_pce_config_write()
 * and pcep_cli_pcep_pce_config_write() */
static int pcep_cli_print_pce_config(struct pcep_config_group_opts *group_opts,
				     char *buf, size_t buf_len)
{
	int lines = 0;

	if (group_opts->source_ip.ipa_type != IPADDR_NONE
	    || group_opts->source_port != 0) {
		csnprintfrr(buf, buf_len, "   ");
		if (IS_IPADDR_V4(&group_opts->source_ip)) {
			csnprintfrr(buf, buf_len, " %s %s %pI4",
				    PCEP_VTYSH_ARG_SOURCE_ADDRESS,
				    PCEP_VTYSH_ARG_IP,
				    &group_opts->source_ip.ipaddr_v4);
		} else if (IS_IPADDR_V6(&group_opts->source_ip)) {
			csnprintfrr(buf, buf_len, " %s %s %pI6",
				    PCEP_VTYSH_ARG_SOURCE_ADDRESS,
				    PCEP_VTYSH_ARG_IPV6,
				    &group_opts->source_ip.ipaddr_v6);
		}
		if (group_opts->source_port > 0) {
			csnprintfrr(buf, buf_len, " %s %d", PCEP_VTYSH_ARG_PORT,
				    group_opts->source_port);
		}
		csnprintfrr(buf, buf_len, "\n");
		lines++;
	}
	/* Group the keep-alive together for devman */
	if ((group_opts->keep_alive_seconds > 0)
	    || (group_opts->min_keep_alive_seconds > 0)
	    || (group_opts->max_keep_alive_seconds > 0)) {
		csnprintfrr(buf, buf_len, "    %s", PCEP_VTYSH_ARG_TIMER);

		if (group_opts->keep_alive_seconds > 0) {
			csnprintfrr(buf, buf_len, " %s %d",
				    PCEP_VTYSH_ARG_KEEP_ALIVE,
				    group_opts->keep_alive_seconds);
		}
		if (group_opts->min_keep_alive_seconds > 0) {
			csnprintfrr(buf, buf_len, " %s %d",
				    PCEP_VTYSH_ARG_KEEP_ALIVE_MIN,
				    group_opts->min_keep_alive_seconds);
		}
		if (group_opts->max_keep_alive_seconds > 0) {
			csnprintfrr(buf, buf_len, " %s %d",
				    PCEP_VTYSH_ARG_KEEP_ALIVE_MAX,
				    group_opts->max_keep_alive_seconds);
		}
		csnprintfrr(buf, buf_len, "\n");
		lines++;
	}

	/* Group the dead-timer together for devman */
	if ((group_opts->dead_timer_seconds > 0)
	    || (group_opts->min_dead_timer_seconds > 0)
	    || (group_opts->max_dead_timer_seconds > 0)) {
		csnprintfrr(buf, buf_len, "    %s", PCEP_VTYSH_ARG_TIMER);

		if (group_opts->dead_timer_seconds > 0) {
			csnprintfrr(buf, buf_len, " %s %d",
				    PCEP_VTYSH_ARG_DEAD_TIMER,
				    group_opts->dead_timer_seconds);
		}
		if (group_opts->min_dead_timer_seconds > 0) {
			csnprintfrr(buf, buf_len, " %s %d",
				    PCEP_VTYSH_ARG_DEAD_TIMER_MIN,
				    group_opts->min_dead_timer_seconds);
		}
		if (group_opts->max_dead_timer_seconds > 0) {
			csnprintfrr(buf, buf_len, " %s %d",
				    PCEP_VTYSH_ARG_DEAD_TIMER_MAX,
				    group_opts->max_dead_timer_seconds);
		}
		csnprintfrr(buf, buf_len, "\n");
		lines++;
	}

	if (group_opts->pcep_request_time_seconds > 0) {
		csnprintfrr(buf, buf_len, "    %s %s %d\n",
			    PCEP_VTYSH_ARG_TIMER, PCEP_VTYSH_ARG_PCEP_REQUEST,
			    group_opts->pcep_request_time_seconds);
		lines++;
	}
	if (group_opts->delegation_timeout_seconds > 0) {
		csnprintfrr(buf, buf_len, "    %s %s %d\n",
			    PCEP_VTYSH_ARG_TIMER,
			    PCEP_VTYSH_ARG_DELEGATION_TIMEOUT,
			    group_opts->delegation_timeout_seconds);
		lines++;
	}
	if (group_opts->session_timeout_inteval_seconds > 0) {
		csnprintfrr(buf, buf_len, "    %s %s %d\n",
			    PCEP_VTYSH_ARG_TIMER,
			    PCEP_VTYSH_ARG_SESSION_TIMEOUT,
			    group_opts->session_timeout_inteval_seconds);
		lines++;
	}
	if (group_opts->tcp_md5_auth[0] != '\0') {
		csnprintfrr(buf, buf_len, "    %s %s\n", PCEP_VTYSH_ARG_TCP_MD5,
			    group_opts->tcp_md5_auth);
		lines++;
	}
	if (group_opts->draft07) {
		csnprintfrr(buf, buf_len, "    %s\n",
			    PCEP_VTYSH_ARG_SR_DRAFT07);
		lines++;
	}
	if (group_opts->pce_initiated) {
		csnprintfrr(buf, buf_len, "    %s\n", PCEP_VTYSH_ARG_PCE_INIT);
		lines++;
	}

	return lines;
}

int pcep_cli_pce_config_write(struct vty *vty)
{
	int lines = 0;
	char buf[1024] = "";

	for (int i = 0; i < MAX_PCE; i++) {
		struct pce_opts_cli *pce_opts_cli = pcep_g->pce_opts_cli[i];
		if (pce_opts_cli == NULL) {
			continue;
		}
		struct pce_opts *pce_opts = &pce_opts_cli->pce_opts;

		vty_out(vty, "   pce %s\n", pce_opts->pce_name);
		if (IS_IPADDR_V6(&pce_opts->addr)) {
			vty_out(vty, "  %s %s %pI6", PCEP_VTYSH_ARG_ADDRESS,
				PCEP_VTYSH_ARG_IPV6, &pce_opts->addr.ipaddr_v6);
		} else if (IS_IPADDR_V4(&pce_opts->addr)) {
			vty_out(vty, "    address %s %pI4", PCEP_VTYSH_ARG_IP,
				&pce_opts->addr.ipaddr_v4);
		}
		if (pce_opts->port != PCEP_DEFAULT_PORT) {
			vty_out(vty, " %s %d", PCEP_VTYSH_ARG_PORT,
				pce_opts->port);
		}
		vty_out(vty, "%s\n", buf);
		lines += 2;

		if (pce_opts_cli->config_group_name[0] != '\0') {
			vty_out(vty, "    config %s\n",
				pce_opts_cli->config_group_name);
			lines++;
		}

		/* Only display the values configured on the PCE, not the values
		 * from its optional pce-config-group, nor the default values */
		lines += pcep_cli_print_pce_config(
			&pce_opts_cli->pce_config_group_opts, buf, sizeof(buf));

		vty_out(vty, "%s", buf);
		buf[0] = '\0';

		vty_out(vty, "   exit\n");
	}

	return lines;
}

int pcep_cli_pcep_pce_config_write(struct vty *vty)
{
	int lines = 0;
	char buf[1024] = "";

	for (int i = 0; i < MAX_PCE; i++) {
		struct pcep_config_group_opts *group_opts =
			pcep_g->config_group_opts[i];
		if (group_opts == NULL) {
			continue;
		}

		vty_out(vty, "   pce-config %s\n", group_opts->name);
		lines += 1;

		lines +=
			pcep_cli_print_pce_config(group_opts, buf, sizeof(buf));
		vty_out(vty, "%s", buf);
		buf[0] = 0;

		vty_out(vty, "   exit\n");
	}

	return lines;
}

/*
 * VTYSH command syntax definitions
 * The param names are taken from the path_pcep_cli_clippy.c generated file.
 */

DEFPY(show_debugging_pathd_pcep,
      show_debugging_pathd_pcep_cmd,
      "show debugging pathd-pcep",
      SHOW_STR
      "State of each debugging option\n"
      "pathd pcep module debugging\n")
{
	vty_out(vty, "Pathd pcep debugging status:\n");

	if (DEBUG_MODE_CHECK(&pcep_g->dbg, DEBUG_MODE_CONF)) {
		if (DEBUG_FLAGS_CHECK(&pcep_g->dbg, PCEP_DEBUG_MODE_BASIC))
			vty_out(vty, "  Pathd pcep %s debugging is on\n",
				PCEP_VTYSH_ARG_BASIC);
		if (DEBUG_FLAGS_CHECK(&pcep_g->dbg, PCEP_DEBUG_MODE_PATH))
			vty_out(vty, "  Pathd pcep %s debugging is on\n",
				PCEP_VTYSH_ARG_PATH);
		if (DEBUG_FLAGS_CHECK(&pcep_g->dbg, PCEP_DEBUG_MODE_PCEP))
			vty_out(vty, "  Pathd pcep %s debugging is on\n",
				PCEP_VTYSH_ARG_MESSAGE);
		if (DEBUG_FLAGS_CHECK(&pcep_g->dbg, PCEP_DEBUG_MODE_PCEPLIB))
			vty_out(vty, "  Pathd pcep %s debugging is on\n",
				PCEP_VTYSH_ARG_PCEPLIB);
	}

	return CMD_SUCCESS;
}

DEFPY(pcep_cli_debug,
      pcep_cli_debug_cmd,
      "[no] debug pathd pcep [<basic|path|message|pceplib>$debug_type]",
      NO_STR DEBUG_STR
      "pathd debugging\n"
      "pcep module debugging\n"
      "module basic debugging\n"
      "path structures debugging\n"
      "pcep message debugging\n"
      "pceplib debugging\n")
{
	return path_pcep_cli_debug(vty, debug_type, !no);
}

DEFPY(pcep_cli_show_srte_pcep_counters,
      pcep_cli_show_srte_pcep_counters_cmd,
      "show sr-te pcep counters",
      SHOW_STR
      "SR-TE info\n"
      "PCEP info\n"
      "PCEP counters\n")
{
	return path_pcep_cli_show_srte_pcep_counters(vty);
}

DEFPY_NOSH(
      pcep_cli_pcep,
      pcep_cli_pcep_cmd,
      "pcep",
      "PCEP configuration\n")
{
	vty->node = PCEP_NODE;
	return CMD_SUCCESS;
}

DEFPY(
      pcep_cli_no_pcep,
      pcep_cli_no_pcep_cmd,
      "no pcep",
      NO_STR
      "PCEP configuration\n")
{
	/* Delete PCCs */
	path_pcep_cli_pcc_delete(vty);

	for (int i = 0; i < MAX_PCE; i++) {
		/* Delete PCEs */
		if (pcep_g->pce_opts_cli[i] != NULL) {
			XFREE(MTYPE_PCEP, pcep_g->pce_opts_cli[i]);
			pcep_g->pce_opts_cli[i] = NULL;
			pcep_g->num_pce_opts_cli--;
		}

		/* Delete PCE-CONFIGs */
		if (pcep_g->config_group_opts[i] != NULL) {
			XFREE(MTYPE_PCEP, pcep_g->config_group_opts[i]);
			pcep_g->config_group_opts[i] = NULL;
			pcep_g->num_config_group_opts--;
		}
	}

	return CMD_SUCCESS;
}

DEFPY_NOSH(
      pcep_cli_pcep_pce_config,
      pcep_cli_pcep_pce_config_cmd,
      "pce-config WORD$name",
      "Shared configuration\n"
      "Shared configuration name\n")
{
	return path_pcep_cli_pcep_pce_config(vty, name);
}

DEFPY(pcep_cli_pcep_no_pce_config,
      pcep_cli_pcep_no_pce_config_cmd,
      "no pce-config WORD$name",
      NO_STR
      "Shared configuration\n"
      "Shared configuration name\n")
{
	return path_pcep_cli_pcep_pce_config_delete(vty, name);
}

DEFPY(pcep_cli_show_srte_pcep_pce_config,
      pcep_cli_show_srte_pcep_pce_config_cmd,
      "show sr-te pcep pce-config [<default|WORD>$name]",
      SHOW_STR
      "SR-TE info\n"
      "PCEP info\n"
      "Show shared PCE configuration\n"
      "Show default hard-coded values\n"
      "Shared configuration name\n")
{
	return path_pcep_cli_show_srte_pcep_pce_config(vty, name);
}

DEFPY_NOSH(
      pcep_cli_pce,
      pcep_cli_pce_cmd,
      "pce WORD$name",
      "PCE configuration, address sub-config is mandatory\n"
      "PCE name\n")
{
	return path_pcep_cli_pce(vty, name);
}

DEFPY(pcep_cli_no_pce,
      pcep_cli_no_pce_cmd,
      "no pce WORD$name",
      NO_STR
      "PCE configuration, address sub-config is mandatory\n"
      "PCE name\n")
{
	return path_pcep_cli_pce_delete(vty, name);
}

DEFPY(pcep_cli_show_srte_pcep_pce,
      pcep_cli_show_srte_pcep_pce_cmd,
      "show sr-te pcep pce [WORD$name]",
      SHOW_STR
      "SR-TE info\n"
      "PCEP info\n"
      "Show detailed pce values\n"
      "pce name\n")
{
	return path_pcep_cli_show_srte_pcep_pce(vty, name);
}

DEFPY(pcep_cli_peer_sr_draft07,
      pcep_cli_peer_sr_draft07_cmd,
      "[no] sr-draft07",
      NO_STR
      "Configure PCC to send PCEP Open with SR draft07\n")
{
	return path_pcep_cli_peer_sr_draft07(vty, no);
}

DEFPY(pcep_cli_peer_pce_initiated,
      pcep_cli_peer_pce_initiated_cmd,
      "[no] pce-initiated",
      NO_STR
      "Configure PCC to accept PCE initiated LSPs\n")
{
	return path_pcep_cli_peer_pce_initiated(vty, no);
}

DEFPY(pcep_cli_peer_tcp_md5_auth,
      pcep_cli_peer_tcp_md5_auth_cmd,
      "[no] tcp-md5-auth WORD",
      NO_STR
      "Configure PCC TCP-MD5 RFC2385 Authentication\n"
      "TCP-MD5 Authentication string\n")
{
	return path_pcep_cli_peer_tcp_md5_auth(vty, tcp_md5_auth, no);
}

DEFPY(pcep_cli_peer_address,
      pcep_cli_peer_address_cmd,
      "address <ip A.B.C.D | ipv6 X:X::X:X> [port (1024-65535)]",
      "PCE IP Address configuration, mandatory configuration\n"
      "PCE IPv4 address\n"
      "Remote PCE server IPv4 address\n"
      "PCE IPv6 address\n"
      "Remote PCE server IPv6 address\n"
      "Remote PCE server port\n"
      "Remote PCE server port value\n")
{
	return path_pcep_cli_peer_address(vty, ip_str, &ip, ipv6_str, &ipv6,
					  port_str, port);
}

DEFPY(pcep_cli_peer_source_address,
      pcep_cli_peer_source_address_cmd,
      "[no] source-address [ip A.B.C.D | ipv6 X:X::X:X] [port (1024-65535)]",
      NO_STR
      "PCE source IP Address configuration\n"
      "PCE source IPv4 address\n"
      "PCE source IPv4 address value\n"
      "PCE source IPv6 address\n"
      "PCE source IPv6 address value\n"
      "Source PCE server port\n"
      "Source PCE server port value\n")
{
	return path_pcep_cli_peer_source_address(vty, ip_str, &ip, ipv6_str,
						 &ipv6, port_str, port, no);
}

DEFPY(pcep_cli_peer_pcep_pce_config_ref,
      pcep_cli_peer_pcep_pce_config_ref_cmd,
      "config WORD$name",
      "PCE shared configuration to use\n"
      "Shared configuration name\n")
{
	return path_pcep_cli_peer_pcep_pce_config_ref(vty, name);
}

DEFPY(pcep_cli_peer_timers,
      pcep_cli_peer_timers_cmd,
      "timer [keep-alive (1-63)] [min-peer-keep-alive (1-255)] [max-peer-keep-alive (1-255)] "
      "[dead-timer (4-255)] [min-peer-dead-timer (4-255)] [max-peer-dead-timer (4-255)] "
      "[pcep-request (1-120)] [session-timeout-interval (1-120)] [delegation-timeout (1-60)]",
      "PCE PCEP Session Timers configuration\n"
      "PCC Keep Alive Timer\n"
      "PCC Keep Alive Timer value in seconds\n"
      "Min Acceptable PCE Keep Alive Timer\n"
      "Min Acceptable PCE Keep Alive Timer value in seconds\n"
      "Max Acceptable PCE Keep Alive Timer\n"
      "Max Acceptable PCE Keep Alive Timer value in seconds\n"
      "PCC Dead Timer\n"
      "PCC Dead Timer value in seconds\n"
      "Min Acceptable PCE Dead Timer\n"
      "Min Acceptable PCE Dead Timer value in seconds\n"
      "Max Acceptable PCE Dead Timer\n"
      "Max Acceptable PCE Dead Timer value in seconds\n"
      "PCC PCEP Request Timer\n"
      "PCC PCEP Request Timer value in seconds\n"
      "PCC Session Timeout Interval\n"
      "PCC Session Timeout Interval value in seconds\n"
      "Multi-PCE delegation timeout\n"
      "Multi-PCE delegation timeout value in seconds\n")
{
	return path_pcep_cli_peer_timers(
		vty, keep_alive_str, keep_alive, min_peer_keep_alive_str,
		min_peer_keep_alive, max_peer_keep_alive_str,
		max_peer_keep_alive, dead_timer_str, dead_timer,
		min_peer_dead_timer_str, min_peer_dead_timer,
		max_peer_dead_timer_str, max_peer_dead_timer, pcep_request_str,
		pcep_request, session_timeout_interval_str,
		session_timeout_interval, delegation_timeout_str,
		delegation_timeout);
}

DEFPY_NOSH(
      pcep_cli_pcc,
      pcep_cli_pcc_cmd,
      "pcc",
      "PCC configuration\n")
{
	return path_pcep_cli_pcc(vty);
}

DEFPY(pcep_cli_no_pcc,
      pcep_cli_no_pcc_cmd,
      "no pcc",
      NO_STR
      "PCC configuration\n")
{
	return path_pcep_cli_pcc_delete(vty);
}

DEFPY(pcep_cli_pcc_pcc_msd,
      pcep_cli_pcc_pcc_msd_cmd,
      "msd (1-32)",
      "PCC maximum SID depth \n"
      "PCC maximum SID depth value\n")
{
	return path_pcep_cli_pcc_pcc_msd(vty, msd_str, msd, false);
}

DEFPY(no_pcep_cli_pcc_pcc_msd,
      no_pcep_cli_pcc_pcc_msd_cmd,
      "no msd [(1-32)]",
      NO_STR
      "PCC maximum SID depth \n"
      "PCC maximum SID depth value\n")
{
	return path_pcep_cli_pcc_pcc_msd(vty, msd_str, msd, true);
}

DEFPY(pcep_cli_pcc_pcc_peer,
      pcep_cli_pcc_pcc_peer_cmd,
      "[no] peer WORD [precedence (1-255)]",
      NO_STR
      "PCC PCE peer\n"
      "PCC PCE name\n"
      "PCC Multi-PCE precedence\n"
      "PCE precedence\n")
{
	if (no != NULL) {
		return path_pcep_cli_pcc_pcc_peer_delete(
			vty, peer, precedence_str, precedence);
	} else {
		return path_pcep_cli_pcc_pcc_peer(vty, peer, precedence_str,
						  precedence);
	}
}

DEFPY(pcep_cli_show_srte_pcc,
      pcep_cli_show_srte_pcc_cmd,
      "show sr-te pcep pcc",
      SHOW_STR
      "SR-TE info\n"
      "PCEP info\n"
      "Show current PCC configuration\n")
{
	return path_pcep_cli_show_srte_pcep_pcc(vty);
}

DEFPY(pcep_cli_show_srte_pcep_session,
      pcep_cli_show_srte_pcep_session_cmd,
      "show sr-te pcep session WORD$pce [json$uj]",
      SHOW_STR
      "SR-TE info\n"
      "PCEP info\n"
      "Show PCEP Session information\n"
      "PCE name\n"
      JSON_STR)
{
	return path_pcep_cli_show_srte_pcep_session(vty, pce, !!uj);
}

DEFPY(pcep_cli_show_srte_pcep_sessions,
      pcep_cli_show_srte_pcep_sessions_cmd,
      "show sr-te pcep session [json$uj]",
      SHOW_STR
      "SR-TE info\n"
      "PCEP info\n"
      "Show PCEP Session information\n"
      JSON_STR)
{
	return path_pcep_cli_show_srte_pcep_session(vty, NULL, !!uj);
}

DEFPY(pcep_cli_clear_srte_pcep_session,
      pcep_cli_clear_srte_pcep_session_cmd,
      "clear sr-te pcep session [WORD]$pce",
      CLEAR_STR
      "SR-TE\n"
      "PCEP\n"
      "Reset PCEP connection\n"
      "PCE name\n")
{
	return path_pcep_cli_clear_srte_pcep_session(vty, pce);
}

void pcep_cli_init(void)
{
	hook_register(pathd_srte_config_write, pcep_cli_pcep_config_write);
	hook_register(nb_client_debug_config_write,
		      pcep_cli_debug_config_write);
	hook_register(nb_client_debug_set_all, pcep_cli_debug_set_all);

	memset(&pce_connections_g, 0, sizeof(pce_connections_g));

	install_node(&pcep_node);
	install_node(&pcep_pcc_node);
	install_node(&pcep_pce_node);
	install_node(&pcep_pce_config_node);

	install_default(PCEP_PCE_CONFIG_NODE);
	install_default(PCEP_PCE_NODE);
	install_default(PCEP_PCC_NODE);
	install_default(PCEP_NODE);

	install_element(SR_TRAFFIC_ENG_NODE, &pcep_cli_pcep_cmd);
	install_element(SR_TRAFFIC_ENG_NODE, &pcep_cli_no_pcep_cmd);

	/* PCEP configuration group related configuration commands */
	install_element(PCEP_NODE, &pcep_cli_pcep_pce_config_cmd);
	install_element(PCEP_NODE, &pcep_cli_pcep_no_pce_config_cmd);
	install_element(PCEP_PCE_CONFIG_NODE,
			&pcep_cli_peer_source_address_cmd);
	install_element(PCEP_PCE_CONFIG_NODE, &pcep_cli_peer_timers_cmd);
	install_element(PCEP_PCE_CONFIG_NODE, &pcep_cli_peer_sr_draft07_cmd);
	install_element(PCEP_PCE_CONFIG_NODE, &pcep_cli_peer_pce_initiated_cmd);
	install_element(PCEP_PCE_CONFIG_NODE, &pcep_cli_peer_tcp_md5_auth_cmd);

	/* PCE peer related configuration commands */
	install_element(PCEP_NODE, &pcep_cli_pce_cmd);
	install_element(PCEP_NODE, &pcep_cli_no_pce_cmd);
	install_element(PCEP_PCE_NODE, &pcep_cli_peer_address_cmd);
	install_element(PCEP_PCE_NODE, &pcep_cli_peer_source_address_cmd);
	install_element(PCEP_PCE_NODE, &pcep_cli_peer_pcep_pce_config_ref_cmd);
	install_element(PCEP_PCE_NODE, &pcep_cli_peer_timers_cmd);
	install_element(PCEP_PCE_NODE, &pcep_cli_peer_sr_draft07_cmd);
	install_element(PCEP_PCE_NODE, &pcep_cli_peer_pce_initiated_cmd);
	install_element(PCEP_PCE_NODE, &pcep_cli_peer_tcp_md5_auth_cmd);

	/* PCC related configuration commands */
	install_element(ENABLE_NODE, &pcep_cli_show_srte_pcc_cmd);
	install_element(PCEP_NODE, &pcep_cli_pcc_cmd);
	install_element(PCEP_NODE, &pcep_cli_no_pcc_cmd);
	install_element(PCEP_PCC_NODE, &pcep_cli_pcc_pcc_peer_cmd);
	install_element(PCEP_PCC_NODE, &pcep_cli_pcc_pcc_msd_cmd);
	install_element(PCEP_PCC_NODE, &no_pcep_cli_pcc_pcc_msd_cmd);

	/* Top commands */
	install_element(CONFIG_NODE, &pcep_cli_debug_cmd);
	install_element(ENABLE_NODE, &pcep_cli_debug_cmd);
	install_element(ENABLE_NODE, &show_debugging_pathd_pcep_cmd);
	install_element(ENABLE_NODE, &pcep_cli_show_srte_pcep_counters_cmd);
	install_element(ENABLE_NODE, &pcep_cli_show_srte_pcep_pce_config_cmd);
	install_element(ENABLE_NODE, &pcep_cli_show_srte_pcep_pce_cmd);
	install_element(ENABLE_NODE, &pcep_cli_show_srte_pcep_session_cmd);
	install_element(ENABLE_NODE, &pcep_cli_show_srte_pcep_sessions_cmd);
	install_element(ENABLE_NODE, &pcep_cli_clear_srte_pcep_session_cmd);
}
