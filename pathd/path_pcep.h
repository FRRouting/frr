// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright (C) 2020  NetDEF, Inc.
 */

#ifndef _PATH_PCEP_H_
#define _PATH_PCEP_H_

#include <stdbool.h>
#include <debug.h>
#include <netinet/tcp.h>
#include "memory.h"
#include "pceplib/pcep_utils_logging.h"
#include "pceplib/pcep_pcc_api.h"
#include "mpls.h"
#include "pathd/pathd.h"

DECLARE_MTYPE(PCEP);

#define PCEP_DEFAULT_PORT 4189
#define MAX_PCC 32
#define MAX_PCE 32
#define MAX_TAG_SIZE 50
#define PCEP_DEBUG_MODE_BASIC 0x01
#define PCEP_DEBUG_MODE_PATH 0x02
#define PCEP_DEBUG_MODE_PCEP 0x04
#define PCEP_DEBUG_MODE_PCEPLIB 0x08
#define PCEP_DEBUG_MODE_ALL 0x0F
#define PCEP_DEBUG(fmt, ...)                                                   \
	do {                                                                   \
		if (DEBUG_FLAGS_CHECK(&pcep_g->dbg, PCEP_DEBUG_MODE_BASIC))    \
			DEBUGD(&pcep_g->dbg, "pcep: " fmt, ##__VA_ARGS__);     \
	} while (0)
#define PCEP_DEBUG_PATH(fmt, ...)                                              \
	do {                                                                   \
		if (DEBUG_FLAGS_CHECK(&pcep_g->dbg, PCEP_DEBUG_MODE_PATH))     \
			DEBUGD(&pcep_g->dbg, "pcep: " fmt, ##__VA_ARGS__);     \
	} while (0)
#define PCEP_DEBUG_PCEP(fmt, ...)                                              \
	do {                                                                   \
		if (DEBUG_FLAGS_CHECK(&pcep_g->dbg, PCEP_DEBUG_MODE_PCEP))     \
			DEBUGD(&pcep_g->dbg, "pcep: " fmt, ##__VA_ARGS__);     \
	} while (0)
#define PCEP_DEBUG_PCEPLIB(priority, fmt, ...)                                 \
	do {                                                                   \
		switch (priority) {                                            \
		case LOG_DEBUG:                                                \
			if (DEBUG_FLAGS_CHECK(&pcep_g->dbg,                    \
					      PCEP_DEBUG_MODE_PCEPLIB))        \
				DEBUGD(&pcep_g->dbg, "pcep: " fmt,             \
				       ##__VA_ARGS__);                         \
			break;                                                 \
		case LOG_INFO:                                                 \
			if (DEBUG_FLAGS_CHECK(&pcep_g->dbg,                    \
					      PCEP_DEBUG_MODE_PCEPLIB))        \
				DEBUGI(&pcep_g->dbg, "pcep: " fmt,             \
				       ##__VA_ARGS__);                         \
			break;                                                 \
		case LOG_NOTICE:                                               \
			if (DEBUG_FLAGS_CHECK(&pcep_g->dbg,                    \
					      PCEP_DEBUG_MODE_PCEPLIB))        \
				DEBUGN(&pcep_g->dbg, "pcep: " fmt,             \
				       ##__VA_ARGS__);                         \
			break;                                                 \
		case LOG_WARNING:                                              \
		case LOG_ERR:                                                  \
		default:                                                       \
			zlog(priority, "pcep: " fmt, ##__VA_ARGS__);           \
			break;                                                 \
		}                                                              \
	} while (0)

struct pcep_config_group_opts {
	char name[64];
	char tcp_md5_auth[PCEP_MD5SIG_MAXKEYLEN];
	struct ipaddr source_ip;
	short source_port;
	bool draft07;
	bool pce_initiated;
	int keep_alive_seconds;
	int min_keep_alive_seconds;
	int max_keep_alive_seconds;
	int dead_timer_seconds;
	int min_dead_timer_seconds;
	int max_dead_timer_seconds;
	int pcep_request_time_seconds;
	int session_timeout_inteval_seconds;
	int delegation_timeout_seconds;
};

struct pce_opts {
	struct ipaddr addr;
	short port;
	char pce_name[64];
	struct pcep_config_group_opts config_opts;
	uint8_t precedence; /* Multi-PCE precedence */
};

struct pcc_opts {
	struct ipaddr addr;
	short port;
	short msd;
};

/* Encapsulate the pce_opts with needed CLI information */
struct pce_opts_cli {
	struct pce_opts pce_opts;
	char config_group_name[64];
	/* These are the values configured in the pcc-peer sub-commands.
	 * These need to be stored for later merging. Notice, it could
	 * be that not all of them are set. */
	struct pcep_config_group_opts pce_config_group_opts;
	/* The pce_opts->config_opts will be a merge of the default values,
	 * optional config_group values (which overwrite default values),
	 * and any values configured in the pce sub-commands (which overwrite
	 * both default and config_group values). This flag indicates of the
	 * values need to be merged or not. */
	bool merged;
};

struct lsp_nb_key {
	uint32_t color;
	struct ipaddr endpoint;
	uint32_t preference;
};

struct sid_mpls {
	mpls_label_t label;
	uint8_t traffic_class;
	bool is_bottom;
	uint8_t ttl;
};

struct pcep_caps {
	bool is_stateful;
	/* If we know the objective functions supported by the PCE.
	 * If we don't know, it doesn't mean the PCE doesn't support any */
	bool supported_ofs_are_known;
	/* Defined if we know which objective funtions are supported by the PCE.
	 * One bit per objective function, the bit index being equal to
	 * enum pcep_objfun_type values: bit 0 is not used, bit 1 is
	 * PCEP_OBJFUN_MCP, up to bit 17 that is PCEP_OBJFUN_MSN */
	uint32_t supported_ofs;
};

union sid {
	uint32_t value;
	struct sid_mpls mpls;
};

struct nai {
	/* NAI type */
	enum pcep_sr_subobj_nai type;
	/* Local IP address*/
	struct ipaddr local_addr;
	/* Local interface identifier if the NAI is an unnumbered adjacency */
	uint32_t local_iface;
	/* Remote address if the NAI is an adjacency */
	struct ipaddr remote_addr;
	/* Remote interface identifier if the NAI is an unnumbered adjacency */
	uint32_t remote_iface;
};

struct path_hop {
	/* Pointer to the next hop in the path */
	struct path_hop *next;
	/* Indicateif this ia a loose or strict hop */
	bool is_loose;
	/* Indicate if there is an SID for the hop */
	bool has_sid;
	/* Indicate if the hop as a MPLS label */
	bool is_mpls;
	/* Indicate if the MPLS label has extra attributes (TTL, class..)*/
	bool has_attribs;
	/* Hop's SID if available */
	union sid sid;
	/* Indicate if there is a NAI for this hop */
	bool has_nai;
	/* NAI if available */
	struct nai nai;
};

struct path_metric {
	/* Pointer to the next metric */
	struct path_metric *next;
	/* The metric type */
	enum pcep_metric_types type;
	/* If the metric should be enforced */
	bool enforce;
	/* If the metric value is bound (a maximum) */
	bool is_bound;
	/* If the metric value is computed */
	bool is_computed;
	/* The metric value */
	float value;
};

struct path {
	/* Both the nbkey and the plspid are keys comming from the PCC,
	but the PCE is only using the plspid. The missing key is looked up by
	the PCC so we always have both */

	/* The northbound key identifying this path */
	struct lsp_nb_key nbkey;
	/* The generated unique PLSP identifier for this path.
	   See draft-ietf-pce-stateful-pce */
	uint32_t plsp_id;

	/* The transport address the path is comming from, PCE or PCC*/
	struct ipaddr sender;
	/* The pcc protocol address, must be the same family as the endpoint */
	struct ipaddr pcc_addr;

	/* The identifier of the PCC the path is for/from. If 0 it is undefined,
	meaning it hasn't be set yet or is for all the PCC */
	int pcc_id;

	/* The origin of the path creation */
	enum srte_protocol_origin create_origin;
	/* The origin of the path modification */
	enum srte_protocol_origin update_origin;
	/* The identifier of the entity that originated the path */
	const char *originator;
	/* The type of the path, for PCE initiated or updated path it is always
	SRTE_CANDIDATE_TYPE_DYNAMIC */
	enum srte_candidate_type type;

	/* The following data comes from either the PCC or the PCE if available
	 */

	/* Path's binding SID */
	mpls_label_t binding_sid;
	/* The name of the path */
	const char *name;
	/* The request identifier from the PCE, when getting a path from the
	   PCE. See draft-ietf-pce-stateful-pce */
	uint32_t srp_id;
	/* The request identifier from the PCC , when getting a path from the
	   PCE after a computation request. See rfc5440, section-7.4 */
	uint32_t req_id;
	/* The operational status of the path */
	enum pcep_lsp_operational_status status;
	/* If true, the receiver (PCC) must remove the path.
	   See draft-ietf-pce-pce-initiated-lsp */
	bool do_remove;
	/* Indicate the given path was removed by the PCC.
	   See draft-ietf-pce-stateful-pce, section-7.3, flag R */
	bool was_removed;
	/* Indicate the path is part of the synchronization process.
	   See draft-ietf-pce-stateful-pce, section-7.3, flag S */
	bool is_synching;
	/* Indicate if the path bandwidth requirment is defined */
	bool has_bandwidth;
	/* Indicate if the bandwidth requirment should be enforced */
	bool enforce_bandwidth;
	/* Path required bandwidth if defined */
	float bandwidth;
	/* Specify the list of hop defining the path */
	struct path_hop *first_hop;
	/* Specify the list of metrics */
	struct path_metric *first_metric;
	/* Indicate if the path has a PCC-defined objective function */
	bool has_pcc_objfun;
	/* Indicate the PCC-defined objective function is required */
	bool enforce_pcc_objfun;
	/* PCC-defined Objective Function */
	enum objfun_type pcc_objfun;
	/* Indicate if the path has a PCE-defined objective function */
	bool has_pce_objfun;
	/* PCE-defined Objective Function */
	enum objfun_type pce_objfun;
	/* Indicate if some affinity filters are defined */
	bool has_affinity_filters;
	/* Affinity attribute filters indexed by enum affinity_filter_type - 1
	 */
	uint32_t affinity_filters[MAX_AFFINITY_FILTER_TYPE];

	/* The following data need to be specialized for a given PCE */

	/* Indicate the path is delegated to the PCE.
	   See draft-ietf-pce-stateful-pce, section-7.3, flag D */
	bool is_delegated;
	/* Indicate if the PCE wants the path to get active.
	   See draft-ietf-pce-stateful-pce, section-7.3, flag A */
	bool go_active;
	/* Indicate the given path was created by the PCE,
	   See draft-ietf-pce-pce-initiated-lsp, section-5.3.1, flag C */
	bool was_created;

	/* The following data is defined for comnputation replies */

	/* Indicate that no path could be computed */
	bool no_path;
};

struct pcep_glob {
	struct debug dbg;
	struct event_loop *master;
	struct frr_pthread *fpt;
	uint8_t num_pce_opts_cli;
	struct pce_opts_cli *pce_opts_cli[MAX_PCE];
	uint8_t num_config_group_opts;
	struct pcep_config_group_opts *config_group_opts[MAX_PCE];
};

extern struct pcep_glob *pcep_g;

struct pcep_error {
	struct path *path;
	int error_type;
	int error_value;
	/* Rfc 8281 PcInitiated error on bad values */
#define ERROR_19_1 1
#define ERROR_19_3 2
#define ERROR_19_9 3
};

/* Path Helper Functions */
struct path *pcep_new_path(void);
struct path_hop *pcep_new_hop(void);
struct path_metric *pcep_new_metric(void);
struct path *pcep_copy_path(struct path *path);
void pcep_free_path(struct path *path);


#endif // _PATH_PCEP_H_
