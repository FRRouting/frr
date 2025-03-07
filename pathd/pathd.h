// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright (C) 2020  NetDEF, Inc.
 */

#ifndef _FRR_PATHD_H_
#define _FRR_PATHD_H_

#include "lib/memory.h"
#include "lib/mpls.h"
#include "lib/ipaddr.h"
#include "lib/srte.h"
#include "lib/hook.h"
#include "lib/prefix.h"

#define PATH_SID_ERROR 1
#define PATH_SID_NO_ERROR 0
#define CHECK_SID(or, ts, es)                                                  \
	((or == SRTE_ORIGIN_PCEP && (ts == MPLS_LABEL_NONE || es != ts))       \
	 || (or == SRTE_ORIGIN_LOCAL && ts == MPLS_LABEL_NONE))

DECLARE_MGROUP(PATHD);

DECLARE_HOOK(pathd_srte_config_write, (struct vty *vty), (vty));

enum srte_protocol_origin {
	SRTE_ORIGIN_UNDEFINED = 0,
	SRTE_ORIGIN_PCEP = 1,
	SRTE_ORIGIN_BGP = 2,
	SRTE_ORIGIN_LOCAL = 3,
};

extern struct debug path_policy_debug;

enum srte_policy_status {
	SRTE_POLICY_STATUS_UNKNOWN = 0,
	SRTE_POLICY_STATUS_DOWN = 1,
	SRTE_POLICY_STATUS_UP = 2,
	SRTE_POLICY_STATUS_GOING_DOWN = 3,
	SRTE_POLICY_STATUS_GOING_UP = 4
};

enum srte_candidate_type {
	SRTE_CANDIDATE_TYPE_UNDEFINED = 0,
	SRTE_CANDIDATE_TYPE_EXPLICIT = 1,
	SRTE_CANDIDATE_TYPE_DYNAMIC = 2,
};

enum srte_candidate_metric_type {
	/* IGP metric */
	SRTE_CANDIDATE_METRIC_TYPE_IGP = 1,
	/* TE metric */
	SRTE_CANDIDATE_METRIC_TYPE_TE = 2,
	/* Hop Counts */
	SRTE_CANDIDATE_METRIC_TYPE_HC = 3,
	/* Aggregate bandwidth consumption */
	SRTE_CANDIDATE_METRIC_TYPE_ABC = 4,
	/* Load of the most loaded link */
	SRTE_CANDIDATE_METRIC_TYPE_LMLL = 5,
	/* Cumulative IGP cost */
	SRTE_CANDIDATE_METRIC_TYPE_CIGP = 6,
	/* Cumulative TE cost */
	SRTE_CANDIDATE_METRIC_TYPE_CTE = 7,
	/* P2MP IGP metric */
	SRTE_CANDIDATE_METRIC_TYPE_PIGP = 8,
	/* P2MP TE metric */
	SRTE_CANDIDATE_METRIC_TYPE_PTE = 9,
	/* P2MP hop count metric */
	SRTE_CANDIDATE_METRIC_TYPE_PHC = 10,
	/* Segment-ID (SID) Depth */
	SRTE_CANDIDATE_METRIC_TYPE_MSD = 11,
	/* Path Delay metric */
	SRTE_CANDIDATE_METRIC_TYPE_PD = 12,
	/* Path Delay Variation metric */
	SRTE_CANDIDATE_METRIC_TYPE_PDV = 13,
	/* Path Loss metric */
	SRTE_CANDIDATE_METRIC_TYPE_PL = 14,
	/* P2MP Path Delay metric */
	SRTE_CANDIDATE_METRIC_TYPE_PPD = 15,
	/* P2MP Path Delay variation metric */
	SRTE_CANDIDATE_METRIC_TYPE_PPDV = 16,
	/* P2MP Path Loss metric */
	SRTE_CANDIDATE_METRIC_TYPE_PPL = 17,
	/* Number of adaptations on a path */
	SRTE_CANDIDATE_METRIC_TYPE_NAP = 18,
	/* Number of layers on a path */
	SRTE_CANDIDATE_METRIC_TYPE_NLP = 19,
	/* Domain Count metric */
	SRTE_CANDIDATE_METRIC_TYPE_DC = 20,
	/* Border Node Count metric */
	SRTE_CANDIDATE_METRIC_TYPE_BNC = 21,
};
#define MAX_METRIC_TYPE 21

enum srte_segment_nai_type {
	SRTE_SEGMENT_NAI_TYPE_NONE = 0,
	SRTE_SEGMENT_NAI_TYPE_IPV4_NODE = 1,
	SRTE_SEGMENT_NAI_TYPE_IPV6_NODE = 2,
	SRTE_SEGMENT_NAI_TYPE_IPV4_ADJACENCY = 3,
	SRTE_SEGMENT_NAI_TYPE_IPV6_ADJACENCY = 4,
	SRTE_SEGMENT_NAI_TYPE_IPV4_UNNUMBERED_ADJACENCY = 5,
	SRTE_SEGMENT_NAI_TYPE_IPV6_ADJACENCY_LINK_LOCAL_ADDRESSES = 6,
	SRTE_SEGMENT_NAI_TYPE_IPV4_LOCAL_IFACE = 7,
	SRTE_SEGMENT_NAI_TYPE_IPV6_LOCAL_IFACE = 8,
	SRTE_SEGMENT_NAI_TYPE_IPV4_ALGORITHM = 9,
	SRTE_SEGMENT_NAI_TYPE_IPV6_ALGORITHM = 10
};

enum objfun_type {
	OBJFUN_UNDEFINED = 0,
	/* Minimum Cost Path [RFC5541] */
	OBJFUN_MCP = 1,
	/* Minimum Load Path [RFC5541] */
	OBJFUN_MLP = 2,
	/* Maximum residual Bandwidth Path [RFC5541] */
	OBJFUN_MBP = 3,
	/* Minimize aggregate Bandwidth Consumption [RFC5541] */
	OBJFUN_MBC = 4,
	/* Minimize the Load of the most loaded Link [RFC5541] */
	OBJFUN_MLL = 5,
	/* Minimize the Cumulative Cost of a set of paths [RFC5541] */
	OBJFUN_MCC = 6,
	/* Shortest Path Tree [RFC8306] */
	OBJFUN_SPT = 7,
	/* Minimum Cost Tree [RFC8306] */
	OBJFUN_MCT = 8,
	/* Minimum Packet Loss Path [RFC8233] */
	OBJFUN_MPLP = 9,
	/* Maximum Under-Utilized Path [RFC8233] */
	OBJFUN_MUP = 10,
	/* Maximum Reserved Under-Utilized Path [RFC8233] */
	OBJFUN_MRUP = 11,
	/* Minimize the number of Transit Domains [RFC8685] */
	OBJFUN_MTD = 12,
	/* Minimize the number of Border Nodes [RFC8685] */
	OBJFUN_MBN = 13,
	/* Minimize the number of Common Transit Domains [RFC8685] */
	OBJFUN_MCTD = 14,
	/* Minimize the number of Shared Links [RFC8800] */
	OBJFUN_MSL = 15,
	/* Minimize the number of Shared SRLGs [RFC8800] */
	OBJFUN_MSS = 16,
	/* Minimize the number of Shared Nodes [RFC8800] */
	OBJFUN_MSN = 17,
};
#define MAX_OBJFUN_TYPE 17

enum affinity_filter_type {
	AFFINITY_FILTER_UNDEFINED = 0,
	AFFINITY_FILTER_EXCLUDE_ANY = 1,
	AFFINITY_FILTER_INCLUDE_ANY = 2,
	AFFINITY_FILTER_INCLUDE_ALL = 3,
};
#define MAX_AFFINITY_FILTER_TYPE 3

struct srte_segment_list;

struct srte_segment_entry {
	RB_ENTRY(srte_segment_entry) entry;

	/* The segment list the entry belong to */
	struct srte_segment_list *segment_list;

	/* Index of the Label. */
	uint32_t index;

	/* Label Value. */
	mpls_label_t sid_value;

	/* NAI Type */
	enum srte_segment_nai_type nai_type;
	/* NAI local address when nai type is not NONE */
	struct ipaddr nai_local_addr;
	/* NAI local interface when nai type is not IPv4 unnumbered adjacency */
	uint32_t nai_local_iface;
	/* NAI local interface when nai type is IPv4 or IPv6 adjacency */
	struct ipaddr nai_remote_addr;
	/* NAI remote interface when nai type is not IPv4 unnumbered adjacency
	 */
	uint32_t nai_remote_iface;
	/* Support draft-ietf-spring-segment-routing-policy sl types queries*/
	uint8_t nai_local_prefix_len;
	uint8_t nai_algorithm;
};
RB_HEAD(srte_segment_entry_head, srte_segment_entry);
RB_PROTOTYPE(srte_segment_entry_head, srte_segment_entry, entry,
	     srte_segment_entry_compare)

struct srte_segment_list {
	RB_ENTRY(srte_segment_list) entry;

	/* Name of the Segment List. */
	char name[64];

	/* The Protocol-Origin. */
	enum srte_protocol_origin protocol_origin;

	/* The Originator */
	char originator[64];

	/* Nexthops. */
	struct srte_segment_entry_head segments;

	/* Status flags. */
	uint16_t flags;
#define F_SEGMENT_LIST_NEW 0x0002
#define F_SEGMENT_LIST_MODIFIED 0x0004
#define F_SEGMENT_LIST_DELETED 0x0008
#define F_SEGMENT_LIST_SID_CONFLICT 0x0010
};
RB_HEAD(srte_segment_list_head, srte_segment_list);
RB_PROTOTYPE(srte_segment_list_head, srte_segment_list, entry,
	     srte_segment_list_compare)

struct srte_metric {
	uint16_t flags;
#define F_METRIC_IS_DEFINED 0x0001
#define F_METRIC_IS_REQUIRED 0x0002
#define F_METRIC_IS_BOUND 0x0004
#define F_METRIC_IS_COMPUTED 0x0008
	float value;
};

/* Runtime information about the candidate path */
struct srte_lsp {
	/* Backpointer to the Candidate Path. */
	struct srte_candidate *candidate;

	/* The associated Segment List. */
	struct srte_segment_list *segment_list;

	/* The Protocol-Origin. */
	enum srte_protocol_origin protocol_origin;

	/* The Originator */
	char originator[64];

	/* The Discriminator */
	uint32_t discriminator;

	/* Flags. */
	uint32_t flags;

	/* Metrics LSP Values */
	struct srte_metric metrics[MAX_METRIC_TYPE];

	/* Bandwidth Configured Value */
	float bandwidth;

	/* The objective function in used */
	enum objfun_type objfun;
};

/* Configured candidate path */
struct srte_candidate {
	RB_ENTRY(srte_candidate) entry;

	/* Backpointer to SR Policy */
	struct srte_policy *policy;

	/* The LSP associated with this candidate path. */
	struct srte_lsp *lsp;

	/* Administrative preference. */
	uint32_t preference;

	/* Symbolic Name. */
	char name[64];

	/* The associated Segment List. */
	struct srte_segment_list *segment_list;

	/* The Protocol-Origin. */
	enum srte_protocol_origin protocol_origin;

	/* The Originator */
	char originator[64];

	/* The Discriminator */
	uint32_t discriminator;

	/* The Type (explicit or dynamic) */
	enum srte_candidate_type type;

	/* Flags. */
	uint32_t flags;
#define F_CANDIDATE_BEST 0x0001
#define F_CANDIDATE_NEW 0x0002
#define F_CANDIDATE_MODIFIED 0x0004
#define F_CANDIDATE_DELETED 0x0008
#define F_CANDIDATE_HAS_BANDWIDTH 0x0100
#define F_CANDIDATE_REQUIRED_BANDWIDTH 0x0200
#define F_CANDIDATE_HAS_OBJFUN 0x0400
#define F_CANDIDATE_REQUIRED_OBJFUN 0x0800
#define F_CANDIDATE_HAS_EXCLUDE_ANY 0x1000
#define F_CANDIDATE_HAS_INCLUDE_ANY 0x2000
#define F_CANDIDATE_HAS_INCLUDE_ALL 0x4000

	/* Metrics Configured Values */
	struct srte_metric metrics[MAX_METRIC_TYPE];

	/* Bandwidth Configured Value */
	float bandwidth;

	/* Configured objective functions */
	enum objfun_type objfun;

	/* Path constraints attribute filters */
	uint32_t affinity_filters[MAX_AFFINITY_FILTER_TYPE];

	/* Hooks delaying timer */
	struct event *hook_timer;
};

RB_HEAD(srte_candidate_head, srte_candidate);
RB_PROTOTYPE(srte_candidate_head, srte_candidate, entry, srte_candidate_compare)

#define ENDPOINT_STR_LENGTH IPADDR_STRING_SIZE

struct srte_policy {
	RB_ENTRY(srte_policy) entry;

	/* Color */
	uint32_t color;

	/* Endpoint */
	struct ipaddr endpoint;

	/* Name */
	char name[64];

	/* Binding SID */
	mpls_label_t binding_sid;

	/* The Protocol-Origin. */
	enum srte_protocol_origin protocol_origin;

	/* The Originator */
	char originator[64];

	/* Operational Status of the policy */
	enum srte_policy_status status;

	/* Best candidate path. */
	struct srte_candidate *best_candidate;

	/* Candidate Paths */
	struct srte_candidate_head candidate_paths;
	/* Status flags. */
	uint16_t flags;
#define F_POLICY_NEW 0x0002
#define F_POLICY_MODIFIED 0x0004
#define F_POLICY_DELETED 0x0008
	/* SRP id for PcInitiated support */
	int srp_id;
};
RB_HEAD(srte_policy_head, srte_policy);
RB_PROTOTYPE(srte_policy_head, srte_policy, entry, srte_policy_compare)

DECLARE_HOOK(pathd_candidate_created, (struct srte_candidate * candidate),
	     (candidate));
DECLARE_HOOK(pathd_candidate_updated, (struct srte_candidate * candidate),
	     (candidate));
DECLARE_HOOK(pathd_candidate_removed, (struct srte_candidate * candidate),
	     (candidate));

extern struct srte_segment_list_head srte_segment_lists;
extern struct srte_policy_head srte_policies;
extern struct zebra_privs_t pathd_privs;

/* master thread, defined in path_main.c */
extern struct event_loop *master;

/* pathd.c */
struct srte_segment_list *srte_segment_list_add(const char *name);
void srte_segment_list_del(struct srte_segment_list *segment_list);
struct srte_segment_list *srte_segment_list_find(const char *name);
struct srte_segment_entry *
srte_segment_entry_add(struct srte_segment_list *segment_list, uint32_t index);
void srte_segment_entry_del(struct srte_segment_entry *segment);
int srte_segment_entry_set_nai(struct srte_segment_entry *segment,
			       enum srte_segment_nai_type type,
			       struct ipaddr *local_ip, uint32_t local_iface,
			       struct ipaddr *remote_ip, uint32_t remote_iface,
			       uint8_t algo, uint8_t pref_len);
void srte_segment_set_local_modification(struct srte_segment_list *s_list,
					 struct srte_segment_entry *s_entry,
					 uint32_t ted_sid);
struct srte_policy *srte_policy_add(uint32_t color, struct ipaddr *endpoint,
				    enum srte_protocol_origin origin,
				    const char *originator);
void srte_policy_del(struct srte_policy *policy);
struct srte_policy *srte_policy_find(uint32_t color, struct ipaddr *endpoint);
int srte_policy_update_ted_sid(void);
void srte_policy_update_binding_sid(struct srte_policy *policy,
				    uint32_t binding_sid);
void srte_apply_changes(void);
void srte_clean_zebra(void);
void srte_policy_apply_changes(struct srte_policy *policy);
struct srte_candidate *srte_candidate_add(struct srte_policy *policy,
					  uint32_t preference,
					  enum srte_protocol_origin origin,
					  const char *originator);
void srte_candidate_del(struct srte_candidate *candidate);
void srte_candidate_set_bandwidth(struct srte_candidate *candidate,
				  float bandwidth, bool required);
void srte_candidate_unset_bandwidth(struct srte_candidate *candidate);
void srte_candidate_set_metric(struct srte_candidate *candidate,
			       enum srte_candidate_metric_type type,
			       float value, bool required, bool is_cound,
			       bool is_computed);
void srte_candidate_unset_metric(struct srte_candidate *candidate,
				 enum srte_candidate_metric_type type);
void srte_candidate_set_objfun(struct srte_candidate *candidate, bool required,
			       enum objfun_type type);
void srte_candidate_unset_objfun(struct srte_candidate *candidate);
void srte_candidate_set_affinity_filter(struct srte_candidate *candidate,
					enum affinity_filter_type type,
					uint32_t filter);
void srte_candidate_unset_affinity_filter(struct srte_candidate *candidate,
					  enum affinity_filter_type type);
void srte_lsp_set_bandwidth(struct srte_lsp *lsp, float bandwidth,
			    bool required);
void srte_lsp_unset_bandwidth(struct srte_lsp *lsp);
void srte_lsp_set_metric(struct srte_lsp *lsp,
			 enum srte_candidate_metric_type type, float value,
			 bool required, bool is_cound, bool is_computed);
void srte_lsp_unset_metric(struct srte_lsp *lsp,
			   enum srte_candidate_metric_type type);
struct srte_candidate *srte_candidate_find(struct srte_policy *policy,
					   uint32_t preference);
struct srte_segment_entry *
srte_segment_entry_find(struct srte_segment_list *segment_list, uint32_t index);
void srte_candidate_status_update(struct srte_candidate *candidate, int status);
void srte_candidate_unset_segment_list(const char *originator, bool force);
const char *srte_origin2str(enum srte_protocol_origin origin);
void pathd_shutdown(void);

/* path_cli.c */
void path_cli_init(void);


/**
 * Search for sid based in prefix and algorithm
 *
 * @param Prefix	The prefix to use
 * @param algo		Algorithm we want to query for
 * @param ted_sid	Sid to query
 *
 * @return		void
 */
int32_t srte_ted_do_query_type_c(struct srte_segment_entry *entry,
				 struct prefix *prefix_cli, uint32_t algo);

/**
 * Search for sid based in prefix and interface id
 *
 * @param Prefix	The prefix to use
 * @param local_iface	The id of interface
 * @param ted_sid	Sid to query
 *
 * @return		void
 */
int32_t srte_ted_do_query_type_e(struct srte_segment_entry *entry,
				 struct prefix *prefix_cli,
				 uint32_t local_iface);
/**
 * Search for sid based in local and remote ip
 *
 * @param entry		entry to update
 * @param local		Local addr for query
 * @param remote	Local addr for query
 *
 * @return		void
 */
int32_t srte_ted_do_query_type_f(struct srte_segment_entry *entry,
				 struct ipaddr *local, struct ipaddr *remote);
#endif /* _FRR_PATHD_H_ */
