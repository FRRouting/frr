/*
 * IS-IS Rout(e)ing protocol - isisd.h
 *
 * Copyright (C) 2001,2002   Sampo Saaristo
 *                           Tampere University of Technology
 *                           Institute of Communications Engineering
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public Licenseas published by the Free
 * Software Foundation; either version 2 of the License, or (at your option)
 * any later version.
 *
 * This program is distributed in the hope that it will be useful,but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; see the file COPYING; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA
 */

#ifndef ISISD_H
#define ISISD_H

#include "vty.h"

#include "isisd/isis_constants.h"
#include "isisd/isis_common.h"
#include "isisd/isis_redist.h"
#include "isis_flags.h"
#include "dict.h"
#include "isis_memory.h"
#include "qobj.h"

extern struct zebra_privs_t isisd_privs;

/* uncomment if you are a developer in bug hunt */
/* #define EXTREME_DEBUG  */
/* #define EXTREME_DICT_DEBUG */

struct isis {
	unsigned long process_id;
	int sysid_set;
	uint8_t sysid[ISIS_SYS_ID_LEN]; /* SystemID for this IS */
	uint32_t router_id;		/* Router ID from zebra */
	struct list *area_list;	/* list of IS-IS areas */
	struct list *init_circ_list;
	struct list *nexthops;		  /* IPv4 next hops from this IS */
	struct list *nexthops6;		  /* IPv6 next hops from this IS */
	uint8_t max_area_addrs;		  /* maximumAreaAdresses */
	struct area_addr *man_area_addrs; /* manualAreaAddresses */
	uint32_t debugs;		  /* bitmap for debug */
	time_t uptime;			  /* when did we start */
	struct thread *t_dync_clean;      /* dynamic hostname cache cleanup thread */
	uint32_t circuit_ids_used[8];     /* 256 bits to track circuit ids 1 through 255 */

	struct route_table *ext_info[REDIST_PROTOCOL_COUNT];

	QOBJ_FIELDS
};

extern struct isis *isis;
DECLARE_QOBJ_TYPE(isis_area)

struct isis_area {
	struct isis *isis;			       /* back pointer */
	dict_t *lspdb[ISIS_LEVELS];		       /* link-state dbs */
	struct isis_spftree *spftree[ISIS_LEVELS];     /* The v4 SPTs */
	struct route_table *route_table[ISIS_LEVELS];  /* IPv4 routes */
	struct isis_spftree *spftree6[ISIS_LEVELS];    /* The v6 SPTs */
	struct route_table *route_table6[ISIS_LEVELS]; /* IPv6 routes */
#define DEFAULT_LSP_MTU 1497
	unsigned int lsp_mtu;      /* Size of LSPs to generate */
	struct list *circuit_list; /* IS-IS circuits */
	struct flags flags;
	struct thread *t_tick; /* LSP walker */
	struct thread *t_lsp_refresh[ISIS_LEVELS];
	/* t_lsp_refresh is used in two ways:
	 * a) regular refresh of LSPs
	 * b) (possibly throttled) updates to LSPs
	 *
	 * The lsp_regenerate_pending flag tracks whether the timer is active
	 * for the a) or the b) case.
	 *
	 * It is of utmost importance to clear this flag when the timer is
	 * rescheduled for normal refresh, because otherwise, updates will
	 * be delayed until the next regular refresh.
	 */
	int lsp_regenerate_pending[ISIS_LEVELS];

	/*
	 * Configurables
	 */
	struct isis_passwd area_passwd;
	struct isis_passwd domain_passwd;
	/* do we support dynamic hostnames?  */
	char dynhostname;
	/* do we support new style metrics?  */
	char newmetric;
	char oldmetric;
	/* identifies the routing instance   */
	char *area_tag;
	/* area addresses for this area      */
	struct list *area_addrs;
	uint16_t max_lsp_lifetime[ISIS_LEVELS];
	char is_type; /* level-1 level-1-2 or level-2-only */
	/* are we overloaded? */
	char overload_bit;
	/* L1/L2 router identifier for inter-area traffic */
	char attached_bit;
	uint16_t lsp_refresh[ISIS_LEVELS];
	/* minimum time allowed before lsp retransmission */
	uint16_t lsp_gen_interval[ISIS_LEVELS];
	/* min interval between between consequtive SPFs */
	uint16_t min_spf_interval[ISIS_LEVELS];
	/* the percentage of LSP mtu size used, before generating a new frag */
	int lsp_frag_threshold;
	int ip_circuits;
	/* logging adjacency changes? */
	uint8_t log_adj_changes;
	/* multi topology settings */
	struct list *mt_settings;
	int ipv6_circuits;
	/* Counters */
	uint32_t circuit_state_changes;
	struct isis_redist redist_settings[REDIST_PROTOCOL_COUNT]
					  [ZEBRA_ROUTE_MAX + 1][ISIS_LEVELS];
	struct route_table *ext_reach[REDIST_PROTOCOL_COUNT][ISIS_LEVELS];

	struct spf_backoff *spf_delay_ietf[ISIS_LEVELS]; /*Structure with IETF
							    SPF algo
							    parameters*/
	struct thread *spf_timer[ISIS_LEVELS];

	QOBJ_FIELDS
};
DECLARE_QOBJ_TYPE(isis_area)

void isis_init(void);
void isis_new(unsigned long);
struct isis_area *isis_area_create(const char *);
struct isis_area *isis_area_lookup(const char *);
int isis_area_get(struct vty *vty, const char *area_tag);
void print_debug(struct vty *, int, int);

void isis_area_overload_bit_set(struct isis_area *area, bool overload_bit);
void isis_area_attached_bit_set(struct isis_area *area, bool attached_bit);
void isis_area_dynhostname_set(struct isis_area *area, bool dynhostname);
void isis_area_metricstyle_set(struct isis_area *area, bool old_metric,
			       bool new_metric);
void isis_area_lsp_mtu_set(struct isis_area *area, unsigned int lsp_mtu);
void isis_area_is_type_set(struct isis_area *area, int is_type);
void isis_area_max_lsp_lifetime_set(struct isis_area *area, int level,
				    uint16_t max_lsp_lifetime);
void isis_area_lsp_refresh_set(struct isis_area *area, int level,
			       uint16_t lsp_refresh);
/* IS_LEVEL_1 sets area_passwd, IS_LEVEL_2 domain_passwd */
int isis_area_passwd_unset(struct isis_area *area, int level);
int isis_area_passwd_cleartext_set(struct isis_area *area, int level,
				   const char *passwd, uint8_t snp_auth);
int isis_area_passwd_hmac_md5_set(struct isis_area *area, int level,
				  const char *passwd, uint8_t snp_auth);
void isis_vty_init(void);

/* Master of threads. */
extern struct thread_master *master;

#define DEBUG_ADJ_PACKETS                (1<<0)
#define DEBUG_CHECKSUM_ERRORS            (1<<1)
#define DEBUG_LOCAL_UPDATES              (1<<2)
#define DEBUG_PROTOCOL_ERRORS            (1<<3)
#define DEBUG_SNP_PACKETS                (1<<4)
#define DEBUG_UPDATE_PACKETS             (1<<5)
#define DEBUG_SPF_EVENTS                 (1<<6)
#define DEBUG_SPF_STATS                  (1<<7)
#define DEBUG_SPF_TRIGGERS               (1<<8)
#define DEBUG_RTE_EVENTS                 (1<<9)
#define DEBUG_EVENTS                     (1<<10)
#define DEBUG_ZEBRA                      (1<<11)
#define DEBUG_PACKET_DUMP                (1<<12)
#define DEBUG_LSP_GEN                    (1<<13)
#define DEBUG_LSP_SCHED                  (1<<14)

#define lsp_debug(...)                                                         \
	do {                                                                   \
		if (isis->debugs & DEBUG_LSP_GEN)                              \
			zlog_debug(__VA_ARGS__);                               \
	} while (0)

#define sched_debug(...)                                                       \
	do {                                                                   \
		if (isis->debugs & DEBUG_LSP_SCHED)                            \
			zlog_debug(__VA_ARGS__);                               \
	} while (0)

#define DEBUG_TE                         (1<<13)

#define IS_DEBUG_ISIS(x)                 (isis->debugs & x)

#endif /* ISISD_H */
