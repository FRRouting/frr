// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * IS-IS Rout(e)ing protocol - isis_circuit.h
 *
 * Copyright (C) 2001,2002   Sampo Saaristo
 *                           Tampere University of Technology
 *                           Institute of Communications Engineering
 */

#ifndef ISIS_CIRCUIT_H
#define ISIS_CIRCUIT_H

#include "vty.h"
#include "if.h"
#include "qobj.h"
#include "prefix.h"
#include "ferr.h"
#include "nexthop.h"

#include "isis_constants.h"
#include "isis_common.h"
#include "isis_csm.h"

DECLARE_HOOK(isis_if_new_hook, (struct interface *ifp), (ifp));

struct isis_lsp;

struct password {
	struct password *next;
	int len;
	uint8_t *pass;
};

struct metric {
	uint8_t metric_default;
	uint8_t metric_error;
	uint8_t metric_expense;
	uint8_t metric_delay;
};

struct isis_bcast_info {
	uint8_t snpa[ETH_ALEN];		      /* SNPA of this circuit */
	char run_dr_elect[ISIS_LEVELS];       /* Should we run dr election ? */
	struct event *t_run_dr[ISIS_LEVELS];  /* DR election thread */
	struct event *t_send_lan_hello[ISIS_LEVELS];  /* send LAN IIHs in this
							  thread */
	struct list *adjdb[ISIS_LEVELS];	      /* adjacency dbs */
	struct list *lan_neighs[ISIS_LEVELS];     /* list of lx neigh snpa */
	char is_dr[ISIS_LEVELS];		  /* Are we level x DR ? */
	uint8_t l1_desig_is[ISIS_SYS_ID_LEN + 1]; /* level-1 DR */
	uint8_t l2_desig_is[ISIS_SYS_ID_LEN + 1]; /* level-2 DR */
	struct event *t_refresh_pseudo_lsp[ISIS_LEVELS]; /* refresh pseudo-node
							     LSPs */
};

struct isis_p2p_info {
	struct isis_adjacency *neighbor;
	struct event *t_send_p2p_hello; /* send P2P IIHs in this thread  */
};

struct isis_circuit_arg {
	int level;
	struct isis_circuit *circuit;
};

/*
 * Hello padding types
 */
enum isis_hello_padding {
	ISIS_HELLO_PADDING_ALWAYS,
	ISIS_HELLO_PADDING_DISABLED,
	ISIS_HELLO_PADDING_DURING_ADJACENCY_FORMATION
};

struct isis_circuit {
	enum isis_circuit_state state;
	uint8_t circuit_id;	  /* l1/l2 bcast CircuitID */
	time_t last_uptime;
	struct isis *isis;
	struct isis_area *area;      /* back pointer to the area */
	struct interface *interface; /* interface info from z */
	int fd;			     /* IS-IS l1/2 socket */
	int sap_length;		     /* SAP length for DLPI */
	struct nlpids nlpids;
	/*
	 * Threads
	 */
	struct event *t_read;
	struct event *t_send_csnp[ISIS_LEVELS];
	struct event *t_send_psnp[ISIS_LEVELS];
	struct isis_tx_queue *tx_queue;
	struct isis_circuit_arg
		level_arg[ISIS_LEVELS]; /* used as argument for threads */

	/* there is no real point in two streams, just for programming kicker */
	int (*rx)(struct isis_circuit *circuit, uint8_t *ssnpa);
	struct stream *rcv_stream; /* Stream for receiving */
	int (*tx)(struct isis_circuit *circuit, int level);
	struct stream *snd_stream; /* Stream for sending */
	int idx;		   /* idx in S[RM|SN] flags */
#define CIRCUIT_T_UNKNOWN    0
#define CIRCUIT_T_BROADCAST  1
#define CIRCUIT_T_P2P        2
#define CIRCUIT_T_LOOPBACK   3
	int circ_type;		   /* type of the physical interface */
	int circ_type_config;      /* config type of the physical interface */
	union {
		struct isis_bcast_info bc;
		struct isis_p2p_info p2p;
	} u;
	uint8_t priority[ISIS_LEVELS]; /* l1/2 IS configured priority */
	enum isis_hello_padding pad_hellos; /* type of Hello PDUs padding */
	char ext_domain;    /* externalDomain   (boolean) */
	int lsp_regenerate_pending[ISIS_LEVELS];
	uint64_t lsp_error_counter;

	/*
	 * Configurables
	 */
	char *tag;		       /* area tag */
	struct isis_passwd passwd;     /* Circuit rx/tx password */
	int is_type_config;	       /* configured circuit is type */
	int is_type;		       /* circuit is type == level of circuit
					* differentiated from circuit type (media) */
	uint32_t hello_interval[ISIS_LEVELS];   /* hello-interval in seconds */
	uint16_t hello_multiplier[ISIS_LEVELS]; /* hello-multiplier */
	uint16_t csnp_interval[ISIS_LEVELS];    /* csnp-interval in seconds */
	uint16_t psnp_interval[ISIS_LEVELS];    /* psnp-interval in seconds */
	uint8_t metric[ISIS_LEVELS];
	uint32_t te_metric[ISIS_LEVELS];
	struct isis_ext_subtlvs *ext; /* Extended parameters (TE + Adj SID */
	int ip_router;  /* Route IP ? */
	int is_passive; /* Is Passive ? */
	struct list *mt_settings;   /* IS-IS MT Settings */
	struct list *ip_addrs;      /* our IP addresses */
	int ipv6_router;	    /* Route IPv6 ? */
	struct list *ipv6_link;     /* our link local IPv6 addresses */
	struct list *ipv6_non_link; /* our non-link local IPv6 addresses */
	uint16_t upadjcount[ISIS_LEVELS];
#define ISIS_CIRCUIT_FLAPPED_AFTER_SPF 0x01
#define ISIS_CIRCUIT_IF_DOWN_FROM_Z 0x02
	uint8_t flags;
	bool disable_threeway_adj;
	struct {
		bool enabled;
		char *profile;
	} bfd_config;
	struct ldp_sync_info *ldp_sync_info;
	bool lfa_protection[ISIS_LEVELS];
	bool rlfa_protection[ISIS_LEVELS];
	uint32_t rlfa_max_metric[ISIS_LEVELS];
	struct hash *lfa_excluded_ifaces[ISIS_LEVELS];
	bool tilfa_protection[ISIS_LEVELS];
	bool tilfa_node_protection[ISIS_LEVELS];
	bool tilfa_link_fallback[ISIS_LEVELS];
	/*
	 * Counters as in 10589--11.2.5.9
	 */
	uint32_t adj_state_changes; /* changesInAdjacencyState */
	uint32_t init_failures;     /* intialisationFailures */
	uint32_t ctrl_pdus_rxed;    /* controlPDUsReceived */
	uint32_t ctrl_pdus_txed;    /* controlPDUsSent */
	uint32_t desig_changes[ISIS_LEVELS]; /* lanLxDesignatedIntermediateSystemChanges
					      */
	uint32_t rej_adjacencies; /* rejectedAdjacencies */
	/*
	 * Counters as in ietf-isis@2019-09-09.yang
	 */
	uint32_t id_len_mismatches; /* id-len-mismatch */
	uint32_t max_area_addr_mismatches; /* max-area-addresses-mismatch */
	uint32_t auth_type_failures; /*authentication-type-fails */
	uint32_t auth_failures; /* authentication-fails */

	uint32_t snmp_id; /* Circuit id in snmp */

	uint32_t snmp_adj_idx_gen; /* Create unique id for adjacency on creation
				    */
	struct list *snmp_adj_list; /* List in id order */

	QOBJ_FIELDS;
};
DECLARE_QOBJ_TYPE(isis_circuit);

void isis_circuit_init(void);
struct isis_circuit *isis_circuit_new(struct interface *ifp, const char *tag);
void isis_circuit_del(struct isis_circuit *circuit);
struct isis_circuit *circuit_scan_by_ifp(struct interface *ifp);
void isis_circuit_configure(struct isis_circuit *circuit,
			    struct isis_area *area);
void isis_circuit_deconfigure(struct isis_circuit *circuit,
			      struct isis_area *area);
void isis_circuit_if_add(struct isis_circuit *circuit, struct interface *ifp);
void isis_circuit_if_del(struct isis_circuit *circuit, struct interface *ifp);
void isis_circuit_if_bind(struct isis_circuit *circuit, struct interface *ifp);
void isis_circuit_if_unbind(struct isis_circuit *circuit,
			    struct interface *ifp);
void isis_circuit_add_addr(struct isis_circuit *circuit,
			   struct connected *conn);
void isis_circuit_del_addr(struct isis_circuit *circuit,
			   struct connected *conn);
void isis_circuit_prepare(struct isis_circuit *circuit);
int isis_circuit_up(struct isis_circuit *circuit);
void isis_circuit_down(struct isis_circuit *);
void circuit_update_nlpids(struct isis_circuit *circuit);
void isis_circuit_print_vty(struct isis_circuit *circuit, struct vty *vty,
			    char detail);
void isis_circuit_print_json(struct isis_circuit *circuit,
			     struct json_object *json, char detail);
size_t isis_circuit_pdu_size(struct isis_circuit *circuit);
void isis_circuit_switchover_routes(struct isis_circuit *circuit, int family,
				    union g_addr *nexthop_ip,
				    ifindex_t ifindex);
void isis_circuit_stream(struct isis_circuit *circuit, struct stream **stream);

void isis_circuit_af_set(struct isis_circuit *circuit, bool ip_router,
			 bool ipv6_router);
ferr_r isis_circuit_passive_set(struct isis_circuit *circuit, bool passive);
void isis_circuit_is_type_set(struct isis_circuit *circuit, int is_type);
void isis_circuit_circ_type_set(struct isis_circuit *circuit, int circ_type);

ferr_r isis_circuit_metric_set(struct isis_circuit *circuit, int level,
			       int metric);

ferr_r isis_circuit_passwd_unset(struct isis_circuit *circuit);
ferr_r isis_circuit_passwd_set(struct isis_circuit *circuit,
			       uint8_t passwd_type, const char *passwd);
ferr_r isis_circuit_passwd_cleartext_set(struct isis_circuit *circuit,
					 const char *passwd);
ferr_r isis_circuit_passwd_hmac_md5_set(struct isis_circuit *circuit,
					const char *passwd);

int isis_circuit_mt_enabled_set(struct isis_circuit *circuit, uint16_t mtid,
				bool enabled);

#ifdef FABRICD
DECLARE_HOOK(isis_circuit_config_write,
	    (struct isis_circuit *circuit, struct vty *vty),
	    (circuit, vty));
#endif

DECLARE_HOOK(isis_circuit_add_addr_hook, (struct isis_circuit *circuit),
	     (circuit));

DECLARE_HOOK(isis_circuit_new_hook, (struct isis_circuit *circuit), (circuit));
DECLARE_HOOK(isis_circuit_del_hook, (struct isis_circuit *circuit), (circuit));

#endif /* _ZEBRA_ISIS_CIRCUIT_H */
