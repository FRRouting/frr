/*
 * IS-IS Rout(e)ing protocol - isis_circuit.h
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

#ifndef ISIS_CIRCUIT_H
#define ISIS_CIRCUIT_H

#include "vty.h"
#include "if.h"
#include "qobj.h"

#include "isis_constants.h"
#include "isis_common.h"

#define CIRCUIT_MAX 255

struct password {
	struct password *next;
	int len;
	u_char *pass;
};

struct metric {
	u_char metric_default;
	u_char metric_error;
	u_char metric_expense;
	u_char metric_delay;
};

struct isis_bcast_info {
	u_char snpa[ETH_ALEN];		    /* SNPA of this circuit */
	char run_dr_elect[2];		    /* Should we run dr election ? */
	struct thread *t_run_dr[2];	 /* DR election thread */
	struct thread *t_send_lan_hello[2]; /* send LAN IIHs in this thread */
	struct list *adjdb[2];		    /* adjacency dbs */
	struct list *lan_neighs[2];	 /* list of lx neigh snpa */
	char is_dr[2];			    /* Are we level x DR ? */
	u_char l1_desig_is[ISIS_SYS_ID_LEN + 1]; /* level-1 DR */
	u_char l2_desig_is[ISIS_SYS_ID_LEN + 1]; /* level-2 DR */
	struct thread *t_refresh_pseudo_lsp[2];  /* refresh pseudo-node LSPs */
};

struct isis_p2p_info {
	struct isis_adjacency *neighbor;
	struct thread *t_send_p2p_hello; /* send P2P IIHs in this thread  */
};

struct isis_circuit {
	int state;
	u_char circuit_id;	   /* l1/l2 p2p/bcast CircuitID */
	struct isis_area *area;      /* back pointer to the area */
	struct interface *interface; /* interface info from z */
	int fd;			     /* IS-IS l1/2 socket */
	int sap_length;		     /* SAP length for DLPI */
	struct nlpids nlpids;
	/*
	 * Threads
	 */
	struct thread *t_read;
	struct thread *t_send_csnp[2];
	struct thread *t_send_psnp[2];
	struct list *lsp_queue;	/* LSPs to be txed (both levels) */
	time_t lsp_queue_last_cleared; /* timestamp used to enforce transmit
					* interval;
					* for scalability, use one timestamp per
					* circuit, instead of one per lsp per
					* circuit
					*/
	/* there is no real point in two streams, just for programming kicker */
	int (*rx)(struct isis_circuit *circuit, u_char *ssnpa);
	struct stream *rcv_stream; /* Stream for receiving */
	int (*tx)(struct isis_circuit *circuit, int level);
	struct stream *snd_stream; /* Stream for sending */
	int idx;		   /* idx in S[RM|SN] flags */
				   /* $FRR indent$ */
				   /* clang-format off */
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
	u_char priority[2]; /* l1/2 IS configured priority */
	int pad_hellos;     /* add padding to Hello PDUs ? */
	char ext_domain;    /* externalDomain   (boolean) */
	int lsp_regenerate_pending[ISIS_LEVELS];
	/*
	 * Configurables
	 */
	struct isis_passwd passwd;     /* Circuit rx/tx password */
	int is_type;		       /* circuit is type == level of circuit
					* differentiated from circuit type (media) */
	u_int32_t hello_interval[2];   /* l1HelloInterval in msecs */
	u_int16_t hello_multiplier[2]; /* l1HelloMultiplier */
	u_int16_t csnp_interval[2];    /* level-1 csnp-interval in seconds */
	u_int16_t psnp_interval[2];    /* level-1 psnp-interval in seconds */
	u_int8_t metric[2];
	u_int32_t te_metric[2];
	struct mpls_te_circuit
		*mtc;   /* Support for MPLS-TE parameters - see isis_te.[c,h] */
	int ip_router;  /* Route IP ? */
	int is_passive; /* Is Passive ? */
	struct list *mt_settings;   /* IS-IS MT Settings */
	struct list *ip_addrs;      /* our IP addresses */
	int ipv6_router;	    /* Route IPv6 ? */
	struct list *ipv6_link;     /* our link local IPv6 addresses */
	struct list *ipv6_non_link; /* our non-link local IPv6 addresses */
	u_int16_t upadjcount[2];
#define ISIS_CIRCUIT_FLAPPED_AFTER_SPF 0x01
	u_char flags;
	/*
	 * Counters as in 10589--11.2.5.9
	 */
	u_int32_t adj_state_changes; /* changesInAdjacencyState */
	u_int32_t init_failures;     /* intialisationFailures */
	u_int32_t ctrl_pdus_rxed;    /* controlPDUsReceived */
	u_int32_t ctrl_pdus_txed;    /* controlPDUsSent */
	u_int32_t
		desig_changes[2]; /* lanLxDesignatedIntermediateSystemChanges */
	u_int32_t rej_adjacencies; /* rejectedAdjacencies */

	QOBJ_FIELDS
};
DECLARE_QOBJ_TYPE(isis_circuit)

void isis_circuit_init(void);
struct isis_circuit *isis_circuit_new(void);
void isis_circuit_del(struct isis_circuit *circuit);
struct isis_circuit *circuit_lookup_by_ifp(struct interface *ifp,
					   struct list *list);
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
size_t isis_circuit_pdu_size(struct isis_circuit *circuit);
void isis_circuit_stream(struct isis_circuit *circuit, struct stream **stream);

struct isis_circuit *isis_circuit_create(struct isis_area *area,
					 struct interface *ifp);
void isis_circuit_af_set(struct isis_circuit *circuit, bool ip_router,
			 bool ipv6_router);
int isis_circuit_passive_set(struct isis_circuit *circuit, bool passive);
void isis_circuit_is_type_set(struct isis_circuit *circuit, int is_type);
int isis_circuit_circ_type_set(struct isis_circuit *circuit, int circ_type);

int isis_circuit_metric_set(struct isis_circuit *circuit, int level,
			    int metric);

int isis_circuit_passwd_unset(struct isis_circuit *circuit);
int isis_circuit_passwd_cleartext_set(struct isis_circuit *circuit,
				      const char *passwd);
int isis_circuit_passwd_hmac_md5_set(struct isis_circuit *circuit,
				     const char *passwd);

int isis_circuit_mt_enabled_set(struct isis_circuit *circuit, uint16_t mtid,
				bool enabled);

#endif /* _ZEBRA_ISIS_CIRCUIT_H */
