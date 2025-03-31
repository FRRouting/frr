// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * OSPF Interface functions.
 * Copyright (C) 1999 Toshiaki Takada
 */

#ifndef _ZEBRA_OSPF_INTERFACE_H
#define _ZEBRA_OSPF_INTERFACE_H

#include "lib/bfd.h"
#include "qobj.h"
#include "hook.h"
#include "keychain.h"
#include "ospfd/ospf_packet.h"
#include "ospfd/ospf_spf.h"
#include <ospfd/ospf_flood.h>

#define IF_OSPF_IF_INFO(I) ((struct ospf_if_info *)((I)->info))
#define IF_DEF_PARAMS(I) (IF_OSPF_IF_INFO (I)->def_params)
#define IF_OIFS(I)  (IF_OSPF_IF_INFO (I)->oifs)
#define IF_OIFS_PARAMS(I) (IF_OSPF_IF_INFO (I)->params)

/* Despite the name, this macro probably is for specialist use only */
#define OSPF_IF_PARAM_CONFIGURED(S, P) ((S) && (S)->P##__config)

/* Test whether an OSPF interface parameter is set, generally, given some
 * existing ospf interface
 */
#define OSPF_IF_PARAM_IS_SET(O, P)                                             \
	(OSPF_IF_PARAM_CONFIGURED((O)->params, P)                              \
	 || OSPF_IF_PARAM_CONFIGURED(IF_DEF_PARAMS((O)->ifp)->P))

#define OSPF_IF_PARAM(O, P)                                                    \
	(OSPF_IF_PARAM_CONFIGURED((O)->params, P)                              \
		 ? (O)->params->P                                              \
		 : IF_DEF_PARAMS((O)->ifp)->P)

#define DECLARE_IF_PARAM(T, P)                                                 \
	T P;                                                                   \
	uint8_t P##__config : 1
#define UNSET_IF_PARAM(S, P) ((S)->P##__config) = 0
#define SET_IF_PARAM(S, P) ((S)->P##__config) = 1

struct ospf_if_params {
	DECLARE_IF_PARAM(uint32_t,
			 transmit_delay); /* Interface Transmisson Delay */
	DECLARE_IF_PARAM(uint32_t,
			 output_cost_cmd); /* Command Interface Output Cost */
	DECLARE_IF_PARAM(uint32_t,
			 retransmit_interval); /* Retransmission Interval */
	DECLARE_IF_PARAM(uint32_t,
			 retransmit_window); /* Retransmission Window */
	DECLARE_IF_PARAM(uint8_t, passive_interface); /* OSPF Interface is
							passive: no sending or
							receiving (no need to
							join multicast groups)
							*/
	DECLARE_IF_PARAM(uint8_t, priority); /* OSPF Interface priority */
	/* Enable OSPF on this interface with area if_area */
	DECLARE_IF_PARAM(struct in_addr, if_area);
	uint32_t if_area_id_fmt;

	bool type_cfg;
	DECLARE_IF_PARAM(uint8_t, type); /* type of interface */
#define OSPF_IF_ACTIVE                  0
#define OSPF_IF_PASSIVE		        1

#define OSPF_IF_PASSIVE_STATUS(O)                                              \
	(OSPF_IF_PARAM_CONFIGURED((O)->params, passive_interface)              \
		 ? (O)->params->passive_interface                              \
		 : (OSPF_IF_PARAM_CONFIGURED(IF_DEF_PARAMS((O)->ifp),          \
					     passive_interface)                \
			    ? IF_DEF_PARAMS((O)->ifp)->passive_interface       \
			    : (O)->ospf->passive_interface_default))

	DECLARE_IF_PARAM(uint32_t, v_hello); /* Hello Interval */
	DECLARE_IF_PARAM(uint32_t, v_wait);  /* Router Dead Interval */
	bool is_v_wait_set;                  /* Check for Dead Interval set */

	/* GR Hello Delay Interval */
	DECLARE_IF_PARAM(uint16_t, v_gr_hello_delay);

	/* MTU mismatch check (see RFC2328, chap 10.6) */
	DECLARE_IF_PARAM(uint8_t, mtu_ignore);

	/* Fast-Hellos */
	DECLARE_IF_PARAM(uint8_t, fast_hello);

	/* Prefix-Suppression */
	DECLARE_IF_PARAM(bool, prefix_suppression);

	/* Authentication data. */
	uint8_t auth_simple[OSPF_AUTH_SIMPLE_SIZE + 1]; /* Simple password. */
	uint8_t auth_simple__config : 1;

	DECLARE_IF_PARAM(struct list *,
			 auth_crypt);     /* List of Auth cryptographic data. */
	DECLARE_IF_PARAM(int, auth_type); /* OSPF authentication type */

	DECLARE_IF_PARAM(char*, keychain_name); /* OSPF HMAC Cryptographic Authentication*/

	/* Other, non-configuration state */
	uint32_t network_lsa_seqnum; /* Network LSA seqnum */

	/* BFD configuration */
	struct bfd_configuration {
		/** BFD session detection multiplier. */
		uint8_t detection_multiplier;
		/** BFD session minimum required receive interval. */
		uint32_t min_rx;
		/** BFD session minimum required transmission interval. */
		uint32_t min_tx;
		/** BFD profile. */
		char profile[BFD_PROFILE_NAME_LEN];
	} *bfd_config;

	/* MPLS LDP-IGP Sync configuration */
	struct ldp_sync_info *ldp_sync_info;

	/* point-to-point DMVPN configuration */
	uint8_t ptp_dmvpn;

	/* point-to-multipoint delayed reflooding configuration */
	bool p2mp_delay_reflood;

	/* point-to-multipoint doesn't support broadcast */
	bool p2mp_non_broadcast;

	/* Opaque LSA capability at interface level (see RFC5250) */
	DECLARE_IF_PARAM(bool, opaque_capable);

	/* Name of prefix-list name for packet source address filtering. */
	DECLARE_IF_PARAM(char *, nbr_filter_name);
};

enum { MEMBER_ALLROUTERS = 0,
       MEMBER_DROUTERS,
       MEMBER_MAX,
};

struct ospf_if_info {
	struct ospf_if_params *def_params;
	struct route_table *params;
	struct route_table *oifs;
	unsigned int
		membership_counts[MEMBER_MAX]; /* multicast group refcnts */

	uint32_t curr_mtu;

	/* Per-interface write socket, configured via 'ospf' object */
	int oii_fd;
};

struct ospf_interface;

struct ospf_vl_data {
	struct in_addr vl_peer;	/* Router-ID of the peer */
	struct in_addr vl_area_id;     /* Transit area */
	int vl_area_id_fmt;	    /* Area ID format */
	struct ospf_interface *vl_oi;  /* Interface data structure */
	struct vertex_nexthop nexthop; /* Nexthop router and oi to use */
	struct in_addr peer_addr;      /* Address used to reach the peer */
	uint8_t flags;
};


#define OSPF_VL_MAX_COUNT 256
#define OSPF_VL_MTU	  1500

#define OSPF_VL_FLAG_APPROVED 0x01

struct crypt_key {
	uint8_t key_id;
	uint8_t auth_key[OSPF_AUTH_MD5_SIZE + 1];
};

/* OSPF interface structure. */
struct ospf_interface {
	/* This interface's parent ospf instance. */
	struct ospf *ospf;

	/* OSPF Area. */
	struct ospf_area *area;

	/* Position range in Router LSA */
	uint16_t lsa_pos_beg; /* inclusive, >= */
	uint16_t lsa_pos_end; /* exclusive, <  */

	/* Interface data from zebra. */
	struct interface *ifp;
	struct ospf_vl_data *vl_data; /* Data for Virtual Link */

	/* Packet send buffer. */
	struct ospf_fifo *obuf; /* Output queue */

	/* OSPF Network Type. */
	uint8_t type;
#define OSPF_IF_NON_BROADCAST(O)                                               \
	(((O)->type == OSPF_IFTYPE_NBMA) ||                                    \
	 ((((O)->type == OSPF_IFTYPE_POINTOMULTIPOINT) &&                      \
	   (O)->p2mp_non_broadcast)))

	/* point-to-point DMVPN configuration */
	uint8_t ptp_dmvpn;

	/* point-to-multipoint delayed reflooding */
	bool p2mp_delay_reflood;

	/* point-to-multipoint doesn't support broadcast */
	bool p2mp_non_broadcast;

	/* State of Interface State Machine. */
	uint8_t state;

	/* To which multicast groups do we currently belong? */
	uint8_t multicast_memberships;
#define OI_MEMBER_FLAG(M) (1 << (M))
#define OI_MEMBER_COUNT(O,M) (IF_OSPF_IF_INFO(oi->ifp)->membership_counts[(M)])
#define OI_MEMBER_CHECK(O, M)                                                  \
	(CHECK_FLAG((O)->multicast_memberships, OI_MEMBER_FLAG(M)))
#define OI_MEMBER_JOINED(O, M)                                                 \
	do {                                                                   \
		SET_FLAG((O)->multicast_memberships, OI_MEMBER_FLAG(M));       \
		IF_OSPF_IF_INFO((O)->ifp)->membership_counts[(M)]++;           \
	} while (0)
#define OI_MEMBER_LEFT(O, M)                                                   \
	do {                                                                   \
		UNSET_FLAG((O)->multicast_memberships, OI_MEMBER_FLAG(M));     \
		IF_OSPF_IF_INFO((O)->ifp)->membership_counts[(M)]--;           \
	} while (0)

	struct prefix *address;      /* Interface prefix */
	struct connected *connected; /* Pointer to connected */

	/* Configured varables. */
	struct ospf_if_params *params;

	uint32_t crypt_seqnum; /* Cryptographic Sequence Number */
	uint32_t output_cost;  /* Acutual Interface Output Cost */

	/* Neighbor information. */
	struct route_table *nbrs;       /* OSPF Neighbor List */
	struct ospf_neighbor *nbr_self; /* Neighbor Self */
#define DR(I)			((I)->nbr_self->d_router)
#define BDR(I)			((I)->nbr_self->bd_router)
#define OPTIONS(I)		((I)->nbr_self->options)
#define PRIORITY(I)		((I)->nbr_self->priority)

	/* List of configured NBMA neighbor. */
	struct list *nbr_nbma;

	/* Configured prefix-list for filtering neighbors. */
	struct prefix_list *nbr_filter;

	/* Graceful-Restart data. */
	struct {
		struct {
			uint16_t elapsed_seconds;
			struct event *t_grace_send;
		} hello_delay;
	} gr;

	/* self-originated LSAs. */
	struct ospf_lsa *network_lsa_self; /* network-LSA. */
	struct list *opaque_lsa_self;      /* Type-9 Opaque-LSAs */

	struct route_table *ls_upd_queue;

	/*
	 * List of LSAs for delayed and direct link
	 * state acknowledgment transmission.
	 */
	struct ospf_lsa_list_head ls_ack_delayed;
	struct ospf_lsa_list_head ls_ack_direct;

	/* Timer values. */
	uint32_t v_ls_ack_delayed; /* Delayed Link State Acknowledgment */

	/* Threads. */
	struct event *t_hello;		 /* timer */
	struct event *t_wait;		 /* timer */
	struct event *t_ls_ack_delayed;	 /* timer */
	struct event *t_ls_ack_direct;	 /* event */
	struct event *t_ls_upd_event;	 /* event */
	struct event *t_opaque_lsa_self; /* Type-9 Opaque-LSAs */

	int on_write_q;

	/* Statistics fields. */
	uint32_t hello_in;     /* Hello message input count. */
	uint32_t hello_out;    /* Hello message output count. */
	uint32_t db_desc_in;   /* database desc. message input count. */
	uint32_t db_desc_out;  /* database desc. message output count. */
	uint32_t ls_req_in;    /* LS request message input count. */
	uint32_t ls_req_out;   /* LS request message output count. */
	uint32_t ls_upd_in;    /* LS update message input count. */
	uint32_t ls_upd_out;   /* LS update message output count. */
	uint32_t ls_ack_in;    /* LS Ack message input count. */
	uint32_t ls_ack_out;   /* LS Ack message output count. */
	uint32_t discarded;    /* discarded input count by error. */
	uint32_t state_change; /* Number of status change. */
	uint32_t ls_rxmt_lsa;  /* Number of LSAs retransmitted. */

	uint32_t full_nbrs;

	/* Buffered values for keychain and key */
	struct keychain *keychain;
	struct key *key;

	QOBJ_FIELDS;
};
DECLARE_QOBJ_TYPE(ospf_interface);

/* Prototypes. */
extern char *ospf_if_name(struct ospf_interface *oi);
extern struct ospf_interface *
ospf_if_new(struct ospf *ospf, struct interface *ifp, struct prefix *p);
extern void ospf_if_cleanup(struct ospf_interface *oi);
extern void ospf_if_free(struct ospf_interface *oi);
extern int ospf_if_up(struct ospf_interface *oi);
extern int ospf_if_down(struct ospf_interface *oi);

extern int ospf_if_is_up(struct ospf_interface *oi);
extern struct ospf_interface *ospf_if_lookup_by_lsa_pos(struct ospf_area *area,
							int lsa_pos);
extern struct ospf_interface *
ospf_if_lookup_by_local_addr(struct ospf *ospf, struct interface *ifp,
			     struct in_addr addr);
extern struct ospf_interface *ospf_if_lookup_by_prefix(struct ospf *ospf,
						       struct prefix_ipv4 *p);
extern struct ospf_interface *ospf_if_table_lookup(struct interface *ifp,
						   struct prefix *p);
extern struct ospf_interface *ospf_if_addr_local(struct in_addr addr);
extern struct ospf_interface *ospf_if_lookup_recv_if(struct ospf *ospf,
						     struct in_addr addr,
						     struct interface *ifp);
extern struct ospf_interface *ospf_if_is_configured(struct ospf *ospf,
						    struct in_addr *addr);

extern struct ospf_if_params *ospf_lookup_if_params(struct interface *ifp,
						    struct in_addr addr);
extern struct ospf_if_params *ospf_get_if_params(struct interface *ifp,
						 struct in_addr addr);
extern void ospf_free_if_params(struct interface *ifp, struct in_addr addr);
extern void ospf_if_update_params(struct interface *ifp, struct in_addr addr);

extern int ospf_if_new_hook(struct interface *ifp);
extern void ospf_if_init(void);
extern void ospf_if_stream_unset(struct ospf_interface *oi);
extern int ospf_if_is_enable(struct ospf_interface *oi);
extern int ospf_if_get_output_cost(struct ospf_interface *oi);
extern void ospf_if_recalculate_output_cost(struct interface *ifp);

/* Simulate down/up on the interface. */
extern void ospf_if_reset(struct interface *ifp);

extern struct ospf_interface *ospf_vl_new(struct ospf *ospf,
					  struct ospf_vl_data *vl_data);
extern struct ospf_vl_data *ospf_vl_data_new(struct ospf_area *area,
					     struct in_addr addr);
extern struct ospf_vl_data *
ospf_vl_lookup(struct ospf *ospf, struct ospf_area *area, struct in_addr addr);
extern int ospf_vl_count(struct ospf *ospf, struct ospf_area *area);
extern void ospf_vl_data_free(struct ospf_vl_data *vl_data);
extern void ospf_vl_add(struct ospf *ospf, struct ospf_vl_data *vl_data);
extern void ospf_vl_delete(struct ospf *ospf, struct ospf_vl_data *vl_data);
extern void ospf_vl_up_check(struct ospf_area *area, struct in_addr addr,
			     struct vertex *vertex);
extern void ospf_vl_unapprove(struct ospf *ospf);
extern void ospf_vl_shut_unapproved(struct ospf *ospf);
extern int ospf_full_virtual_nbrs(struct ospf_area *area);
extern int ospf_vls_in_area(struct ospf_area *area);

extern struct crypt_key *ospf_crypt_key_lookup(struct list *list,
					       uint8_t key_id);
extern struct crypt_key *ospf_crypt_key_new(void);
extern void ospf_crypt_key_add(struct list *list, struct crypt_key *key);
extern int ospf_crypt_key_delete(struct list *list, uint8_t key_id);
extern uint8_t ospf_default_iftype(struct interface *ifp);
extern int ospf_interface_neighbor_count(struct ospf_interface *oi);
extern void ospf_intf_neighbor_filter_apply(struct ospf_interface *oi);

/* Set all multicast memberships appropriately based on the type and
   state of the interface. */
extern void ospf_if_set_multicast(struct ospf_interface *oi);

extern void ospf_if_interface(struct interface *ifp);

extern uint32_t ospf_if_count_area_params(struct interface *ifp);
extern void ospf_reset_hello_timer(struct interface *ifp, struct in_addr addr,
				   bool is_addr);

extern void ospf_interface_fifo_flush(struct ospf_interface *oi);
DECLARE_HOOK(ospf_vl_add, (struct ospf_vl_data * vd), (vd));
DECLARE_HOOK(ospf_vl_delete, (struct ospf_vl_data * vd), (vd));

DECLARE_HOOK(ospf_if_update, (struct interface * ifp), (ifp));
DECLARE_HOOK(ospf_if_delete, (struct interface * ifp), (ifp));

#endif /* _ZEBRA_OSPF_INTERFACE_H */
