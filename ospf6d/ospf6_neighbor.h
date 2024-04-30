// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright (C) 2003 Yasuhiro Ohara
 */

#ifndef OSPF6_NEIGHBOR_H
#define OSPF6_NEIGHBOR_H

#include "typesafe.h"
#include "hook.h"

#include "ospf6_message.h"

/* Forward declaration(s). */
struct ospf6_area;

/* Debug option */
extern unsigned char conf_debug_ospf6_neighbor;
#define OSPF6_DEBUG_NEIGHBOR_STATE   0x01
#define OSPF6_DEBUG_NEIGHBOR_EVENT   0x02
#define OSPF6_DEBUG_NEIGHBOR_ON(level) (conf_debug_ospf6_neighbor |= (level))
#define OSPF6_DEBUG_NEIGHBOR_OFF(level) (conf_debug_ospf6_neighbor &= ~(level))
#define IS_OSPF6_DEBUG_NEIGHBOR(level)                                         \
	(conf_debug_ospf6_neighbor & OSPF6_DEBUG_NEIGHBOR_##level)

struct ospf6_helper_info {

	/* Grace interval received from
	 * Restarting Router.
	 */
	uint32_t recvd_grace_period;

	/* Grace interval used for grace
	 * gracetimer.
	 */
	uint32_t actual_grace_period;

	/* Grace timer,This Router acts as
	 * helper until this timer until
	 * this timer expires.
	 */
	struct event *t_grace_timer;

	/* Helper status */
	uint32_t gr_helper_status;

	/* Helper exit reason*/
	uint32_t helper_exit_reason;

	/* Planned/Unplanned restart*/
	uint32_t gr_restart_reason;


	/* Helper rejected reason */
	uint32_t rejected_reason;
};

struct ospf6_if_p2xp_neighcfg;

/* Neighbor structure */
struct ospf6_neighbor {
	/* Neighbor Router ID String */
	char name[36];

	/* OSPFv3 Interface this neighbor belongs to */
	struct ospf6_interface *ospf6_if;

	/* P2P/P2MP config for this neighbor.
	 * can be NULL if not explicitly configured!
	 */
	struct ospf6_if_p2xp_neighcfg *p2xp_cfg;

	/* Neighbor state */
	uint8_t state;

	/* timestamp of last changing state */
	uint32_t state_change;
	struct timeval last_changed;

	/* last received hello */
	struct timeval last_hello;
	uint32_t hello_in;

	/* Neighbor Router ID */
	in_addr_t router_id;

	/* Neighbor Interface ID */
	ifindex_t ifindex;

	/* Router Priority of this neighbor */
	uint8_t priority;

	in_addr_t drouter;
	in_addr_t bdrouter;
	in_addr_t prev_drouter;
	in_addr_t prev_bdrouter;

	/* Options field (Capability) */
	char options[3];

	/* IPaddr of I/F on neighbour's link */
	struct in6_addr linklocal_addr;

	/* For Database Exchange */
	uint8_t dbdesc_bits;
	uint32_t dbdesc_seqnum;
	/* Last received Database Description packet */
	struct ospf6_dbdesc dbdesc_last;

	/* LS-list */
	struct ospf6_lsdb *summary_list;
	struct ospf6_lsdb *request_list;
	struct ospf6_lsdb *retrans_list;

	/* LSA list for message transmission */
	struct ospf6_lsdb *dbdesc_list;
	struct ospf6_lsdb *lsreq_list;
	struct ospf6_lsdb *lsupdate_list;
	struct ospf6_lsdb *lsack_list;

	struct ospf6_lsa *last_ls_req;

	/* Inactivity timer */
	struct event *inactivity_timer;

	/* Timer to release the last dbdesc packet */
	struct event *last_dbdesc_release_timer;

	/* Thread for sending message */
	struct event *thread_send_dbdesc;
	struct event *thread_send_lsreq;
	struct event *thread_send_lsupdate;
	struct event *thread_send_lsack;
	struct event *thread_exchange_done;
	struct event *thread_adj_ok;
	struct event *event_loading_done;

	/* BFD information */
	struct bfd_session_params *bfd_session;

	/* ospf6 graceful restart HELPER info */
	struct ospf6_helper_info gr_helper_info;

	/* seqnum_h/l is used to compare sequence
	 * number in received packet Auth header
	 */
	uint32_t seqnum_h[OSPF6_MESSAGE_TYPE_MAX];
	uint32_t seqnum_l[OSPF6_MESSAGE_TYPE_MAX];
	bool auth_present;
	bool lls_present;
};

/* Neighbor state */
#define OSPF6_NEIGHBOR_DOWN     1
#define OSPF6_NEIGHBOR_ATTEMPT  2
#define OSPF6_NEIGHBOR_INIT     3
#define OSPF6_NEIGHBOR_TWOWAY   4
#define OSPF6_NEIGHBOR_EXSTART  5
#define OSPF6_NEIGHBOR_EXCHANGE 6
#define OSPF6_NEIGHBOR_LOADING  7
#define OSPF6_NEIGHBOR_FULL     8

/* Neighbor Events */
#define OSPF6_NEIGHBOR_EVENT_NO_EVENT             0
#define OSPF6_NEIGHBOR_EVENT_HELLO_RCVD           1
#define OSPF6_NEIGHBOR_EVENT_TWOWAY_RCVD          2
#define OSPF6_NEIGHBOR_EVENT_NEGOTIATION_DONE     3
#define OSPF6_NEIGHBOR_EVENT_EXCHANGE_DONE        4
#define OSPF6_NEIGHBOR_EVENT_LOADING_DONE         5
#define OSPF6_NEIGHBOR_EVENT_ADJ_OK               6
#define OSPF6_NEIGHBOR_EVENT_SEQNUMBER_MISMATCH   7
#define OSPF6_NEIGHBOR_EVENT_BAD_LSREQ            8
#define OSPF6_NEIGHBOR_EVENT_ONEWAY_RCVD          9
#define OSPF6_NEIGHBOR_EVENT_INACTIVITY_TIMER    10
#define OSPF6_NEIGHBOR_EVENT_MAX_EVENT           11

extern const char *const ospf6_neighbor_event_str[];

static inline const char *ospf6_neighbor_event_string(int event)
{
#define OSPF6_NEIGHBOR_UNKNOWN_EVENT_STRING "UnknownEvent"

	if (event < OSPF6_NEIGHBOR_EVENT_MAX_EVENT)
		return ospf6_neighbor_event_str[event];
	return OSPF6_NEIGHBOR_UNKNOWN_EVENT_STRING;
}

extern const char *const ospf6_neighbor_state_str[];


/* Function Prototypes */
int ospf6_neighbor_cmp(void *va, void *vb);
void ospf6_neighbor_dbex_init(struct ospf6_neighbor *on);

struct ospf6_neighbor *ospf6_neighbor_lookup(uint32_t router_id,
					     struct ospf6_interface *oi);
struct ospf6_neighbor *ospf6_area_neighbor_lookup(struct ospf6_area *area,
						  uint32_t router_id);
struct ospf6_neighbor *ospf6_neighbor_create(uint32_t router_id,
					     struct ospf6_interface *oi);
void ospf6_neighbor_delete(struct ospf6_neighbor *on);

void ospf6_neighbor_lladdr_set(struct ospf6_neighbor *on,
			       const struct in6_addr *addr);
struct ospf6_if_p2xp_neighcfg *ospf6_if_p2xp_find(struct ospf6_interface *oi,
						  const struct in6_addr *addr);
void ospf6_if_p2xp_up(struct ospf6_interface *oi);

uint32_t ospf6_neighbor_cost(struct ospf6_neighbor *on);

/* Neighbor event */
extern void hello_received(struct event *thread);
extern void twoway_received(struct event *thread);
extern void negotiation_done(struct event *thread);
extern void exchange_done(struct event *thread);
extern void loading_done(struct event *thread);
extern void adj_ok(struct event *thread);
extern void seqnumber_mismatch(struct event *thread);
extern void bad_lsreq(struct event *thread);
extern void oneway_received(struct event *thread);
extern void inactivity_timer(struct event *thread);
extern void ospf6_check_nbr_loading(struct ospf6_neighbor *on);

extern void ospf6_neighbor_init(void);
extern int config_write_ospf6_debug_neighbor(struct vty *vty);
extern int config_write_ospf6_p2xp_neighbor(struct vty *vty,
					    struct ospf6_interface *oi);
extern void install_element_ospf6_debug_neighbor(void);

DECLARE_HOOK(ospf6_neighbor_change,
	     (struct ospf6_neighbor * on, int state, int next_state),
	     (on, state, next_state));

#endif /* OSPF6_NEIGHBOR_H */
