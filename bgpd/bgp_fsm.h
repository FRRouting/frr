// SPDX-License-Identifier: GPL-2.0-or-later
/* BGP-4 Finite State Machine
 * From RFC1771 [A Border Gateway Protocol 4 (BGP-4)]
 * Copyright (C) 1998 Kunihiro Ishiguro
 */

#ifndef _QUAGGA_BGP_FSM_H
#define _QUAGGA_BGP_FSM_H

/* Macro for BGP read, write and timer thread.  */
#define BGP_TIMER_ON(T, F, V)                                                  \
	do {                                                                   \
		if ((peer->status != Deleted))                                 \
			event_add_timer(bm->master, (F), peer, (V), &(T));     \
	} while (0)

#define BGP_EVENT_ADD(P, E)                                                    \
	do {                                                                   \
		if ((P)->status != Deleted)                                    \
			event_add_event(bm->master, bgp_event, (P), (E),       \
					NULL);                                 \
	} while (0)

#define BGP_EVENT_FLUSH(P)                                                     \
	do {                                                                   \
		assert(peer);                                                  \
		event_cancel_event_ready(bm->master, (P));                     \
	} while (0)

#define BGP_UPDATE_GROUP_TIMER_ON(T, F)                                        \
	do {                                                                   \
		if (BGP_SUPPRESS_FIB_ENABLED(peer->bgp) &&                     \
		    PEER_ROUTE_ADV_DELAY(peer))                                \
			event_add_timer_msec(                                  \
				bm->master, (F), peer,                         \
				(BGP_DEFAULT_UPDATE_ADVERTISEMENT_TIME *       \
				 1000),                                        \
				(T));                                          \
		else                                                           \
			event_add_timer_msec(bm->master, (F), peer, 0, (T));   \
	} while (0)

#define BGP_MSEC_JITTER 10

/* Status codes for bgp_event_update() */
#define FSM_PEER_NOOP           0
#define FSM_PEER_STOPPED        1
#define FSM_PEER_TRANSFERRED    2
#define FSM_PEER_TRANSITIONED   3

#define BGP_PEER_GR_HELPER_ENABLE(peer)	\
	do {		\
		UNSET_FLAG( \
			peer->peer_gr_new_status_flag,		\
			PEER_GRACEFUL_RESTART_NEW_STATE_RESTART);	\
		SET_FLAG( \
			peer->peer_gr_new_status_flag,	\
			PEER_GRACEFUL_RESTART_NEW_STATE_HELPER);\
	} while (0)

#define BGP_PEER_GR_ENABLE(peer)\
	do {				\
		SET_FLAG(   \
			peer->peer_gr_new_status_flag,	\
			PEER_GRACEFUL_RESTART_NEW_STATE_RESTART); \
		UNSET_FLAG( \
			peer->peer_gr_new_status_flag,	\
			PEER_GRACEFUL_RESTART_NEW_STATE_HELPER);\
	} while (0)

#define BGP_PEER_GR_DISABLE(peer)\
	do {				\
		UNSET_FLAG( \
			peer->peer_gr_new_status_flag,	\
			PEER_GRACEFUL_RESTART_NEW_STATE_RESTART);\
		UNSET_FLAG(\
			peer->peer_gr_new_status_flag, \
			PEER_GRACEFUL_RESTART_NEW_STATE_HELPER);\
	} while (0)

#define BGP_PEER_GR_GLOBAL_INHERIT_SET(peer) \
			SET_FLAG(peer->peer_gr_new_status_flag,	\
				PEER_GRACEFUL_RESTART_NEW_STATE_INHERIT)

#define BGP_PEER_GR_GLOBAL_INHERIT_UNSET(peer)	\
			UNSET_FLAG(peer->peer_gr_new_status_flag, \
				PEER_GRACEFUL_RESTART_NEW_STATE_INHERIT)

#define BGP_PEER_GRACEFUL_RESTART_CAPABLE(peer)                                \
	(CHECK_FLAG(peer->cap, PEER_CAP_RESTART_ADV)                           \
	 && CHECK_FLAG(peer->cap, PEER_CAP_RESTART_RCV))

#define BGP_PEER_RESTARTING_MODE(peer)                                         \
	(CHECK_FLAG(peer->flags, PEER_FLAG_GRACEFUL_RESTART) &&                \
	 CHECK_FLAG(peer->cap, PEER_CAP_GRACEFUL_RESTART_R_BIT_ADV) &&         \
	 !CHECK_FLAG(peer->cap, PEER_CAP_GRACEFUL_RESTART_R_BIT_RCV))

#define BGP_PEER_HELPER_MODE(peer)                                             \
	(CHECK_FLAG(peer->flags, PEER_FLAG_GRACEFUL_RESTART_HELPER) &&         \
	 CHECK_FLAG(peer->cap, PEER_CAP_GRACEFUL_RESTART_R_BIT_RCV) &&         \
	 !CHECK_FLAG(peer->cap, PEER_CAP_GRACEFUL_RESTART_R_BIT_ADV))

/* Prototypes. */

/*
 * Update FSM for peer based on whether we have valid nexthops or not.
 */
extern void bgp_fsm_nht_update(struct peer *peer, bool has_valid_nexthops);
extern void bgp_event(struct event *event);
extern int bgp_event_update(struct peer *, enum bgp_fsm_events event);
extern int bgp_stop(struct peer *peer);
extern void bgp_timer_set(struct peer *);
extern void bgp_routeadv_timer(struct event *event);
extern void bgp_fsm_change_status(struct peer *peer,
				  enum bgp_fsm_status status);
extern const char *const peer_down_str[];
extern void bgp_update_delay_end(struct bgp *);
extern void bgp_maxmed_update(struct bgp *);
extern bool bgp_maxmed_onstartup_configured(struct bgp *);
extern bool bgp_maxmed_onstartup_active(struct bgp *);
extern int bgp_fsm_error_subcode(int status);

/**
 * Start the route advertisement timer (that honors MRAI) for all the
 * peers. Typically called at the end of initial convergence, coming
 * out of read-only mode.
 */
extern void bgp_start_routeadv(struct bgp *);

/**
 * See if the route advertisement timer needs to be adjusted for a
 * peer. For example, if the last update was written to the peer a
 * long while back, we don't need to wait for the periodic advertisement
 * timer to expire to send the new set of prefixes. It should fire
 * instantly and updates should go out sooner.
 */
extern void bgp_adjust_routeadv(struct peer *);

#include "hook.h"
DECLARE_HOOK(peer_backward_transition, (struct peer *peer), (peer));
DECLARE_HOOK(peer_established, (struct peer *peer), (peer));

int bgp_gr_update_all(struct bgp *bgp, int global_gr_cmd);
int bgp_neighbor_graceful_restart(struct peer *peer, int peer_gr_cmd);
unsigned int bgp_peer_gr_action(struct peer *peer,
		int old_peer_state, int new_peer_state);
void bgp_peer_move_to_gr_mode(struct peer *peer, int new_state);
unsigned int bgp_peer_gr_helper_enable(struct peer *peer);
unsigned int bgp_peer_gr_enable(struct peer *peer);
unsigned int bgp_peer_gr_global_inherit(struct peer *peer);
unsigned int bgp_peer_gr_disable(struct peer *peer);
enum peer_mode bgp_peer_gr_mode_get(struct peer *peer);
enum global_mode bgp_global_gr_mode_get(struct bgp *bgp);
enum peer_mode bgp_get_peer_gr_mode_from_flags(struct peer *peer);
unsigned int bgp_peer_gr_global_inherit_unset(struct peer *peer);
int bgp_gr_lookup_n_update_all_peer(struct bgp *bgp,
		enum global_mode global_new_state,
		enum global_mode global_old_state);
void bgp_peer_gr_flags_update(struct peer *peer);
const char *print_peer_gr_mode(enum peer_mode pr_mode);
const char *print_peer_gr_cmd(enum peer_gr_command pr_gr_cmd);
const char *print_global_gr_mode(enum global_mode gl_mode);
const char *print_global_gr_cmd(enum global_gr_command gl_gr_cmd);
int bgp_peer_reg_with_nht(struct peer *peer);
#endif /* _QUAGGA_BGP_FSM_H */
