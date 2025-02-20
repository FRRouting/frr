// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright (C) 2020 Volta Networks, Inc
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 *
 */

#ifndef _PATH_TED_H
#define _PATH_TED_H

#ifdef __cplusplus

extern "C" {
#endif

#include <zebra.h>

#include <stdbool.h>

#include <debug.h>
#include "linklist.h"
#include "log.h"
#include "command.h"
#include "stream.h"
#include "prefix.h"
#include "zclient.h"
#include "link_state.h"

extern struct ted_state ted_state_g;
#define TIMER_RETRY_DELAY 5 /* Timeout in seconds between ls sync request */
#define TED_KEY 1
#define TED_ASN 1
#define TED_NAME "PATHD TED"

enum igp_import {
	IMPORT_UNKNOWN = 0,
	IMPORT_ISIS,
	IMPORT_OSPFv2,
	IMPORT_OSPFv3
};
struct ted_state {
	struct event_loop *main;
	/* Status of TED: enable or disable */
	bool enabled;
	/* From which igp is going to receive data */
	enum igp_import import;
	/* The TED itself as in link_state.h */
	struct ls_ted *ted;
	/* Timer for ted sync */
	struct event *t_link_state_sync;
	/* Timer for refresh sid in segment list */
	struct event *t_segment_list_refresh;
	/* delay interval in seconds */
	uint32_t link_state_delay_interval;
	/* delay interval refresh in seconds */
	uint32_t segment_list_refresh_interval;
	struct debug dbg;
};
/* Debug flags. */
#define PATH_TED_DEBUG(fmt, ...)                                               \
	DEBUGD(&ted_state_g.dbg, "mpls-te: " fmt, ##__VA_ARGS__)

#define PATH_TED_ERROR(fmt, ...)                                               \
	DEBUGE(&ted_state_g.dbg, "mpls-te: " fmt, ##__VA_ARGS__)

#define PATH_TED_WARN(fmt, ...)                                                \
	DEBUGW(&ted_state_g.dbg, "mpls-te: " fmt, ##__VA_ARGS__)

#define PATH_TED_INFO(fmt, ...)                                                \
	DEBUGI(&ted_state_g.dbg, "mpls-te: " fmt, ##__VA_ARGS__)

/* TED management functions */
bool path_ted_is_initialized(void);
void path_ted_init(struct event_loop *master);
uint32_t path_ted_teardown(void);
void path_ted_timer_sync_cancel(void);
void path_ted_timer_refresh_cancel(void);
int path_ted_segment_list_refresh(void);

/* TED configuration functions */
uint32_t path_ted_config_write(struct vty *vty);

/* TED util functions */
/* clang-format off */
#define LS_MSG_EVENT_PRINT(event) event == LS_MSG_EVENT_ADD?"add"\
		    : event == LS_MSG_EVENT_DELETE?"del"\
		    : event == LS_MSG_EVENT_UPDATE?"upd"\
		    : event == LS_MSG_EVENT_SYNC?"syn"\
		    : event == LS_MSG_EVENT_SYNC?"und" : "none"
#define LS_MSG_TYPE_PRINT(type) type == LS_MSG_TYPE_NODE?"node"\
		    : type == LS_MSG_TYPE_ATTRIBUTES?"att"\
		    : type == LS_MSG_TYPE_PREFIX?"pre" : "none"
#define LS_IGP_PRINT(type) type == ISIS_L1?"ISIS_L1"\
		    : type == ISIS_L2?"ISIS_L2"\
		    : type == DIRECT?"DIRECT"\
		    : type == STATIC?"STATIC"\
		    : type == OSPFv2?"OSPFv2" : "none"
#define PATH_TED_IGP_PRINT(type) type == IMPORT_OSPFv2?"OSPFv2"\
		    : type == IMPORT_OSPFv3?"OSPFv3"\
		    : type == IMPORT_ISIS?"ISIS" : "none"
/* clang-format on */


uint32_t path_ted_get_current_igp(uint32_t);
/* TED Query functions */

/*
 * Type of queries from draft-ietf-spring-segment-routing-policy-07 for types
 * f,c,e
 */

/**
 * Search for sid based in prefix and optional algo
 *
 * @param prefix	Net prefix to resolv
 * @param algo		Algorithm for link state
 *
 * @return		sid of attribute
 */
uint32_t path_ted_query_type_c(struct prefix *prefix, uint8_t algo);

/**
 * Search for sid based in prefix and interface id
 *
 * @param prefix	Net prefix to resolv
 * @param iface_id	The interface id
 *
 * @return		sid of attribute
 */
uint32_t path_ted_query_type_e(struct prefix *prefix, uint32_t iface_id);

/**
 * Search for sid based in local, remote pair
 *
 * @param local		local ip of attribute
 * @param remote	remote ip of attribute
 *
 * @return		sid of attribute
 */
uint32_t path_ted_query_type_f(struct ipaddr *local, struct ipaddr *remote);


/**
 * Handle the received opaque msg
 *
 * @param msg	Holds the ted data
 *
 * @return		sid of attribute
 */
uint32_t path_ted_rcvd_message(struct ls_message *msg);

#ifdef __cplusplus
}
#endif

#endif /* _PATH_TED_H */
