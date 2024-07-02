// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright (C) 2020 Volta Networks, Inc
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

#include <zebra.h>

#include <stdlib.h>

#include "memory.h"
#include "log.h"
#include "command.h"
#include "prefix.h"
#include <lib/json.h>

#include "pathd.h"
#include "pathd/path_errors.h"
#include "pathd/path_ted.h"

#include "pathd/path_ted_clippy.c"

static struct ls_ted *path_ted_create_ted(void);
static void path_ted_register_vty(void);
static void path_ted_unregister_vty(void);
static uint32_t path_ted_start_importing_igp(const char *daemon_str);
static uint32_t path_ted_stop_importing_igp(void);
static enum zclient_send_status path_ted_link_state_sync(void);
static void path_ted_timer_handler_sync(struct event *thread);
static void path_ted_timer_handler_refresh(struct event *thread);

extern struct zclient *zclient;

struct ted_state ted_state_g = { .dbg = { .conf = "debug pathd mpls-te",
					  .desc = "Pathd TED" } };

/*
 * path_path_ted public API function implementations
 */

void path_ted_init(struct event_loop *master)
{
	ted_state_g.main = master;
	ted_state_g.link_state_delay_interval = TIMER_RETRY_DELAY;
	ted_state_g.segment_list_refresh_interval = TIMER_RETRY_DELAY;
	path_ted_register_vty();
	path_ted_segment_list_refresh();
}

uint32_t path_ted_teardown(void)
{
	PATH_TED_DEBUG("%s : TED [%p]", __func__, ted_state_g.ted);
	path_ted_unregister_vty();
	path_ted_stop_importing_igp();
	ls_ted_del_all(&ted_state_g.ted);
	path_ted_timer_sync_cancel();
	path_ted_timer_refresh_cancel();
	return 0;
}

/**
 * Set all needed to receive igp data.
 *
 * @return		true if ok
 *
 */
uint32_t path_ted_start_importing_igp(const char *daemon_str)
{
	uint32_t status = 0;

	if (strcmp(daemon_str, "ospfv2") == 0)
		ted_state_g.import = IMPORT_OSPFv2;
	else if (strcmp(daemon_str, "ospfv3") == 0) {
		ted_state_g.import = IMPORT_UNKNOWN;
		return 1;
	} else if (strcmp(daemon_str, "isis") == 0)
		ted_state_g.import = IMPORT_ISIS;
	else {
		ted_state_g.import = IMPORT_UNKNOWN;
		return 1;
	}

	if (ls_register(zclient, false /*client*/) != 0) {
		PATH_TED_ERROR("%s: PATHD-TED: Unable to register Link State",
			       __func__);
		ted_state_g.import = IMPORT_UNKNOWN;
		status = 1;
	} else {
		if (path_ted_link_state_sync() != -1) {
			PATH_TED_DEBUG("%s: PATHD-TED: Importing %s data ON",
				       __func__,
				       PATH_TED_IGP_PRINT(ted_state_g.import));
		} else {
			PATH_TED_WARN("%s: PATHD-TED: Importing %s data OFF",
				      __func__,
				      PATH_TED_IGP_PRINT(ted_state_g.import));
			ted_state_g.import = IMPORT_UNKNOWN;
		}
	}
	return status;
}

/**
 * Unset all needed to receive igp data.
 *
 * @return		true if ok
 *
 */
uint32_t path_ted_stop_importing_igp(void)
{
	uint32_t status = 0;

	if (ted_state_g.import != IMPORT_UNKNOWN) {
		if (ls_unregister(zclient, false /*client*/) != 0) {
			PATH_TED_ERROR(
				"%s: PATHD-TED: Unable to unregister Link State",
				__func__);
			status = 1;
		} else {
			ted_state_g.import = IMPORT_UNKNOWN;
			PATH_TED_DEBUG("%s: PATHD-TED: Importing igp data OFF",
				   __func__);
		}
		path_ted_timer_sync_cancel();
	}
	return status;
}
/**
 * Check for ted status
 *
 * @return		true if ok
 *
 */
bool path_ted_is_initialized(void)
{
	if (ted_state_g.ted == NULL) {
		PATH_TED_WARN("PATHD TED ls_ted not initialized");
		return false;
	}

	return true;
}

/**
 * Creates an empty ted
 *
 * @param void
 *
 * @return		Ptr to ted or NULL
 */
struct ls_ted *path_ted_create_ted(void)
{
	struct ls_ted *ted = ls_ted_new(TED_KEY, TED_NAME, TED_ASN);

	if (ted == NULL) {
		PATH_TED_ERROR("%s Unable to initialize TED Key [%d] ASN [%d] Name [%s]",
			 __func__, TED_KEY, TED_ASN, TED_NAME);
	} else {
		PATH_TED_INFO("%s Initialize TED Key [%d] ASN [%d] Name [%s]",
			 __func__, TED_KEY, TED_ASN, TED_NAME);
	}

	return ted;
}

uint32_t path_ted_rcvd_message(struct ls_message *msg)
{
	if (!path_ted_is_initialized())
		return 1;

	if (msg == NULL) {
		PATH_TED_ERROR("%s: [rcv ted] TED received NULL message ",
			       __func__);
		return 1;
	}

	if (path_ted_get_current_igp(msg->data.node->adv.origin))
		return 1;

	switch (msg->type) {
	case LS_MSG_TYPE_NODE:
		ls_msg2vertex(ted_state_g.ted, msg, true /*hard delete*/);
		break;

	case LS_MSG_TYPE_ATTRIBUTES:
		ls_msg2edge(ted_state_g.ted, msg, true /*ĥard delete*/);
		break;

	case LS_MSG_TYPE_PREFIX:
		ls_msg2subnet(ted_state_g.ted, msg, true /*hard delete*/);
		break;

	default:
		PATH_TED_DEBUG(
			"%s: [rcv ted] TED received unknown message type [%d]",
			__func__, msg->type);
		break;
	}
	return 0;
}

uint32_t path_ted_query_type_f(struct ipaddr *local, struct ipaddr *remote)
{
	uint32_t sid = MPLS_LABEL_NONE;
	struct ls_edge *edge;
	struct ls_edge_key key;

	if (!path_ted_is_initialized())
		return MPLS_LABEL_NONE;

	if (!local || !remote)
		return MPLS_LABEL_NONE;

	switch (local->ipa_type) {
	case IPADDR_V4:
		/* We have local and remote ip */
		/* so check all attributes in ted */
		key.family = AF_INET;
		IPV4_ADDR_COPY(&key.k.addr, &local->ip._v4_addr);
		edge = ls_find_edge_by_key(ted_state_g.ted, key);
		if (edge) {
			if (edge->attributes->standard.remote.s_addr
				    == remote->ip._v4_addr.s_addr
			    && CHECK_FLAG(edge->attributes->flags,
					  LS_ATTR_ADJ_SID)) {
				sid = edge->attributes->adj_sid[0]
					      .sid; /* from primary */
				break;
			}
		}
		break;
	case IPADDR_V6:
		key.family = AF_INET6;
		IPV6_ADDR_COPY(&key.k.addr6, &local->ip._v6_addr);
		edge = ls_find_edge_by_key(ted_state_g.ted, key);
		if (edge) {
			if ((0 == memcmp(&edge->attributes->standard.remote6,
					 &remote->ip._v6_addr,
					 sizeof(remote->ip._v6_addr)) &&
			     CHECK_FLAG(edge->attributes->flags,
					LS_ATTR_ADJ_SID6))) {
				sid = edge->attributes->adj_sid[ADJ_PRI_IPV6]
					      .sid; /* from primary */
				break;
			}
		}
		break;
	case IPADDR_NONE:
		break;
	}

	return sid;
}

uint32_t path_ted_query_type_c(struct prefix *prefix, uint8_t algo)
{
	uint32_t sid = MPLS_LABEL_NONE;
	struct ls_subnet *subnet;

	if (!path_ted_is_initialized())
		return MPLS_LABEL_NONE;

	if (!prefix)
		return MPLS_LABEL_NONE;

	switch (prefix->family) {
	case AF_INET:
	case AF_INET6:
		subnet = ls_find_subnet(ted_state_g.ted, prefix);
		if (subnet) {
			if ((CHECK_FLAG(subnet->ls_pref->flags, LS_PREF_SR))
			    && (subnet->ls_pref->sr.algo == algo))
				sid = subnet->ls_pref->sr.sid;
		}
		break;
	default:
		break;
	}

	return sid;
}

uint32_t path_ted_query_type_e(struct prefix *prefix, uint32_t iface_id)
{
	uint32_t sid = MPLS_LABEL_NONE;
	struct ls_subnet *subnet;
	struct listnode *lst_node;
	struct ls_edge *edge;

	if (!path_ted_is_initialized())
		return MPLS_LABEL_NONE;

	if (!prefix)
		return MPLS_LABEL_NONE;

	switch (prefix->family) {
	case AF_INET:
	case AF_INET6:
		subnet = ls_find_subnet(ted_state_g.ted, prefix);
		if (subnet && subnet->vertex
		    && subnet->vertex->outgoing_edges) {
			/* from the vertex linked in subnet */
			/* loop over outgoing edges */
			for (ALL_LIST_ELEMENTS_RO(
				     subnet->vertex->outgoing_edges, lst_node,
				     edge)) {
				/* and look for ifaceid */
				/* so get sid of attribute */
				if (CHECK_FLAG(edge->attributes->flags,
					       LS_ATTR_LOCAL_ID)
				    && edge->attributes->standard.local_id
					       == iface_id) {
					sid = subnet->ls_pref->sr.sid;
					break;
				}
			}
		}
		break;
	default:
		break;
	}

	return sid;
}

DEFPY (debug_path_ted,
       debug_path_ted_cmd,
       "[no] debug pathd mpls-te",
       NO_STR
       DEBUG_STR
       "path debugging\n"
       "ted debugging\n")
{
	uint32_t mode = DEBUG_NODE2MODE(vty->node);

	DEBUG_MODE_SET(&ted_state_g.dbg, mode, !no);
	return CMD_SUCCESS;
}

/*
 * Following are vty command functions.
 */
/* clang-format off */
DEFUN (path_ted_on,
       path_ted_on_cmd,
       "mpls-te on",
       NO_STR
       "Enable the TE database (TED) functionality\n")
/* clang-format on */
{

	if (ted_state_g.enabled) {
		PATH_TED_DEBUG("%s: PATHD-TED: Enabled ON -> ON.", __func__);
		return CMD_SUCCESS;
	}

	ted_state_g.ted = path_ted_create_ted();
	ted_state_g.enabled = true;
	PATH_TED_DEBUG("%s: PATHD-TED: Enabled OFF -> ON.", __func__);

	return CMD_SUCCESS;
}

/* clang-format off */
DEFUN (no_path_ted,
       no_path_ted_cmd,
       "no mpls-te [on]",
       NO_STR
       NO_STR
       "Disable the TE Database functionality\n")
/* clang-format on */
{
	if (!ted_state_g.enabled) {
		PATH_TED_DEBUG("%s: PATHD-TED: OFF -> OFF", __func__);
		return CMD_SUCCESS;
	}

	/* Remove TED */
	ls_ted_del_all(&ted_state_g.ted);
	ted_state_g.enabled = false;
	PATH_TED_DEBUG("%s: PATHD-TED: ON -> OFF", __func__);
	ted_state_g.import = IMPORT_UNKNOWN;
	if (ls_unregister(zclient, false /*client*/) != 0) {
		vty_out(vty, "Unable to unregister Link State\n");
		return CMD_WARNING;
	}

	return CMD_SUCCESS;
}

/* clang-format off */
DEFPY(path_ted_import,
       path_ted_import_cmd,
       "mpls-te import <ospfv2|ospfv3|isis>$import_daemon",
       "Enable the TE database (TED) fill with remote igp data\n"
       "import\n"
       "Origin ospfv2\n"
       "Origin ospfv3\n"
       "Origin isis\n")
/* clang-format on */
{

	if (ted_state_g.enabled)
		if (path_ted_start_importing_igp(import_daemon)) {
			vty_out(vty, "Unable to start importing\n");
			return CMD_WARNING;
		}
	return CMD_SUCCESS;
}

/* clang-format off */
DEFUN (no_path_ted_import,
       no_path_ted_import_cmd,
       "no mpls-te import",
       NO_STR
       NO_STR
       "Disable the TE Database fill with remote igp data\n")
/* clang-format on */
{

	if (ted_state_g.import) {
		if (path_ted_stop_importing_igp()) {
			vty_out(vty, "Unable to stop importing\n");
			return CMD_WARNING;
		} else {
			PATH_TED_DEBUG(
				"%s: PATHD-TED: Importing igp data already OFF",
				__func__);
		}
	}
	return CMD_SUCCESS;
}

/* clang-format off */
DEFPY (show_pathd_ted_db,
       show_pathd_ted_db_cmd,
       "show pathd ted database <verbose|json>$ver_json ",
       "show command\n"
       "pathd daemon\n"
       "traffic eng\n"
       "database\n"
       "verbose output\n"
       "Show complete received TED database\n")
/* clang-format on */
{
	bool st_json = false;
	json_object *json = NULL;

	if (!ted_state_g.enabled) {
		vty_out(vty, "Traffic Engineering database is not enabled\n");
		return CMD_WARNING;
	}
	if (strcmp(ver_json, "json") == 0) {
		st_json = true;
		json = json_object_new_object();
	}
	/* Show the complete TED */
	ls_show_ted(ted_state_g.ted, vty, json, !st_json);
	if (st_json)
		vty_json(vty, json);
	return CMD_SUCCESS;
}

/**
 * Help fn to show ted related configuration
 *
 * @param vty
 *
 * @return		Status
 */
uint32_t path_ted_config_write(struct vty *vty)
{

	if (ted_state_g.enabled) {
		vty_out(vty, "  mpls-te on\n");
		switch (ted_state_g.import) {
		case IMPORT_ISIS:
			vty_out(vty, "  mpls-te import isis\n");
			break;
		case IMPORT_OSPFv2:
			vty_out(vty, "  mpls-te import ospfv2\n");
			break;
		case IMPORT_OSPFv3:
			vty_out(vty, "  mpls-te import ospfv3\n");
			break;
		case IMPORT_UNKNOWN:
			break;
		}
	}
	return 0;
}

/**
 * Register the fn's for CLI and hook for config show
 *
 * @param void
 *
 */
static void path_ted_register_vty(void)
{
	install_element(VIEW_NODE, &show_pathd_ted_db_cmd);
	install_element(SR_TRAFFIC_ENG_NODE, &path_ted_on_cmd);
	install_element(SR_TRAFFIC_ENG_NODE, &no_path_ted_cmd);
	install_element(SR_TRAFFIC_ENG_NODE, &path_ted_import_cmd);
	install_element(SR_TRAFFIC_ENG_NODE, &no_path_ted_import_cmd);

	install_element(CONFIG_NODE, &debug_path_ted_cmd);
	install_element(ENABLE_NODE, &debug_path_ted_cmd);

	debug_install(&ted_state_g.dbg);
}

/**
 * UnRegister the fn's for CLI and hook for config show
 *
 * @param void
 *
 */
static void path_ted_unregister_vty(void)
{
	uninstall_element(VIEW_NODE, &show_pathd_ted_db_cmd);
	uninstall_element(SR_TRAFFIC_ENG_NODE, &path_ted_on_cmd);
	uninstall_element(SR_TRAFFIC_ENG_NODE, &no_path_ted_cmd);
	uninstall_element(SR_TRAFFIC_ENG_NODE, &path_ted_import_cmd);
	uninstall_element(SR_TRAFFIC_ENG_NODE, &no_path_ted_import_cmd);
}

/**
 * Ask igp for a complete TED so far
 *
 * @param void
 *
 * @return		zclient status
 */
enum zclient_send_status path_ted_link_state_sync(void)
{
	enum zclient_send_status status;

	status = ls_request_sync(zclient);
	if (status == -1) {
		PATH_TED_ERROR(
			"%s: PATHD-TED: Opaque error asking for TED sync ",
			__func__);
		return status;
	} else {
		PATH_TED_DEBUG("%s: PATHD-TED: Opaque asked for TED sync ",
			       __func__);
	}
	event_add_timer(ted_state_g.main, path_ted_timer_handler_sync,
			&ted_state_g, ted_state_g.link_state_delay_interval,
			&ted_state_g.t_link_state_sync);

	return status;
}

/**
 * Timer cb for check link state sync
 *
 * @param thread	Current thread
 *
 * @return		status
 */
void path_ted_timer_handler_sync(struct event *thread)
{
	/* data unpacking */
	struct ted_state *data = EVENT_ARG(thread);

	assert(data != NULL);
	/* Retry the sync */
	path_ted_link_state_sync();
}

/**
 * refresg segment list and create timer to keep up updated
 *
 * @param void
 *
 * @return		status
 */
int path_ted_segment_list_refresh(void)
{
	int status = 0;

	path_ted_timer_refresh_cancel();
	event_add_timer(ted_state_g.main, path_ted_timer_handler_refresh,
			&ted_state_g, ted_state_g.segment_list_refresh_interval,
			&ted_state_g.t_segment_list_refresh);

	return status;
}

/**
 * Timer cb for refreshing sid in segment lists
 *
 * @param void
 *
 * @return		status
 */
void path_ted_timer_handler_refresh(struct event *thread)
{
	if (!path_ted_is_initialized())
		return;

	PATH_TED_DEBUG("%s: PATHD-TED: Refresh sid from current TED", __func__);
	/* data unpacking */
	struct ted_state *data = EVENT_ARG(thread);

	assert(data != NULL);

	srte_policy_update_ted_sid();
}

/**
 * Cancel sync timer
 *
 * @param void
 *
 * @return		void status
 */
void path_ted_timer_sync_cancel(void)
{
	if (ted_state_g.t_link_state_sync != NULL) {
		event_cancel(&ted_state_g.t_link_state_sync);
		ted_state_g.t_link_state_sync = NULL;
	}
}

/**
 * Cancel refresh timer
 *
 * @param void
 *
 * @return		void status
 */
void path_ted_timer_refresh_cancel(void)
{
	if (ted_state_g.t_segment_list_refresh != NULL) {
		event_cancel(&ted_state_g.t_segment_list_refresh);
		ted_state_g.t_segment_list_refresh = NULL;
	}
}

/**
 * Check which igp is configured
 *
 * @param igp who want to check against config-
 *
 * @return		status
 */
uint32_t path_ted_get_current_igp(uint32_t igp)
{
	switch (igp) {
	case ISIS_L1:
	case ISIS_L2:
		if (ted_state_g.import != IMPORT_ISIS) {
			PATH_TED_ERROR(
				"%s: [rcv ted] Incorrect igp origin wait (%s) got (%s) ",
				__func__,
				PATH_TED_IGP_PRINT(ted_state_g.import),
				LS_IGP_PRINT(igp));
			return 1;
		}
		break;
	case OSPFv2:
		if (ted_state_g.import != IMPORT_OSPFv2) {
			PATH_TED_ERROR(
				"%s: [rcv ted] Incorrect igp origin wait (%s) got (%s) ",
				__func__,
				PATH_TED_IGP_PRINT(ted_state_g.import),
				LS_IGP_PRINT(igp));
			return 1;
		}
		break;
	case STATIC:
		break;
	}
	return 0;
}
