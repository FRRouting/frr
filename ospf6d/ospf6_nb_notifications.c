// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * OSPFv3 northbound notifications (RFC 9129 ietf-ospf).
 * Copyright (C) 2026  Eric Parsonage
 *
 * Wires the existing ospf6_neighbor_change / ospf6_interface_change /
 * GR helper hooks to the YANG notification dispatcher so mgmtd (and any
 * frontend subscribed to it) sees an ietf-ospf event each time an
 * OSPFv3 state transitions.
 */

#include <zebra.h>

#include "debug.h"
#include "if.h"
#include "linklist.h"
#include "log.h"
#include "northbound.h"
#include "vrf.h"
#include "yang.h"
#include "yang_wrappers.h"

#include "ospf6d/ospf6d.h"
#include "ospf6d/ospf6_area.h"
#include "ospf6d/ospf6_tlv.h"
#include "ospf6d/ospf6_gr.h"
#include "ospf6d/ospf6_interface.h"
#include "ospf6d/ospf6_neighbor.h"
#include "ospf6d/ospf6_top.h"
#include "ospf6_nb.h"

#define _dbg(fmt, ...) DEBUGD(&nb_dbg_notif, "OSPF6-NOTIF: %s: " fmt, __func__, ##__VA_ARGS__)

/*
 * OSPFv3 NSM state values already match RFC 9129's nbr-state-type 1:1
 * (down=1, attempt=2, init=3, twoway=4, exstart=5, exchange=6,
 * loading=7, full=8), so no lookup table is needed.
 */
static int ospf6d_ietf_nbr_state_yang(int nsm_state)
{
	if (nsm_state >= OSPF6_NEIGHBOR_DOWN && nsm_state <= OSPF6_NEIGHBOR_FULL)
		return nsm_state;
	return -1;
}


/*
 * OSPFv3 ISM state codes deviate from RFC 9129's `if-state-type`:
 * FRR reserves 5 (skipped) and orders DROther=6, BDR=7, DR=8, while the
 * RFC orders dr=5, bdr=6, dr-other=7.  Translate via switch.
 *
 * FRR reserves OSPF6_INTERFACE_NONE (0) for the pre-init lifecycle slot.
 * It folds into the RFC's `down` so an interface lifecycle transition
 * through that state stays observable through if-state-change rather
 * than disappearing into a -1 returned by the default arm.
 */
static int ospf6d_ietf_if_state_yang(int ism_state)
{
	switch (ism_state) {
	case OSPF6_INTERFACE_NONE:
	case OSPF6_INTERFACE_DOWN:
		return 1; /* down */
	case OSPF6_INTERFACE_LOOPBACK:
		return 2; /* loopback */
	case OSPF6_INTERFACE_WAITING:
		return 3; /* waiting */
	case OSPF6_INTERFACE_POINTTOPOINT:
		return 4; /* point-to-point */
	case OSPF6_INTERFACE_DR:
		return 5; /* dr */
	case OSPF6_INTERFACE_BDR:
		return 6; /* bdr */
	case OSPF6_INTERFACE_DROTHER:
		return 7; /* dr-other */
	default:
		return -1;
	}
}

static void ospf6d_ietf_notif_add_instance_hdr(struct list *args, const char *xpath,
					       const struct ospf6 *ospf6)
{
	char xpath_arg[XPATH_MAXLEN];

	snprintf(xpath_arg, sizeof(xpath_arg), "%s/routing-protocol-name", xpath);
	listnode_add(args, yang_data_new_string(xpath_arg,
						ospf6d_ietf_ospf_instance_name(ospf6)));

	snprintf(xpath_arg, sizeof(xpath_arg), "%s/address-family", xpath);
	listnode_add(args, yang_data_new_string(xpath_arg, "ipv6"));
}

static void ospf6d_ietf_notif_add_interface_hdr(struct list *args, const char *xpath,
						const struct interface *ifp)
{
	char xpath_arg[XPATH_MAXLEN];

	snprintf(xpath_arg, sizeof(xpath_arg), "%s/interface/interface", xpath);
	listnode_add(args, yang_data_new_string(xpath_arg, ifp->name));
}

static void ospf6d_ietf_notif_add_neighbor_hdr(struct list *args, const char *xpath,
					       const struct ospf6_neighbor *on)
{
	char xpath_arg[XPATH_MAXLEN];
	char buf[INET6_ADDRSTRLEN];
	struct in_addr rid;

	rid.s_addr = on->router_id;
	snprintf(xpath_arg, sizeof(xpath_arg), "%s/neighbor-router-id", xpath);
	inet_ntop(AF_INET, &rid, buf, sizeof(buf));
	listnode_add(args, yang_data_new_string(xpath_arg, buf));

	snprintf(xpath_arg, sizeof(xpath_arg), "%s/neighbor-ip-addr", xpath);
	inet_ntop(AF_INET6, &on->linklocal_addr, buf, sizeof(buf));
	listnode_add(args, yang_data_new_string(xpath_arg, buf));
}

/*
 * XPath: /ietf-ospf:nbr-state-change
 *
 * Emitted on every NSM transition.  The OSPF-v3 hook fires after the state
 * change has been recorded in `on->state`; the `next_state` and `prev_state`
 * arguments come from the hook signature.
 */
static int ospf6d_ietf_nbr_state_change(struct ospf6_neighbor *on, int next_state, int prev_state)
{
	const char *xpath = "/ietf-ospf:nbr-state-change";
	struct list *args;
	char xpath_arg[XPATH_MAXLEN];
	int yang_state;

	yang_state = ospf6d_ietf_nbr_state_yang(next_state);
	if (yang_state < 0)
		return 0;
	(void)prev_state;

	if (!on->ospf6_if || !on->ospf6_if->interface || !on->ospf6_if->area ||
	    !on->ospf6_if->area->ospf6)
		return 0;

	args = yang_data_list_new();
	ospf6d_ietf_notif_add_instance_hdr(args, xpath, on->ospf6_if->area->ospf6);
	ospf6d_ietf_notif_add_interface_hdr(args, xpath, on->ospf6_if->interface);
	ospf6d_ietf_notif_add_neighbor_hdr(args, xpath, on);

	snprintf(xpath_arg, sizeof(xpath_arg), "%s/state", xpath);
	listnode_add(args, yang_data_new_enum(xpath_arg, yang_state));

	_dbg("nbr router-id 0x%08x on %s state %d", ntohl(on->router_id),
	     on->ospf6_if->interface->name, next_state);

	nb_notification_send(xpath, args);
	return 0;
}

/*
 * XPath: /ietf-ospf:if-state-change
 *
 * Emitted on every OSPFv3 ISM transition.  The hook fires after the state
 * has been swapped in.  `old_state` is unused by the RFC notification but
 * passed by the hook caller.
 */
static int ospf6d_ietf_if_state_change(struct ospf6_interface *oi, int state, int old_state)
{
	const char *xpath = "/ietf-ospf:if-state-change";
	struct list *args;
	char xpath_arg[XPATH_MAXLEN];
	int yang_state;

	yang_state = ospf6d_ietf_if_state_yang(state);
	if (yang_state < 0)
		return 0;
	(void)old_state;

	if (!oi->interface || !oi->area || !oi->area->ospf6)
		return 0;

	args = yang_data_list_new();
	ospf6d_ietf_notif_add_instance_hdr(args, xpath, oi->area->ospf6);
	ospf6d_ietf_notif_add_interface_hdr(args, xpath, oi->interface);

	snprintf(xpath_arg, sizeof(xpath_arg), "%s/state", xpath);
	listnode_add(args, yang_data_new_enum(xpath_arg, yang_state));

	_dbg("iface %s state %d", oi->interface->name, state);

	nb_notification_send(xpath, args);
	return 0;
}

/*
 * Translate FRR's `ospf6_helper_exit_reason` (0..4) into RFC 9129's
 * `restart-exit-reason-type` (1..5).  Same names in the same order,
 * just offset by 1.
 */
static int ospf6d_ietf_helper_exit_reason_yang(int exit_reason)
{
	switch (exit_reason) {
	case OSPF6_GR_HELPER_EXIT_NONE:
		return 1; /* none */
	case OSPF6_GR_HELPER_INPROGRESS:
		return 2; /* in-progress */
	case OSPF6_GR_HELPER_COMPLETED:
		return 3; /* completed */
	case OSPF6_GR_HELPER_GRACE_TIMEOUT:
		return 4; /* timed-out */
	case OSPF6_GR_HELPER_TOPO_CHG:
		return 5; /* topology-changed */
	default:
		/*
		 * Caller logs and suppresses.  Returning `none` here would
		 * falsely report "helper has not exited" for an exit that
		 * just happened for an unfamiliar reason.
		 */
		return -1;
	}
}

static bool ospf6d_ietf_restart_status_valid(int status)
{
	return status >= 1 && status <= 3;
}

static bool ospf6d_ietf_helper_status_valid(int status)
{
	return status >= 1 && status <= 2;
}

/*
 * XPath: /ietf-ospf:restart-status-change
 *
 * Emit when the local OSPFv3 instance transitions in/out of graceful-
 * restart.  status follows RFC restart-status-type values.
 */
void ospf6d_ietf_notif_restart_status_change(struct ospf6 *ospf6, int status, int exit_reason)
{
	const char *xpath = "/ietf-ospf:restart-status-change";
	struct list *args;
	char xpath_arg[XPATH_MAXLEN];
	int yang_exit;

	if (!ospf6)
		return;

	if (!ospf6d_ietf_restart_status_valid(status)) {
		zlog_warn("%s: unrecognised GR restart status %d, suppressing notification",
			  __func__, status);
		return;
	}

	args = yang_data_list_new();
	ospf6d_ietf_notif_add_instance_hdr(args, xpath, ospf6);

	snprintf(xpath_arg, sizeof(xpath_arg), "%s/status", xpath);
	listnode_add(args, yang_data_new_enum(xpath_arg, status));

	snprintf(xpath_arg, sizeof(xpath_arg), "%s/restart-interval", xpath);
	listnode_add(args, yang_data_new_uint16(xpath_arg, ospf6->gr_info.grace_period));

	yang_exit = ospf6d_ietf_helper_exit_reason_yang(exit_reason);
	if (yang_exit < 0) {
		zlog_warn("%s: unrecognised GR exit reason %d, suppressing notification",
			  __func__, exit_reason);
		list_delete(&args);
		return;
	}
	snprintf(xpath_arg, sizeof(xpath_arg), "%s/exit-reason", xpath);
	listnode_add(args, yang_data_new_enum(xpath_arg, yang_exit));

	_dbg("instance %s gr status %d exit %d", ospf6->name ?: VRF_DEFAULT_NAME, status,
	     exit_reason);
	nb_notification_send(xpath, args);
}

/*
 * XPath: /ietf-ospf:nbr-restart-helper-status-change
 *
 * Emit when this router enters or leaves helper mode for an OSPFv3
 * neighbour's graceful restart.
 */
void ospf6d_ietf_notif_nbr_restart_helper_status_change(struct ospf6_neighbor *on, int status,
							uint16_t age, int exit_reason)
{
	const char *xpath = "/ietf-ospf:nbr-restart-helper-status-change";
	struct list *args;
	char xpath_arg[XPATH_MAXLEN];
	int yang_exit;

	if (!on || !on->ospf6_if || !on->ospf6_if->interface || !on->ospf6_if->area ||
	    !on->ospf6_if->area->ospf6)
		return;

	if (!ospf6d_ietf_helper_status_valid(status)) {
		zlog_warn("%s: unrecognised GR helper status %d, suppressing notification",
			  __func__, status);
		return;
	}

	args = yang_data_list_new();
	ospf6d_ietf_notif_add_instance_hdr(args, xpath, on->ospf6_if->area->ospf6);
	ospf6d_ietf_notif_add_interface_hdr(args, xpath, on->ospf6_if->interface);
	ospf6d_ietf_notif_add_neighbor_hdr(args, xpath, on);

	snprintf(xpath_arg, sizeof(xpath_arg), "%s/status", xpath);
	listnode_add(args, yang_data_new_enum(xpath_arg, status));

	snprintf(xpath_arg, sizeof(xpath_arg), "%s/age", xpath);
	listnode_add(args, yang_data_new_uint16(xpath_arg, age));

	yang_exit = ospf6d_ietf_helper_exit_reason_yang(exit_reason);
	if (yang_exit < 0) {
		zlog_warn("%s: unrecognised GR helper exit reason %d, suppressing notification",
			  __func__, exit_reason);
		list_delete(&args);
		return;
	}
	snprintf(xpath_arg, sizeof(xpath_arg), "%s/exit-reason", xpath);
	listnode_add(args, yang_data_new_enum(xpath_arg, yang_exit));

	_dbg("nbr router-id 0x%08x helper status %d exit %d", ntohl(on->router_id), status,
	     exit_reason);
	nb_notification_send(xpath, args);
}
void ospf6d_ietf_notif_init(void)
{
	hook_register(ospf6_neighbor_change, ospf6d_ietf_nbr_state_change);
	hook_register(ospf6_interface_change, ospf6d_ietf_if_state_change);
}
