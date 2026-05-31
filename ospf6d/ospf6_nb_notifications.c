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

void ospf6d_ietf_notif_init(void)
{
	hook_register(ospf6_neighbor_change, ospf6d_ietf_nbr_state_change);
}
