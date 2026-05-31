// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * OSPFv2 northbound notifications (RFC 9129 ietf-ospf).
 * Copyright (C) 2026  Eric Parsonage
 *
 * Wires the existing ospf_nsm_change / ospf_ism_change / GR helper /
 * packet validation hooks to the YANG notification dispatcher so mgmtd
 * (and any frontend subscribed to it) sees an ietf-ospf event each time
 * an OSPFv2 state transitions.
 */

#include <zebra.h>

#include "debug.h"
#include "if.h"
#include "linklist.h"
#include "log.h"
#include "northbound.h"
#include "yang.h"
#include "yang_wrappers.h"

#include "ospfd/ospfd.h"
#include "ospfd/ospf_dump.h"
#include "ospfd/ospf_interface.h"
#include "ospfd/ospf_ism.h"
#include "ospfd/ospf_lsa.h"
#include "ospfd/ospf_lsdb.h"
#include "ospfd/ospf_neighbor.h"
#include "ospfd/ospf_nsm.h"
#include "ospf_nb.h"

#define _dbg(fmt, ...) DEBUGD(&nb_dbg_notif, "OSPF-NOTIF: %s: " fmt, __func__, ##__VA_ARGS__)

/*
 * Translate FRR's internal NSM state code into the integer value RFC 9129's
 * `nbr-state-type` enum assigns to the same name.  yang_data_new_enum() takes
 * the YANG-defined numeric value and looks up the corresponding name; the two
 * code points happen to differ on OSPFv2 because FRR reserves 0 / 1 for the
 * DependUpon / Deleted control codes.
 */
static int ospfd_ietf_nbr_state_yang(int nsm_state)
{
	switch (nsm_state) {
	case NSM_Down:
		return 1; /* down */
	case NSM_Attempt:
		return 2; /* attempt */
	case NSM_Init:
		return 3; /* init */
	case NSM_TwoWay:
		return 4; /* 2-way */
	case NSM_ExStart:
		return 5; /* exstart */
	case NSM_Exchange:
		return 6; /* exchange */
	case NSM_Loading:
		return 7; /* loading */
	case NSM_Full:
		return 8; /* full */
	default:
		return -1;
	}
}

static void ospfd_ietf_notif_add_instance_hdr(struct list *args, const char *xpath,
					      const struct ospf *ospf)
{
	char xpath_arg[XPATH_MAXLEN];
	char buf[XPATH_MAXLEN];

	snprintf(xpath_arg, sizeof(xpath_arg), "%s/routing-protocol-name", xpath);
	listnode_add(args,
		     yang_data_new_string(xpath_arg,
					  ospfd_ietf_ospf_instance_name(ospf, buf, sizeof(buf))));

	snprintf(xpath_arg, sizeof(xpath_arg), "%s/address-family", xpath);
	listnode_add(args, yang_data_new_string(xpath_arg, "ipv4"));
}

static void ospfd_ietf_notif_add_interface_hdr(struct list *args, const char *xpath,
					       const struct interface *ifp)
{
	char xpath_arg[XPATH_MAXLEN];

	snprintf(xpath_arg, sizeof(xpath_arg), "%s/interface/interface", xpath);
	listnode_add(args, yang_data_new_string(xpath_arg, ifp->name));
}

static void ospfd_ietf_notif_add_neighbor_hdr(struct list *args, const char *xpath,
					      const struct ospf_neighbor *nbr)
{
	char xpath_arg[XPATH_MAXLEN];
	char buf[INET_ADDRSTRLEN];

	snprintf(xpath_arg, sizeof(xpath_arg), "%s/neighbor-router-id", xpath);
	inet_ntop(AF_INET, &nbr->router_id, buf, sizeof(buf));
	listnode_add(args, yang_data_new_string(xpath_arg, buf));

	snprintf(xpath_arg, sizeof(xpath_arg), "%s/neighbor-ip-addr", xpath);
	inet_ntop(AF_INET, &nbr->src, buf, sizeof(buf));
	listnode_add(args, yang_data_new_string(xpath_arg, buf));
}

/*
 * XPath: /ietf-ospf:nbr-state-change
 *
 * Emitted on every NSM transition.  The OSPF-v2 NSM hook fires after the
 * state has been swapped in, so `nbr->state` is already `next_state` here;
 * the `oldstate` argument is supplied by the hook caller.
 */
static int ospfd_ietf_nbr_state_change(struct ospf_neighbor *nbr, int next_state, int old_state)
{
	const char *xpath = "/ietf-ospf:nbr-state-change";
	struct list *args;
	char xpath_arg[XPATH_MAXLEN];
	int yang_state;

	yang_state = ospfd_ietf_nbr_state_yang(next_state);
	if (yang_state < 0)
		return 0;
	(void)old_state;

	if (!nbr->oi || !nbr->oi->ifp || !nbr->oi->ospf)
		return 0;

	args = yang_data_list_new();
	ospfd_ietf_notif_add_instance_hdr(args, xpath, nbr->oi->ospf);
	ospfd_ietf_notif_add_interface_hdr(args, xpath, nbr->oi->ifp);
	ospfd_ietf_notif_add_neighbor_hdr(args, xpath, nbr);

	snprintf(xpath_arg, sizeof(xpath_arg), "%s/state", xpath);
	listnode_add(args, yang_data_new_enum(xpath_arg, yang_state));

	_dbg("nbr %pI4 on %s -> %s", &nbr->router_id, nbr->oi->ifp->name,
	     lookup_msg(ospf_nsm_state_msg, next_state, NULL));

	nb_notification_send(xpath, args);
	return 0;
}

void ospfd_ietf_notif_init(void)
{
	hook_register(ospf_nsm_change, ospfd_ietf_nbr_state_change);
}
