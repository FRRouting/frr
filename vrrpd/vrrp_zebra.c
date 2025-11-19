// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * VRRP Zebra interfacing.
 * Copyright (C) 2018-2019 Cumulus Networks, Inc.
 * Quentin Young
 */
#include <zebra.h>

#include "lib/if.h"
#include "lib/linklist.h"
#include "lib/log.h"
#include "lib/prefix.h"
#include "lib/vty.h"
#include "lib/zclient.h"

#include "vrrp.h"
#include "vrrp_debug.h"
#include "vrrp_zebra.h"

#define VRRP_LOGPFX "[ZEBRA] "

static struct zclient *zclient;

static void vrrp_zebra_debug_if_state(struct interface *ifp, const char *func)
{
	DEBUGD(&vrrp_dbg_zebra,
	       "%s: %s index %d vrf %s(%u) parent %d mac %02x:%02x:%02x:%02x:%02x:%02x flags %ld metric %d mtu %d operative %d",
	       func, ifp->name, ifp->ifindex, ifp->vrf->name, ifp->vrf->vrf_id,
	       ifp->link_ifindex, ifp->hw_addr[0], ifp->hw_addr[1],
	       ifp->hw_addr[2], ifp->hw_addr[3], ifp->hw_addr[4],
	       ifp->hw_addr[5], (long)ifp->flags, ifp->metric, ifp->mtu,
	       if_is_operative(ifp));
}

static void vrrp_zebra_debug_if_dump_address(struct interface *ifp,
					     const char *func)
{
	struct connected *ifc;

	DEBUGD(&vrrp_dbg_zebra, "%s: interface %s addresses:", func, ifp->name);

	frr_each (if_connected, ifp->connected, ifc) {
		struct prefix *p = ifc->address;

		DEBUGD(&vrrp_dbg_zebra, "%s: interface %s address %pFX %s",
		       func, ifp->name, p,
		       CHECK_FLAG(ifc->flags, ZEBRA_IFA_SECONDARY) ? "secondary"
								   : "primary");
	}
}


static void vrrp_zebra_connected(struct zclient *zclient)
{
	zclient_send_reg_requests(zclient, VRF_DEFAULT);
}

/* Router-id update message from zebra. */
static int vrrp_router_id_update_zebra(int command, struct zclient *zclient,
				       zebra_size_t length, vrf_id_t vrf_id)
{
	struct prefix router_id;

	zebra_router_id_update_read(zclient->ibuf, &router_id);

	return 0;
}

int vrrp_ifp_create(struct interface *ifp)
{
	vrrp_zebra_debug_if_state(ifp, __func__);

	vrrp_if_add(ifp);

	return 0;
}

int vrrp_ifp_destroy(struct interface *ifp)
{
	vrrp_zebra_debug_if_state(ifp, __func__);

	vrrp_if_del(ifp);

	return 0;
}

int vrrp_ifp_up(struct interface *ifp)
{
	vrrp_zebra_debug_if_state(ifp, __func__);

	vrrp_if_up(ifp);

	return 0;
}

int vrrp_ifp_down(struct interface *ifp)
{
	vrrp_zebra_debug_if_state(ifp, __func__);

	vrrp_if_down(ifp);

	return 0;
}

static int vrrp_zebra_if_address_add(int command, struct zclient *zclient,
				     zebra_size_t length, vrf_id_t vrf_id)
{
	struct connected *c;

	/*
	 * zebra api notifies address adds/dels events by using the same call
	 * interface_add_read below, see comments in lib/zclient.c
	 *
	 * zebra_interface_address_read(ZEBRA_INTERFACE_ADDRESS_ADD, ...)
	 * will add address to interface list by calling
	 * connected_add_by_prefix()
	 */
	c = zebra_interface_address_read(command, zclient->ibuf, vrf_id);

	if (!c)
		return 0;

	vrrp_zebra_debug_if_state(c->ifp, __func__);
	vrrp_zebra_debug_if_dump_address(c->ifp, __func__);

	vrrp_if_address_add(c->ifp);

	return 0;
}

static int vrrp_zebra_if_address_del(int command, struct zclient *client,
				     zebra_size_t length, vrf_id_t vrf_id)
{
	struct connected *c;

	/*
	 * zebra api notifies address adds/dels events by using the same call
	 * interface_add_read below, see comments in lib/zclient.c
	 *
	 * zebra_interface_address_read(ZEBRA_INTERFACE_ADDRESS_DELETE, ...)
	 * will remove address from interface list by calling
	 * connected_delete_by_prefix()
	 */
	c = zebra_interface_address_read(command, client->ibuf, vrf_id);

	if (!c)
		return 0;

	vrrp_zebra_debug_if_state(c->ifp, __func__);
	vrrp_zebra_debug_if_dump_address(c->ifp, __func__);

	vrrp_if_address_del(c->ifp);
	connected_free(&c);

	return 0;
}

void vrrp_zebra_radv_set(struct vrrp_router *r, bool enable)
{
	DEBUGD(&vrrp_dbg_zebra,
	       VRRP_LOGPFX VRRP_LOGPFX_VRID
	       "Requesting Zebra to turn router advertisements %s for %s",
	       r->vr->vrid, enable ? "on" : "off", r->mvl_ifp->name);

	zclient_send_interface_radv_req(zclient, r->mvl_ifp->vrf->vrf_id,
					r->mvl_ifp, enable, VRRP_RADV_INT);
}

void vrrp_zclient_send_interface_protodown(struct interface *ifp, bool down)
{
	DEBUGD(&vrrp_dbg_zebra,
	       VRRP_LOGPFX "Requesting Zebra to set %s protodown %s", ifp->name,
	       down ? "on" : "off");

	zclient_send_interface_protodown(zclient, ifp->vrf->vrf_id, ifp, down);
}

static zclient_handler *const vrrp_handlers[] = {
	[ZEBRA_ROUTER_ID_UPDATE] = vrrp_router_id_update_zebra,
	[ZEBRA_INTERFACE_ADDRESS_ADD] = vrrp_zebra_if_address_add,
	[ZEBRA_INTERFACE_ADDRESS_DELETE] = vrrp_zebra_if_address_del,
};

void vrrp_zebra_init(void)
{
	hook_register_prio(if_real, 0, vrrp_ifp_create);
	hook_register_prio(if_up, 0, vrrp_ifp_up);
	hook_register_prio(if_down, 0, vrrp_ifp_down);
	hook_register_prio(if_unreal, 0, vrrp_ifp_destroy);

	/* Socket for receiving updates from Zebra daemon */
	zclient = zclient_new(master, &zclient_options_default, vrrp_handlers,
			      array_size(vrrp_handlers));

	zclient->zebra_connected = vrrp_zebra_connected;

	zclient_init(zclient, ZEBRA_ROUTE_VRRP, 0, &vrrp_privs);

	zlog_notice("%s: zclient socket initialized", __func__);
}
