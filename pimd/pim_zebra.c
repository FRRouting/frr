// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * PIM for Quagga
 * Copyright (C) 2008  Everton da Silva Marques
 */

#include <zebra.h>

#include "if.h"
#include "log.h"
#include "prefix.h"
#include "zclient.h"
#include "stream.h"
#include "network.h"
#include "vty.h"
#include "plist.h"
#include "lib/bfd.h"

#include "pimd.h"
#include "pim_pim.h"
#include "pim_zebra.h"
#include "pim_iface.h"
#include "pim_str.h"
#include "pim_oil.h"
#include "pim_rpf.h"
#include "pim_time.h"
#include "pim_join.h"
#include "pim_zlookup.h"
#include "pim_ifchannel.h"
#include "pim_rp.h"
#include "pim_igmpv3.h"
#include "pim_jp_agg.h"
#include "pim_nht.h"
#include "pim_ssm.h"
#include "pim_vxlan.h"
#include "pim_mlag.h"

#undef PIM_DEBUG_IFADDR_DUMP
#define PIM_DEBUG_IFADDR_DUMP

struct zclient *zclient;


/* Router-id update message from zebra. */
static int pim_router_id_update_zebra(ZAPI_CALLBACK_ARGS)
{
	struct prefix router_id;

	zebra_router_id_update_read(zclient->ibuf, &router_id);

	return 0;
}

#ifdef PIM_DEBUG_IFADDR_DUMP
static void dump_if_address(struct interface *ifp)
{
	struct connected *ifc;

	zlog_debug("%s %s: interface %s addresses:", __FILE__, __func__,
		   ifp->name);

	frr_each (if_connected, ifp->connected, ifc) {
		struct prefix *p = ifc->address;

		if (p->family != AF_INET)
			continue;

		zlog_debug("%s %s: interface %s address %pI4 %s", __FILE__,
			   __func__, ifp->name, &p->u.prefix4,
			   CHECK_FLAG(ifc->flags, ZEBRA_IFA_SECONDARY)
				   ? "secondary"
				   : "primary");
	}
}
#endif

static int pim_zebra_if_address_add(ZAPI_CALLBACK_ARGS)
{
	struct connected *c;
	struct prefix *p;
	struct pim_interface *pim_ifp;

	/*
	  zebra api notifies address adds/dels events by using the same call
	  interface_add_read below, see comments in lib/zclient.c

	  zebra_interface_address_read(ZEBRA_INTERFACE_ADDRESS_ADD, ...)
	  will add address to interface list by calling
	  connected_add_by_prefix()
	*/
	c = zebra_interface_address_read(cmd, zclient->ibuf, vrf_id);
	if (!c)
		return 0;

	pim_ifp = c->ifp->info;
	p = c->address;

	if (PIM_DEBUG_ZEBRA) {
		zlog_debug("%s: %s(%s) connected IP address %pFX flags %u %s",
			   __func__, c->ifp->name,
			   (pim_ifp ? VRF_LOGNAME(pim_ifp->pim->vrf)
				    : "Unknown"),
			   p, c->flags,
			   CHECK_FLAG(c->flags, ZEBRA_IFA_SECONDARY)
				   ? "secondary"
				   : "primary");

#ifdef PIM_DEBUG_IFADDR_DUMP
		dump_if_address(c->ifp);
#endif
	}

#if PIM_IPV == 4
	if (p->family != PIM_AF)
		SET_FLAG(c->flags, ZEBRA_IFA_SECONDARY);
	else if (!CHECK_FLAG(c->flags, ZEBRA_IFA_SECONDARY)) {
		/* trying to add primary address? */
		pim_addr primary_addr = pim_find_primary_addr(c->ifp);
		pim_addr addr = pim_addr_from_prefix(p);

		if (pim_addr_cmp(primary_addr, addr)) {
			if (PIM_DEBUG_ZEBRA)
				zlog_warn(
					"%s: %s : forcing secondary flag on %pFX",
					__func__, c->ifp->name, p);
			SET_FLAG(c->flags, ZEBRA_IFA_SECONDARY);
		}
	}
#else /* PIM_IPV != 4 */
	if (p->family != PIM_AF)
		return 0;
#endif

	pim_if_addr_add(c);
	if (pim_ifp) {
		struct pim_instance *pim;

		pim = pim_get_pim_instance(vrf_id);
		if (!pim) {
			if (PIM_DEBUG_ZEBRA)
				zlog_debug("%s: Unable to find pim instance",
					   __func__);
			return 0;
		}

		pim_ifp->pim = pim;

		pim_rp_check_on_if_add(pim_ifp);
	}

	if (if_is_loopback(c->ifp)) {
		struct vrf *vrf = vrf_lookup_by_id(vrf_id);
		struct interface *ifp;

		FOR_ALL_INTERFACES (vrf, ifp) {
			if (!if_is_loopback(ifp) && if_is_operative(ifp))
				pim_if_addr_add_all(ifp);
		}
	}

	pim_cand_addrs_changed();
	return 0;
}

static int pim_zebra_if_address_del(ZAPI_CALLBACK_ARGS)
{
	struct connected *c;
	struct prefix *p;
	struct vrf *vrf = vrf_lookup_by_id(vrf_id);

	if (!vrf)
		return 0;

	/*
	  zebra api notifies address adds/dels events by using the same call
	  interface_add_read below, see comments in lib/zclient.c

	  zebra_interface_address_read(ZEBRA_INTERFACE_ADDRESS_DELETE, ...)
	  will remove address from interface list by calling
	  connected_delete_by_prefix()
	*/
	c = zebra_interface_address_read(cmd, zclient->ibuf, vrf_id);
	if (!c)
		return 0;

	p = c->address;

	if (PIM_DEBUG_ZEBRA) {
		zlog_debug(
			"%s: %s(%s) disconnected IP address %pFX flags %u %s",
			__func__, c->ifp->name, VRF_LOGNAME(vrf), p, c->flags,
			CHECK_FLAG(c->flags, ZEBRA_IFA_SECONDARY)
				? "secondary"
				: "primary");
#ifdef PIM_DEBUG_IFADDR_DUMP
		dump_if_address(c->ifp);
#endif
	}

	if (p->family == PIM_AF) {
		struct pim_instance *pim;

		pim = vrf->info;
		pim_if_addr_del(c, 0);
		pim_rp_setup(pim);
		pim_i_am_rp_re_evaluate(pim);
	}

	connected_free(&c);

	pim_cand_addrs_changed();
	return 0;
}

void pim_zebra_update_all_interfaces(struct pim_instance *pim)
{
	struct interface *ifp;

	FOR_ALL_INTERFACES (pim->vrf, ifp) {
		struct pim_interface *pim_ifp = ifp->info;
		struct pim_iface_upstream_switch *us;
		struct listnode *node;

		if (!pim_ifp)
			continue;

		for (ALL_LIST_ELEMENTS_RO(pim_ifp->upstream_switch_list, node,
					  us)) {
			struct pim_rpf rpf;

			rpf.source_nexthop.interface = ifp;
			rpf.rpf_addr = us->address;
			pim_joinprune_send(&rpf, us->us);
			pim_jp_agg_clear_group(us->us);
		}
	}
}

void pim_zebra_upstream_rpf_changed(struct pim_instance *pim,
				    struct pim_upstream *up,
				    struct pim_rpf *old)
{
	if (old->source_nexthop.interface) {
		struct pim_neighbor *nbr;

		nbr = pim_neighbor_find(old->source_nexthop.interface,
					old->rpf_addr, true);

		if (nbr)
			pim_jp_agg_remove_group(nbr->upstream_jp_agg, up, nbr);

		/*
		 * We have detected a case where we might need
		 * to rescan the inherited o_list so do it.
		 */
		if (up->channel_oil->oil_inherited_rescan) {
			pim_upstream_inherited_olist_decide(pim, up);
			up->channel_oil->oil_inherited_rescan = 0;
		}

		if (up->join_state == PIM_UPSTREAM_JOINED) {
			/*
			 * If we come up real fast we can be here
			 * where the mroute has not been installed
			 * so install it.
			 */
			if (!up->channel_oil->installed)
				pim_upstream_mroute_add(up->channel_oil,
							__func__);

			/*
			 * RFC 4601: 4.5.7.  Sending (S,G)
			 * Join/Prune Messages
			 *
			 * Transitions from Joined State
			 *
			 * RPF'(S,G) changes not due to an Assert
			 *
			 * The upstream (S,G) state machine remains
			 * in Joined state. Send Join(S,G) to the new
			 * upstream neighbor, which is the new value
			 * of RPF'(S,G).  Send Prune(S,G) to the old
			 * upstream neighbor, which is the old value
			 * of RPF'(S,G).  Set the Join Timer (JT) to
			 * expire after t_periodic seconds.
			 */
			pim_jp_agg_switch_interface(old, &up->rpf, up);

			pim_upstream_join_timer_restart(up, old);
		} /* up->join_state == PIM_UPSTREAM_JOINED */
	}

	else {
		/*
		 * We have detected a case where we might need
		 * to rescan the inherited o_list so do it.
		 */
		if (up->channel_oil->oil_inherited_rescan) {
			pim_upstream_inherited_olist_decide(pim, up);
			up->channel_oil->oil_inherited_rescan = 0;
		}

		if (up->join_state == PIM_UPSTREAM_JOINED)
			pim_jp_agg_switch_interface(old, &up->rpf, up);

		if (!up->channel_oil->installed)
			pim_upstream_mroute_add(up->channel_oil, __func__);
	}

	/* FIXME can join_desired actually be changed by pim_rpf_update()
	 * returning PIM_RPF_CHANGED ?
	 */
	pim_upstream_update_join_desired(pim, up);
}

__attribute__((unused))
static int pim_zebra_vxlan_sg_proc(ZAPI_CALLBACK_ARGS)
{
	struct stream *s;
	struct pim_instance *pim;
	pim_sgaddr sg;
	size_t prefixlen;

	pim = pim_get_pim_instance(vrf_id);
	if (!pim)
		return 0;

	s = zclient->ibuf;

	prefixlen = stream_getl(s);
	stream_get(&sg.src, s, prefixlen);
	stream_get(&sg.grp, s, prefixlen);

	if (PIM_DEBUG_ZEBRA)
		zlog_debug("%s:recv SG %s %pSG", VRF_LOGNAME(pim->vrf),
			   (cmd == ZEBRA_VXLAN_SG_ADD) ? "add" : "del", &sg);

	if (cmd == ZEBRA_VXLAN_SG_ADD)
		pim_vxlan_sg_add(pim, &sg);
	else
		pim_vxlan_sg_del(pim, &sg);

	return 0;
}

__attribute__((unused))
static void pim_zebra_vxlan_replay(void)
{
	struct stream *s = NULL;

	/* Check socket. */
	if (!zclient || zclient->sock < 0)
		return;

	s = zclient->obuf;
	stream_reset(s);

	zclient_create_header(s, ZEBRA_VXLAN_SG_REPLAY, VRF_DEFAULT);
	stream_putw_at(s, 0, stream_get_endp(s));

	zclient_send_message(zclient);
}

void pim_scan_oil(struct pim_instance *pim)
{
	struct channel_oil *c_oil;

	pim->scan_oil_last = pim_time_monotonic_sec();
	++pim->scan_oil_events;

	frr_each (rb_pim_oil, &pim->channel_oil_head, c_oil)
		pim_upstream_mroute_iif_update(c_oil, __func__);
}

static void on_rpf_cache_refresh(struct event *t)
{
	struct pim_instance *pim = EVENT_ARG(t);

	/* update kernel multicast forwarding cache (MFC) */
	pim_scan_oil(pim);

	pim->rpf_cache_refresh_last = pim_time_monotonic_sec();
	++pim->rpf_cache_refresh_events;

	// It is called as part of pim_neighbor_add
	// pim_rp_setup ();
}

void sched_rpf_cache_refresh(struct pim_instance *pim)
{
	++pim->rpf_cache_refresh_requests;

	pim_rpf_set_refresh_time(pim);

	if (pim->rpf_cache_refresher) {
		/* Refresh timer is already running */
		return;
	}

	/* Start refresh timer */

	if (PIM_DEBUG_ZEBRA) {
		zlog_debug("%s: triggering %ld msec timer", __func__,
			   router->rpf_cache_refresh_delay_msec);
	}

	event_add_timer_msec(router->master, on_rpf_cache_refresh, pim,
			     router->rpf_cache_refresh_delay_msec,
			     &pim->rpf_cache_refresher);
}

static void pim_zebra_connected(struct zclient *zclient)
{
#if PIM_IPV == 4
	/* Send the client registration */
	bfd_client_sendmsg(zclient, ZEBRA_BFD_CLIENT_REGISTER, router->vrf_id);
#endif

	zclient_send_reg_requests(zclient, router->vrf_id);

#if PIM_IPV == 4
	/* request for VxLAN BUM group addresses */
	pim_zebra_vxlan_replay();
#endif
}

static void pim_zebra_capabilities(struct zclient_capabilities *cap)
{
	router->mlag_role = cap->role;
	router->multipath = cap->ecmp;
}

static zclient_handler *const pim_handlers[] = {
	[ZEBRA_INTERFACE_ADDRESS_ADD] = pim_zebra_if_address_add,
	[ZEBRA_INTERFACE_ADDRESS_DELETE] = pim_zebra_if_address_del,

	[ZEBRA_ROUTER_ID_UPDATE] = pim_router_id_update_zebra,

#if PIM_IPV == 4
	[ZEBRA_VXLAN_SG_ADD] = pim_zebra_vxlan_sg_proc,
	[ZEBRA_VXLAN_SG_DEL] = pim_zebra_vxlan_sg_proc,

	[ZEBRA_MLAG_PROCESS_UP] = pim_zebra_mlag_process_up,
	[ZEBRA_MLAG_PROCESS_DOWN] = pim_zebra_mlag_process_down,
	[ZEBRA_MLAG_FORWARD_MSG] = pim_zebra_mlag_handle_msg,
#endif
};

void pim_zebra_init(void)
{
	/* Socket for receiving updates from Zebra daemon */
	zclient = zclient_new(router->master, &zclient_options_default,
			      pim_handlers, array_size(pim_handlers));

	zclient->zebra_capabilities = pim_zebra_capabilities;
	zclient->zebra_connected = pim_zebra_connected;
	zclient->nexthop_update = pim_nexthop_update;

	zclient_init(zclient, ZEBRA_ROUTE_PIM, 0, &pimd_privs);
	if (PIM_DEBUG_PIM_TRACE) {
		zlog_notice("%s: zclient socket initialized", __func__);
	}

	zclient_lookup_new();
}

void pim_forward_start(struct pim_ifchannel *ch)
{
	struct pim_upstream *up = ch->upstream;
	uint32_t mask = 0;

	if (PIM_DEBUG_PIM_TRACE)
		zlog_debug("%s: (S,G)=%pSG oif=%s (%pPA)", __func__, &ch->sg,
			   ch->interface->name, &up->upstream_addr);

	if (PIM_IF_FLAG_TEST_PROTO_IGMP(ch->flags))
		mask = PIM_OIF_FLAG_PROTO_GM;

	if (PIM_IF_FLAG_TEST_PROTO_PIM(ch->flags))
		mask |= PIM_OIF_FLAG_PROTO_PIM;

	pim_channel_add_oif(up->channel_oil, ch->interface,
			mask, __func__);
}

void pim_forward_stop(struct pim_ifchannel *ch)
{
	struct pim_upstream *up = ch->upstream;

	if (PIM_DEBUG_PIM_TRACE) {
		zlog_debug("%s: (S,G)=%s oif=%s installed: %d",
			   __func__, ch->sg_str, ch->interface->name,
			   up->channel_oil->installed);
	}

	/*
	 * If a channel is being removed, check to see if we still need
	 * to inherit the interface.  If so make sure it is added in
	 */
	if (pim_upstream_evaluate_join_desired_interface(up, ch, ch->parent))
		pim_channel_add_oif(up->channel_oil, ch->interface,
				    PIM_OIF_FLAG_PROTO_PIM, __func__);
	else
		pim_channel_del_oif(up->channel_oil, ch->interface,
				    PIM_OIF_FLAG_PROTO_PIM, __func__);
}

void pim_zebra_zclient_update(struct vty *vty)
{
	vty_out(vty, "Zclient update socket: ");

	if (zclient) {
		vty_out(vty, "%d failures=%d\n", zclient->sock, zclient->fail);
	} else {
		vty_out(vty, "<null zclient>\n");
	}
}

struct zclient *pim_zebra_zclient_get(void)
{
	if (zclient)
		return zclient;
	else
		return NULL;
}

void pim_zebra_interface_set_master(struct interface *vrf,
				    struct interface *ifp)
{
	zclient_interface_set_master(zclient, vrf, ifp);
}
