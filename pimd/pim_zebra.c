/*
 * PIM for Quagga
 * Copyright (C) 2008  Everton da Silva Marques
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; see the file COPYING; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA
 */

#include <zebra.h>

#include "zebra/rib.h"

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

#undef PIM_DEBUG_IFADDR_DUMP
#define PIM_DEBUG_IFADDR_DUMP

static struct zclient *zclient = NULL;


/* Router-id update message from zebra. */
static int pim_router_id_update_zebra(int command, struct zclient *zclient,
				      zebra_size_t length, vrf_id_t vrf_id)
{
	struct prefix router_id;

	zebra_router_id_update_read(zclient->ibuf, &router_id);

	return 0;
}

static int pim_zebra_if_add(int command, struct zclient *zclient,
			    zebra_size_t length, vrf_id_t vrf_id)
{
	struct interface *ifp;
	struct pim_instance *pim;

	/*
	  zebra api adds/dels interfaces using the same call
	  interface_add_read below, see comments in lib/zclient.c
	*/
	ifp = zebra_interface_add_read(zclient->ibuf, vrf_id);
	if (!ifp)
		return 0;

	pim = pim_get_pim_instance(vrf_id);
	if (PIM_DEBUG_ZEBRA) {
		zlog_debug(
			"%s: %s index %d(%u) flags %ld metric %d mtu %d operative %d",
			__PRETTY_FUNCTION__, ifp->name, ifp->ifindex, vrf_id,
			(long)ifp->flags, ifp->metric, ifp->mtu,
			if_is_operative(ifp));
	}

	if (if_is_operative(ifp)) {
		struct pim_interface *pim_ifp;

		pim_ifp = ifp->info;
		/*
		 * If we have a pim_ifp already and this is an if_add
		 * that means that we probably have a vrf move event
		 * If that is the case, set the proper vrfness.
		 */
		if (pim_ifp)
			pim_ifp->pim = pim;
		pim_if_addr_add_all(ifp);
	}

	/*
	 * If we are a vrf device that is up, open up the pim_socket for
	 * listening
	 * to incoming pim messages irrelevant if the user has configured us
	 * for pim or not.
	 */
	if (pim_if_is_vrf_device(ifp)) {
		struct pim_interface *pim_ifp;

		if (!ifp->info) {
			pim_ifp = pim_if_new(ifp, 0, 0);
			ifp->info = pim_ifp;
		}

		pim_sock_add(ifp);
	}

	return 0;
}

static int pim_zebra_if_del(int command, struct zclient *zclient,
			    zebra_size_t length, vrf_id_t vrf_id)
{
	struct interface *ifp;

	/*
	  zebra api adds/dels interfaces using the same call
	  interface_add_read below, see comments in lib/zclient.c

	  comments in lib/zclient.c seem to indicate that calling
	  zebra_interface_add_read is the correct call, but that
	  results in an attemted out of bounds read which causes
	  pimd to assert. Other clients use zebra_interface_state_read
	  and it appears to work just fine.
	*/
	ifp = zebra_interface_state_read(zclient->ibuf, vrf_id);
	if (!ifp)
		return 0;

	if (PIM_DEBUG_ZEBRA) {
		zlog_debug(
			"%s: %s index %d(%u) flags %ld metric %d mtu %d operative %d",
			__PRETTY_FUNCTION__, ifp->name, ifp->ifindex, vrf_id,
			(long)ifp->flags, ifp->metric, ifp->mtu,
			if_is_operative(ifp));
	}

	if (!if_is_operative(ifp))
		pim_if_addr_del_all(ifp);

	return 0;
}

static int pim_zebra_if_state_up(int command, struct zclient *zclient,
				 zebra_size_t length, vrf_id_t vrf_id)
{
	struct pim_instance *pim;
	struct interface *ifp;
	uint32_t table_id;

	/*
	  zebra api notifies interface up/down events by using the same call
	  zebra_interface_state_read below, see comments in lib/zclient.c
	*/
	ifp = zebra_interface_state_read(zclient->ibuf, vrf_id);
	if (!ifp)
		return 0;

	if (PIM_DEBUG_ZEBRA) {
		zlog_debug(
			"%s: %s index %d(%u) flags %ld metric %d mtu %d operative %d",
			__PRETTY_FUNCTION__, ifp->name, ifp->ifindex, vrf_id,
			(long)ifp->flags, ifp->metric, ifp->mtu,
			if_is_operative(ifp));
	}

	pim = pim_get_pim_instance(vrf_id);
	if (if_is_operative(ifp)) {
		struct pim_interface *pim_ifp;

		pim_ifp = ifp->info;
		/*
		 * If we have a pim_ifp already and this is an if_add
		 * that means that we probably have a vrf move event
		 * If that is the case, set the proper vrfness.
		 */
		if (pim_ifp)
			pim_ifp->pim = pim;

		/*
		  pim_if_addr_add_all() suffices for bringing up both IGMP and
		  PIM
		*/
		pim_if_addr_add_all(ifp);
	}

	/*
	 * If we have a pimreg device callback and it's for a specific
	 * table set the master appropriately
	 */
	if (sscanf(ifp->name, "pimreg%" SCNu32, &table_id) == 1) {
		struct vrf *vrf;
		RB_FOREACH (vrf, vrf_name_head, &vrfs_by_name) {
			if ((table_id == vrf->data.l.table_id)
			    && (ifp->vrf_id != vrf->vrf_id)) {
				struct interface *master = if_lookup_by_name(
					vrf->name, vrf->vrf_id);

				if (!master) {
					zlog_debug(
						"%s: Unable to find Master interface for %s",
						__PRETTY_FUNCTION__, vrf->name);
					return 0;
				}
				zclient_interface_set_master(zclient, master,
							     ifp);
			}
		}
	}
	return 0;
}

static int pim_zebra_if_state_down(int command, struct zclient *zclient,
				   zebra_size_t length, vrf_id_t vrf_id)
{
	struct interface *ifp;

	/*
	  zebra api notifies interface up/down events by using the same call
	  zebra_interface_state_read below, see comments in lib/zclient.c
	*/
	ifp = zebra_interface_state_read(zclient->ibuf, vrf_id);
	if (!ifp)
		return 0;

	if (PIM_DEBUG_ZEBRA) {
		zlog_debug(
			"%s: %s index %d(%u) flags %ld metric %d mtu %d operative %d",
			__PRETTY_FUNCTION__, ifp->name, ifp->ifindex, vrf_id,
			(long)ifp->flags, ifp->metric, ifp->mtu,
			if_is_operative(ifp));
	}

	if (!if_is_operative(ifp)) {
		pim_ifchannel_delete_all(ifp);
		/*
		  pim_if_addr_del_all() suffices for shutting down IGMP,
		  but not for shutting down PIM
		*/
		pim_if_addr_del_all(ifp);

		/*
		  pim_sock_delete() closes the socket, stops read and timer
		  threads,
		  and kills all neighbors.
		*/
		if (ifp->info) {
			pim_sock_delete(ifp, "link down");
		}
	}

	if (ifp->info)
		pim_if_del_vif(ifp);

	return 0;
}

#ifdef PIM_DEBUG_IFADDR_DUMP
static void dump_if_address(struct interface *ifp)
{
	struct connected *ifc;
	struct listnode *node;

	zlog_debug("%s %s: interface %s addresses:", __FILE__,
		   __PRETTY_FUNCTION__, ifp->name);

	for (ALL_LIST_ELEMENTS_RO(ifp->connected, node, ifc)) {
		struct prefix *p = ifc->address;

		if (p->family != AF_INET)
			continue;

		zlog_debug("%s %s: interface %s address %s %s", __FILE__,
			   __PRETTY_FUNCTION__, ifp->name,
			   inet_ntoa(p->u.prefix4),
			   CHECK_FLAG(ifc->flags, ZEBRA_IFA_SECONDARY)
				   ? "secondary"
				   : "primary");
	}
}
#endif

static int pim_zebra_if_address_add(int command, struct zclient *zclient,
				    zebra_size_t length, vrf_id_t vrf_id)
{
	struct connected *c;
	struct prefix *p;
	struct pim_interface *pim_ifp;
	struct pim_instance *pim;

	/*
	  zebra api notifies address adds/dels events by using the same call
	  interface_add_read below, see comments in lib/zclient.c

	  zebra_interface_address_read(ZEBRA_INTERFACE_ADDRESS_ADD, ...)
	  will add address to interface list by calling
	  connected_add_by_prefix()
	*/
	c = zebra_interface_address_read(command, zclient->ibuf, vrf_id);
	if (!c)
		return 0;

	pim_ifp = c->ifp->info;
	p = c->address;

	if (PIM_DEBUG_ZEBRA) {
		char buf[BUFSIZ];
		prefix2str(p, buf, BUFSIZ);
		zlog_debug("%s: %s(%u) connected IP address %s flags %u %s",
			   __PRETTY_FUNCTION__, c->ifp->name, vrf_id, buf,
			   c->flags,
			   CHECK_FLAG(c->flags, ZEBRA_IFA_SECONDARY)
				   ? "secondary"
				   : "primary");

#ifdef PIM_DEBUG_IFADDR_DUMP
		dump_if_address(c->ifp);
#endif
	}

	if (!CHECK_FLAG(c->flags, ZEBRA_IFA_SECONDARY)) {
		/* trying to add primary address */

		struct in_addr primary_addr = pim_find_primary_addr(c->ifp);
		if (p->family != AF_INET
		    || primary_addr.s_addr != p->u.prefix4.s_addr) {
			if (PIM_DEBUG_ZEBRA) {
				/* but we had a primary address already */

				char buf[BUFSIZ];

				prefix2str(p, buf, BUFSIZ);

				zlog_warn(
					"%s: %s : forcing secondary flag on %s",
					__PRETTY_FUNCTION__, c->ifp->name, buf);
			}
			SET_FLAG(c->flags, ZEBRA_IFA_SECONDARY);
		}
	}

	pim_if_addr_add(c);
	if (pim_ifp) {
		pim = pim_get_pim_instance(vrf_id);
		pim_ifp->pim = pim;

		pim_rp_check_on_if_add(pim_ifp);
	}

	if (if_is_loopback(c->ifp)) {
		struct vrf *vrf = vrf_lookup_by_id(VRF_DEFAULT);
		struct interface *ifp;

		FOR_ALL_INTERFACES (vrf, ifp) {
			if (!if_is_loopback(ifp) && if_is_operative(ifp))
				pim_if_addr_add_all(ifp);
		}
	}

	return 0;
}

static int pim_zebra_if_address_del(int command, struct zclient *client,
				    zebra_size_t length, vrf_id_t vrf_id)
{
	struct connected *c;
	struct prefix *p;
	struct vrf *vrf = vrf_lookup_by_id(vrf_id);
	struct pim_instance *pim;

	if (!vrf)
		return 0;
	pim = vrf->info;

	/*
	  zebra api notifies address adds/dels events by using the same call
	  interface_add_read below, see comments in lib/zclient.c

	  zebra_interface_address_read(ZEBRA_INTERFACE_ADDRESS_DELETE, ...)
	  will remove address from interface list by calling
	  connected_delete_by_prefix()
	*/
	c = zebra_interface_address_read(command, client->ibuf, vrf_id);
	if (!c)
		return 0;

	p = c->address;
	if (p->family == AF_INET) {
		if (PIM_DEBUG_ZEBRA) {
			char buf[BUFSIZ];
			prefix2str(p, buf, BUFSIZ);
			zlog_debug(
				"%s: %s(%u) disconnected IP address %s flags %u %s",
				__PRETTY_FUNCTION__, c->ifp->name, vrf_id, buf,
				c->flags,
				CHECK_FLAG(c->flags, ZEBRA_IFA_SECONDARY)
					? "secondary"
					: "primary");

#ifdef PIM_DEBUG_IFADDR_DUMP
			dump_if_address(c->ifp);
#endif
		}

		pim_if_addr_del(c, 0);
		pim_rp_setup(pim);
		pim_i_am_rp_re_evaluate(pim);
	}

	connected_free(c);
	return 0;
}

static void scan_upstream_rpf_cache(struct pim_instance *pim)
{
	struct listnode *up_node;
	struct listnode *up_nextnode;
	struct listnode *node;
	struct pim_upstream *up;
	struct interface *ifp;

	for (ALL_LIST_ELEMENTS(pim->upstream_list, up_node, up_nextnode, up)) {
		enum pim_rpf_result rpf_result;
		struct pim_rpf old;
		struct prefix nht_p;

		nht_p.family = AF_INET;
		nht_p.prefixlen = IPV4_MAX_BITLEN;
		nht_p.u.prefix4.s_addr = up->upstream_addr.s_addr;
		pim_resolve_upstream_nh(pim, &nht_p);

		old.source_nexthop.interface = up->rpf.source_nexthop.interface;
		old.source_nexthop.nbr = up->rpf.source_nexthop.nbr;
		rpf_result = pim_rpf_update(pim, up, &old, 0);

		if (rpf_result == PIM_RPF_FAILURE)
			continue;

		if (rpf_result == PIM_RPF_CHANGED) {
			struct pim_neighbor *nbr;

			nbr = pim_neighbor_find(old.source_nexthop.interface,
						old.rpf_addr.u.prefix4);
			if (nbr)
				pim_jp_agg_remove_group(nbr->upstream_jp_agg,
							up);

			/*
			 * We have detected a case where we might need
			 * to rescan
			 * the inherited o_list so do it.
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
					pim_mroute_add(up->channel_oil,
						       __PRETTY_FUNCTION__);

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
				pim_jp_agg_switch_interface(&old, &up->rpf, up);

				pim_upstream_join_timer_restart(up, &old);
			} /* up->join_state == PIM_UPSTREAM_JOINED */

			/* FIXME can join_desired actually be changed by
			   pim_rpf_update()
			   returning PIM_RPF_CHANGED ? */
			pim_upstream_update_join_desired(pim, up);

		} /* PIM_RPF_CHANGED */

	} /* for (qpim_upstream_list) */

	FOR_ALL_INTERFACES (pim->vrf, ifp)
		if (ifp->info) {
			struct pim_interface *pim_ifp = ifp->info;
			struct pim_iface_upstream_switch *us;

			for (ALL_LIST_ELEMENTS_RO(pim_ifp->upstream_switch_list,
						  node, us)) {
				struct pim_rpf rpf;

				rpf.source_nexthop.interface = ifp;
				rpf.rpf_addr.u.prefix4 = us->address;
				pim_joinprune_send(&rpf, us->us);
				pim_jp_agg_clear_group(us->us);
			}
		}
}

void pim_scan_individual_oil(struct channel_oil *c_oil, int in_vif_index)
{
	struct in_addr vif_source;
	int input_iface_vif_index;
	int old_vif_index;

	if (!pim_rp_set_upstream_addr(c_oil->pim, &vif_source,
				      c_oil->oil.mfcc_origin,
				      c_oil->oil.mfcc_mcastgrp))
		return;

	if (in_vif_index)
		input_iface_vif_index = in_vif_index;
	else {
		struct prefix src, grp;

		src.family = AF_INET;
		src.prefixlen = IPV4_MAX_BITLEN;
		src.u.prefix4 = vif_source;
		grp.family = AF_INET;
		grp.prefixlen = IPV4_MAX_BITLEN;
		grp.u.prefix4 = c_oil->oil.mfcc_mcastgrp;

		if (PIM_DEBUG_ZEBRA) {
			char source_str[INET_ADDRSTRLEN];
			char group_str[INET_ADDRSTRLEN];
			pim_inet4_dump("<source?>", c_oil->oil.mfcc_origin,
				       source_str, sizeof(source_str));
			pim_inet4_dump("<group?>", c_oil->oil.mfcc_mcastgrp,
				       group_str, sizeof(group_str));
			zlog_debug(
				"%s: channel_oil (%s,%s) upstream info is not present.",
				__PRETTY_FUNCTION__, source_str, group_str);
		}
		input_iface_vif_index = pim_ecmp_fib_lookup_if_vif_index(
			c_oil->pim, vif_source, &src, &grp);
	}

	if (input_iface_vif_index < 1) {
		if (PIM_DEBUG_ZEBRA) {
			char source_str[INET_ADDRSTRLEN];
			char group_str[INET_ADDRSTRLEN];
			pim_inet4_dump("<source?>", c_oil->oil.mfcc_origin,
				       source_str, sizeof(source_str));
			pim_inet4_dump("<group?>", c_oil->oil.mfcc_mcastgrp,
				       group_str, sizeof(group_str));
			zlog_debug(
				"%s %s: could not find input interface(%d) for (S,G)=(%s,%s)",
				__FILE__, __PRETTY_FUNCTION__,
				c_oil->oil.mfcc_parent, source_str, group_str);
		}
		pim_mroute_del(c_oil, __PRETTY_FUNCTION__);
		return;
	}

	if (input_iface_vif_index == c_oil->oil.mfcc_parent) {
		if (!c_oil->installed)
			pim_mroute_add(c_oil, __PRETTY_FUNCTION__);

		/* RPF unchanged */
		return;
	}

	if (PIM_DEBUG_ZEBRA) {
		struct interface *old_iif = pim_if_find_by_vif_index(
			c_oil->pim, c_oil->oil.mfcc_parent);
		struct interface *new_iif = pim_if_find_by_vif_index(
			c_oil->pim, input_iface_vif_index);
		char source_str[INET_ADDRSTRLEN];
		char group_str[INET_ADDRSTRLEN];
		pim_inet4_dump("<source?>", c_oil->oil.mfcc_origin, source_str,
			       sizeof(source_str));
		pim_inet4_dump("<group?>", c_oil->oil.mfcc_mcastgrp, group_str,
			       sizeof(group_str));
		zlog_debug(
			"%s %s: (S,G)=(%s,%s) input interface changed from %s vif_index=%d to %s vif_index=%d",
			__FILE__, __PRETTY_FUNCTION__, source_str, group_str,
			(old_iif) ? old_iif->name : "<old_iif?>",
			c_oil->oil.mfcc_parent,
			(new_iif) ? new_iif->name : "<new_iif?>",
			input_iface_vif_index);
	}

	/* new iif loops to existing oif ? */
	if (c_oil->oil.mfcc_ttls[input_iface_vif_index]) {
		struct interface *new_iif = pim_if_find_by_vif_index(
			c_oil->pim, input_iface_vif_index);

		if (PIM_DEBUG_ZEBRA) {
			char source_str[INET_ADDRSTRLEN];
			char group_str[INET_ADDRSTRLEN];
			pim_inet4_dump("<source?>", c_oil->oil.mfcc_origin,
				       source_str, sizeof(source_str));
			pim_inet4_dump("<group?>", c_oil->oil.mfcc_mcastgrp,
				       group_str, sizeof(group_str));
			zlog_debug(
				"%s %s: (S,G)=(%s,%s) new iif loops to existing oif: %s vif_index=%d",
				__FILE__, __PRETTY_FUNCTION__, source_str,
				group_str,
				(new_iif) ? new_iif->name : "<new_iif?>",
				input_iface_vif_index);
		}
	}

	/* update iif vif_index */
	old_vif_index = c_oil->oil.mfcc_parent;
	c_oil->oil.mfcc_parent = input_iface_vif_index;

	/* update kernel multicast forwarding cache (MFC) */
	if (pim_mroute_add(c_oil, __PRETTY_FUNCTION__)) {
		if (PIM_DEBUG_MROUTE) {
			/* just log warning */
			struct interface *old_iif = pim_if_find_by_vif_index(
				c_oil->pim, old_vif_index);
			struct interface *new_iif = pim_if_find_by_vif_index(
				c_oil->pim, input_iface_vif_index);
			char source_str[INET_ADDRSTRLEN];
			char group_str[INET_ADDRSTRLEN];
			pim_inet4_dump("<source?>", c_oil->oil.mfcc_origin,
				       source_str, sizeof(source_str));
			pim_inet4_dump("<group?>", c_oil->oil.mfcc_mcastgrp,
				       group_str, sizeof(group_str));
			zlog_debug(
				"%s %s: (S,G)=(%s,%s) failure updating input interface from %s vif_index=%d to %s vif_index=%d",
				__FILE__, __PRETTY_FUNCTION__, source_str,
				group_str,
				old_iif ? old_iif->name : "<old_iif?>",
				c_oil->oil.mfcc_parent,
				new_iif ? new_iif->name : "<new_iif?>",
				input_iface_vif_index);
		}
	}
}

void pim_scan_oil(struct pim_instance *pim)
{
	struct listnode *node;
	struct listnode *nextnode;
	struct channel_oil *c_oil;
	ifindex_t ifindex;
	int vif_index = 0;

	pim->scan_oil_last = pim_time_monotonic_sec();
	++pim->scan_oil_events;

	for (ALL_LIST_ELEMENTS(pim->channel_oil_list, node, nextnode, c_oil)) {
		if (c_oil->up && c_oil->up->rpf.source_nexthop.interface) {
			ifindex = c_oil->up->rpf.source_nexthop
					  .interface->ifindex;
			vif_index =
				pim_if_find_vifindex_by_ifindex(pim, ifindex);
			/* Pass Current selected NH vif index to mroute
			 * download */
			if (vif_index)
				pim_scan_individual_oil(c_oil, vif_index);
		} else
			pim_scan_individual_oil(c_oil, 0);
	}
}

static int on_rpf_cache_refresh(struct thread *t)
{
	struct pim_instance *pim = THREAD_ARG(t);

	/* update PIM protocol state */
	scan_upstream_rpf_cache(pim);

	/* update kernel multicast forwarding cache (MFC) */
	pim_scan_oil(pim);

	pim->rpf_cache_refresh_last = pim_time_monotonic_sec();
	++pim->rpf_cache_refresh_events;

	// It is called as part of pim_neighbor_add
	// pim_rp_setup ();
	return 0;
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
		zlog_debug("%s: triggering %ld msec timer", __PRETTY_FUNCTION__,
			   qpim_rpf_cache_refresh_delay_msec);
	}

	thread_add_timer_msec(master, on_rpf_cache_refresh, pim,
			      qpim_rpf_cache_refresh_delay_msec,
			      &pim->rpf_cache_refresher);
}

static void pim_zebra_connected(struct zclient *zclient)
{
	/* Send the client registration */
	bfd_client_sendmsg(zclient, ZEBRA_BFD_CLIENT_REGISTER);

	zclient_send_reg_requests(zclient, pimg->vrf_id);
}

void pim_zebra_init(void)
{
	/* Socket for receiving updates from Zebra daemon */
	zclient = zclient_new_notify(master, &zclient_options_default);

	zclient->zebra_connected = pim_zebra_connected;
	zclient->router_id_update = pim_router_id_update_zebra;
	zclient->interface_add = pim_zebra_if_add;
	zclient->interface_delete = pim_zebra_if_del;
	zclient->interface_up = pim_zebra_if_state_up;
	zclient->interface_down = pim_zebra_if_state_down;
	zclient->interface_address_add = pim_zebra_if_address_add;
	zclient->interface_address_delete = pim_zebra_if_address_del;
	zclient->nexthop_update = pim_parse_nexthop_update;

	zclient_init(zclient, ZEBRA_ROUTE_PIM, 0, &pimd_privs);
	if (PIM_DEBUG_PIM_TRACE) {
		zlog_notice("%s: zclient socket initialized",
			    __PRETTY_FUNCTION__);
	}

	zclient_lookup_new();
}

void igmp_anysource_forward_start(struct pim_instance *pim,
				  struct igmp_group *group)
{
	struct igmp_source *source;
	struct in_addr src_addr = {.s_addr = 0};
	/* Any source (*,G) is forwarded only if mode is EXCLUDE {empty} */
	zassert(group->group_filtermode_isexcl);
	zassert(listcount(group->group_source_list) < 1);

	source = source_new(group, src_addr);
	if (!source) {
		zlog_warn("%s: Failure to create * source",
			  __PRETTY_FUNCTION__);
		return;
	}

	igmp_source_forward_start(pim, source);
}

void igmp_anysource_forward_stop(struct igmp_group *group)
{
	struct igmp_source *source;
	struct in_addr star = {.s_addr = 0};

	source = igmp_find_source_by_addr(group, star);
	if (source)
		igmp_source_forward_stop(source);
}

static void igmp_source_forward_reevaluate_one(struct pim_instance *pim,
					       struct igmp_source *source)
{
	struct prefix_sg sg;
	struct igmp_group *group = source->source_group;
	struct pim_ifchannel *ch;

	if ((source->source_addr.s_addr != INADDR_ANY)
	    || !IGMP_SOURCE_TEST_FORWARDING(source->source_flags))
		return;

	memset(&sg, 0, sizeof(struct prefix_sg));
	sg.src = source->source_addr;
	sg.grp = group->group_addr;

	ch = pim_ifchannel_find(group->group_igmp_sock->interface, &sg);
	if (pim_is_grp_ssm(pim, group->group_addr)) {
		/* If SSM group withdraw local membership */
		if (ch
		    && (ch->local_ifmembership == PIM_IFMEMBERSHIP_INCLUDE)) {
			if (PIM_DEBUG_PIM_EVENTS)
				zlog_debug(
					"local membership del for %s as G is now SSM",
					pim_str_sg_dump(&sg));
			pim_ifchannel_local_membership_del(
				group->group_igmp_sock->interface, &sg);
		}
	} else {
		/* If ASM group add local membership */
		if (!ch
		    || (ch->local_ifmembership == PIM_IFMEMBERSHIP_NOINFO)) {
			if (PIM_DEBUG_PIM_EVENTS)
				zlog_debug(
					"local membership add for %s as G is now ASM",
					pim_str_sg_dump(&sg));
			pim_ifchannel_local_membership_add(
				group->group_igmp_sock->interface, &sg);
		}
	}
}

void igmp_source_forward_reevaluate_all(struct pim_instance *pim)
{
	struct interface *ifp;

	FOR_ALL_INTERFACES (pim->vrf, ifp) {
		struct pim_interface *pim_ifp = ifp->info;
		struct listnode *sock_node;
		struct igmp_sock *igmp;

		if (!pim_ifp)
			continue;

		/* scan igmp sockets */
		for (ALL_LIST_ELEMENTS_RO(pim_ifp->igmp_socket_list, sock_node,
					  igmp)) {
			struct listnode *grpnode;
			struct igmp_group *grp;

			/* scan igmp groups */
			for (ALL_LIST_ELEMENTS_RO(igmp->igmp_group_list,
						  grpnode, grp)) {
				struct listnode *srcnode;
				struct igmp_source *src;

				/* scan group sources */
				for (ALL_LIST_ELEMENTS_RO(
					     grp->group_source_list, srcnode,
					     src)) {
					igmp_source_forward_reevaluate_one(pim,
									   src);
				} /* scan group sources */
			}	 /* scan igmp groups */
		}		  /* scan igmp sockets */
	}			  /* scan interfaces */
}

void igmp_source_forward_start(struct pim_instance *pim,
			       struct igmp_source *source)
{
	struct igmp_group *group;
	struct prefix_sg sg;
	int result;
	int input_iface_vif_index = 0;

	memset(&sg, 0, sizeof(struct prefix_sg));
	sg.src = source->source_addr;
	sg.grp = source->source_group->group_addr;

	if (PIM_DEBUG_IGMP_TRACE) {
		zlog_debug(
			"%s: (S,G)=%s igmp_sock=%d oif=%s fwd=%d",
			__PRETTY_FUNCTION__, pim_str_sg_dump(&sg),
			source->source_group->group_igmp_sock->fd,
			source->source_group->group_igmp_sock->interface->name,
			IGMP_SOURCE_TEST_FORWARDING(source->source_flags));
	}

	/* Prevent IGMP interface from installing multicast route multiple
	   times */
	if (IGMP_SOURCE_TEST_FORWARDING(source->source_flags)) {
		return;
	}

	group = source->source_group;

	if (!source->source_channel_oil) {
		struct in_addr vif_source;
		struct pim_interface *pim_oif;
		struct prefix nht_p, src, grp;
		struct pim_nexthop_cache out_pnc;
		struct pim_nexthop nexthop;
		struct pim_upstream *up = NULL;

		if (!pim_rp_set_upstream_addr(pim, &vif_source,
					      source->source_addr, sg.grp))
			return;

		/* Register addr with Zebra NHT */
		nht_p.family = AF_INET;
		nht_p.prefixlen = IPV4_MAX_BITLEN;
		nht_p.u.prefix4 = vif_source;
		memset(&out_pnc, 0, sizeof(struct pim_nexthop_cache));

		src.family = AF_INET;
		src.prefixlen = IPV4_MAX_BITLEN;
		src.u.prefix4 = vif_source; // RP or Src address
		grp.family = AF_INET;
		grp.prefixlen = IPV4_MAX_BITLEN;
		grp.u.prefix4 = sg.grp;

		if (pim_find_or_track_nexthop(pim, &nht_p, NULL, NULL,
					      &out_pnc)) {
			if (out_pnc.nexthop_num) {
				up = pim_upstream_find(pim, &sg);
				memset(&nexthop, 0, sizeof(nexthop));
				if (up)
					memcpy(&nexthop,
					       &up->rpf.source_nexthop,
					       sizeof(struct pim_nexthop));
				pim_ecmp_nexthop_search(pim, &out_pnc, &nexthop,
							&src, &grp, 0);
				if (nexthop.interface)
					input_iface_vif_index =
						pim_if_find_vifindex_by_ifindex(
							pim,
							nexthop.interface->ifindex);
			} else {
				if (PIM_DEBUG_ZEBRA) {
					char buf1[INET_ADDRSTRLEN];
					char buf2[INET_ADDRSTRLEN];
					pim_inet4_dump("<source?>",
						       nht_p.u.prefix4, buf1,
						       sizeof(buf1));
					pim_inet4_dump("<source?>",
						       grp.u.prefix4, buf2,
						       sizeof(buf2));
					zlog_debug(
						"%s: NHT Nexthop not found for addr %s grp %s",
						__PRETTY_FUNCTION__, buf1,
						buf2);
				}
			}
		} else
			input_iface_vif_index =
				pim_ecmp_fib_lookup_if_vif_index(
					pim, vif_source, &src, &grp);

		if (PIM_DEBUG_ZEBRA) {
			char buf2[INET_ADDRSTRLEN];
			pim_inet4_dump("<source?>", vif_source, buf2,
				       sizeof(buf2));
			zlog_debug("%s: NHT %s vif_source %s vif_index:%d ",
				   __PRETTY_FUNCTION__, pim_str_sg_dump(&sg),
				   buf2, input_iface_vif_index);
		}

		if (input_iface_vif_index < 1) {
			if (PIM_DEBUG_IGMP_TRACE) {
				char source_str[INET_ADDRSTRLEN];
				pim_inet4_dump("<source?>", source->source_addr,
					       source_str, sizeof(source_str));
				zlog_debug(
					"%s %s: could not find input interface for source %s",
					__FILE__, __PRETTY_FUNCTION__,
					source_str);
			}
			return;
		}

		/*
		  Protect IGMP against adding looped MFC entries created by both
		  source and receiver attached to the same interface. See TODO
		  T22.
		*/
		pim_oif =
			source->source_group->group_igmp_sock->interface->info;
		if (!pim_oif) {
			if (PIM_DEBUG_IGMP_TRACE) {
				zlog_debug(
					"%s: multicast not enabled on oif=%s ?",
					__PRETTY_FUNCTION__,
					source->source_group->group_igmp_sock
						->interface->name);
			}
			return;
		}

		if (input_iface_vif_index == pim_oif->mroute_vif_index) {
			/* ignore request for looped MFC entry */
			if (PIM_DEBUG_IGMP_TRACE) {
				zlog_debug(
					"%s: ignoring request for looped MFC entry (S,G)=%s: igmp_sock=%d oif=%s vif_index=%d",
					__PRETTY_FUNCTION__,
					pim_str_sg_dump(&sg),
					source->source_group->group_igmp_sock
						->fd,
					source->source_group->group_igmp_sock
						->interface->name,
					input_iface_vif_index);
			}
			return;
		}

		source->source_channel_oil =
			pim_channel_oil_add(pim, &sg, input_iface_vif_index);
		if (!source->source_channel_oil) {
			if (PIM_DEBUG_IGMP_TRACE) {
				zlog_debug(
					"%s %s: could not create OIL for channel (S,G)=%s",
					__FILE__, __PRETTY_FUNCTION__,
					pim_str_sg_dump(&sg));
			}
			return;
		}
	}

	result = pim_channel_add_oif(source->source_channel_oil,
				     group->group_igmp_sock->interface,
				     PIM_OIF_FLAG_PROTO_IGMP);
	if (result) {
		if (PIM_DEBUG_MROUTE) {
			zlog_warn("%s: add_oif() failed with return=%d",
				  __func__, result);
		}
		return;
	}

	/*
	  Feed IGMPv3-gathered local membership information into PIM
	  per-interface (S,G) state.
	 */
	if (!pim_ifchannel_local_membership_add(
		    group->group_igmp_sock->interface, &sg)) {
		if (PIM_DEBUG_MROUTE)
			zlog_warn("%s: Failure to add local membership for %s",
				  __PRETTY_FUNCTION__, pim_str_sg_dump(&sg));
		return;
	}

	IGMP_SOURCE_DO_FORWARDING(source->source_flags);
}

/*
  igmp_source_forward_stop: stop fowarding, but keep the source
  igmp_source_delete:       stop fowarding, and delete the source
 */
void igmp_source_forward_stop(struct igmp_source *source)
{
	struct igmp_group *group;
	struct prefix_sg sg;
	int result;

	memset(&sg, 0, sizeof(struct prefix_sg));
	sg.src = source->source_addr;
	sg.grp = source->source_group->group_addr;

	if (PIM_DEBUG_IGMP_TRACE) {
		zlog_debug(
			"%s: (S,G)=%s igmp_sock=%d oif=%s fwd=%d",
			__PRETTY_FUNCTION__, pim_str_sg_dump(&sg),
			source->source_group->group_igmp_sock->fd,
			source->source_group->group_igmp_sock->interface->name,
			IGMP_SOURCE_TEST_FORWARDING(source->source_flags));
	}

	/* Prevent IGMP interface from removing multicast route multiple
	   times */
	if (!IGMP_SOURCE_TEST_FORWARDING(source->source_flags)) {
		return;
	}

	group = source->source_group;

	/*
	 It appears that in certain circumstances that
	 igmp_source_forward_stop is called when IGMP forwarding
	 was not enabled in oif_flags for this outgoing interface.
	 Possibly because of multiple calls. When that happens, we
	 enter the below if statement and this function returns early
	 which in turn triggers the calling function to assert.
	 Making the call to pim_channel_del_oif and ignoring the return code
	 fixes the issue without ill effect, similar to
	 pim_forward_stop below.
	*/
	result = pim_channel_del_oif(source->source_channel_oil,
				     group->group_igmp_sock->interface,
				     PIM_OIF_FLAG_PROTO_IGMP);
	if (result) {
		if (PIM_DEBUG_IGMP_TRACE)
			zlog_debug(
				"%s: pim_channel_del_oif() failed with return=%d",
				__func__, result);
		return;
	}

	/*
	  Feed IGMPv3-gathered local membership information into PIM
	  per-interface (S,G) state.
	 */
	pim_ifchannel_local_membership_del(group->group_igmp_sock->interface,
					   &sg);

	IGMP_SOURCE_DONT_FORWARDING(source->source_flags);
}

void pim_forward_start(struct pim_ifchannel *ch)
{
	struct pim_upstream *up = ch->upstream;
	uint32_t mask = PIM_OIF_FLAG_PROTO_PIM;
	int input_iface_vif_index = 0;
	struct pim_instance *pim;
	struct pim_interface *pim_ifp;

	pim_ifp = ch->interface->info;
	pim = pim_ifp->pim;

	if (PIM_DEBUG_PIM_TRACE) {
		char source_str[INET_ADDRSTRLEN];
		char group_str[INET_ADDRSTRLEN];
		char upstream_str[INET_ADDRSTRLEN];

		pim_inet4_dump("<source?>", ch->sg.src, source_str,
			       sizeof(source_str));
		pim_inet4_dump("<group?>", ch->sg.grp, group_str,
			       sizeof(group_str));
		pim_inet4_dump("<upstream?>", up->upstream_addr, upstream_str,
			       sizeof(upstream_str));
		zlog_debug("%s: (S,G)=(%s,%s) oif=%s (%s)", __PRETTY_FUNCTION__,
			   source_str, group_str, ch->interface->name,
			   upstream_str);
	}

	/* Resolve IIF for upstream as mroute_del sets mfcc_parent to MAXVIFS,
	   as part of mroute_del called by pim_forward_stop.
	*/
	if (!up->channel_oil
	    || (up->channel_oil
		&& up->channel_oil->oil.mfcc_parent >= MAXVIFS)) {
		struct prefix nht_p, src, grp;
		struct pim_nexthop_cache out_pnc;

		/* Register addr with Zebra NHT */
		nht_p.family = AF_INET;
		nht_p.prefixlen = IPV4_MAX_BITLEN;
		nht_p.u.prefix4.s_addr = up->upstream_addr.s_addr;
		grp.family = AF_INET;
		grp.prefixlen = IPV4_MAX_BITLEN;
		grp.u.prefix4 = up->sg.grp;
		memset(&out_pnc, 0, sizeof(struct pim_nexthop_cache));

		if (pim_find_or_track_nexthop(pim, &nht_p, NULL, NULL,
					      &out_pnc)) {
			if (out_pnc.nexthop_num) {
				src.family = AF_INET;
				src.prefixlen = IPV4_MAX_BITLEN;
				src.u.prefix4 =
					up->upstream_addr; // RP or Src address
				grp.family = AF_INET;
				grp.prefixlen = IPV4_MAX_BITLEN;
				grp.u.prefix4 = up->sg.grp;
				// Compute PIM RPF using Cached nexthop
				if (pim_ecmp_nexthop_search(
					    pim, &out_pnc,
					    &up->rpf.source_nexthop, &src, &grp,
					    0))
					input_iface_vif_index =
						pim_if_find_vifindex_by_ifindex(
							pim,
							up->rpf.source_nexthop
								.interface->ifindex);
				else {
					if (PIM_DEBUG_TRACE)
						zlog_debug(
							"%s: Nexthop selection failed for %s ",
							__PRETTY_FUNCTION__,
							up->sg_str);
				}
			} else {
				if (PIM_DEBUG_ZEBRA) {
					char buf1[INET_ADDRSTRLEN];
					char buf2[INET_ADDRSTRLEN];
					pim_inet4_dump("<source?>",
						       nht_p.u.prefix4, buf1,
						       sizeof(buf1));
					pim_inet4_dump("<source?>",
						       grp.u.prefix4, buf2,
						       sizeof(buf2));
					zlog_debug(
						"%s: NHT pnc is NULL for addr %s grp %s",
						__PRETTY_FUNCTION__, buf1,
						buf2);
				}
			}
		} else
			input_iface_vif_index =
				pim_ecmp_fib_lookup_if_vif_index(
					pim, up->upstream_addr, &src, &grp);

		if (input_iface_vif_index < 1) {
			if (PIM_DEBUG_PIM_TRACE) {
				char source_str[INET_ADDRSTRLEN];
				pim_inet4_dump("<source?>", up->sg.src,
					       source_str, sizeof(source_str));
				zlog_debug(
					"%s %s: could not find input interface for source %s",
					__FILE__, __PRETTY_FUNCTION__,
					source_str);
			}
			return;
		}
		if (PIM_DEBUG_TRACE) {
			struct interface *in_intf = pim_if_find_by_vif_index(
				pim, input_iface_vif_index);
			zlog_debug(
				"%s: Update channel_oil IIF %s VIFI %d entry %s ",
				__PRETTY_FUNCTION__,
				in_intf ? in_intf->name : "NIL",
				input_iface_vif_index, up->sg_str);
		}
		up->channel_oil = pim_channel_oil_add(pim, &up->sg,
						      input_iface_vif_index);
		if (!up->channel_oil) {
			if (PIM_DEBUG_PIM_TRACE)
				zlog_debug(
					"%s %s: could not create OIL for channel (S,G)=%s",
					__FILE__, __PRETTY_FUNCTION__,
					up->sg_str);
			return;
		}
	}

	if (up->flags & PIM_UPSTREAM_FLAG_MASK_SRC_IGMP)
		mask = PIM_OIF_FLAG_PROTO_IGMP;

	pim_channel_add_oif(up->channel_oil, ch->interface, mask);
}

void pim_forward_stop(struct pim_ifchannel *ch, bool install_it)
{
	struct pim_upstream *up = ch->upstream;

	if (PIM_DEBUG_PIM_TRACE) {
		zlog_debug("%s: (S,G)=%s oif=%s install_it: %d installed: %d",
			   __PRETTY_FUNCTION__, ch->sg_str, ch->interface->name,
			   install_it, up->channel_oil->installed);
	}

	pim_channel_del_oif(up->channel_oil, ch->interface,
			    PIM_OIF_FLAG_PROTO_PIM);

	if (install_it && !up->channel_oil->installed)
		pim_mroute_add(up->channel_oil, __PRETTY_FUNCTION__);
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
