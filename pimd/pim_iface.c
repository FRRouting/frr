// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * PIM for Quagga
 * Copyright (C) 2008  Everton da Silva Marques
 */

#include <zebra.h>

#include "if.h"
#include "log.h"
#include "vty.h"
#include "memory.h"
#include "prefix.h"
#include "vrf.h"
#include "linklist.h"
#include "plist.h"
#include "hash.h"
#include "ferr.h"
#include "network.h"

#include "pimd.h"
#include "pim_instance.h"
#include "pim_zebra.h"
#include "pim_iface.h"
#include "pim_igmp.h"
#include "pim_mroute.h"
#include "pim_oil.h"
#include "pim_str.h"
#include "pim_pim.h"
#include "pim_neighbor.h"
#include "pim_ifchannel.h"
#include "pim_sock.h"
#include "pim_time.h"
#include "pim_ssmpingd.h"
#include "pim_rp.h"
#include "pim_nht.h"
#include "pim_jp_agg.h"
#include "pim_igmp_join.h"
#include "pim_vxlan.h"

#include "pim6_mld.h"

static void pim_if_gm_join_del_all(struct interface *ifp);

static int gm_join_sock(const char *ifname, ifindex_t ifindex,
			pim_addr group_addr, pim_addr source_addr,
			struct pim_interface *pim_ifp);

void pim_if_init(struct pim_instance *pim)
{
	int i;

	for (i = 0; i < MAXVIFS; i++)
		pim->iface_vif_index[i] = 0;
}

void pim_if_terminate(struct pim_instance *pim)
{
	struct interface *ifp;

	FOR_ALL_INTERFACES (pim->vrf, ifp) {
		struct pim_interface *pim_ifp = ifp->info;

		if (!pim_ifp)
			continue;

		pim_if_delete(ifp);
	}
	return;
}

static void pim_sec_addr_free(struct pim_secondary_addr *sec_addr)
{
	XFREE(MTYPE_PIM_SEC_ADDR, sec_addr);
}

__attribute__((unused))
static int pim_sec_addr_comp(const void *p1, const void *p2)
{
	const struct pim_secondary_addr *sec1 = p1;
	const struct pim_secondary_addr *sec2 = p2;

	if (sec1->addr.family == AF_INET && sec2->addr.family == AF_INET6)
		return -1;

	if (sec1->addr.family == AF_INET6 && sec2->addr.family == AF_INET)
		return 1;

	if (sec1->addr.family == AF_INET) {
		if (ntohl(sec1->addr.u.prefix4.s_addr)
		    < ntohl(sec2->addr.u.prefix4.s_addr))
			return -1;

		if (ntohl(sec1->addr.u.prefix4.s_addr)
		    > ntohl(sec2->addr.u.prefix4.s_addr))
			return 1;
	} else {
		return memcmp(&sec1->addr.u.prefix6, &sec2->addr.u.prefix6,
			      sizeof(struct in6_addr));
	}

	return 0;
}

struct pim_interface *pim_if_new(struct interface *ifp, bool gm, bool pim,
				 bool ispimreg, bool is_vxlan_term)
{
	struct pim_interface *pim_ifp;

	assert(ifp);
	assert(!ifp->info);

	pim_ifp = XCALLOC(MTYPE_PIM_INTERFACE, sizeof(*pim_ifp));

	pim_ifp->pim = ifp->vrf->info;
	pim_ifp->mroute_vif_index = -1;

	pim_ifp->igmp_version = IGMP_DEFAULT_VERSION;
	pim_ifp->mld_version = MLD_DEFAULT_VERSION;
	pim_ifp->gm_default_robustness_variable =
		GM_DEFAULT_ROBUSTNESS_VARIABLE;
	pim_ifp->gm_default_query_interval = GM_GENERAL_QUERY_INTERVAL;
	pim_ifp->gm_query_max_response_time_dsec =
		GM_QUERY_MAX_RESPONSE_TIME_DSEC;
	pim_ifp->gm_specific_query_max_response_time_dsec =
		GM_SPECIFIC_QUERY_MAX_RESPONSE_TIME_DSEC;
	pim_ifp->gm_last_member_query_count = GM_DEFAULT_ROBUSTNESS_VARIABLE;

	/* BSM config on interface: true by default */
	pim_ifp->bsm_enable = true;
	pim_ifp->ucast_bsm_accept = true;
	pim_ifp->am_i_dr = false;

	/*
	  RFC 3376: 8.3. Query Response Interval
	  The number of seconds represented by the [Query Response Interval]
	  must be less than the [Query Interval].
	 */
	assert(pim_ifp->gm_query_max_response_time_dsec <
	       pim_ifp->gm_default_query_interval);

	pim_ifp->pim_enable = pim;
	pim_ifp->pim_passive_enable = false;
	pim_ifp->gm_enable = gm;

	pim_ifp->gm_join_list = NULL;
	pim_ifp->pim_neighbor_list = NULL;
	pim_ifp->upstream_switch_list = NULL;
	pim_ifp->pim_generation_id = 0;

	/* list of struct gm_sock */
	pim_igmp_if_init(pim_ifp, ifp);

	/* list of struct pim_neighbor */
	pim_ifp->pim_neighbor_list = list_new();
	pim_ifp->pim_neighbor_list->del = (void (*)(void *))pim_neighbor_free;

	pim_ifp->upstream_switch_list = list_new();
	pim_ifp->upstream_switch_list->del =
		(void (*)(void *))pim_jp_agg_group_list_free;
	pim_ifp->upstream_switch_list->cmp = pim_jp_agg_group_list_cmp;

	pim_ifp->sec_addr_list = list_new();
	pim_ifp->sec_addr_list->del = (void (*)(void *))pim_sec_addr_free;
	pim_ifp->sec_addr_list->cmp =
		(int (*)(void *, void *))pim_sec_addr_comp;

	pim_ifp->activeactive = false;

	RB_INIT(pim_ifchannel_rb, &pim_ifp->ifchannel_rb);

	ifp->info = pim_ifp;

	pim_sock_reset(ifp);

	pim_if_add_vif(ifp, ispimreg, is_vxlan_term);
	pim_ifp->pim->mcast_if_count++;

	return pim_ifp;
}

void pim_if_delete(struct interface *ifp)
{
	struct pim_interface *pim_ifp;

	assert(ifp);
	pim_ifp = ifp->info;
	assert(pim_ifp);

	pim_ifp->pim->mcast_if_count--;
	if (pim_ifp->gm_join_list) {
		pim_if_gm_join_del_all(ifp);
	}

	pim_ifchannel_delete_all(ifp);
#if PIM_IPV == 4
	igmp_sock_delete_all(ifp);
#endif
	if (pim_ifp->pim_sock_fd >= 0)
		pim_sock_delete(ifp, "Interface removed from configuration");

	pim_if_del_vif(ifp);

	pim_igmp_if_fini(pim_ifp);

	list_delete(&pim_ifp->pim_neighbor_list);
	list_delete(&pim_ifp->upstream_switch_list);
	list_delete(&pim_ifp->sec_addr_list);

	if (pim_ifp->bfd_config.profile)
		XFREE(MTYPE_TMP, pim_ifp->bfd_config.profile);

	XFREE(MTYPE_PIM_INTERFACE, pim_ifp->boundary_oil_plist);
	XFREE(MTYPE_PIM_INTERFACE, pim_ifp);

	ifp->info = NULL;
}

void pim_if_update_could_assert(struct interface *ifp)
{
	struct pim_interface *pim_ifp;
	struct pim_ifchannel *ch;

	pim_ifp = ifp->info;
	assert(pim_ifp);

	RB_FOREACH (ch, pim_ifchannel_rb, &pim_ifp->ifchannel_rb) {
		pim_ifchannel_update_could_assert(ch);
	}
}

static void pim_if_update_my_assert_metric(struct interface *ifp)
{
	struct pim_interface *pim_ifp;
	struct pim_ifchannel *ch;

	pim_ifp = ifp->info;
	assert(pim_ifp);

	RB_FOREACH (ch, pim_ifchannel_rb, &pim_ifp->ifchannel_rb) {
		pim_ifchannel_update_my_assert_metric(ch);
	}
}

static void pim_addr_change(struct interface *ifp)
{
	struct pim_interface *pim_ifp;

	pim_ifp = ifp->info;
	assert(pim_ifp);

	pim_if_dr_election(ifp); /* router's own DR Priority (addr) changes --
				    Done TODO T30 */
	pim_if_update_join_desired(pim_ifp); /* depends on DR */
	pim_if_update_could_assert(ifp);     /* depends on DR */
	pim_if_update_my_assert_metric(ifp); /* depends on could_assert */
	pim_if_update_assert_tracking_desired(
		ifp); /* depends on DR, join_desired */

	/*
	  RFC 4601: 4.3.1.  Sending Hello Messages

	  1) Before an interface goes down or changes primary IP address, a
	  Hello message with a zero HoldTime should be sent immediately
	  (with the old IP address if the IP address changed).
	  -- Done at the caller of the function as new ip already updated here

	  2) After an interface has changed its IP address, it MUST send a
	  Hello message with its new IP address.
	  -- DONE below

	  3) If an interface changes one of its secondary IP addresses, a
	  Hello message with an updated Address_List option and a non-zero
	  HoldTime should be sent immediately.
	  -- FIXME See TODO T31
	 */
	PIM_IF_FLAG_UNSET_HELLO_SENT(pim_ifp->flags);
	if (pim_ifp->pim_sock_fd < 0)
		return;
	pim_hello_restart_now(ifp); /* send hello and restart timer */
}

static int detect_primary_address_change(struct interface *ifp,
					 int force_prim_as_any,
					 const char *caller)
{
	struct pim_interface *pim_ifp = ifp->info;
	pim_addr new_prim_addr;
	int changed;

	if (force_prim_as_any)
		new_prim_addr = PIMADDR_ANY;
	else
		new_prim_addr = pim_find_primary_addr(ifp);

	changed = pim_addr_cmp(new_prim_addr, pim_ifp->primary_address);

	if (PIM_DEBUG_ZEBRA)
		zlog_debug("%s: old=%pPA new=%pPA on interface %s: %s",
			   __func__, &pim_ifp->primary_address, &new_prim_addr,
			   ifp->name, changed ? "changed" : "unchanged");

	if (changed) {
		/* Before updating pim_ifp send Hello time with 0 hold time */
		if (pim_ifp->pim_enable) {
			pim_hello_send(ifp, 0 /* zero-sec holdtime */);
		}
		pim_ifp->primary_address = new_prim_addr;
	}

	return changed;
}

static struct pim_secondary_addr *
pim_sec_addr_find(struct pim_interface *pim_ifp, struct prefix *addr)
{
	struct pim_secondary_addr *sec_addr;
	struct listnode *node;

	for (ALL_LIST_ELEMENTS_RO(pim_ifp->sec_addr_list, node, sec_addr)) {
		if (prefix_cmp(&sec_addr->addr, addr) == 0) {
			return sec_addr;
		}
	}

	return NULL;
}

static void pim_sec_addr_del(struct pim_interface *pim_ifp,
			     struct pim_secondary_addr *sec_addr)
{
	listnode_delete(pim_ifp->sec_addr_list, sec_addr);
	pim_sec_addr_free(sec_addr);
}

static int pim_sec_addr_add(struct pim_interface *pim_ifp, struct prefix *addr)
{
	int changed = 0;
	struct pim_secondary_addr *sec_addr;

	sec_addr = pim_sec_addr_find(pim_ifp, addr);
	if (sec_addr) {
		sec_addr->flags &= ~PIM_SEC_ADDRF_STALE;
		return changed;
	}

	sec_addr = XCALLOC(MTYPE_PIM_SEC_ADDR, sizeof(*sec_addr));

	changed = 1;
	sec_addr->addr = *addr;
	listnode_add_sort(pim_ifp->sec_addr_list, sec_addr);

	return changed;
}

static int pim_sec_addr_del_all(struct pim_interface *pim_ifp)
{
	int changed = 0;

	if (!list_isempty(pim_ifp->sec_addr_list)) {
		changed = 1;
		/* remove all nodes and free up the list itself */
		list_delete_all_node(pim_ifp->sec_addr_list);
	}

	return changed;
}

static int pim_sec_addr_update(struct interface *ifp)
{
	struct pim_interface *pim_ifp = ifp->info;
	struct connected *ifc;
	struct listnode *node;
	struct listnode *nextnode;
	struct pim_secondary_addr *sec_addr;
	int changed = 0;

	for (ALL_LIST_ELEMENTS_RO(pim_ifp->sec_addr_list, node, sec_addr)) {
		sec_addr->flags |= PIM_SEC_ADDRF_STALE;
	}

	frr_each (if_connected, ifp->connected, ifc) {
		pim_addr addr = pim_addr_from_prefix(ifc->address);

		if (pim_addr_is_any(addr))
			continue;

		if (!pim_addr_cmp(addr, pim_ifp->primary_address)) {
			/* don't add the primary address into the secondary
			 * address list */
			continue;
		}

		if (pim_sec_addr_add(pim_ifp, ifc->address)) {
			changed = 1;
		}
	}

	/* Drop stale entries */
	for (ALL_LIST_ELEMENTS(pim_ifp->sec_addr_list, node, nextnode,
			       sec_addr)) {
		if (sec_addr->flags & PIM_SEC_ADDRF_STALE) {
			pim_sec_addr_del(pim_ifp, sec_addr);
			changed = 1;
		}
	}

	return changed;
}

static int detect_secondary_address_change(struct interface *ifp,
					   int force_prim_as_any,
					   const char *caller)
{
	struct pim_interface *pim_ifp = ifp->info;
	int changed = 0;

	if (force_prim_as_any) {
		/* if primary address is being forced to zero just flush the
		 * secondary address list */
		changed = pim_sec_addr_del_all(pim_ifp);
	} else {
		/* re-evaluate the secondary address list */
		changed = pim_sec_addr_update(ifp);
	}

	return changed;
}

static void detect_address_change(struct interface *ifp, int force_prim_as_any,
				  const char *caller)
{
	int changed = 0;
	struct pim_interface *pim_ifp;

	pim_ifp = ifp->info;
	if (!pim_ifp)
		return;

	if (detect_primary_address_change(ifp, force_prim_as_any, caller)) {
		changed = 1;
	}

	if (detect_secondary_address_change(ifp, force_prim_as_any, caller)) {
		changed = 1;
	}


	if (changed) {
		if (!pim_ifp->pim_enable) {
			return;
		}

		pim_addr_change(ifp);
	}

	/* XXX: if we have unnumbered interfaces we need to run detect address
	 * address change on all of them when the lo address changes */
}

int pim_update_source_set(struct interface *ifp, pim_addr source)
{
	struct pim_interface *pim_ifp = ifp->info;

	if (!pim_ifp) {
		return PIM_IFACE_NOT_FOUND;
	}

	if (!pim_addr_cmp(pim_ifp->update_source, source)) {
		return PIM_UPDATE_SOURCE_DUP;
	}

	pim_ifp->update_source = source;
	detect_address_change(ifp, 0 /* force_prim_as_any */, __func__);

	return PIM_SUCCESS;
}

void pim_if_addr_add(struct connected *ifc)
{
	struct pim_interface *pim_ifp;
	struct interface *ifp;
	bool vxlan_term;

	assert(ifc);

	ifp = ifc->ifp;
	assert(ifp);
	pim_ifp = ifp->info;
	if (!pim_ifp)
		return;

	if (!if_is_operative(ifp))
		return;

	if (PIM_DEBUG_ZEBRA)
		zlog_debug("%s: %s ifindex=%d connected IP address %pFX %s",
			   __func__, ifp->name, ifp->ifindex, ifc->address,
			   CHECK_FLAG(ifc->flags, ZEBRA_IFA_SECONDARY)
				   ? "secondary"
				   : "primary");
#if PIM_IPV != 4
	if (IN6_IS_ADDR_LINKLOCAL(&ifc->address->u.prefix6) ||
	    IN6_IS_ADDR_LOOPBACK(&ifc->address->u.prefix6)) {
		if (IN6_IS_ADDR_UNSPECIFIED(&pim_ifp->ll_lowest))
			pim_ifp->ll_lowest = ifc->address->u.prefix6;
		else if (IPV6_ADDR_CMP(&ifc->address->u.prefix6,
				       &pim_ifp->ll_lowest) < 0)
			pim_ifp->ll_lowest = ifc->address->u.prefix6;

		if (IPV6_ADDR_CMP(&ifc->address->u.prefix6,
				  &pim_ifp->ll_highest) > 0)
			pim_ifp->ll_highest = ifc->address->u.prefix6;

		if (PIM_DEBUG_ZEBRA)
			zlog_debug(
				"%s: new link-local %pI6, lowest now %pI6, highest %pI6",
				ifc->ifp->name, &ifc->address->u.prefix6,
				&pim_ifp->ll_lowest, &pim_ifp->ll_highest);
	}
#endif

	detect_address_change(ifp, 0, __func__);

	// if (ifc->address->family != AF_INET)
	//  return;

#if PIM_IPV == 4
	struct in_addr ifaddr = ifc->address->u.prefix4;

	if (pim_ifp->gm_enable) {
		struct gm_sock *igmp;

		/* lookup IGMP socket */
		igmp = pim_igmp_sock_lookup_ifaddr(pim_ifp->gm_socket_list,
						   ifaddr);
		if (!igmp) {
			/* if addr new, add IGMP socket */
			if (ifc->address->family == AF_INET)
				pim_igmp_sock_add(pim_ifp->gm_socket_list,
						  ifaddr, ifp, false);
		} else if (igmp->mtrace_only) {
			igmp_sock_delete(igmp);
			pim_igmp_sock_add(pim_ifp->gm_socket_list, ifaddr, ifp,
					  false);
		}

		/* Replay Static IGMP groups */
		if (pim_ifp->gm_join_list) {
			struct listnode *node;
			struct listnode *nextnode;
			struct gm_join *ij;
			int join_fd;

			for (ALL_LIST_ELEMENTS(pim_ifp->gm_join_list, node,
					       nextnode, ij)) {
				/* Close socket and reopen with Source and Group
				 */
				close(ij->sock_fd);
				join_fd = gm_join_sock(
					ifp->name, ifp->ifindex, ij->group_addr,
					ij->source_addr, pim_ifp);
				if (join_fd < 0) {
					char group_str[INET_ADDRSTRLEN];
					char source_str[INET_ADDRSTRLEN];
					pim_inet4_dump("<grp?>", ij->group_addr,
						       group_str,
						       sizeof(group_str));
					pim_inet4_dump(
						"<src?>", ij->source_addr,
						source_str, sizeof(source_str));
					zlog_warn(
						"%s: gm_join_sock() failure for IGMP group %s source %s on interface %s",
						__func__, group_str, source_str,
						ifp->name);
					/* warning only */
				} else
					ij->sock_fd = join_fd;
			}
		}
	} /* igmp */
	else {
		struct gm_sock *igmp;

		/* lookup IGMP socket */
		igmp = pim_igmp_sock_lookup_ifaddr(pim_ifp->gm_socket_list,
						   ifaddr);
		if (ifc->address->family == AF_INET) {
			if (igmp)
				igmp_sock_delete(igmp);
			/* if addr new, add IGMP socket */
			pim_igmp_sock_add(pim_ifp->gm_socket_list, ifaddr, ifp,
					  true);
		}
	} /* igmp mtrace only */
#endif

	if (pim_ifp->pim_enable) {

		if (!pim_addr_is_any(pim_ifp->primary_address)) {

			/* Interface has a valid socket ? */
			if (pim_ifp->pim_sock_fd < 0) {
				if (pim_sock_add(ifp)) {
					zlog_warn(
						"Failure creating PIM socket for interface %s",
						ifp->name);
				}
			}
			struct pim_nexthop_cache *pnc = NULL;
			struct pim_rpf rpf;
			struct zclient *zclient = NULL;

			zclient = pim_zebra_zclient_get();
			/* RP config might come prior to (local RP's interface)
			   IF UP event.
			   In this case, pnc would not have pim enabled
			   nexthops.
			   Once Interface is UP and pim info is available,
			   reregister
			   with RNH address to receive update and add the
			   interface as nexthop. */
			memset(&rpf, 0, sizeof(struct pim_rpf));
			rpf.rpf_addr = pim_addr_from_prefix(ifc->address);
			pnc = pim_nexthop_cache_find(pim_ifp->pim, &rpf);
			if (pnc)
				pim_sendmsg_zebra_rnh(pim_ifp->pim, zclient,
						      pnc,
						      ZEBRA_NEXTHOP_REGISTER);
		}
	} /* pim */

	/*
	  PIM or IGMP is enabled on interface, and there is at least one
	  address assigned, then try to create a vif_index.
	*/
	if (pim_ifp->mroute_vif_index < 0) {
		vxlan_term = pim_vxlan_is_term_dev_cfg(pim_ifp->pim, ifp);
		pim_if_add_vif(ifp, false, vxlan_term);
	}
	gm_ifp_update(ifp);
	pim_ifchannel_scan_forward_start(ifp);
}

static void pim_if_addr_del_igmp(struct connected *ifc)
{
#if PIM_IPV == 4
	struct pim_interface *pim_ifp = ifc->ifp->info;
	struct gm_sock *igmp;
	struct in_addr ifaddr;

	if (ifc->address->family != AF_INET) {
		/* non-IPv4 address */
		return;
	}

	if (!pim_ifp) {
		/* IGMP not enabled on interface */
		return;
	}

	ifaddr = ifc->address->u.prefix4;

	/* lookup IGMP socket */
	igmp = pim_igmp_sock_lookup_ifaddr(pim_ifp->gm_socket_list, ifaddr);
	if (igmp) {
		/* if addr found, del IGMP socket */
		igmp_sock_delete(igmp);
	}
#endif
}

static void pim_if_addr_del_pim(struct connected *ifc)
{
	struct pim_interface *pim_ifp = ifc->ifp->info;

	if (ifc->address->family != PIM_AF) {
		/* non-IPv4 address */
		return;
	}

	if (!pim_ifp) {
		/* PIM not enabled on interface */
		return;
	}

	if (!pim_addr_is_any(pim_ifp->primary_address)) {
		/* Interface keeps a valid primary address */
		return;
	}

	if (pim_ifp->pim_sock_fd < 0) {
		/* Interface does not hold a valid socket any longer */
		return;
	}

	/*
	  pim_sock_delete() closes the socket, stops read and timer threads,
	  and kills all neighbors.
	 */
	pim_sock_delete(ifc->ifp,
			"last address has been removed from interface");
}

void pim_if_addr_del(struct connected *ifc, int force_prim_as_any)
{
	struct interface *ifp;

	assert(ifc);
	ifp = ifc->ifp;
	assert(ifp);

	if (PIM_DEBUG_ZEBRA)
		zlog_debug("%s: %s ifindex=%d disconnected IP address %pFX %s",
			   __func__, ifp->name, ifp->ifindex, ifc->address,
			   CHECK_FLAG(ifc->flags, ZEBRA_IFA_SECONDARY)
				   ? "secondary"
				   : "primary");

#if PIM_IPV == 6
	struct pim_interface *pim_ifp = ifc->ifp->info;

	if (pim_ifp &&
	    (!IPV6_ADDR_CMP(&ifc->address->u.prefix6, &pim_ifp->ll_lowest) ||
	     !IPV6_ADDR_CMP(&ifc->address->u.prefix6, &pim_ifp->ll_highest))) {
		struct connected *cc;

		memset(&pim_ifp->ll_lowest, 0xff, sizeof(pim_ifp->ll_lowest));
		memset(&pim_ifp->ll_highest, 0, sizeof(pim_ifp->ll_highest));

		frr_each (if_connected, ifc->ifp->connected, cc) {
			if (!IN6_IS_ADDR_LINKLOCAL(&cc->address->u.prefix6) &&
			    !IN6_IS_ADDR_LOOPBACK(&cc->address->u.prefix6))
				continue;

			if (IPV6_ADDR_CMP(&cc->address->u.prefix6,
					  &pim_ifp->ll_lowest) < 0)
				pim_ifp->ll_lowest = cc->address->u.prefix6;
			if (IPV6_ADDR_CMP(&cc->address->u.prefix6,
					  &pim_ifp->ll_highest) > 0)
				pim_ifp->ll_highest = cc->address->u.prefix6;
		}

		if (pim_ifp->ll_lowest.s6_addr[0] == 0xff)
			memset(&pim_ifp->ll_lowest, 0,
			       sizeof(pim_ifp->ll_lowest));

		if (PIM_DEBUG_ZEBRA)
			zlog_debug(
				"%s: removed link-local %pI6, lowest now %pI6, highest %pI6",
				ifc->ifp->name, &ifc->address->u.prefix6,
				&pim_ifp->ll_lowest, &pim_ifp->ll_highest);

		gm_ifp_update(ifp);
	}
#endif

	detect_address_change(ifp, force_prim_as_any, __func__);

	pim_if_addr_del_igmp(ifc);
	pim_if_addr_del_pim(ifc);
}

void pim_if_addr_add_all(struct interface *ifp)
{
	struct connected *ifc;
	int v4_addrs = 0;
	int v6_addrs = 0;
	struct pim_interface *pim_ifp = ifp->info;
	bool vxlan_term;


	/* PIM/IGMP enabled ? */
	if (!pim_ifp)
		return;

	frr_each (if_connected, ifp->connected, ifc) {
		struct prefix *p = ifc->address;

		if (p->family != AF_INET)
			v6_addrs++;
		else
			v4_addrs++;
		pim_if_addr_add(ifc);
	}

	if (!v4_addrs && v6_addrs && !if_is_loopback(ifp) &&
	    pim_ifp->pim_enable && !pim_addr_is_any(pim_ifp->primary_address) &&
	    pim_ifp->pim_sock_fd < 0 && pim_sock_add(ifp)) {
		/* Interface has a valid primary address ? */
		/* Interface has a valid socket ? */
		zlog_warn("Failure creating PIM socket for interface %s",
			  ifp->name);
	}
	/*
	 * PIM or IGMP/MLD is enabled on interface, and there is at least one
	 * address assigned, then try to create a vif_index.
	 */
	if (pim_ifp->mroute_vif_index < 0) {
		vxlan_term = pim_vxlan_is_term_dev_cfg(pim_ifp->pim, ifp);
		pim_if_add_vif(ifp, false, vxlan_term);
	}
	gm_ifp_update(ifp);
	pim_ifchannel_scan_forward_start(ifp);

	pim_rp_setup(pim_ifp->pim);
	pim_rp_check_on_if_add(pim_ifp);
}

void pim_if_addr_del_all(struct interface *ifp)
{
	struct connected *ifc;
	struct pim_instance *pim;

	pim = ifp->vrf->info;
	if (!pim)
		return;

	/* PIM/IGMP enabled ? */
	if (!ifp->info)
		return;

	frr_each_safe (if_connected, ifp->connected, ifc) {
		struct prefix *p = ifc->address;

		if (p->family != PIM_AF)
			continue;

		pim_if_addr_del(ifc, 1 /* force_prim_as_any=true */);
	}

	pim_rp_setup(pim);
	pim_i_am_rp_re_evaluate(pim);
}

void pim_if_addr_del_all_igmp(struct interface *ifp)
{
	struct connected *ifc;

	/* PIM/IGMP enabled ? */
	if (!ifp->info)
		return;

	frr_each_safe (if_connected, ifp->connected, ifc) {
		struct prefix *p = ifc->address;

		if (p->family != AF_INET)
			continue;

		pim_if_addr_del_igmp(ifc);
	}
}

pim_addr pim_find_primary_addr(struct interface *ifp)
{
	struct connected *ifc;
	struct pim_interface *pim_ifp = ifp->info;

	if (pim_ifp && !pim_addr_is_any(pim_ifp->update_source))
		return pim_ifp->update_source;

#if PIM_IPV == 6
	if (pim_ifp && !pim_addr_is_any(pim_ifp->ll_highest))
		return pim_ifp->ll_highest;

	pim_addr best_addr = PIMADDR_ANY;

	frr_each (if_connected, ifp->connected, ifc) {
		pim_addr addr;

		if (ifc->address->family != AF_INET6)
			continue;

		addr = pim_addr_from_prefix(ifc->address);
		if (!IN6_IS_ADDR_LINKLOCAL(&addr))
			continue;
		if (pim_addr_cmp(addr, best_addr) > 0)
			best_addr = addr;
	}

	return best_addr;
#else
	int v4_addrs = 0;
	int v6_addrs = 0;
	struct connected *promote_ifc = NULL;

	frr_each (if_connected, ifp->connected, ifc) {
		switch (ifc->address->family) {
		case AF_INET:
			v4_addrs++;
			break;
		case AF_INET6:
			v6_addrs++;
			break;
		default:
			continue;
		}

		if (ifc->address->family != PIM_AF)
			continue;

		if (CHECK_FLAG(ifc->flags, ZEBRA_IFA_SECONDARY)) {
			promote_ifc = ifc;
			continue;
		}

		return pim_addr_from_prefix(ifc->address);
	}


	/* Promote the new primary address. */
	if (v4_addrs && promote_ifc) {
		UNSET_FLAG(promote_ifc->flags, ZEBRA_IFA_SECONDARY);
		return pim_addr_from_prefix(promote_ifc->address);
	}

	/*
	 * If we have no v4_addrs and v6 is configured
	 * We probably are using unnumbered
	 * So let's grab the loopbacks v4 address
	 * and use that as the primary address
	 */
	if (!v4_addrs && v6_addrs) {
		struct interface *lo_ifp;

		// DBS - Come back and check here
		if (ifp->vrf->vrf_id == VRF_DEFAULT)
			lo_ifp = if_lookup_by_name("lo", ifp->vrf->vrf_id);
		else
			lo_ifp = if_lookup_by_name(ifp->vrf->name,
						   ifp->vrf->vrf_id);

		if (lo_ifp && (lo_ifp != ifp))
			return pim_find_primary_addr(lo_ifp);
	}
	return PIMADDR_ANY;
#endif
}

static int pim_iface_next_vif_index(struct interface *ifp)
{
	struct pim_interface *pim_ifp = ifp->info;
	struct pim_instance *pim = pim_ifp->pim;
	int i;

	/*
	 * The pimreg vif is always going to be in index 0
	 * of the table.
	 */
	if (ifp->ifindex == PIM_OIF_PIM_REGISTER_VIF)
		return 0;

	for (i = 1; i < MAXVIFS; i++) {
		if (pim->iface_vif_index[i] == 0)
			return i;
	}
	return MAXVIFS;
}

/*
  pim_if_add_vif() uses ifindex as vif_index

  see also pim_if_find_vifindex_by_ifindex()
 */
int pim_if_add_vif(struct interface *ifp, bool ispimreg, bool is_vxlan_term)
{
	struct pim_interface *pim_ifp = ifp->info;
	pim_addr ifaddr;
	unsigned char flags = 0;

	assert(pim_ifp);

	if (pim_ifp->mroute_vif_index > 0) {
		zlog_warn("%s: vif_index=%d > 0 on interface %s ifindex=%d",
			  __func__, pim_ifp->mroute_vif_index, ifp->name,
			  ifp->ifindex);
		return -1;
	}

	if (ifp->ifindex < 0) {
		zlog_warn("%s: ifindex=%d < 0 on interface %s", __func__,
			  ifp->ifindex, ifp->name);
		return -2;
	} else if ((ifp->ifindex == PIM_OIF_PIM_REGISTER_VIF) &&
		   ((strncmp(ifp->name, "pimreg", 6)) &&
		    (strncmp(ifp->name, "pim6reg", 7)))) {
		zlog_warn("%s: ifindex=%d on interface %s", __func__,
			  ifp->ifindex, ifp->name);
		return -2;
	}

	ifaddr = pim_ifp->primary_address;
#if PIM_IPV != 6
	/* IPv6 API is always by interface index */
	if (!ispimreg && !is_vxlan_term && pim_addr_is_any(ifaddr)) {
		zlog_warn(
			"%s: could not get address for interface %s ifindex=%d",
			__func__, ifp->name, ifp->ifindex);
		return -4;
	}
#endif

	pim_ifp->mroute_vif_index = pim_iface_next_vif_index(ifp);

	if (pim_ifp->mroute_vif_index >= MAXVIFS) {
		zlog_warn(
			"%s: Attempting to configure more than MAXVIFS=%d on pim enabled interface %s",
			__func__, MAXVIFS, ifp->name);
		return -3;
	}

	if (ifp->ifindex == PIM_OIF_PIM_REGISTER_VIF)
		flags = VIFF_REGISTER;
#ifdef VIFF_USE_IFINDEX
	else
		flags = VIFF_USE_IFINDEX;
#endif

	if (pim_mroute_add_vif(ifp, ifaddr, flags)) {
		/* pim_mroute_add_vif reported error */
		return -5;
	}

	pim_ifp->pim->iface_vif_index[pim_ifp->mroute_vif_index] = 1;

	if (!ispimreg)
		gm_ifp_update(ifp);

	/* if the device qualifies as pim_vxlan iif/oif update vxlan entries */
	pim_vxlan_add_vif(ifp);
	return 0;
}

int pim_if_del_vif(struct interface *ifp)
{
	struct pim_interface *pim_ifp = ifp->info;

	if (pim_ifp->mroute_vif_index < 1) {
		zlog_warn("%s: vif_index=%d < 1 on interface %s ifindex=%d",
			  __func__, pim_ifp->mroute_vif_index, ifp->name,
			  ifp->ifindex);
		return -1;
	}

	/* if the device was a pim_vxlan iif/oif update vxlan mroute entries */
	pim_vxlan_del_vif(ifp);

	gm_ifp_teardown(ifp);

	pim_mroute_del_vif(ifp);

	/*
	  Update vif_index
	 */
	pim_ifp->pim->iface_vif_index[pim_ifp->mroute_vif_index] = 0;

	pim_ifp->mroute_vif_index = -1;
	return 0;
}

// DBS - VRF Revist
struct interface *pim_if_find_by_vif_index(struct pim_instance *pim,
					   ifindex_t vif_index)
{
	struct interface *ifp;

	FOR_ALL_INTERFACES (pim->vrf, ifp) {
		if (ifp->info) {
			struct pim_interface *pim_ifp;
			pim_ifp = ifp->info;

			if (vif_index == pim_ifp->mroute_vif_index)
				return ifp;
		}
	}

	return 0;
}

/*
  pim_if_add_vif() uses ifindex as vif_index
 */
int pim_if_find_vifindex_by_ifindex(struct pim_instance *pim, ifindex_t ifindex)
{
	struct pim_interface *pim_ifp;
	struct interface *ifp;

	ifp = if_lookup_by_index(ifindex, pim->vrf->vrf_id);
	if (!ifp || !ifp->info)
		return -1;
	pim_ifp = ifp->info;

	return pim_ifp->mroute_vif_index;
}

int pim_if_lan_delay_enabled(struct interface *ifp)
{
	struct pim_interface *pim_ifp;

	pim_ifp = ifp->info;
	assert(pim_ifp);
	assert(pim_ifp->pim_number_of_nonlandelay_neighbors >= 0);

	return pim_ifp->pim_number_of_nonlandelay_neighbors == 0;
}

uint16_t pim_if_effective_propagation_delay_msec(struct interface *ifp)
{
	if (pim_if_lan_delay_enabled(ifp)) {
		struct pim_interface *pim_ifp;
		pim_ifp = ifp->info;
		return pim_ifp->pim_neighbors_highest_propagation_delay_msec;
	} else {
		return PIM_DEFAULT_PROPAGATION_DELAY_MSEC;
	}
}

uint16_t pim_if_effective_override_interval_msec(struct interface *ifp)
{
	if (pim_if_lan_delay_enabled(ifp)) {
		struct pim_interface *pim_ifp;
		pim_ifp = ifp->info;
		return pim_ifp->pim_neighbors_highest_override_interval_msec;
	} else {
		return PIM_DEFAULT_OVERRIDE_INTERVAL_MSEC;
	}
}

int pim_if_t_override_msec(struct interface *ifp)
{
	int effective_override_interval_msec;
	int t_override_msec;

	effective_override_interval_msec =
		pim_if_effective_override_interval_msec(ifp);

	t_override_msec =
		frr_weak_random() % (effective_override_interval_msec + 1);

	return t_override_msec;
}

uint16_t pim_if_jp_override_interval_msec(struct interface *ifp)
{
	return pim_if_effective_propagation_delay_msec(ifp)
	       + pim_if_effective_override_interval_msec(ifp);
}

/*
  RFC 4601: 4.1.6.  State Summarization Macros

  The function NBR( I, A ) uses information gathered through PIM Hello
  messages to map the IP address A of a directly connected PIM
  neighbor router on interface I to the primary IP address of the same
  router (Section 4.3.4).  The primary IP address of a neighbor is the
  address that it uses as the source of its PIM Hello messages.
*/
struct pim_neighbor *pim_if_find_neighbor(struct interface *ifp, pim_addr addr)
{
	struct listnode *neighnode;
	struct pim_neighbor *neigh;
	struct pim_interface *pim_ifp;
	struct prefix p;

	assert(ifp);

	pim_ifp = ifp->info;
	if (!pim_ifp) {
		zlog_warn("%s: multicast not enabled on interface %s", __func__,
			  ifp->name);
		return 0;
	}

	pim_addr_to_prefix(&p, addr);

	for (ALL_LIST_ELEMENTS_RO(pim_ifp->pim_neighbor_list, neighnode,
				  neigh)) {

		/* primary address ? */
		if (!pim_addr_cmp(neigh->source_addr, addr))
			return neigh;

		/* secondary address ? */
		if (pim_neighbor_find_secondary(neigh, &p))
			return neigh;
	}

	if (PIM_DEBUG_PIM_TRACE)
		zlog_debug(
			"%s: neighbor not found for address %pPA on interface %s",
			__func__, &addr, ifp->name);

	return NULL;
}

long pim_if_t_suppressed_msec(struct interface *ifp)
{
	struct pim_interface *pim_ifp;
	long t_suppressed_msec;
	uint32_t ramount = 0;

	pim_ifp = ifp->info;
	assert(pim_ifp);

	/* join suppression disabled ? */
	if (pim_ifp->pim_can_disable_join_suppression)
		return 0;

	/* t_suppressed = t_periodic * rand(1.1, 1.4) */
	ramount = 1100 + (frr_weak_random() % (1400 - 1100 + 1));
	t_suppressed_msec = router->t_periodic * ramount;

	return t_suppressed_msec;
}

static void gm_join_free(struct gm_join *ij)
{
	XFREE(MTYPE_PIM_IGMP_JOIN, ij);
}

static struct gm_join *gm_join_find(struct list *join_list, pim_addr group_addr,
				    pim_addr source_addr)
{
	struct listnode *node;
	struct gm_join *ij;

	assert(join_list);

	for (ALL_LIST_ELEMENTS_RO(join_list, node, ij)) {
		if ((!pim_addr_cmp(group_addr, ij->group_addr)) &&
		    (!pim_addr_cmp(source_addr, ij->source_addr)))
			return ij;
	}

	return 0;
}

static int gm_join_sock(const char *ifname, ifindex_t ifindex,
			pim_addr group_addr, pim_addr source_addr,
			struct pim_interface *pim_ifp)
{
	int join_fd;

	pim_ifp->igmp_ifstat_joins_sent++;

	join_fd = pim_socket_raw(IPPROTO_GM);
	if (join_fd < 0) {
		pim_ifp->igmp_ifstat_joins_failed++;
		return -1;
	}

	if (pim_gm_join_source(join_fd, ifindex, group_addr, source_addr)) {
		zlog_warn(
			"%s: setsockopt(fd=%d) failure for " GM
			" group %pPAs source %pPAs ifindex %d on interface %s: errno=%d: %s",
			__func__, join_fd, &group_addr, &source_addr, ifindex,
			ifname, errno, safe_strerror(errno));

		pim_ifp->igmp_ifstat_joins_failed++;

		close(join_fd);
		return -2;
	}

	return join_fd;
}

static struct gm_join *gm_join_new(struct interface *ifp, pim_addr group_addr,
				   pim_addr source_addr)
{
	struct pim_interface *pim_ifp;
	struct gm_join *ij;
	int join_fd;

	pim_ifp = ifp->info;
	assert(pim_ifp);

	join_fd = gm_join_sock(ifp->name, ifp->ifindex, group_addr, source_addr,
			       pim_ifp);
	if (join_fd < 0) {
		zlog_warn("%s: gm_join_sock() failure for " GM
			  " group %pPAs source %pPAs on interface %s",
			  __func__, &group_addr, &source_addr, ifp->name);
		return 0;
	}

	ij = XCALLOC(MTYPE_PIM_IGMP_JOIN, sizeof(*ij));

	ij->sock_fd = join_fd;
	ij->group_addr = group_addr;
	ij->source_addr = source_addr;
	ij->sock_creation = pim_time_monotonic_sec();

	listnode_add(pim_ifp->gm_join_list, ij);

	return ij;
}

ferr_r pim_if_gm_join_add(struct interface *ifp, pim_addr group_addr,
			  pim_addr source_addr)
{
	struct pim_interface *pim_ifp;
	struct gm_join *ij;

	pim_ifp = ifp->info;
	if (!pim_ifp) {
		return ferr_cfg_invalid("multicast not enabled on interface %s",
					ifp->name);
	}

	if (!pim_ifp->gm_join_list) {
		pim_ifp->gm_join_list = list_new();
		pim_ifp->gm_join_list->del = (void (*)(void *))gm_join_free;
	}

	ij = gm_join_find(pim_ifp->gm_join_list, group_addr, source_addr);

	/* This interface has already been configured to join this IGMP/MLD
	 * group
	 */
	if (ij) {
		return ferr_ok();
	}

	(void)gm_join_new(ifp, group_addr, source_addr);

	if (PIM_DEBUG_GM_EVENTS) {
		zlog_debug(
			"%s: issued static " GM
			" join for channel (S,G)=(%pPA,%pPA) on interface %s",
			__func__, &source_addr, &group_addr, ifp->name);
	}

	return ferr_ok();
}

int pim_if_gm_join_del(struct interface *ifp, pim_addr group_addr,
		       pim_addr source_addr)
{
	struct pim_interface *pim_ifp;
	struct gm_join *ij;

	pim_ifp = ifp->info;
	if (!pim_ifp) {
		zlog_warn("%s: multicast not enabled on interface %s", __func__,
			  ifp->name);
		return -1;
	}

	if (!pim_ifp->gm_join_list) {
		zlog_warn("%s: no " GM " join on interface %s", __func__,
			  ifp->name);
		return -2;
	}

	ij = gm_join_find(pim_ifp->gm_join_list, group_addr, source_addr);
	if (!ij) {
		zlog_warn("%s: could not find " GM
			  " group %pPAs source %pPAs on interface %s",
			  __func__, &group_addr, &source_addr, ifp->name);
		return -3;
	}

	if (close(ij->sock_fd)) {
		zlog_warn(
			"%s: failure closing sock_fd=%d for " GM
			" group %pPAs source %pPAs on interface %s: errno=%d: %s",
			__func__, ij->sock_fd, &group_addr, &source_addr,
			ifp->name, errno, safe_strerror(errno));
		/* warning only */
	}
	listnode_delete(pim_ifp->gm_join_list, ij);
	gm_join_free(ij);
	if (listcount(pim_ifp->gm_join_list) < 1) {
		list_delete(&pim_ifp->gm_join_list);
		pim_ifp->gm_join_list = 0;
	}

	return 0;
}

__attribute__((unused))
static void pim_if_gm_join_del_all(struct interface *ifp)
{
	struct pim_interface *pim_ifp;
	struct listnode *node;
	struct listnode *nextnode;
	struct gm_join *ij;

	pim_ifp = ifp->info;
	if (!pim_ifp) {
		zlog_warn("%s: multicast not enabled on interface %s", __func__,
			  ifp->name);
		return;
	}

	if (!pim_ifp->gm_join_list)
		return;

	for (ALL_LIST_ELEMENTS(pim_ifp->gm_join_list, node, nextnode, ij))
		pim_if_gm_join_del(ifp, ij->group_addr, ij->source_addr);
}

/*
  RFC 4601

  Transitions from "I am Assert Loser" State

  Current Winner's GenID Changes or NLT Expires

  The Neighbor Liveness Timer associated with the current winner
  expires or we receive a Hello message from the current winner
  reporting a different GenID from the one it previously reported.
  This indicates that the current winner's interface or router has
  gone down (and may have come back up), and so we must assume it no
  longer knows it was the winner.
 */
void pim_if_assert_on_neighbor_down(struct interface *ifp, pim_addr neigh_addr)
{
	struct pim_interface *pim_ifp;
	struct pim_ifchannel *ch;

	pim_ifp = ifp->info;
	assert(pim_ifp);

	RB_FOREACH (ch, pim_ifchannel_rb, &pim_ifp->ifchannel_rb) {
		/* Is (S,G,I) assert loser ? */
		if (ch->ifassert_state != PIM_IFASSERT_I_AM_LOSER)
			continue;
		/* Dead neighbor was winner ? */
		if (pim_addr_cmp(ch->ifassert_winner, neigh_addr))
			continue;

		assert_action_a5(ch);
	}
}

void pim_if_update_join_desired(struct pim_interface *pim_ifp)
{
	struct pim_ifchannel *ch;

	/* clear off flag from interface's upstreams */
	RB_FOREACH (ch, pim_ifchannel_rb, &pim_ifp->ifchannel_rb) {
		PIM_UPSTREAM_FLAG_UNSET_DR_JOIN_DESIRED_UPDATED(
			ch->upstream->flags);
	}

	/* scan per-interface (S,G,I) state on this I interface */
	RB_FOREACH (ch, pim_ifchannel_rb, &pim_ifp->ifchannel_rb) {
		struct pim_upstream *up = ch->upstream;

		if (PIM_UPSTREAM_FLAG_TEST_DR_JOIN_DESIRED_UPDATED(up->flags))
			continue;

		/* update join_desired for the global (S,G) state */
		pim_upstream_update_join_desired(pim_ifp->pim, up);
		PIM_UPSTREAM_FLAG_SET_DR_JOIN_DESIRED_UPDATED(up->flags);
	}
}

void pim_if_update_assert_tracking_desired(struct interface *ifp)
{
	struct pim_interface *pim_ifp;
	struct pim_ifchannel *ch;

	pim_ifp = ifp->info;
	if (!pim_ifp)
		return;

	RB_FOREACH (ch, pim_ifchannel_rb, &pim_ifp->ifchannel_rb) {
		pim_ifchannel_update_assert_tracking_desired(ch);
	}
}

/*
 * PIM wants to have an interface pointer for everything it does.
 * The pimreg is a special interface that we have that is not
 * quite an interface but a VIF is created for it.
 */
void pim_if_create_pimreg(struct pim_instance *pim)
{
	char pimreg_name[IFNAMSIZ];

	if (!pim->regiface) {
		if (pim->vrf->vrf_id == VRF_DEFAULT)
			strlcpy(pimreg_name, PIMREG, sizeof(pimreg_name));
		else
			snprintf(pimreg_name, sizeof(pimreg_name), PIMREG "%u",
				 pim->vrf->data.l.table_id);

		pim->regiface = if_get_by_name(pimreg_name, pim->vrf->vrf_id,
					       pim->vrf->name);
		pim->regiface->ifindex = PIM_OIF_PIM_REGISTER_VIF;

		/*
		 * The pimreg interface might has been removed from
		 * kerenl with the VRF's deletion.  It must be
		 * recreated, so delete the old one first.
		 */
		if (pim->regiface->info)
			pim_if_delete(pim->regiface);

		pim_if_new(pim->regiface, false, false, true,
			   false /*vxlan_term*/);

		/*
		 * On vrf moves we delete the interface if there
		 * is nothing going on with it.  We cannot have
		 * the pimregiface deleted.
		 */
		pim->regiface->configured = true;

	}
}

struct prefix *pim_if_connected_to_source(struct interface *ifp, pim_addr src)
{
	struct connected *c;
	struct prefix p;

	if (!ifp)
		return NULL;

	pim_addr_to_prefix(&p, src);

	frr_each (if_connected, ifp->connected, c) {
		if (c->address->family != PIM_AF)
			continue;
		if (prefix_match(c->address, &p))
			return c->address;
		if (CONNECTED_PEER(c) && prefix_match(c->destination, &p))
			/* this is not a typo, on PtP we need to return the
			 * *local* address that lines up with src.
			 */
			return c->address;
	}

	return NULL;
}

bool pim_if_is_vrf_device(struct interface *ifp)
{
	if (if_is_vrf(ifp))
		return true;

	return false;
}

int pim_if_ifchannel_count(struct pim_interface *pim_ifp)
{
	struct pim_ifchannel *ch;
	int count = 0;

	RB_FOREACH (ch, pim_ifchannel_rb, &pim_ifp->ifchannel_rb) {
		count++;
	}

	return count;
}

static int pim_ifp_create(struct interface *ifp)
{
	struct pim_instance *pim;

	pim = ifp->vrf->info;
	if (PIM_DEBUG_ZEBRA) {
		zlog_debug(
			"%s: %s index %d vrf %s(%u) flags %ld metric %d mtu %d operative %d",
			__func__, ifp->name, ifp->ifindex, ifp->vrf->name,
			ifp->vrf->vrf_id, (long)ifp->flags, ifp->metric,
			ifp->mtu, if_is_operative(ifp));
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

		/*
		 * Due to ordering issues based upon when
		 * a command is entered we should ensure that
		 * the pim reg is created for this vrf if we
		 * have configuration for it already.
		 *
		 * this is a no-op if it's already been done.
		 */
		pim_if_create_pimreg(pim);
	}

#if PIM_IPV == 4
	/*
	 * If we are a vrf device that is up, open up the pim_socket for
	 * listening
	 * to incoming pim messages irrelevant if the user has configured us
	 * for pim or not.
	 */
	if (pim_if_is_vrf_device(ifp)) {
		struct pim_interface *pim_ifp;

		if (!ifp->info) {
			pim_ifp = pim_if_new(ifp, false, false, false,
					     false /*vxlan_term*/);
			ifp->info = pim_ifp;
		}

		pim_sock_add(ifp);
	}

	if (!strncmp(ifp->name, PIM_VXLAN_TERM_DEV_NAME,
		     sizeof(PIM_VXLAN_TERM_DEV_NAME))) {
		if (pim->mcast_if_count < MAXVIFS)
			pim_vxlan_add_term_dev(pim, ifp);
		else
			zlog_warn(
				"%s: Cannot enable pim on %s. MAXVIFS(%d) reached. Deleting and readding the vxlan termimation device after unconfiguring pim from other interfaces may succeed.",
				__func__, ifp->name, MAXVIFS);
	}
#endif

	return 0;
}

static int pim_ifp_up(struct interface *ifp)
{
	uint32_t table_id;
	struct pim_interface *pim_ifp;
	struct pim_instance *pim;

	if (PIM_DEBUG_ZEBRA) {
		zlog_debug(
			"%s: %s index %d vrf %s(%u) flags %ld metric %d mtu %d operative %d",
			__func__, ifp->name, ifp->ifindex, ifp->vrf->name,
			ifp->vrf->vrf_id, (long)ifp->flags, ifp->metric,
			ifp->mtu, if_is_operative(ifp));
	}

	pim = ifp->vrf->info;

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

	/*
	 * If we have a pimreg device callback and it's for a specific
	 * table set the master appropriately
	 */
	if (sscanf(ifp->name, "" PIMREG "%" SCNu32, &table_id) == 1) {
		struct vrf *vrf;
		RB_FOREACH (vrf, vrf_name_head, &vrfs_by_name) {
			if ((table_id == vrf->data.l.table_id)
			    && (ifp->vrf->vrf_id != vrf->vrf_id)) {
				struct interface *master = if_lookup_by_name(
					vrf->name, vrf->vrf_id);

				if (!master) {
					zlog_debug(
						"%s: Unable to find Master interface for %s",
						__func__, vrf->name);
					return 0;
				}
				pim_zebra_interface_set_master(master, ifp);
			}
		}
	}
	return 0;
}

static int pim_ifp_down(struct interface *ifp)
{
	if (PIM_DEBUG_ZEBRA) {
		zlog_debug(
			"%s: %s index %d vrf %s(%u) flags %ld metric %d mtu %d operative %d",
			__func__, ifp->name, ifp->ifindex, ifp->vrf->name,
			ifp->vrf->vrf_id, (long)ifp->flags, ifp->metric,
			ifp->mtu, if_is_operative(ifp));
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

	if (ifp->info) {
		pim_if_del_vif(ifp);
		pim_ifstat_reset(ifp);
	}

	return 0;
}

static int pim_ifp_destroy(struct interface *ifp)
{
	if (PIM_DEBUG_ZEBRA) {
		zlog_debug(
			"%s: %s index %d vrf %s(%u) flags %ld metric %d mtu %d operative %d",
			__func__, ifp->name, ifp->ifindex, ifp->vrf->name,
			ifp->vrf->vrf_id, (long)ifp->flags, ifp->metric,
			ifp->mtu, if_is_operative(ifp));
	}

	if (!if_is_operative(ifp))
		pim_if_addr_del_all(ifp);

#if PIM_IPV == 4
	struct pim_instance *pim;

	pim = ifp->vrf->info;
	if (pim && pim->vxlan.term_if == ifp)
		pim_vxlan_del_term_dev(pim);
#endif

	return 0;
}

static int pim_if_new_hook(struct interface *ifp)
{
	return 0;
}

static int pim_if_delete_hook(struct interface *ifp)
{
	if (ifp->info)
		pim_if_delete(ifp);

	return 0;
}

void pim_iface_init(void)
{
	hook_register_prio(if_add, 0, pim_if_new_hook);
	hook_register_prio(if_del, 0, pim_if_delete_hook);

	hook_register_prio(if_real, 0, pim_ifp_create);
	hook_register_prio(if_up, 0, pim_ifp_up);
	hook_register_prio(if_down, 0, pim_ifp_down);
	hook_register_prio(if_unreal, 0, pim_ifp_destroy);
}

static void pim_if_membership_clear(struct interface *ifp)
{
	struct pim_interface *pim_ifp;

	pim_ifp = ifp->info;
	assert(pim_ifp);

	if (pim_ifp->pim_enable && pim_ifp->gm_enable)
		return;

	pim_ifchannel_membership_clear(ifp);
}

void pim_pim_interface_delete(struct interface *ifp)
{
	struct pim_interface *pim_ifp = ifp->info;

	if (!pim_ifp)
		return;

	pim_ifp->pim_enable = false;

	pim_if_membership_clear(ifp);

	/*
	 * pim_sock_delete() removes all neighbors from
	 * pim_ifp->pim_neighbor_list.
	 */
	pim_sock_delete(ifp, "pim unconfigured on interface");
	pim_upstream_nh_if_update(pim_ifp->pim, ifp);

	if (!pim_ifp->gm_enable) {
		pim_if_addr_del_all(ifp);
		pim_if_delete(ifp);
	}
}

void pim_gm_interface_delete(struct interface *ifp)
{
	struct pim_interface *pim_ifp = ifp->info;

	if (!pim_ifp)
		return;

	pim_ifp->gm_enable = false;

	pim_if_membership_clear(ifp);

#if PIM_IPV == 4
	igmp_sock_delete_all(ifp);
#else
	gm_ifp_teardown(ifp);
#endif

	if (!pim_ifp->pim_enable)
		pim_if_delete(ifp);
}
