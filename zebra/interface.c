/*
 * Interface function.
 * Copyright (C) 1997, 1999 Kunihiro Ishiguro
 *
 * This file is part of GNU Zebra.
 *
 * GNU Zebra is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2, or (at your option) any
 * later version.
 *
 * GNU Zebra is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; see the file COPYING; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA
 */

#include <zebra.h>

#include "if.h"
#include "lib_errors.h"
#include "vty.h"
#include "sockunion.h"
#include "prefix.h"
#include "command.h"
#include "memory.h"
#include "zebra_memory.h"
#include "ioctl.h"
#include "connected.h"
#include "log.h"
#include "zclient.h"
#include "vrf.h"

#include "zebra/rtadv.h"
#include "zebra_ns.h"
#include "zebra_vrf.h"
#include "zebra/interface.h"
#include "zebra/rib.h"
#include "zebra/rt.h"
#include "zebra/zebra_router.h"
#include "zebra/redistribute.h"
#include "zebra/debug.h"
#include "zebra/irdp.h"
#include "zebra/zebra_ptm.h"
#include "zebra/rt_netlink.h"
#include "zebra/if_netlink.h"
#include "zebra/interface.h"
#include "zebra/zebra_vxlan.h"
#include "zebra/zebra_errors.h"

DEFINE_MTYPE_STATIC(ZEBRA, ZINFO, "Zebra Interface Information")

#define ZEBRA_PTM_SUPPORT

DEFINE_HOOK(zebra_if_extra_info, (struct vty * vty, struct interface *ifp),
	    (vty, ifp))
DEFINE_HOOK(zebra_if_config_wr, (struct vty * vty, struct interface *ifp),
	    (vty, ifp))


static void if_down_del_nbr_connected(struct interface *ifp);

static int if_zebra_speed_update(struct thread *thread)
{
	struct interface *ifp = THREAD_ARG(thread);
	struct zebra_if *zif = ifp->info;
	uint32_t new_speed;
	bool changed = false;
	int error = 0;

	zif->speed_update = NULL;

	new_speed = kernel_get_speed(ifp, &error);

	/* error may indicate vrf not available or
	 * interfaces not available.
	 * note that loopback & virtual interfaces can return 0 as speed
	 */
	if (error < 0)
		return 1;

	if (new_speed != ifp->speed) {
		zlog_info("%s: %s old speed: %u new speed: %u",
			  __PRETTY_FUNCTION__, ifp->name, ifp->speed,
			  new_speed);
		ifp->speed = new_speed;
		if_add_update(ifp);
		changed = true;
	}

	if (changed || new_speed == UINT32_MAX)
		thread_add_timer(zrouter.master, if_zebra_speed_update, ifp, 5,
				 &zif->speed_update);
	return 1;
}

static void zebra_if_node_destroy(route_table_delegate_t *delegate,
				  struct route_table *table,
				  struct route_node *node)
{
	if (node->info)
		list_delete((struct list **)&node->info);
	route_node_destroy(delegate, table, node);
}

static void zebra_if_nhg_dependents_free(struct zebra_if *zebra_if)
{
	nhg_connected_tree_free(&zebra_if->nhg_dependents);
}

static void zebra_if_nhg_dependents_init(struct zebra_if *zebra_if)
{
	nhg_connected_tree_init(&zebra_if->nhg_dependents);
}


route_table_delegate_t zebra_if_table_delegate = {
	.create_node = route_node_create,
	.destroy_node = zebra_if_node_destroy};

/* Called when new interface is added. */
static int if_zebra_new_hook(struct interface *ifp)
{
	struct zebra_if *zebra_if;

	zebra_if = XCALLOC(MTYPE_ZINFO, sizeof(struct zebra_if));

	zebra_if->multicast = IF_ZEBRA_MULTICAST_UNSPEC;
	zebra_if->shutdown = IF_ZEBRA_SHUTDOWN_OFF;

	zebra_if_nhg_dependents_init(zebra_if);

	zebra_ptm_if_init(zebra_if);

	ifp->ptm_enable = zebra_ptm_get_enable_state();
#if defined(HAVE_RTADV)
	{
		/* Set default router advertise values. */
		struct rtadvconf *rtadv;

		rtadv = &zebra_if->rtadv;

		rtadv->AdvSendAdvertisements = 0;
		rtadv->MaxRtrAdvInterval = RTADV_MAX_RTR_ADV_INTERVAL;
		rtadv->MinRtrAdvInterval = RTADV_MIN_RTR_ADV_INTERVAL;
		rtadv->AdvIntervalTimer = 0;
		rtadv->AdvManagedFlag = 0;
		rtadv->AdvOtherConfigFlag = 0;
		rtadv->AdvHomeAgentFlag = 0;
		rtadv->AdvLinkMTU = 0;
		rtadv->AdvReachableTime = 0;
		rtadv->AdvRetransTimer = 0;
		rtadv->AdvCurHopLimit = 0;
		rtadv->AdvDefaultLifetime =
			-1; /* derive from MaxRtrAdvInterval */
		rtadv->HomeAgentPreference = 0;
		rtadv->HomeAgentLifetime =
			-1; /* derive from AdvDefaultLifetime */
		rtadv->AdvIntervalOption = 0;
		rtadv->DefaultPreference = RTADV_PREF_MEDIUM;

		rtadv->AdvPrefixList = list_new();
		rtadv->AdvRDNSSList = list_new();
		rtadv->AdvDNSSLList = list_new();
	}
#endif /* HAVE_RTADV */

	memset(&zebra_if->neigh_mac[0], 0, 6);

	/* Initialize installed address chains tree. */
	zebra_if->ipv4_subnets =
		route_table_init_with_delegate(&zebra_if_table_delegate);

	ifp->info = zebra_if;

	/*
	 * Some platforms are telling us that the interface is
	 * up and ready to go.  When we check the speed we
	 * sometimes get the wrong value.  Wait a couple
	 * of seconds and ask again.  Hopefully it's all settled
	 * down upon startup.
	 */
	thread_add_timer(zrouter.master, if_zebra_speed_update, ifp, 15,
			 &zebra_if->speed_update);
	return 0;
}

static void if_nhg_dependents_check_valid(struct nhg_hash_entry *nhe)
{
	zebra_nhg_check_valid(nhe);
	if (!CHECK_FLAG(nhe->flags, NEXTHOP_GROUP_VALID))
		/* Assuming uninstalled as well here */
		UNSET_FLAG(nhe->flags, NEXTHOP_GROUP_INSTALLED);
}

static void if_down_nhg_dependents(const struct interface *ifp)
{
	struct nhg_connected *rb_node_dep = NULL;
	struct zebra_if *zif = (struct zebra_if *)ifp->info;

	frr_each(nhg_connected_tree, &zif->nhg_dependents, rb_node_dep)
		if_nhg_dependents_check_valid(rb_node_dep->nhe);
}

static void if_nhg_dependents_release(const struct interface *ifp)
{
	struct nhg_connected *rb_node_dep = NULL;
	struct zebra_if *zif = (struct zebra_if *)ifp->info;

	frr_each(nhg_connected_tree, &zif->nhg_dependents, rb_node_dep) {
		rb_node_dep->nhe->ifp = NULL; /* Null it out */
		if_nhg_dependents_check_valid(rb_node_dep->nhe);
	}
}

/* Called when interface is deleted. */
static int if_zebra_delete_hook(struct interface *ifp)
{
	struct zebra_if *zebra_if;

	if (ifp->info) {
		zebra_if = ifp->info;

		/* Free installed address chains tree. */
		if (zebra_if->ipv4_subnets)
			route_table_finish(zebra_if->ipv4_subnets);
#if defined(HAVE_RTADV)

		struct rtadvconf *rtadv;

		rtadv = &zebra_if->rtadv;
		list_delete(&rtadv->AdvPrefixList);
		list_delete(&rtadv->AdvRDNSSList);
		list_delete(&rtadv->AdvDNSSLList);
#endif /* HAVE_RTADV */

		if_nhg_dependents_release(ifp);
		zebra_if_nhg_dependents_free(zebra_if);

		XFREE(MTYPE_TMP, zebra_if->desc);

		THREAD_OFF(zebra_if->speed_update);

		XFREE(MTYPE_ZINFO, zebra_if);
	}

	return 0;
}

/* Build the table key */
static void if_build_key(uint32_t ifindex, struct prefix *p)
{
	p->family = AF_INET;
	p->prefixlen = IPV4_MAX_BITLEN;
	p->u.prefix4.s_addr = ifindex;
}

/* Link an interface in a per NS interface tree */
struct interface *if_link_per_ns(struct zebra_ns *ns, struct interface *ifp)
{
	struct prefix p;
	struct route_node *rn;

	if (ifp->ifindex == IFINDEX_INTERNAL)
		return NULL;

	if_build_key(ifp->ifindex, &p);
	rn = route_node_get(ns->if_table, &p);
	if (rn->info) {
		ifp = (struct interface *)rn->info;
		route_unlock_node(rn); /* get */
		return ifp;
	}

	rn->info = ifp;
	ifp->node = rn;

	return ifp;
}

/* Delete a VRF. This is called in vrf_terminate(). */
void if_unlink_per_ns(struct interface *ifp)
{
	ifp->node->info = NULL;
	route_unlock_node(ifp->node);
	ifp->node = NULL;
}

/* Look up an interface by identifier within a NS */
struct interface *if_lookup_by_index_per_ns(struct zebra_ns *ns,
					    uint32_t ifindex)
{
	struct prefix p;
	struct route_node *rn;
	struct interface *ifp = NULL;

	if_build_key(ifindex, &p);
	rn = route_node_lookup(ns->if_table, &p);
	if (rn) {
		ifp = (struct interface *)rn->info;
		route_unlock_node(rn); /* lookup */
	}
	return ifp;
}

/* Look up an interface by name within a NS */
struct interface *if_lookup_by_name_per_ns(struct zebra_ns *ns,
					   const char *ifname)
{
	struct route_node *rn;
	struct interface *ifp;

	for (rn = route_top(ns->if_table); rn; rn = route_next(rn)) {
		ifp = (struct interface *)rn->info;
		if (ifp && strcmp(ifp->name, ifname) == 0) {
			route_unlock_node(rn);
			return (ifp);
		}
	}

	return NULL;
}

const char *ifindex2ifname_per_ns(struct zebra_ns *zns, unsigned int ifindex)
{
	struct interface *ifp;

	return ((ifp = if_lookup_by_index_per_ns(zns, ifindex)) != NULL)
		       ? ifp->name
		       : "unknown";
}

/* Tie an interface address to its derived subnet list of addresses. */
int if_subnet_add(struct interface *ifp, struct connected *ifc)
{
	struct route_node *rn;
	struct zebra_if *zebra_if;
	struct prefix cp;
	struct list *addr_list;

	assert(ifp && ifp->info && ifc);
	zebra_if = ifp->info;

	/* Get address derived subnet node and associated address list, while
	   marking
	   address secondary attribute appropriately. */
	cp = *CONNECTED_PREFIX(ifc);
	apply_mask(&cp);
	rn = route_node_get(zebra_if->ipv4_subnets, &cp);

	if ((addr_list = rn->info))
		SET_FLAG(ifc->flags, ZEBRA_IFA_SECONDARY);
	else {
		UNSET_FLAG(ifc->flags, ZEBRA_IFA_SECONDARY);
		rn->info = addr_list = list_new();
		route_lock_node(rn);
	}

	/* Tie address at the tail of address list. */
	listnode_add(addr_list, ifc);

	/* Return list element count. */
	return (addr_list->count);
}

/* Untie an interface address from its derived subnet list of addresses. */
int if_subnet_delete(struct interface *ifp, struct connected *ifc)
{
	struct route_node *rn;
	struct zebra_if *zebra_if;
	struct list *addr_list;
	struct prefix cp;

	assert(ifp && ifp->info && ifc);
	zebra_if = ifp->info;

	cp = *CONNECTED_PREFIX(ifc);
	apply_mask(&cp);

	/* Get address derived subnet node. */
	rn = route_node_lookup(zebra_if->ipv4_subnets, &cp);
	if (!(rn && rn->info)) {
		flog_warn(EC_ZEBRA_REMOVE_ADDR_UNKNOWN_SUBNET,
			  "Trying to remove an address from an unknown subnet."
			  " (please report this bug)");
		return -1;
	}
	route_unlock_node(rn);

	/* Untie address from subnet's address list. */
	addr_list = rn->info;

	/* Deleting an address that is not registered is a bug.
	 * In any case, we shouldn't decrement the lock counter if the address
	 * is unknown. */
	if (!listnode_lookup(addr_list, ifc)) {
		flog_warn(
			EC_ZEBRA_REMOVE_UNREGISTERED_ADDR,
			"Trying to remove an address from a subnet where it is not"
			" currently registered. (please report this bug)");
		return -1;
	}

	listnode_delete(addr_list, ifc);
	route_unlock_node(rn);

	/* Return list element count, if not empty. */
	if (addr_list->count) {
		/* If deleted address is primary, mark subsequent one as such
		 * and distribute. */
		if (!CHECK_FLAG(ifc->flags, ZEBRA_IFA_SECONDARY)) {
			ifc = listgetdata(
				(struct listnode *)listhead(addr_list));
			zebra_interface_address_delete_update(ifp, ifc);
			UNSET_FLAG(ifc->flags, ZEBRA_IFA_SECONDARY);
			/* XXX: Linux kernel removes all the secondary addresses
			 * when the primary
			 * address is removed. We could try to work around that,
			 * though this is
			 * non-trivial. */
			zebra_interface_address_add_update(ifp, ifc);
		}

		return addr_list->count;
	}

	/* Otherwise, free list and route node. */
	list_delete(&addr_list);
	rn->info = NULL;
	route_unlock_node(rn);

	return 0;
}

/* if_flags_mangle: A place for hacks that require mangling
 * or tweaking the interface flags.
 *
 * ******************** Solaris flags hacks **************************
 *
 * Solaris IFF_UP flag reflects only the primary interface as the
 * routing socket only sends IFINFO for the primary interface.  Hence
 * ~IFF_UP does not per se imply all the logical interfaces are also
 * down - which we only know of as addresses. Instead we must determine
 * whether the interface really is up or not according to how many
 * addresses are still attached. (Solaris always sends RTM_DELADDR if
 * an interface, logical or not, goes ~IFF_UP).
 *
 * Ie, we mangle IFF_UP to *additionally* reflect whether or not there
 * are addresses left in struct connected, not just the actual underlying
 * IFF_UP flag.
 *
 * We must hence remember the real state of IFF_UP, which we do in
 * struct zebra_if.primary_state.
 *
 * Setting IFF_UP within zebra to administratively shutdown the
 * interface will affect only the primary interface/address on Solaris.
 ************************End Solaris flags hacks ***********************
 */
static void if_flags_mangle(struct interface *ifp, uint64_t *newflags)
{
#ifdef SUNOS_5
	struct zebra_if *zif = ifp->info;

	zif->primary_state = *newflags & (IFF_UP & 0xff);

	if (CHECK_FLAG(zif->primary_state, IFF_UP)
	    || listcount(ifp->connected) > 0)
		SET_FLAG(*newflags, IFF_UP);
	else
		UNSET_FLAG(*newflags, IFF_UP);
#endif /* SUNOS_5 */
}

/* Update the flags field of the ifp with the new flag set provided.
 * Take whatever actions are required for any changes in flags we care
 * about.
 *
 * newflags should be the raw value, as obtained from the OS.
 */
void if_flags_update(struct interface *ifp, uint64_t newflags)
{
	if_flags_mangle(ifp, &newflags);

	if (if_is_no_ptm_operative(ifp)) {
		/* operative -> inoperative? */
		ifp->flags = newflags;
		if (!if_is_operative(ifp))
			if_down(ifp);
	} else {
		/* inoperative -> operative? */
		ifp->flags = newflags;
		if (if_is_operative(ifp))
			if_up(ifp);
	}
}

/* Wake up configured address if it is not in current kernel
   address. */
static void if_addr_wakeup(struct interface *ifp)
{
	struct listnode *node, *nnode;
	struct connected *ifc;
	struct prefix *p;
	enum zebra_dplane_result dplane_res;

	for (ALL_LIST_ELEMENTS(ifp->connected, node, nnode, ifc)) {
		p = ifc->address;

		if (CHECK_FLAG(ifc->conf, ZEBRA_IFC_CONFIGURED)
		    && !CHECK_FLAG(ifc->conf, ZEBRA_IFC_QUEUED)) {
			/* Address check. */
			if (p->family == AF_INET) {
				if (!if_is_up(ifp)) {
					/* Assume zebra is configured like
					 * following:
					 *
					 *   interface gre0
					 *    ip addr 192.0.2.1/24
					 *   !
					 *
					 * As soon as zebra becomes first aware
					 * that gre0 exists in the
					 * kernel, it will set gre0 up and
					 * configure its addresses.
					 *
					 * (This may happen at startup when the
					 * interface already exists
					 * or during runtime when the interface
					 * is added to the kernel)
					 *
					 * XXX: IRDP code is calling here via
					 * if_add_update - this seems
					 * somewhat weird.
					 * XXX: RUNNING is not a settable flag
					 * on any system
					 * I (paulj) am aware of.
					*/
					if_set_flags(ifp, IFF_UP | IFF_RUNNING);
					if_refresh(ifp);
				}

				dplane_res = dplane_intf_addr_set(ifp, ifc);
				if (dplane_res ==
				    ZEBRA_DPLANE_REQUEST_FAILURE) {
					flog_err_sys(
						EC_ZEBRA_IFACE_ADDR_ADD_FAILED,
						"Can't set interface's address: %s",
						dplane_res2str(dplane_res));
					continue;
				}

				SET_FLAG(ifc->conf, ZEBRA_IFC_QUEUED);
				/* The address will be advertised to zebra
				 * clients when the notification
				 * from the kernel has been received.
				 * It will also be added to the interface's
				 * subnet list then. */
			}
			if (p->family == AF_INET6) {
				if (!if_is_up(ifp)) {
					/* See long comment above */
					if_set_flags(ifp, IFF_UP | IFF_RUNNING);
					if_refresh(ifp);
				}


				dplane_res = dplane_intf_addr_set(ifp, ifc);
				if (dplane_res ==
				    ZEBRA_DPLANE_REQUEST_FAILURE) {
					flog_err_sys(
						EC_ZEBRA_IFACE_ADDR_ADD_FAILED,
						"Can't set interface's address: %s",
						dplane_res2str(dplane_res));
					continue;
				}

				SET_FLAG(ifc->conf, ZEBRA_IFC_QUEUED);
				/* The address will be advertised to zebra
				 * clients when the notification
				 * from the kernel has been received. */
			}
		}
	}
}

/* Handle interface addition */
void if_add_update(struct interface *ifp)
{
	struct zebra_if *if_data;
	struct zebra_ns *zns;
	struct zebra_vrf *zvrf = vrf_info_lookup(ifp->vrf_id);

	/* case interface populate before vrf enabled */
	if (zvrf->zns)
		zns = zvrf->zns;
	else
		zns = zebra_ns_lookup(NS_DEFAULT);
	if_link_per_ns(zns, ifp);
	if_data = ifp->info;
	assert(if_data);

	if (if_data->multicast == IF_ZEBRA_MULTICAST_ON)
		if_set_flags(ifp, IFF_MULTICAST);
	else if (if_data->multicast == IF_ZEBRA_MULTICAST_OFF)
		if_unset_flags(ifp, IFF_MULTICAST);

	zebra_ptm_if_set_ptm_state(ifp, if_data);

	zebra_interface_add_update(ifp);

	if (!CHECK_FLAG(ifp->status, ZEBRA_INTERFACE_ACTIVE)) {
		SET_FLAG(ifp->status, ZEBRA_INTERFACE_ACTIVE);

		if (if_data->shutdown == IF_ZEBRA_SHUTDOWN_ON) {
			if (IS_ZEBRA_DEBUG_KERNEL)
				zlog_debug(
					"interface %s vrf %u index %d is shutdown. "
					"Won't wake it up.",
					ifp->name, ifp->vrf_id, ifp->ifindex);
			return;
		}

		if_addr_wakeup(ifp);

		if (IS_ZEBRA_DEBUG_KERNEL)
			zlog_debug(
				"interface %s vrf %u index %d becomes active.",
				ifp->name, ifp->vrf_id, ifp->ifindex);

	} else {
		if (IS_ZEBRA_DEBUG_KERNEL)
			zlog_debug("interface %s vrf %u index %d is added.",
				   ifp->name, ifp->vrf_id, ifp->ifindex);
	}
}

/* Install connected routes corresponding to an interface. */
static void if_install_connected(struct interface *ifp)
{
	struct listnode *node;
	struct listnode *next;
	struct connected *ifc;

	if (ifp->connected) {
		for (ALL_LIST_ELEMENTS(ifp->connected, node, next, ifc)) {
			if (CHECK_FLAG(ifc->conf, ZEBRA_IFC_REAL))
				zebra_interface_address_add_update(ifp, ifc);

			connected_up(ifp, ifc);
		}
	}
}

/* Uninstall connected routes corresponding to an interface. */
static void if_uninstall_connected(struct interface *ifp)
{
	struct listnode *node;
	struct listnode *next;
	struct connected *ifc;

	if (ifp->connected) {
		for (ALL_LIST_ELEMENTS(ifp->connected, node, next, ifc)) {
			zebra_interface_address_delete_update(ifp, ifc);
			connected_down(ifp, ifc);
		}
	}
}

/* Uninstall and delete connected routes corresponding to an interface. */
/* TODO - Check why IPv4 handling here is different from install or if_down */
static void if_delete_connected(struct interface *ifp)
{
	struct connected *ifc;
	struct prefix cp;
	struct route_node *rn;
	struct zebra_if *zebra_if;
	struct listnode *node;
	struct listnode *last = NULL;

	zebra_if = ifp->info;

	if (!ifp->connected)
		return;

	while ((node = (last ? last->next : listhead(ifp->connected)))) {
		ifc = listgetdata(node);

		cp = *CONNECTED_PREFIX(ifc);
		apply_mask(&cp);

		if (cp.family == AF_INET
		    && (rn = route_node_lookup(zebra_if->ipv4_subnets, &cp))) {
			struct listnode *anode;
			struct listnode *next;
			struct listnode *first;
			struct list *addr_list;

			route_unlock_node(rn);
			addr_list = (struct list *)rn->info;

			/* Remove addresses, secondaries first. */
			first = listhead(addr_list);
			if (first)
				for (anode = first->next; anode || first;
				     anode = next) {
					if (!anode) {
						anode = first;
						first = NULL;
					}
					next = anode->next;

					ifc = listgetdata(anode);
					connected_down(ifp, ifc);

					/* XXX: We have to send notifications
					 * here explicitly, because we destroy
					 * the ifc before receiving the
					 * notification about the address being
					 * deleted.
					 */
					zebra_interface_address_delete_update(
						ifp, ifc);

					UNSET_FLAG(ifc->conf, ZEBRA_IFC_REAL);
					UNSET_FLAG(ifc->conf, ZEBRA_IFC_QUEUED);

					/* Remove from subnet chain. */
					list_delete_node(addr_list, anode);
					route_unlock_node(rn);

					/* Remove from interface address list
					 * (unconditionally). */
					if (!CHECK_FLAG(ifc->conf,
							ZEBRA_IFC_CONFIGURED)) {
						listnode_delete(ifp->connected,
								ifc);
						connected_free(&ifc);
					} else
						last = node;
				}

			/* Free chain list and respective route node. */
			list_delete(&addr_list);
			rn->info = NULL;
			route_unlock_node(rn);
		} else if (cp.family == AF_INET6) {
			connected_down(ifp, ifc);

			zebra_interface_address_delete_update(ifp, ifc);

			UNSET_FLAG(ifc->conf, ZEBRA_IFC_REAL);
			UNSET_FLAG(ifc->conf, ZEBRA_IFC_QUEUED);

			if (CHECK_FLAG(ifc->conf, ZEBRA_IFC_CONFIGURED))
				last = node;
			else {
				listnode_delete(ifp->connected, ifc);
				connected_free(&ifc);
			}
		} else {
			last = node;
		}
	}
}

/* Handle an interface delete event */
void if_delete_update(struct interface *ifp)
{
	struct zebra_if *zif;

	if (if_is_up(ifp)) {
		flog_err(
			EC_LIB_INTERFACE,
			"interface %s vrf %u index %d is still up while being deleted.",
			ifp->name, ifp->vrf_id, ifp->ifindex);
		return;
	}

	if (!CHECK_FLAG(ifp->status, ZEBRA_INTERFACE_ACTIVE))
		return;

	/* Mark interface as inactive */
	UNSET_FLAG(ifp->status, ZEBRA_INTERFACE_ACTIVE);

	if (IS_ZEBRA_DEBUG_KERNEL)
		zlog_debug("interface %s vrf %u index %d is now inactive.",
			   ifp->name, ifp->vrf_id, ifp->ifindex);

	/* Delete connected routes from the kernel. */
	if_delete_connected(ifp);

	/* Send out notification on interface delete. */
	zebra_interface_delete_update(ifp);

	if_unlink_per_ns(ifp);

	/* Update ifindex after distributing the delete message.  This is in
	   case any client needs to have the old value of ifindex available
	   while processing the deletion.  Each client daemon is responsible
	   for setting ifindex to IFINDEX_INTERNAL after processing the
	   interface deletion message. */
	if_set_index(ifp, IFINDEX_INTERNAL);
	ifp->node = NULL;

	/* if the ifp is in a vrf, move it to default so vrf can be deleted if
	 * desired. This operation is not done for netns implementation to avoid
	 * collision with interface with the same name in the default vrf (can
	 * occur with this implementation whereas it is not possible with
	 * vrf-lite).
	 */
	if (ifp->vrf_id && !vrf_is_backend_netns())
		if_handle_vrf_change(ifp, VRF_DEFAULT);

	/* Reset some zebra interface params to default values. */
	zif = ifp->info;
	if (zif) {
		zif->zif_type = ZEBRA_IF_OTHER;
		zif->zif_slave_type = ZEBRA_IF_SLAVE_NONE;
		memset(&zif->l2info, 0, sizeof(union zebra_l2if_info));
		memset(&zif->brslave_info, 0,
		       sizeof(struct zebra_l2info_brslave));
	}

	if (!ifp->configured) {
		if (IS_ZEBRA_DEBUG_KERNEL)
			zlog_debug("interface %s is being deleted from the system",
				   ifp->name);
		if_delete(&ifp);
	}
}

/* VRF change for an interface */
void if_handle_vrf_change(struct interface *ifp, vrf_id_t vrf_id)
{
	vrf_id_t old_vrf_id;

	old_vrf_id = ifp->vrf_id;

	/* Uninstall connected routes. */
	if_uninstall_connected(ifp);

	/* Delete any IPv4 neighbors created to implement RFC 5549 */
	if_nbr_ipv6ll_to_ipv4ll_neigh_del_all(ifp);

	/* Delete all neighbor addresses learnt through IPv6 RA */
	if_down_del_nbr_connected(ifp);

	/* Send out notification on interface VRF change. */
	/* This is to issue an UPDATE or a DELETE, as appropriate. */
	zebra_interface_vrf_update_del(ifp, vrf_id);

	/* update VRF */
	if_update_to_new_vrf(ifp, vrf_id);

	/* Send out notification on interface VRF change. */
	/* This is to issue an ADD, if needed. */
	zebra_interface_vrf_update_add(ifp, old_vrf_id);

	/* Install connected routes (in new VRF). */
	if (if_is_operative(ifp))
		if_install_connected(ifp);
}

static void ipv6_ll_address_to_mac(struct in6_addr *address, uint8_t *mac)
{
	mac[0] = address->s6_addr[8] ^ 0x02;
	mac[1] = address->s6_addr[9];
	mac[2] = address->s6_addr[10];
	mac[3] = address->s6_addr[13];
	mac[4] = address->s6_addr[14];
	mac[5] = address->s6_addr[15];
}

void if_nbr_mac_to_ipv4ll_neigh_update(struct interface *ifp,
				       char mac[6],
				       struct in6_addr *address,
				       int add)
{
	struct zebra_vrf *zvrf = vrf_info_lookup(ifp->vrf_id);
	struct zebra_if *zif = ifp->info;
	char buf[16] = "169.254.0.1";
	struct in_addr ipv4_ll;
	ns_id_t ns_id;

	inet_pton(AF_INET, buf, &ipv4_ll);

	ns_id = zvrf->zns->ns_id;

	/*
	 * Remove and re-add any existing neighbor entry for this address,
	 * since Netlink doesn't currently offer update message types.
	 */
	kernel_neigh_update(0, ifp->ifindex, ipv4_ll.s_addr, mac, 6, ns_id);

	/* Add new neighbor entry.
	 *
	 * We force installation even if current neighbor entry is the same.
	 * Since this function is used to refresh our MAC entries after an
	 * interface flap, if we don't force in our custom entries with their
	 * state set to PERMANENT or REACHABLE then the kernel will attempt to
	 * resolve our leftover entries, fail, mark them unreachable and then
	 * they'll be useless to us.
	 */
	if (add)
		kernel_neigh_update(add, ifp->ifindex, ipv4_ll.s_addr, mac, 6,
				    ns_id);

	memcpy(&zif->neigh_mac[0], &mac[0], 6);

	/*
	 * We need to note whether or not we originated a v6
	 * neighbor entry for this interface.  So that when
	 * someone unwisely accidently deletes this entry
	 * we can shove it back in.
	 */
	zif->v6_2_v4_ll_neigh_entry = !!add;
	memcpy(&zif->v6_2_v4_ll_addr6, address, sizeof(*address));

	zvrf->neigh_updates++;
}

void if_nbr_ipv6ll_to_ipv4ll_neigh_update(struct interface *ifp,
					  struct in6_addr *address, int add)
{

	char mac[6];

	ipv6_ll_address_to_mac(address, (uint8_t *)mac);
	if_nbr_mac_to_ipv4ll_neigh_update(ifp, mac, address, add);
}

static void if_nbr_ipv6ll_to_ipv4ll_neigh_add_all(struct interface *ifp)
{
	if (listhead(ifp->nbr_connected)) {
		struct nbr_connected *nbr_connected;
		struct listnode *node;

		for (ALL_LIST_ELEMENTS_RO(ifp->nbr_connected, node,
					  nbr_connected))
			if_nbr_ipv6ll_to_ipv4ll_neigh_update(
				ifp, &nbr_connected->address->u.prefix6, 1);
	}
}

void if_nbr_ipv6ll_to_ipv4ll_neigh_del_all(struct interface *ifp)
{
	if (listhead(ifp->nbr_connected)) {
		struct nbr_connected *nbr_connected;
		struct listnode *node;

		for (ALL_LIST_ELEMENTS_RO(ifp->nbr_connected, node,
					  nbr_connected))
			if_nbr_ipv6ll_to_ipv4ll_neigh_update(
				ifp, &nbr_connected->address->u.prefix6, 0);
	}
}

static void if_down_del_nbr_connected(struct interface *ifp)
{
	struct nbr_connected *nbr_connected;
	struct listnode *node, *nnode;

	for (ALL_LIST_ELEMENTS(ifp->nbr_connected, node, nnode,
			       nbr_connected)) {
		listnode_delete(ifp->nbr_connected, nbr_connected);
		nbr_connected_free(nbr_connected);
	}
}

void if_nhg_dependents_add(struct interface *ifp, struct nhg_hash_entry *nhe)
{
	if (ifp->info) {
		struct zebra_if *zif = (struct zebra_if *)ifp->info;

		nhg_connected_tree_add_nhe(&zif->nhg_dependents, nhe);
	}
}

void if_nhg_dependents_del(struct interface *ifp, struct nhg_hash_entry *nhe)
{
	if (ifp->info) {
		struct zebra_if *zif = (struct zebra_if *)ifp->info;

		nhg_connected_tree_del_nhe(&zif->nhg_dependents, nhe);
	}
}

unsigned int if_nhg_dependents_count(const struct interface *ifp)
{
	if (ifp->info) {
		struct zebra_if *zif = (struct zebra_if *)ifp->info;

		return nhg_connected_tree_count(&zif->nhg_dependents);
	}

	return 0;
}


bool if_nhg_dependents_is_empty(const struct interface *ifp)
{
	if (ifp->info) {
		struct zebra_if *zif = (struct zebra_if *)ifp->info;

		return nhg_connected_tree_is_empty(&zif->nhg_dependents);
	}

	return false;
}

/* Interface is up. */
void if_up(struct interface *ifp)
{
	struct zebra_if *zif;
	struct interface *link_if;
	struct zebra_vrf *zvrf = vrf_info_lookup(ifp->vrf_id);

	zif = ifp->info;
	zif->up_count++;
	quagga_timestamp(2, zif->up_last, sizeof(zif->up_last));

	/* Notify the protocol daemons. */
	if (ifp->ptm_enable && (ifp->ptm_status == ZEBRA_PTM_STATUS_DOWN)) {
		flog_warn(EC_ZEBRA_PTM_NOT_READY,
			  "%s: interface %s hasn't passed ptm check\n",
			  __func__, ifp->name);
		return;
	}
	zebra_interface_up_update(ifp);

	if_nbr_ipv6ll_to_ipv4ll_neigh_add_all(ifp);

#if defined(HAVE_RTADV)
	/* Enable fast tx of RA if enabled && RA interval is not in msecs */
	if (zif->rtadv.AdvSendAdvertisements
	    && (zif->rtadv.MaxRtrAdvInterval >= 1000)) {
		zif->rtadv.inFastRexmit = 1;
		zif->rtadv.NumFastReXmitsRemain = RTADV_NUM_FAST_REXMITS;
	}
#endif

	/* Install connected routes to the kernel. */
	if_install_connected(ifp);

	/* Handle interface up for specific types for EVPN. Non-VxLAN interfaces
	 * are checked to see if (remote) neighbor entries need to be installed
	 * on them for ARP suppression.
	 */
	if (IS_ZEBRA_IF_VXLAN(ifp))
		zebra_vxlan_if_up(ifp);
	else if (IS_ZEBRA_IF_BRIDGE(ifp)) {
		link_if = ifp;
		zebra_vxlan_svi_up(ifp, link_if);
	} else if (IS_ZEBRA_IF_VLAN(ifp)) {
		link_if = if_lookup_by_index_per_ns(zvrf->zns,
						    zif->link_ifindex);
		if (link_if)
			zebra_vxlan_svi_up(ifp, link_if);
	}
}

/* Interface goes down.  We have to manage different behavior of based
   OS. */
void if_down(struct interface *ifp)
{
	struct zebra_if *zif;
	struct interface *link_if;
	struct zebra_vrf *zvrf = vrf_info_lookup(ifp->vrf_id);

	zif = ifp->info;
	zif->down_count++;
	quagga_timestamp(2, zif->down_last, sizeof(zif->down_last));

	if_down_nhg_dependents(ifp);

	/* Handle interface down for specific types for EVPN. Non-VxLAN
	 * interfaces
	 * are checked to see if (remote) neighbor entries need to be purged
	 * for ARP suppression.
	 */
	if (IS_ZEBRA_IF_VXLAN(ifp))
		zebra_vxlan_if_down(ifp);
	else if (IS_ZEBRA_IF_BRIDGE(ifp)) {
		link_if = ifp;
		zebra_vxlan_svi_down(ifp, link_if);
	} else if (IS_ZEBRA_IF_VLAN(ifp)) {
		link_if = if_lookup_by_index_per_ns(zvrf->zns,
						    zif->link_ifindex);
		if (link_if)
			zebra_vxlan_svi_down(ifp, link_if);
	}


	/* Notify to the protocol daemons. */
	zebra_interface_down_update(ifp);

	/* Uninstall connected routes from the kernel. */
	if_uninstall_connected(ifp);

	if_nbr_ipv6ll_to_ipv4ll_neigh_del_all(ifp);

	/* Delete all neighbor addresses learnt through IPv6 RA */
	if_down_del_nbr_connected(ifp);
}

void if_refresh(struct interface *ifp)
{
	if_get_flags(ifp);
}

void zebra_if_update_link(struct interface *ifp, ifindex_t link_ifindex,
			  ns_id_t ns_id)
{
	struct zebra_if *zif;

	if (IS_ZEBRA_IF_VETH(ifp))
		return;
	zif = (struct zebra_if *)ifp->info;
	zif->link_ifindex = link_ifindex;
	zif->link = if_lookup_by_index_per_ns(zebra_ns_lookup(ns_id),
					      link_ifindex);
}

/*
 * during initial link dump kernel does not order lower devices before
 * upper devices so we need to fixup link dependencies at the end of dump
 */
void zebra_if_update_all_links(void)
{
	struct route_node *rn;
	struct interface *ifp;
	struct zebra_if *zif;
	struct zebra_ns *ns;

	if (IS_ZEBRA_DEBUG_KERNEL)
		zlog_info("fixup link dependencies");

	ns = zebra_ns_lookup(NS_DEFAULT);
	for (rn = route_top(ns->if_table); rn; rn = route_next(rn)) {
		ifp = (struct interface *)rn->info;
		if (!ifp)
			continue;
		zif = ifp->info;
		if ((zif->link_ifindex != IFINDEX_INTERNAL) && !zif->link) {
			zif->link = if_lookup_by_index_per_ns(ns,
							 zif->link_ifindex);
			if (IS_ZEBRA_DEBUG_KERNEL)
				zlog_debug("interface %s/%d's lower fixup to %s/%d",
						ifp->name, ifp->ifindex,
						zif->link?zif->link->name:"unk",
						zif->link_ifindex);
		}
	}
}

void zebra_if_set_protodown(struct interface *ifp, bool down)
{
#ifdef HAVE_NETLINK
	netlink_protodown(ifp, down);
#else
	zlog_warn("Protodown is not supported on this platform");
#endif
}

/* Output prefix string to vty. */
static int prefix_vty_out(struct vty *vty, struct prefix *p)
{
	char str[INET6_ADDRSTRLEN];

	inet_ntop(p->family, &p->u.prefix, str, sizeof(str));
	vty_out(vty, "%s", str);
	return strlen(str);
}

/* Dump if address information to vty. */
static void connected_dump_vty(struct vty *vty, struct connected *connected)
{
	struct prefix *p;

	/* Print interface address. */
	p = connected->address;
	vty_out(vty, "  %s ", prefix_family_str(p));
	prefix_vty_out(vty, p);
	vty_out(vty, "/%d", p->prefixlen);

	/* If there is destination address, print it. */
	if (CONNECTED_PEER(connected) && connected->destination) {
		vty_out(vty, " peer ");
		prefix_vty_out(vty, connected->destination);
		vty_out(vty, "/%d", connected->destination->prefixlen);
	}

	if (CHECK_FLAG(connected->flags, ZEBRA_IFA_SECONDARY))
		vty_out(vty, " secondary");

	if (CHECK_FLAG(connected->flags, ZEBRA_IFA_UNNUMBERED))
		vty_out(vty, " unnumbered");

	if (connected->label)
		vty_out(vty, " %s", connected->label);

	vty_out(vty, "\n");
}

/* Dump interface neighbor address information to vty. */
static void nbr_connected_dump_vty(struct vty *vty,
				   struct nbr_connected *connected)
{
	struct prefix *p;

	/* Print interface address. */
	p = connected->address;
	vty_out(vty, "  %s ", prefix_family_str(p));
	prefix_vty_out(vty, p);
	vty_out(vty, "/%d", p->prefixlen);

	vty_out(vty, "\n");
}

static const char *zebra_ziftype_2str(zebra_iftype_t zif_type)
{
	switch (zif_type) {
	case ZEBRA_IF_OTHER:
		return "Other";
		break;

	case ZEBRA_IF_BRIDGE:
		return "Bridge";
		break;

	case ZEBRA_IF_VLAN:
		return "Vlan";
		break;

	case ZEBRA_IF_VXLAN:
		return "Vxlan";
		break;

	case ZEBRA_IF_VRF:
		return "VRF";
		break;

	case ZEBRA_IF_VETH:
		return "VETH";
		break;

	case ZEBRA_IF_BOND:
		return "bond";

	case ZEBRA_IF_BOND_SLAVE:
		return "bond_slave";

	case ZEBRA_IF_MACVLAN:
		return "macvlan";

	default:
		return "Unknown";
		break;
	}
}

/* Interface's brief information print out to vty interface. */
static void ifs_dump_brief_vty(struct vty *vty, struct vrf *vrf)
{
	struct connected *connected;
	struct listnode *node;
	struct route_node *rn;
	struct zebra_if *zebra_if;
	struct prefix *p;
	struct interface *ifp;
	bool print_header = true;

	FOR_ALL_INTERFACES (vrf, ifp) {
		char global_pfx[PREFIX_STRLEN] = {0};
		char buf[PREFIX_STRLEN] = {0};
		bool first_pfx_printed = false;

		if (print_header) {
			vty_out(vty, "%-16s%-8s%-16s%s\n", "Interface",
				"Status", "VRF", "Addresses");
			vty_out(vty, "%-16s%-8s%-16s%s\n", "---------",
				"------", "---", "---------");
			print_header = false; /* We have at least 1 iface */
		}
		zebra_if = ifp->info;

		vty_out(vty, "%-16s", ifp->name);

		if (if_is_up(ifp))
			vty_out(vty, "%-8s", "up");
		else
			vty_out(vty, "%-8s", "down");

		vty_out(vty, "%-16s", vrf->name);

		for (rn = route_top(zebra_if->ipv4_subnets); rn;
		     rn = route_next(rn)) {
			if (!rn->info)
				continue;
			uint32_t list_size = listcount((struct list *)rn->info);

			for (ALL_LIST_ELEMENTS_RO((struct list *)rn->info, node,
						  connected)) {
				if (!CHECK_FLAG(connected->flags,
						ZEBRA_IFA_SECONDARY)) {
					p = connected->address;
					prefix2str(p, buf, sizeof(buf));
					if (first_pfx_printed) {
						/* padding to prepare row only for ip addr */
						vty_out(vty, "%-40s", "");
						if (list_size > 1)
							vty_out(vty, "+ ");
						vty_out(vty, "%s\n", buf);
					} else {
						if (list_size > 1)
							vty_out(vty, "+ ");
						vty_out(vty, "%s\n", buf);
					}
					first_pfx_printed = true;
					break;
				}
			}
		}

		uint32_t v6_list_size = 0;
		for (ALL_LIST_ELEMENTS_RO(ifp->connected, node, connected)) {
			if (CHECK_FLAG(connected->conf, ZEBRA_IFC_REAL)
				&& (connected->address->family == AF_INET6))
				v6_list_size++;
		}
		for (ALL_LIST_ELEMENTS_RO(ifp->connected, node, connected)) {
			if (CHECK_FLAG(connected->conf, ZEBRA_IFC_REAL)
			    && !CHECK_FLAG(connected->flags,
					   ZEBRA_IFA_SECONDARY)
			    && (connected->address->family == AF_INET6)) {
				p = connected->address;
				/* Don't print link local pfx */
				if (!IN6_IS_ADDR_LINKLOCAL(&p->u.prefix6)) {
					prefix2str(p, global_pfx, PREFIX_STRLEN);
					if (first_pfx_printed) {
						/* padding to prepare row only for ip addr */
						vty_out(vty, "%-40s", "");
						if (v6_list_size > 1)
							vty_out(vty, "+ ");
						vty_out(vty, "%s\n", global_pfx);
					} else {
						if (v6_list_size > 1)
							vty_out(vty, "+ ");
						vty_out(vty, "%s\n", global_pfx);
					}
					first_pfx_printed = true;
					break;
				}
			}
		}
		if (!first_pfx_printed)
			vty_out(vty, "\n");
	}
	vty_out(vty, "\n");
}

/* Interface's information print out to vty interface. */
static void if_dump_vty(struct vty *vty, struct interface *ifp)
{
	struct connected *connected;
	struct nbr_connected *nbr_connected;
	struct listnode *node;
	struct route_node *rn;
	struct zebra_if *zebra_if;
	struct vrf *vrf;

	zebra_if = ifp->info;

	vty_out(vty, "Interface %s is ", ifp->name);
	if (if_is_up(ifp)) {
		vty_out(vty, "up, line protocol ");

		if (CHECK_FLAG(ifp->status, ZEBRA_INTERFACE_LINKDETECTION)) {
			if (if_is_running(ifp))
				vty_out(vty, "is up\n");
			else
				vty_out(vty, "is down\n");
		} else {
			vty_out(vty, "detection is disabled\n");
		}
	} else {
		vty_out(vty, "down\n");
	}

	vty_out(vty, "  Link ups:   %5u    last: %s\n", zebra_if->up_count,
		zebra_if->up_last[0] ? zebra_if->up_last : "(never)");
	vty_out(vty, "  Link downs: %5u    last: %s\n", zebra_if->down_count,
		zebra_if->down_last[0] ? zebra_if->down_last : "(never)");

	zebra_ptm_show_status(vty, ifp);

	vrf = vrf_lookup_by_id(ifp->vrf_id);
	vty_out(vty, "  vrf: %s\n", vrf->name);

	if (ifp->desc)
		vty_out(vty, "  Description: %s\n", ifp->desc);
	if (zebra_if->desc)
		vty_out(vty, "  OS Description: %s\n", zebra_if->desc);

	if (ifp->ifindex == IFINDEX_INTERNAL) {
		vty_out(vty, "  pseudo interface\n");
		return;
	} else if (!CHECK_FLAG(ifp->status, ZEBRA_INTERFACE_ACTIVE)) {
		vty_out(vty, "  index %d inactive interface\n", ifp->ifindex);
		return;
	}

	vty_out(vty, "  index %d metric %d mtu %d speed %u ", ifp->ifindex,
		ifp->metric, ifp->mtu, ifp->speed);
	if (ifp->mtu6 != ifp->mtu)
		vty_out(vty, "mtu6 %d ", ifp->mtu6);
	vty_out(vty, "\n  flags: %s\n", if_flag_dump(ifp->flags));

	/* Hardware address. */
	vty_out(vty, "  Type: %s\n", if_link_type_str(ifp->ll_type));
	if (ifp->hw_addr_len != 0) {
		int i;

		vty_out(vty, "  HWaddr: ");
		for (i = 0; i < ifp->hw_addr_len; i++)
			vty_out(vty, "%s%02x", i == 0 ? "" : ":",
				ifp->hw_addr[i]);
		vty_out(vty, "\n");
	}

	/* Bandwidth in Mbps */
	if (ifp->bandwidth != 0) {
		vty_out(vty, "  bandwidth %u Mbps", ifp->bandwidth);
		vty_out(vty, "\n");
	}

	for (rn = route_top(zebra_if->ipv4_subnets); rn; rn = route_next(rn)) {
		if (!rn->info)
			continue;

		for (ALL_LIST_ELEMENTS_RO((struct list *)rn->info, node,
					  connected))
			connected_dump_vty(vty, connected);
	}

	for (ALL_LIST_ELEMENTS_RO(ifp->connected, node, connected)) {
		if (CHECK_FLAG(connected->conf, ZEBRA_IFC_REAL)
		    && (connected->address->family == AF_INET6))
			connected_dump_vty(vty, connected);
	}

	vty_out(vty, "  Interface Type %s\n",
		zebra_ziftype_2str(zebra_if->zif_type));
	if (IS_ZEBRA_IF_BRIDGE(ifp)) {
		struct zebra_l2info_bridge *bridge_info;

		bridge_info = &zebra_if->l2info.br;
		vty_out(vty, "  Bridge VLAN-aware: %s\n",
			bridge_info->vlan_aware ? "yes" : "no");
	} else if (IS_ZEBRA_IF_VLAN(ifp)) {
		struct zebra_l2info_vlan *vlan_info;

		vlan_info = &zebra_if->l2info.vl;
		vty_out(vty, "  VLAN Id %u\n", vlan_info->vid);
	} else if (IS_ZEBRA_IF_VXLAN(ifp)) {
		struct zebra_l2info_vxlan *vxlan_info;

		vxlan_info = &zebra_if->l2info.vxl;
		vty_out(vty, "  VxLAN Id %u", vxlan_info->vni);
		if (vxlan_info->vtep_ip.s_addr != INADDR_ANY)
			vty_out(vty, " VTEP IP: %s",
				inet_ntoa(vxlan_info->vtep_ip));
		if (vxlan_info->access_vlan)
			vty_out(vty, " Access VLAN Id %u\n",
				vxlan_info->access_vlan);
		if (vxlan_info->mcast_grp.s_addr != INADDR_ANY)
			vty_out(vty, "  Mcast Group %s",
					inet_ntoa(vxlan_info->mcast_grp));
		vty_out(vty, "\n");
	}

	if (IS_ZEBRA_IF_BRIDGE_SLAVE(ifp)) {
		struct zebra_l2info_brslave *br_slave;

		br_slave = &zebra_if->brslave_info;
		if (br_slave->bridge_ifindex != IFINDEX_INTERNAL) {
			if (br_slave->br_if)
				vty_out(vty, "  Master interface: %s\n",
					br_slave->br_if->name);
			else
				vty_out(vty, "  Master ifindex: %u\n",
					br_slave->bridge_ifindex);
		}
	}

	if (IS_ZEBRA_IF_BOND_SLAVE(ifp)) {
		struct zebra_l2info_bondslave *bond_slave;

		bond_slave = &zebra_if->bondslave_info;
		if (bond_slave->bond_ifindex != IFINDEX_INTERNAL) {
			if (bond_slave->bond_if)
				vty_out(vty, "  Master interface: %s\n",
					bond_slave->bond_if->name);
			else
				vty_out(vty, "  Master ifindex: %u\n",
					bond_slave->bond_ifindex);
		}
	}

	if (zebra_if->link_ifindex != IFINDEX_INTERNAL) {
		if (zebra_if->link)
			vty_out(vty, "  Parent interface: %s\n", zebra_if->link->name);
		else
			vty_out(vty, "  Parent ifindex: %d\n", zebra_if->link_ifindex);
	}

	if (HAS_LINK_PARAMS(ifp)) {
		int i;
		struct if_link_params *iflp = ifp->link_params;
		vty_out(vty, "  Traffic Engineering Link Parameters:\n");
		if (IS_PARAM_SET(iflp, LP_TE_METRIC))
			vty_out(vty, "    TE metric %u\n", iflp->te_metric);
		if (IS_PARAM_SET(iflp, LP_MAX_BW))
			vty_out(vty, "    Maximum Bandwidth %g (Byte/s)\n",
				iflp->max_bw);
		if (IS_PARAM_SET(iflp, LP_MAX_RSV_BW))
			vty_out(vty,
				"    Maximum Reservable Bandwidth %g (Byte/s)\n",
				iflp->max_rsv_bw);
		if (IS_PARAM_SET(iflp, LP_UNRSV_BW)) {
			vty_out(vty,
				"    Unreserved Bandwidth per Class Type in Byte/s:\n");
			for (i = 0; i < MAX_CLASS_TYPE; i += 2)
				vty_out(vty,
					"      [%d]: %g (Bytes/sec),\t[%d]: %g (Bytes/sec)\n",
					i, iflp->unrsv_bw[i], i + 1,
					iflp->unrsv_bw[i + 1]);
		}

		if (IS_PARAM_SET(iflp, LP_ADM_GRP))
			vty_out(vty, "    Administrative Group:%u\n",
				iflp->admin_grp);
		if (IS_PARAM_SET(iflp, LP_DELAY)) {
			vty_out(vty, "    Link Delay Average: %u (micro-sec.)",
				iflp->av_delay);
			if (IS_PARAM_SET(iflp, LP_MM_DELAY)) {
				vty_out(vty, " Min:  %u (micro-sec.)",
					iflp->min_delay);
				vty_out(vty, " Max:  %u (micro-sec.)",
					iflp->max_delay);
			}
			vty_out(vty, "\n");
		}
		if (IS_PARAM_SET(iflp, LP_DELAY_VAR))
			vty_out(vty,
				"    Link Delay Variation %u (micro-sec.)\n",
				iflp->delay_var);
		if (IS_PARAM_SET(iflp, LP_PKT_LOSS))
			vty_out(vty, "    Link Packet Loss %g (in %%)\n",
				iflp->pkt_loss);
		if (IS_PARAM_SET(iflp, LP_AVA_BW))
			vty_out(vty, "    Available Bandwidth %g (Byte/s)\n",
				iflp->ava_bw);
		if (IS_PARAM_SET(iflp, LP_RES_BW))
			vty_out(vty, "    Residual Bandwidth %g (Byte/s)\n",
				iflp->res_bw);
		if (IS_PARAM_SET(iflp, LP_USE_BW))
			vty_out(vty, "    Utilized Bandwidth %g (Byte/s)\n",
				iflp->use_bw);
		if (IS_PARAM_SET(iflp, LP_RMT_AS))
			vty_out(vty, "    Neighbor ASBR IP: %s AS: %u \n",
				inet_ntoa(iflp->rmt_ip), iflp->rmt_as);
	}

	hook_call(zebra_if_extra_info, vty, ifp);

	if (listhead(ifp->nbr_connected))
		vty_out(vty, "  Neighbor address(s):\n");
	for (ALL_LIST_ELEMENTS_RO(ifp->nbr_connected, node, nbr_connected))
		nbr_connected_dump_vty(vty, nbr_connected);

#ifdef HAVE_PROC_NET_DEV
	/* Statistics print out using proc file system. */
	vty_out(vty,
		"    %lu input packets (%lu multicast), %lu bytes, "
		"%lu dropped\n",
		ifp->stats.rx_packets, ifp->stats.rx_multicast,
		ifp->stats.rx_bytes, ifp->stats.rx_dropped);

	vty_out(vty,
		"    %lu input errors, %lu length, %lu overrun,"
		" %lu CRC, %lu frame\n",
		ifp->stats.rx_errors, ifp->stats.rx_length_errors,
		ifp->stats.rx_over_errors, ifp->stats.rx_crc_errors,
		ifp->stats.rx_frame_errors);

	vty_out(vty, "    %lu fifo, %lu missed\n", ifp->stats.rx_fifo_errors,
		ifp->stats.rx_missed_errors);

	vty_out(vty, "    %lu output packets, %lu bytes, %lu dropped\n",
		ifp->stats.tx_packets, ifp->stats.tx_bytes,
		ifp->stats.tx_dropped);

	vty_out(vty,
		"    %lu output errors, %lu aborted, %lu carrier,"
		" %lu fifo, %lu heartbeat\n",
		ifp->stats.tx_errors, ifp->stats.tx_aborted_errors,
		ifp->stats.tx_carrier_errors, ifp->stats.tx_fifo_errors,
		ifp->stats.tx_heartbeat_errors);

	vty_out(vty, "    %lu window, %lu collisions\n",
		ifp->stats.tx_window_errors, ifp->stats.collisions);
#endif /* HAVE_PROC_NET_DEV */

#ifdef HAVE_NET_RT_IFLIST
	/* Statistics print out using sysctl (). */
	vty_out(vty,
		"    input packets %llu, bytes %llu, dropped %llu,"
		" multicast packets %llu\n",
		(unsigned long long)ifp->stats.ifi_ipackets,
		(unsigned long long)ifp->stats.ifi_ibytes,
		(unsigned long long)ifp->stats.ifi_iqdrops,
		(unsigned long long)ifp->stats.ifi_imcasts);

	vty_out(vty, "    input errors %llu\n",
		(unsigned long long)ifp->stats.ifi_ierrors);

	vty_out(vty,
		"    output packets %llu, bytes %llu,"
		" multicast packets %llu\n",
		(unsigned long long)ifp->stats.ifi_opackets,
		(unsigned long long)ifp->stats.ifi_obytes,
		(unsigned long long)ifp->stats.ifi_omcasts);

	vty_out(vty, "    output errors %llu\n",
		(unsigned long long)ifp->stats.ifi_oerrors);

	vty_out(vty, "    collisions %llu\n",
		(unsigned long long)ifp->stats.ifi_collisions);
#endif /* HAVE_NET_RT_IFLIST */
}

static void interface_update_stats(void)
{
#ifdef HAVE_PROC_NET_DEV
	/* If system has interface statistics via proc file system, update
	   statistics. */
	ifstat_update_proc();
#endif /* HAVE_PROC_NET_DEV */
#ifdef HAVE_NET_RT_IFLIST
	ifstat_update_sysctl();
#endif /* HAVE_NET_RT_IFLIST */
}

struct cmd_node interface_node = {INTERFACE_NODE, "%s(config-if)# ", 1};

#ifndef VTYSH_EXTRACT_PL
#include "zebra/interface_clippy.c"
#endif
/* Show all interfaces to vty. */
DEFPY(show_interface, show_interface_cmd,
      "show interface [vrf NAME$vrf_name] [brief$brief]",
      SHOW_STR
      "Interface status and configuration\n"
      VRF_CMD_HELP_STR
      "Interface status and configuration summary\n")
{
	struct vrf *vrf;
	struct interface *ifp;
	vrf_id_t vrf_id = VRF_DEFAULT;

	interface_update_stats();

	if (vrf_name)
		VRF_GET_ID(vrf_id, vrf_name, false);

	/* All interface print. */
	vrf = vrf_lookup_by_id(vrf_id);
	if (brief) {
		ifs_dump_brief_vty(vty, vrf);
	} else {
		FOR_ALL_INTERFACES (vrf, ifp) {
			if_dump_vty(vty, ifp);
		}
	}

	return CMD_SUCCESS;
}


/* Show all interfaces to vty. */
DEFPY (show_interface_vrf_all,
       show_interface_vrf_all_cmd,
       "show interface vrf all [brief$brief]",
       SHOW_STR
       "Interface status and configuration\n"
       VRF_ALL_CMD_HELP_STR
       "Interface status and configuration summary\n")
{
	struct vrf *vrf;
	struct interface *ifp;

	interface_update_stats();

	/* All interface print. */
	RB_FOREACH (vrf, vrf_name_head, &vrfs_by_name) {
		if (brief) {
			ifs_dump_brief_vty(vty, vrf);
		} else {
			FOR_ALL_INTERFACES (vrf, ifp)
				if_dump_vty(vty, ifp);
		}
	}

	return CMD_SUCCESS;
}

/* Show specified interface to vty. */

DEFUN (show_interface_name_vrf,
       show_interface_name_vrf_cmd,
       "show interface IFNAME vrf NAME",
       SHOW_STR
       "Interface status and configuration\n"
       "Interface name\n"
       VRF_CMD_HELP_STR)
{
	int idx_ifname = 2;
	int idx_name = 4;
	struct interface *ifp;
	vrf_id_t vrf_id;

	interface_update_stats();

	VRF_GET_ID(vrf_id, argv[idx_name]->arg, false);

	/* Specified interface print. */
	ifp = if_lookup_by_name(argv[idx_ifname]->arg, vrf_id);
	if (ifp == NULL) {
		vty_out(vty, "%% Can't find interface %s\n",
			argv[idx_ifname]->arg);
		return CMD_WARNING;
	}
	if_dump_vty(vty, ifp);

	return CMD_SUCCESS;
}

/* Show specified interface to vty. */
DEFUN (show_interface_name_vrf_all,
       show_interface_name_vrf_all_cmd,
       "show interface IFNAME [vrf all]",
       SHOW_STR
       "Interface status and configuration\n"
       "Interface name\n"
       VRF_ALL_CMD_HELP_STR)
{
	int idx_ifname = 2;
	struct vrf *vrf;
	struct interface *ifp;
	int found = 0;

	interface_update_stats();

	/* All interface print. */
	RB_FOREACH (vrf, vrf_name_head, &vrfs_by_name) {
		/* Specified interface print. */
		ifp = if_lookup_by_name(argv[idx_ifname]->arg, vrf->vrf_id);
		if (ifp) {
			if_dump_vty(vty, ifp);
			found++;
		}
	}

	if (!found) {
		vty_out(vty, "%% Can't find interface %s\n",
			argv[idx_ifname]->arg);
		return CMD_WARNING;
	}

	return CMD_SUCCESS;
}


static void if_show_description(struct vty *vty, vrf_id_t vrf_id)
{
	struct vrf *vrf = vrf_lookup_by_id(vrf_id);
	struct interface *ifp;

	vty_out(vty, "Interface       Status  Protocol  Description\n");
	FOR_ALL_INTERFACES (vrf, ifp) {
		int len;
		struct zebra_if *zif;
		bool intf_desc;

		intf_desc = false;

		len = vty_out(vty, "%s", ifp->name);
		vty_out(vty, "%*s", (16 - len), " ");

		if (if_is_up(ifp)) {
			vty_out(vty, "up      ");
			if (CHECK_FLAG(ifp->status,
				       ZEBRA_INTERFACE_LINKDETECTION)) {
				if (if_is_running(ifp))
					vty_out(vty, "up        ");
				else
					vty_out(vty, "down      ");
			} else {
				vty_out(vty, "unknown   ");
			}
		} else {
			vty_out(vty, "down    down      ");
		}

		if (ifp->desc) {
			intf_desc = true;
			vty_out(vty, "%s", ifp->desc);
		}
		zif = ifp->info;
		if (zif && zif->desc) {
			vty_out(vty, "%s%s",
				intf_desc
					? "\n                                  "
					: "",
				zif->desc);
		}

		vty_out(vty, "\n");
	}
}

DEFUN (show_interface_desc,
       show_interface_desc_cmd,
       "show interface description [vrf NAME]",
       SHOW_STR
       "Interface status and configuration\n"
       "Interface description\n"
       VRF_CMD_HELP_STR)
{
	vrf_id_t vrf_id = VRF_DEFAULT;

	if (argc > 3)
		VRF_GET_ID(vrf_id, argv[4]->arg, false);

	if_show_description(vty, vrf_id);

	return CMD_SUCCESS;
}


DEFUN (show_interface_desc_vrf_all,
       show_interface_desc_vrf_all_cmd,
       "show interface description vrf all",
       SHOW_STR
       "Interface status and configuration\n"
       "Interface description\n"
       VRF_ALL_CMD_HELP_STR)
{
	struct vrf *vrf;

	RB_FOREACH (vrf, vrf_name_head, &vrfs_by_name)
		if (!RB_EMPTY(if_name_head, &vrf->ifaces_by_name)) {
			vty_out(vty, "\n\tVRF %u\n\n", vrf->vrf_id);
			if_show_description(vty, vrf->vrf_id);
		}

	return CMD_SUCCESS;
}

DEFUN (multicast,
       multicast_cmd,
       "multicast",
       "Set multicast flag to interface\n")
{
	VTY_DECLVAR_CONTEXT(interface, ifp);
	int ret;
	struct zebra_if *if_data;

	if (CHECK_FLAG(ifp->status, ZEBRA_INTERFACE_ACTIVE)) {
		ret = if_set_flags(ifp, IFF_MULTICAST);
		if (ret < 0) {
			vty_out(vty, "Can't set multicast flag\n");
			return CMD_WARNING_CONFIG_FAILED;
		}
		if_refresh(ifp);
	}
	if_data = ifp->info;
	if_data->multicast = IF_ZEBRA_MULTICAST_ON;

	return CMD_SUCCESS;
}

DEFUN (no_multicast,
       no_multicast_cmd,
       "no multicast",
       NO_STR
       "Unset multicast flag to interface\n")
{
	VTY_DECLVAR_CONTEXT(interface, ifp);
	int ret;
	struct zebra_if *if_data;

	if (CHECK_FLAG(ifp->status, ZEBRA_INTERFACE_ACTIVE)) {
		ret = if_unset_flags(ifp, IFF_MULTICAST);
		if (ret < 0) {
			vty_out(vty, "Can't unset multicast flag\n");
			return CMD_WARNING_CONFIG_FAILED;
		}
		if_refresh(ifp);
	}
	if_data = ifp->info;
	if_data->multicast = IF_ZEBRA_MULTICAST_OFF;

	return CMD_SUCCESS;
}

DEFUN (linkdetect,
       linkdetect_cmd,
       "link-detect",
       "Enable link detection on interface\n")
{
	VTY_DECLVAR_CONTEXT(interface, ifp);
	int if_was_operative;

	if_was_operative = if_is_no_ptm_operative(ifp);
	SET_FLAG(ifp->status, ZEBRA_INTERFACE_LINKDETECTION);

	/* When linkdetection is enabled, if might come down */
	if (!if_is_no_ptm_operative(ifp) && if_was_operative)
		if_down(ifp);

	/* FIXME: Will defer status change forwarding if interface
	   does not come down! */

	return CMD_SUCCESS;
}


DEFUN (no_linkdetect,
       no_linkdetect_cmd,
       "no link-detect",
       NO_STR
       "Disable link detection on interface\n")
{
	VTY_DECLVAR_CONTEXT(interface, ifp);
	int if_was_operative;

	if_was_operative = if_is_no_ptm_operative(ifp);
	UNSET_FLAG(ifp->status, ZEBRA_INTERFACE_LINKDETECTION);

	/* Interface may come up after disabling link detection */
	if (if_is_operative(ifp) && !if_was_operative)
		if_up(ifp);

	/* FIXME: see linkdetect_cmd */

	return CMD_SUCCESS;
}

DEFUN (shutdown_if,
       shutdown_if_cmd,
       "shutdown",
       "Shutdown the selected interface\n")
{
	VTY_DECLVAR_CONTEXT(interface, ifp);
	int ret;
	struct zebra_if *if_data;

	if (ifp->ifindex != IFINDEX_INTERNAL) {
		ret = if_unset_flags(ifp, IFF_UP);
		if (ret < 0) {
			vty_out(vty, "Can't shutdown interface\n");
			return CMD_WARNING_CONFIG_FAILED;
		}
		if_refresh(ifp);
	}
	if_data = ifp->info;
	if_data->shutdown = IF_ZEBRA_SHUTDOWN_ON;

	return CMD_SUCCESS;
}

DEFUN (no_shutdown_if,
       no_shutdown_if_cmd,
       "no shutdown",
       NO_STR
       "Shutdown the selected interface\n")
{
	VTY_DECLVAR_CONTEXT(interface, ifp);
	int ret;
	struct zebra_if *if_data;

	if (ifp->ifindex != IFINDEX_INTERNAL) {
		ret = if_set_flags(ifp, IFF_UP | IFF_RUNNING);
		if (ret < 0) {
			vty_out(vty, "Can't up interface\n");
			return CMD_WARNING_CONFIG_FAILED;
		}
		if_refresh(ifp);

		/* Some addresses (in particular, IPv6 addresses on Linux) get
		 * removed when the interface goes down. They need to be
		 * readded.
		 */
		if_addr_wakeup(ifp);
	}

	if_data = ifp->info;
	if_data->shutdown = IF_ZEBRA_SHUTDOWN_OFF;

	return CMD_SUCCESS;
}

DEFUN (bandwidth_if,
       bandwidth_if_cmd,
       "bandwidth (1-100000)",
       "Set bandwidth informational parameter\n"
       "Bandwidth in megabits\n")
{
	int idx_number = 1;
	VTY_DECLVAR_CONTEXT(interface, ifp);
	unsigned int bandwidth;

	bandwidth = strtol(argv[idx_number]->arg, NULL, 10);

	/* bandwidth range is <1-100000> */
	if (bandwidth < 1 || bandwidth > 100000) {
		vty_out(vty, "Bandwidth is invalid\n");
		return CMD_WARNING_CONFIG_FAILED;
	}

	ifp->bandwidth = bandwidth;

	/* force protocols to recalculate routes due to cost change */
	if (if_is_operative(ifp))
		zebra_interface_up_update(ifp);

	return CMD_SUCCESS;
}

DEFUN (no_bandwidth_if,
       no_bandwidth_if_cmd,
       "no bandwidth [(1-100000)]",
       NO_STR
       "Set bandwidth informational parameter\n"
       "Bandwidth in megabits\n")
{
	VTY_DECLVAR_CONTEXT(interface, ifp);

	ifp->bandwidth = 0;

	/* force protocols to recalculate routes due to cost change */
	if (if_is_operative(ifp))
		zebra_interface_up_update(ifp);

	return CMD_SUCCESS;
}


struct cmd_node link_params_node = {
	LINK_PARAMS_NODE, "%s(config-link-params)# ", 1,
};

static void link_param_cmd_set_uint32(struct interface *ifp, uint32_t *field,
				      uint32_t type, uint32_t value)
{
	/* Update field as needed */
	if (IS_PARAM_UNSET(ifp->link_params, type) || *field != value) {
		*field = value;
		SET_PARAM(ifp->link_params, type);

		/* force protocols to update LINK STATE due to parameters change
		 */
		if (if_is_operative(ifp))
			zebra_interface_parameters_update(ifp);
	}
}
static void link_param_cmd_set_float(struct interface *ifp, float *field,
				     uint32_t type, float value)
{

	/* Update field as needed */
	if (IS_PARAM_UNSET(ifp->link_params, type) || *field != value) {
		*field = value;
		SET_PARAM(ifp->link_params, type);

		/* force protocols to update LINK STATE due to parameters change
		 */
		if (if_is_operative(ifp))
			zebra_interface_parameters_update(ifp);
	}
}

static void link_param_cmd_unset(struct interface *ifp, uint32_t type)
{
	if (ifp->link_params == NULL)
		return;

	/* Unset field */
	UNSET_PARAM(ifp->link_params, type);

	/* force protocols to update LINK STATE due to parameters change */
	if (if_is_operative(ifp))
		zebra_interface_parameters_update(ifp);
}

DEFUN_NOSH (link_params,
       link_params_cmd,
       "link-params",
       LINK_PARAMS_STR)
{
	/* vty->qobj_index stays the same @ interface pointer */
	vty->node = LINK_PARAMS_NODE;

	return CMD_SUCCESS;
}

DEFUN_NOSH (exit_link_params,
       exit_link_params_cmd,
       "exit-link-params",
       "Exit from Link Params configuration mode\n")
{
	if (vty->node == LINK_PARAMS_NODE)
		vty->node = INTERFACE_NODE;
	return CMD_SUCCESS;
}

/* Specific Traffic Engineering parameters commands */
DEFUN (link_params_enable,
       link_params_enable_cmd,
       "enable",
       "Activate link parameters on this interface\n")
{
	VTY_DECLVAR_CONTEXT(interface, ifp);

	/* This command could be issue at startup, when activate MPLS TE */
	/* on a new interface or after a ON / OFF / ON toggle */
	/* In all case, TE parameters are reset to their default factory */
	if (IS_ZEBRA_DEBUG_EVENT || IS_ZEBRA_DEBUG_MPLS)
		zlog_debug(
			"Link-params: enable TE link parameters on interface %s",
			ifp->name);

	if (!if_link_params_get(ifp)) {
		if (IS_ZEBRA_DEBUG_EVENT || IS_ZEBRA_DEBUG_MPLS)
			zlog_debug(
				"Link-params: failed to init TE link parameters  %s",
				ifp->name);

		return CMD_WARNING_CONFIG_FAILED;
	}

	/* force protocols to update LINK STATE due to parameters change */
	if (if_is_operative(ifp))
		zebra_interface_parameters_update(ifp);

	return CMD_SUCCESS;
}

DEFUN (no_link_params_enable,
       no_link_params_enable_cmd,
       "no enable",
       NO_STR
       "Disable link parameters on this interface\n")
{
	VTY_DECLVAR_CONTEXT(interface, ifp);

	if (IS_ZEBRA_DEBUG_EVENT || IS_ZEBRA_DEBUG_MPLS)
		zlog_debug("MPLS-TE: disable TE link parameters on interface %s",
			   ifp->name);

	if_link_params_free(ifp);

	/* force protocols to update LINK STATE due to parameters change */
	if (if_is_operative(ifp))
		zebra_interface_parameters_update(ifp);

	return CMD_SUCCESS;
}

/* STANDARD TE metrics */
DEFUN (link_params_metric,
       link_params_metric_cmd,
       "metric (0-4294967295)",
       "Link metric for MPLS-TE purpose\n"
       "Metric value in decimal\n")
{
	int idx_number = 1;
	VTY_DECLVAR_CONTEXT(interface, ifp);
	struct if_link_params *iflp = if_link_params_get(ifp);
	uint32_t metric;

	metric = strtoul(argv[idx_number]->arg, NULL, 10);

	/* Update TE metric if needed */
	link_param_cmd_set_uint32(ifp, &iflp->te_metric, LP_TE_METRIC, metric);

	return CMD_SUCCESS;
}

DEFUN (no_link_params_metric,
       no_link_params_metric_cmd,
       "no metric",
       NO_STR
       "Disable Link Metric on this interface\n")
{
	VTY_DECLVAR_CONTEXT(interface, ifp);

	/* Unset TE Metric */
	link_param_cmd_unset(ifp, LP_TE_METRIC);

	return CMD_SUCCESS;
}

DEFUN (link_params_maxbw,
       link_params_maxbw_cmd,
       "max-bw BANDWIDTH",
       "Maximum bandwidth that can be used\n"
       "Bytes/second (IEEE floating point format)\n")
{
	int idx_bandwidth = 1;
	VTY_DECLVAR_CONTEXT(interface, ifp);
	struct if_link_params *iflp = if_link_params_get(ifp);

	float bw;

	if (sscanf(argv[idx_bandwidth]->arg, "%g", &bw) != 1) {
		vty_out(vty, "link_params_maxbw: fscanf: %s\n",
			safe_strerror(errno));
		return CMD_WARNING_CONFIG_FAILED;
	}

	/* Check that Maximum bandwidth is not lower than other bandwidth
	 * parameters */
	if ((bw <= iflp->max_rsv_bw) || (bw <= iflp->unrsv_bw[0])
	    || (bw <= iflp->unrsv_bw[1]) || (bw <= iflp->unrsv_bw[2])
	    || (bw <= iflp->unrsv_bw[3]) || (bw <= iflp->unrsv_bw[4])
	    || (bw <= iflp->unrsv_bw[5]) || (bw <= iflp->unrsv_bw[6])
	    || (bw <= iflp->unrsv_bw[7]) || (bw <= iflp->ava_bw)
	    || (bw <= iflp->res_bw) || (bw <= iflp->use_bw)) {
		vty_out(vty,
			"Maximum Bandwidth could not be lower than others bandwidth\n");
		return CMD_WARNING_CONFIG_FAILED;
	}

	/* Update Maximum Bandwidth if needed */
	link_param_cmd_set_float(ifp, &iflp->max_bw, LP_MAX_BW, bw);

	return CMD_SUCCESS;
}

DEFUN (link_params_max_rsv_bw,
       link_params_max_rsv_bw_cmd,
       "max-rsv-bw BANDWIDTH",
       "Maximum bandwidth that may be reserved\n"
       "Bytes/second (IEEE floating point format)\n")
{
	int idx_bandwidth = 1;
	VTY_DECLVAR_CONTEXT(interface, ifp);
	struct if_link_params *iflp = if_link_params_get(ifp);
	float bw;

	if (sscanf(argv[idx_bandwidth]->arg, "%g", &bw) != 1) {
		vty_out(vty, "link_params_max_rsv_bw: fscanf: %s\n",
			safe_strerror(errno));
		return CMD_WARNING_CONFIG_FAILED;
	}

	/* Check that bandwidth is not greater than maximum bandwidth parameter
	 */
	if (bw > iflp->max_bw) {
		vty_out(vty,
			"Maximum Reservable Bandwidth could not be greater than Maximum Bandwidth (%g)\n",
			iflp->max_bw);
		return CMD_WARNING_CONFIG_FAILED;
	}

	/* Update Maximum Reservable Bandwidth if needed */
	link_param_cmd_set_float(ifp, &iflp->max_rsv_bw, LP_MAX_RSV_BW, bw);

	return CMD_SUCCESS;
}

DEFUN (link_params_unrsv_bw,
       link_params_unrsv_bw_cmd,
       "unrsv-bw (0-7) BANDWIDTH",
       "Unreserved bandwidth at each priority level\n"
       "Priority\n"
       "Bytes/second (IEEE floating point format)\n")
{
	int idx_number = 1;
	int idx_bandwidth = 2;
	VTY_DECLVAR_CONTEXT(interface, ifp);
	struct if_link_params *iflp = if_link_params_get(ifp);
	int priority;
	float bw;

	/* We don't have to consider about range check here. */
	if (sscanf(argv[idx_number]->arg, "%d", &priority) != 1) {
		vty_out(vty, "link_params_unrsv_bw: fscanf: %s\n",
			safe_strerror(errno));
		return CMD_WARNING_CONFIG_FAILED;
	}

	if (sscanf(argv[idx_bandwidth]->arg, "%g", &bw) != 1) {
		vty_out(vty, "link_params_unrsv_bw: fscanf: %s\n",
			safe_strerror(errno));
		return CMD_WARNING_CONFIG_FAILED;
	}

	/* Check that bandwidth is not greater than maximum bandwidth parameter
	 */
	if (bw > iflp->max_bw) {
		vty_out(vty,
			"UnReserved Bandwidth could not be greater than Maximum Bandwidth (%g)\n",
			iflp->max_bw);
		return CMD_WARNING_CONFIG_FAILED;
	}

	/* Update Unreserved Bandwidth if needed */
	link_param_cmd_set_float(ifp, &iflp->unrsv_bw[priority], LP_UNRSV_BW,
				 bw);

	return CMD_SUCCESS;
}

DEFUN (link_params_admin_grp,
       link_params_admin_grp_cmd,
       "admin-grp BITPATTERN",
       "Administrative group membership\n"
       "32-bit Hexadecimal value (e.g. 0xa1)\n")
{
	int idx_bitpattern = 1;
	VTY_DECLVAR_CONTEXT(interface, ifp);
	struct if_link_params *iflp = if_link_params_get(ifp);
	unsigned long value;

	if (sscanf(argv[idx_bitpattern]->arg, "0x%lx", &value) != 1) {
		vty_out(vty, "link_params_admin_grp: fscanf: %s\n",
			safe_strerror(errno));
		return CMD_WARNING_CONFIG_FAILED;
	}

	/* Update Administrative Group if needed */
	link_param_cmd_set_uint32(ifp, &iflp->admin_grp, LP_ADM_GRP, value);

	return CMD_SUCCESS;
}

DEFUN (no_link_params_admin_grp,
       no_link_params_admin_grp_cmd,
       "no admin-grp",
       NO_STR
       "Disable Administrative group membership on this interface\n")
{
	VTY_DECLVAR_CONTEXT(interface, ifp);

	/* Unset Admin Group */
	link_param_cmd_unset(ifp, LP_ADM_GRP);

	return CMD_SUCCESS;
}

/* RFC5392 & RFC5316: INTER-AS */
DEFUN (link_params_inter_as,
       link_params_inter_as_cmd,
       "neighbor A.B.C.D as (1-4294967295)",
       "Configure remote ASBR information (Neighbor IP address and AS number)\n"
       "Remote IP address in dot decimal A.B.C.D\n"
       "Remote AS number\n"
       "AS number in the range <1-4294967295>\n")
{
	int idx_ipv4 = 1;
	int idx_number = 3;

	VTY_DECLVAR_CONTEXT(interface, ifp);
	struct if_link_params *iflp = if_link_params_get(ifp);
	struct in_addr addr;
	uint32_t as;

	if (!inet_aton(argv[idx_ipv4]->arg, &addr)) {
		vty_out(vty, "Please specify Router-Addr by A.B.C.D\n");
		return CMD_WARNING_CONFIG_FAILED;
	}

	as = strtoul(argv[idx_number]->arg, NULL, 10);

	/* Update Remote IP and Remote AS fields if needed */
	if (IS_PARAM_UNSET(iflp, LP_RMT_AS) || iflp->rmt_as != as
	    || iflp->rmt_ip.s_addr != addr.s_addr) {

		iflp->rmt_as = as;
		iflp->rmt_ip.s_addr = addr.s_addr;
		SET_PARAM(iflp, LP_RMT_AS);

		/* force protocols to update LINK STATE due to parameters change
		 */
		if (if_is_operative(ifp))
			zebra_interface_parameters_update(ifp);
	}
	return CMD_SUCCESS;
}

DEFUN (no_link_params_inter_as,
       no_link_params_inter_as_cmd,
       "no neighbor",
       NO_STR
       "Remove Neighbor IP address and AS number for Inter-AS TE\n")
{
	VTY_DECLVAR_CONTEXT(interface, ifp);
	struct if_link_params *iflp = if_link_params_get(ifp);

	/* Reset Remote IP and AS neighbor */
	iflp->rmt_as = 0;
	iflp->rmt_ip.s_addr = 0;
	UNSET_PARAM(iflp, LP_RMT_AS);

	/* force protocols to update LINK STATE due to parameters change */
	if (if_is_operative(ifp))
		zebra_interface_parameters_update(ifp);

	return CMD_SUCCESS;
}

/* RFC7471: OSPF Traffic Engineering (TE) Metric extensions &
 * draft-ietf-isis-metric-extensions-07.txt */
DEFUN (link_params_delay,
       link_params_delay_cmd,
       "delay (0-16777215) [min (0-16777215) max (0-16777215)]",
       "Unidirectional Average Link Delay\n"
       "Average delay in micro-second as decimal (0...16777215)\n"
       "Minimum delay\n"
       "Minimum delay in micro-second as decimal (0...16777215)\n"
       "Maximum delay\n"
       "Maximum delay in micro-second as decimal (0...16777215)\n")
{
	/* Get and Check new delay values */
	uint32_t delay = 0, low = 0, high = 0;
	delay = strtoul(argv[1]->arg, NULL, 10);
	if (argc == 6) {
		low = strtoul(argv[3]->arg, NULL, 10);
		high = strtoul(argv[5]->arg, NULL, 10);
	}

	VTY_DECLVAR_CONTEXT(interface, ifp);
	struct if_link_params *iflp = if_link_params_get(ifp);
	uint8_t update = 0;

	if (argc == 2) {
		/* Check new delay value against old Min and Max delays if set
		 */
		if (IS_PARAM_SET(iflp, LP_MM_DELAY)
		    && (delay <= iflp->min_delay || delay >= iflp->max_delay)) {
			vty_out(vty,
				"Average delay should be comprise between Min (%d) and Max (%d) delay\n",
				iflp->min_delay, iflp->max_delay);
			return CMD_WARNING_CONFIG_FAILED;
		}
		/* Update delay if value is not set or change */
		if (IS_PARAM_UNSET(iflp, LP_DELAY) || iflp->av_delay != delay) {
			iflp->av_delay = delay;
			SET_PARAM(iflp, LP_DELAY);
			update = 1;
		}
		/* Unset Min and Max delays if already set */
		if (IS_PARAM_SET(iflp, LP_MM_DELAY)) {
			iflp->min_delay = 0;
			iflp->max_delay = 0;
			UNSET_PARAM(iflp, LP_MM_DELAY);
			update = 1;
		}
	} else {
		/* Check new delays value coherency */
		if (delay <= low || delay >= high) {
			vty_out(vty,
				"Average delay should be comprise between Min (%d) and Max (%d) delay\n",
				low, high);
			return CMD_WARNING_CONFIG_FAILED;
		}
		/* Update Delays if needed */
		if (IS_PARAM_UNSET(iflp, LP_DELAY)
		    || IS_PARAM_UNSET(iflp, LP_MM_DELAY)
		    || iflp->av_delay != delay || iflp->min_delay != low
		    || iflp->max_delay != high) {
			iflp->av_delay = delay;
			SET_PARAM(iflp, LP_DELAY);
			iflp->min_delay = low;
			iflp->max_delay = high;
			SET_PARAM(iflp, LP_MM_DELAY);
			update = 1;
		}
	}

	/* force protocols to update LINK STATE due to parameters change */
	if (update == 1 && if_is_operative(ifp))
		zebra_interface_parameters_update(ifp);

	return CMD_SUCCESS;
}

DEFUN (no_link_params_delay,
       no_link_params_delay_cmd,
       "no delay",
       NO_STR
       "Disable Unidirectional Average, Min & Max Link Delay on this interface\n")
{
	VTY_DECLVAR_CONTEXT(interface, ifp);
	struct if_link_params *iflp = if_link_params_get(ifp);

	/* Unset Delays */
	iflp->av_delay = 0;
	UNSET_PARAM(iflp, LP_DELAY);
	iflp->min_delay = 0;
	iflp->max_delay = 0;
	UNSET_PARAM(iflp, LP_MM_DELAY);

	/* force protocols to update LINK STATE due to parameters change */
	if (if_is_operative(ifp))
		zebra_interface_parameters_update(ifp);

	return CMD_SUCCESS;
}

DEFUN (link_params_delay_var,
       link_params_delay_var_cmd,
       "delay-variation (0-16777215)",
       "Unidirectional Link Delay Variation\n"
       "delay variation in micro-second as decimal (0...16777215)\n")
{
	int idx_number = 1;
	VTY_DECLVAR_CONTEXT(interface, ifp);
	struct if_link_params *iflp = if_link_params_get(ifp);
	uint32_t value;

	value = strtoul(argv[idx_number]->arg, NULL, 10);

	/* Update Delay Variation if needed */
	link_param_cmd_set_uint32(ifp, &iflp->delay_var, LP_DELAY_VAR, value);

	return CMD_SUCCESS;
}

DEFUN (no_link_params_delay_var,
       no_link_params_delay_var_cmd,
       "no delay-variation",
       NO_STR
       "Disable Unidirectional Delay Variation on this interface\n")
{
	VTY_DECLVAR_CONTEXT(interface, ifp);

	/* Unset Delay Variation */
	link_param_cmd_unset(ifp, LP_DELAY_VAR);

	return CMD_SUCCESS;
}

DEFUN (link_params_pkt_loss,
       link_params_pkt_loss_cmd,
       "packet-loss PERCENTAGE",
       "Unidirectional Link Packet Loss\n"
       "percentage of total traffic by 0.000003% step and less than 50.331642%\n")
{
	int idx_percentage = 1;
	VTY_DECLVAR_CONTEXT(interface, ifp);
	struct if_link_params *iflp = if_link_params_get(ifp);
	float fval;

	if (sscanf(argv[idx_percentage]->arg, "%g", &fval) != 1) {
		vty_out(vty, "link_params_pkt_loss: fscanf: %s\n",
			safe_strerror(errno));
		return CMD_WARNING_CONFIG_FAILED;
	}

	if (fval > MAX_PKT_LOSS)
		fval = MAX_PKT_LOSS;

	/* Update Packet Loss if needed */
	link_param_cmd_set_float(ifp, &iflp->pkt_loss, LP_PKT_LOSS, fval);

	return CMD_SUCCESS;
}

DEFUN (no_link_params_pkt_loss,
       no_link_params_pkt_loss_cmd,
       "no packet-loss",
       NO_STR
       "Disable Unidirectional Link Packet Loss on this interface\n")
{
	VTY_DECLVAR_CONTEXT(interface, ifp);

	/* Unset Packet Loss */
	link_param_cmd_unset(ifp, LP_PKT_LOSS);

	return CMD_SUCCESS;
}

DEFUN (link_params_res_bw,
       link_params_res_bw_cmd,
       "res-bw BANDWIDTH",
       "Unidirectional Residual Bandwidth\n"
       "Bytes/second (IEEE floating point format)\n")
{
	int idx_bandwidth = 1;
	VTY_DECLVAR_CONTEXT(interface, ifp);
	struct if_link_params *iflp = if_link_params_get(ifp);
	float bw;

	if (sscanf(argv[idx_bandwidth]->arg, "%g", &bw) != 1) {
		vty_out(vty, "link_params_res_bw: fscanf: %s\n",
			safe_strerror(errno));
		return CMD_WARNING_CONFIG_FAILED;
	}

	/* Check that bandwidth is not greater than maximum bandwidth parameter
	 */
	if (bw > iflp->max_bw) {
		vty_out(vty,
			"Residual Bandwidth could not be greater than Maximum Bandwidth (%g)\n",
			iflp->max_bw);
		return CMD_WARNING_CONFIG_FAILED;
	}

	/* Update Residual Bandwidth if needed */
	link_param_cmd_set_float(ifp, &iflp->res_bw, LP_RES_BW, bw);

	return CMD_SUCCESS;
}

DEFUN (no_link_params_res_bw,
       no_link_params_res_bw_cmd,
       "no res-bw",
       NO_STR
       "Disable Unidirectional Residual Bandwidth on this interface\n")
{
	VTY_DECLVAR_CONTEXT(interface, ifp);

	/* Unset Residual Bandwidth */
	link_param_cmd_unset(ifp, LP_RES_BW);

	return CMD_SUCCESS;
}

DEFUN (link_params_ava_bw,
       link_params_ava_bw_cmd,
       "ava-bw BANDWIDTH",
       "Unidirectional Available Bandwidth\n"
       "Bytes/second (IEEE floating point format)\n")
{
	int idx_bandwidth = 1;
	VTY_DECLVAR_CONTEXT(interface, ifp);
	struct if_link_params *iflp = if_link_params_get(ifp);
	float bw;

	if (sscanf(argv[idx_bandwidth]->arg, "%g", &bw) != 1) {
		vty_out(vty, "link_params_ava_bw: fscanf: %s\n",
			safe_strerror(errno));
		return CMD_WARNING_CONFIG_FAILED;
	}

	/* Check that bandwidth is not greater than maximum bandwidth parameter
	 */
	if (bw > iflp->max_bw) {
		vty_out(vty,
			"Available Bandwidth could not be greater than Maximum Bandwidth (%g)\n",
			iflp->max_bw);
		return CMD_WARNING_CONFIG_FAILED;
	}

	/* Update Residual Bandwidth if needed */
	link_param_cmd_set_float(ifp, &iflp->ava_bw, LP_AVA_BW, bw);

	return CMD_SUCCESS;
}

DEFUN (no_link_params_ava_bw,
       no_link_params_ava_bw_cmd,
       "no ava-bw",
       NO_STR
       "Disable Unidirectional Available Bandwidth on this interface\n")
{
	VTY_DECLVAR_CONTEXT(interface, ifp);

	/* Unset Available Bandwidth */
	link_param_cmd_unset(ifp, LP_AVA_BW);

	return CMD_SUCCESS;
}

DEFUN (link_params_use_bw,
       link_params_use_bw_cmd,
       "use-bw BANDWIDTH",
       "Unidirectional Utilised Bandwidth\n"
       "Bytes/second (IEEE floating point format)\n")
{
	int idx_bandwidth = 1;
	VTY_DECLVAR_CONTEXT(interface, ifp);
	struct if_link_params *iflp = if_link_params_get(ifp);
	float bw;

	if (sscanf(argv[idx_bandwidth]->arg, "%g", &bw) != 1) {
		vty_out(vty, "link_params_use_bw: fscanf: %s\n",
			safe_strerror(errno));
		return CMD_WARNING_CONFIG_FAILED;
	}

	/* Check that bandwidth is not greater than maximum bandwidth parameter
	 */
	if (bw > iflp->max_bw) {
		vty_out(vty,
			"Utilised Bandwidth could not be greater than Maximum Bandwidth (%g)\n",
			iflp->max_bw);
		return CMD_WARNING_CONFIG_FAILED;
	}

	/* Update Utilized Bandwidth if needed */
	link_param_cmd_set_float(ifp, &iflp->use_bw, LP_USE_BW, bw);

	return CMD_SUCCESS;
}

DEFUN (no_link_params_use_bw,
       no_link_params_use_bw_cmd,
       "no use-bw",
       NO_STR
       "Disable Unidirectional Utilised Bandwidth on this interface\n")
{
	VTY_DECLVAR_CONTEXT(interface, ifp);

	/* Unset Utilised Bandwidth */
	link_param_cmd_unset(ifp, LP_USE_BW);

	return CMD_SUCCESS;
}

static int ip_address_install(struct vty *vty, struct interface *ifp,
			      const char *addr_str, const char *peer_str,
			      const char *label)
{
	struct zebra_if *if_data;
	struct prefix_ipv4 lp, pp;
	struct connected *ifc;
	struct prefix_ipv4 *p;
	int ret;
	enum zebra_dplane_result dplane_res;

	if_data = ifp->info;

	ret = str2prefix_ipv4(addr_str, &lp);
	if (ret <= 0) {
		vty_out(vty, "%% Malformed address \n");
		return CMD_WARNING_CONFIG_FAILED;
	}

	if (ipv4_martian(&lp.prefix)) {
		vty_out(vty, "%% Invalid address\n");
		return CMD_WARNING_CONFIG_FAILED;
	}

	if (peer_str) {
		if (lp.prefixlen != 32) {
			vty_out(vty,
				"%% Local prefix length for P-t-P address must be /32\n");
			return CMD_WARNING_CONFIG_FAILED;
		}

		ret = str2prefix_ipv4(peer_str, &pp);
		if (ret <= 0) {
			vty_out(vty, "%% Malformed peer address\n");
			return CMD_WARNING_CONFIG_FAILED;
		}
	}

	ifc = connected_check_ptp(ifp, &lp, peer_str ? &pp : NULL);
	if (!ifc) {
		ifc = connected_new();
		ifc->ifp = ifp;

		/* Address. */
		p = prefix_ipv4_new();
		*p = lp;
		ifc->address = (struct prefix *)p;

		if (peer_str) {
			SET_FLAG(ifc->flags, ZEBRA_IFA_PEER);
			p = prefix_ipv4_new();
			*p = pp;
			ifc->destination = (struct prefix *)p;
		}

		/* Label. */
		if (label)
			ifc->label = XSTRDUP(MTYPE_CONNECTED_LABEL, label);

		/* Add to linked list. */
		listnode_add(ifp->connected, ifc);
	}

	/* This address is configured from zebra. */
	if (!CHECK_FLAG(ifc->conf, ZEBRA_IFC_CONFIGURED))
		SET_FLAG(ifc->conf, ZEBRA_IFC_CONFIGURED);

	/* In case of this route need to install kernel. */
	if (!CHECK_FLAG(ifc->conf, ZEBRA_IFC_QUEUED)
	    && CHECK_FLAG(ifp->status, ZEBRA_INTERFACE_ACTIVE)
	    && !(if_data && if_data->shutdown == IF_ZEBRA_SHUTDOWN_ON)) {
		/* Some system need to up the interface to set IP address. */
		if (!if_is_up(ifp)) {
			if_set_flags(ifp, IFF_UP | IFF_RUNNING);
			if_refresh(ifp);
		}

		dplane_res = dplane_intf_addr_set(ifp, ifc);
		if (dplane_res == ZEBRA_DPLANE_REQUEST_FAILURE) {
			vty_out(vty, "%% Can't set interface IP address: %s.\n",
				dplane_res2str(dplane_res));
			return CMD_WARNING_CONFIG_FAILED;
		}

		SET_FLAG(ifc->conf, ZEBRA_IFC_QUEUED);
		/* The address will be advertised to zebra clients when the
		 * notification
		 * from the kernel has been received.
		 * It will also be added to the subnet chain list, then. */
	}

	return CMD_SUCCESS;
}

static int ip_address_uninstall(struct vty *vty, struct interface *ifp,
				const char *addr_str, const char *peer_str,
				const char *label)
{
	struct prefix_ipv4 lp, pp;
	struct connected *ifc;
	int ret;
	enum zebra_dplane_result dplane_res;

	/* Convert to prefix structure. */
	ret = str2prefix_ipv4(addr_str, &lp);
	if (ret <= 0) {
		vty_out(vty, "%% Malformed address \n");
		return CMD_WARNING_CONFIG_FAILED;
	}

	if (peer_str) {
		if (lp.prefixlen != 32) {
			vty_out(vty,
				"%% Local prefix length for P-t-P address must be /32\n");
			return CMD_WARNING_CONFIG_FAILED;
		}

		ret = str2prefix_ipv4(peer_str, &pp);
		if (ret <= 0) {
			vty_out(vty, "%% Malformed peer address\n");
			return CMD_WARNING_CONFIG_FAILED;
		}
	}

	/* Check current interface address. */
	ifc = connected_check_ptp(ifp, &lp, peer_str ? &pp : NULL);
	if (!ifc) {
		vty_out(vty, "%% Can't find address\n");
		return CMD_WARNING_CONFIG_FAILED;
	}

	/* This is not configured address. */
	if (!CHECK_FLAG(ifc->conf, ZEBRA_IFC_CONFIGURED))
		return CMD_WARNING_CONFIG_FAILED;

	UNSET_FLAG(ifc->conf, ZEBRA_IFC_CONFIGURED);

	/* This is not real address or interface is not active. */
	if (!CHECK_FLAG(ifc->conf, ZEBRA_IFC_QUEUED)
	    || !CHECK_FLAG(ifp->status, ZEBRA_INTERFACE_ACTIVE)) {
		listnode_delete(ifp->connected, ifc);
		connected_free(&ifc);
		return CMD_WARNING_CONFIG_FAILED;
	}

	/* This is real route. */
	dplane_res = dplane_intf_addr_unset(ifp, ifc);
	if (dplane_res == ZEBRA_DPLANE_REQUEST_FAILURE) {
		vty_out(vty, "%% Can't unset interface IP address: %s.\n",
			dplane_res2str(dplane_res));
		return CMD_WARNING_CONFIG_FAILED;
	}
	UNSET_FLAG(ifc->conf, ZEBRA_IFC_QUEUED);
	/* we will receive a kernel notification about this route being removed.
	 * this will trigger its removal from the connected list. */
	return CMD_SUCCESS;
}

DEFUN (ip_address,
       ip_address_cmd,
       "ip address A.B.C.D/M",
       "Interface Internet Protocol config commands\n"
       "Set the IP address of an interface\n"
       "IP address (e.g. 10.0.0.1/8)\n")
{
	int idx_ipv4_prefixlen = 2;
	VTY_DECLVAR_CONTEXT(interface, ifp);
	return ip_address_install(vty, ifp, argv[idx_ipv4_prefixlen]->arg, NULL,
				  NULL);
}

DEFUN (no_ip_address,
       no_ip_address_cmd,
       "no ip address A.B.C.D/M",
       NO_STR
       "Interface Internet Protocol config commands\n"
       "Set the IP address of an interface\n"
       "IP Address (e.g. 10.0.0.1/8)\n")
{
	int idx_ipv4_prefixlen = 3;
	VTY_DECLVAR_CONTEXT(interface, ifp);
	return ip_address_uninstall(vty, ifp, argv[idx_ipv4_prefixlen]->arg,
				    NULL, NULL);
}

DEFUN(ip_address_peer,
      ip_address_peer_cmd,
      "ip address A.B.C.D peer A.B.C.D/M",
      "Interface Internet Protocol config commands\n"
      "Set the IP address of an interface\n"
      "Local IP (e.g. 10.0.0.1) for P-t-P address\n"
      "Specify P-t-P address\n"
      "Peer IP address (e.g. 10.0.0.1/8)\n")
{
	VTY_DECLVAR_CONTEXT(interface, ifp);
	return ip_address_install(vty, ifp, argv[2]->arg, argv[4]->arg, NULL);
}

DEFUN(no_ip_address_peer,
      no_ip_address_peer_cmd,
      "no ip address A.B.C.D peer A.B.C.D/M",
      NO_STR
      "Interface Internet Protocol config commands\n"
      "Set the IP address of an interface\n"
      "Local IP (e.g. 10.0.0.1) for P-t-P address\n"
      "Specify P-t-P address\n"
      "Peer IP address (e.g. 10.0.0.1/8)\n")
{
	VTY_DECLVAR_CONTEXT(interface, ifp);
	return ip_address_uninstall(vty, ifp, argv[3]->arg, argv[5]->arg, NULL);
}

#ifdef HAVE_NETLINK
DEFUN (ip_address_label,
       ip_address_label_cmd,
       "ip address A.B.C.D/M label LINE",
       "Interface Internet Protocol config commands\n"
       "Set the IP address of an interface\n"
       "IP address (e.g. 10.0.0.1/8)\n"
       "Label of this address\n"
       "Label\n")
{
	int idx_ipv4_prefixlen = 2;
	int idx_line = 4;
	VTY_DECLVAR_CONTEXT(interface, ifp);
	return ip_address_install(vty, ifp, argv[idx_ipv4_prefixlen]->arg, NULL,
				  argv[idx_line]->arg);
}

DEFUN (no_ip_address_label,
       no_ip_address_label_cmd,
       "no ip address A.B.C.D/M label LINE",
       NO_STR
       "Interface Internet Protocol config commands\n"
       "Set the IP address of an interface\n"
       "IP address (e.g. 10.0.0.1/8)\n"
       "Label of this address\n"
       "Label\n")
{
	int idx_ipv4_prefixlen = 3;
	int idx_line = 5;
	VTY_DECLVAR_CONTEXT(interface, ifp);
	return ip_address_uninstall(vty, ifp, argv[idx_ipv4_prefixlen]->arg,
				    NULL, argv[idx_line]->arg);
}
#endif /* HAVE_NETLINK */

static int ipv6_address_install(struct vty *vty, struct interface *ifp,
				const char *addr_str, const char *peer_str,
				const char *label)
{
	struct zebra_if *if_data;
	struct prefix_ipv6 cp;
	struct connected *ifc;
	struct prefix_ipv6 *p;
	int ret;
	enum zebra_dplane_result dplane_res;

	if_data = ifp->info;

	ret = str2prefix_ipv6(addr_str, &cp);
	if (ret <= 0) {
		vty_out(vty, "%% Malformed address \n");
		return CMD_WARNING_CONFIG_FAILED;
	}

	if (ipv6_martian(&cp.prefix)) {
		vty_out(vty, "%% Invalid address\n");
		return CMD_WARNING_CONFIG_FAILED;
	}

	ifc = connected_check(ifp, (struct prefix *)&cp);
	if (!ifc) {
		ifc = connected_new();
		ifc->ifp = ifp;

		/* Address. */
		p = prefix_ipv6_new();
		*p = cp;
		ifc->address = (struct prefix *)p;

		/* Label. */
		if (label)
			ifc->label = XSTRDUP(MTYPE_CONNECTED_LABEL, label);

		/* Add to linked list. */
		listnode_add(ifp->connected, ifc);
	}

	/* This address is configured from zebra. */
	if (!CHECK_FLAG(ifc->conf, ZEBRA_IFC_CONFIGURED))
		SET_FLAG(ifc->conf, ZEBRA_IFC_CONFIGURED);

	/* In case of this route need to install kernel. */
	if (!CHECK_FLAG(ifc->conf, ZEBRA_IFC_QUEUED)
	    && CHECK_FLAG(ifp->status, ZEBRA_INTERFACE_ACTIVE)
	    && !(if_data && if_data->shutdown == IF_ZEBRA_SHUTDOWN_ON)) {
		/* Some system need to up the interface to set IP address. */
		if (!if_is_up(ifp)) {
			if_set_flags(ifp, IFF_UP | IFF_RUNNING);
			if_refresh(ifp);
		}

		dplane_res = dplane_intf_addr_set(ifp, ifc);
		if (dplane_res == ZEBRA_DPLANE_REQUEST_FAILURE) {
			vty_out(vty, "%% Can't set interface IP address: %s.\n",
				dplane_res2str(dplane_res));
			return CMD_WARNING_CONFIG_FAILED;
		}

		SET_FLAG(ifc->conf, ZEBRA_IFC_QUEUED);
		/* The address will be advertised to zebra clients when the
		 * notification
		 * from the kernel has been received. */
	}

	return CMD_SUCCESS;
}

/* Return true if an ipv6 address is configured on ifp */
int ipv6_address_configured(struct interface *ifp)
{
	struct connected *connected;
	struct listnode *node;

	for (ALL_LIST_ELEMENTS_RO(ifp->connected, node, connected))
		if (CHECK_FLAG(connected->conf, ZEBRA_IFC_REAL)
		    && (connected->address->family == AF_INET6))
			return 1;

	return 0;
}

static int ipv6_address_uninstall(struct vty *vty, struct interface *ifp,
				  const char *addr_str, const char *peer_str,
				  const char *label)
{
	struct prefix_ipv6 cp;
	struct connected *ifc;
	int ret;
	enum zebra_dplane_result dplane_res;

	/* Convert to prefix structure. */
	ret = str2prefix_ipv6(addr_str, &cp);
	if (ret <= 0) {
		vty_out(vty, "%% Malformed address \n");
		return CMD_WARNING_CONFIG_FAILED;
	}

	/* Check current interface address. */
	ifc = connected_check(ifp, (struct prefix *)&cp);
	if (!ifc) {
		vty_out(vty, "%% Can't find address\n");
		return CMD_WARNING_CONFIG_FAILED;
	}

	/* This is not configured address. */
	if (!CHECK_FLAG(ifc->conf, ZEBRA_IFC_CONFIGURED))
		return CMD_WARNING_CONFIG_FAILED;

	UNSET_FLAG(ifc->conf, ZEBRA_IFC_CONFIGURED);

	/* This is not real address or interface is not active. */
	if (!CHECK_FLAG(ifc->conf, ZEBRA_IFC_QUEUED)
	    || !CHECK_FLAG(ifp->status, ZEBRA_INTERFACE_ACTIVE)) {
		listnode_delete(ifp->connected, ifc);
		connected_free(&ifc);
		return CMD_WARNING_CONFIG_FAILED;
	}

	/* This is real route. */
	dplane_res = dplane_intf_addr_unset(ifp, ifc);
	if (dplane_res == ZEBRA_DPLANE_REQUEST_FAILURE) {
		vty_out(vty, "%% Can't unset interface IP address: %s.\n",
			dplane_res2str(dplane_res));
		return CMD_WARNING_CONFIG_FAILED;
	}

	UNSET_FLAG(ifc->conf, ZEBRA_IFC_QUEUED);
	/* This information will be propagated to the zclients when the
	 * kernel notification is received. */
	return CMD_SUCCESS;
}

DEFUN (ipv6_address,
       ipv6_address_cmd,
       "ipv6 address X:X::X:X/M",
       "Interface IPv6 config commands\n"
       "Set the IP address of an interface\n"
       "IPv6 address (e.g. 3ffe:506::1/48)\n")
{
	int idx_ipv6_prefixlen = 2;
	VTY_DECLVAR_CONTEXT(interface, ifp);
	return ipv6_address_install(vty, ifp, argv[idx_ipv6_prefixlen]->arg,
				    NULL, NULL);
}

DEFUN (no_ipv6_address,
       no_ipv6_address_cmd,
       "no ipv6 address X:X::X:X/M",
       NO_STR
       "Interface IPv6 config commands\n"
       "Set the IP address of an interface\n"
       "IPv6 address (e.g. 3ffe:506::1/48)\n")
{
	int idx_ipv6_prefixlen = 3;
	VTY_DECLVAR_CONTEXT(interface, ifp);
	return ipv6_address_uninstall(vty, ifp, argv[idx_ipv6_prefixlen]->arg,
				      NULL, NULL);
}

static int link_params_config_write(struct vty *vty, struct interface *ifp)
{
	int i;

	if ((ifp == NULL) || !HAS_LINK_PARAMS(ifp))
		return -1;

	struct if_link_params *iflp = ifp->link_params;

	vty_out(vty, " link-params\n");
	vty_out(vty, "  enable\n");
	if (IS_PARAM_SET(iflp, LP_TE_METRIC) && iflp->te_metric != ifp->metric)
		vty_out(vty, "  metric %u\n", iflp->te_metric);
	if (IS_PARAM_SET(iflp, LP_MAX_BW) && iflp->max_bw != iflp->default_bw)
		vty_out(vty, "  max-bw %g\n", iflp->max_bw);
	if (IS_PARAM_SET(iflp, LP_MAX_RSV_BW)
	    && iflp->max_rsv_bw != iflp->default_bw)
		vty_out(vty, "  max-rsv-bw %g\n", iflp->max_rsv_bw);
	if (IS_PARAM_SET(iflp, LP_UNRSV_BW)) {
		for (i = 0; i < 8; i++)
			if (iflp->unrsv_bw[i] != iflp->default_bw)
				vty_out(vty, "  unrsv-bw %d %g\n", i,
					iflp->unrsv_bw[i]);
	}
	if (IS_PARAM_SET(iflp, LP_ADM_GRP))
		vty_out(vty, "  admin-grp 0x%x\n", iflp->admin_grp);
	if (IS_PARAM_SET(iflp, LP_DELAY)) {
		vty_out(vty, "  delay %u", iflp->av_delay);
		if (IS_PARAM_SET(iflp, LP_MM_DELAY)) {
			vty_out(vty, " min %u", iflp->min_delay);
			vty_out(vty, " max %u", iflp->max_delay);
		}
		vty_out(vty, "\n");
	}
	if (IS_PARAM_SET(iflp, LP_DELAY_VAR))
		vty_out(vty, "  delay-variation %u\n", iflp->delay_var);
	if (IS_PARAM_SET(iflp, LP_PKT_LOSS))
		vty_out(vty, "  packet-loss %g\n", iflp->pkt_loss);
	if (IS_PARAM_SET(iflp, LP_AVA_BW))
		vty_out(vty, "  ava-bw %g\n", iflp->ava_bw);
	if (IS_PARAM_SET(iflp, LP_RES_BW))
		vty_out(vty, "  res-bw %g\n", iflp->res_bw);
	if (IS_PARAM_SET(iflp, LP_USE_BW))
		vty_out(vty, "  use-bw %g\n", iflp->use_bw);
	if (IS_PARAM_SET(iflp, LP_RMT_AS))
		vty_out(vty, "  neighbor %s as %u\n", inet_ntoa(iflp->rmt_ip),
			iflp->rmt_as);
	vty_out(vty, "  exit-link-params\n");
	return 0;
}

static int if_config_write(struct vty *vty)
{
	struct vrf *vrf0;
	struct interface *ifp;

	zebra_ptm_write(vty);

	RB_FOREACH (vrf0, vrf_name_head, &vrfs_by_name)
		FOR_ALL_INTERFACES (vrf0, ifp) {
			struct zebra_if *if_data;
			struct listnode *addrnode;
			struct connected *ifc;
			struct prefix *p;
			struct vrf *vrf;

			if_data = ifp->info;
			vrf = vrf_lookup_by_id(ifp->vrf_id);

			if (ifp->vrf_id == VRF_DEFAULT)
				vty_frame(vty, "interface %s\n", ifp->name);
			else
				vty_frame(vty, "interface %s vrf %s\n",
					  ifp->name, vrf->name);

			if (if_data) {
				if (if_data->shutdown == IF_ZEBRA_SHUTDOWN_ON)
					vty_out(vty, " shutdown\n");

				zebra_ptm_if_write(vty, if_data);
			}

			if (ifp->desc)
				vty_out(vty, " description %s\n", ifp->desc);

			/* Assign bandwidth here to avoid unnecessary interface
			   flap
			   while processing config script */
			if (ifp->bandwidth != 0)
				vty_out(vty, " bandwidth %u\n", ifp->bandwidth);

			if (!CHECK_FLAG(ifp->status,
					ZEBRA_INTERFACE_LINKDETECTION))
				vty_out(vty, " no link-detect\n");

			for (ALL_LIST_ELEMENTS_RO(ifp->connected, addrnode,
						  ifc)) {
				if (CHECK_FLAG(ifc->conf,
					       ZEBRA_IFC_CONFIGURED)) {
					char buf[INET6_ADDRSTRLEN];
					p = ifc->address;
					vty_out(vty, " ip%s address %s",
						p->family == AF_INET ? ""
								     : "v6",
						inet_ntop(p->family,
							  &p->u.prefix, buf,
							  sizeof(buf)));
					if (CONNECTED_PEER(ifc)) {
						p = ifc->destination;
						vty_out(vty, " peer %s",
							inet_ntop(p->family,
								  &p->u.prefix,
								  buf,
								  sizeof(buf)));
					}
					vty_out(vty, "/%d", p->prefixlen);

					if (ifc->label)
						vty_out(vty, " label %s",
							ifc->label);

					vty_out(vty, "\n");
				}
			}

			if (if_data) {
				if (if_data->multicast
				    != IF_ZEBRA_MULTICAST_UNSPEC)
					vty_out(vty, " %smulticast\n",
						if_data->multicast
								== IF_ZEBRA_MULTICAST_ON
							? ""
							: "no ");
			}

			hook_call(zebra_if_config_wr, vty, ifp);

			link_params_config_write(vty, ifp);

			vty_endframe(vty, "!\n");
		}
	return 0;
}

/* Allocate and initialize interface vector. */
void zebra_if_init(void)
{
	/* Initialize interface and new hook. */
	hook_register_prio(if_add, 0, if_zebra_new_hook);
	hook_register_prio(if_del, 0, if_zebra_delete_hook);

	/* Install configuration write function. */
	install_node(&interface_node, if_config_write);
	install_node(&link_params_node, NULL);
	if_cmd_init();
	/*
	 * This is *intentionally* setting this to NULL, signaling
	 * that interface creation for zebra acts differently
	 */
	if_zapi_callbacks(NULL, NULL, NULL, NULL);

	install_element(VIEW_NODE, &show_interface_cmd);
	install_element(VIEW_NODE, &show_interface_vrf_all_cmd);
	install_element(VIEW_NODE, &show_interface_name_vrf_cmd);
	install_element(VIEW_NODE, &show_interface_name_vrf_all_cmd);

	install_element(ENABLE_NODE, &show_interface_desc_cmd);
	install_element(ENABLE_NODE, &show_interface_desc_vrf_all_cmd);
	install_element(INTERFACE_NODE, &multicast_cmd);
	install_element(INTERFACE_NODE, &no_multicast_cmd);
	install_element(INTERFACE_NODE, &linkdetect_cmd);
	install_element(INTERFACE_NODE, &no_linkdetect_cmd);
	install_element(INTERFACE_NODE, &shutdown_if_cmd);
	install_element(INTERFACE_NODE, &no_shutdown_if_cmd);
	install_element(INTERFACE_NODE, &bandwidth_if_cmd);
	install_element(INTERFACE_NODE, &no_bandwidth_if_cmd);
	install_element(INTERFACE_NODE, &ip_address_cmd);
	install_element(INTERFACE_NODE, &no_ip_address_cmd);
	install_element(INTERFACE_NODE, &ip_address_peer_cmd);
	install_element(INTERFACE_NODE, &no_ip_address_peer_cmd);
	install_element(INTERFACE_NODE, &ipv6_address_cmd);
	install_element(INTERFACE_NODE, &no_ipv6_address_cmd);
#ifdef HAVE_NETLINK
	install_element(INTERFACE_NODE, &ip_address_label_cmd);
	install_element(INTERFACE_NODE, &no_ip_address_label_cmd);
#endif /* HAVE_NETLINK */
	install_element(INTERFACE_NODE, &link_params_cmd);
	install_default(LINK_PARAMS_NODE);
	install_element(LINK_PARAMS_NODE, &link_params_enable_cmd);
	install_element(LINK_PARAMS_NODE, &no_link_params_enable_cmd);
	install_element(LINK_PARAMS_NODE, &link_params_metric_cmd);
	install_element(LINK_PARAMS_NODE, &no_link_params_metric_cmd);
	install_element(LINK_PARAMS_NODE, &link_params_maxbw_cmd);
	install_element(LINK_PARAMS_NODE, &link_params_max_rsv_bw_cmd);
	install_element(LINK_PARAMS_NODE, &link_params_unrsv_bw_cmd);
	install_element(LINK_PARAMS_NODE, &link_params_admin_grp_cmd);
	install_element(LINK_PARAMS_NODE, &no_link_params_admin_grp_cmd);
	install_element(LINK_PARAMS_NODE, &link_params_inter_as_cmd);
	install_element(LINK_PARAMS_NODE, &no_link_params_inter_as_cmd);
	install_element(LINK_PARAMS_NODE, &link_params_delay_cmd);
	install_element(LINK_PARAMS_NODE, &no_link_params_delay_cmd);
	install_element(LINK_PARAMS_NODE, &link_params_delay_var_cmd);
	install_element(LINK_PARAMS_NODE, &no_link_params_delay_var_cmd);
	install_element(LINK_PARAMS_NODE, &link_params_pkt_loss_cmd);
	install_element(LINK_PARAMS_NODE, &no_link_params_pkt_loss_cmd);
	install_element(LINK_PARAMS_NODE, &link_params_ava_bw_cmd);
	install_element(LINK_PARAMS_NODE, &no_link_params_ava_bw_cmd);
	install_element(LINK_PARAMS_NODE, &link_params_res_bw_cmd);
	install_element(LINK_PARAMS_NODE, &no_link_params_res_bw_cmd);
	install_element(LINK_PARAMS_NODE, &link_params_use_bw_cmd);
	install_element(LINK_PARAMS_NODE, &no_link_params_use_bw_cmd);
	install_element(LINK_PARAMS_NODE, &exit_link_params_cmd);
}
