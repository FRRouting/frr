// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Interface function.
 * Copyright (C) 1997, 1999 Kunihiro Ishiguro
 */

#include <zebra.h>

#include "if.h"
#include "lib_errors.h"
#include "vty.h"
#include "sockunion.h"
#include "prefix.h"
#include "command.h"
#include "memory.h"
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
#include "zebra/zebra_vxlan.h"
#include "zebra/zebra_errors.h"
#include "zebra/zebra_evpn_mh.h"

DEFINE_MTYPE_STATIC(ZEBRA, ZINFO, "Zebra Interface Information");

#define ZEBRA_PTM_SUPPORT

DEFINE_HOOK(zebra_if_extra_info, (struct vty * vty, struct interface *ifp),
	    (vty, ifp));

DEFINE_MTYPE(ZEBRA, ZIF_DESC, "Intf desc");

static void if_down_del_nbr_connected(struct interface *ifp);

static void if_zebra_speed_update(struct event *thread)
{
	struct interface *ifp = EVENT_ARG(thread);
	struct zebra_if *zif = ifp->info;
	uint32_t new_speed;
	bool changed = false;
	int error = 0;

	new_speed = kernel_get_speed(ifp, &error);

	/* error may indicate vrf not available or
	 * interfaces not available.
	 * note that loopback & virtual interfaces can return 0 as speed
	 */
	if (error == INTERFACE_SPEED_ERROR_READ)
		return;

	if (new_speed != ifp->speed) {
		zlog_info("%s: %s old speed: %u new speed: %u", __func__,
			  ifp->name, ifp->speed, new_speed);
		ifp->speed = new_speed;
		if_add_update(ifp);
		changed = true;
	}

	if (changed || error == INTERFACE_SPEED_ERROR_UNKNOWN) {
#define SPEED_UPDATE_SLEEP_TIME 5
#define SPEED_UPDATE_COUNT_MAX (4 * 60 / SPEED_UPDATE_SLEEP_TIME)
		/*
		 * Some interfaces never actually have an associated speed
		 * with them ( I am looking at you bridges ).
		 * So instead of iterating forever, let's give the
		 * system 4 minutes to try to figure out the speed
		 * if after that it it's probably never going to become
		 * useful.
		 * Since I don't know all the wonderful types of interfaces
		 * that may come into existence in the future I am going
		 * to not update the system to keep track of that.  This
		 * is far simpler to just stop trying after 4 minutes
		 */
		if (error == INTERFACE_SPEED_ERROR_UNKNOWN &&
		    zif->speed_update_count == SPEED_UPDATE_COUNT_MAX)
			return;

		zif->speed_update_count++;
		event_add_timer(zrouter.master, if_zebra_speed_update, ifp,
				SPEED_UPDATE_SLEEP_TIME, &zif->speed_update);
		event_ignore_late_timer(zif->speed_update);
	}
}

static void zebra_if_node_destroy(route_table_delegate_t *delegate,
				  struct route_table *table,
				  struct route_node *node)
{
	if (node->info)
		list_delete((struct list **)&node->info);
	route_node_destroy(delegate, table, node);
}

route_table_delegate_t zebra_if_table_delegate = {
	.create_node = route_node_create,
	.destroy_node = zebra_if_node_destroy};

/* Called when new interface is added. */
static int if_zebra_new_hook(struct interface *ifp)
{
	struct zebra_if *zebra_if;

	zebra_if = XCALLOC(MTYPE_ZINFO, sizeof(struct zebra_if));
	zebra_if->ifp = ifp;

	zebra_if->multicast = IF_ZEBRA_DATA_UNSPEC;
	zebra_if->mpls_config = IF_ZEBRA_DATA_UNSPEC;
	zebra_if->shutdown = IF_ZEBRA_DATA_UNSPEC;

	zebra_if->link_nsid = NS_UNKNOWN;

	nhg_connected_tree_init(&zebra_if->nhg_dependents);

	zebra_ptm_if_init(zebra_if);

	ifp->ptm_enable = zebra_ptm_get_enable_state();

	rtadv_if_init(zebra_if);

	zebra_evpn_mh_if_init(zebra_if);

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
	zebra_if->speed_update_count = 0;
	event_add_timer(zrouter.master, if_zebra_speed_update, ifp, 15,
			&zebra_if->speed_update);
	event_ignore_late_timer(zebra_if->speed_update);

	return 0;
}

static void if_down_nhg_dependents(const struct interface *ifp)
{
	struct nhg_connected *rb_node_dep = NULL;
	struct zebra_if *zif = (struct zebra_if *)ifp->info;

	frr_each(nhg_connected_tree, &zif->nhg_dependents, rb_node_dep)
		zebra_nhg_check_valid(rb_node_dep->nhe);
}

static void if_nhg_dependents_release(const struct interface *ifp)
{
	struct nhg_connected *rb_node_dep = NULL;
	struct zebra_if *zif = (struct zebra_if *)ifp->info;

	frr_each(nhg_connected_tree, &zif->nhg_dependents, rb_node_dep) {
		rb_node_dep->nhe->ifp = NULL; /* Null it out */
		zebra_nhg_check_valid(rb_node_dep->nhe);
		if (CHECK_FLAG(rb_node_dep->nhe->flags,
			       NEXTHOP_GROUP_KEEP_AROUND) &&
		    rb_node_dep->nhe->refcnt == 1)
			zebra_nhg_decrement_ref(rb_node_dep->nhe);
	}
}

/* Called when interface is deleted. */
static int if_zebra_delete_hook(struct interface *ifp)
{
	struct zebra_if *zebra_if;
	struct zebra_l2info_bond *bond;

	if (ifp->info) {
		zebra_if = ifp->info;

		/* If we set protodown, clear our reason now from the kernel */
		if (ZEBRA_IF_IS_PROTODOWN(zebra_if) && zebra_if->protodown_rc &&
		    !ZEBRA_IF_IS_PROTODOWN_ONLY_EXTERNAL(zebra_if))
			zebra_if_update_protodown_rc(ifp, true,
						     (zebra_if->protodown_rc &
						      ~ZEBRA_PROTODOWN_ALL));

		/* Free installed address chains tree. */
		if (zebra_if->ipv4_subnets)
			route_table_finish(zebra_if->ipv4_subnets);

		rtadv_if_fini(zebra_if);

		bond = &zebra_if->bond_info;
		if (bond && bond->mbr_zifs)
			list_delete(&bond->mbr_zifs);

		zebra_l2_bridge_if_cleanup(ifp);
		zebra_evpn_if_cleanup(zebra_if);
		zebra_evpn_mac_ifp_del(ifp);

		if_nhg_dependents_release(ifp);
		nhg_connected_tree_free(&zebra_if->nhg_dependents);

		XFREE(MTYPE_ZIF_DESC, zebra_if->desc);

		EVENT_OFF(zebra_if->speed_update);

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
	if (!ifp->node)
		return;

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

struct interface *if_lookup_by_index_per_nsid(ns_id_t ns_id, uint32_t ifindex)
{
	struct zebra_ns *zns;

	zns = zebra_ns_lookup(ns_id);
	return zns ? if_lookup_by_index_per_ns(zns, ifindex) : NULL;
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
			  "Trying to remove an address from an unknown subnet. (please report this bug)");
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
			"Trying to remove an address from a subnet where it is not currently registered. (please report this bug)");
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
	return;
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
			if_up(ifp, true);
	}
}

/* Wake up configured address if it is not in current kernel
   address. */
void if_addr_wakeup(struct interface *ifp)
{
	struct connected *ifc;
	struct prefix *p;
	enum zebra_dplane_result dplane_res;

	frr_each_safe (if_connected, ifp->connected, ifc) {
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
	struct zebra_vrf *zvrf = ifp->vrf->info;

	/* case interface populate before vrf enabled */
	if (zvrf->zns)
		zns = zvrf->zns;
	else
		zns = zebra_ns_lookup(NS_DEFAULT);
	if_link_per_ns(zns, ifp);
	if_data = ifp->info;
	assert(if_data);

	if (if_data->multicast == IF_ZEBRA_DATA_ON)
		if_set_flags(ifp, IFF_MULTICAST);
	else if (if_data->multicast == IF_ZEBRA_DATA_OFF)
		if_unset_flags(ifp, IFF_MULTICAST);

	zebra_ptm_if_set_ptm_state(ifp, if_data);

	zebra_interface_add_update(ifp);

	if (!CHECK_FLAG(ifp->status, ZEBRA_INTERFACE_ACTIVE)) {
		SET_FLAG(ifp->status, ZEBRA_INTERFACE_ACTIVE);

		if (if_data->shutdown == IF_ZEBRA_DATA_ON) {
			if (IS_ZEBRA_DEBUG_KERNEL) {
				zlog_debug(
					"interface %s vrf %s(%u) index %d is shutdown. Won't wake it up.",
					ifp->name, ifp->vrf->name,
					ifp->vrf->vrf_id, ifp->ifindex);
			}

			return;
		}

		if_addr_wakeup(ifp);

		if (if_data->mpls_config == IF_ZEBRA_DATA_ON)
			dplane_intf_mpls_modify_state(ifp, true);
		else if (if_data->mpls_config == IF_ZEBRA_DATA_OFF)
			dplane_intf_mpls_modify_state(ifp, false);

		if (IS_ZEBRA_DEBUG_KERNEL)
			zlog_debug(
				"interface %s vrf %s(%u) index %d becomes active.",
				ifp->name, ifp->vrf->name, ifp->vrf->vrf_id,
				ifp->ifindex);

	} else {
		if (IS_ZEBRA_DEBUG_KERNEL)
			zlog_debug("interface %s vrf %s(%u) index %d is added.",
				   ifp->name, ifp->vrf->name, ifp->vrf->vrf_id,
				   ifp->ifindex);
	}
}

/* Install connected routes corresponding to an interface. */
static void if_install_connected(struct interface *ifp)
{
	struct connected *ifc;

	frr_each (if_connected, ifp->connected, ifc) {
		if (CHECK_FLAG(ifc->conf, ZEBRA_IFC_REAL))
			zebra_interface_address_add_update(ifp, ifc);

		connected_up(ifp, ifc);
	}
}

/* Uninstall connected routes corresponding to an interface. */
static void if_uninstall_connected(struct interface *ifp)
{
	struct connected *ifc;

	frr_each_safe (if_connected, ifp->connected, ifc) {
		zebra_interface_address_delete_update(ifp, ifc);
		connected_down(ifp, ifc);
	}
}

/* Uninstall and delete connected routes corresponding to an interface. */
/* TODO - Check why IPv4 handling here is different from install or if_down */
static void if_delete_connected(struct interface *ifp)
{
	struct connected *ifc, *ifc_next;
	struct prefix cp;
	struct route_node *rn;
	struct zebra_if *zebra_if;

	zebra_if = ifp->info;

	for (ifc = if_connected_first(ifp->connected); ifc; ifc = ifc_next) {
		ifc_next = if_connected_next(ifp->connected, ifc);

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
						if (ifc == ifc_next)
							ifc_next = if_connected_next(
								ifp->connected,
								ifc);

						if_connected_del(ifp->connected,
								 ifc);
						connected_free(&ifc);
					}
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

			if (!CHECK_FLAG(ifc->conf, ZEBRA_IFC_CONFIGURED)) {
				if_connected_del(ifp->connected, ifc);
				connected_free(&ifc);
			}
		}
	}
}

/* Handle an interface delete event */
void if_delete_update(struct interface **pifp)
{
	struct zebra_if *zif;
	struct interface *ifp = *pifp;

	if (if_is_up(ifp)) {
		flog_err(
			EC_LIB_INTERFACE,
			"interface %s vrf %s(%u) index %d is still up while being deleted.",
			ifp->name, ifp->vrf->name, ifp->vrf->vrf_id,
			ifp->ifindex);
		return;
	}

	if (!CHECK_FLAG(ifp->status, ZEBRA_INTERFACE_ACTIVE))
		return;

	/* Mark interface as inactive */
	UNSET_FLAG(ifp->status, ZEBRA_INTERFACE_ACTIVE);

	if (IS_ZEBRA_DEBUG_KERNEL)
		zlog_debug("interface %s vrf %s(%u) index %d is now inactive.",
			   ifp->name, ifp->vrf->name, ifp->vrf->vrf_id,
			   ifp->ifindex);

	/* Delete connected routes from the kernel. */
	if_delete_connected(ifp);

	/* if the ifp is in a vrf, move it to default so vrf can be deleted if
	 * desired. This operation is not done for netns implementation to avoid
	 * collision with interface with the same name in the default vrf (can
	 * occur with this implementation whereas it is not possible with
	 * vrf-lite).
	 */
	if (ifp->vrf->vrf_id && !vrf_is_backend_netns())
		if_handle_vrf_change(ifp, VRF_DEFAULT);

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

	UNSET_FLAG(ifp->status, ZEBRA_INTERFACE_VRF_LOOPBACK);

	/* Reset some zebra interface params to default values. */
	zif = ifp->info;
	if (zif) {
		zebra_evpn_if_cleanup(zif);
		zif->zif_type = ZEBRA_IF_OTHER;
		zif->zif_slave_type = ZEBRA_IF_SLAVE_NONE;
		memset(&zif->l2info, 0, sizeof(union zebra_l2if_info));
		memset(&zif->brslave_info, 0,
		       sizeof(struct zebra_l2info_brslave));
		zebra_evpn_mac_ifp_del(ifp);
	}

	if (!ifp->configured) {
		if (IS_ZEBRA_DEBUG_KERNEL)
			zlog_debug("interface %s is being deleted from the system",
				   ifp->name);
		if_delete(pifp);
	}
}

/* VRF change for an interface */
void if_handle_vrf_change(struct interface *ifp, vrf_id_t vrf_id)
{
	vrf_id_t old_vrf_id;

	old_vrf_id = ifp->vrf->vrf_id;

	/* Uninstall connected routes. */
	if_uninstall_connected(ifp);

	/* Delete any IPv4 neighbors created to implement RFC 5549 */
	if_nbr_ipv6ll_to_ipv4ll_neigh_del_all(ifp);

	/* Delete all neighbor addresses learnt through IPv6 RA */
	if_down_del_nbr_connected(ifp);

	/* Send out notification on interface VRF change. */
	/* This is to issue a DELETE, as appropriate. */
	zebra_interface_vrf_update_del(ifp, vrf_id);

	if (if_is_vrf(ifp))
		return;

	/* update VRF */
	if_update_to_new_vrf(ifp, vrf_id);

	/* Send out notification on interface VRF change. */
	/* This is to issue an ADD, if needed. */
	zebra_interface_vrf_update_add(ifp, old_vrf_id);
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
	struct zebra_vrf *zvrf = ifp->vrf->info;
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
	kernel_neigh_update(0, ifp->ifindex, (void *)&ipv4_ll.s_addr, mac, 6,
			    ns_id, AF_INET, true);

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
		kernel_neigh_update(add, ifp->ifindex, (void *)&ipv4_ll.s_addr,
				    mac, 6, ns_id, AF_INET, true);

	memcpy(&zif->neigh_mac[0], &mac[0], 6);

	/*
	 * We need to note whether or not we originated a v6
	 * neighbor entry for this interface.  So that when
	 * someone unwisely accidentally deletes this entry
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

/* Interface is up. */
void if_up(struct interface *ifp, bool install_connected)
{
	struct zebra_if *zif;
	struct interface *link_if;

	zif = ifp->info;
	zif->up_count++;
	frr_timestamp(2, zif->up_last, sizeof(zif->up_last));

	/* Notify the protocol daemons. */
	if (ifp->ptm_enable && (ifp->ptm_status == ZEBRA_PTM_STATUS_DOWN)) {
		flog_warn(EC_ZEBRA_PTM_NOT_READY,
			  "%s: interface %s hasn't passed ptm check",
			  __func__, ifp->name);
		return;
	}
	zebra_interface_up_update(ifp);

	if_nbr_ipv6ll_to_ipv4ll_neigh_add_all(ifp);

	rtadv_if_up(zif);

	/* Install connected routes to the kernel. */
	if (install_connected)
		if_install_connected(ifp);

	/*
	 * Interface associated NHG's have been deleted on
	 * interface down events, now that this interface
	 * is coming back up, let's resync the zebra -> dplane
	 * nhg's so that they can be continued to be used.
	 */
	zebra_interface_nhg_reinstall(ifp);

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
		link_if = zif->link;
		if (link_if)
			zebra_vxlan_svi_up(ifp, link_if);
	} else if (IS_ZEBRA_IF_MACVLAN(ifp)) {
		zebra_vxlan_macvlan_up(ifp);
	}

	if (zif->es_info.es)
		zebra_evpn_es_if_oper_state_change(zif, true /*up*/);

	if (zif->flags & ZIF_FLAG_EVPN_MH_UPLINK)
		zebra_evpn_mh_uplink_oper_update(zif);

	event_add_timer(zrouter.master, if_zebra_speed_update, ifp, 0,
			&zif->speed_update);
	event_ignore_late_timer(zif->speed_update);

	if_addr_wakeup(ifp);
}

/* Interface goes down.  We have to manage different behavior of based
   OS. */
void if_down(struct interface *ifp)
{
	struct zebra_if *zif;
	struct interface *link_if;

	zif = ifp->info;
	zif->down_count++;
	frr_timestamp(2, zif->down_last, sizeof(zif->down_last));

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
		link_if = zif->link;
		if (link_if)
			zebra_vxlan_svi_down(ifp, link_if);
	} else if (IS_ZEBRA_IF_MACVLAN(ifp)) {
		zebra_vxlan_macvlan_down(ifp);
	}

	if (zif->es_info.es)
		zebra_evpn_es_if_oper_state_change(zif, false /*up*/);

	if (zif->flags & ZIF_FLAG_EVPN_MH_UPLINK)
		zebra_evpn_mh_uplink_oper_update(zif);

	/* Notify to the protocol daemons. */
	zebra_interface_down_update(ifp);

	/* Uninstall connected routes from the kernel. */
	if_uninstall_connected(ifp);

	if_nbr_ipv6ll_to_ipv4ll_neigh_del_all(ifp);

	/* Delete all neighbor addresses learnt through IPv6 RA */
	if_down_del_nbr_connected(ifp);

	rib_update_handle_vrf_all(RIB_UPDATE_INTERFACE_DOWN, ZEBRA_ROUTE_KERNEL);
}

void if_refresh(struct interface *ifp)
{
#ifndef GNU_LINUX
	if_get_flags(ifp);
#endif
}

void zebra_if_update_link(struct interface *ifp, ifindex_t link_ifindex,
			  ns_id_t ns_id)
{
	struct zebra_if *zif;

	zif = (struct zebra_if *)ifp->info;
	zif->link_nsid = ns_id;
	zif->link_ifindex = link_ifindex;
	zif->link = if_lookup_by_index_per_ns(zebra_ns_lookup(ns_id),
					      link_ifindex);
}

/*
 * during initial link dump kernel does not order lower devices before
 * upper devices so we need to fixup link dependencies at the end of dump
 */
void zebra_if_update_all_links(struct zebra_ns *zns)
{
	struct route_node *rn;
	struct interface *ifp;
	struct zebra_if *zif;

	if (IS_ZEBRA_DEBUG_KERNEL)
		zlog_info("fixup link dependencies");

	for (rn = route_top(zns->if_table); rn; rn = route_next(rn)) {
		ifp = (struct interface *)rn->info;
		if (!ifp)
			continue;
		zif = ifp->info;
		/* update bond-member to bond linkages */
		if ((IS_ZEBRA_IF_BOND_SLAVE(ifp))
		    && (zif->bondslave_info.bond_ifindex != IFINDEX_INTERNAL)
		    && !zif->bondslave_info.bond_if) {
			if (IS_ZEBRA_DEBUG_EVPN_MH_ES || IS_ZEBRA_DEBUG_KERNEL)
				zlog_debug("bond mbr %s map to bond %d",
					   zif->ifp->name,
					   zif->bondslave_info.bond_ifindex);
			zebra_l2_map_slave_to_bond(zif, ifp->vrf->vrf_id);
		}

		/* update SVI linkages */
		if ((zif->link_ifindex != IFINDEX_INTERNAL) && !zif->link) {
			zif->link = if_lookup_by_index_per_nsid(
				zif->link_nsid, zif->link_ifindex);
			if (IS_ZEBRA_DEBUG_KERNEL)
				zlog_debug("interface %s/%d's lower fixup to %s/%d",
						ifp->name, ifp->ifindex,
						zif->link?zif->link->name:"unk",
						zif->link_ifindex);
		}

		/* Update VLAN<=>SVI map */
		if (IS_ZEBRA_IF_VLAN(ifp))
			zebra_evpn_acc_bd_svi_set(zif, NULL,
						  !!if_is_operative(ifp));
	}
}

static bool if_ignore_set_protodown(const struct interface *ifp, bool new_down,
				    uint32_t new_protodown_rc)
{
	struct zebra_if *zif;
	bool old_down, old_set_down, old_unset_down;

	zif = ifp->info;

	/*
	 * FRR does not have enough data to make this request
	 */
	if (ifp->ifindex == IFINDEX_INTERNAL)
		return true;

	/* Current state as we know it */
	old_down = !!(ZEBRA_IF_IS_PROTODOWN(zif));
	old_set_down = !!CHECK_FLAG(zif->flags, ZIF_FLAG_SET_PROTODOWN);
	old_unset_down = !!CHECK_FLAG(zif->flags, ZIF_FLAG_UNSET_PROTODOWN);

	if (new_protodown_rc == zif->protodown_rc) {
		/* Early return if already down & reason bitfield matches */
		if (new_down == old_down) {
			if (IS_ZEBRA_DEBUG_KERNEL)
				zlog_debug(
					"Ignoring request to set protodown %s for interface %s (%u): protodown %s is already set (reason bitfield: old 0x%x new 0x%x)",
					new_down ? "on" : "off", ifp->name,
					ifp->ifindex, new_down ? "on" : "off",
					zif->protodown_rc, new_protodown_rc);

			return true;
		}

		/* Early return if already set queued & reason bitfield matches
		 */
		if (new_down && old_set_down) {
			if (IS_ZEBRA_DEBUG_KERNEL)
				zlog_debug(
					"Ignoring request to set protodown %s for interface %s (%u): protodown %s is already queued to dplane (reason bitfield: old 0x%x new 0x%x)",
					new_down ? "on" : "off", ifp->name,
					ifp->ifindex, new_down ? "on" : "off",
					zif->protodown_rc, new_protodown_rc);

			return true;
		}

		/* Early return if already unset queued & reason bitfield
		 * matches */
		if (!new_down && old_unset_down) {
			if (IS_ZEBRA_DEBUG_KERNEL)
				zlog_debug(
					"Ignoring request to set protodown %s for interface %s (%u): protodown %s is already queued to dplane (reason bitfield: old 0x%x new 0x%x)",
					new_down ? "on" : "off", ifp->name,
					ifp->ifindex, new_down ? "on" : "off",
					zif->protodown_rc, new_protodown_rc);

			return true;
		}
	}

	return false;
}

int zebra_if_update_protodown_rc(struct interface *ifp, bool new_down,
				 uint32_t new_protodown_rc)
{
	struct zebra_if *zif;

	zif = ifp->info;

	/* Check if we already have this state or it's queued */
	if (if_ignore_set_protodown(ifp, new_down, new_protodown_rc))
		return 1;

	zlog_info(
		"Setting protodown %s - interface %s (%u): reason bitfield change from 0x%x --> 0x%x",
		new_down ? "on" : "off", ifp->name, ifp->ifindex,
		zif->protodown_rc, new_protodown_rc);

	zif->protodown_rc = new_protodown_rc;

	if (new_down)
		SET_FLAG(zif->flags, ZIF_FLAG_SET_PROTODOWN);
	else
		SET_FLAG(zif->flags, ZIF_FLAG_UNSET_PROTODOWN);

#ifdef HAVE_NETLINK
	dplane_intf_update(ifp);
#else
	zlog_warn("Protodown is not supported on this platform");
#endif
	return 0;
}

int zebra_if_set_protodown(struct interface *ifp, bool new_down,
			   enum protodown_reasons new_reason)
{
	struct zebra_if *zif;
	uint32_t new_protodown_rc;

	zif = ifp->info;

	if (new_down)
		new_protodown_rc = zif->protodown_rc | new_reason;
	else
		new_protodown_rc = zif->protodown_rc & ~new_reason;

	return zebra_if_update_protodown_rc(ifp, new_down, new_protodown_rc);
}

/*
 * Handle an interface events based on info in a dplane context object.
 * This runs in the main pthread, using the info in the context object to
 * modify an interface.
 */
static void zebra_if_addr_update_ctx(struct zebra_dplane_ctx *ctx,
				     struct interface *ifp)
{
	uint8_t flags = 0;
	const char *label = NULL;
	uint32_t metric = METRIC_MAX;
	const struct prefix *addr, *dest = NULL;
	enum dplane_op_e op;

	if (!ifp)
		return;

	op = dplane_ctx_get_op(ctx);
	addr = dplane_ctx_get_intf_addr(ctx);

	if (IS_ZEBRA_DEBUG_KERNEL)
		zlog_debug("%s: %s: ifindex %s(%u), addr %pFX", __func__,
			   dplane_op2str(dplane_ctx_get_op(ctx)), ifp->name,
			   ifp->ifindex, addr);

	/* Is there a peer or broadcast address? */
	dest = dplane_ctx_get_intf_dest(ctx);
	if (dest->prefixlen == 0)
		dest = NULL;

	if (dplane_ctx_intf_is_connected(ctx))
		SET_FLAG(flags, ZEBRA_IFA_PEER);

	/* Flags. */
	if (dplane_ctx_intf_is_secondary(ctx))
		SET_FLAG(flags, ZEBRA_IFA_SECONDARY);

	if (dplane_ctx_intf_is_noprefixroute(ctx))
		SET_FLAG(flags, ZEBRA_IFA_NOPREFIXROUTE);

	/* Label? */
	if (dplane_ctx_intf_has_label(ctx))
		label = dplane_ctx_get_intf_label(ctx);

	if (label && strcmp(ifp->name, label) == 0)
		label = NULL;

	metric = dplane_ctx_get_intf_metric(ctx);

	/* Register interface address to the interface. */
	if (addr->family == AF_INET) {
		if (op == DPLANE_OP_INTF_ADDR_ADD)
			connected_add_ipv4(
				ifp, flags, &addr->u.prefix4, addr->prefixlen,
				dest ? &dest->u.prefix4 : NULL, label, metric);
		else if (CHECK_FLAG(flags, ZEBRA_IFA_PEER)) {
			/* Delete with a peer address */
			connected_delete_ipv4(ifp, flags, &addr->u.prefix4,
					      addr->prefixlen,
					      &dest->u.prefix4);
		} else
			connected_delete_ipv4(ifp, flags, &addr->u.prefix4,
					      addr->prefixlen, NULL);
	}

	if (addr->family == AF_INET6) {
		if (op == DPLANE_OP_INTF_ADDR_ADD) {
			connected_add_ipv6(ifp, flags, &addr->u.prefix6,
					   dest ? &dest->u.prefix6 : NULL,
					   addr->prefixlen, label, metric);
		} else
			connected_delete_ipv6(ifp, &addr->u.prefix6, NULL,
					      addr->prefixlen);
	}

	/*
	 * Linux kernel does not send route delete on interface down/addr del
	 * so we have to re-process routes it owns (i.e. kernel routes)
	 */
	if (op != DPLANE_OP_INTF_ADDR_ADD)
		rib_update(RIB_UPDATE_KERNEL);
}

static void zebra_if_update_ctx(struct zebra_dplane_ctx *ctx,
				struct interface *ifp)
{
	enum zebra_dplane_result dp_res;
	struct zebra_if *zif;
	bool pd_reason_val;
	bool down;

	if (!ifp) {
		if (IS_ZEBRA_DEBUG_KERNEL)
			zlog_debug("%s: Can't find ifp", __func__);

		return;
	}

	dp_res = dplane_ctx_get_status(ctx);
	pd_reason_val = dplane_ctx_get_intf_pd_reason_val(ctx);
	down = dplane_ctx_intf_is_protodown(ctx);

	if (IS_ZEBRA_DEBUG_KERNEL)
		zlog_debug("%s: %s: if %s(%u) ctx-protodown %s ctx-reason %d",
			   __func__, dplane_op2str(dplane_ctx_get_op(ctx)),
			   ifp->name, ifp->ifindex, down ? "on" : "off",
			   pd_reason_val);

	zif = ifp->info;
	if (!zif) {
		if (IS_ZEBRA_DEBUG_KERNEL)
			zlog_debug("%s: if %s(%u) zebra info pointer is NULL",
				   __func__, ifp->name, ifp->ifindex);
		return;
	}

	if (dp_res != ZEBRA_DPLANE_REQUEST_SUCCESS) {
		if (IS_ZEBRA_DEBUG_KERNEL)
			zlog_debug("%s: if %s(%u) dplane update failed",
				   __func__, ifp->name, ifp->ifindex);
		goto done;
	}

	/* Update our info */
	COND_FLAG(zif->flags, ZIF_FLAG_PROTODOWN, down);

done:
	/* Clear our dplane flags */
	UNSET_FLAG(zif->flags, ZIF_FLAG_SET_PROTODOWN);
	UNSET_FLAG(zif->flags, ZIF_FLAG_UNSET_PROTODOWN);
}

/*
 * Handle netconf change from a dplane context object; runs in the main
 * pthread so it can update zebra data structs.
 */
static void zebra_if_netconf_update_ctx(struct zebra_dplane_ctx *ctx,
					struct interface *ifp,
					ifindex_t ifindex)
{
	struct zebra_if *zif = NULL;
	afi_t afi;
	enum dplane_netconf_status_e mpls, mcast_on, linkdown;
	bool *mcast_set, *linkdown_set;

	if (!ifp && ifindex != -1 && ifindex != -2) {
		if (IS_ZEBRA_DEBUG_KERNEL)
			zlog_debug("%s: Can't find ifp(%u)", __func__, ifindex);

		return;
	}

	afi = dplane_ctx_get_afi(ctx);
	mpls = dplane_ctx_get_netconf_mpls(ctx);
	linkdown = dplane_ctx_get_netconf_linkdown(ctx);
	mcast_on = dplane_ctx_get_netconf_mcast(ctx);

	if (ifindex == DPLANE_NETCONF_IFINDEX_ALL) {
		if (afi == AFI_IP) {
			mcast_set = &zrouter.all_mc_forwardingv4;
			linkdown_set = &zrouter.all_linkdownv4;
		} else {
			mcast_set = &zrouter.all_mc_forwardingv6;
			linkdown_set = &zrouter.all_linkdownv6;
		}
	} else if (ifindex == DPLANE_NETCONF_IFINDEX_DEFAULT) {
		if (afi == AFI_IP) {
			mcast_set = &zrouter.default_mc_forwardingv4;
			linkdown_set = &zrouter.default_linkdownv4;
		} else {
			mcast_set = &zrouter.default_mc_forwardingv6;
			linkdown_set = &zrouter.default_linkdownv6;
		}
	} else {
		zif = ifp->info;
		if (!zif) {
			if (IS_ZEBRA_DEBUG_KERNEL)
				zlog_debug(
					"%s: if %s(%u) zebra info pointer is NULL",
					__func__, ifp ? ifp->name : "(null)",
					ifp ? ifp->ifindex : ifindex);
			return;
		}
		if (afi == AFI_IP) {
			mcast_set = &zif->v4mcast_on;
			linkdown_set = &zif->linkdown;
		} else {
			mcast_set = &zif->v6mcast_on;
			linkdown_set = &zif->linkdownv6;
		}

		/*
		 * mpls netconf data is neither v4 or v6 it's AF_MPLS!
		 */
		if (mpls == DPLANE_NETCONF_STATUS_ENABLED) {
			zif->mpls = true;
			zebra_mpls_turned_on();
		} else if (mpls == DPLANE_NETCONF_STATUS_DISABLED)
			zif->mpls = false;
	}

	if (linkdown == DPLANE_NETCONF_STATUS_ENABLED)
		*linkdown_set = true;
	else if (linkdown == DPLANE_NETCONF_STATUS_DISABLED)
		*linkdown_set = false;

	if (mcast_on == DPLANE_NETCONF_STATUS_ENABLED)
		*mcast_set = true;
	else if (mcast_on == DPLANE_NETCONF_STATUS_DISABLED)
		*mcast_set = false;

	if (IS_ZEBRA_DEBUG_KERNEL)
		zlog_debug(
			"%s: afi: %d if %s, ifindex %d, mpls %s mc_forwarding: %s linkdown %s",
			__func__, afi, ifp ? ifp->name : "Global",
			ifp ? ifp->ifindex : ifindex,
			(zif ? (zif->mpls ? "ON" : "OFF") : "OFF"),
			(*mcast_set ? "ON" : "OFF"),
			(*linkdown_set ? "ON" : "OFF"));
}

static void interface_vrf_change(enum dplane_op_e op, ifindex_t ifindex,
				 const char *name, uint32_t tableid,
				 ns_id_t ns_id)
{
	struct vrf *vrf;
	struct zebra_vrf *zvrf = NULL;

	if (op == DPLANE_OP_INTF_DELETE) {
		if (IS_ZEBRA_DEBUG_DPLANE)
			zlog_debug("DPLANE_OP_INTF_DELETE for VRF %s(%u)", name,
				   ifindex);

		vrf = vrf_lookup_by_id((vrf_id_t)ifindex);
		if (!vrf) {
			flog_warn(EC_ZEBRA_VRF_NOT_FOUND,
				  "%s(%u): vrf not found", name, ifindex);
			return;
		}

		vrf_delete(vrf);
	} else {
		if (IS_ZEBRA_DEBUG_DPLANE)
			zlog_debug(
				"DPLANE_OP_INTF_UPDATE for VRF %s(%u) table %u",
				name, ifindex, tableid);

		/*
		 * For a given tableid, if there already exists a vrf and it
		 * is different from the current vrf to be operated, then there
		 * is a misconfiguration and zebra will exit.
		 */
		vrf_id_t exist_id = zebra_vrf_lookup_by_table(tableid, ns_id);

		if (exist_id != VRF_DEFAULT) {
			vrf = vrf_lookup_by_id(exist_id);

			if (!vrf_lookup_by_id((vrf_id_t)ifindex) && !vrf) {
				flog_err(EC_ZEBRA_VRF_NOT_FOUND,
					 "VRF %s id %u does not exist", name,
					 ifindex);
				exit(-1);
			}

			if (vrf && strcmp(name, vrf->name)) {
				flog_err(EC_ZEBRA_VRF_MISCONFIGURED,
					 "VRF %s id %u table id overlaps existing vrf %s(%d), misconfiguration exiting",
					 name, ifindex, vrf->name, vrf->vrf_id);
				exit(-1);
			}
		}

		vrf = vrf_update((vrf_id_t)ifindex, name);
		if (!vrf) {
			flog_err(EC_LIB_INTERFACE, "VRF %s id %u not created",
				 name, ifindex);
			return;
		}

		/*
		 * This is the only place that we get the actual kernel table_id
		 * being used.  We need it to set the table_id of the routes
		 * we are passing to the kernel.... And to throw some totally
		 * awesome parties. that too.
		 *
		 * At this point we *must* have a zvrf because the vrf_create
		 * callback creates one.  We *must* set the table id
		 * before the vrf_enable because of( at the very least )
		 * static routes being delayed for installation until
		 * during the vrf_enable callbacks.
		 */
		zvrf = (struct zebra_vrf *)vrf->info;
		zvrf->table_id = tableid;

		/* Enable the created VRF. */
		if (!vrf_enable(vrf)) {
			flog_err(EC_LIB_INTERFACE,
				 "Failed to enable VRF %s id %u", name,
				 ifindex);
			return;
		}
	}
}

/*
 *  Note: on netlink systems, there should be a 1-to-1 mapping
 * between interface names and ifindex values.
 */
static void set_ifindex(struct interface *ifp, ifindex_t ifi_index,
			struct zebra_ns *zns)
{
	struct interface *oifp;

	oifp = if_lookup_by_index_per_ns(zns, ifi_index);
	if ((oifp != NULL) && (oifp != ifp)) {
		if (ifi_index == IFINDEX_INTERNAL)
			flog_err(
				EC_LIB_INTERFACE,
				"Netlink is setting interface %s ifindex to reserved internal value %u",
				ifp->name, ifi_index);
		else {
			if (IS_ZEBRA_DEBUG_KERNEL)
				zlog_debug(
					"interface index %d was renamed from %s to %s",
					ifi_index, oifp->name, ifp->name);
			if (if_is_up(oifp))
				flog_err(
					EC_LIB_INTERFACE,
					"interface rename detected on up interface: index %d was renamed from %s to %s, results are uncertain!",
					ifi_index, oifp->name, ifp->name);
			if_delete_update(&oifp);
		}
	}
	if_set_index(ifp, ifi_index);
}

static inline void zebra_if_set_ziftype(struct interface *ifp,
					enum zebra_iftype zif_type,
					enum zebra_slave_iftype zif_slave_type)
{
	struct zebra_if *zif;

	zif = (struct zebra_if *)ifp->info;
	zif->zif_slave_type = zif_slave_type;

	if (zif->zif_type != zif_type) {
		zif->zif_type = zif_type;
		/* If the if_type has been set to bond initialize ES info
		 * against it. XXX - note that we don't handle the case where
		 * a zif changes from bond to non-bond; it is really
		 * an unexpected/error condition.
		 */
		zebra_evpn_if_init(zif);
	}
}

static void interface_update_hw_addr(struct zebra_dplane_ctx *ctx,
				     struct interface *ifp)
{
	int i;

	ifp->hw_addr_len = dplane_ctx_get_ifp_hw_addr_len(ctx);
	memcpy(ifp->hw_addr, dplane_ctx_get_ifp_hw_addr(ctx), ifp->hw_addr_len);

	for (i = 0; i < ifp->hw_addr_len; i++)
		if (ifp->hw_addr[i] != 0)
			break;

	if (i == ifp->hw_addr_len)
		ifp->hw_addr_len = 0;
}

static void interface_update_l2info(struct zebra_dplane_ctx *ctx,
				    struct interface *ifp,
				    enum zebra_iftype zif_type, int add,
				    ns_id_t link_nsid)
{
	const struct zebra_l2info_vxlan *vxlan_info;
	const struct zebra_l2info_gre *gre_info;

	switch (zif_type) {
	case ZEBRA_IF_BRIDGE:
		zebra_l2_bridge_add_update(ifp,
					   dplane_ctx_get_ifp_bridge_info(ctx));
		break;
	case ZEBRA_IF_VLAN:
		zebra_l2_vlanif_update(ifp, dplane_ctx_get_ifp_vlan_info(ctx));
		zebra_evpn_acc_bd_svi_set(ifp->info, NULL,
					  !!if_is_operative(ifp));
		break;
	case ZEBRA_IF_VXLAN:
		vxlan_info = dplane_ctx_get_ifp_vxlan_info(ctx);
		zebra_l2_vxlanif_add_update(ifp, vxlan_info, add);
		if (link_nsid != NS_UNKNOWN && vxlan_info->ifindex_link)
			zebra_if_update_link(ifp, vxlan_info->ifindex_link,
					     link_nsid);
		break;
	case ZEBRA_IF_GRE:
		gre_info = dplane_ctx_get_ifp_gre_info(ctx);
		zebra_l2_greif_add_update(ifp, gre_info, add);
		if (link_nsid != NS_UNKNOWN && gre_info->ifindex_link)
			zebra_if_update_link(ifp, gre_info->ifindex_link,
					     link_nsid);
		break;
	case ZEBRA_IF_OTHER:
	case ZEBRA_IF_VRF:
	case ZEBRA_IF_MACVLAN:
	case ZEBRA_IF_VETH:
	case ZEBRA_IF_BOND:
		break;
	}
}

static bool is_if_protodown_reason_only_frr(uint32_t rc_bitfield)
{
	uint8_t frr_protodown_r_bit = if_netlink_get_frr_protodown_r_bit();

	return (rc_bitfield == (((uint32_t)1) << frr_protodown_r_bit));
}

static void interface_if_protodown(struct interface *ifp, bool protodown,
				   uint32_t rc_bitfield)
{
	struct zebra_if *zif = ifp->info;
	bool old_protodown, reason_extern;

	reason_extern = !!CHECK_FLAG(zif->protodown_rc,
				     ZEBRA_PROTODOWN_EXTERNAL);
	/*
	 * Set our reason code to note it wasn't us.
	 * If the reason we got from the kernel is ONLY frr though, don't
	 * set it.
	 */
	COND_FLAG(zif->protodown_rc, ZEBRA_PROTODOWN_EXTERNAL,
		  protodown && rc_bitfield &&
			  !is_if_protodown_reason_only_frr(rc_bitfield));


	old_protodown = !!ZEBRA_IF_IS_PROTODOWN(zif);
	if (protodown == old_protodown)
		return;

	if (IS_ZEBRA_DEBUG_EVPN_MH_ES || IS_ZEBRA_DEBUG_DPLANE)
		zlog_debug("interface %s dplane change, protodown %s curr reason_extern %u",
			   ifp->name, protodown ? "on" : "off", reason_extern);

	/* Set protodown, respectively */
	COND_FLAG(zif->flags, ZIF_FLAG_PROTODOWN, protodown);

	if (zebra_evpn_is_es_bond_member(ifp)) {
		/* Check it's not already being sent to the dplane first */
		if (protodown &&
		    CHECK_FLAG(zif->flags, ZIF_FLAG_SET_PROTODOWN)) {
			if (IS_ZEBRA_DEBUG_EVPN_MH_ES || IS_ZEBRA_DEBUG_KERNEL)
				zlog_debug(
					"bond mbr %s protodown on recv'd but already sent protodown on to the dplane",
					ifp->name);
			return;
		}

		if (!protodown &&
		    CHECK_FLAG(zif->flags, ZIF_FLAG_UNSET_PROTODOWN)) {
			if (IS_ZEBRA_DEBUG_EVPN_MH_ES || IS_ZEBRA_DEBUG_KERNEL)
				zlog_debug(
					"bond mbr %s protodown off recv'd but already sent protodown off to the dplane",
					ifp->name);
			return;
		}

		if (!protodown && reason_extern) {
			if (IS_ZEBRA_DEBUG_EVPN_MH_ES || IS_ZEBRA_DEBUG_KERNEL)
				zlog_debug("bond member %s has protodown reason external and clear the reason, skip reinstall.",
					   ifp->name);
			return;
		}

		if (IS_ZEBRA_DEBUG_EVPN_MH_ES || IS_ZEBRA_DEBUG_KERNEL)
			zlog_debug(
				"bond mbr %s reinstate protodown %s in the dplane",
				ifp->name, old_protodown ? "on" : "off");

		if (old_protodown)
			SET_FLAG(zif->flags, ZIF_FLAG_SET_PROTODOWN);
		else
			SET_FLAG(zif->flags, ZIF_FLAG_UNSET_PROTODOWN);

		dplane_intf_update(zif->ifp);
	}
}

static void if_sweep_protodown(struct zebra_if *zif)
{
	bool protodown;

	protodown = !!ZEBRA_IF_IS_PROTODOWN(zif);

	if (!protodown)
		return;

	if (IS_ZEBRA_DEBUG_KERNEL)
		zlog_debug("interface %s sweeping protodown %s reason 0x%x",
			   zif->ifp->name, protodown ? "on" : "off",
			   zif->protodown_rc);

	/* Only clear our reason codes, leave external if it was set */
	UNSET_FLAG(zif->protodown_rc, ZEBRA_PROTODOWN_ALL);
	dplane_intf_update(zif->ifp);
}

static void
interface_bridge_vxlan_vlan_vni_map_update(struct zebra_dplane_ctx *ctx,
					   struct interface *ifp)
{
	const struct zebra_vxlan_vni_array *vniarray =
		dplane_ctx_get_ifp_vxlan_vni_array(ctx);
	struct zebra_vxlan_vni vni_start, vni_end;
	struct hash *vni_table = NULL;
	struct zebra_vxlan_vni vni, *vnip;
	vni_t vni_id;
	vlanid_t vid;
	int i;

	if (vniarray == NULL)
		return;

	memset(&vni_start, 0, sizeof(vni_start));
	memset(&vni_end, 0, sizeof(vni_end));

	for (i = 0; i < vniarray->count; i++) {
		uint16_t flags = vniarray->vnis[i].flags;

		if (flags & DPLANE_BRIDGE_VLAN_INFO_RANGE_BEGIN) {
			vni_start = vniarray->vnis[i];
			continue;
		}

		if (flags & DPLANE_BRIDGE_VLAN_INFO_RANGE_END)
			vni_end = vniarray->vnis[i];

		if (!(flags & DPLANE_BRIDGE_VLAN_INFO_RANGE_END)) {
			vni_start = vniarray->vnis[i];
			vni_end = vniarray->vnis[i];
		}

		if (IS_ZEBRA_DEBUG_DPLANE)
			zlog_debug(
				"Vlan-Vni(%d:%d-%d:%d) update for VxLAN IF %s(%u)",
				vni_start.access_vlan, vni_end.access_vlan,
				vni_start.vni, vni_end.vni, ifp->name,
				ifp->ifindex);

		if (!vni_table) {
			vni_table = zebra_vxlan_vni_table_create();
			if (!vni_table)
				return;
		}

		for (vid = vni_start.access_vlan, vni_id = vni_start.vni;
		     vid <= vni_end.access_vlan; vid++, vni_id++) {

			memset(&vni, 0, sizeof(vni));
			vni.vni = vni_id;
			vni.access_vlan = vid;
			vnip = hash_get(vni_table, &vni, zebra_vxlan_vni_alloc);
			if (!vnip)
				return;
		}

		memset(&vni_start, 0, sizeof(vni_start));
		memset(&vni_end, 0, sizeof(vni_end));
	}

	if (vni_table)
		zebra_vxlan_if_vni_table_add_update(ifp, vni_table);
}

static void interface_bridge_vxlan_update(struct zebra_dplane_ctx *ctx,
					  struct interface *ifp)
{
	struct zebra_if *zif = ifp->info;
	const struct zebra_dplane_bridge_vlan_info *bvinfo;

	if (dplane_ctx_get_ifp_no_afspec(ctx))
		return;

	if (IS_ZEBRA_VXLAN_IF_SVD(zif))
		interface_bridge_vxlan_vlan_vni_map_update(ctx, ifp);

	if (dplane_ctx_get_ifp_no_bridge_vlan_info(ctx))
		return;

	bvinfo = dplane_ctx_get_ifp_bridge_vlan_info(ctx);

	if (!(bvinfo->flags & DPLANE_BRIDGE_VLAN_INFO_PVID))
		return;

	if (IS_ZEBRA_DEBUG_DPLANE)
		zlog_debug("Access VLAN %u for VxLAN IF %s(%u)", bvinfo->vid,
			   ifp->name, ifp->ifindex);

	zebra_l2_vxlanif_update_access_vlan(ifp, bvinfo->vid);
}

static void interface_bridge_vlan_update(struct zebra_dplane_ctx *ctx,
					 struct interface *ifp)
{
	struct zebra_if *zif = ifp->info;
	const struct zebra_dplane_bridge_vlan_info_array *bvarray;
	struct zebra_dplane_bridge_vlan_info bvinfo;
	bitfield_t old_vlan_bitmap;
	uint16_t vid_range_start = 0;
	int32_t i;

	/* cache the old bitmap addrs */
	old_vlan_bitmap = zif->vlan_bitmap;
	/* create a new bitmap space for re-eval */
	bf_init(zif->vlan_bitmap, IF_VLAN_BITMAP_MAX);

	/* Could we have multiple bridge vlan infos? */
	bvarray = dplane_ctx_get_ifp_bridge_vlan_info_array(ctx);
	if (!bvarray)
		return;

	for (i = 0; i < bvarray->count; i++) {
		bvinfo = bvarray->array[i];

		if (bvinfo.flags & DPLANE_BRIDGE_VLAN_INFO_RANGE_BEGIN) {
			vid_range_start = bvinfo.vid;
			continue;
		}

		if (!(bvinfo.flags & DPLANE_BRIDGE_VLAN_INFO_RANGE_END))
			vid_range_start = bvinfo.vid;

		zebra_vlan_bitmap_compute(ifp, vid_range_start, bvinfo.vid);
	}

	zebra_vlan_mbr_re_eval(ifp, old_vlan_bitmap);
	bf_free(old_vlan_bitmap);
}

static void interface_bridge_handling(struct zebra_dplane_ctx *ctx,
				      struct interface *ifp,
				      enum zebra_iftype zif_type)
{
	struct zebra_if *zif;

	if (!ifp) {
		zlog_warn("Cannot find bridge if %s(%u)",
			  dplane_ctx_get_ifname(ctx),
			  dplane_ctx_get_ifindex(ctx));
		return;
	}

	if (IS_ZEBRA_IF_VXLAN(ifp))
		return interface_bridge_vxlan_update(ctx, ifp);

	/*
	 * build vlan bitmap associated with this interface if that
	 * device type is interested in the vlans
	 */
	zif = ifp->info;
	if (bf_is_inited(zif->vlan_bitmap))
		interface_bridge_vlan_update(ctx, ifp);
}

static void zebra_if_dplane_ifp_handling(struct zebra_dplane_ctx *ctx)
{
	enum dplane_op_e op = dplane_ctx_get_op(ctx);
	const char *name = dplane_ctx_get_ifname(ctx);
	ns_id_t ns_id = dplane_ctx_get_ns_id(ctx);
	ifindex_t ifindex = dplane_ctx_get_ifindex(ctx);
	ifindex_t bond_ifindex = dplane_ctx_get_ifp_bond_ifindex(ctx);
	uint32_t tableid = dplane_ctx_get_ifp_table_id(ctx);
	enum zebra_iftype zif_type = dplane_ctx_get_ifp_zif_type(ctx);
	struct interface *ifp;
	struct zebra_ns *zns;

	zns = zebra_ns_lookup(ns_id);
	if (!zns) {
		zlog_err("Where is our namespace?");
		return;
	}

	if (IS_ZEBRA_DEBUG_DPLANE)
		zlog_debug("%s for %s(%u)", dplane_op2str(op), name, ifindex);

	ifp = if_lookup_by_name_per_ns(zns, name);
	if (op == DPLANE_OP_INTF_DELETE) {
		/* Delete interface notification from kernel */
		if (ifp == NULL) {
			if (IS_ZEBRA_DEBUG_EVENT)
				zlog_debug(
					"Delete LINK received for unknown interface %s(%u)",
					name, ifindex);
			return;
		}

		if (IS_ZEBRA_IF_BOND(ifp))
			zebra_l2if_update_bond(ifp, false);
		if (IS_ZEBRA_IF_BOND_SLAVE(ifp))
			zebra_l2if_update_bond_slave(ifp, bond_ifindex, false);
		/* Special handling for bridge or VxLAN interfaces. */
		if (IS_ZEBRA_IF_BRIDGE(ifp))
			zebra_l2_bridge_del(ifp);
		else if (IS_ZEBRA_IF_VXLAN(ifp))
			zebra_l2_vxlanif_del(ifp);

		if_delete_update(&ifp);

		if (zif_type == ZEBRA_IF_VRF && !vrf_is_backend_netns())
			interface_vrf_change(op, ifindex, name, tableid, ns_id);
	} else {
		ifindex_t master_ifindex, bridge_ifindex, bond_ifindex,
			link_ifindex;
		enum zebra_slave_iftype zif_slave_type;
		uint8_t bypass;
		uint64_t flags;
		vrf_id_t vrf_id;
		uint32_t mtu;
		ns_id_t link_nsid;
		struct zebra_if *zif;
		bool protodown, protodown_set, startup;
		uint32_t rc_bitfield;
		uint8_t old_hw_addr[INTERFACE_HWADDR_MAX];
		char *desc;
		uint8_t family;

		/* If VRF, create or update the VRF structure itself. */
		if (zif_type == ZEBRA_IF_VRF && !vrf_is_backend_netns())
			interface_vrf_change(op, ifindex, name, tableid, ns_id);

		master_ifindex = dplane_ctx_get_ifp_master_ifindex(ctx);
		zif_slave_type = dplane_ctx_get_ifp_zif_slave_type(ctx);
		bridge_ifindex = dplane_ctx_get_ifp_bridge_ifindex(ctx);
		bond_ifindex = dplane_ctx_get_ifp_bond_ifindex(ctx);
		bypass = dplane_ctx_get_ifp_bypass(ctx);
		flags = dplane_ctx_get_ifp_flags(ctx);
		vrf_id = dplane_ctx_get_ifp_vrf_id(ctx);
		mtu = dplane_ctx_get_ifp_mtu(ctx);
		link_ifindex = dplane_ctx_get_ifp_link_ifindex(ctx);
		link_nsid = dplane_ctx_get_ifp_link_nsid(ctx);
		protodown_set = dplane_ctx_get_ifp_protodown_set(ctx);
		protodown = dplane_ctx_get_ifp_protodown(ctx);
		rc_bitfield = dplane_ctx_get_ifp_rc_bitfield(ctx);
		startup = dplane_ctx_get_ifp_startup(ctx);
		desc = dplane_ctx_get_ifp_desc(ctx);
		family = dplane_ctx_get_ifp_family(ctx);

#ifndef AF_BRIDGE
		/*
		 * Work around to make free bsd happy at the moment
		 */
#define AF_BRIDGE 7
#endif
		if (family == AF_BRIDGE)
			return interface_bridge_handling(ctx, ifp, zif_type);

		if (ifp == NULL ||
		    !CHECK_FLAG(ifp->status, ZEBRA_INTERFACE_ACTIVE)) {
			/* Add interface notification from kernel */
			if (IS_ZEBRA_DEBUG_KERNEL)
				zlog_debug(
					"RTM_NEWLINK ADD for %s(%u) vrf_id %u type %d sl_type %d master %u",
					name, ifindex, vrf_id, zif_type,
					zif_slave_type, master_ifindex);

			if (ifp == NULL) {
				/* unknown interface */
				ifp = if_get_by_name(name, vrf_id, NULL);
			} else {
				/* pre-configured interface, learnt now */
				if (ifp->vrf->vrf_id != vrf_id)
					if_update_to_new_vrf(ifp, vrf_id);
			}

			zif = ifp->info;

			/* Update interface information. */
			set_ifindex(ifp, ifindex, zns);
			ifp->flags = flags;
			ifp->mtu6 = ifp->mtu = mtu;
			ifp->metric = 0;
			ifp->speed = kernel_get_speed(ifp, NULL);
			ifp->ptm_status = ZEBRA_PTM_STATUS_UNKNOWN;
			ifp->txqlen = dplane_ctx_get_intf_txqlen(ctx);

			/* Set interface type */
			zebra_if_set_ziftype(ifp, zif_type, zif_slave_type);
			if (IS_ZEBRA_IF_VRF(ifp))
				SET_FLAG(ifp->status,
					 ZEBRA_INTERFACE_VRF_LOOPBACK);

			/* Update link. */
			zebra_if_update_link(ifp, link_ifindex, link_nsid);

			ifp->ll_type = dplane_ctx_get_ifp_zltype(ctx);
			interface_update_hw_addr(ctx, ifp);

			/* Inform clients, install any configured addresses. */
			if_add_update(ifp);

			/*
			 * Extract and save L2 interface information, take
			 * additional actions.
			 */
			interface_update_l2info(ctx, ifp, zif_type, 1,
						link_nsid);
			if (IS_ZEBRA_IF_BOND(ifp))
				zebra_l2if_update_bond(ifp, true);
			if (IS_ZEBRA_IF_BRIDGE_SLAVE(ifp))
				zebra_l2if_update_bridge_slave(
					ifp, bridge_ifindex, ns_id,
					ZEBRA_BRIDGE_NO_ACTION);
			else if (IS_ZEBRA_IF_BOND_SLAVE(ifp))
				zebra_l2if_update_bond_slave(ifp, bond_ifindex,
							     !!bypass);

			if (protodown_set) {
				interface_if_protodown(ifp, protodown,
						       rc_bitfield);
				if (startup)
					if_sweep_protodown(zif);
			}

			if (IS_ZEBRA_IF_BRIDGE(ifp)) {
				if (IS_ZEBRA_DEBUG_KERNEL)
					zlog_debug(
						"RTM_NEWLINK ADD for %s(%u), vlan-aware %d",
						name, ifp->ifindex,
						IS_ZEBRA_IF_BRIDGE_VLAN_AWARE(
							zif));
			}
		} else if (ifp->vrf->vrf_id != vrf_id) {
			/* VRF change for an interface. */
			if (IS_ZEBRA_DEBUG_KERNEL)
				zlog_debug(
					"RTM_NEWLINK vrf-change for %s(%u) vrf_id %u -> %u",
					name, ifp->ifindex, ifp->vrf->vrf_id,
					vrf_id);

			if_handle_vrf_change(ifp, vrf_id);
		} else {
			bool was_bridge_slave, was_bond_slave;
			uint8_t chgflags = ZEBRA_BRIDGE_NO_ACTION;

			zif = ifp->info;

			/* Interface update. */
			if (IS_ZEBRA_DEBUG_KERNEL)
				zlog_debug(
					"RTM_NEWLINK update for %s(%u) sl_type %d master %u",
					name, ifp->ifindex, zif_slave_type,
					master_ifindex);

			set_ifindex(ifp, ifindex, zns);
			ifp->mtu6 = ifp->mtu = mtu;
			ifp->metric = 0;
			ifp->txqlen = dplane_ctx_get_intf_txqlen(ctx);

			/*
			 * Update interface type - NOTE: Only slave_type can
			 * change.
			 */
			was_bridge_slave = IS_ZEBRA_IF_BRIDGE_SLAVE(ifp);
			was_bond_slave = IS_ZEBRA_IF_BOND_SLAVE(ifp);
			zebra_if_set_ziftype(ifp, zif_type, zif_slave_type);

			memcpy(old_hw_addr, ifp->hw_addr, INTERFACE_HWADDR_MAX);

			/* Update link. */
			zebra_if_update_link(ifp, link_ifindex, link_nsid);

			ifp->ll_type = dplane_ctx_get_ifp_zltype(ctx);
			interface_update_hw_addr(ctx, ifp);

			if (protodown_set)
				interface_if_protodown(ifp, protodown,
						       rc_bitfield);

			if (if_is_no_ptm_operative(ifp)) {
				bool is_up = if_is_operative(ifp);

				ifp->flags = flags;
				if (!if_is_no_ptm_operative(ifp) ||
				    CHECK_FLAG(zif->flags,
					       ZIF_FLAG_PROTODOWN)) {
					if (IS_ZEBRA_DEBUG_KERNEL)
						zlog_debug(
							"Intf %s(%u) has gone DOWN",
							name, ifp->ifindex);
					if_down(ifp);
					rib_update(RIB_UPDATE_KERNEL);
				} else if (if_is_operative(ifp)) {
					bool mac_updated = false;

					/*
					 * Must notify client daemons of new
					 * interface status.
					 */
					if (IS_ZEBRA_DEBUG_KERNEL)
						zlog_debug(
							"Intf %s(%u) PTM up, notifying clients",
							name, ifp->ifindex);
					if_up(ifp, !is_up);

					/*
					 * Update EVPN VNI when SVI MAC change
					 */
					if (memcmp(old_hw_addr, ifp->hw_addr,
						   INTERFACE_HWADDR_MAX))
						mac_updated = true;
					if (IS_ZEBRA_IF_VLAN(ifp) &&
					    mac_updated) {
						struct interface *link_if;

						link_if = if_lookup_by_index_per_ns(
							zebra_ns_lookup(
								NS_DEFAULT),
							link_ifindex);
						if (link_if)
							zebra_vxlan_svi_up(
								ifp, link_if);
					} else if (mac_updated &&
						   IS_ZEBRA_IF_BRIDGE(ifp)) {
						zlog_debug(
							"Intf %s(%u) bridge changed MAC address",
							name, ifp->ifindex);
						chgflags =
							ZEBRA_BRIDGE_MASTER_MAC_CHANGE;
					}
				}
			} else {
				ifp->flags = flags;
				if (if_is_operative(ifp) &&
				    !CHECK_FLAG(zif->flags,
						ZIF_FLAG_PROTODOWN)) {
					if (IS_ZEBRA_DEBUG_KERNEL)
						zlog_debug(
							"Intf %s(%u) has come UP",
							name, ifp->ifindex);
					if_up(ifp, true);
					if (IS_ZEBRA_IF_BRIDGE(ifp))
						chgflags =
							ZEBRA_BRIDGE_MASTER_UP;
				} else {
					if (IS_ZEBRA_DEBUG_KERNEL)
						zlog_debug(
							"Intf %s(%u) has gone DOWN",
							name, ifp->ifindex);
					if_down(ifp);
					rib_update(RIB_UPDATE_KERNEL);
				}
			}

			/*
			 * Extract and save L2 interface information, take
			 * additional actions.
			 */
			interface_update_l2info(ctx, ifp, zif_type, 0,
						link_nsid);
			if (IS_ZEBRA_IF_BRIDGE(ifp))
				zebra_l2if_update_bridge(ifp, chgflags);
			if (IS_ZEBRA_IF_BOND(ifp))
				zebra_l2if_update_bond(ifp, true);
			if (IS_ZEBRA_IF_BRIDGE_SLAVE(ifp) || was_bridge_slave)
				zebra_l2if_update_bridge_slave(
					ifp, bridge_ifindex, ns_id, chgflags);
			else if (IS_ZEBRA_IF_BOND_SLAVE(ifp) || was_bond_slave)
				zebra_l2if_update_bond_slave(ifp, bond_ifindex,
							     !!bypass);
			if (IS_ZEBRA_IF_BRIDGE(ifp)) {
				if (IS_ZEBRA_DEBUG_KERNEL)
					zlog_debug(
						"RTM_NEWLINK update for %s(%u), vlan-aware %d",
						name, ifp->ifindex,
						IS_ZEBRA_IF_BRIDGE_VLAN_AWARE(
							zif));
			}
		}

		zif = ifp->info;
		if (zif) {
			XFREE(MTYPE_ZIF_DESC, zif->desc);
			if (desc[0])
				zif->desc = XSTRDUP(MTYPE_ZIF_DESC, desc);
		}
	}
}

void zebra_if_dplane_result(struct zebra_dplane_ctx *ctx)
{
	struct zebra_ns *zns;
	struct interface *ifp;
	ns_id_t ns_id;
	enum dplane_op_e op;
	enum zebra_dplane_result dp_res;
	ifindex_t ifindex;

	ns_id = dplane_ctx_get_ns_id(ctx);
	dp_res = dplane_ctx_get_status(ctx);
	op = dplane_ctx_get_op(ctx);
	ifindex = dplane_ctx_get_ifindex(ctx);

	if (IS_ZEBRA_DEBUG_DPLANE_DETAIL || IS_ZEBRA_DEBUG_KERNEL)
		zlog_debug("Intf dplane ctx %p, op %s, ifindex (%u), result %s",
			   ctx, dplane_op2str(op), ifindex,
			   dplane_res2str(dp_res));

	zns = zebra_ns_lookup(ns_id);
	if (zns == NULL) {
		/* No ns - deleted maybe? */
		if (IS_ZEBRA_DEBUG_KERNEL)
			zlog_debug("%s: can't find zns id %u", __func__, ns_id);

		return;
	}

	ifp = if_lookup_by_index_per_ns(zns, ifindex);

	if (op == DPLANE_OP_INTF_ADDR_ADD || op == DPLANE_OP_INTF_ADDR_DEL) {
		zebra_if_addr_update_ctx(ctx, ifp);
	} else if (op == DPLANE_OP_INTF_INSTALL ||
		   op == DPLANE_OP_INTF_UPDATE || op == DPLANE_OP_INTF_DELETE) {
		/*
		 * Queued from the dplane means it is something
		 * that we need to handle( create/delete the
		 * interface as needed )
		 */
		if (dp_res == ZEBRA_DPLANE_REQUEST_QUEUED)
			zebra_if_dplane_ifp_handling(ctx);
		else
			zebra_if_update_ctx(ctx, ifp);
	} else if (op == DPLANE_OP_INTF_NETCONFIG) {
		zebra_if_netconf_update_ctx(ctx, ifp, ifindex);
	}
}

/* Dump if address information to vty. */
static void connected_dump_vty(struct vty *vty, json_object *json,
			       struct connected *connected)
{
	struct prefix *p;
	json_object *json_addr = NULL;

	/* Print interface address. */
	p = connected->address;

	if (json) {
		json_addr = json_object_new_object();
		json_object_array_add(json, json_addr);
		json_object_string_addf(json_addr, "address", "%pFX", p);
	} else {
		vty_out(vty, "  %s %pFX", prefix_family_str(p), p);
	}

	/* If there is destination address, print it. */
	if (CONNECTED_PEER(connected) && connected->destination) {
		if (json) {
			json_object_string_addf(json_addr, "peer", "%pFX",
						connected->destination);
		} else {
			vty_out(vty, " peer %pFX", connected->destination);
		}
	}

	if (json)
		json_object_boolean_add(
			json_addr, "secondary",
			CHECK_FLAG(connected->flags, ZEBRA_IFA_SECONDARY));
	else if (CHECK_FLAG(connected->flags, ZEBRA_IFA_SECONDARY))
		vty_out(vty, " secondary");

	if (json)
		json_object_boolean_add(json_addr, "noPrefixRoute",
					CHECK_FLAG(connected->flags, ZEBRA_IFA_NOPREFIXROUTE));
	else if (CHECK_FLAG(connected->flags, ZEBRA_IFA_NOPREFIXROUTE))
		vty_out(vty, " noprefixroute");

	if (json)
		json_object_boolean_add(
			json_addr, "unnumbered",
			CHECK_FLAG(connected->flags, ZEBRA_IFA_UNNUMBERED));
	else if (CHECK_FLAG(connected->flags, ZEBRA_IFA_UNNUMBERED))
		vty_out(vty, " unnumbered");

	if (connected->label) {
		if (json)
			json_object_string_add(json_addr, "label",
					       connected->label);
		else
			vty_out(vty, " %s", connected->label);
	}

	if (!json)
		vty_out(vty, "\n");
}

/* Dump interface neighbor address information to vty. */
static void nbr_connected_dump_vty(struct vty *vty, json_object *json,
				   struct nbr_connected *connected)
{
	struct prefix *p;
	char buf[PREFIX2STR_BUFFER];

	/* Print interface address. */
	p = connected->address;
	if (json)
		json_array_string_add(json, prefix2str(p, buf, sizeof(buf)));
	else
		vty_out(vty, "  %s %pFX\n", prefix_family_str(p), p);
}

static const char *
zebra_zifslavetype_2str(enum zebra_slave_iftype zif_slave_type)
{
	switch (zif_slave_type) {
	case ZEBRA_IF_SLAVE_BRIDGE:
		return "Bridge";
	case ZEBRA_IF_SLAVE_VRF:
		return "Vrf";
	case ZEBRA_IF_SLAVE_BOND:
		return "Bond";
	case ZEBRA_IF_SLAVE_OTHER:
		return "Other";
	case ZEBRA_IF_SLAVE_NONE:
		return "None";
	}
	return "None";
}

static const char *zebra_ziftype_2str(enum zebra_iftype zif_type)
{
	switch (zif_type) {
	case ZEBRA_IF_OTHER:
		return "Other";

	case ZEBRA_IF_BRIDGE:
		return "Bridge";

	case ZEBRA_IF_VLAN:
		return "Vlan";

	case ZEBRA_IF_VXLAN:
		return "Vxlan";

	case ZEBRA_IF_VRF:
		return "VRF";

	case ZEBRA_IF_VETH:
		return "VETH";

	case ZEBRA_IF_BOND:
		return "bond";

	case ZEBRA_IF_MACVLAN:
		return "macvlan";

	case ZEBRA_IF_GRE:
		return "GRE";

	default:
		return "Unknown";
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
					if (first_pfx_printed) {
						/* padding to prepare row only
						 * for ip addr */
						vty_out(vty, "%-40s", "");
						if (list_size > 1)
							vty_out(vty, "+ ");
						vty_out(vty, "%pFX\n", p);
					} else {
						if (list_size > 1)
							vty_out(vty, "+ ");
						vty_out(vty, "%pFX\n", p);
					}
					first_pfx_printed = true;
					break;
				}
			}
		}

		uint32_t v6_list_size = 0;
		frr_each (if_connected, ifp->connected, connected) {
			if (CHECK_FLAG(connected->conf, ZEBRA_IFC_REAL)
				&& (connected->address->family == AF_INET6))
				v6_list_size++;
		}
		frr_each (if_connected, ifp->connected, connected) {
			if (!CHECK_FLAG(connected->flags, ZEBRA_IFA_SECONDARY) &&
			    (connected->address->family == AF_INET6)) {
				p = connected->address;
				if (first_pfx_printed) {
					vty_out(vty, "%-40s", "");
					if (v6_list_size > 1)
						vty_out(vty, "+ ");
					vty_out(vty, "%pFX\n", p);
				} else {
					if (v6_list_size > 1)
						vty_out(vty, "+ ");
					vty_out(vty, "%pFX\n", p);
				}
				first_pfx_printed = true;
				break;
			}
		}
		if (!first_pfx_printed)
			vty_out(vty, "\n");
	}
	vty_out(vty, "\n");
}

static void ifs_dump_brief_vty_json(json_object *json, struct vrf *vrf)
{
	struct connected *connected;
	struct interface *ifp;

	FOR_ALL_INTERFACES (vrf, ifp) {
		json_object *json_if;
		json_object *json_addrs;

		json_if = json_object_new_object();
		json_object_object_add(json, ifp->name, json_if);

		json_object_string_add(json_if, "status",
				       if_is_up(ifp) ? "up" : "down");
		json_object_string_add(json_if, "vrfName", vrf->name);

		json_addrs = json_object_new_array();
		json_object_object_add(json_if, "addresses", json_addrs);
		frr_each (if_connected, ifp->connected, connected) {
			if (!CHECK_FLAG(connected->flags, ZEBRA_IFA_SECONDARY)) {
				char buf[PREFIX2STR_BUFFER];

				json_array_string_add(
					json_addrs,
					prefix2str(connected->address, buf,
						   sizeof(buf)));
			}
		}
	}
}

const char *zebra_protodown_rc_str(uint32_t protodown_rc, char *pd_buf,
				   uint32_t pd_buf_len)
{
	pd_buf[0] = '\0';
	size_t len;

	strlcat(pd_buf, "(", pd_buf_len);

	if (CHECK_FLAG(protodown_rc, ZEBRA_PROTODOWN_EXTERNAL))
		strlcat(pd_buf, "external,", pd_buf_len);

	if (CHECK_FLAG(protodown_rc, ZEBRA_PROTODOWN_EVPN_STARTUP_DELAY))
		strlcat(pd_buf, "startup-delay,", pd_buf_len);

	if (CHECK_FLAG(protodown_rc, ZEBRA_PROTODOWN_EVPN_UPLINK_DOWN))
		strlcat(pd_buf, "uplinks-down,", pd_buf_len);

	if (CHECK_FLAG(protodown_rc, ZEBRA_PROTODOWN_VRRP))
		strlcat(pd_buf, "vrrp,", pd_buf_len);

	if (CHECK_FLAG(protodown_rc, ZEBRA_PROTODOWN_SHARP))
		strlcat(pd_buf, "sharp,", pd_buf_len);

	len = strnlen(pd_buf, pd_buf_len);

	/* Remove trailing comma */
	if (pd_buf[len - 1] == ',')
		pd_buf[len - 1] = '\0';

	strlcat(pd_buf, ")", pd_buf_len);

	return pd_buf;
}

static inline bool if_is_protodown_applicable(struct interface *ifp)
{
	if (IS_ZEBRA_IF_BOND(ifp))
		return false;

	return true;
}

static void zebra_vxlan_if_vni_dump_vty(struct vty *vty,
					struct zebra_vxlan_vni *vni)
{
	char str[INET6_ADDRSTRLEN];

	vty_out(vty, "  VxLAN Id %u", vni->vni);
	if (vni->access_vlan)
		vty_out(vty, " Access VLAN Id %u\n", vni->access_vlan);

	if (vni->mcast_grp.s_addr != INADDR_ANY)
		vty_out(vty, "  Mcast Group %s",
			inet_ntop(AF_INET, &vni->mcast_grp, str, sizeof(str)));
}

static void zebra_vxlan_if_vni_hash_dump_vty(struct hash_bucket *bucket,
					     void *ctxt)
{
	struct vty *vty;
	struct zebra_vxlan_vni *vni;

	vni = (struct zebra_vxlan_vni *)bucket->data;
	vty = (struct vty *)ctxt;

	zebra_vxlan_if_vni_dump_vty(vty, vni);
}

static void zebra_vxlan_if_dump_vty(struct vty *vty, struct zebra_if *zebra_if)
{
	struct zebra_l2info_vxlan *vxlan_info;
	struct zebra_vxlan_vni_info *vni_info;

	vxlan_info = &zebra_if->l2info.vxl;
	vni_info = &vxlan_info->vni_info;

	if (vxlan_info->vtep_ip.s_addr != INADDR_ANY)
		vty_out(vty, " VTEP IP: %pI4", &vxlan_info->vtep_ip);

	if (vxlan_info->ifindex_link && (vxlan_info->link_nsid != NS_UNKNOWN)) {
		struct interface *ifp;

		ifp = if_lookup_by_index_per_ns(
			zebra_ns_lookup(vxlan_info->link_nsid),
			vxlan_info->ifindex_link);
		vty_out(vty, " Link Interface %s",
			ifp == NULL ? "Unknown" : ifp->name);
	}

	if (IS_ZEBRA_VXLAN_IF_VNI(zebra_if)) {
		zebra_vxlan_if_vni_dump_vty(vty, &vni_info->vni);
	} else {
		hash_iterate(vni_info->vni_table,
			     zebra_vxlan_if_vni_hash_dump_vty, vty);
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
	char pd_buf[ZEBRA_PROTODOWN_RC_STR_LEN];

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

	zebra_ptm_show_status(vty, NULL, ifp);

	vty_out(vty, "  vrf: %s\n", ifp->vrf->name);

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

	vty_out(vty, "  index %d metric %d mtu %d speed %u txqlen %u",
		ifp->ifindex, ifp->metric, ifp->mtu, ifp->speed, ifp->txqlen);
	if (ifp->mtu6 != ifp->mtu)
		vty_out(vty, "mtu6 %d ", ifp->mtu6);
	vty_out(vty, "\n  flags: %s\n", if_flag_dump(ifp->flags));

	if (zebra_if->mpls)
		vty_out(vty, "  MPLS enabled\n");

	if (zebra_if->linkdown)
		vty_out(vty, "  Ignore all v4 routes with linkdown\n");
	if (zebra_if->linkdownv6)
		vty_out(vty, "  Ignore all v6 routes with linkdown\n");

	if (zebra_if->v4mcast_on)
		vty_out(vty, "  v4 Multicast forwarding is on\n");
	if (zebra_if->v6mcast_on)
		vty_out(vty, "  v6 Multicast forwarding is on\n");

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
			connected_dump_vty(vty, NULL, connected);
	}

	frr_each (if_connected, ifp->connected, connected) {
		if (connected->address->family == AF_INET6)
			connected_dump_vty(vty, NULL, connected);
	}

	vty_out(vty, "  Interface Type %s\n",
		zebra_ziftype_2str(zebra_if->zif_type));
	vty_out(vty, "  Interface Slave Type %s\n",
		zebra_zifslavetype_2str(zebra_if->zif_slave_type));

	if (IS_ZEBRA_IF_BRIDGE(ifp)) {
		vty_out(vty, "  Bridge VLAN-aware: %s\n",
			IS_ZEBRA_IF_BRIDGE_VLAN_AWARE(zebra_if) ? "yes" : "no");
	} else if (IS_ZEBRA_IF_VLAN(ifp)) {
		struct zebra_l2info_vlan *vlan_info;

		vlan_info = &zebra_if->l2info.vl;
		vty_out(vty, "  VLAN Id %u\n", vlan_info->vid);
	} else if (IS_ZEBRA_IF_VXLAN(ifp)) {
		zebra_vxlan_if_dump_vty(vty, zebra_if);
	} else if (IS_ZEBRA_IF_GRE(ifp)) {
		struct zebra_l2info_gre *gre_info;

		gre_info = &zebra_if->l2info.gre;
		if (gre_info->vtep_ip.s_addr != INADDR_ANY) {
			vty_out(vty, "  VTEP IP: %pI4", &gre_info->vtep_ip);
			if (gre_info->vtep_ip_remote.s_addr != INADDR_ANY)
				vty_out(vty, " , remote %pI4",
					&gre_info->vtep_ip_remote);
			vty_out(vty, "\n");
		}
		if (gre_info->ifindex_link &&
		    (gre_info->link_nsid != NS_UNKNOWN)) {
			struct interface *ifp;

			ifp = if_lookup_by_index_per_ns(
					zebra_ns_lookup(gre_info->link_nsid),
					gre_info->ifindex_link);
			vty_out(vty, "  Link Interface %s\n",
				ifp == NULL ? "Unknown" :
				ifp->name);
		}
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

	if (zebra_if->flags & ZIF_FLAG_LACP_BYPASS)
		vty_out(vty, "  LACP bypass: on\n");

	zebra_evpn_if_es_print(vty, NULL, zebra_if);
	vty_out(vty, "  protodown: %s %s\n",
		(ZEBRA_IF_IS_PROTODOWN(zebra_if)) ? "on" : "off",
		if_is_protodown_applicable(ifp) ? "" : "(n/a)");
	if (zebra_if->protodown_rc)
		vty_out(vty, "  protodown reasons: %s\n",
			zebra_protodown_rc_str(zebra_if->protodown_rc, pd_buf,
					       sizeof(pd_buf)));

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
			vty_out(vty, "    Link Packet Loss %f (in %%)\n",
				(double)iflp->pkt_loss * LOSS_PRECISION);
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
			vty_out(vty, "    Neighbor ASBR IP: %pI4 AS: %u \n",
				&iflp->rmt_ip, iflp->rmt_as);
	}

	hook_call(zebra_if_extra_info, vty, ifp);

	if (listhead(ifp->nbr_connected))
		vty_out(vty, "  Neighbor address(s):\n");
	for (ALL_LIST_ELEMENTS_RO(ifp->nbr_connected, node, nbr_connected))
		nbr_connected_dump_vty(vty, NULL, nbr_connected);

#ifdef HAVE_PROC_NET_DEV
	/* Statistics print out using proc file system. */
	vty_out(vty,
		"    %lu input packets (%lu multicast), %lu bytes, %lu dropped\n",
		ifp->stats.rx_packets, ifp->stats.rx_multicast,
		ifp->stats.rx_bytes, ifp->stats.rx_dropped);

	vty_out(vty,
		"    %lu input errors, %lu length, %lu overrun, %lu CRC, %lu frame\n",
		ifp->stats.rx_errors, ifp->stats.rx_length_errors,
		ifp->stats.rx_over_errors, ifp->stats.rx_crc_errors,
		ifp->stats.rx_frame_errors);

	vty_out(vty, "    %lu fifo, %lu missed\n", ifp->stats.rx_fifo_errors,
		ifp->stats.rx_missed_errors);

	vty_out(vty, "    %lu output packets, %lu bytes, %lu dropped\n",
		ifp->stats.tx_packets, ifp->stats.tx_bytes,
		ifp->stats.tx_dropped);

	vty_out(vty,
		"    %lu output errors, %lu aborted, %lu carrier, %lu fifo, %lu heartbeat\n",
		ifp->stats.tx_errors, ifp->stats.tx_aborted_errors,
		ifp->stats.tx_carrier_errors, ifp->stats.tx_fifo_errors,
		ifp->stats.tx_heartbeat_errors);

	vty_out(vty, "    %lu window, %lu collisions\n",
		ifp->stats.tx_window_errors, ifp->stats.collisions);
#endif /* HAVE_PROC_NET_DEV */

#ifdef HAVE_NET_RT_IFLIST
	/* Statistics print out using sysctl (). */
	vty_out(vty,
		"    input packets %llu, bytes %llu, dropped %llu, multicast packets %llu\n",
		(unsigned long long)ifp->stats.ifi_ipackets,
		(unsigned long long)ifp->stats.ifi_ibytes,
		(unsigned long long)ifp->stats.ifi_iqdrops,
		(unsigned long long)ifp->stats.ifi_imcasts);

	vty_out(vty, "    input errors %llu\n",
		(unsigned long long)ifp->stats.ifi_ierrors);

	vty_out(vty,
		"    output packets %llu, bytes %llu, multicast packets %llu\n",
		(unsigned long long)ifp->stats.ifi_opackets,
		(unsigned long long)ifp->stats.ifi_obytes,
		(unsigned long long)ifp->stats.ifi_omcasts);

	vty_out(vty, "    output errors %llu\n",
		(unsigned long long)ifp->stats.ifi_oerrors);

	vty_out(vty, "    collisions %llu\n",
		(unsigned long long)ifp->stats.ifi_collisions);
#endif /* HAVE_NET_RT_IFLIST */
}

static void zebra_vxlan_if_vni_dump_vty_json(json_object *json_if,
					     struct zebra_vxlan_vni *vni)
{
	json_object_int_add(json_if, "vxlanId", vni->vni);
	if (vni->access_vlan)
		json_object_int_add(json_if, "accessVlanId", vni->access_vlan);
	if (vni->mcast_grp.s_addr != INADDR_ANY)
		json_object_string_addf(json_if, "mcastGroup", "%pI4",
					&vni->mcast_grp);
}

static void zebra_vxlan_if_vni_hash_dump_vty_json(struct hash_bucket *bucket,
						  void *ctxt)
{
	json_object *json_if;
	struct zebra_vxlan_vni *vni;

	vni = (struct zebra_vxlan_vni *)bucket->data;
	json_if = (json_object *)ctxt;

	zebra_vxlan_if_vni_dump_vty_json(json_if, vni);
}

static void zebra_vxlan_if_dump_vty_json(json_object *json_if,
					 struct zebra_if *zebra_if)
{
	struct zebra_l2info_vxlan *vxlan_info;
	struct zebra_vxlan_vni_info *vni_info;

	vxlan_info = &zebra_if->l2info.vxl;
	vni_info = &vxlan_info->vni_info;

	if (vxlan_info->vtep_ip.s_addr != INADDR_ANY)
		json_object_string_addf(json_if, "vtepIp", "%pI4",
					&vxlan_info->vtep_ip);

	if (vxlan_info->ifindex_link && (vxlan_info->link_nsid != NS_UNKNOWN)) {
		struct interface *ifp;

		ifp = if_lookup_by_index_per_ns(
			zebra_ns_lookup(vxlan_info->link_nsid),
			vxlan_info->ifindex_link);
		json_object_string_add(json_if, "linkInterface",
				       ifp == NULL ? "Unknown" : ifp->name);
	}
	if (IS_ZEBRA_VXLAN_IF_VNI(zebra_if)) {
		zebra_vxlan_if_vni_dump_vty_json(json_if, &vni_info->vni);
	} else {
		hash_iterate(vni_info->vni_table,
			     zebra_vxlan_if_vni_hash_dump_vty_json, json_if);
	}
}

static void if_dump_vty_json(struct vty *vty, struct interface *ifp,
			     json_object *json)
{
	struct connected *connected;
	struct nbr_connected *nbr_connected;
	struct listnode *node;
	struct route_node *rn;
	struct zebra_if *zebra_if;
	char pd_buf[ZEBRA_PROTODOWN_RC_STR_LEN];
	char buf[BUFSIZ];
	json_object *json_if;
	json_object *json_addrs;

	json_if = json_object_new_object();
	json_object_object_add(json, ifp->name, json_if);

	if (if_is_up(ifp)) {
		json_object_string_add(json_if, "administrativeStatus", "up");

		if (CHECK_FLAG(ifp->status, ZEBRA_INTERFACE_LINKDETECTION)) {
			json_object_string_add(json_if, "operationalStatus",
					       if_is_running(ifp) ? "up"
								  : "down");
			json_object_boolean_add(json_if, "linkDetection", true);
		} else {
			json_object_boolean_add(json_if, "linkDetection",
						false);
		}
	} else {
		json_object_string_add(json_if, "administrativeStatus", "down");
	}

	zebra_if = ifp->info;

	json_object_int_add(json_if, "linkUps", zebra_if->up_count);
	json_object_int_add(json_if, "linkDowns", zebra_if->down_count);
	if (zebra_if->up_last[0])
		json_object_string_add(json_if, "lastLinkUp",
				       zebra_if->up_last);
	if (zebra_if->down_last[0])
		json_object_string_add(json_if, "lastLinkDown",
				       zebra_if->down_last);

	zebra_ptm_show_status(vty, json_if, ifp);

	json_object_string_add(json_if, "vrfName", ifp->vrf->name);

	if (ifp->desc)
		json_object_string_add(json_if, "description", ifp->desc);
	if (zebra_if->desc)
		json_object_string_add(json_if, "OsDescription",
				       zebra_if->desc);

	json_object_boolean_add(json_if, "mplsEnabled", zebra_if->mpls);
	json_object_boolean_add(json_if, "linkDown", zebra_if->linkdown);
	json_object_boolean_add(json_if, "linkDownV6", zebra_if->linkdownv6);
	json_object_boolean_add(json_if, "mcForwardingV4",
				zebra_if->v4mcast_on);
	json_object_boolean_add(json_if, "mcForwardingV6",
				zebra_if->v6mcast_on);

	if (ifp->ifindex == IFINDEX_INTERNAL) {
		json_object_boolean_add(json_if, "pseudoInterface", true);
		return;
	} else if (!CHECK_FLAG(ifp->status, ZEBRA_INTERFACE_ACTIVE)) {
		json_object_int_add(json_if, "index", ifp->ifindex);
		return;
	}

	json_object_boolean_add(json_if, "pseudoInterface", false);
	json_object_int_add(json_if, "index", ifp->ifindex);
	json_object_int_add(json_if, "metric", ifp->metric);
	json_object_int_add(json_if, "mtu", ifp->mtu);
	if (ifp->mtu6 != ifp->mtu)
		json_object_int_add(json_if, "mtu6", ifp->mtu6);
	json_object_int_add(json_if, "speed", ifp->speed);
	json_object_int_add(json_if, "txqlen", ifp->txqlen);
	json_object_string_add(json_if, "flags", if_flag_dump(ifp->flags));

	/* Hardware address. */
	json_object_string_add(json_if, "type", if_link_type_str(ifp->ll_type));
	if (ifp->hw_addr_len != 0) {
		char hwbuf[BUFSIZ];

		hwbuf[0] = '\0';
		for (int i = 0; i < ifp->hw_addr_len; i++) {
			snprintf(buf, sizeof(buf), "%s%02x", i == 0 ? "" : ":",
				 ifp->hw_addr[i]);
			strlcat(hwbuf, buf, sizeof(hwbuf));
		}
		json_object_string_add(json_if, "hardwareAddress", hwbuf);
	}

	/* Bandwidth in Mbps */
	if (ifp->bandwidth != 0)
		json_object_int_add(json_if, "bandwidth", ifp->bandwidth);


	/* IP addresses. */
	json_addrs = json_object_new_array();
	json_object_object_add(json_if, "ipAddresses", json_addrs);

	for (rn = route_top(zebra_if->ipv4_subnets); rn; rn = route_next(rn)) {
		if (!rn->info)
			continue;

		for (ALL_LIST_ELEMENTS_RO((struct list *)rn->info, node,
					  connected))
			connected_dump_vty(vty, json_addrs, connected);
	}

	frr_each (if_connected, ifp->connected, connected) {
		if (connected->address->family == AF_INET6)
			connected_dump_vty(vty, json_addrs, connected);
	}

	json_object_string_add(json_if, "interfaceType",
			       zebra_ziftype_2str(zebra_if->zif_type));
	json_object_string_add(
		json_if, "interfaceSlaveType",
		zebra_zifslavetype_2str(zebra_if->zif_slave_type));

	if (IS_ZEBRA_IF_BRIDGE(ifp)) {
		struct zebra_l2info_bridge *bridge_info;

		bridge_info = &zebra_if->l2info.br;
		json_object_boolean_add(json_if, "bridgeVlanAware",
					bridge_info->bridge.vlan_aware);
	} else if (IS_ZEBRA_IF_VLAN(ifp)) {
		struct zebra_l2info_vlan *vlan_info;

		vlan_info = &zebra_if->l2info.vl;
		json_object_int_add(json_if, "vlanId", vlan_info->vid);
	} else if (IS_ZEBRA_IF_VXLAN(ifp)) {
		zebra_vxlan_if_dump_vty_json(json_if, zebra_if);

	} else if (IS_ZEBRA_IF_GRE(ifp)) {
		struct zebra_l2info_gre *gre_info;

		gre_info = &zebra_if->l2info.gre;
		if (gre_info->vtep_ip.s_addr != INADDR_ANY) {
			json_object_string_addf(json_if, "vtepIp", "%pI4",
						&gre_info->vtep_ip);
			if (gre_info->vtep_ip_remote.s_addr != INADDR_ANY)
				json_object_string_addf(
					json_if, "vtepRemoteIp", "%pI4",
					&gre_info->vtep_ip_remote);
		}
		if (gre_info->ifindex_link
		    && (gre_info->link_nsid != NS_UNKNOWN)) {
			struct interface *ifp;

			ifp = if_lookup_by_index_per_ns(
				zebra_ns_lookup(gre_info->link_nsid),
				gre_info->ifindex_link);
			json_object_string_add(json_if, "linkInterface",
					       ifp == NULL ? "Unknown"
							   : ifp->name);
		}
	}

	if (IS_ZEBRA_IF_BRIDGE_SLAVE(ifp)) {
		struct zebra_l2info_brslave *br_slave;

		br_slave = &zebra_if->brslave_info;
		if (br_slave->bridge_ifindex != IFINDEX_INTERNAL) {
			if (br_slave->br_if)
				json_object_string_add(json_if,
						       "masterInterface",
						       br_slave->br_if->name);
			else
				json_object_int_add(json_if, "masterIfindex",
						    br_slave->bridge_ifindex);
		}
	}

	if (IS_ZEBRA_IF_BOND_SLAVE(ifp)) {
		struct zebra_l2info_bondslave *bond_slave;

		bond_slave = &zebra_if->bondslave_info;
		if (bond_slave->bond_ifindex != IFINDEX_INTERNAL) {
			if (bond_slave->bond_if)
				json_object_string_add(
					json_if, "masterInterface",
					bond_slave->bond_if->name);
			else
				json_object_int_add(json_if, "masterIfindex",
						    bond_slave->bond_ifindex);
		}
	}

	json_object_boolean_add(
		json_if, "lacpBypass",
		CHECK_FLAG(zebra_if->flags, ZIF_FLAG_LACP_BYPASS));

	zebra_evpn_if_es_print(vty, json_if, zebra_if);

	if (if_is_protodown_applicable(ifp)) {
		json_object_string_add(
			json_if, "protodown",
			(ZEBRA_IF_IS_PROTODOWN(zebra_if)) ? "on" : "off");
		if (zebra_if->protodown_rc)
			json_object_string_add(
				json_if, "protodownReason",
				zebra_protodown_rc_str(zebra_if->protodown_rc,
						       pd_buf, sizeof(pd_buf)));
	}

	if (zebra_if->link_ifindex != IFINDEX_INTERNAL) {
		if (zebra_if->link)
			json_object_string_add(json_if, "parentInterface",
					       zebra_if->link->name);
		else
			json_object_int_add(json_if, "parentIfindex",
					    zebra_if->link_ifindex);
	}

	if (HAS_LINK_PARAMS(ifp)) {
		struct if_link_params *iflp = ifp->link_params;
		json_object *json_te;

		json_te = json_object_new_object();
		json_object_object_add(
			json_if, "trafficEngineeringLinkParameters", json_te);

		if (IS_PARAM_SET(iflp, LP_TE_METRIC))
			json_object_int_add(json_te, "teMetric",
					    iflp->te_metric);
		if (IS_PARAM_SET(iflp, LP_MAX_BW))
			json_object_double_add(json_te, "maximumBandwidth",
					       iflp->max_bw);
		if (IS_PARAM_SET(iflp, LP_MAX_RSV_BW))
			json_object_double_add(json_te,
					       "maximumReservableBandwidth",
					       iflp->max_rsv_bw);
		if (IS_PARAM_SET(iflp, LP_UNRSV_BW)) {
			json_object *json_bws;

			json_bws = json_object_new_object();
			json_object_object_add(json_te, "unreservedBandwidth",
					       json_bws);
			for (unsigned int i = 0; i < MAX_CLASS_TYPE; ++i) {
				char buf_ct[64];

				snprintf(buf_ct, sizeof(buf_ct), "classType%u",
					 i);
				json_object_double_add(json_bws, buf_ct,
						       iflp->unrsv_bw[i]);
			}
		}

		if (IS_PARAM_SET(iflp, LP_ADM_GRP))
			json_object_int_add(json_te, "administrativeGroup",
					    iflp->admin_grp);
		if (IS_PARAM_SET(iflp, LP_DELAY)) {
			json_object_int_add(json_te, "linkDelayAverage",
					    iflp->av_delay);
			if (IS_PARAM_SET(iflp, LP_MM_DELAY)) {
				json_object_int_add(json_te, "linkDelayMinimum",
						    iflp->min_delay);
				json_object_int_add(json_te, "linkDelayMaximum",
						    iflp->max_delay);
			}
		}
		if (IS_PARAM_SET(iflp, LP_DELAY_VAR))
			json_object_int_add(json_te, "linkDelayVariation",
					    iflp->delay_var);
		if (IS_PARAM_SET(iflp, LP_PKT_LOSS))
			json_object_double_add(json_te, "linkPacketLoss",
					       (double)iflp->pkt_loss *
						       LOSS_PRECISION);
		if (IS_PARAM_SET(iflp, LP_AVA_BW))
			json_object_double_add(json_te, "availableBandwidth",
					       iflp->ava_bw);
		if (IS_PARAM_SET(iflp, LP_RES_BW))
			json_object_double_add(json_te, "residualBandwidth",
					       iflp->res_bw);
		if (IS_PARAM_SET(iflp, LP_USE_BW))
			json_object_double_add(json_te, "utilizedBandwidth",
					       iflp->use_bw);
		if (IS_PARAM_SET(iflp, LP_RMT_AS))
			json_object_string_addf(json_te, "neighborAsbrIp",
						"%pI4", &iflp->rmt_ip);
		json_object_int_add(json_te, "neighborAsbrAs", iflp->rmt_as);
	}

	if (listhead(ifp->nbr_connected)) {
		json_object *json_nbr_addrs;

		json_nbr_addrs = json_object_new_array();
		json_object_object_add(json_if, "neighborIpAddresses",
				       json_nbr_addrs);

		for (ALL_LIST_ELEMENTS_RO(ifp->nbr_connected, node,
					  nbr_connected))
			nbr_connected_dump_vty(vty, json_nbr_addrs,
					       nbr_connected);
	}

#ifdef HAVE_PROC_NET_DEV
	json_object_int_add(json_if, "inputPackets", stats.rx_packets);
	json_object_int_add(json_if, "inputBytes", ifp->stats.rx_bytes);
	json_object_int_add(json_if, "inputDropped", ifp->stats.rx_dropped);
	json_object_int_add(json_if, "inputMulticastPackets",
			    ifp->stats.rx_multicast);
	json_object_int_add(json_if, "inputErrors", ifp->stats.rx_errors);
	json_object_int_add(json_if, "inputLengthErrors",
			    ifp->stats.rx_length_errors);
	json_object_int_add(json_if, "inputOverrunErrors",
			    ifp->stats.rx_over_errors);
	json_object_int_add(json_if, "inputCrcErrors",
			    ifp->stats.rx_crc_errors);
	json_object_int_add(json_if, "inputFrameErrors",
			    ifp->stats.rx_frame_errors);
	json_object_int_add(json_if, "inputFifoErrors",
			    ifp->stats.rx_fifo_errors);
	json_object_int_add(json_if, "inputMissedErrors",
			    ifp->stats.rx_missed_errors);
	json_object_int_add(json_if, "outputPackets", ifp->stats.tx_packets);
	json_object_int_add(json_if, "outputBytes", ifp->stats.tx_bytes);
	json_object_int_add(json_if, "outputDroppedPackets",
			    ifp->stats.tx_dropped);
	json_object_int_add(json_if, "outputErrors", ifp->stats.tx_errors);
	json_object_int_add(json_if, "outputAbortedErrors",
			    ifp->stats.tx_aborted_errors);
	json_object_int_add(json_if, "outputCarrierErrors",
			    ifp->stats.tx_carrier_errors);
	json_object_int_add(json_if, "outputFifoErrors",
			    ifp->stats.tx_fifo_errors);
	json_object_int_add(json_if, "outputHeartbeatErrors",
			    ifp->stats.tx_heartbeat_errors);
	json_object_int_add(json_if, "outputWindowErrors",
			    ifp->stats.tx_window_errors);
	json_object_int_add(json_if, "collisions", ifp->stats.collisions);
#endif /* HAVE_PROC_NET_DEV */

#ifdef HAVE_NET_RT_IFLIST
	json_object_int_add(json_if, "inputPackets", ifp->stats.ifi_ipackets);
	json_object_int_add(json_if, "inputBytes", ifp->stats.ifi_ibytes);
	json_object_int_add(json_if, "inputDropd", ifp->stats.ifi_iqdrops);
	json_object_int_add(json_if, "inputMulticastPackets",
			    ifp->stats.ifi_imcasts);
	json_object_int_add(json_if, "inputErrors", ifp->stats.ifi_ierrors);
	json_object_int_add(json_if, "outputPackets", ifp->stats.ifi_opackets);
	json_object_int_add(json_if, "outputBytes", ifp->stats.ifi_obytes);
	json_object_int_add(json_if, "outputMulticastPackets",
			    ifp->stats.ifi_omcasts);
	json_object_int_add(json_if, "outputErrors", ifp->stats.ifi_oerrors);
	json_object_int_add(json_if, "collisions", ifp->stats.ifi_collisions);
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

#include "zebra/interface_clippy.c"
/* Show all interfaces to vty. */
DEFPY(show_interface, show_interface_cmd,
      "show interface vrf NAME$vrf_name [brief$brief] [json$uj]",
      SHOW_STR
      "Interface status and configuration\n"
      VRF_CMD_HELP_STR
      "Interface status and configuration summary\n"
      JSON_STR)
{
	struct vrf *vrf;
	struct interface *ifp;
	json_object *json = NULL;

	interface_update_stats();

	vrf = vrf_lookup_by_name(vrf_name);
	if (!vrf) {
		if (uj)
			vty_out(vty, "{}\n");
		else
			vty_out(vty, "%% VRF %s not found\n", vrf_name);
		return CMD_WARNING;
	}

	if (uj)
		json = json_object_new_object();

	if (brief) {
		if (json)
			ifs_dump_brief_vty_json(json, vrf);
		else
			ifs_dump_brief_vty(vty, vrf);
	} else {
		FOR_ALL_INTERFACES (vrf, ifp) {
			if (json)
				if_dump_vty_json(vty, ifp, json);
			else
				if_dump_vty(vty, ifp);
		}
	}

	if (json)
		vty_json(vty, json);

	return CMD_SUCCESS;
}


/* Show all interfaces to vty. */
DEFPY (show_interface_vrf_all,
       show_interface_vrf_all_cmd,
       "show interface [vrf all] [brief$brief] [json$uj]",
       SHOW_STR
       "Interface status and configuration\n"
       VRF_ALL_CMD_HELP_STR
       "Interface status and configuration summary\n"
       JSON_STR)
{
	struct vrf *vrf;
	struct interface *ifp;
	json_object *json = NULL;

	interface_update_stats();

	if (uj)
		json = json_object_new_object();

	/* All interface print. */
	RB_FOREACH (vrf, vrf_name_head, &vrfs_by_name) {
		if (brief) {
			if (json)
				ifs_dump_brief_vty_json(json, vrf);
			else
				ifs_dump_brief_vty(vty, vrf);
		} else {
			FOR_ALL_INTERFACES (vrf, ifp) {
				if (json)
					if_dump_vty_json(vty, ifp, json);
				else
					if_dump_vty(vty, ifp);
			}
		}
	}

	if (json)
		vty_json(vty, json);

	return CMD_SUCCESS;
}

/* Show specified interface to vty. */

DEFPY (show_interface_name_vrf,
       show_interface_name_vrf_cmd,
       "show interface IFNAME$ifname vrf NAME$vrf_name [json$uj]",
       SHOW_STR
       "Interface status and configuration\n"
       "Interface name\n"
       VRF_CMD_HELP_STR
       JSON_STR)
{
	struct interface *ifp;
	struct vrf *vrf;
	json_object *json = NULL;

	interface_update_stats();

	vrf = vrf_lookup_by_name(vrf_name);
	if (!vrf) {
		if (uj)
			vty_out(vty, "{}\n");
		else
			vty_out(vty, "%% VRF %s not found\n", vrf_name);
		return CMD_WARNING;
	}

	ifp = if_lookup_by_name_vrf(ifname, vrf);
	if (ifp == NULL) {
		if (uj)
			vty_out(vty, "{}\n");
		else
			vty_out(vty, "%% Can't find interface %s\n", ifname);
		return CMD_WARNING;
	}

	if (uj)
		json = json_object_new_object();

	if (json)
		if_dump_vty_json(vty, ifp, json);
	else
		if_dump_vty(vty, ifp);

	if (json)
		vty_json(vty, json);

	return CMD_SUCCESS;
}

/* Show specified interface to vty. */
DEFPY (show_interface_name_vrf_all,
       show_interface_name_vrf_all_cmd,
       "show interface IFNAME$ifname [vrf all] [json$uj]",
       SHOW_STR
       "Interface status and configuration\n"
       "Interface name\n"
       VRF_ALL_CMD_HELP_STR
       JSON_STR)
{
	struct interface *ifp = NULL;
	struct interface *ifptmp;
	struct vrf *vrf;
	json_object *json = NULL;
	int count = 0;

	interface_update_stats();

	RB_FOREACH (vrf, vrf_name_head, &vrfs_by_name) {
		ifptmp = if_lookup_by_name_vrf(ifname, vrf);
		if (ifptmp) {
			ifp = ifptmp;
			count++;
			if (!vrf_is_backend_netns())
				break;
		}
	}

	if (ifp == NULL) {
		if (uj)
			vty_out(vty, "{}\n");
		else
			vty_out(vty, "%% Can't find interface %s\n", ifname);
		return CMD_WARNING;
	}
	if (count > 1) {
		if (uj) {
			vty_out(vty, "{}\n");
		} else {
			vty_out(vty,
				"%% There are multiple interfaces with name %s\n",
				ifname);
			vty_out(vty, "%% You must specify the VRF name\n");
		}
		return CMD_WARNING;
	}

	if (uj)
		json = json_object_new_object();

	if (json)
		if_dump_vty_json(vty, ifp, json);
	else
		if_dump_vty(vty, ifp);

	if (json)
		vty_json(vty, json);

	return CMD_SUCCESS;
}

static void if_show_description(struct vty *vty, struct vrf *vrf)
{
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
       "show interface description vrf NAME",
       SHOW_STR
       "Interface status and configuration\n"
       "Interface description\n"
       VRF_CMD_HELP_STR)
{
	struct vrf *vrf;

	vrf = vrf_lookup_by_name(argv[4]->arg);
	if (!vrf) {
		vty_out(vty, "%% VRF %s not found\n", argv[4]->arg);
		return CMD_WARNING;
	}

	if_show_description(vty, vrf);

	return CMD_SUCCESS;
}


DEFUN (show_interface_desc_vrf_all,
       show_interface_desc_vrf_all_cmd,
       "show interface description [vrf all]",
       SHOW_STR
       "Interface status and configuration\n"
       "Interface description\n"
       VRF_ALL_CMD_HELP_STR)
{
	struct vrf *vrf;

	RB_FOREACH (vrf, vrf_name_head, &vrfs_by_name)
		if (!RB_EMPTY(if_name_head, &vrf->ifaces_by_name)) {
			vty_out(vty, "\n\tVRF %s(%u)\n\n", VRF_LOGNAME(vrf),
				vrf->vrf_id);
			if_show_description(vty, vrf);
		}

	return CMD_SUCCESS;
}

void if_arp(struct interface *ifp, bool enable)
{
	int ret;

	if (!CHECK_FLAG(ifp->status, ZEBRA_INTERFACE_ACTIVE))
		return;

	if (enable)
		ret = if_unset_flags(ifp, IFF_NOARP);
	else
		ret = if_set_flags(ifp, IFF_NOARP);

	if (ret < 0) {
		zlog_debug("Can't %sset noarp flag on interface %s",
			   enable ? "" : "un", ifp->name);
		return;
	}

	if_refresh(ifp);
}

int if_multicast_set(struct interface *ifp)
{
	struct zebra_if *if_data;

	if (CHECK_FLAG(ifp->status, ZEBRA_INTERFACE_ACTIVE)) {
		if (if_set_flags(ifp, IFF_MULTICAST) < 0) {
			zlog_debug("Can't set multicast flag on interface %s",
				   ifp->name);
			return -1;
		}
		if_refresh(ifp);
	}
	if_data = ifp->info;
	if_data->multicast = IF_ZEBRA_DATA_ON;

	return 0;
}

int if_multicast_unset(struct interface *ifp)
{
	struct zebra_if *if_data;

	if (CHECK_FLAG(ifp->status, ZEBRA_INTERFACE_ACTIVE)) {
		if (if_unset_flags(ifp, IFF_MULTICAST) < 0) {
			zlog_debug("Can't unset multicast flag on interface %s",
				   ifp->name);
			return -1;
		}
		if_refresh(ifp);
	}
	if_data = ifp->info;
	if_data->multicast = IF_ZEBRA_DATA_OFF;

	return 0;
}

int if_linkdetect(struct interface *ifp, bool detect)
{
	int if_was_operative;

	if_was_operative = if_is_no_ptm_operative(ifp);
	if (detect) {
		SET_FLAG(ifp->status, ZEBRA_INTERFACE_LINKDETECTION);

		/* When linkdetection is enabled, if might come down */
		if (!if_is_no_ptm_operative(ifp) && if_was_operative)
			if_down(ifp);
	} else {
		UNSET_FLAG(ifp->status, ZEBRA_INTERFACE_LINKDETECTION);

		/* Interface may come up after disabling link detection */
		if (if_is_operative(ifp) && !if_was_operative)
			if_up(ifp, true);
	}
	/* FIXME: Will defer status change forwarding if interface
	   does not come down! */
	return 0;
}

int if_shutdown(struct interface *ifp)
{
	struct zebra_if *if_data;

	if (ifp->ifindex != IFINDEX_INTERNAL) {
		/* send RA lifetime of 0 before stopping. rfc4861/6.2.5 */
		rtadv_stop_ra(ifp);
		if (if_unset_flags(ifp, IFF_UP) < 0) {
			zlog_debug("Can't shutdown interface %s", ifp->name);
			return -1;
		}
		if_refresh(ifp);
	}
	if_data = ifp->info;
	if_data->shutdown = IF_ZEBRA_DATA_ON;

	return 0;
}

int if_no_shutdown(struct interface *ifp)
{
	struct zebra_if *if_data;

	if (ifp->ifindex != IFINDEX_INTERNAL) {
		if (if_set_flags(ifp, IFF_UP | IFF_RUNNING) < 0) {
			zlog_debug("Can't up interface %s", ifp->name);
			return -1;
		}
		if_refresh(ifp);

		/* Some addresses (in particular, IPv6 addresses on Linux) get
		 * removed when the interface goes down. They need to be
		 * readded.
		 */
		if_addr_wakeup(ifp);
	}

	if_data = ifp->info;
	if_data->shutdown = IF_ZEBRA_DATA_OFF;

	return 0;
}

void link_param_cmd_set_uint32(struct interface *ifp, uint32_t *field,
			       uint32_t type, uint32_t value)
{
	/* Update field as needed */
	if (IS_PARAM_UNSET(ifp->link_params, type) || *field != value) {
		*field = value;
		SET_PARAM(ifp->link_params, type);
	}
}

void link_param_cmd_set_float(struct interface *ifp, float *field,
			      uint32_t type, float value)
{
	/* Update field as needed */
	if (IS_PARAM_UNSET(ifp->link_params, type) || *field != value) {
		*field = value;
		SET_PARAM(ifp->link_params, type);
	}
}

void link_param_cmd_unset(struct interface *ifp, uint32_t type)
{
	if (ifp->link_params == NULL)
		return;

	/* Unset field */
	UNSET_PARAM(ifp->link_params, type);
}

void if_ip_address_install(struct interface *ifp, struct prefix *prefix,
			   const char *label, struct prefix *pp)
{
	struct zebra_if *if_data;
	struct connected *ifc;

	if_data = ifp->info;

	ifc = connected_check_ptp(ifp, prefix, pp);
	if (!ifc) {
		ifc = connected_new();
		ifc->ifp = ifp;

		/* Address. */
		ifc->address = prefix_new();
		prefix_copy(ifc->address, prefix);

		if (pp) {
			SET_FLAG(ifc->flags, ZEBRA_IFA_PEER);
			ifc->destination = prefix_new();
			prefix_copy(ifc->destination, pp);
		}

		/* Label. */
		if (label)
			ifc->label = XSTRDUP(MTYPE_CONNECTED_LABEL, label);

		/* Add to linked list. */
		if_connected_add_tail(ifp->connected, ifc);
	}

	/* This address is configured from zebra. */
	if (!CHECK_FLAG(ifc->conf, ZEBRA_IFC_CONFIGURED))
		SET_FLAG(ifc->conf, ZEBRA_IFC_CONFIGURED);

	/* In case of this route need to install kernel. */
	if (!CHECK_FLAG(ifc->conf, ZEBRA_IFC_QUEUED) &&
	    CHECK_FLAG(ifp->status, ZEBRA_INTERFACE_ACTIVE) &&
	    !(if_data && if_data->shutdown == IF_ZEBRA_DATA_ON)) {
		/* Some system need to up the interface to set IP address. */
		if (!if_is_up(ifp)) {
			if_set_flags(ifp, IFF_UP | IFF_RUNNING);
			if_refresh(ifp);
		}

		dplane_intf_addr_set(ifp, ifc);

		SET_FLAG(ifc->conf, ZEBRA_IFC_QUEUED);
		/* The address will be advertised to zebra clients when the
		 * notification
		 * from the kernel has been received.
		 * It will also be added to the subnet chain list, then. */
	}
}

void if_ip_address_uninstall(struct interface *ifp, struct prefix *prefix,
			     struct prefix *pp)
{
	struct connected *ifc;

	ifc = connected_check_ptp(ifp, prefix, pp);
	assert(ifc);

	UNSET_FLAG(ifc->conf, ZEBRA_IFC_CONFIGURED);

	/* This is not real address or interface is not active. */
	if (!CHECK_FLAG(ifc->conf, ZEBRA_IFC_QUEUED)
	    || !CHECK_FLAG(ifp->status, ZEBRA_INTERFACE_ACTIVE)) {
		if_connected_del(ifp->connected, ifc);
		connected_free(&ifc);
		return;
	}

	/* This is real route. */
	dplane_intf_addr_unset(ifp, ifc);

	UNSET_FLAG(ifc->conf, ZEBRA_IFC_QUEUED);
}

void if_ipv6_address_install(struct interface *ifp, struct prefix *prefix)
{
	struct zebra_if *if_data;
	struct connected *ifc;

	if_data = ifp->info;

	ifc = connected_check(ifp, prefix);
	if (!ifc) {
		ifc = connected_new();
		ifc->ifp = ifp;

		/* Address. */
		ifc->address = prefix_new();
		prefix_copy(ifc->address, prefix);

		/* Add to linked list. */
		if_connected_add_tail(ifp->connected, ifc);
	}

	/* This address is configured from zebra. */
	if (!CHECK_FLAG(ifc->conf, ZEBRA_IFC_CONFIGURED))
		SET_FLAG(ifc->conf, ZEBRA_IFC_CONFIGURED);

	/* In case of this route need to install kernel. */
	if (!CHECK_FLAG(ifc->conf, ZEBRA_IFC_QUEUED) &&
	    CHECK_FLAG(ifp->status, ZEBRA_INTERFACE_ACTIVE) &&
	    !(if_data && if_data->shutdown == IF_ZEBRA_DATA_ON)) {
		/* Some system need to up the interface to set IP address. */
		if (!if_is_up(ifp)) {
			if_set_flags(ifp, IFF_UP | IFF_RUNNING);
			if_refresh(ifp);
		}

		dplane_intf_addr_set(ifp, ifc);

		SET_FLAG(ifc->conf, ZEBRA_IFC_QUEUED);
		/* The address will be advertised to zebra clients when the
		 * notification
		 * from the kernel has been received. */
	}
}

void if_ipv6_address_uninstall(struct interface *ifp, struct prefix *prefix)
{
	struct connected *ifc;

	ifc = connected_check(ifp, prefix);
	assert(ifc);

	UNSET_FLAG(ifc->conf, ZEBRA_IFC_CONFIGURED);

	/* This is not real address or interface is not active. */
	if (!CHECK_FLAG(ifc->conf, ZEBRA_IFC_QUEUED)
	    || !CHECK_FLAG(ifp->status, ZEBRA_INTERFACE_ACTIVE)) {
		if_connected_del(ifp->connected, ifc);
		connected_free(&ifc);
		return;
	}

	/* This is real route. */
	dplane_intf_addr_unset(ifp, ifc);

	UNSET_FLAG(ifc->conf, ZEBRA_IFC_QUEUED);
}

/* Allocate and initialize interface vector. */
void zebra_if_init(void)
{
	/* Initialize interface and new hook. */
	hook_register_prio(if_add, 0, if_zebra_new_hook);
	hook_register_prio(if_del, 0, if_zebra_delete_hook);

	install_element(VIEW_NODE, &show_interface_cmd);
	install_element(VIEW_NODE, &show_interface_vrf_all_cmd);
	install_element(VIEW_NODE, &show_interface_name_vrf_cmd);
	install_element(VIEW_NODE, &show_interface_name_vrf_all_cmd);

	install_element(ENABLE_NODE, &show_interface_desc_cmd);
	install_element(ENABLE_NODE, &show_interface_desc_vrf_all_cmd);
}
