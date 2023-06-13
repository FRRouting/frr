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
#include "lib/northbound_cli.h"

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
#include "zebra/zebra_evpn_mh.h"

DEFINE_MTYPE_STATIC(ZEBRA, ZINFO, "Zebra Interface Information");

#define ZEBRA_PTM_SUPPORT

DEFINE_HOOK(zebra_if_extra_info, (struct vty * vty, struct interface *ifp),
	    (vty, ifp));
DEFINE_HOOK(zebra_if_config_wr, (struct vty * vty, struct interface *ifp),
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
	if (error < 0)
		return;

	if (new_speed != ifp->speed) {
		zlog_info("%s: %s old speed: %u new speed: %u", __func__,
			  ifp->name, ifp->speed, new_speed);
		ifp->speed = new_speed;
		if_add_update(ifp);
		changed = true;
	}

	if (changed || new_speed == UINT32_MAX) {
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
		if (new_speed == UINT32_MAX &&
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
	zebra_if->ifp = ifp;

	zebra_if->multicast = IF_ZEBRA_DATA_UNSPEC;
	zebra_if->shutdown = IF_ZEBRA_DATA_OFF;

	zebra_if->link_nsid = NS_UNKNOWN;

	zebra_if_nhg_dependents_init(zebra_if);

	zebra_ptm_if_init(zebra_if);

	ifp->ptm_enable = zebra_ptm_get_enable_state();

	rtadv_if_init(zebra_if);

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

static void if_nhg_dependents_check_valid(struct nhg_hash_entry *nhe)
{
	zebra_nhg_check_valid(nhe);
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

		zebra_l2_bridge_if_cleanup(ifp);
		zebra_evpn_if_cleanup(zebra_if);
		zebra_evpn_mac_ifp_del(ifp);

		if_nhg_dependents_release(ifp);
		zebra_if_nhg_dependents_free(zebra_if);

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
	if (ifp->vrf->vrf_id && !vrf_is_backend_netns())
		if_handle_vrf_change(ifp, VRF_DEFAULT);

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
	/* This is to issue an UPDATE or a DELETE, as appropriate. */
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

	if (IS_ZEBRA_IF_VETH(ifp))
		return;
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
		zif = ifp ? ifp->info : NULL;
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
	if (ifp == NULL) {
		if (op != DPLANE_OP_INTF_NETCONFIG ||
		    (ifindex != -1 && ifindex != -2)) {
			if (IS_ZEBRA_DEBUG_KERNEL)
				zlog_debug(
					"%s: can't find ifp at nsid %u index %d",
					__func__, ns_id, ifindex);

			return;
		}
	}

	switch (op) {
	case DPLANE_OP_INTF_ADDR_ADD:
	case DPLANE_OP_INTF_ADDR_DEL:
		zebra_if_addr_update_ctx(ctx, ifp);
		break;

	case DPLANE_OP_INTF_INSTALL:
	case DPLANE_OP_INTF_UPDATE:
	case DPLANE_OP_INTF_DELETE:
		zebra_if_update_ctx(ctx, ifp);
		break;

	case DPLANE_OP_INTF_NETCONFIG:
		zebra_if_netconf_update_ctx(ctx, ifp, ifindex);
		break;

	case DPLANE_OP_ROUTE_INSTALL:
	case DPLANE_OP_ROUTE_UPDATE:
	case DPLANE_OP_ROUTE_DELETE:
	case DPLANE_OP_NH_DELETE:
	case DPLANE_OP_NH_INSTALL:
	case DPLANE_OP_NH_UPDATE:
	case DPLANE_OP_ROUTE_NOTIFY:
	case DPLANE_OP_LSP_INSTALL:
	case DPLANE_OP_LSP_UPDATE:
	case DPLANE_OP_LSP_DELETE:
	case DPLANE_OP_LSP_NOTIFY:
	case DPLANE_OP_PW_INSTALL:
	case DPLANE_OP_PW_UNINSTALL:
	case DPLANE_OP_SYS_ROUTE_ADD:
	case DPLANE_OP_SYS_ROUTE_DELETE:
	case DPLANE_OP_ADDR_INSTALL:
	case DPLANE_OP_ADDR_UNINSTALL:
	case DPLANE_OP_MAC_INSTALL:
	case DPLANE_OP_MAC_DELETE:
	case DPLANE_OP_NEIGH_INSTALL:
	case DPLANE_OP_NEIGH_UPDATE:
	case DPLANE_OP_NEIGH_DELETE:
	case DPLANE_OP_NEIGH_IP_INSTALL:
	case DPLANE_OP_NEIGH_IP_DELETE:
	case DPLANE_OP_VTEP_ADD:
	case DPLANE_OP_VTEP_DELETE:
	case DPLANE_OP_RULE_ADD:
	case DPLANE_OP_RULE_DELETE:
	case DPLANE_OP_RULE_UPDATE:
	case DPLANE_OP_NEIGH_DISCOVER:
	case DPLANE_OP_BR_PORT_UPDATE:
	case DPLANE_OP_NONE:
	case DPLANE_OP_IPTABLE_ADD:
	case DPLANE_OP_IPTABLE_DELETE:
	case DPLANE_OP_IPSET_ADD:
	case DPLANE_OP_IPSET_DELETE:
	case DPLANE_OP_IPSET_ENTRY_ADD:
	case DPLANE_OP_IPSET_ENTRY_DELETE:
	case DPLANE_OP_NEIGH_TABLE_UPDATE:
	case DPLANE_OP_GRE_SET:
	case DPLANE_OP_TC_QDISC_INSTALL:
	case DPLANE_OP_TC_QDISC_UNINSTALL:
	case DPLANE_OP_TC_CLASS_ADD:
	case DPLANE_OP_TC_CLASS_DELETE:
	case DPLANE_OP_TC_CLASS_UPDATE:
	case DPLANE_OP_TC_FILTER_ADD:
	case DPLANE_OP_TC_FILTER_DELETE:
	case DPLANE_OP_TC_FILTER_UPDATE:
		break; /* should never hit here */
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

	case ZEBRA_IF_BOND_SLAVE:
		return "bond_slave";

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
					if (first_pfx_printed) {
						/* padding to prepare row only
						 * for ip addr */
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
		}
		if (!first_pfx_printed)
			vty_out(vty, "\n");
	}
	vty_out(vty, "\n");
}

static void ifs_dump_brief_vty_json(json_object *json, struct vrf *vrf)
{
	struct connected *connected;
	struct listnode *node;
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
		for (ALL_LIST_ELEMENTS_RO(ifp->connected, node, connected)) {
			if (CHECK_FLAG(connected->conf, ZEBRA_IFC_REAL)
			    && !CHECK_FLAG(connected->flags,
					   ZEBRA_IFA_SECONDARY)
			    && !(connected->address->family == AF_INET6
				 && IN6_IS_ADDR_LINKLOCAL(
					 &connected->address->u.prefix6))) {
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

	vty_out(vty, "  index %d metric %d mtu %d speed %u ", ifp->ifindex,
		ifp->metric, ifp->mtu, ifp->speed);
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

	for (ALL_LIST_ELEMENTS_RO(ifp->connected, node, connected)) {
		if (CHECK_FLAG(connected->conf, ZEBRA_IFC_REAL)
		    && (connected->address->family == AF_INET6))
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

	zebra_ptm_show_status(vty, json, ifp);

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

	for (ALL_LIST_ELEMENTS_RO(ifp->connected, node, connected)) {
		if (CHECK_FLAG(connected->conf, ZEBRA_IFC_REAL)
		    && (connected->address->family == AF_INET6))
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
					       iflp->pkt_loss);
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
	if_data->multicast = IF_ZEBRA_DATA_ON;

	return CMD_SUCCESS;
}

DEFPY (mpls,
       mpls_cmd,
       "[no] mpls enable",
       NO_STR
       MPLS_STR
       "Set mpls to be on for the interface\n")
{
	VTY_DECLVAR_CONTEXT(interface, ifp);
	struct zebra_if *if_data = ifp->info;

	if (no) {
		dplane_intf_mpls_modify_state(ifp, false);
		if_data->mpls = IF_ZEBRA_DATA_UNSPEC;
	} else {
		dplane_intf_mpls_modify_state(ifp, true);
		if_data->mpls = IF_ZEBRA_DATA_ON;
	}

	return CMD_SUCCESS;
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
	if_data->multicast = IF_ZEBRA_DATA_OFF;

	return CMD_SUCCESS;
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

DEFUN(linkdetect, linkdetect_cmd, "link-detect",
      "Enable link detection on interface\n")
{
	VTY_DECLVAR_CONTEXT(interface, ifp);

	if_linkdetect(ifp, true);

	return CMD_SUCCESS;
}


DEFUN (no_linkdetect,
       no_linkdetect_cmd,
       "no link-detect",
       NO_STR
       "Disable link detection on interface\n")
{
	VTY_DECLVAR_CONTEXT(interface, ifp);

	if_linkdetect(ifp, false);

	return CMD_SUCCESS;
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

DEFUN (shutdown_if,
       shutdown_if_cmd,
       "shutdown",
       "Shutdown the selected interface\n")
{
	VTY_DECLVAR_CONTEXT(interface, ifp);
	int ret;
	struct zebra_if *if_data;

	if (ifp->ifindex != IFINDEX_INTERNAL) {
		/* send RA lifetime of 0 before stopping. rfc4861/6.2.5 */
		rtadv_stop_ra(ifp);
		ret = if_unset_flags(ifp, IFF_UP);
		if (ret < 0) {
			vty_out(vty, "Can't shutdown interface\n");
			return CMD_WARNING_CONFIG_FAILED;
		}
		if_refresh(ifp);
	}
	if_data = ifp->info;
	if_data->shutdown = IF_ZEBRA_DATA_ON;

	return CMD_SUCCESS;
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
	if_data->shutdown = IF_ZEBRA_DATA_OFF;

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
	.name = "link-params",
	.node = LINK_PARAMS_NODE,
	.parent_node = INTERFACE_NODE,
	.prompt = "%s(config-link-params)# ",
	.no_xpath = true,
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

	if (!if_link_params_get(ifp))
		if_link_params_enable(ifp);

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
	char xpath[XPATH_MAXLEN];
	int ret;
	VTY_DECLVAR_CONTEXT(interface, ifp);

	if (IS_ZEBRA_DEBUG_EVENT || IS_ZEBRA_DEBUG_MPLS)
		zlog_debug("MPLS-TE: disable TE link parameters on interface %s",
			   ifp->name);

	if_link_params_free(ifp);

	snprintf(
		xpath, sizeof(xpath),
		"/frr-interface:lib/interface[name='%s']/frr-zebra:zebra/link-params/affinities",
		ifp->name);
	if (yang_dnode_exists(running_config->dnode, xpath))
		nb_cli_enqueue_change(vty, xpath, NB_OP_DESTROY, NULL);

	ret = nb_cli_apply_changes(vty, NULL);

	if (ret != CMD_SUCCESS)
		return ret;

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

	if (!iflp)
		iflp = if_link_params_enable(ifp);

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
	if (iflp && ((bw <= iflp->max_rsv_bw) || (bw <= iflp->unrsv_bw[0]) ||
		     (bw <= iflp->unrsv_bw[1]) || (bw <= iflp->unrsv_bw[2]) ||
		     (bw <= iflp->unrsv_bw[3]) || (bw <= iflp->unrsv_bw[4]) ||
		     (bw <= iflp->unrsv_bw[5]) || (bw <= iflp->unrsv_bw[6]) ||
		     (bw <= iflp->unrsv_bw[7]) || (bw <= iflp->ava_bw) ||
		     (bw <= iflp->res_bw) || (bw <= iflp->use_bw))) {
		vty_out(vty,
			"Maximum Bandwidth could not be lower than others bandwidth\n");
		return CMD_WARNING_CONFIG_FAILED;
	}

	if (!iflp)
		iflp = if_link_params_enable(ifp);

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
	if (iflp && bw > iflp->max_bw) {
		vty_out(vty,
			"Maximum Reservable Bandwidth could not be greater than Maximum Bandwidth (%g)\n",
			iflp->max_bw);
		return CMD_WARNING_CONFIG_FAILED;
	}

	if (!iflp)
		iflp = if_link_params_enable(ifp);

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
	if (iflp && bw > iflp->max_bw) {
		vty_out(vty,
			"UnReserved Bandwidth could not be greater than Maximum Bandwidth (%g)\n",
			iflp->max_bw);
		return CMD_WARNING_CONFIG_FAILED;
	}

	if (!iflp)
		iflp = if_link_params_enable(ifp);

	/* Update Unreserved Bandwidth if needed */
	link_param_cmd_set_float(ifp, &iflp->unrsv_bw[priority], LP_UNRSV_BW,
				 bw);

	return CMD_SUCCESS;
}

DEFPY_YANG(link_params_admin_grp, link_params_admin_grp_cmd,
	   "admin-grp BITPATTERN",
	   "Administrative group membership\n"
	   "32-bit Hexadecimal value (e.g. 0xa1)\n")
{
	char xpath[XPATH_MAXLEN];
	int idx_bitpattern = 1;
	unsigned long value;
	char value_str[11];

	VTY_DECLVAR_CONTEXT(interface, ifp);

	snprintf(
		xpath, sizeof(xpath),
		"/frr-interface:lib/interface[name='%s']/frr-zebra:zebra/link-params/affinities",
		ifp->name);
	if (yang_dnode_exists(running_config->dnode, xpath)) {
		vty_out(vty,
			"cannot use the admin-grp command when affinity is set\n");
		return CMD_WARNING_CONFIG_FAILED;
	}

	if (sscanf(argv[idx_bitpattern]->arg, "0x%lx", &value) != 1) {
		vty_out(vty, "link_params_admin_grp: fscanf: %s\n",
			safe_strerror(errno));
		return CMD_WARNING_CONFIG_FAILED;
	}

	if (value > 0xFFFFFFFF) {
		vty_out(vty, "value must be not be superior to 0xFFFFFFFF\n");
		return CMD_WARNING_CONFIG_FAILED;
	}

	snprintf(value_str, sizeof(value_str), "%ld", value);

	nb_cli_enqueue_change(
		vty, "./frr-zebra:zebra/link-params/legacy-admin-group",
		NB_OP_MODIFY, value_str);

	return nb_cli_apply_changes(vty, NULL);
}

DEFPY_YANG(no_link_params_admin_grp, no_link_params_admin_grp_cmd,
	   "no admin-grp",
	   NO_STR "Disable Administrative group membership on this interface\n")
{
	nb_cli_enqueue_change(
		vty, "./frr-zebra:zebra/link-params/legacy-admin-group",
		NB_OP_DESTROY, NULL);

	return nb_cli_apply_changes(vty, NULL);
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

	if (!iflp)
		iflp = if_link_params_enable(ifp);

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

	if (!iflp)
		return CMD_SUCCESS;

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
		/*
		 * Check new delay value against old Min and Max delays if set
		 *
		 * RFC 7471 Section 4.2.7:
		 *    It is possible for min delay and max delay to be
		 *    the same value.
		 *
		 * Therefore, it is also allowed that the average
		 * delay be equal to the min delay or max delay.
		 */
		if (iflp && IS_PARAM_SET(iflp, LP_MM_DELAY) &&
		    (delay < iflp->min_delay || delay > iflp->max_delay)) {
			vty_out(vty,
				"Average delay should be in range Min (%d) - Max (%d) delay\n",
				iflp->min_delay, iflp->max_delay);
			return CMD_WARNING_CONFIG_FAILED;
		}

		if (!iflp)
			iflp = if_link_params_enable(ifp);

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
		/*
		 * Check new delays value coherency. See above note
		 * regarding average delay equal to min/max allowed
		 */
		if (delay < low || delay > high) {
			vty_out(vty,
				"Average delay should be in range Min (%d) - Max (%d) delay\n",
				low, high);
			return CMD_WARNING_CONFIG_FAILED;
		}

		if (!iflp)
			iflp = if_link_params_enable(ifp);

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

	if (!iflp)
		return CMD_SUCCESS;

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

	if (!iflp)
		iflp = if_link_params_enable(ifp);

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

	if (!iflp)
		iflp = if_link_params_enable(ifp);

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
	if (iflp && bw > iflp->max_bw) {
		vty_out(vty,
			"Residual Bandwidth could not be greater than Maximum Bandwidth (%g)\n",
			iflp->max_bw);
		return CMD_WARNING_CONFIG_FAILED;
	}

	if (!iflp)
		iflp = if_link_params_enable(ifp);

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
	if (iflp && bw > iflp->max_bw) {
		vty_out(vty,
			"Available Bandwidth could not be greater than Maximum Bandwidth (%g)\n",
			iflp->max_bw);
		return CMD_WARNING_CONFIG_FAILED;
	}

	if (!iflp)
		iflp = if_link_params_enable(ifp);

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
	if (iflp && bw > iflp->max_bw) {
		vty_out(vty,
			"Utilised Bandwidth could not be greater than Maximum Bandwidth (%g)\n",
			iflp->max_bw);
		return CMD_WARNING_CONFIG_FAILED;
	}

	if (!iflp)
		iflp = if_link_params_enable(ifp);

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

static int ag_change(struct vty *vty, int argc, struct cmd_token **argv,
		     const char *xpath, bool no, int start_idx)
{
	for (int i = start_idx; i < argc; i++)
		nb_cli_enqueue_change(vty, xpath,
				      no ? NB_OP_DESTROY : NB_OP_CREATE,
				      argv[i]->arg);
	return nb_cli_apply_changes(vty, NULL);
}

/*
 * XPath:
 * /frr-interface:lib/interface/frr-zebra:zebra/link-params/affinities/affinity
 */
DEFPY_YANG(link_params_affinity, link_params_affinity_cmd,
	   "[no] affinity NAME...",
	   NO_STR
	   "Interface affinities\n"
	   "Affinity names\n")
{
	VTY_DECLVAR_CONTEXT(interface, ifp);
	char xpath[XPATH_MAXLEN];

	snprintf(
		xpath, sizeof(xpath),
		"/frr-interface:lib/interface[name='%s']/frr-zebra:zebra/link-params/legacy-admin-group",
		ifp->name);
	if (yang_dnode_exists(running_config->dnode, xpath)) {
		vty_out(vty,
			"cannot use the affinity command when admin-grp is set\n");
		return CMD_WARNING_CONFIG_FAILED;
	}

	return ag_change(vty, argc, argv,
			 "./frr-zebra:zebra/link-params/affinities/affinity",
			 no, no ? 2 : 1);
}


/*
 * XPath:
 * /frr-interface:lib/interface/frr-zebra:zebra/link-params/affinities/affinity-mode
 */
DEFPY_YANG(link_params_affinity_mode, link_params_affinity_mode_cmd,
	   "affinity-mode <standard|extended|both>$affmode",
	   "Interface affinity mode\n"
	   "Standard Admin-Group only RFC3630,5305,5329 (default)\n"
	   "Extended Admin-Group only RFC7308\n"
	   "Standard and extended Admin-Group format\n")
{
	const char *xpath = "./frr-zebra:zebra/link-params/affinity-mode";

	nb_cli_enqueue_change(vty, xpath, NB_OP_MODIFY, affmode);

	return nb_cli_apply_changes(vty, NULL);
}

DEFPY_YANG(no_link_params_affinity_mode, no_link_params_affinity_mode_cmd,
	   "no affinity-mode [<standard|extended|both>]",
	   NO_STR
	   "Interface affinity mode\n"
	   "Standard Admin-Group only RFC3630,5305,5329 (default)\n"
	   "Extended Admin-Group only RFC7308\n"
	   "Standard and extended Admin-Group format\n")
{
	const char *xpath = "./frr-zebra:zebra/link-params/affinity-mode";

	nb_cli_enqueue_change(vty, xpath, NB_OP_MODIFY, "standard");

	return nb_cli_apply_changes(vty, NULL);
}

static int ag_iter_cb(const struct lyd_node *dnode, void *arg)
{
	struct vty *vty = (struct vty *)arg;

	vty_out(vty, " %s", yang_dnode_get_string(dnode, "."));
	return YANG_ITER_CONTINUE;
}

void cli_show_legacy_admin_group(struct vty *vty, const struct lyd_node *dnode,
				 bool show_defaults)
{
	if (!yang_dnode_exists(dnode, "./legacy-admin-group"))
		return;

	vty_out(vty, "  admin-group 0x%x\n",
		yang_dnode_get_uint32(dnode, "./legacy-admin-group"));
}

void cli_show_affinity_mode(struct vty *vty, const struct lyd_node *dnode,
			    bool show_defaults)
{
	enum affinity_mode affinity_mode = yang_dnode_get_enum(dnode, ".");

	if (affinity_mode == AFFINITY_MODE_STANDARD)
		vty_out(vty, "  affinity-mode standard\n");
	else if (affinity_mode == AFFINITY_MODE_BOTH)
		vty_out(vty, "  affinity-mode both\n");
}

void cli_show_affinity(struct vty *vty, const struct lyd_node *dnode,
		       bool show_defaults)
{
	if (!yang_dnode_exists(dnode, "./affinity"))
		return;

	vty_out(vty, "  affinity");
	yang_dnode_iterate(ag_iter_cb, vty, dnode, "./affinity");
	vty_out(vty, "\n");
}

int if_ip_address_install(struct interface *ifp, struct prefix *prefix,
			  const char *label, struct prefix *pp)
{
	struct zebra_if *if_data;
	struct prefix_ipv4 lp;
	struct prefix_ipv4 *p;
	struct connected *ifc;
	enum zebra_dplane_result dplane_res;

	if_data = ifp->info;

	lp.family = prefix->family;
	lp.prefix = prefix->u.prefix4;
	lp.prefixlen = prefix->prefixlen;
	apply_mask_ipv4(&lp);

	ifc = connected_check_ptp(ifp, &lp, pp ? pp : NULL);
	if (!ifc) {
		ifc = connected_new();
		ifc->ifp = ifp;

		/* Address. */
		p = prefix_ipv4_new();
		*p = lp;
		ifc->address = (struct prefix *)p;

		if (pp) {
			SET_FLAG(ifc->flags, ZEBRA_IFA_PEER);
			p = prefix_ipv4_new();
			*p = *(struct prefix_ipv4 *)pp;
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
	if (!CHECK_FLAG(ifc->conf, ZEBRA_IFC_QUEUED) &&
	    CHECK_FLAG(ifp->status, ZEBRA_INTERFACE_ACTIVE) &&
	    !(if_data && if_data->shutdown == IF_ZEBRA_DATA_ON)) {
		/* Some system need to up the interface to set IP address. */
		if (!if_is_up(ifp)) {
			if_set_flags(ifp, IFF_UP | IFF_RUNNING);
			if_refresh(ifp);
		}

		dplane_res = dplane_intf_addr_set(ifp, ifc);
		if (dplane_res == ZEBRA_DPLANE_REQUEST_FAILURE) {
			zlog_debug(
				"dplane can't set interface IP address: %s.",
				dplane_res2str(dplane_res));
			return NB_ERR;
		}

		SET_FLAG(ifc->conf, ZEBRA_IFC_QUEUED);
		/* The address will be advertised to zebra clients when the
		 * notification
		 * from the kernel has been received.
		 * It will also be added to the subnet chain list, then. */
	}

	return 0;
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
		if (lp.prefixlen != IPV4_MAX_BITLEN) {
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
	if (!CHECK_FLAG(ifc->conf, ZEBRA_IFC_QUEUED) &&
	    CHECK_FLAG(ifp->status, ZEBRA_INTERFACE_ACTIVE) &&
	    !(if_data && if_data->shutdown == IF_ZEBRA_DATA_ON)) {
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

int if_ip_address_uinstall(struct interface *ifp, struct prefix *prefix)
{
	struct connected *ifc = NULL;
	enum zebra_dplane_result dplane_res;

	if (prefix->family == AF_INET) {
		/* Check current interface address. */
		ifc = connected_check_ptp(ifp, prefix, NULL);
		if (!ifc) {
			zlog_debug("interface %s Can't find address",
				   ifp->name);
			return -1;
		}

	} else if (prefix->family == AF_INET6) {
		/* Check current interface address. */
		ifc = connected_check(ifp, prefix);
	}

	if (!ifc) {
		zlog_debug("interface %s Can't find address", ifp->name);
		return -1;
	}
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
		zlog_debug("Can't unset interface IP address: %s.",
			   dplane_res2str(dplane_res));
		return -1;
	}
	UNSET_FLAG(ifc->conf, ZEBRA_IFC_QUEUED);

	return 0;
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
		if (lp.prefixlen != IPV4_MAX_BITLEN) {
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

int if_ipv6_address_install(struct interface *ifp, struct prefix *prefix,
			    const char *label)
{
	struct zebra_if *if_data;
	struct prefix_ipv6 cp;
	struct connected *ifc;
	struct prefix_ipv6 *p;
	enum zebra_dplane_result dplane_res;

	if_data = ifp->info;

	cp.family = prefix->family;
	cp.prefixlen = prefix->prefixlen;
	cp.prefix = prefix->u.prefix6;
	apply_mask_ipv6(&cp);

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
	if (!CHECK_FLAG(ifc->conf, ZEBRA_IFC_QUEUED) &&
	    CHECK_FLAG(ifp->status, ZEBRA_INTERFACE_ACTIVE) &&
	    !(if_data && if_data->shutdown == IF_ZEBRA_DATA_ON)) {
		/* Some system need to up the interface to set IP address. */
		if (!if_is_up(ifp)) {
			if_set_flags(ifp, IFF_UP | IFF_RUNNING);
			if_refresh(ifp);
		}

		dplane_res = dplane_intf_addr_set(ifp, ifc);
		if (dplane_res == ZEBRA_DPLANE_REQUEST_FAILURE) {
			zlog_debug(
				"dplane can't set interface IP address: %s.",
				dplane_res2str(dplane_res));
			return NB_ERR;
		}

		SET_FLAG(ifc->conf, ZEBRA_IFC_QUEUED);
		/* The address will be advertised to zebra clients when the
		 * notification
		 * from the kernel has been received. */
	}

	return 0;
}

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
	if (!CHECK_FLAG(ifc->conf, ZEBRA_IFC_QUEUED) &&
	    CHECK_FLAG(ifp->status, ZEBRA_INTERFACE_ACTIVE) &&
	    !(if_data && if_data->shutdown == IF_ZEBRA_DATA_ON)) {
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
	const struct lyd_node *dnode;
	char xpath[XPATH_MAXLEN];
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

	snprintf(
		xpath, sizeof(xpath),
		"/frr-interface:lib/interface[name='%s']/frr-zebra:zebra/link-params",
		ifp->name);
	dnode = yang_dnode_get(running_config->dnode, xpath);
	if (dnode)
		nb_cli_show_dnode_cmds(vty, dnode, false);

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
		vty_out(vty, "  neighbor %pI4 as %u\n", &iflp->rmt_ip,
			iflp->rmt_as);

	vty_out(vty, " exit-link-params\n");
	return 0;
}

static int if_config_write(struct vty *vty)
{
	struct vrf *vrf;
	struct interface *ifp;

	zebra_ptm_write(vty);

	RB_FOREACH (vrf, vrf_name_head, &vrfs_by_name)
		FOR_ALL_INTERFACES (vrf, ifp) {
			struct zebra_if *if_data;
			struct listnode *addrnode;
			struct connected *ifc;
			struct prefix *p;

			if_data = ifp->info;

			if_vty_config_start(vty, ifp);

			if (if_data) {
				if (if_data->shutdown == IF_ZEBRA_DATA_ON)
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
				if (if_data->multicast != IF_ZEBRA_DATA_UNSPEC)
					vty_out(vty, " %smulticast\n",
						if_data->multicast ==
								IF_ZEBRA_DATA_ON
							? ""
							: "no ");
				if (if_data->mpls == IF_ZEBRA_DATA_ON)
					vty_out(vty, " mpls enable\n");
			}

			hook_call(zebra_if_config_wr, vty, ifp);
			zebra_evpn_mh_if_write(vty, ifp);
			link_params_config_write(vty, ifp);

			if_vty_config_end(vty);
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
	if_cmd_init(if_config_write);
	install_node(&link_params_node);
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
	install_element(INTERFACE_NODE, &mpls_cmd);
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
	install_element(LINK_PARAMS_NODE, &link_params_affinity_cmd);
	install_element(LINK_PARAMS_NODE, &link_params_affinity_mode_cmd);
	install_element(LINK_PARAMS_NODE, &no_link_params_affinity_mode_cmd);
	install_element(LINK_PARAMS_NODE, &exit_link_params_cmd);

	/* setup EVPN MH elements */
	zebra_evpn_interface_init();
}
