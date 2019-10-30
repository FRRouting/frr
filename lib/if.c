/*
 * Interface functions.
 * Copyright (C) 1997, 98 Kunihiro Ishiguro
 *
 * This file is part of GNU Zebra.
 *
 * GNU Zebra is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published
 * by the Free Software Foundation; either version 2, or (at your
 * option) any later version.
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

#include "linklist.h"
#include "vector.h"
#include "lib_errors.h"
#include "vty.h"
#include "command.h"
#include "vrf.h"
#include "if.h"
#include "sockunion.h"
#include "prefix.h"
#include "memory.h"
#include "table.h"
#include "buffer.h"
#include "log.h"
#include "northbound_cli.h"
#ifndef VTYSH_EXTRACT_PL
#include "lib/if_clippy.c"
#endif

DEFINE_MTYPE_STATIC(LIB, IF, "Interface")
DEFINE_MTYPE_STATIC(LIB, CONNECTED, "Connected")
DEFINE_MTYPE_STATIC(LIB, NBR_CONNECTED, "Neighbor Connected")
DEFINE_MTYPE(LIB, CONNECTED_LABEL, "Connected interface label")
DEFINE_MTYPE_STATIC(LIB, IF_LINK_PARAMS, "Informational Link Parameters")

static struct interface *if_lookup_by_ifindex(ifindex_t ifindex,
					      vrf_id_t vrf_id);
static int if_cmp_func(const struct interface *, const struct interface *);
static int if_cmp_index_func(const struct interface *ifp1,
			     const struct interface *ifp2);
RB_GENERATE(if_name_head, interface, name_entry, if_cmp_func);
RB_GENERATE(if_index_head, interface, index_entry, if_cmp_index_func);

DEFINE_QOBJ_TYPE(interface)

DEFINE_HOOK(if_add, (struct interface * ifp), (ifp))
DEFINE_KOOH(if_del, (struct interface * ifp), (ifp))

struct interface_master{
	int (*create_hook)(struct interface *ifp);
	int (*up_hook)(struct interface *ifp);
	int (*down_hook)(struct interface *ifp);
	int (*destroy_hook)(struct interface *ifp);
} ifp_master = { 0, };

/* Compare interface names, returning an integer greater than, equal to, or
 * less than 0, (following the strcmp convention), according to the
 * relationship between ifp1 and ifp2.  Interface names consist of an
 * alphabetic prefix and a numeric suffix.  The primary sort key is
 * lexicographic by name, and then numeric by number.  No number sorts
 * before all numbers.  Examples: de0 < de1, de100 < fxp0 < xl0, devpty <
 * devpty0, de0 < del0
 */
int if_cmp_name_func(const char *p1, const char *p2)
{
	unsigned int l1, l2;
	long int x1, x2;
	int res;

	while (*p1 && *p2) {
		/* look up to any number */
		l1 = strcspn(p1, "0123456789");
		l2 = strcspn(p2, "0123456789");

		/* name lengths are different -> compare names */
		if (l1 != l2)
			return (strcmp(p1, p2));

		/* Note that this relies on all numbers being less than all
		 * letters, so
		 * that de0 < del0.
		 */
		res = strncmp(p1, p2, l1);

		/* names are different -> compare them */
		if (res)
			return res;

		/* with identical name part, go to numeric part */
		p1 += l1;
		p2 += l1;

		if (!*p1 && !*p2)
			return 0;
		if (!*p1)
			return -1;
		if (!*p2)
			return 1;

		x1 = strtol(p1, (char **)&p1, 10);
		x2 = strtol(p2, (char **)&p2, 10);

		/* let's compare numbers now */
		if (x1 < x2)
			return -1;
		if (x1 > x2)
			return 1;

		/* numbers were equal, lets do it again..
		(it happens with name like "eth123.456:789") */
	}
	if (*p1)
		return 1;
	if (*p2)
		return -1;
	return 0;
}

static int if_cmp_func(const struct interface *ifp1,
		       const struct interface *ifp2)
{
	return if_cmp_name_func(ifp1->name, ifp2->name);
}

static int if_cmp_index_func(const struct interface *ifp1,
			     const struct interface *ifp2)
{
	return ifp1->ifindex - ifp2->ifindex;
}

static void ifp_connected_free(void *arg)
{
	struct connected *c = arg;

	connected_free(&c);
}

/* Create new interface structure. */
static struct interface *if_new(vrf_id_t vrf_id)
{
	struct interface *ifp;

	ifp = XCALLOC(MTYPE_IF, sizeof(struct interface));

	ifp->ifindex = IFINDEX_INTERNAL;
	ifp->name[0] = '\0';

	ifp->vrf_id = vrf_id;

	ifp->connected = list_new();
	ifp->connected->del = ifp_connected_free;

	ifp->nbr_connected = list_new();
	ifp->nbr_connected->del = (void (*)(void *))nbr_connected_free;

	/* Enable Link-detection by default */
	SET_FLAG(ifp->status, ZEBRA_INTERFACE_LINKDETECTION);

	QOBJ_REG(ifp, interface);
	return ifp;
}

void if_new_via_zapi(struct interface *ifp)
{
	if (ifp_master.create_hook)
		(*ifp_master.create_hook)(ifp);
}

void if_destroy_via_zapi(struct interface *ifp)
{
	if (ifp_master.destroy_hook)
		(*ifp_master.destroy_hook)(ifp);

	if_set_index(ifp, IFINDEX_INTERNAL);
	if (!ifp->configured)
		if_delete(&ifp);
}

void if_up_via_zapi(struct interface *ifp)
{
	if (ifp_master.up_hook)
		(*ifp_master.up_hook)(ifp);
}

void if_down_via_zapi(struct interface *ifp)
{
	if (ifp_master.down_hook)
		(*ifp_master.down_hook)(ifp);
}

struct interface *if_create_name(const char *name, vrf_id_t vrf_id)
{
	struct interface *ifp;

	ifp = if_new(vrf_id);

	if_set_name(ifp, name);

	hook_call(if_add, ifp);
	return ifp;
}

struct interface *if_create_ifindex(ifindex_t ifindex, vrf_id_t vrf_id)
{
	struct interface *ifp;

	ifp = if_new(vrf_id);

	if_set_index(ifp, ifindex);

	hook_call(if_add, ifp);
	return ifp;
}

/* Create new interface structure. */
void if_update_to_new_vrf(struct interface *ifp, vrf_id_t vrf_id)
{
	struct vrf *old_vrf, *vrf;

	/* remove interface from old master vrf list */
	old_vrf = vrf_lookup_by_id(ifp->vrf_id);
	if (old_vrf) {
		if (ifp->name[0] != '\0')
			IFNAME_RB_REMOVE(old_vrf, ifp);

		if (ifp->ifindex != IFINDEX_INTERNAL)
			IFINDEX_RB_REMOVE(old_vrf, ifp);
	}

	ifp->vrf_id = vrf_id;
	vrf = vrf_get(ifp->vrf_id, NULL);

	if (ifp->name[0] != '\0')
		IFNAME_RB_INSERT(vrf, ifp);

	if (ifp->ifindex != IFINDEX_INTERNAL)
		IFINDEX_RB_INSERT(vrf, ifp);

	/*
	 * HACK: Change the interface VRF in the running configuration directly,
	 * bypassing the northbound layer. This is necessary to avoid deleting
	 * the interface and readding it in the new VRF, which would have
	 * several implications.
	 */
	if (yang_module_find("frr-interface")) {
		struct lyd_node *if_dnode;

		if_dnode = yang_dnode_get(
			running_config->dnode,
			"/frr-interface:lib/interface[name='%s'][vrf='%s']/vrf",
			ifp->name, old_vrf->name);
		if (if_dnode) {
			yang_dnode_change_leaf(if_dnode, vrf->name);
			running_config->version++;
		}
	}
}


/* Delete interface structure. */
void if_delete_retain(struct interface *ifp)
{
	hook_call(if_del, ifp);
	QOBJ_UNREG(ifp);

	/* Free connected address list */
	list_delete_all_node(ifp->connected);

	/* Free connected nbr address list */
	list_delete_all_node(ifp->nbr_connected);
}

/* Delete and free interface structure. */
void if_delete(struct interface **ifp)
{
	struct interface *ptr = *ifp;
	struct vrf *vrf;

	vrf = vrf_lookup_by_id(ptr->vrf_id);
	assert(vrf);

	IFNAME_RB_REMOVE(vrf, ptr);
	if (ptr->ifindex != IFINDEX_INTERNAL)
		IFINDEX_RB_REMOVE(vrf, ptr);

	if_delete_retain(ptr);

	list_delete(&ptr->connected);
	list_delete(&ptr->nbr_connected);

	if_link_params_free(ptr);

	XFREE(MTYPE_TMP, ptr->desc);

	XFREE(MTYPE_IF, ptr);
	*ifp = NULL;
}

/* Used only internally to check within VRF only */
static struct interface *if_lookup_by_ifindex(ifindex_t ifindex,
					      vrf_id_t vrf_id)
{
	struct vrf *vrf;
	struct interface if_tmp;

	vrf = vrf_lookup_by_id(vrf_id);
	if (!vrf)
		return NULL;

	if_tmp.ifindex = ifindex;
	return RB_FIND(if_index_head, &vrf->ifaces_by_index, &if_tmp);
}

/* Interface existance check by index. */
struct interface *if_lookup_by_index(ifindex_t ifindex, vrf_id_t vrf_id)
{
	switch (vrf_get_backend()) {
	case VRF_BACKEND_UNKNOWN:
	case VRF_BACKEND_NETNS:
		return(if_lookup_by_ifindex(ifindex, vrf_id));
	case VRF_BACKEND_VRF_LITE:
		return(if_lookup_by_index_all_vrf(ifindex));
	}
	return NULL;
}

const char *ifindex2ifname(ifindex_t ifindex, vrf_id_t vrf_id)
{
	struct interface *ifp;

	return ((ifp = if_lookup_by_index(ifindex, vrf_id)) != NULL)
		       ? ifp->name
		       : "unknown";
}

ifindex_t ifname2ifindex(const char *name, vrf_id_t vrf_id)
{
	struct interface *ifp;

	return ((ifp = if_lookup_by_name(name, vrf_id)) != NULL)
		       ? ifp->ifindex
		       : IFINDEX_INTERNAL;
}

/* Interface existance check by interface name. */
struct interface *if_lookup_by_name(const char *name, vrf_id_t vrf_id)
{
	struct vrf *vrf = vrf_lookup_by_id(vrf_id);
	struct interface if_tmp;

	if (!vrf || !name
	    || strnlen(name, INTERFACE_NAMSIZ) == INTERFACE_NAMSIZ)
		return NULL;

	strlcpy(if_tmp.name, name, sizeof(if_tmp.name));
	return RB_FIND(if_name_head, &vrf->ifaces_by_name, &if_tmp);
}

struct interface *if_lookup_by_name_all_vrf(const char *name)
{
	struct vrf *vrf;
	struct interface *ifp;

	if (!name || strnlen(name, INTERFACE_NAMSIZ) == INTERFACE_NAMSIZ)
		return NULL;

	RB_FOREACH (vrf, vrf_id_head, &vrfs_by_id) {
		ifp = if_lookup_by_name(name, vrf->vrf_id);
		if (ifp)
			return ifp;
	}

	return NULL;
}

struct interface *if_lookup_by_index_all_vrf(ifindex_t ifindex)
{
	struct vrf *vrf;
	struct interface *ifp;

	if (ifindex == IFINDEX_INTERNAL)
		return NULL;

	RB_FOREACH (vrf, vrf_id_head, &vrfs_by_id) {
		ifp = if_lookup_by_ifindex(ifindex, vrf->vrf_id);
		if (ifp)
			return ifp;
	}

	return NULL;
}

/* Lookup interface by IP address. */
struct interface *if_lookup_exact_address(void *src, int family,
					  vrf_id_t vrf_id)
{
	struct vrf *vrf = vrf_lookup_by_id(vrf_id);
	struct listnode *cnode;
	struct interface *ifp;
	struct prefix *p;
	struct connected *c;

	FOR_ALL_INTERFACES (vrf, ifp) {
		for (ALL_LIST_ELEMENTS_RO(ifp->connected, cnode, c)) {
			p = c->address;

			if (p && (p->family == family)) {
				if (family == AF_INET) {
					if (IPV4_ADDR_SAME(
						    &p->u.prefix4,
						    (struct in_addr *)src))
						return ifp;
				} else if (family == AF_INET6) {
					if (IPV6_ADDR_SAME(
						    &p->u.prefix6,
						    (struct in6_addr *)src))
						return ifp;
				}
			}
		}
	}
	return NULL;
}

/* Lookup interface by IP address. */
struct connected *if_lookup_address(void *matchaddr, int family,
				    vrf_id_t vrf_id)
{
	struct vrf *vrf = vrf_lookup_by_id(vrf_id);
	struct prefix addr;
	int bestlen = 0;
	struct listnode *cnode;
	struct interface *ifp;
	struct connected *c;
	struct connected *match;

	if (family == AF_INET) {
		addr.family = AF_INET;
		addr.u.prefix4 = *((struct in_addr *)matchaddr);
		addr.prefixlen = IPV4_MAX_BITLEN;
	} else if (family == AF_INET6) {
		addr.family = AF_INET6;
		addr.u.prefix6 = *((struct in6_addr *)matchaddr);
		addr.prefixlen = IPV6_MAX_BITLEN;
	}

	match = NULL;

	FOR_ALL_INTERFACES (vrf, ifp) {
		for (ALL_LIST_ELEMENTS_RO(ifp->connected, cnode, c)) {
			if (c->address && (c->address->family == AF_INET)
			    && prefix_match(CONNECTED_PREFIX(c), &addr)
			    && (c->address->prefixlen > bestlen)) {
				bestlen = c->address->prefixlen;
				match = c;
			}
		}
	}
	return match;
}

/* Lookup interface by prefix */
struct interface *if_lookup_prefix(struct prefix *prefix, vrf_id_t vrf_id)
{
	struct vrf *vrf = vrf_lookup_by_id(vrf_id);
	struct listnode *cnode;
	struct interface *ifp;
	struct connected *c;

	FOR_ALL_INTERFACES (vrf, ifp) {
		for (ALL_LIST_ELEMENTS_RO(ifp->connected, cnode, c)) {
			if (prefix_cmp(c->address, prefix) == 0) {
				return ifp;
			}
		}
	}
	return NULL;
}

size_t if_lookup_by_hwaddr(const uint8_t *hw_addr, size_t addrsz,
			   struct interface ***result, vrf_id_t vrf_id)
{
	struct vrf *vrf = vrf_lookup_by_id(vrf_id);

	struct list *rs = list_new();
	struct interface *ifp;

	FOR_ALL_INTERFACES (vrf, ifp) {
		if (ifp->hw_addr_len == (int)addrsz
		    && !memcmp(hw_addr, ifp->hw_addr, addrsz))
			listnode_add(rs, ifp);
	}

	if (rs->count) {
		*result = XCALLOC(MTYPE_TMP,
				  sizeof(struct interface *) * rs->count);
		list_to_array(rs, (void **)*result, rs->count);
	}

	int count = rs->count;

	list_delete(&rs);

	return count;
}


/* Get interface by name if given name interface doesn't exist create
   one. */
struct interface *if_get_by_name(const char *name, vrf_id_t vrf_id)
{
	struct interface *ifp;

	switch (vrf_get_backend()) {
	case VRF_BACKEND_UNKNOWN:
	case VRF_BACKEND_NETNS:
		ifp = if_lookup_by_name(name, vrf_id);
		if (ifp)
			return ifp;
		return if_create_name(name, vrf_id);
	case VRF_BACKEND_VRF_LITE:
		ifp = if_lookup_by_name_all_vrf(name);
		if (ifp) {
			if (ifp->vrf_id == vrf_id)
				return ifp;
			/* If it came from the kernel or by way of zclient,
			 * believe it and update the ifp accordingly.
			 */
			if_update_to_new_vrf(ifp, vrf_id);
			return ifp;
		}
		return if_create_name(name, vrf_id);
	}

	return NULL;
}

struct interface *if_get_by_ifindex(ifindex_t ifindex, vrf_id_t vrf_id)
{
	struct interface *ifp;

	switch (vrf_get_backend()) {
	case VRF_BACKEND_UNKNOWN:
	case VRF_BACKEND_NETNS:
		ifp = if_lookup_by_ifindex(ifindex, vrf_id);
		if (ifp)
			return ifp;
		return if_create_ifindex(ifindex, vrf_id);
	case VRF_BACKEND_VRF_LITE:
		ifp = if_lookup_by_index_all_vrf(ifindex);
		if (ifp) {
			if (ifp->vrf_id == vrf_id)
				return ifp;
			/* If it came from the kernel or by way of zclient,
			 * believe it and update the ifp accordingly.
			 */
			if_update_to_new_vrf(ifp, vrf_id);
			return ifp;
		}
		return if_create_ifindex(ifindex, vrf_id);
	}

	return NULL;
}

void if_set_index(struct interface *ifp, ifindex_t ifindex)
{
	struct vrf *vrf;

	vrf = vrf_get(ifp->vrf_id, NULL);
	assert(vrf);

	if (ifp->ifindex == ifindex)
		return;

	if (ifp->ifindex != IFINDEX_INTERNAL)
		IFINDEX_RB_REMOVE(vrf, ifp);

	ifp->ifindex = ifindex;

	if (ifp->ifindex != IFINDEX_INTERNAL)
		IFINDEX_RB_INSERT(vrf, ifp)
}

void if_set_name(struct interface *ifp, const char *name)
{
	struct vrf *vrf;

	vrf = vrf_get(ifp->vrf_id, NULL);
	assert(vrf);

	if (if_cmp_name_func(ifp->name, name) == 0)
		return;

	if (ifp->name[0] != '\0')
		IFNAME_RB_REMOVE(vrf, ifp);

	strlcpy(ifp->name, name, sizeof(ifp->name));

	if (ifp->name[0] != '\0')
		IFNAME_RB_INSERT(vrf, ifp);
}

/* Does interface up ? */
int if_is_up(const struct interface *ifp)
{
	return ifp->flags & IFF_UP;
}

/* Is interface running? */
int if_is_running(const struct interface *ifp)
{
	return ifp->flags & IFF_RUNNING;
}

/* Is the interface operative, eg. either UP & RUNNING
   or UP & !ZEBRA_INTERFACE_LINK_DETECTION and
   if ptm checking is enabled, then ptm check has passed */
int if_is_operative(const struct interface *ifp)
{
	return ((ifp->flags & IFF_UP)
		&& (((ifp->flags & IFF_RUNNING)
		     && (ifp->ptm_status || !ifp->ptm_enable))
		    || !CHECK_FLAG(ifp->status,
				   ZEBRA_INTERFACE_LINKDETECTION)));
}

/* Is the interface operative, eg. either UP & RUNNING
   or UP & !ZEBRA_INTERFACE_LINK_DETECTION, without PTM check */
int if_is_no_ptm_operative(const struct interface *ifp)
{
	return ((ifp->flags & IFF_UP)
		&& ((ifp->flags & IFF_RUNNING)
		    || !CHECK_FLAG(ifp->status,
				   ZEBRA_INTERFACE_LINKDETECTION)));
}

/* Is this loopback interface ? */
int if_is_loopback(const struct interface *ifp)
{
	/* XXX: Do this better, eg what if IFF_WHATEVER means X on platform M
	 * but Y on platform N?
	 */
	return (ifp->flags & (IFF_LOOPBACK | IFF_NOXMIT | IFF_VIRTUAL));
}

/* Check interface is VRF */
int if_is_vrf(const struct interface *ifp)
{
	return CHECK_FLAG(ifp->status, ZEBRA_INTERFACE_VRF_LOOPBACK);
}

bool if_is_loopback_or_vrf(const struct interface *ifp)
{
	if (if_is_loopback(ifp) || if_is_vrf(ifp))
		return true;

	return false;
}

/* Does this interface support broadcast ? */
int if_is_broadcast(const struct interface *ifp)
{
	return ifp->flags & IFF_BROADCAST;
}

/* Does this interface support broadcast ? */
int if_is_pointopoint(const struct interface *ifp)
{
	return ifp->flags & IFF_POINTOPOINT;
}

/* Does this interface support multicast ? */
int if_is_multicast(const struct interface *ifp)
{
	return ifp->flags & IFF_MULTICAST;
}

/* Printout flag information into log */
const char *if_flag_dump(unsigned long flag)
{
	int separator = 0;
	static char logbuf[BUFSIZ];

#define IFF_OUT_LOG(X, STR)                                                    \
	if (flag & (X)) {                                                      \
		if (separator)                                                 \
			strlcat(logbuf, ",", sizeof(logbuf));                  \
		else                                                           \
			separator = 1;                                         \
		strlcat(logbuf, STR, sizeof(logbuf));                          \
	}

	strlcpy(logbuf, "<", BUFSIZ);
	IFF_OUT_LOG(IFF_UP, "UP");
	IFF_OUT_LOG(IFF_BROADCAST, "BROADCAST");
	IFF_OUT_LOG(IFF_DEBUG, "DEBUG");
	IFF_OUT_LOG(IFF_LOOPBACK, "LOOPBACK");
	IFF_OUT_LOG(IFF_POINTOPOINT, "POINTOPOINT");
	IFF_OUT_LOG(IFF_NOTRAILERS, "NOTRAILERS");
	IFF_OUT_LOG(IFF_RUNNING, "RUNNING");
	IFF_OUT_LOG(IFF_NOARP, "NOARP");
	IFF_OUT_LOG(IFF_PROMISC, "PROMISC");
	IFF_OUT_LOG(IFF_ALLMULTI, "ALLMULTI");
	IFF_OUT_LOG(IFF_OACTIVE, "OACTIVE");
	IFF_OUT_LOG(IFF_SIMPLEX, "SIMPLEX");
	IFF_OUT_LOG(IFF_LINK0, "LINK0");
	IFF_OUT_LOG(IFF_LINK1, "LINK1");
	IFF_OUT_LOG(IFF_LINK2, "LINK2");
	IFF_OUT_LOG(IFF_MULTICAST, "MULTICAST");
	IFF_OUT_LOG(IFF_NOXMIT, "NOXMIT");
	IFF_OUT_LOG(IFF_NORTEXCH, "NORTEXCH");
	IFF_OUT_LOG(IFF_VIRTUAL, "VIRTUAL");
	IFF_OUT_LOG(IFF_IPV4, "IPv4");
	IFF_OUT_LOG(IFF_IPV6, "IPv6");

	strlcat(logbuf, ">", sizeof(logbuf));

	return logbuf;
#undef IFF_OUT_LOG
}

/* For debugging */
static void if_dump(const struct interface *ifp)
{
	struct listnode *node;
	struct connected *c __attribute__((unused));

	for (ALL_LIST_ELEMENTS_RO(ifp->connected, node, c))
		zlog_info(
			"Interface %s vrf %u index %d metric %d mtu %d "
			"mtu6 %d %s",
			ifp->name, ifp->vrf_id, ifp->ifindex, ifp->metric,
			ifp->mtu, ifp->mtu6, if_flag_dump(ifp->flags));
}

/* Interface printing for all interface. */
void if_dump_all(void)
{
	struct vrf *vrf;
	void *ifp;

	RB_FOREACH (vrf, vrf_id_head, &vrfs_by_id)
		FOR_ALL_INTERFACES (vrf, ifp)
			if_dump(ifp);
}

#ifdef SUNOS_5
/* Need to handle upgrade from SUNWzebra to Quagga. SUNWzebra created
 * a seperate struct interface for each logical interface, so config
 * file may be full of 'interface fooX:Y'. Solaris however does not
 * expose logical interfaces via PF_ROUTE, so trying to track logical
 * interfaces can be fruitless, for that reason Quagga only tracks
 * the primary IP interface.
 *
 * We try accomodate SUNWzebra by:
 * - looking up the interface name, to see whether it exists, if so
 *   its useable
 *   - for protocol daemons, this could only because zebra told us of
 *     the interface
 *   - for zebra, only because it learnt from kernel
 * - if not:
 *   - search the name to see if it contains a sub-ipif / logical interface
 *     seperator, the ':' char. If it does:
 *     - text up to that char must be the primary name - get that name.
 *     if not:
 *     - no idea, just get the name in its entirety.
 */
static struct interface *if_sunwzebra_get(const char *name, vrf_id_t vrf_id)
{
	struct interface *ifp;
	char *cp;

	if ((ifp = if_lookup_by_name(name, vrf_id)) != NULL)
		return ifp;

	/* hunt the primary interface name... */
	cp = strchr(name, ':');
	if (cp)
		*cp = '\0';

	return if_get_by_name(name, vrf_id);
}
#endif /* SUNOS_5 */

#if 0
/* For debug purpose. */
DEFUN (show_address,
       show_address_cmd,
       "show address [vrf NAME]",
       SHOW_STR
       "address\n"
       VRF_CMD_HELP_STR)
{
  int idx_vrf = 3;
  struct listnode *node;
  struct interface *ifp;
  struct connected *ifc;
  struct prefix *p;
  vrf_id_t vrf_id = VRF_DEFAULT;

  if (argc > 2)
    VRF_GET_ID (vrf_id, argv[idx_vrf]->arg);

  FOR_ALL_INTERFACES (vrf, ifp)
    {
      for (ALL_LIST_ELEMENTS_RO (ifp->connected, node, ifc))
	{
	  p = ifc->address;

	  if (p->family == AF_INET)
	    vty_out (vty, "%s/%d\n", inet_ntoa (p->u.prefix4), p->prefixlen);
	}
    }
  return CMD_SUCCESS;
}

DEFUN (show_address_vrf_all,
       show_address_vrf_all_cmd,
       "show address vrf all",
       SHOW_STR
       "address\n"
       VRF_ALL_CMD_HELP_STR)
{
  struct vrf *vrf;
  struct listnode *node;
  struct interface *ifp;
  struct connected *ifc;
  struct prefix *p;

  RB_FOREACH (vrf, vrf_name_head, &vrfs_by_name)
    {
      if (RB_EMPTY (if_name_head, &vrf->ifaces_by_name))
        continue;

      vty_out (vty, "\nVRF %u\n\n", vrf->vrf_id);

      FOR_ALL_INTERFACES (vrf, ifp)
        {
          for (ALL_LIST_ELEMENTS_RO (ifp->connected, node, ifc))
            {
              p = ifc->address;

              if (p->family == AF_INET)
                vty_out (vty, "%s/%d\n", inet_ntoa (p->u.prefix4), p->prefixlen);
            }
        }
    }
  return CMD_SUCCESS;
}
#endif

/* Allocate connected structure. */
struct connected *connected_new(void)
{
	return XCALLOC(MTYPE_CONNECTED, sizeof(struct connected));
}

/* Allocate nbr connected structure. */
struct nbr_connected *nbr_connected_new(void)
{
	return XCALLOC(MTYPE_NBR_CONNECTED, sizeof(struct nbr_connected));
}

/* Free connected structure. */
void connected_free(struct connected **connected)
{
	struct connected *ptr = *connected;

	if (ptr->address)
		prefix_free(&ptr->address);

	if (ptr->destination)
		prefix_free(&ptr->destination);

	XFREE(MTYPE_CONNECTED_LABEL, ptr->label);

	XFREE(MTYPE_CONNECTED, ptr);
	*connected = NULL;
}

/* Free nbr connected structure. */
void nbr_connected_free(struct nbr_connected *connected)
{
	if (connected->address)
		prefix_free(&connected->address);

	XFREE(MTYPE_NBR_CONNECTED, connected);
}

/* If same interface nbr address already exists... */
struct nbr_connected *nbr_connected_check(struct interface *ifp,
					  struct prefix *p)
{
	struct nbr_connected *ifc;
	struct listnode *node;

	for (ALL_LIST_ELEMENTS_RO(ifp->nbr_connected, node, ifc))
		if (prefix_same(ifc->address, p))
			return ifc;

	return NULL;
}

/* Print if_addr structure. */
static void __attribute__((unused))
connected_log(struct connected *connected, char *str)
{
	struct prefix *p;
	struct interface *ifp;
	char logbuf[BUFSIZ];
	char buf[BUFSIZ];

	ifp = connected->ifp;
	p = connected->address;

	snprintf(logbuf, BUFSIZ, "%s interface %s vrf %u %s %s/%d ", str,
		 ifp->name, ifp->vrf_id, prefix_family_str(p),
		 inet_ntop(p->family, &p->u.prefix, buf, BUFSIZ), p->prefixlen);

	p = connected->destination;
	if (p) {
		strncat(logbuf, inet_ntop(p->family, &p->u.prefix, buf, BUFSIZ),
			BUFSIZ - strlen(logbuf));
	}
	zlog_info("%s", logbuf);
}

/* Print if_addr structure. */
static void __attribute__((unused))
nbr_connected_log(struct nbr_connected *connected, char *str)
{
	struct prefix *p;
	struct interface *ifp;
	char logbuf[BUFSIZ];
	char buf[BUFSIZ];

	ifp = connected->ifp;
	p = connected->address;

	snprintf(logbuf, BUFSIZ, "%s interface %s %s %s/%d ", str, ifp->name,
		 prefix_family_str(p),
		 inet_ntop(p->family, &p->u.prefix, buf, BUFSIZ), p->prefixlen);

	zlog_info("%s", logbuf);
}

/* If two connected address has same prefix return 1. */
static int connected_same_prefix(struct prefix *p1, struct prefix *p2)
{
	if (p1->family == p2->family) {
		if (p1->family == AF_INET
		    && IPV4_ADDR_SAME(&p1->u.prefix4, &p2->u.prefix4))
			return 1;
		if (p1->family == AF_INET6
		    && IPV6_ADDR_SAME(&p1->u.prefix6, &p2->u.prefix6))
			return 1;
	}
	return 0;
}

/* count the number of connected addresses that are in the given family */
unsigned int connected_count_by_family(struct interface *ifp, int family)
{
	struct listnode *cnode;
	struct connected *connected;
	unsigned int cnt = 0;

	for (ALL_LIST_ELEMENTS_RO(ifp->connected, cnode, connected))
		if (connected->address->family == family)
			cnt++;

	return cnt;
}

struct connected *connected_lookup_prefix_exact(struct interface *ifp,
						struct prefix *p)
{
	struct listnode *node;
	struct listnode *next;
	struct connected *ifc;

	for (node = listhead(ifp->connected); node; node = next) {
		ifc = listgetdata(node);
		next = node->next;

		if (connected_same_prefix(ifc->address, p))
			return ifc;
	}
	return NULL;
}

struct connected *connected_delete_by_prefix(struct interface *ifp,
					     struct prefix *p)
{
	struct listnode *node;
	struct listnode *next;
	struct connected *ifc;

	/* In case of same prefix come, replace it with new one. */
	for (node = listhead(ifp->connected); node; node = next) {
		ifc = listgetdata(node);
		next = node->next;

		if (connected_same_prefix(ifc->address, p)) {
			listnode_delete(ifp->connected, ifc);
			return ifc;
		}
	}
	return NULL;
}

/* Find the address on our side that will be used when packets
   are sent to dst. */
struct connected *connected_lookup_prefix(struct interface *ifp,
					  struct prefix *addr)
{
	struct listnode *cnode;
	struct connected *c;
	struct connected *match;

	match = NULL;

	for (ALL_LIST_ELEMENTS_RO(ifp->connected, cnode, c)) {
		if (c->address && (c->address->family == addr->family)
		    && prefix_match(CONNECTED_PREFIX(c), addr)
		    && (!match
			|| (c->address->prefixlen > match->address->prefixlen)))
			match = c;
	}
	return match;
}

struct connected *connected_add_by_prefix(struct interface *ifp,
					  struct prefix *p,
					  struct prefix *destination)
{
	struct connected *ifc;

	/* Allocate new connected address. */
	ifc = connected_new();
	ifc->ifp = ifp;

	/* Fetch interface address */
	ifc->address = prefix_new();
	memcpy(ifc->address, p, sizeof(struct prefix));

	/* Fetch dest address */
	if (destination) {
		ifc->destination = prefix_new();
		memcpy(ifc->destination, destination, sizeof(struct prefix));
	}

	/* Add connected address to the interface. */
	listnode_add(ifp->connected, ifc);
	return ifc;
}

struct connected *connected_get_linklocal(struct interface *ifp)
{
	struct listnode *n;
	struct connected *c = NULL;

	for (ALL_LIST_ELEMENTS_RO(ifp->connected, n, c)) {
		if (c->address->family == AF_INET6
		    && IN6_IS_ADDR_LINKLOCAL(&c->address->u.prefix6))
			break;
	}
	return c;
}

#if 0  /* this route_table of struct connected's is unused                     \
	* however, it would be good to use a route_table rather than           \
	* a list..                                                             \
	*/
/* Interface looking up by interface's address. */
/* Interface's IPv4 address reverse lookup table. */
struct route_table *ifaddr_ipv4_table;
/* struct route_table *ifaddr_ipv6_table; */

static void
ifaddr_ipv4_add (struct in_addr *ifaddr, struct interface *ifp)
{
  struct route_node *rn;
  struct prefix_ipv4 p;

  p.family = AF_INET;
  p.prefixlen = IPV4_MAX_PREFIXLEN;
  p.prefix = *ifaddr;

  rn = route_node_get (ifaddr_ipv4_table, (struct prefix *) &p);
  if (rn)
    {
      route_unlock_node (rn);
      zlog_info ("ifaddr_ipv4_add(): address %s is already added",
		 inet_ntoa (*ifaddr));
      return;
    }
  rn->info = ifp;
}

static void
ifaddr_ipv4_delete (struct in_addr *ifaddr, struct interface *ifp)
{
  struct route_node *rn;
  struct prefix_ipv4 p;

  p.family = AF_INET;
  p.prefixlen = IPV4_MAX_PREFIXLEN;
  p.prefix = *ifaddr;

  rn = route_node_lookup (ifaddr_ipv4_table, (struct prefix *) &p);
  if (! rn)
    {
      zlog_info ("ifaddr_ipv4_delete(): can't find address %s",
		 inet_ntoa (*ifaddr));
      return;
    }
  rn->info = NULL;
  route_unlock_node (rn);
  route_unlock_node (rn);
}

/* Lookup interface by interface's IP address or interface index. */
static struct interface *
ifaddr_ipv4_lookup (struct in_addr *addr, ifindex_t ifindex)
{
  struct prefix_ipv4 p;
  struct route_node *rn;
  struct interface *ifp;

  if (addr)
    {
      p.family = AF_INET;
      p.prefixlen = IPV4_MAX_PREFIXLEN;
      p.prefix = *addr;

      rn = route_node_lookup (ifaddr_ipv4_table, (struct prefix *) &p);
      if (! rn)
	return NULL;

      ifp = rn->info;
      route_unlock_node (rn);
      return ifp;
    }
  else
    return if_lookup_by_index(ifindex, VRF_DEFAULT);
}
#endif /* ifaddr_ipv4_table */

void if_terminate(struct vrf *vrf)
{
	struct interface *ifp;

	while (!RB_EMPTY(if_name_head, &vrf->ifaces_by_name)) {
		ifp = RB_ROOT(if_name_head, &vrf->ifaces_by_name);

		if (ifp->node) {
			ifp->node->info = NULL;
			route_unlock_node(ifp->node);
		}
		if_delete(&ifp);
	}
}

const char *if_link_type_str(enum zebra_link_type llt)
{
	switch (llt) {
#define llts(T,S) case (T): return (S)
		llts(ZEBRA_LLT_UNKNOWN, "Unknown");
		llts(ZEBRA_LLT_ETHER, "Ethernet");
		llts(ZEBRA_LLT_EETHER, "Experimental Ethernet");
		llts(ZEBRA_LLT_AX25, "AX.25 Level 2");
		llts(ZEBRA_LLT_PRONET, "PROnet token ring");
		llts(ZEBRA_LLT_IEEE802, "IEEE 802.2 Ethernet/TR/TB");
		llts(ZEBRA_LLT_ARCNET, "ARCnet");
		llts(ZEBRA_LLT_APPLETLK, "AppleTalk");
		llts(ZEBRA_LLT_DLCI, "Frame Relay DLCI");
		llts(ZEBRA_LLT_ATM, "ATM");
		llts(ZEBRA_LLT_METRICOM, "Metricom STRIP");
		llts(ZEBRA_LLT_IEEE1394, "IEEE 1394 IPv4");
		llts(ZEBRA_LLT_EUI64, "EUI-64");
		llts(ZEBRA_LLT_INFINIBAND, "InfiniBand");
		llts(ZEBRA_LLT_SLIP, "SLIP");
		llts(ZEBRA_LLT_CSLIP, "Compressed SLIP");
		llts(ZEBRA_LLT_SLIP6, "SLIPv6");
		llts(ZEBRA_LLT_CSLIP6, "Compressed SLIPv6");
		llts(ZEBRA_LLT_ROSE, "ROSE packet radio");
		llts(ZEBRA_LLT_X25, "CCITT X.25");
		llts(ZEBRA_LLT_PPP, "PPP");
		llts(ZEBRA_LLT_CHDLC, "Cisco HDLC");
		llts(ZEBRA_LLT_RAWHDLC, "Raw HDLC");
		llts(ZEBRA_LLT_LAPB, "LAPB");
		llts(ZEBRA_LLT_IPIP, "IPIP Tunnel");
		llts(ZEBRA_LLT_IPIP6, "IPIP6 Tunnel");
		llts(ZEBRA_LLT_FRAD, "FRAD");
		llts(ZEBRA_LLT_SKIP, "SKIP vif");
		llts(ZEBRA_LLT_LOOPBACK, "Loopback");
		llts(ZEBRA_LLT_LOCALTLK, "Localtalk");
		llts(ZEBRA_LLT_FDDI, "FDDI");
		llts(ZEBRA_LLT_SIT, "IPv6-in-IPv4 SIT");
		llts(ZEBRA_LLT_IPDDP, "IP-in-DDP tunnel");
		llts(ZEBRA_LLT_IPGRE, "GRE over IP");
		llts(ZEBRA_LLT_PIMREG, "PIMSM registration");
		llts(ZEBRA_LLT_HIPPI, "HiPPI");
		llts(ZEBRA_LLT_IRDA, "IrDA");
		llts(ZEBRA_LLT_FCPP, "Fibre-Channel PtP");
		llts(ZEBRA_LLT_FCAL, "Fibre-Channel Arbitrated Loop");
		llts(ZEBRA_LLT_FCPL, "Fibre-Channel Public Loop");
		llts(ZEBRA_LLT_FCFABRIC, "Fibre-Channel Fabric");
		llts(ZEBRA_LLT_IEEE802_TR, "IEEE 802.2 Token Ring");
		llts(ZEBRA_LLT_IEEE80211, "IEEE 802.11");
		llts(ZEBRA_LLT_IEEE80211_RADIOTAP, "IEEE 802.11 Radiotap");
		llts(ZEBRA_LLT_IEEE802154, "IEEE 802.15.4");
		llts(ZEBRA_LLT_IEEE802154_PHY, "IEEE 802.15.4 Phy");
	default:
		flog_err(EC_LIB_DEVELOPMENT, "Unknown value %d", llt);
		return "Unknown type!";
#undef llts
	}
	return NULL;
}

struct if_link_params *if_link_params_get(struct interface *ifp)
{
	int i;

	if (ifp->link_params != NULL)
		return ifp->link_params;

	struct if_link_params *iflp =
		XCALLOC(MTYPE_IF_LINK_PARAMS, sizeof(struct if_link_params));
	if (iflp == NULL)
		return NULL;

	/* Set TE metric equal to standard metric */
	iflp->te_metric = ifp->metric;

	/* Compute default bandwidth based on interface */
	iflp->default_bw =
		((ifp->bandwidth ? ifp->bandwidth : DEFAULT_BANDWIDTH)
		 * TE_KILO_BIT / TE_BYTE);

	/* Set Max, Reservable and Unreserved Bandwidth */
	iflp->max_bw = iflp->default_bw;
	iflp->max_rsv_bw = iflp->default_bw;
	for (i = 0; i < MAX_CLASS_TYPE; i++)
		iflp->unrsv_bw[i] = iflp->default_bw;

	/* Update Link parameters status */
	iflp->lp_status =
		LP_TE_METRIC | LP_MAX_BW | LP_MAX_RSV_BW | LP_UNRSV_BW;

	/* Finally attach newly created Link Parameters */
	ifp->link_params = iflp;

	return iflp;
}

void if_link_params_free(struct interface *ifp)
{
	if (ifp->link_params == NULL)
		return;
	XFREE(MTYPE_IF_LINK_PARAMS, ifp->link_params);
	ifp->link_params = NULL;
}

/* ----------- CLI commands ----------- */

/*
 * XPath: /frr-interface:lib/interface
 */
DEFPY_NOSH (interface,
       interface_cmd,
       "interface IFNAME [vrf NAME$vrf_name]",
       "Select an interface to configure\n"
       "Interface's name\n"
       VRF_CMD_HELP_STR)
{
	char xpath_list[XPATH_MAXLEN];
	vrf_id_t vrf_id;
	struct interface *ifp;
	int ret;

	if (!vrf_name)
		vrf_name = VRF_DEFAULT_NAME;

	/*
	 * This command requires special handling to maintain backward
	 * compatibility. If a VRF name is not specified, it means we're willing
	 * to accept any interface with the given name on any VRF. If no
	 * interface is found, then a new one should be created on the default
	 * VRF.
	 */
	VRF_GET_ID(vrf_id, vrf_name, false);
	ifp = if_lookup_by_name_all_vrf(ifname);
	if (ifp && ifp->vrf_id != vrf_id) {
		struct vrf *vrf;

		/*
		 * Special case 1: a VRF name was specified, but the found
		 * interface is associated to different VRF. Reject the command.
		 */
		if (vrf_id != VRF_DEFAULT) {
			vty_out(vty, "%% interface %s not in %s vrf\n", ifname,
				vrf_name);
			return CMD_WARNING_CONFIG_FAILED;
		}

		/*
		 * Special case 2: a VRF name was *not* specified, and the found
		 * interface is associated to a VRF other than the default one.
		 * Update vrf_id and vrf_name to account for that.
		 */
		vrf = vrf_lookup_by_id(ifp->vrf_id);
		assert(vrf);
		vrf_id = ifp->vrf_id;
		vrf_name = vrf->name;
	}

	snprintf(xpath_list, sizeof(xpath_list),
		 "/frr-interface:lib/interface[name='%s'][vrf='%s']", ifname,
		 vrf_name);

	nb_cli_enqueue_change(vty, ".", NB_OP_CREATE, NULL);
	ret = nb_cli_apply_changes(vty, xpath_list);
	if (ret == CMD_SUCCESS) {
		VTY_PUSH_XPATH(INTERFACE_NODE, xpath_list);

		/*
		 * For backward compatibility with old commands we still need
		 * to use the qobj infrastructure. This can be removed once
		 * all interface-level commands are converted to the new
		 * northbound model.
		 */
		ifp = if_lookup_by_name(ifname, vrf_id);
		if (ifp)
			VTY_PUSH_CONTEXT(INTERFACE_NODE, ifp);
	}

	return ret;
}

DEFPY (no_interface,
       no_interface_cmd,
       "no interface IFNAME [vrf NAME$vrf_name]",
       NO_STR
       "Delete a pseudo interface's configuration\n"
       "Interface's name\n"
       VRF_CMD_HELP_STR)
{
	if (!vrf_name)
		vrf_name = VRF_DEFAULT_NAME;

	nb_cli_enqueue_change(vty, ".", NB_OP_DESTROY, NULL);

	return nb_cli_apply_changes(
		vty, "/frr-interface:lib/interface[name='%s'][vrf='%s']",
		ifname, vrf_name);
}

static void cli_show_interface(struct vty *vty, struct lyd_node *dnode,
			bool show_defaults)
{
	const char *vrf;

	vrf = yang_dnode_get_string(dnode, "./vrf");

	vty_out(vty, "!\n");
	vty_out(vty, "interface %s", yang_dnode_get_string(dnode, "./name"));
	if (!strmatch(vrf, VRF_DEFAULT_NAME))
		vty_out(vty, " vrf %s", vrf);
	vty_out(vty, "\n");
}

/*
 * XPath: /frr-interface:lib/interface/description
 */
DEFPY (interface_desc,
       interface_desc_cmd,
       "description LINE...",
       "Interface specific description\n"
       "Characters describing this interface\n")
{
	char *desc;
	int ret;

	desc = argv_concat(argv, argc, 1);
	nb_cli_enqueue_change(vty, "./description", NB_OP_MODIFY, desc);
	ret = nb_cli_apply_changes(vty, NULL);
	XFREE(MTYPE_TMP, desc);

	return ret;
}

DEFPY  (no_interface_desc,
	no_interface_desc_cmd,
	"no description",
	NO_STR
	"Interface specific description\n")
{
	nb_cli_enqueue_change(vty, "./description", NB_OP_DESTROY, NULL);

	return nb_cli_apply_changes(vty, NULL);
}

static void cli_show_interface_desc(struct vty *vty, struct lyd_node *dnode,
			     bool show_defaults)
{
	vty_out(vty, " description %s\n", yang_dnode_get_string(dnode, NULL));
}

/* Interface autocomplete. */
static void if_autocomplete(vector comps, struct cmd_token *token)
{
	struct interface *ifp;
	struct vrf *vrf;

	RB_FOREACH (vrf, vrf_name_head, &vrfs_by_name) {
		FOR_ALL_INTERFACES (vrf, ifp) {
			vector_set(comps, XSTRDUP(MTYPE_COMPLETION, ifp->name));
		}
	}
}

static const struct cmd_variable_handler if_var_handlers[] = {
	{/* "interface NAME" */
	 .varname = "interface",
	 .completions = if_autocomplete},
	{.tokenname = "IFNAME", .completions = if_autocomplete},
	{.tokenname = "INTERFACE", .completions = if_autocomplete},
	{.completions = NULL}};

void if_cmd_init(void)
{
	cmd_variable_handler_register(if_var_handlers);

	install_element(CONFIG_NODE, &interface_cmd);
	install_element(CONFIG_NODE, &no_interface_cmd);

	install_default(INTERFACE_NODE);
	install_element(INTERFACE_NODE, &interface_desc_cmd);
	install_element(INTERFACE_NODE, &no_interface_desc_cmd);
}

void if_zapi_callbacks(int (*create)(struct interface *ifp),
		       int (*up)(struct interface *ifp),
		       int (*down)(struct interface *ifp),
		       int (*destroy)(struct interface *ifp))
{
	ifp_master.create_hook = create;
	ifp_master.up_hook = up;
	ifp_master.down_hook = down;
	ifp_master.destroy_hook = destroy;
}

/* ------- Northbound callbacks ------- */

/*
 * XPath: /frr-interface:lib/interface
 */
static int lib_interface_create(enum nb_event event,
				const struct lyd_node *dnode,
				union nb_resource *resource)
{
	const char *ifname;
	const char *vrfname;
	struct vrf *vrf;
	struct interface *ifp;

	ifname = yang_dnode_get_string(dnode, "./name");
	vrfname = yang_dnode_get_string(dnode, "./vrf");

	switch (event) {
	case NB_EV_VALIDATE:
		vrf = vrf_lookup_by_name(vrfname);
		if (!vrf) {
			zlog_warn("%s: VRF %s doesn't exist", __func__,
				  vrfname);
			return NB_ERR_VALIDATION;
		}
		if (vrf->vrf_id == VRF_UNKNOWN) {
			zlog_warn("%s: VRF %s is not active", __func__,
				  vrf->name);
			return NB_ERR_VALIDATION;
		}

		/* if VRF is netns or not yet known - init for instance
		 * then assumption is that passed config is exact
		 * then the user intent was not to use an other iface
		 */
		if (vrf_get_backend() == VRF_BACKEND_VRF_LITE) {
			ifp = if_lookup_by_name_all_vrf(ifname);
			if (ifp && ifp->vrf_id != vrf->vrf_id) {
				zlog_warn(
					"%s: interface %s already exists in another VRF",
					__func__, ifp->name);
				return NB_ERR_VALIDATION;
			}
		}
		break;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		vrf = vrf_lookup_by_name(vrfname);
		assert(vrf);
#ifdef SUNOS_5
		ifp = if_sunwzebra_get(ifname, vrf->vrf_id);
#else
		ifp = if_get_by_name(ifname, vrf->vrf_id);
#endif /* SUNOS_5 */

		ifp->configured = true;
		nb_running_set_entry(dnode, ifp);
		break;
	}

	return NB_OK;
}

static int lib_interface_destroy(enum nb_event event,
				 const struct lyd_node *dnode)
{
	struct interface *ifp;


	switch (event) {
	case NB_EV_VALIDATE:
		ifp = nb_running_get_entry(dnode, NULL, true);
		if (CHECK_FLAG(ifp->status, ZEBRA_INTERFACE_ACTIVE)) {
			zlog_warn("%s: only inactive interfaces can be deleted",
				  __func__);
			return NB_ERR_VALIDATION;
		}
		break;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		ifp = nb_running_unset_entry(dnode);

		ifp->configured = false;
		if_delete(&ifp);
		break;
	}

	return NB_OK;
}

/*
 * XPath: /frr-interface:lib/interface
 */
static const void *lib_interface_get_next(const void *parent_list_entry,
					  const void *list_entry)
{
	struct vrf *vrf;
	struct interface *pif = (struct interface *)list_entry;

	if (list_entry == NULL) {
		vrf = RB_MIN(vrf_name_head, &vrfs_by_name);
		assert(vrf);
		pif = RB_MIN(if_name_head, &vrf->ifaces_by_name);
	} else {
		vrf = vrf_lookup_by_id(pif->vrf_id);
		pif = RB_NEXT(if_name_head, pif);
		/* if no more interfaces, switch to next vrf */
		while (pif == NULL) {
			vrf = RB_NEXT(vrf_name_head, vrf);
			if (!vrf)
				return NULL;
			pif = RB_MIN(if_name_head, &vrf->ifaces_by_name);
		}
	}

	return pif;
}

static int lib_interface_get_keys(const void *list_entry,
				  struct yang_list_keys *keys)
{
	const struct interface *ifp = list_entry;

	struct vrf *vrf = vrf_lookup_by_id(ifp->vrf_id);

	assert(vrf);

	keys->num = 2;
	strlcpy(keys->key[0], ifp->name, sizeof(keys->key[0]));
	strlcpy(keys->key[1], vrf->name, sizeof(keys->key[1]));

	return NB_OK;
}

static const void *lib_interface_lookup_entry(const void *parent_list_entry,
					      const struct yang_list_keys *keys)
{
	const char *ifname = keys->key[0];
	const char *vrfname = keys->key[1];
	struct vrf *vrf = vrf_lookup_by_name(vrfname);

	return vrf ? if_lookup_by_name(ifname, vrf->vrf_id) : NULL;
}

/*
 * XPath: /frr-interface:lib/interface/description
 */
static int lib_interface_description_modify(enum nb_event event,
					    const struct lyd_node *dnode,
					    union nb_resource *resource)
{
	struct interface *ifp;
	const char *description;

	if (event != NB_EV_APPLY)
		return NB_OK;

	ifp = nb_running_get_entry(dnode, NULL, true);
	XFREE(MTYPE_TMP, ifp->desc);
	description = yang_dnode_get_string(dnode, NULL);
	ifp->desc = XSTRDUP(MTYPE_TMP, description);

	return NB_OK;
}

static int lib_interface_description_destroy(enum nb_event event,
					     const struct lyd_node *dnode)
{
	struct interface *ifp;

	if (event != NB_EV_APPLY)
		return NB_OK;

	ifp = nb_running_get_entry(dnode, NULL, true);
	XFREE(MTYPE_TMP, ifp->desc);

	return NB_OK;
}

/* clang-format off */
const struct frr_yang_module_info frr_interface_info = {
	.name = "frr-interface",
	.nodes = {
		{
			.xpath = "/frr-interface:lib/interface",
			.cbs = {
				.create = lib_interface_create,
				.destroy = lib_interface_destroy,
				.cli_show = cli_show_interface,
				.get_next = lib_interface_get_next,
				.get_keys = lib_interface_get_keys,
				.lookup_entry = lib_interface_lookup_entry,
			},
		},
		{
			.xpath = "/frr-interface:lib/interface/description",
			.cbs = {
				.modify = lib_interface_description_modify,
				.destroy = lib_interface_description_destroy,
				.cli_show = cli_show_interface_desc,
			},
		},
		{
			.xpath = NULL,
		},
	}
};
