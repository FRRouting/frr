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

DEFINE_MTYPE(LIB, IF, "Interface")
DEFINE_MTYPE_STATIC(LIB, CONNECTED, "Connected")
DEFINE_MTYPE_STATIC(LIB, NBR_CONNECTED, "Neighbor Connected")
DEFINE_MTYPE(LIB, CONNECTED_LABEL, "Connected interface label")
DEFINE_MTYPE_STATIC(LIB, IF_LINK_PARAMS, "Informational Link Parameters")

DEFINE_QOBJ_TYPE(interface)

DEFINE_HOOK(if_add, (struct interface *ifp), (ifp))
DEFINE_KOOH(if_del, (struct interface *ifp), (ifp))

/* List of interfaces in only the default VRF */
int ptm_enable = 0;

/* Compare interface names, returning an integer greater than, equal to, or
 * less than 0, (following the strcmp convention), according to the
 * relationship between ifp1 and ifp2.  Interface names consist of an
 * alphabetic prefix and a numeric suffix.  The primary sort key is
 * lexicographic by name, and then numeric by number.  No number sorts
 * before all numbers.  Examples: de0 < de1, de100 < fxp0 < xl0, devpty <
 * devpty0, de0 < del0
 */
int if_cmp_name_func(char *p1, char *p2)
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

		if (!*p1)
			return -1;
		if (!*p2)
			return 1;

		x1 = strtol(p1, &p1, 10);
		x2 = strtol(p2, &p2, 10);

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

static int if_cmp_func(struct interface *ifp1, struct interface *ifp2)
{
	return if_cmp_name_func(ifp1->name, ifp2->name);
}

/* Create new interface structure. */
struct interface *if_create(const char *name, vrf_id_t vrf_id)
{
	struct interface *ifp;
	struct list *intf_list = vrf_iflist_get(vrf_id);

	ifp = XCALLOC(MTYPE_IF, sizeof(struct interface));
	ifp->ifindex = IFINDEX_INTERNAL;

	assert(name);
	strlcpy(ifp->name, name, sizeof(ifp->name));
	ifp->vrf_id = vrf_id;
	if (if_lookup_by_name(ifp->name, vrf_id) == NULL)
		listnode_add_sort(intf_list, ifp);
	else
		zlog_err(
			"if_create(%s): corruption detected -- interface with this "
			"name exists already in VRF %u!",
			ifp->name, vrf_id);
	ifp->connected = list_new();
	ifp->connected->del = (void (*)(void *))connected_free;

	ifp->nbr_connected = list_new();
	ifp->nbr_connected->del = (void (*)(void *))nbr_connected_free;

	/* Enable Link-detection by default */
	SET_FLAG(ifp->status, ZEBRA_INTERFACE_LINKDETECTION);

	QOBJ_REG(ifp, interface);
        hook_call(if_add, ifp);
	return ifp;
}

/* Create new interface structure. */
void if_update_to_new_vrf(struct interface *ifp, vrf_id_t vrf_id)
{
	struct list *intf_list = vrf_iflist_get(vrf_id);

	/* remove interface from old master vrf list */
	if (vrf_iflist(ifp->vrf_id))
		listnode_delete(vrf_iflist(ifp->vrf_id), ifp);

	ifp->vrf_id = vrf_id;
	if (if_lookup_by_name(ifp->name, vrf_id) == NULL)
		listnode_add_sort(intf_list, ifp);
	else
		zlog_err(
			"%s(%s): corruption detected -- interface with this "
			"name exists already in VRF %u!", __func__,
			ifp->name, vrf_id);

	return;
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
void if_delete(struct interface *ifp)
{
	listnode_delete(vrf_iflist(ifp->vrf_id), ifp);

	if_delete_retain(ifp);

	list_delete_and_null(&ifp->connected);
	list_delete_and_null(&ifp->nbr_connected);

	if_link_params_free(ifp);

	XFREE(MTYPE_IF, ifp);
}

/* Interface existance check by index. */
struct interface *if_lookup_by_index(ifindex_t ifindex, vrf_id_t vrf_id)
{
	struct listnode *node;
	struct interface *ifp;

	for (ALL_LIST_ELEMENTS_RO(vrf_iflist(vrf_id), node, ifp)) {
		if (ifp->ifindex == ifindex)
			return ifp;
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
	struct listnode *node;
	struct interface *ifp;

	if (!name || strnlen(name, INTERFACE_NAMSIZ) == INTERFACE_NAMSIZ)
		return NULL;

	for (ALL_LIST_ELEMENTS_RO(vrf_iflist(vrf_id), node, ifp)) {
		if (strcmp(name, ifp->name) == 0)
			return ifp;
	}

	return NULL;
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

/* Lookup interface by IPv4 address. */
struct interface *if_lookup_exact_address(void *src, int family,
					  vrf_id_t vrf_id)
{
	struct listnode *node;
	struct listnode *cnode;
	struct interface *ifp;
	struct prefix *p;
	struct connected *c;

	for (ALL_LIST_ELEMENTS_RO(vrf_iflist(vrf_id), node, ifp)) {
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

/* Lookup interface by IPv4 address. */
struct connected *if_lookup_address(void *matchaddr, int family,
				    vrf_id_t vrf_id)
{
	struct listnode *node;
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

	for (ALL_LIST_ELEMENTS_RO(vrf_iflist(vrf_id), node, ifp)) {
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
	struct listnode *node;
	struct listnode *cnode;
	struct interface *ifp;
	struct connected *c;

	for (ALL_LIST_ELEMENTS_RO(vrf_iflist(vrf_id), node, ifp)) {
		for (ALL_LIST_ELEMENTS_RO(ifp->connected, cnode, c)) {
			if (prefix_cmp(c->address, prefix) == 0) {
				return ifp;
			}
		}
	}
	return NULL;
}

/* Get interface by name if given name interface doesn't exist create
   one. */
struct interface *if_get_by_name(const char *name, vrf_id_t vrf_id, int vty)
{
	struct interface *ifp;

	ifp = if_lookup_by_name_all_vrf(name);
	if (ifp) {
		if (ifp->vrf_id == vrf_id)
			return ifp;

		/* Found a match on a different VRF. If the interface command
		 * was entered in vty without a VRF (passed as VRF_DEFAULT),
		 * accept the ifp we found. If a vrf was entered and there is
		 * a mismatch, reject it if from vty. If it came from the kernel
		 * or by way of zclient, believe it and update the ifp
		 * accordingly.
		 */
		if (vty) {
			if (vrf_id == VRF_DEFAULT)
				return ifp;
			return NULL;
		} else {
			if_update_to_new_vrf(ifp, vrf_id);
			return ifp;
		}
	}

	return if_create(name, vrf_id);
}

/* Does interface up ? */
int if_is_up(struct interface *ifp)
{
	return ifp->flags & IFF_UP;
}

/* Is interface running? */
int if_is_running(struct interface *ifp)
{
	return ifp->flags & IFF_RUNNING;
}

/* Is the interface operative, eg. either UP & RUNNING
   or UP & !ZEBRA_INTERFACE_LINK_DETECTION and
   if ptm checking is enabled, then ptm check has passed */
int if_is_operative(struct interface *ifp)
{
	return ((ifp->flags & IFF_UP)
		&& (((ifp->flags & IFF_RUNNING)
		     && (ifp->ptm_status || !ifp->ptm_enable))
		    || !CHECK_FLAG(ifp->status,
				   ZEBRA_INTERFACE_LINKDETECTION)));
}

/* Is the interface operative, eg. either UP & RUNNING
   or UP & !ZEBRA_INTERFACE_LINK_DETECTION, without PTM check */
int if_is_no_ptm_operative(struct interface *ifp)
{
	return ((ifp->flags & IFF_UP)
		&& ((ifp->flags & IFF_RUNNING)
		    || !CHECK_FLAG(ifp->status,
				   ZEBRA_INTERFACE_LINKDETECTION)));
}

/* Is this loopback interface ? */
int if_is_loopback(struct interface *ifp)
{
	/* XXX: Do this better, eg what if IFF_WHATEVER means X on platform M
	 * but Y on platform N?
	 */
	return (ifp->flags & (IFF_LOOPBACK | IFF_NOXMIT | IFF_VIRTUAL));
}

/* Does this interface support broadcast ? */
int if_is_broadcast(struct interface *ifp)
{
	return ifp->flags & IFF_BROADCAST;
}

/* Does this interface support broadcast ? */
int if_is_pointopoint(struct interface *ifp)
{
	return ifp->flags & IFF_POINTOPOINT;
}

/* Does this interface support multicast ? */
int if_is_multicast(struct interface *ifp)
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
			strlcat(logbuf, ",", BUFSIZ);                          \
		else                                                           \
			separator = 1;                                         \
		strlcat(logbuf, STR, BUFSIZ);                                  \
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

	strlcat(logbuf, ">", BUFSIZ);

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
	struct listnode *node;
	void *p;

	RB_FOREACH (vrf, vrf_id_head, &vrfs_by_id)
		if (vrf->iflist != NULL)
			for (ALL_LIST_ELEMENTS_RO(vrf->iflist, node, p))
				if_dump(p);
}

DEFUN (interface_desc,
       interface_desc_cmd,
       "description LINE...",
       "Interface specific description\n"
       "Characters describing this interface\n")
{
	int idx_line = 1;
	VTY_DECLVAR_CONTEXT(interface, ifp);

	if (ifp->desc)
		XFREE(MTYPE_TMP, ifp->desc);
	ifp->desc = argv_concat(argv, argc, idx_line);

	return CMD_SUCCESS;
}

DEFUN (no_interface_desc,
       no_interface_desc_cmd,
       "no description",
       NO_STR
       "Interface specific description\n")
{
	VTY_DECLVAR_CONTEXT(interface, ifp);

	if (ifp->desc)
		XFREE(MTYPE_TMP, ifp->desc);
	ifp->desc = NULL;

	return CMD_SUCCESS;
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
static struct interface *if_sunwzebra_get(char *name, vrf_id_t vrf_id)
{
	struct interface *ifp;
	char *cp;

	if ((ifp = if_lookup_by_name(name, vrf_id)) != NULL)
		return ifp;

	/* hunt the primary interface name... */
	cp = strchr(name, ':');
	if (cp)
		*cp = '\0';

	return if_get_by_name(name, vrf_id, 1);
}
#endif /* SUNOS_5 */

DEFUN (interface,
       interface_cmd,
       "interface IFNAME [vrf NAME]",
       "Select an interface to configure\n"
       "Interface's name\n"
       VRF_CMD_HELP_STR)
{
	int idx_ifname = 1;
	int idx_vrf = 3;
	const char *ifname = argv[idx_ifname]->arg;
	const char *vrfname = (argc > 2) ? argv[idx_vrf]->arg : NULL;

	struct interface *ifp;
	vrf_id_t vrf_id = VRF_DEFAULT;

	if (strlen(ifname) > INTERFACE_NAMSIZ) {
		vty_out(vty,
			"%% Interface name %s is invalid: length exceeds "
			"%d characters\n",
			ifname, INTERFACE_NAMSIZ);
		return CMD_WARNING_CONFIG_FAILED;
	}

	/*Pending: need proper vrf name based lookup/(possible creation of VRF)
	 Imagine forward reference of a vrf by name in this interface config */
	if (vrfname)
		VRF_GET_ID(vrf_id, vrfname);

#ifdef SUNOS_5
	ifp = if_sunwzebra_get(ifname, vrf_id);
#else
	ifp = if_get_by_name(ifname, vrf_id, 1);
#endif /* SUNOS_5 */

	if (!ifp) {
		vty_out(vty, "%% interface %s not in %s\n", ifname, vrfname);
		return CMD_WARNING_CONFIG_FAILED;
	}
	VTY_PUSH_CONTEXT(INTERFACE_NODE, ifp);

	return CMD_SUCCESS;
}

DEFUN_NOSH (no_interface,
           no_interface_cmd,
           "no interface IFNAME [vrf NAME]",
           NO_STR
           "Delete a pseudo interface's configuration\n"
           "Interface's name\n"
           VRF_CMD_HELP_STR)
{
	const char *ifname = argv[2]->arg;
	const char *vrfname = (argc > 3) ? argv[3]->arg : NULL;

	// deleting interface
	struct interface *ifp;
	vrf_id_t vrf_id = VRF_DEFAULT;

	if (argc > 3)
		VRF_GET_ID(vrf_id, vrfname);

	ifp = if_lookup_by_name(ifname, vrf_id);

	if (ifp == NULL) {
		vty_out(vty, "%% Interface %s does not exist\n", ifname);
		return CMD_WARNING_CONFIG_FAILED;
	}

	if (CHECK_FLAG(ifp->status, ZEBRA_INTERFACE_ACTIVE)) {
		vty_out(vty, "%% Only inactive interfaces can be deleted\n");
		return CMD_WARNING_CONFIG_FAILED;
	}

	if_delete(ifp);

	return CMD_SUCCESS;
}

void if_cmd_init(void)
{
	install_element(CONFIG_NODE, &interface_cmd);
	install_element(CONFIG_NODE, &no_interface_cmd);

	install_default(INTERFACE_NODE);
	install_element(INTERFACE_NODE, &interface_desc_cmd);
	install_element(INTERFACE_NODE, &no_interface_desc_cmd);
}

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
  struct listnode *node2;
  struct interface *ifp;
  struct connected *ifc;
  struct prefix *p;
  vrf_id_t vrf_id = VRF_DEFAULT;

  if (argc > 2)
    VRF_GET_ID (vrf_id, argv[idx_vrf]->arg);

  for (ALL_LIST_ELEMENTS_RO (vrf_iflist (vrf_id), node, ifp))
    {
      for (ALL_LIST_ELEMENTS_RO (ifp->connected, node2, ifc))
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
  struct listnode *node2;
  struct interface *ifp;
  struct connected *ifc;
  struct prefix *p;

  RB_FOREACH (vrf, vrf_name_head, &vrfs_by_name)
    {
      if (!vrf->iflist || !listcount (vrf->iflist))
        continue;

      vty_out (vty, "\nVRF %u\n\n", vrf->vrf_id);

      for (ALL_LIST_ELEMENTS_RO (vrf->iflist, node, ifp))
        {
          for (ALL_LIST_ELEMENTS_RO (ifp->connected, node2, ifc))
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
void connected_free(struct connected *connected)
{
	if (connected->address)
		prefix_free(connected->address);

	if (connected->destination)
		prefix_free(connected->destination);

	if (connected->label)
		XFREE(MTYPE_CONNECTED_LABEL, connected->label);

	XFREE(MTYPE_CONNECTED, connected);
}

/* Free nbr connected structure. */
void nbr_connected_free(struct nbr_connected *connected)
{
	if (connected->address)
		prefix_free(connected->address);

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

static void if_autocomplete(vector comps, struct cmd_token *token)
{
	struct interface *ifp;
	struct listnode *ln;
	struct vrf *vrf = NULL;

	RB_FOREACH (vrf, vrf_name_head, &vrfs_by_name) {
		for (ALL_LIST_ELEMENTS_RO(vrf->iflist, ln, ifp))
			vector_set(comps, XSTRDUP(MTYPE_COMPLETION, ifp->name));
	}
}

static const struct cmd_variable_handler if_var_handlers[] = {
	{/* "interface NAME" */
	 .varname = "interface",
	 .completions = if_autocomplete},
	{.tokenname = "IFNAME", .completions = if_autocomplete},
	{.tokenname = "INTERFACE", .completions = if_autocomplete},
	{.completions = NULL}};

/* Initialize interface list. */
void if_init(struct list **intf_list)
{
	*intf_list = list_new();
#if 0
  ifaddr_ipv4_table = route_table_init ();
#endif /* ifaddr_ipv4_table */

	(*intf_list)->cmp = (int (*)(void *, void *))if_cmp_func;

	cmd_variable_handler_register(if_var_handlers);
}

void if_terminate(struct list **intf_list)
{
	for (;;) {
		struct interface *ifp;

		ifp = listnode_head(*intf_list);
		if (ifp == NULL)
			break;

		if (ifp->node) {
			ifp->node->info = NULL;
			route_unlock_node(ifp->node);
		}

		if_delete(ifp);
	}

	list_delete_and_null(intf_list);
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
		zlog_warn("Unknown value %d", llt);
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
