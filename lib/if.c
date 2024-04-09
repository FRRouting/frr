// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Interface functions.
 * Copyright (C) 1997, 98 Kunihiro Ishiguro
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
#include "admin_group.h"
#include "lib/if_clippy.c"

DEFINE_MTYPE_STATIC(LIB, IF, "Interface");
DEFINE_MTYPE_STATIC(LIB, IFDESC, "Intf Desc");
DEFINE_MTYPE_STATIC(LIB, CONNECTED, "Connected");
DEFINE_MTYPE_STATIC(LIB, NBR_CONNECTED, "Neighbor Connected");
DEFINE_MTYPE(LIB, CONNECTED_LABEL, "Connected interface label");
DEFINE_MTYPE_STATIC(LIB, IF_LINK_PARAMS, "Informational Link Parameters");

static void if_set_name(struct interface *ifp, const char *name);
static struct interface *if_lookup_by_ifindex(ifindex_t ifindex,
					      vrf_id_t vrf_id);
static struct interface *if_lookup_by_index_all_vrf(ifindex_t ifindex);
static int if_cmp_func(const struct interface *, const struct interface *);
static int if_cmp_index_func(const struct interface *ifp1,
			     const struct interface *ifp2);
RB_GENERATE(if_name_head, interface, name_entry, if_cmp_func);
RB_GENERATE(if_index_head, interface, index_entry, if_cmp_index_func);

DEFINE_QOBJ_TYPE(interface);

DEFINE_HOOK(if_add, (struct interface *ifp), (ifp));
DEFINE_KOOH(if_del, (struct interface *ifp), (ifp));

DEFINE_HOOK(if_real, (struct interface *ifp), (ifp));
DEFINE_KOOH(if_unreal, (struct interface *ifp), (ifp));

DEFINE_HOOK(if_up, (struct interface *ifp), (ifp));
DEFINE_KOOH(if_down, (struct interface *ifp), (ifp));

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
		char *tmp1, *tmp2;

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

		x1 = strtol(p1, &tmp1, 10);
		x2 = strtol(p2, &tmp2, 10);

		/* let's compare numbers now */
		if (x1 < x2)
			return -1;
		if (x1 > x2)
			return 1;

		/* Compare string if numbers are equal (distinguish foo-1 from foo-001) */
		l1 = strspn(p1, "0123456789");
		l2 = strspn(p2, "0123456789");
		if (l1 != l2)
			return (strcmp(p1, p2));

		/* Continue to parse the rest of the string */
		p1 = (const char *)tmp1;
		p2 = (const char *)tmp2;

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
	if (ifp1->ifindex == ifp2->ifindex)
		return 0;
	else if (ifp1->ifindex > ifp2->ifindex)
		return 1;
	else
		return -1;
}

static void ifp_connected_free(void *arg)
{
	struct connected *c = arg;

	connected_free(&c);
}

/* Create new interface structure. */
static struct interface *if_new(struct vrf *vrf)
{
	struct interface *ifp;

	assert(vrf);

	ifp = XCALLOC(MTYPE_IF, sizeof(struct interface));

	ifp->ifindex = IFINDEX_INTERNAL;
	ifp->name[0] = '\0';

	ifp->vrf = vrf;

	if_connected_init(ifp->connected);

	ifp->nbr_connected = list_new();
	ifp->nbr_connected->del = (void (*)(void *))nbr_connected_free;

	/* Enable Link-detection by default */
	SET_FLAG(ifp->status, ZEBRA_INTERFACE_LINKDETECTION);

	QOBJ_REG(ifp, interface);
	return ifp;
}

void if_new_via_zapi(struct interface *ifp)
{
	hook_call(if_real, ifp);
}

void if_destroy_via_zapi(struct interface *ifp)
{
	hook_call(if_unreal, ifp);

	ifp->oldifindex = ifp->ifindex;
	if_set_index(ifp, IFINDEX_INTERNAL);

	if (!ifp->configured)
		if_delete(&ifp);
}

void if_up_via_zapi(struct interface *ifp)
{
	hook_call(if_up, ifp);
}

void if_down_via_zapi(struct interface *ifp)
{
	hook_call(if_down, ifp);
}

static struct interface *if_create_name(const char *name, struct vrf *vrf)
{
	struct interface *ifp;

	ifp = if_new(vrf);

	if_set_name(ifp, name);

	hook_call(if_add, ifp);
	return ifp;
}

/* Create new interface structure. */
void if_update_to_new_vrf(struct interface *ifp, vrf_id_t vrf_id)
{
	struct vrf *old_vrf, *vrf;

	/* remove interface from old master vrf list */
	old_vrf = ifp->vrf;

	if (ifp->name[0] != '\0')
		IFNAME_RB_REMOVE(old_vrf, ifp);

	if (ifp->ifindex != IFINDEX_INTERNAL)
		IFINDEX_RB_REMOVE(old_vrf, ifp);

	vrf = vrf_get(vrf_id, NULL);
	ifp->vrf = vrf;

	if (ifp->name[0] != '\0')
		IFNAME_RB_INSERT(vrf, ifp);

	if (ifp->ifindex != IFINDEX_INTERNAL)
		IFINDEX_RB_INSERT(vrf, ifp);
}


/* Delete interface structure. */
void if_delete_retain(struct interface *ifp)
{
	struct connected *ifc;

	hook_call(if_del, ifp);
	QOBJ_UNREG(ifp);

	/* Free connected address list */
	while ((ifc = if_connected_pop(ifp->connected)))
		ifp_connected_free(ifc);

	/* Free connected nbr address list */
	list_delete_all_node(ifp->nbr_connected);
}

/* Delete and free interface structure. */
void if_delete(struct interface **ifp)
{
	struct interface *ptr = *ifp;
	struct vrf *vrf = ptr->vrf;

	IFNAME_RB_REMOVE(vrf, ptr);
	if (ptr->ifindex != IFINDEX_INTERNAL)
		IFINDEX_RB_REMOVE(vrf, ptr);

	if_delete_retain(ptr);

	if_connected_fini(ptr->connected);
	list_delete(&ptr->nbr_connected);

	if_link_params_free(ptr);

	XFREE(MTYPE_IFDESC, ptr->desc);

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

/* Interface existence check by index. */
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

/* Interface existence check by index. */
struct interface *if_vrf_lookup_by_index_next(ifindex_t ifindex,
					      vrf_id_t vrf_id)
{
	struct vrf *vrf = vrf_lookup_by_id(vrf_id);
	struct interface *tmp_ifp;
	bool found = false;

	if (!vrf)
		return NULL;

	if (ifindex == 0) {
		tmp_ifp = RB_MIN(if_index_head, &vrf->ifaces_by_index);
		/* skip the vrf interface */
		if (tmp_ifp && if_is_vrf(tmp_ifp))
			ifindex = tmp_ifp->ifindex;
		else
			return tmp_ifp;
	}

	RB_FOREACH (tmp_ifp, if_index_head, &vrf->ifaces_by_index) {
		if (found) {
			/* skip the vrf interface */
			if (tmp_ifp && if_is_vrf(tmp_ifp))
				continue;
			else
				return tmp_ifp;
		}
		if (tmp_ifp->ifindex == ifindex)
			found = true;
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

/* Interface existence check by interface name. */
struct interface *if_lookup_by_name(const char *name, vrf_id_t vrf_id)
{
	struct vrf *vrf = vrf_lookup_by_id(vrf_id);
	struct interface if_tmp;

	if (!vrf || !name || strnlen(name, IFNAMSIZ) == IFNAMSIZ)
		return NULL;

	strlcpy(if_tmp.name, name, sizeof(if_tmp.name));
	return RB_FIND(if_name_head, &vrf->ifaces_by_name, &if_tmp);
}

struct interface *if_lookup_by_name_vrf(const char *name, struct vrf *vrf)
{
	struct interface if_tmp;

	if (!name || strnlen(name, IFNAMSIZ) == IFNAMSIZ)
		return NULL;

	strlcpy(if_tmp.name, name, sizeof(if_tmp.name));
	return RB_FIND(if_name_head, &vrf->ifaces_by_name, &if_tmp);
}

static struct interface *if_lookup_by_name_all_vrf(const char *name)
{
	struct vrf *vrf;
	struct interface *ifp;

	if (!name || strnlen(name, IFNAMSIZ) == IFNAMSIZ)
		return NULL;

	RB_FOREACH (vrf, vrf_name_head, &vrfs_by_name) {
		ifp = if_lookup_by_name_vrf(name, vrf);
		if (ifp)
			return ifp;
	}

	return NULL;
}

static struct interface *if_lookup_by_index_all_vrf(ifindex_t ifindex)
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

/* Lookup interface by IP address.
 *
 * supersedes if_lookup_exact_address(), which didn't care about up/down
 * state.  but all users we have either only care if the address is local
 * (=> use if_address_is_local() please), or care about UP interfaces before
 * anything else
 *
 * to accept only UP interfaces, check if_is_up() on the returned ifp.
 */
struct interface *if_lookup_address_local(const void *src, int family,
					  vrf_id_t vrf_id)
{
	struct vrf *vrf = vrf_lookup_by_id(vrf_id);
	struct interface *ifp, *best_down = NULL;
	struct prefix *p;
	struct connected *c;

	if (family != AF_INET && family != AF_INET6)
		return NULL;

	FOR_ALL_INTERFACES (vrf, ifp) {
		frr_each (if_connected, ifp->connected, c) {
			p = c->address;

			if (!p || p->family != family)
				continue;

			if (family == AF_INET) {
				if (!IPV4_ADDR_SAME(&p->u.prefix4,
						    (struct in_addr *)src))
					continue;
			} else if (family == AF_INET6) {
				if (!IPV6_ADDR_SAME(&p->u.prefix6,
						    (struct in6_addr *)src))
					continue;
			}

			if (if_is_up(ifp))
				return ifp;
			if (!best_down)
				best_down = ifp;
		}
	}
	return best_down;
}

/* Lookup interface by IP address. */
struct connected *if_lookup_address(const void *matchaddr, int family,
				    vrf_id_t vrf_id)
{
	struct vrf *vrf = vrf_lookup_by_id(vrf_id);
	struct prefix addr;
	int bestlen = 0;
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
	} else
		assert(!"Attempted lookup of family not supported");

	match = NULL;

	FOR_ALL_INTERFACES (vrf, ifp) {
		frr_each (if_connected, ifp->connected, c) {
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
struct interface *if_lookup_prefix(const struct prefix *prefix, vrf_id_t vrf_id)
{
	struct vrf *vrf = vrf_lookup_by_id(vrf_id);
	struct interface *ifp;
	struct connected *c;

	FOR_ALL_INTERFACES (vrf, ifp) {
		frr_each (if_connected, ifp->connected, c) {
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

/* Get the VRF loopback interface, i.e. the loopback on the default VRF
 * or the VRF interface.
 */
struct interface *if_get_vrf_loopback(vrf_id_t vrf_id)
{
	struct interface *ifp = NULL;
	struct vrf *vrf = vrf_lookup_by_id(vrf_id);

	FOR_ALL_INTERFACES (vrf, ifp)
		if (if_is_loopback(ifp))
			return ifp;

	return NULL;
}

/* Get interface by name if given name interface doesn't exist create
   one. */
struct interface *if_get_by_name(const char *name, vrf_id_t vrf_id,
				 const char *vrf_name)
{
	struct interface *ifp = NULL;
	struct vrf *vrf;

	switch (vrf_get_backend()) {
	case VRF_BACKEND_UNKNOWN:
	case VRF_BACKEND_NETNS:
		vrf = vrf_get(vrf_id, vrf_name);
		assert(vrf);

		ifp = if_lookup_by_name_vrf(name, vrf);
		if (ifp) {
			/* If it came from the kernel or by way of zclient,
			 * believe it and update the ifp accordingly.
			 */
			if (ifp->vrf->vrf_id != vrf_id && vrf_id != VRF_UNKNOWN)
				if_update_to_new_vrf(ifp, vrf_id);

			return ifp;
		}

		break;
	case VRF_BACKEND_VRF_LITE:
		ifp = if_lookup_by_name_all_vrf(name);
		if (ifp) {
			/* If it came from the kernel or by way of zclient,
			 * believe it and update the ifp accordingly.
			 */
			if (ifp->vrf->vrf_id != vrf_id && vrf_id != VRF_UNKNOWN)
				if_update_to_new_vrf(ifp, vrf_id);

			return ifp;
		}

		vrf = vrf_get(vrf_id, vrf_name);
		assert(vrf);

		break;
	default:
		return NULL;
	}

	return if_create_name(name, vrf);
}

int if_set_index(struct interface *ifp, ifindex_t ifindex)
{
	if (ifp->ifindex == ifindex)
		return 0;

	/*
	 * If there is already an interface with this ifindex, we will collide
	 * on insertion, so don't even try.
	 */
	if (if_lookup_by_ifindex(ifindex, ifp->vrf->vrf_id))
		return -1;

	if (ifp->ifindex != IFINDEX_INTERNAL)
		IFINDEX_RB_REMOVE(ifp->vrf, ifp);

	ifp->ifindex = ifindex;

	if (ifp->ifindex != IFINDEX_INTERNAL) {
		/*
		 * This should never happen, since we checked if there was
		 * already an interface with the desired ifindex at the top of
		 * the function. Nevertheless.
		 */
		if (IFINDEX_RB_INSERT(ifp->vrf, ifp))
			return -1;
	}

	return 0;
}

static void if_set_name(struct interface *ifp, const char *name)
{
	if (if_cmp_name_func(ifp->name, name) == 0)
		return;

	if (ifp->name[0] != '\0')
		IFNAME_RB_REMOVE(ifp->vrf, ifp);

	strlcpy(ifp->name, name, sizeof(ifp->name));

	if (ifp->name[0] != '\0')
		IFNAME_RB_INSERT(ifp->vrf, ifp);
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
int if_is_loopback_exact(const struct interface *ifp)
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

/* Should this interface be treated as a loopback? */
bool if_is_loopback(const struct interface *ifp)
{
	if (if_is_loopback_exact(ifp) || if_is_vrf(ifp))
		return true;

	return false;
}

/* Does this interface support broadcast ? */
int if_is_broadcast(const struct interface *ifp)
{
	return ifp->flags & IFF_BROADCAST;
}

/* Does this interface support pointopoint ? */
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
	const struct connected *c;

	frr_each (if_connected_const, ifp->connected, c)
		zlog_info(
			"Interface %s vrf %s(%u) index %d metric %d mtu %d mtu6 %d %s",
			ifp->name, ifp->vrf->name, ifp->vrf->vrf_id,
			ifp->ifindex, ifp->metric, ifp->mtu, ifp->mtu6,
			if_flag_dump(ifp->flags));
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

	prefix_free(&ptr->address);
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

	snprintf(logbuf, sizeof(logbuf), "%s interface %s vrf %s(%u) %s %pFX ",
		 str, ifp->name, ifp->vrf->name, ifp->vrf->vrf_id,
		 prefix_family_str(p), p);

	p = connected->destination;
	if (p) {
		strlcat(logbuf, inet_ntop(p->family, &p->u.prefix, buf, BUFSIZ),
			BUFSIZ);
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

	ifp = connected->ifp;
	p = connected->address;

	snprintf(logbuf, sizeof(logbuf), "%s interface %s %s %pFX ", str,
		 ifp->name, prefix_family_str(p), p);

	zlog_info("%s", logbuf);
}

/* If two connected address has same prefix return 1. */
static int connected_same_prefix(const struct prefix *p1,
				 const struct prefix *p2)
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
	struct connected *connected;
	unsigned int cnt = 0;

	frr_each (if_connected, ifp->connected, connected)
		if (connected->address->family == family)
			cnt++;

	return cnt;
}

struct connected *connected_lookup_prefix_exact(struct interface *ifp,
						const struct prefix *p)
{
	struct connected *ifc;

	frr_each (if_connected, ifp->connected, ifc) {
		if (connected_same_prefix(ifc->address, p))
			return ifc;
	}
	return NULL;
}

struct connected *connected_delete_by_prefix(struct interface *ifp,
					     struct prefix *p)
{
	struct connected *ifc;

	/* In case of same prefix come, replace it with new one. */
	frr_each_safe (if_connected, ifp->connected, ifc) {
		if (connected_same_prefix(ifc->address, p)) {
			if_connected_del(ifp->connected, ifc);
			return ifc;
		}
	}
	return NULL;
}

/* Find the address on our side that will be used when packets
   are sent to dst. */
struct connected *connected_lookup_prefix(struct interface *ifp,
					  const struct prefix *addr)
{
	struct connected *c;
	struct connected *match;

	match = NULL;

	frr_each (if_connected, ifp->connected, c) {
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
	if_connected_add_tail(ifp->connected, ifc);
	return ifc;
}

struct connected *connected_get_linklocal(struct interface *ifp)
{
	struct connected *c = NULL;

	frr_each (if_connected, ifp->connected, c) {
		if (c->address->family == AF_INET6
		    && IN6_IS_ADDR_LINKLOCAL(&c->address->u.prefix6))
			break;
	}
	return c;
}

void if_terminate(struct vrf *vrf)
{
	struct interface *ifp;

	while (!RB_EMPTY(if_name_head, &vrf->ifaces_by_name)) {
		ifp = RB_ROOT(if_name_head, &vrf->ifaces_by_name);

		if (ifp->node) {
			ifp->node->info = NULL;
			route_unlock_node(ifp->node);
			ifp->node = NULL;
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
		llts(ZEBRA_LLT_RSRVD, "Reserved");
		llts(ZEBRA_LLT_ADAPT, "Adapt");
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
		llts(ZEBRA_LLT_IP6GRE, "GRE over IPv6");
		llts(ZEBRA_LLT_PIMREG, "PIMSM registration");
		llts(ZEBRA_LLT_HIPPI, "HiPPI");
		llts(ZEBRA_LLT_ECONET, "Acorn Econet");
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
#undef llts
	}
	return NULL;
}

bool if_link_params_cmp(struct if_link_params *iflp1,
			struct if_link_params *iflp2)
{
	struct if_link_params iflp1_copy, iflp2_copy;

	/* Extended admin-groups in if_link_params contain pointers.
	 * They cannot be compared with memcpy.
	 * Make copies of if_link_params without ext. admin-groups
	 * and compare separately the ext. admin-groups.
	 */
	memcpy(&iflp1_copy, iflp1, sizeof(struct if_link_params));
	memset(&iflp1_copy.ext_admin_grp, 0, sizeof(struct admin_group));

	memcpy(&iflp2_copy, iflp2, sizeof(struct if_link_params));
	memset(&iflp2_copy.ext_admin_grp, 0, sizeof(struct admin_group));

	if (memcmp(&iflp1_copy, &iflp2_copy, sizeof(struct if_link_params)))
		return false;

	if (!admin_group_cmp(&iflp1->ext_admin_grp, &iflp2->ext_admin_grp))
		return false;

	return true;
}

void if_link_params_copy(struct if_link_params *dst, struct if_link_params *src)
{
	struct admin_group dst_ag;

	/* backup the admin_group structure that contains a pointer */
	memcpy(&dst_ag, &dst->ext_admin_grp, sizeof(struct admin_group));
	/* copy the if_link_params structure */
	memcpy(dst, src, sizeof(struct if_link_params));
	/* restore the admin_group structure */
	memcpy(&dst->ext_admin_grp, &dst_ag, sizeof(struct admin_group));
	/* copy src->ext_admin_grp data to dst->ext_admin_grp data memory */
	admin_group_copy(&dst->ext_admin_grp, &src->ext_admin_grp);
}

struct if_link_params *if_link_params_get(struct interface *ifp)
{
	return ifp->link_params;
}

struct if_link_params *if_link_params_enable(struct interface *ifp)
{
	struct if_link_params *iflp;
	int i;

	iflp = if_link_params_init(ifp);

	/* Compute default bandwidth based on interface */
	iflp->default_bw =
		((ifp->bandwidth ? ifp->bandwidth : DEFAULT_BANDWIDTH)
		 * TE_MEGA_BIT / TE_BYTE);

	/* Set Max, Reservable and Unreserved Bandwidth */
	iflp->max_bw = iflp->default_bw;
	iflp->max_rsv_bw = iflp->default_bw;
	for (i = 0; i < MAX_CLASS_TYPE; i++)
		iflp->unrsv_bw[i] = iflp->default_bw;

	/* Update Link parameters status */
	iflp->lp_status = LP_MAX_BW | LP_MAX_RSV_BW | LP_UNRSV_BW;

	/* Set TE metric equal to standard metric only if it is set */
	if (ifp->metric != 0) {
		iflp->te_metric = ifp->metric;
		iflp->lp_status |= LP_TE_METRIC;
	}

	/* Finally attach newly created Link Parameters */
	ifp->link_params = iflp;

	return iflp;
}

struct if_link_params *if_link_params_init(struct interface *ifp)
{
	struct if_link_params *iflp = if_link_params_get(ifp);

	if (iflp)
		return iflp;

	iflp = XCALLOC(MTYPE_IF_LINK_PARAMS, sizeof(struct if_link_params));

	admin_group_init(&iflp->ext_admin_grp);

	ifp->link_params = iflp;

	return iflp;
}

void if_link_params_free(struct interface *ifp)
{
	if (!ifp->link_params)
		return;

	admin_group_term(&ifp->link_params->ext_admin_grp);
	XFREE(MTYPE_IF_LINK_PARAMS, ifp->link_params);
}

/* ----------- CLI commands ----------- */

/* Guess the VRF of an interface. */
static int vrfname_by_ifname(const char *ifname, const char **vrfname)
{
	struct vrf *vrf;
	struct interface *ifp;
	int count = 0;

	RB_FOREACH (vrf, vrf_name_head, &vrfs_by_name) {
		FOR_ALL_INTERFACES (vrf, ifp) {
			if (strmatch(ifp->name, ifname)) {
				*vrfname = vrf->name;
				count++;
			}
		}
	}

	return count;
}

/*
 * XPath: /frr-interface:lib/interface
 */
DEFPY_YANG_NOSH (interface,
       interface_cmd,
       "interface IFNAME [vrf NAME$vrf_name]",
       "Select an interface to configure\n"
       "Interface's name\n"
       VRF_CMD_HELP_STR)
{
	char xpath_list[XPATH_MAXLEN];
	struct interface *ifp;
	struct vrf *vrf;
	int ret, count;

	if (vrf_is_backend_netns()) {
		/*
		 * For backward compatibility, if the VRF name is not specified
		 * and there is exactly one interface with this name in the
		 * system, use its VRF. Otherwise fallback to the default VRF.
		 */
		if (!vrf_name) {
			count = vrfname_by_ifname(ifname, &vrf_name);
			if (count != 1)
				vrf_name = VRF_DEFAULT_NAME;
		}

		snprintf(xpath_list, XPATH_MAXLEN,
			 "/frr-interface:lib/interface[name='%s:%s']", vrf_name,
			 ifname);
	} else {
		snprintf(xpath_list, XPATH_MAXLEN,
			 "/frr-interface:lib/interface[name='%s']", ifname);
	}

	nb_cli_enqueue_change(vty, ".", NB_OP_CREATE, NULL);
	ret = nb_cli_apply_changes_clear_pending(vty, "%s", xpath_list);
	if (ret == CMD_SUCCESS) {
		VTY_PUSH_XPATH(INTERFACE_NODE, xpath_list);

		/*
		 * For backward compatibility with old commands we still need
		 * to use the qobj infrastructure. This can be removed once
		 * all interface-level commands are converted to the new
		 * northbound model.
		 */
		if (vrf_is_backend_netns()) {
			vrf = vrf_lookup_by_name(vrf_name);
			if (vrf)
				ifp = if_lookup_by_name_vrf(ifname, vrf);
			else
				ifp = NULL;
		} else {
			ifp = if_lookup_by_name_all_vrf(ifname);
		}
		if (ifp)
			VTY_PUSH_CONTEXT(INTERFACE_NODE, ifp);
	}

	return ret;
}

DEFPY_YANG (no_interface,
       no_interface_cmd,
       "no interface IFNAME [vrf NAME$vrf_name]",
       NO_STR
       "Delete a pseudo interface's configuration\n"
       "Interface's name\n"
       VRF_CMD_HELP_STR)
{
	char xpath_list[XPATH_MAXLEN];
	int count;

	if (vrf_is_backend_netns()) {
		/*
		 * For backward compatibility, if the VRF name is not specified
		 * and there is exactly one interface with this name in the
		 * system, use its VRF. Otherwise fallback to the default VRF.
		 */
		if (!vrf_name) {
			count = vrfname_by_ifname(ifname, &vrf_name);
			if (count != 1)
				vrf_name = VRF_DEFAULT_NAME;
		}

		snprintf(xpath_list, XPATH_MAXLEN,
			 "/frr-interface:lib/interface[name='%s:%s']", vrf_name,
			 ifname);
	} else {
		snprintf(xpath_list, XPATH_MAXLEN,
			 "/frr-interface:lib/interface[name='%s']", ifname);
	}

	nb_cli_enqueue_change(vty, ".", NB_OP_DESTROY, NULL);

	return nb_cli_apply_changes(vty, "%s", xpath_list);
}

static void netns_ifname_split(const char *xpath, char *ifname, char *vrfname)
{
	char *delim;
	int len;

	assert(vrf_is_backend_netns());

	delim = strchr(xpath, ':');
	assert(delim);

	len = delim - xpath;
	memcpy(vrfname, xpath, len);
	vrfname[len] = 0;

	strlcpy(ifname, delim + 1, XPATH_MAXLEN);
}

static void cli_show_interface(struct vty *vty, const struct lyd_node *dnode,
			       bool show_defaults)
{
	vty_out(vty, "!\n");

	if (vrf_is_backend_netns()) {
		char ifname[XPATH_MAXLEN];
		char vrfname[XPATH_MAXLEN];

		netns_ifname_split(yang_dnode_get_string(dnode, "name"),
				   ifname, vrfname);

		vty_out(vty, "interface %s", ifname);
		if (!strmatch(vrfname, VRF_DEFAULT_NAME))
			vty_out(vty, " vrf %s", vrfname);
	} else {
		const char *ifname = yang_dnode_get_string(dnode, "name");

		vty_out(vty, "interface %s", ifname);
	}

	vty_out(vty, "\n");
}

static void cli_show_interface_end(struct vty *vty,
				   const struct lyd_node *dnode)
{
	vty_out(vty, "exit\n");
}

static int cli_cmp_interface(const struct lyd_node *dnode1,
			     const struct lyd_node *dnode2)
{
	const char *ifname1 = yang_dnode_get_string(dnode1, "name");
	const char *ifname2 = yang_dnode_get_string(dnode2, "name");

	return if_cmp_name_func(ifname1, ifname2);
}

void if_vty_config_start(struct vty *vty, struct interface *ifp)
{
	vty_frame(vty, "!\n");
	vty_frame(vty, "interface %s", ifp->name);

	if (vrf_is_backend_netns() && strcmp(ifp->vrf->name, VRF_DEFAULT_NAME))
		vty_frame(vty, " vrf %s", ifp->vrf->name);

	vty_frame(vty, "\n");
}

void if_vty_config_end(struct vty *vty)
{
	vty_endframe(vty, "exit\n!\n");
}

/*
 * XPath: /frr-interface:lib/interface/description
 */
DEFPY_YANG (interface_desc,
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

DEFPY_YANG  (no_interface_desc,
	no_interface_desc_cmd,
	"no description",
	NO_STR
	"Interface specific description\n")
{
	nb_cli_enqueue_change(vty, "./description", NB_OP_DESTROY, NULL);

	return nb_cli_apply_changes(vty, NULL);
}

static void cli_show_interface_desc(struct vty *vty,
				    const struct lyd_node *dnode,
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

static struct cmd_node interface_node = {
	.name = "interface",
	.node = INTERFACE_NODE,
	.parent_node = CONFIG_NODE,
	.prompt = "%s(config-if)# ",
};

static int if_config_write_single(const struct lyd_node *dnode, void *arg)
{
	nb_cli_show_dnode_cmds(arg, dnode, false);

	return YANG_ITER_CONTINUE;
}

static int if_nb_config_write(struct vty *vty)
{
	yang_dnode_iterate(if_config_write_single, vty, running_config->dnode,
			   "/frr-interface:lib/interface");
	return 1;
}

void if_cmd_init(int (*config_write)(struct vty *))
{
	cmd_variable_handler_register(if_var_handlers);

	interface_node.config_write = config_write;
	install_node(&interface_node);

	install_element(CONFIG_NODE, &interface_cmd);
	install_element(CONFIG_NODE, &no_interface_cmd);

	install_default(INTERFACE_NODE);
	install_element(INTERFACE_NODE, &interface_desc_cmd);
	install_element(INTERFACE_NODE, &no_interface_desc_cmd);
}

void if_cmd_init_default(void)
{
	if_cmd_init(if_nb_config_write);
}

/* ------- Northbound callbacks ------- */

/*
 * XPath: /frr-interface:lib/interface
 */
static int lib_interface_create(struct nb_cb_create_args *args)
{
	const char *ifname;
	struct interface *ifp;

	ifname = yang_dnode_get_string(args->dnode, "name");

	switch (args->event) {
	case NB_EV_VALIDATE:
		if (vrf_is_backend_netns()) {
			char ifname_ns[XPATH_MAXLEN];
			char vrfname_ns[XPATH_MAXLEN];

			netns_ifname_split(ifname, ifname_ns, vrfname_ns);

			if (strlen(ifname_ns) > 16) {
				snprintf(
					args->errmsg, args->errmsg_len,
					"Maximum interface name length is 16 characters");
				return NB_ERR_VALIDATION;
			}
			if (strlen(vrfname_ns) > 36) {
				snprintf(
					args->errmsg, args->errmsg_len,
					"Maximum VRF name length is 36 characters");
				return NB_ERR_VALIDATION;
			}
		} else {
			if (strlen(ifname) > 16) {
				snprintf(
					args->errmsg, args->errmsg_len,
					"Maximum interface name length is 16 characters");
				return NB_ERR_VALIDATION;
			}
		}
		break;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		if (vrf_is_backend_netns()) {
			char ifname_ns[XPATH_MAXLEN];
			char vrfname_ns[XPATH_MAXLEN];

			netns_ifname_split(ifname, ifname_ns, vrfname_ns);

			ifp = if_get_by_name(ifname_ns, VRF_UNKNOWN,
					     vrfname_ns);
		} else {
			ifp = if_get_by_name(ifname, VRF_UNKNOWN,
					     VRF_DEFAULT_NAME);
		}

		ifp->configured = true;
		nb_running_set_entry(args->dnode, ifp);
		break;
	}

	return NB_OK;
}

static int lib_interface_destroy(struct nb_cb_destroy_args *args)
{
	struct interface *ifp;
	struct vrf *vrf;

	switch (args->event) {
	case NB_EV_VALIDATE:
		ifp = nb_running_get_entry(args->dnode, NULL, true);
		if (CHECK_FLAG(ifp->status, ZEBRA_INTERFACE_ACTIVE)) {
			snprintf(args->errmsg, args->errmsg_len,
				 "only inactive interfaces can be deleted");
			return NB_ERR_VALIDATION;
		}
		break;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		ifp = nb_running_unset_entry(args->dnode);
		vrf = ifp->vrf;

		ifp->configured = false;
		if_delete(&ifp);

		if (!vrf_is_enabled(vrf))
			vrf_delete(vrf);
		break;
	}

	return NB_OK;
}

/*
 * XPath: /frr-interface:lib/interface
 */
static const void *lib_interface_get_next(struct nb_cb_get_next_args *args)
{
	struct vrf *vrf;
	struct interface *pif = (struct interface *)args->list_entry;

	if (args->list_entry == NULL) {
		vrf = RB_MIN(vrf_name_head, &vrfs_by_name);
		assert(vrf);
		pif = RB_MIN(if_name_head, &vrf->ifaces_by_name);
	} else {
		vrf = pif->vrf;
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

static int lib_interface_get_keys(struct nb_cb_get_keys_args *args)
{
	const struct interface *ifp = args->list_entry;

	args->keys->num = 1;

	if (vrf_is_backend_netns())
		snprintf(args->keys->key[0], sizeof(args->keys->key[0]),
			 "%s:%s", ifp->vrf->name, ifp->name);
	else
		snprintf(args->keys->key[0], sizeof(args->keys->key[0]), "%s",
			 ifp->name);

	return NB_OK;
}

static const void *
lib_interface_lookup_entry(struct nb_cb_lookup_entry_args *args)
{
	if (vrf_is_backend_netns()) {
		char ifname[XPATH_MAXLEN];
		char vrfname[XPATH_MAXLEN];
		struct vrf *vrf;

		netns_ifname_split(args->keys->key[0], ifname, vrfname);

		vrf = vrf_lookup_by_name(vrfname);

		return vrf ? if_lookup_by_name(ifname, vrf->vrf_id) : NULL;
	} else {
		return if_lookup_by_name_all_vrf(args->keys->key[0]);
	}
}

/*
 * XPath: /frr-interface:lib/interface/description
 */
static int lib_interface_description_modify(struct nb_cb_modify_args *args)
{
	struct interface *ifp;
	const char *description;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	ifp = nb_running_get_entry(args->dnode, NULL, true);
	XFREE(MTYPE_IFDESC, ifp->desc);
	description = yang_dnode_get_string(args->dnode, NULL);
	ifp->desc = XSTRDUP(MTYPE_IFDESC, description);

	return NB_OK;
}

static int lib_interface_description_destroy(struct nb_cb_destroy_args *args)
{
	struct interface *ifp;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	ifp = nb_running_get_entry(args->dnode, NULL, true);
	XFREE(MTYPE_IFDESC, ifp->desc);

	return NB_OK;
}

/*
 * XPath: /frr-interface:lib/interface/vrf
 */
static struct yang_data *
lib_interface_vrf_get_elem(struct nb_cb_get_elem_args *args)
{
	const struct interface *ifp = args->list_entry;

	return yang_data_new_string(args->xpath, ifp->vrf->name);
}

/*
 * XPath: /frr-interface:lib/interface/state/if-index
 */
static struct yang_data *
lib_interface_state_if_index_get_elem(struct nb_cb_get_elem_args *args)
{
	const struct interface *ifp = args->list_entry;

	return yang_data_new_int32(args->xpath, ifp->ifindex);
}

/*
 * XPath: /frr-interface:lib/interface/state/mtu
 */
static struct yang_data *
lib_interface_state_mtu_get_elem(struct nb_cb_get_elem_args *args)
{
	const struct interface *ifp = args->list_entry;

	return yang_data_new_uint32(args->xpath, ifp->mtu);
}

/*
 * XPath: /frr-interface:lib/interface/state/mtu6
 */
static struct yang_data *
lib_interface_state_mtu6_get_elem(struct nb_cb_get_elem_args *args)
{
	const struct interface *ifp = args->list_entry;

	return yang_data_new_uint32(args->xpath, ifp->mtu6);
}

/*
 * XPath: /frr-interface:lib/interface/state/speed
 */
static struct yang_data *
lib_interface_state_speed_get_elem(struct nb_cb_get_elem_args *args)
{
	const struct interface *ifp = args->list_entry;

	return yang_data_new_uint32(args->xpath, ifp->speed);
}

/*
 * XPath: /frr-interface:lib/interface/state/metric
 */
static struct yang_data *
lib_interface_state_metric_get_elem(struct nb_cb_get_elem_args *args)
{
	const struct interface *ifp = args->list_entry;

	return yang_data_new_uint32(args->xpath, ifp->metric);
}

/*
 * XPath: /frr-interface:lib/interface/state/flags
 */
static struct yang_data *
lib_interface_state_flags_get_elem(struct nb_cb_get_elem_args *args)
{
	/* TODO: implement me. */
	return NULL;
}

/*
 * XPath: /frr-interface:lib/interface/state/type
 */
static struct yang_data *
lib_interface_state_type_get_elem(struct nb_cb_get_elem_args *args)
{
	/* TODO: implement me. */
	return NULL;
}

/*
 * XPath: /frr-interface:lib/interface/state/phy-address
 */
static struct yang_data *
lib_interface_state_phy_address_get_elem(struct nb_cb_get_elem_args *args)
{
	const struct interface *ifp = args->list_entry;
	struct ethaddr macaddr;

	memcpy(&macaddr.octet, ifp->hw_addr, ETH_ALEN);

	return yang_data_new_mac(args->xpath, &macaddr);
}

/* clang-format off */

/* cli_show callbacks are kept here for daemons not yet converted to mgmtd */
const struct frr_yang_module_info frr_interface_info = {
	.name = "frr-interface",
	.nodes = {
		{
			.xpath = "/frr-interface:lib/interface",
			.cbs = {
				.create = lib_interface_create,
				.destroy = lib_interface_destroy,
				.cli_show = cli_show_interface,
				.cli_show_end = cli_show_interface_end,
				.cli_cmp = cli_cmp_interface,
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
			.xpath = "/frr-interface:lib/interface/vrf",
			.cbs = {
				.get_elem = lib_interface_vrf_get_elem,
			}
		},
		{
			.xpath = "/frr-interface:lib/interface/state/if-index",
			.cbs = {
				.get_elem = lib_interface_state_if_index_get_elem,
			}
		},
		{
			.xpath = "/frr-interface:lib/interface/state/mtu",
			.cbs = {
				.get_elem = lib_interface_state_mtu_get_elem,
			}
		},
		{
			.xpath = "/frr-interface:lib/interface/state/mtu6",
			.cbs = {
				.get_elem = lib_interface_state_mtu6_get_elem,
			}
		},
		{
			.xpath = "/frr-interface:lib/interface/state/speed",
			.cbs = {
				.get_elem = lib_interface_state_speed_get_elem,
			}
		},
		{
			.xpath = "/frr-interface:lib/interface/state/metric",
			.cbs = {
				.get_elem = lib_interface_state_metric_get_elem,
			}
		},
		{
			.xpath = "/frr-interface:lib/interface/state/flags",
			.cbs = {
				.get_elem = lib_interface_state_flags_get_elem,
			}
		},
		{
			.xpath = "/frr-interface:lib/interface/state/type",
			.cbs = {
				.get_elem = lib_interface_state_type_get_elem,
			}
		},
		{
			.xpath = "/frr-interface:lib/interface/state/phy-address",
			.cbs = {
				.get_elem = lib_interface_state_phy_address_get_elem,
			}
		},
		{
			.xpath = NULL,
		},
	}
};

const struct frr_yang_module_info frr_interface_cli_info = {
	.name = "frr-interface",
	.ignore_cfg_cbs = true,
	.nodes = {
		{
			.xpath = "/frr-interface:lib/interface",
			.cbs = {
				.cli_show = cli_show_interface,
				.cli_show_end = cli_show_interface_end,
				.cli_cmp = cli_cmp_interface,
			},
		},
		{
			.xpath = "/frr-interface:lib/interface/description",
			.cbs = {
				.cli_show = cli_show_interface_desc,
			},
		},
		{
			.xpath = NULL,
		},
	}
};
