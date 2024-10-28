// SPDX-License-Identifier: GPL-2.0-or-later
/* Routing Information Base.
 * Copyright (C) 1997, 98, 99, 2001 Kunihiro Ishiguro
 */

#include <zebra.h>

#ifdef GNU_LINUX
#include <linux/rtnetlink.h>
#endif

#include "command.h"
#include "if.h"
#include "linklist.h"
#include "log.h"
#include "memory.h"
#include "mpls.h"
#include "nexthop.h"
#include "prefix.h"
#include "prefix.h"
#include "routemap.h"
#include "sockunion.h"
#include "srcdest_table.h"
#include "table.h"
#include "frrevent.h"
#include "vrf.h"
#include "workqueue.h"
#include "nexthop_group_private.h"
#include "frr_pthread.h"
#include "printfrr.h"
#include "frrscript.h"
#include "frrdistance.h"

#include "zebra/zebra_router.h"
#include "zebra/connected.h"
#include "zebra/debug.h"
#include "zebra/interface.h"
#include "zebra/redistribute.h"
#include "zebra/rib.h"
#include "zebra/rt.h"
#include "zebra/zapi_msg.h"
#include "zebra/zebra_errors.h"
#include "zebra/zebra_ns.h"
#include "zebra/zebra_rnh.h"
#include "zebra/zebra_routemap.h"
#include "zebra/zebra_vrf.h"
#include "zebra/zebra_vxlan.h"
#include "zebra/zapi_msg.h"
#include "zebra/zebra_dplane.h"
#include "zebra/zebra_evpn_mh.h"
#include "zebra/zebra_script.h"

DEFINE_MGROUP(ZEBRA, "zebra");

DEFINE_MTYPE(ZEBRA, RE,       "Route Entry");
DEFINE_MTYPE_STATIC(ZEBRA, RIB_DEST,       "RIB destination");
DEFINE_MTYPE_STATIC(ZEBRA, RIB_UPDATE_CTX, "Rib update context object");
DEFINE_MTYPE_STATIC(ZEBRA, WQ_WRAPPER, "WQ wrapper");

/*
 * Event, list, and mutex for delivery of dataplane results
 */
static pthread_mutex_t dplane_mutex;
static struct event *t_dplane;
static struct dplane_ctx_list_head rib_dplane_q;

DEFINE_HOOK(rib_update, (struct route_node * rn, const char *reason),
	    (rn, reason));
DEFINE_HOOK(rib_shutdown, (struct route_node * rn), (rn));


/*
 * Meta Q's specific names
 *
 * If you add something here ensure that you
 * change MQ_SIZE as well over in rib.h
 */
enum meta_queue_indexes {
	META_QUEUE_NHG,
	META_QUEUE_EVPN,
	META_QUEUE_EARLY_ROUTE,
	META_QUEUE_EARLY_LABEL,
	META_QUEUE_CONNECTED,
	META_QUEUE_KERNEL,
	META_QUEUE_STATIC,
	META_QUEUE_NOTBGP,
	META_QUEUE_BGP,
	META_QUEUE_OTHER,
	META_QUEUE_GR_RUN,
};

/* Each route type's string and default distance value. */
static const struct {
	int key;
	uint8_t distance;
	enum meta_queue_indexes meta_q_map;
} route_info[ZEBRA_ROUTE_MAX] = {
	[ZEBRA_ROUTE_NHG] =
		{ZEBRA_ROUTE_NHG,
		 ZEBRA_MAX_DISTANCE_DEFAULT /* Unneeded for nhg's */,
		 META_QUEUE_NHG},
	[ZEBRA_ROUTE_SYSTEM] = {ZEBRA_ROUTE_SYSTEM,
				ZEBRA_KERNEL_DISTANCE_DEFAULT,
				META_QUEUE_KERNEL},
	[ZEBRA_ROUTE_KERNEL] = {ZEBRA_ROUTE_KERNEL,
				ZEBRA_KERNEL_DISTANCE_DEFAULT,
				META_QUEUE_KERNEL},
	[ZEBRA_ROUTE_CONNECT] = {ZEBRA_ROUTE_CONNECT,
				 ZEBRA_CONNECT_DISTANCE_DEFAULT,
				 META_QUEUE_CONNECTED},
	[ZEBRA_ROUTE_LOCAL] = {ZEBRA_ROUTE_LOCAL,
			       ZEBRA_CONNECT_DISTANCE_DEFAULT,
			       META_QUEUE_CONNECTED},
	[ZEBRA_ROUTE_STATIC] = {ZEBRA_ROUTE_STATIC,
				ZEBRA_STATIC_DISTANCE_DEFAULT,
				META_QUEUE_STATIC},
	[ZEBRA_ROUTE_RIP] = {ZEBRA_ROUTE_RIP, ZEBRA_RIP_DISTANCE_DEFAULT,
			     META_QUEUE_NOTBGP},
	[ZEBRA_ROUTE_RIPNG] = {ZEBRA_ROUTE_RIPNG, ZEBRA_RIP_DISTANCE_DEFAULT,
			       META_QUEUE_NOTBGP},
	[ZEBRA_ROUTE_OSPF] = {ZEBRA_ROUTE_OSPF, ZEBRA_OSPF_DISTANCE_DEFAULT,
			      META_QUEUE_NOTBGP},
	[ZEBRA_ROUTE_OSPF6] = {ZEBRA_ROUTE_OSPF6, ZEBRA_OSPF6_DISTANCE_DEFAULT,
			       META_QUEUE_NOTBGP},
	[ZEBRA_ROUTE_ISIS] = {ZEBRA_ROUTE_ISIS, ZEBRA_ISIS_DISTANCE_DEFAULT,
			      META_QUEUE_NOTBGP},
	[ZEBRA_ROUTE_BGP] = {ZEBRA_ROUTE_BGP,
			     ZEBRA_EBGP_DISTANCE_DEFAULT /* IBGP is 200. */,
			     META_QUEUE_BGP},
	[ZEBRA_ROUTE_PIM] = {ZEBRA_ROUTE_PIM, ZEBRA_MAX_DISTANCE_DEFAULT,
			     META_QUEUE_OTHER},
	[ZEBRA_ROUTE_EIGRP] = {ZEBRA_ROUTE_EIGRP, ZEBRA_EIGRP_DISTANCE_DEFAULT,
			       META_QUEUE_NOTBGP},
	[ZEBRA_ROUTE_NHRP] = {ZEBRA_ROUTE_NHRP, ZEBRA_NHRP_DISTANCE_DEFAULT,
			      META_QUEUE_NOTBGP},
	[ZEBRA_ROUTE_HSLS] = {ZEBRA_ROUTE_HSLS, ZEBRA_MAX_DISTANCE_DEFAULT,
			      META_QUEUE_OTHER},
	[ZEBRA_ROUTE_OLSR] = {ZEBRA_ROUTE_OLSR, ZEBRA_MAX_DISTANCE_DEFAULT,
			      META_QUEUE_OTHER},
	[ZEBRA_ROUTE_TABLE] = {ZEBRA_ROUTE_TABLE, ZEBRA_TABLE_DISTANCE_DEFAULT, META_QUEUE_STATIC},
	[ZEBRA_ROUTE_TABLE_DIRECT] = {ZEBRA_ROUTE_TABLE_DIRECT, ZEBRA_TABLEDIRECT_DISTANCE_DEFAULT, META_QUEUE_STATIC},
	[ZEBRA_ROUTE_LDP] = {ZEBRA_ROUTE_LDP, ZEBRA_LDP_DISTANCE_DEFAULT,
			     META_QUEUE_OTHER},
	[ZEBRA_ROUTE_VNC] = {ZEBRA_ROUTE_VNC, ZEBRA_EBGP_DISTANCE_DEFAULT,
			     META_QUEUE_BGP},
	[ZEBRA_ROUTE_VNC_DIRECT] = {ZEBRA_ROUTE_VNC_DIRECT,
				    ZEBRA_EBGP_DISTANCE_DEFAULT,
				    META_QUEUE_BGP},
	[ZEBRA_ROUTE_VNC_DIRECT_RH] = {ZEBRA_ROUTE_VNC_DIRECT_RH,
				       ZEBRA_EBGP_DISTANCE_DEFAULT,
				       META_QUEUE_BGP},
	[ZEBRA_ROUTE_BGP_DIRECT] = {ZEBRA_ROUTE_BGP_DIRECT,
				    ZEBRA_EBGP_DISTANCE_DEFAULT,
				    META_QUEUE_BGP},
	[ZEBRA_ROUTE_BGP_DIRECT_EXT] = {ZEBRA_ROUTE_BGP_DIRECT_EXT,
					ZEBRA_EBGP_DISTANCE_DEFAULT,
					META_QUEUE_BGP},
	[ZEBRA_ROUTE_BABEL] = {ZEBRA_ROUTE_BABEL, ZEBRA_BABEL_DISTANCE_DEFAULT,
			       META_QUEUE_NOTBGP},
	[ZEBRA_ROUTE_SHARP] = {ZEBRA_ROUTE_SHARP, ZEBRA_SHARP_DISTANCE_DEFAULT,
			       META_QUEUE_OTHER},
	[ZEBRA_ROUTE_PBR] = {ZEBRA_ROUTE_PBR, ZEBRA_PBR_DISTANCE_DEFAULT,
			     META_QUEUE_OTHER},
	[ZEBRA_ROUTE_BFD] = {ZEBRA_ROUTE_BFD, ZEBRA_MAX_DISTANCE_DEFAULT,
			     META_QUEUE_OTHER},
	[ZEBRA_ROUTE_OPENFABRIC] = {ZEBRA_ROUTE_OPENFABRIC,
				    ZEBRA_OPENFABRIC_DISTANCE_DEFAULT,
				    META_QUEUE_NOTBGP},
	[ZEBRA_ROUTE_VRRP] = {ZEBRA_ROUTE_VRRP, ZEBRA_MAX_DISTANCE_DEFAULT,
			      META_QUEUE_OTHER},
	[ZEBRA_ROUTE_SRTE] = {ZEBRA_ROUTE_SRTE, ZEBRA_MAX_DISTANCE_DEFAULT,
			      META_QUEUE_OTHER},
	[ZEBRA_ROUTE_ALL] = {ZEBRA_ROUTE_ALL, ZEBRA_MAX_DISTANCE_DEFAULT,
			     META_QUEUE_OTHER},
	/* Any new route type added to zebra, should be mirrored here */

	/* no entry/default: 150 */
};

/* Wrapper struct for nhg workqueue items; a 'ctx' is an incoming update
 * from the OS, and an 'nhe' is a nhe update.
 */
struct wq_nhg_wrapper {
	int type;
	union {
		struct nhg_ctx *ctx;
		struct nhg_hash_entry *nhe;
	} u;
	bool deletion;
};

#define WQ_NHG_WRAPPER_TYPE_CTX  0x01
#define WQ_NHG_WRAPPER_TYPE_NHG  0x02

/* Wrapper structs for evpn/vxlan workqueue items. */
struct wq_evpn_wrapper {
	int type;
	bool add_p;
	vrf_id_t vrf_id;
	bool esr_rxed;
	uint8_t df_alg;
	uint16_t df_pref;
	uint32_t flags;
	uint32_t seq;
	esi_t esi;
	vni_t vni;
	struct ipaddr ip;
	struct ethaddr macaddr;
	struct prefix prefix;
	struct in_addr vtep_ip;
};

#define WQ_EVPN_WRAPPER_TYPE_VRFROUTE     0x01
#define WQ_EVPN_WRAPPER_TYPE_REM_ES       0x02
#define WQ_EVPN_WRAPPER_TYPE_REM_MACIP    0x03
#define WQ_EVPN_WRAPPER_TYPE_REM_VTEP     0x04

enum wq_label_types {
	WQ_LABEL_FTN_UNINSTALL,
	WQ_LABEL_LABELS_PROCESS,
};

struct wq_label_wrapper {
	enum wq_label_types type;
	vrf_id_t vrf_id;

	struct prefix p;
	enum lsp_types_t ltype;
	uint8_t route_type;
	uint8_t route_instance;

	bool add_p;
	struct zapi_labels zl;

	int afi;
};

static void rib_addnode(struct route_node *rn, struct route_entry *re,
			int process);

/* %pRN is already a printer for route_nodes that just prints the prefix */
#ifdef _FRR_ATTRIBUTE_PRINTFRR
#pragma FRR printfrr_ext "%pZN" (struct route_node *)
#endif

static const char *subqueue2str(enum meta_queue_indexes index)
{
	switch (index) {
	case META_QUEUE_NHG:
		return "NHG Objects";
	case META_QUEUE_EVPN:
		return "EVPN/VxLan Objects";
	case META_QUEUE_EARLY_ROUTE:
		return "Early Route Processing";
	case META_QUEUE_EARLY_LABEL:
		return "Early Label Handling";
	case META_QUEUE_CONNECTED:
		return "Connected Routes";
	case META_QUEUE_KERNEL:
		return "Kernel Routes";
	case META_QUEUE_STATIC:
		return "Static Routes";
	case META_QUEUE_NOTBGP:
		return "RIP/OSPF/ISIS/EIGRP/NHRP Routes";
	case META_QUEUE_BGP:
		return "BGP Routes";
	case META_QUEUE_OTHER:
		return "Other Routes";
	case META_QUEUE_GR_RUN:
		return "Graceful Restart";
	}

	return "Unknown";
}

printfrr_ext_autoreg_p("ZN", printfrr_zebra_node);
static ssize_t printfrr_zebra_node(struct fbuf *buf, struct printfrr_eargs *ea,
				   const void *ptr)
{
	struct route_node *rn = (struct route_node *)ptr;
	ssize_t rv = 0;

	/* just the table number? */
	if (ea->fmt[0] == 't') {
		rib_dest_t *dest;
		struct route_entry *re = NULL;

		ea->fmt++;

		if (!rn)
			return bputch(buf, '!');

		dest = rib_dest_from_rnode(rn);
		if (dest)
			re = re_list_first(&dest->routes);
		if (re)
			rv += bprintfrr(buf, "%u", re->table);
		else
			rv += bputch(buf, '?');

	} else {
		char cbuf[PREFIX_STRLEN * 2 + 6];
		struct rib_table_info *info;

		if (!rn)
			return bputs(buf, "{(route_node *) NULL}");

		srcdest_rnode2str(rn, cbuf, sizeof(cbuf));
		rv += bputs(buf, cbuf);

		info = srcdest_rnode_table_info(rn);
		if (info->safi == SAFI_MULTICAST)
			rv += bputs(buf, " (MRIB)");
	}
	return rv;
}

#define rnode_debug(node, vrf_id, msg, ...)                                    \
	do {                                                                   \
		struct vrf *vrf = vrf_lookup_by_id(vrf_id);                    \
		zlog_debug("%s: (%s:%pZNt):%pZN: " msg, __func__,              \
			   VRF_LOGNAME(vrf), node, node, ##__VA_ARGS__);       \
	} while (0)

#define rnode_info(node, vrf_id, msg, ...)                                     \
	do {                                                                   \
		struct vrf *vrf = vrf_lookup_by_id(vrf_id);                    \
		zlog_info("%s: (%s:%pZNt):%pZN: " msg, __func__,               \
			  VRF_LOGNAME(vrf), node, node, ##__VA_ARGS__);        \
	} while (0)

static char *_dump_re_status(const struct route_entry *re, char *buf,
			     size_t len)
{
	if (re->status == 0) {
		snprintfrr(buf, len, "None ");
		return buf;
	}

	snprintfrr(
		buf, len, "%s%s%s%s%s%s%s%s",
		CHECK_FLAG(re->status, ROUTE_ENTRY_REMOVED) ? "Removed " : "",
		CHECK_FLAG(re->status, ROUTE_ENTRY_CHANGED) ? "Changed " : "",
		CHECK_FLAG(re->status, ROUTE_ENTRY_LABELS_CHANGED)
			? "Label Changed "
			: "",
		CHECK_FLAG(re->status, ROUTE_ENTRY_QUEUED) ? "Queued " : "",
		CHECK_FLAG(re->status, ROUTE_ENTRY_ROUTE_REPLACING)
			? "Replacing "
			: "",
		CHECK_FLAG(re->status, ROUTE_ENTRY_INSTALLED) ? "Installed "
							      : "",
		CHECK_FLAG(re->status, ROUTE_ENTRY_FAILED) ? "Failed " : "",
		CHECK_FLAG(re->status, ROUTE_ENTRY_USE_FIB_NHG) ? "Fib NHG "
								: "");
	return buf;
}

uint8_t route_distance(int type)
{
	uint8_t distance;

	if ((unsigned)type >= array_size(route_info))
		distance = 150;
	else
		distance = route_info[type].distance;

	return distance;
}

int is_zebra_valid_kernel_table(uint32_t table_id)
{
#ifdef linux
	if ((table_id == RT_TABLE_UNSPEC) || (table_id == RT_TABLE_LOCAL)
	    || (table_id == RT_TABLE_COMPAT))
		return 0;
#endif

	return 1;
}

int is_zebra_main_routing_table(uint32_t table_id)
{
	if (table_id == rt_table_main_id)
		return 1;
	return 0;
}

int zebra_check_addr(const struct prefix *p)
{
	if (p->family == AF_INET) {
		uint32_t addr;

		addr = p->u.prefix4.s_addr;
		addr = ntohl(addr);

		if (IPV4_NET127(addr) || IN_CLASSD(addr)
		    || IPV4_LINKLOCAL(addr))
			return 0;
	}
	if (p->family == AF_INET6) {
		if (IN6_IS_ADDR_LOOPBACK(&p->u.prefix6))
			return 0;
		if (IN6_IS_ADDR_LINKLOCAL(&p->u.prefix6))
			return 0;
	}
	return 1;
}

static void route_entry_attach_ref(struct route_entry *re,
				   struct nhg_hash_entry *new)
{
	re->nhe = new;
	re->nhe_id = new->id;
	re->nhe_installed_id = 0;

	if (new->pic_nhe)
		re->pic_nhe_id = new->pic_nhe->id;

	zebra_nhg_increment_ref(new);
}

/* Replace (if 'new_nhghe') or clear (if that's NULL) an re's nhe. */
int route_entry_update_nhe(struct route_entry *re,
			   struct nhg_hash_entry *new_nhghe)
{
	int ret = 0;
	struct nhg_hash_entry *old_nhg = NULL;

	if (new_nhghe == NULL) {
		old_nhg = re->nhe;

		re->nhe_id = 0;
		re->nhe_installed_id = 0;
		re->pic_nhe_id = 0;
		re->nhe = NULL;
		goto done;
	}

	if ((re->nhe_id != 0) && re->nhe && (re->nhe != new_nhghe)) {
		/* Capture previous nhg, if any */
		old_nhg = re->nhe;

		route_entry_attach_ref(re, new_nhghe);
	} else if (!re->nhe)
		/* This is the first time it's being attached */
		route_entry_attach_ref(re, new_nhghe);

done:
	/* Detach / deref previous nhg */

	if (old_nhg) {
		/*
		 * Return true if we are deleting the previous NHE
		 * Note: we dont check the return value of the function anywhere
		 * except at rib_handle_nhg_replace().
		 */
		if (old_nhg->refcnt == 1)
			ret = 1;

		zebra_nhg_decrement_ref(old_nhg);
	}

	return ret;
}

int rib_handle_nhg_replace(struct nhg_hash_entry *old_entry,
			   struct nhg_hash_entry *new_entry)
{
	struct zebra_router_table *zrt;
	struct route_node *rn;
	struct route_entry *re, *next;
	int ret = 0;

	if (IS_ZEBRA_DEBUG_RIB_DETAILED || IS_ZEBRA_DEBUG_NHG_DETAIL)
		zlog_debug("%s: replacing routes nhe (%u) OLD %p NEW %p",
			   __func__, new_entry->id, new_entry, old_entry);

	/* We have to do them ALL */
	RB_FOREACH (zrt, zebra_router_table_head, &zrouter.tables) {
		for (rn = route_top(zrt->table); rn;
		     rn = srcdest_route_next(rn)) {
			RNODE_FOREACH_RE_SAFE (rn, re, next) {
				if (re->nhe && re->nhe == old_entry)
					ret += route_entry_update_nhe(re,
								      new_entry);
			}
		}
	}

	/*
	 * if ret > 0, some previous re->nhe has freed the address to which
	 * old_entry is pointing.
	 */
	return ret;
}

struct route_entry *rib_match(afi_t afi, safi_t safi, vrf_id_t vrf_id,
			      const union g_addr *addr,
			      struct route_node **rn_out)
{
	struct prefix p;
	struct route_table *table;
	struct route_node *rn;
	struct route_entry *match = NULL;

	/* Lookup table.  */
	table = zebra_vrf_table(afi, safi, vrf_id);
	if (!table)
		return 0;

	memset(&p, 0, sizeof(p));
	p.family = afi;
	if (afi == AFI_IP) {
		p.u.prefix4 = addr->ipv4;
		p.prefixlen = IPV4_MAX_BITLEN;
	} else {
		p.u.prefix6 = addr->ipv6;
		p.prefixlen = IPV6_MAX_BITLEN;
	}

	rn = route_node_match(table, &p);

	while (rn) {
		rib_dest_t *dest;

		route_unlock_node(rn);

		dest = rib_dest_from_rnode(rn);
		if (dest && dest->selected_fib
		    && !CHECK_FLAG(dest->selected_fib->status,
				   ROUTE_ENTRY_REMOVED))
			match = dest->selected_fib;

		/* If there is no selected route or matched route is EGP, go up
		   tree. */
		if (!match) {
			do {
				rn = rn->parent;
			} while (rn && rn->info == NULL);
			if (rn)
				route_lock_node(rn);
		} else {
			if (match->type != ZEBRA_ROUTE_CONNECT &&
			    match->type != ZEBRA_ROUTE_LOCAL) {
				if (!CHECK_FLAG(match->status,
						ROUTE_ENTRY_INSTALLED))
					return NULL;
			}

			if (rn_out)
				*rn_out = rn;
			return match;
		}
	}
	return NULL;
}

struct route_entry *rib_match_multicast(afi_t afi, vrf_id_t vrf_id,
					union g_addr *gaddr,
					struct route_node **rn_out)
{
	struct route_entry *re = NULL, *mre = NULL, *ure = NULL;
	struct route_node *m_rn = NULL, *u_rn = NULL;

	switch (zrouter.ipv4_multicast_mode) {
	case MCAST_MRIB_ONLY:
		return rib_match(afi, SAFI_MULTICAST, vrf_id, gaddr, rn_out);
	case MCAST_URIB_ONLY:
		return rib_match(afi, SAFI_UNICAST, vrf_id, gaddr, rn_out);
	case MCAST_NO_CONFIG:
	case MCAST_MIX_MRIB_FIRST:
		re = mre = rib_match(afi, SAFI_MULTICAST, vrf_id, gaddr, &m_rn);
		if (!mre)
			re = ure = rib_match(afi, SAFI_UNICAST, vrf_id, gaddr,
					     &u_rn);
		break;
	case MCAST_MIX_DISTANCE:
		mre = rib_match(afi, SAFI_MULTICAST, vrf_id, gaddr, &m_rn);
		ure = rib_match(afi, SAFI_UNICAST, vrf_id, gaddr, &u_rn);
		if (mre && ure)
			re = ure->distance < mre->distance ? ure : mre;
		else if (mre)
			re = mre;
		else if (ure)
			re = ure;
		break;
	case MCAST_MIX_PFXLEN:
		mre = rib_match(afi, SAFI_MULTICAST, vrf_id, gaddr, &m_rn);
		ure = rib_match(afi, SAFI_UNICAST, vrf_id, gaddr, &u_rn);
		if (mre && ure)
			re = u_rn->p.prefixlen > m_rn->p.prefixlen ? ure : mre;
		else if (mre)
			re = mre;
		else if (ure)
			re = ure;
		break;
	}

	if (rn_out)
		*rn_out = (re == mre) ? m_rn : u_rn;

	if (IS_ZEBRA_DEBUG_RIB) {
		char buf[BUFSIZ];
		inet_ntop(afi == AFI_IP ? AF_INET : AF_INET6, gaddr, buf,
			  BUFSIZ);

		zlog_debug("%s: %s: %pRN vrf: %s(%u) found %s, using %s",
			   __func__, buf, (re == mre) ? m_rn : u_rn,
			   vrf_id_to_name(vrf_id), vrf_id,
			   mre ? (ure ? "MRIB+URIB" : "MRIB")
			       : ure ? "URIB" : "nothing",
			   re == ure ? "URIB" : re == mre ? "MRIB" : "none");
	}
	return re;
}

/*
 * Is this RIB labeled-unicast? It must be of type BGP and all paths
 * (nexthops) must have a label.
 */
int zebra_rib_labeled_unicast(struct route_entry *re)
{
	struct nexthop *nexthop = NULL;
	struct zebra_vrf *zvrf = vrf_info_lookup(re->vrf_id);

	if ((re->type != ZEBRA_ROUTE_BGP) &&
	    !zvrf->zebra_mpls_fec_nexthop_resolution)
		return 0;

	for (ALL_NEXTHOPS(re->nhe->nhg, nexthop))
		if (!nexthop->nh_label || !nexthop->nh_label->num_labels)
			return 0;

	return 1;
}

/* Update flag indicates whether this is a "replace" or not. Currently, this
 * is only used for IPv4.
 */
void rib_install_kernel(struct route_node *rn, struct route_entry *re,
			struct route_entry *old)
{
	struct nexthop *nexthop;
	struct rib_table_info *info = srcdest_rnode_table_info(rn);
	struct zebra_vrf *zvrf = zebra_vrf_lookup_by_id(re->vrf_id);
	enum zebra_dplane_result ret;

	rib_dest_t *dest = rib_dest_from_rnode(rn);

	if (info->safi != SAFI_UNICAST) {
		for (ALL_NEXTHOPS(re->nhe->nhg, nexthop))
			SET_FLAG(nexthop->flags, NEXTHOP_FLAG_FIB);
		return;
	}

	/*
	 * Install the resolved nexthop object first.
	 */
	zebra_nhg_install_kernel(re->nhe, re->type);

	/*
	 * If this is a replace to a new RE let the originator of the RE
	 * know that they've lost
	 */
	if (old && (old != re) && (old->type != re->type))
		zsend_route_notify_owner(rn, old, ZAPI_ROUTE_BETTER_ADMIN_WON,
					 info->afi, info->safi);

	/* Update fib selection */
	dest->selected_fib = re;

	/*
	 * Make sure we update the FPM any time we send new information to
	 * the kernel.
	 */
	hook_call(rib_update, rn, "installing in kernel");

	/* Send add or update */
	if (old)
		ret = dplane_route_update(rn, re, old);
	else
		ret = dplane_route_add(rn, re);

	switch (ret) {
	case ZEBRA_DPLANE_REQUEST_QUEUED:
		SET_FLAG(re->status, ROUTE_ENTRY_QUEUED);

		if (old) {
			SET_FLAG(old->status, ROUTE_ENTRY_QUEUED);
			SET_FLAG(re->status, ROUTE_ENTRY_ROUTE_REPLACING);

			/* Free old FIB nexthop group */
			UNSET_FLAG(old->status, ROUTE_ENTRY_USE_FIB_NHG);
			if (old->fib_ng.nexthop) {
				nexthops_free(old->fib_ng.nexthop);
				old->fib_ng.nexthop = NULL;
			}
		}

		if (zvrf)
			zvrf->installs_queued++;
		break;
	case ZEBRA_DPLANE_REQUEST_FAILURE:
	{
		flog_err(EC_ZEBRA_DP_INSTALL_FAIL,
			 "%u:%u:%pRN: Failed to enqueue dataplane install",
			 re->vrf_id, re->table, rn);
		break;
	}
	case ZEBRA_DPLANE_REQUEST_SUCCESS:
		if (zvrf)
			zvrf->installs++;
		break;
	}

	return;
}

/* Uninstall the route from kernel. */
void rib_uninstall_kernel(struct route_node *rn, struct route_entry *re)
{
	struct nexthop *nexthop;
	struct rib_table_info *info = srcdest_rnode_table_info(rn);
	struct zebra_vrf *zvrf = zebra_vrf_lookup_by_id(re->vrf_id);

	if (info->safi != SAFI_UNICAST) {
		UNSET_FLAG(re->status, ROUTE_ENTRY_INSTALLED);
		for (ALL_NEXTHOPS(re->nhe->nhg, nexthop))
			UNSET_FLAG(nexthop->flags, NEXTHOP_FLAG_FIB);
		return;
	}

	/*
	 * Make sure we update the FPM any time we send new information to
	 * the dataplane.
	 */
	hook_call(rib_update, rn, "uninstalling from kernel");

	switch (dplane_route_delete(rn, re)) {
	case ZEBRA_DPLANE_REQUEST_QUEUED:
		if (zvrf)
			zvrf->removals_queued++;
		break;
	case ZEBRA_DPLANE_REQUEST_FAILURE:
		flog_err(EC_ZEBRA_DP_INSTALL_FAIL,
			 "%u:%pRN: Failed to enqueue dataplane uninstall",
			 re->vrf_id, rn);
		break;
	case ZEBRA_DPLANE_REQUEST_SUCCESS:
		if (zvrf)
			zvrf->removals++;
		break;
	}

	return;
}

bool zebra_update_pic_nhe(struct route_node *rn)
{
	afi_t afi;
	int ret = 0;
	struct nhg_hash_entry *picnhe;
	struct nexthop *nh = NULL;
	struct nhg_hash_entry pic_nh_lookup = { 0 };
	//struct nexthop *nexthop_tmp;
	struct prefix *p;
	struct zebra_vrf *zvrf;
	struct nhg_connected *rb_node_dep = NULL;
	rib_dest_t *dest = rib_dest_from_rnode(rn);
	if (!dest)
		return false;
	zvrf = rib_dest_vrf(dest);
	p = &rn->p;
	afi = family2afi(p->family);
	pic_nh_lookup.afi = afi;
	/* Use a temporary nhe to find pic nh */
	pic_nh_lookup.type = ZEBRA_ROUTE_NHG;
	pic_nh_lookup.vrf_id = zvrf_id(zvrf);
	SET_FLAG(pic_nh_lookup.flags, NEXTHOP_GROUP_PIC_NHT);
	/* the nhg.nexthop is sorted */
	switch (afi) {
	case AFI_IP:
		nh = nexthop_from_ipv4(&p->u.prefix4, NULL, zvrf_id(zvrf));

		break;
	case AFI_IP6:
		nh = nexthop_from_ipv6(&p->u.prefix6, zvrf_id(zvrf));
		break;
	case AFI_UNSPEC:
	case AFI_L2VPN:
	case AFI_MAX:
		return false;
	}

	SET_FLAG(nh->flags, NEXTHOP_FLAG_ACTIVE);
	ret = nexthop_group_add_sorted_nodup(&pic_nh_lookup.nhg, nh);
	if (!ret) {
		nexthop_free(nh);
		return false;
	}
	picnhe = hash_lookup(zrouter.nhgs, &pic_nh_lookup);

	if (pic_nh_lookup.nhg.nexthop)
		nexthops_free(pic_nh_lookup.nhg.nexthop);

	if (!picnhe) {
		return false;
	}
	UNSET_FLAG(picnhe->flags, NEXTHOP_GROUP_VALID);

	frr_each_safe (nhg_connected_tree, &picnhe->nhg_dependents, rb_node_dep) {
		//zebra_nhg_set_invalid(rb_node_dep->nhe);
		if (ZEBRA_DEBUG_DPLANE_DETAILED)
			zlog_debug("%s: pic_nhe %ul become invaild during route %pRN deleted, update pic_nh dependents %ul",
				   __func__, picnhe->id, rn, rb_node_dep->nhe->id);
		UNSET_FLAG(rb_node_dep->nhe->flags, NEXTHOP_GROUP_INSTALLED);
		zebra_nhg_install_kernel(rb_node_dep->nhe, ZEBRA_ROUTE_MAX);
	}

	return true;
}

/*
 * rib_can_delete_dest
 *
 * Returns true if the given dest can be deleted from the table.
 */
static int rib_can_delete_dest(rib_dest_t *dest)
{
	if (re_list_first(&dest->routes)) {
		return 0;
	}

	/*
	 * Unresolved rnh's are stored on the default route's list
	 *
	 * dest->rnode can also be the source prefix node in an
	 * ipv6 sourcedest table.  Fortunately the prefix of a
	 * source prefix node can never be the default prefix.
	 */
	if (is_default_prefix(&dest->rnode->p))
		return 0;

	/*
	 * Don't delete the dest if we have to update the FPM about this
	 * prefix.
	 */
	if (CHECK_FLAG(dest->flags, RIB_DEST_UPDATE_FPM)
	    || CHECK_FLAG(dest->flags, RIB_DEST_SENT_TO_FPM))
		return 0;

	return 1;
}

void zebra_rib_evaluate_rn_nexthops(struct route_node *rn, uint32_t seq,
				    bool rt_delete)
{
	rib_dest_t *dest = rib_dest_from_rnode(rn);
	struct rnh *rnh;

	if (rt_delete)
		zebra_update_pic_nhe(rn);

	/*
	 * We are storing the rnh's associated with
	 * the tracked nexthop as a list of the rnh's
	 * on the rn that we have matched to.  As an
	 * example if you have these rnh's:
	 * rnh 1.1.1.1
	 * rnh 1.1.1.2
	 * rnh 1.1.3.4
	 * rnh 4.5.6.7
	 * Now imagine that you have in the tree these
	 * prefix's:
	 * 1.1.1.1/32
	 * 1.1.1.0/24
	 * 1.1.0.0/16
	 * 0.0.0.0/0
	 *
	 * The 1.1.1.1 rnh would be stored on 1.1.1.1/32
	 * The 1.1.1.2 rnh would be stored on 1.1.1.0/24
	 * The 1.1.3.4 rnh would be stored on the 1.1.0.0/16
	 * and finally the 4.5.6.7 would be stored on the 0.0.0.0/0
	 * prefix.
	 *
	 * Unresolved rnh's are placed at the top
	 * of the tree list.( 0.0.0.0/0 for v4 and 0::0/0 for v6 )
	 * As such for each rn we need to walk up the tree
	 * and see if any rnh's need to see if they
	 * would match a more specific route
	 *
	 * Now if a 1.1.1.2/32 prefix was added to the tree
	 * this function would start at this new node and
	 * see that the 1.1.1.2/32 node has no rnh's and
	 * there is nothing to do on this node currently,
	 * so the function would walk the parent pointers, until the
	 * 1.1.1.0/24 node is hit with the 1.1.1.2 rnh.  This function
	 * would then call zebra_evaluate_rnh() which would then
	 * do a LPM and match on the 1.1.1.2/32 node.  This function
	 * would then pull the 1.1.1.2 rnh off the 1.1.1.0/24 node
	 * and place it on the 1.1.1.1/32 node and notify the upper
	 * level protocols interested about the change( as necessary ).
	 * At this point in time a sequence number is added to note
	 * that the rnh has been moved.
	 * The function would also continue to walk up the tree
	 * looking at the list of rnh's and moving them around
	 * as necessary.  Since in this example nothing else
	 * would change no further actions are made.
	 *
	 * Another case to consider is a node being deleted
	 * suppose the 1.1.1.2/32 route is being deleted.
	 * This function would start at the 1.1.1.1/32 node,
	 * perform a LPM and settle on the 1.1.1.0/24 node
	 * as where it belongs.  The code would update appropriate
	 * interested parties and additionally also mark the sequence
	 * number and walk up the tree.  Eventually it would get to
	 * the 1.1.1.0/24 node and since the seqno matches we would
	 * know that it is not necessary to reconsider this node
	 * as it was already moved to this spot.
	 *
	 * This all works because each node's parent pointer points
	 * to a node that has a prefix that contains this node.  Eventually
	 * the parent traversal will hit the 0.0.0.0/0 node and we know
	 * we are done.  We know this is pretty efficient because when
	 * a more specific is added as we walk the tree we can
	 * find the rnh's that matched to a less specific very easily
	 * and move them to a more specific node.  Also vice-versa as a
	 * more specific node is removed.
	 *
	 * Long term the rnh code might be improved some as the rnh's
	 * are stored as a list.  This might be transformed to a better
	 * data structure.  This has not proven to be necessary yet as
	 * that we have not seen any particular case where a rn is
	 * storing more than a couple rnh's.  If we find a case
	 * where this matters something might need to be done.
	 */
	while (rn) {
		if (IS_ZEBRA_DEBUG_NHT_DETAILED)
			zlog_debug(
				"%s: %pRN Being examined for Nexthop Tracking Count: %zd",
				__func__, rn,
				dest ? rnh_list_count(&dest->nht) : 0);

		if (rt_delete && (!dest || !rnh_list_count(&dest->nht))) {
			if (IS_ZEBRA_DEBUG_NHT_DETAILED)
				zlog_debug("%pRN has no tracking NHTs. Bailing",
					   rn);
			break;
		}
		if (!dest) {
			rn = rn->parent;
			if (rn)
				dest = rib_dest_from_rnode(rn);
			continue;
		}
		/*
		 * If we have any rnh's stored in the nht list
		 * then we know that this route node was used for
		 * nht resolution and as such we need to call the
		 * nexthop tracking evaluation code
		 */
		frr_each_safe(rnh_list, &dest->nht, rnh) {
			struct zebra_vrf *zvrf =
				zebra_vrf_lookup_by_id(rnh->vrf_id);
			struct prefix *p = &rnh->node->p;

			if (IS_ZEBRA_DEBUG_NHT_DETAILED)
				zlog_debug(
					"%s(%u):%pRN has Nexthop(%pRN) depending on it, evaluating %u:%u",
					zvrf_name(zvrf), zvrf_id(zvrf), rn,
					rnh->node, seq, rnh->seqno);

			/*
			 * If we have evaluated this node on this pass
			 * already, due to following the tree up
			 * then we know that we can move onto the next
			 * rnh to process.
			 *
			 * Additionally we call zebra_evaluate_rnh
			 * when we gc the dest.  In this case we know
			 * that there must be no other re's where
			 * we were originally as such we know that
			 * that sequence number is ok to respect.
			 */
			if (rnh->seqno == seq) {
				if (IS_ZEBRA_DEBUG_NHT_DETAILED)
					zlog_debug(
						"    Node processed and moved already");
				continue;
			}

			rnh->seqno = seq;
			zebra_evaluate_rnh(zvrf, family2afi(p->family), 0, p,
					   rnh->safi);
		}

		rn = rn->parent;
		if (rn)
			dest = rib_dest_from_rnode(rn);
	}
}

/*
 * rib_gc_dest
 *
 * Garbage collect the rib dest corresponding to the given route node
 * if appropriate.
 *
 * Returns true if the dest was deleted, false otherwise.
 */
int rib_gc_dest(struct route_node *rn)
{
	rib_dest_t *dest;

	dest = rib_dest_from_rnode(rn);
	if (!dest)
		return 0;

	if (!rib_can_delete_dest(dest))
		return 0;

	if (IS_ZEBRA_DEBUG_RIB) {
		struct zebra_vrf *zvrf;

		zvrf = rib_dest_vrf(dest);
		rnode_debug(rn, zvrf_id(zvrf), "removing dest from table");
	}

	zebra_rib_evaluate_rn_nexthops(rn, zebra_router_get_next_sequence(),
				       true);

	dest->rnode = NULL;
	rnh_list_fini(&dest->nht);
	XFREE(MTYPE_RIB_DEST, dest);
	rn->info = NULL;

	/*
	 * Release the one reference that we keep on the route node.
	 */
	route_unlock_node(rn);
	return 1;
}

void zebra_rtable_node_cleanup(struct route_table *table,
			       struct route_node *node)
{
	struct route_entry *re, *next;

	RNODE_FOREACH_RE_SAFE (node, re, next) {
		rib_unlink(node, re);
	}

	if (node->info) {
		rib_dest_t *dest = node->info;

		/* Remove from update queue of FPM module */
		hook_call(rib_shutdown, node);

		rnh_list_fini(&dest->nht);
		XFREE(MTYPE_RIB_DEST, node->info);
	}
}

static void rib_process_add_fib(struct zebra_vrf *zvrf, struct route_node *rn,
				struct route_entry *new)
{
	hook_call(rib_update, rn, "new route selected");

	/* Update real nexthop. This may actually determine if nexthop is active
	 * or not. */
	if (!nexthop_group_active_nexthop_num(&(new->nhe->nhg))) {
		UNSET_FLAG(new->status, ROUTE_ENTRY_CHANGED);
		return;
	}

	if (IS_ZEBRA_DEBUG_RIB)
		zlog_debug("%s(%u:%u):%pRN: Adding route rn %p, re %p (%s)",
			   zvrf_name(zvrf), zvrf_id(zvrf), new->table, rn, rn,
			   new, zebra_route_string(new->type));

	/* If labeled-unicast route, install transit LSP. */
	if (zebra_rib_labeled_unicast(new))
		zebra_mpls_lsp_install(zvrf, rn, new);

	rib_install_kernel(rn, new, NULL);

	UNSET_FLAG(new->status, ROUTE_ENTRY_CHANGED);
}

static void rib_process_del_fib(struct zebra_vrf *zvrf, struct route_node *rn,
				struct route_entry *old)
{
	hook_call(rib_update, rn, "removing existing route");

	/* Uninstall from kernel. */
	if (IS_ZEBRA_DEBUG_RIB)
		zlog_debug("%s(%u:%u):%pRN: Deleting route rn %p, re %p (%s)",
			   zvrf_name(zvrf), zvrf_id(zvrf), old->table, rn, rn,
			   old, zebra_route_string(old->type));

	/* If labeled-unicast route, uninstall transit LSP. */
	if (zebra_rib_labeled_unicast(old))
		zebra_mpls_lsp_uninstall(zvrf, rn, old);

	rib_uninstall_kernel(rn, old);

	/* Update nexthop for route, reset changed flag. */
	/* Note: this code also handles the Linux case when an interface goes
	 * down, causing the kernel to delete routes without sending DELROUTE
	 * notifications
	 */
	if (RIB_KERNEL_ROUTE(old))
		SET_FLAG(old->status, ROUTE_ENTRY_REMOVED);
	else
		UNSET_FLAG(old->status, ROUTE_ENTRY_CHANGED);
}

static void rib_process_update_fib(struct zebra_vrf *zvrf,
				   struct route_node *rn,
				   struct route_entry *old,
				   struct route_entry *new)
{
	int nh_active = 0;

	/*
	 * We have to install or update if a new route has been selected or
	 * something has changed.
	 */
	if (new != old || CHECK_FLAG(new->status, ROUTE_ENTRY_CHANGED)) {
		hook_call(rib_update, rn, "updating existing route");

		/* Update the nexthop; we could determine here that nexthop is
		 * inactive. */
		if (nexthop_group_active_nexthop_num(&(new->nhe->nhg)))
			nh_active = 1;

		/* If nexthop is active, install the selected route, if
		 * appropriate. If
		 * the install succeeds, cleanup flags for prior route, if
		 * different from
		 * newly selected.
		 */
		if (nh_active) {
			if (IS_ZEBRA_DEBUG_RIB) {
				if (new != old)
					zlog_debug(
						"%s(%u:%u):%pRN: Updating route rn %p, re %p (%s) old %p (%s)",
						zvrf_name(zvrf), zvrf_id(zvrf),
						new->table, rn, rn, new,
						zebra_route_string(new->type),
						old,
						zebra_route_string(old->type));
				else
					zlog_debug(
						"%s(%u:%u):%pRN: Updating route rn %p, re %p (%s)",
						zvrf_name(zvrf), zvrf_id(zvrf),
						new->table, rn, rn, new,
						zebra_route_string(new->type));
			}

			/* If labeled-unicast route, uninstall transit LSP. */
			if (zebra_rib_labeled_unicast(old))
				zebra_mpls_lsp_uninstall(zvrf, rn, old);

			/*
			 * Non-system route should be installed.
			 * If labeled-unicast route, install transit
			 * LSP.
			 */
			if (zebra_rib_labeled_unicast(new))
				zebra_mpls_lsp_install(zvrf, rn, new);

			rib_install_kernel(rn, new, old);
		}

		/*
		 * If nexthop for selected route is not active or install
		 * failed, we
		 * may need to uninstall and delete for redistribution.
		 */
		if (!nh_active) {
			if (IS_ZEBRA_DEBUG_RIB) {
				if (new != old)
					zlog_debug(
						"%s(%u:%u):%pRN: Deleting route rn %p, re %p (%s) old %p (%s) - nexthop inactive",
						zvrf_name(zvrf), zvrf_id(zvrf),
						new->table, rn, rn, new,
						zebra_route_string(new->type),
						old,
						zebra_route_string(old->type));
				else
					zlog_debug(
						"%s(%u:%u):%pRN: Deleting route rn %p, re %p (%s) - nexthop inactive",
						zvrf_name(zvrf), zvrf_id(zvrf),
						new->table, rn, rn, new,
						zebra_route_string(new->type));
			}

			/*
			 * When we have gotten to this point
			 * the new route entry has no nexthops
			 * that are usable and as such we need
			 * to remove the old route, but only
			 * if we were the one who installed
			 * the old route
			 */
			if (!RIB_SYSTEM_ROUTE(old)) {
				/* If labeled-unicast route, uninstall transit
				 * LSP. */
				if (zebra_rib_labeled_unicast(old))
					zebra_mpls_lsp_uninstall(zvrf, rn, old);

				rib_uninstall_kernel(rn, old);
			}
		}
	} else {
		/*
		 * Same route selected; check if in the FIB and if not,
		 * re-install. This is housekeeping code to deal with
		 * race conditions in kernel with linux netlink reporting
		 * interface up before IPv4 or IPv6 protocol is ready
		 * to add routes.
		 */
		if (!CHECK_FLAG(new->status, ROUTE_ENTRY_INSTALLED) ||
		    RIB_SYSTEM_ROUTE(new))
			rib_install_kernel(rn, new, NULL);
	}

	/* Update prior route. */
	if (new != old)
		UNSET_FLAG(old->status, ROUTE_ENTRY_CHANGED);

	/* Clear changed flag. */
	UNSET_FLAG(new->status, ROUTE_ENTRY_CHANGED);
}

static struct route_entry *rib_choose_best_type(uint8_t route_type,
						struct route_entry *current,
						struct route_entry *alternate)
{
	/*
	 * We know that alternate and current are now non-NULL
	 */
	if (alternate->type == route_type) {
		if (current->type != route_type)
			return alternate;

		/* both are connected.  are either loop or vrf? */
		struct nexthop *nexthop = NULL;

		for (ALL_NEXTHOPS(alternate->nhe->nhg, nexthop)) {
			struct interface *ifp = if_lookup_by_index(
				nexthop->ifindex, alternate->vrf_id);

			if (ifp && if_is_loopback(ifp))
				return alternate;
		}

		for (ALL_NEXTHOPS(current->nhe->nhg, nexthop)) {
			struct interface *ifp = if_lookup_by_index(
				nexthop->ifindex, current->vrf_id);

			if (ifp && if_is_loopback(ifp))
				return current;
		}

		/* Neither are loop or vrf so pick best metric  */
		if (alternate->metric <= current->metric)
			return alternate;

		return current;
	}

	return NULL;
}

/* Check if 'alternate' RIB entry is better than 'current'. */
static struct route_entry *rib_choose_best(struct route_entry *current,
					   struct route_entry *alternate)
{
	struct route_entry *possible;

	if (current == NULL)
		return alternate;

	/* filter route selection in following order:
	 * - Local beats Connected
	 * - connected beats other types
	 * - if both connected, loopback or vrf wins
	 * - lower distance beats higher
	 * - lower metric beats higher for equal distance
	 * - last, hence oldest, route wins tie break.
	 */

	/* Connected or Local routes. Check to see if either are a vrf
	 * or loopback interface.  If not, pick the last connected
	 * route of the set of lowest metric connected routes.
	 */
	possible = rib_choose_best_type(ZEBRA_ROUTE_LOCAL, current, alternate);
	if (possible)
		return possible;

	possible = rib_choose_best_type(ZEBRA_ROUTE_CONNECT, current, alternate);
	if (possible)
		return possible;

	if (current->type == ZEBRA_ROUTE_CONNECT ||
	    current->type == ZEBRA_ROUTE_LOCAL)
		return current;

	/* higher distance loses */
	if (alternate->distance < current->distance)
		return alternate;
	if (current->distance < alternate->distance)
		return current;

	/* metric tie-breaks equal distance */
	if (alternate->metric <= current->metric)
		return alternate;

	return current;
}

/* Core function for processing routing information base. */
static void rib_process(struct route_node *rn)
{
	struct route_entry *re;
	struct route_entry *next;
	struct route_entry *old_selected = NULL;
	struct route_entry *new_selected = NULL;
	struct route_entry *old_fib = NULL;
	struct route_entry *new_fib = NULL;
	struct route_entry *best = NULL;
	rib_dest_t *dest;
	struct zebra_vrf *zvrf = NULL;
	struct vrf *vrf;
	struct route_entry *proto_re_changed = NULL;

	vrf_id_t vrf_id = VRF_UNKNOWN;

	assert(rn);

	dest = rib_dest_from_rnode(rn);
	/*
	 * We have an enqueued node with nothing to process here
	 * let's just finish up and return;
	 */
	if (!dest)
		return;

	zvrf = rib_dest_vrf(dest);
	vrf_id = zvrf_id(zvrf);

	vrf = vrf_lookup_by_id(vrf_id);

	/*
	 * we can have rn's that have a NULL info pointer
	 * (dest).  As such let's not let the deref happen
	 * additionally we know RNODE_FOREACH_RE_SAFE
	 * will not iterate so we are ok.
	 */
	if (IS_ZEBRA_DEBUG_RIB_DETAILED) {
		struct route_entry *re = re_list_first(&dest->routes);

		zlog_debug("%s(%u:%u):%pRN: Processing rn %p",
			   VRF_LOGNAME(vrf), vrf_id, re->table, rn,
			   rn);
	}

	old_fib = dest->selected_fib;

	RNODE_FOREACH_RE_SAFE (rn, re, next) {
		if (IS_ZEBRA_DEBUG_RIB_DETAILED) {
			char flags_buf[128];
			char status_buf[128];

			zlog_debug(
				"%s(%u:%u):%pRN: Examine re %p (%s) status: %sflags: %sdist %d metric %d",
				VRF_LOGNAME(vrf), vrf_id, re->table, rn, re,
				zebra_route_string(re->type),
				_dump_re_status(re, status_buf,
						sizeof(status_buf)),
				zclient_dump_route_flags(re->flags, flags_buf,
							 sizeof(flags_buf)),
				re->distance, re->metric);
		}

		/* Currently selected re. */
		if (CHECK_FLAG(re->flags, ZEBRA_FLAG_SELECTED)) {
			assert(old_selected == NULL);
			old_selected = re;
		}

		/* Skip deleted entries from selection */
		if (CHECK_FLAG(re->status, ROUTE_ENTRY_REMOVED))
			continue;

		/*
		 * If the route entry has changed, verify/resolve
		 * the nexthops associated with the entry.
		 *
		 * In any event if we have nexthops that are not active
		 * then we cannot use this particular route entry so
		 * skip it.
		 */
		if (CHECK_FLAG(re->status, ROUTE_ENTRY_CHANGED)) {
			proto_re_changed = re;
			if (!nexthop_active_update(rn, re, old_fib)) {
				struct rib_table_info *info;

				if (re->type == ZEBRA_ROUTE_TABLE) {
					/* XXX: HERE BE DRAGONS!!!!!
					 * In all honesty, I have not yet
					 * figured out what this part does or
					 * why the ROUTE_ENTRY_CHANGED test
					 * above is correct or why we need to
					 * delete a route here, and also not
					 * whether this concerns both selected
					 * and fib route, or only selected
					 * or only fib
					 *
					 * This entry was denied by the 'ip
					 * protocol
					 * table' route-map, we need to delete
					 * it */
					if (re != old_selected) {
						if (IS_ZEBRA_DEBUG_RIB)
							zlog_debug(
								"%s: %s(%u):%pRN: imported via import-table but denied by the ip protocol table route-map",
								__func__,
								VRF_LOGNAME(
									vrf),
								vrf_id, rn);
						rib_unlink(rn, re);
						continue;
					} else
						SET_FLAG(re->status,
							 ROUTE_ENTRY_REMOVED);
				}

				info = srcdest_rnode_table_info(rn);
				zsend_route_notify_owner(
					rn, re, ZAPI_ROUTE_FAIL_INSTALL,
					info->afi, info->safi);
				continue;
			}
		} else {
			/*
			 * If the re has not changed and the nhg we have is
			 * not usable, then we cannot use this route entry
			 * for consideration, as that the route will just
			 * not install if it is selected.
			 */
			if (!nexthop_group_active_nexthop_num(&re->nhe->nhg))
				continue;
		}

		/* Infinite distance. */
		if (re->distance == DISTANCE_INFINITY &&
		    re->type != ZEBRA_ROUTE_KERNEL) {
			UNSET_FLAG(re->status, ROUTE_ENTRY_CHANGED);
			continue;
		}

		if (CHECK_FLAG(re->flags, ZEBRA_FLAG_FIB_OVERRIDE)) {
			best = rib_choose_best(new_fib, re);
			if (new_fib && best != new_fib)
				UNSET_FLAG(new_fib->status,
					   ROUTE_ENTRY_CHANGED);
			new_fib = best;
		} else {
			best = rib_choose_best(new_selected, re);
			if (new_selected && best != new_selected)
				UNSET_FLAG(new_selected->status,
					   ROUTE_ENTRY_CHANGED);
			new_selected = best;
		}
		if (best != re)
			UNSET_FLAG(re->status, ROUTE_ENTRY_CHANGED);
	} /* RNODE_FOREACH_RE */

	/* If no FIB override route, use the selected route also for FIB */
	if (new_fib == NULL)
		new_fib = new_selected;

	/* After the cycle is finished, the following pointers will be set:
	 * old_selected --- RE entry currently having SELECTED
	 * new_selected --- RE entry that is newly SELECTED
	 * old_fib      --- RE entry currently in kernel FIB
	 * new_fib      --- RE entry that is newly to be in kernel FIB
	 * proto_re_changed -- RE that is the last changed entry in the
	 *                     list of RE's.
	 *
	 * new_selected will get SELECTED flag, and is going to be redistributed
	 * the zclients. new_fib (which can be new_selected) will be installed
	 * in kernel.
	 */

	if (IS_ZEBRA_DEBUG_RIB_DETAILED) {
		struct route_entry *entry;

		entry = old_selected
				? old_selected
				: new_selected
					  ? new_selected
					  : old_fib ? old_fib
						    : new_fib ? new_fib : NULL;

		zlog_debug(
			"%s(%u:%u):%pRN: After processing: old_selected %p new_selected %p old_fib %p new_fib %p",
			VRF_LOGNAME(vrf), vrf_id, entry ? entry->table : 0, rn,
			(void *)old_selected, (void *)new_selected,
			(void *)old_fib, (void *)new_fib);
	}

	/* Buffer ROUTE_ENTRY_CHANGED here, because it will get cleared if
	 * fib == selected */
	bool selected_changed = new_selected && CHECK_FLAG(new_selected->status,
							   ROUTE_ENTRY_CHANGED);

	/* Update SELECTED entry */
	if (old_selected != new_selected || selected_changed) {

		if (new_selected && new_selected != new_fib)
			UNSET_FLAG(new_selected->status, ROUTE_ENTRY_CHANGED);

		if (new_selected)
			SET_FLAG(new_selected->flags, ZEBRA_FLAG_SELECTED);

		if (old_selected) {
			/*
			 * If we're removing the old entry, we should tell
			 * redist subscribers about that *if* they aren't
			 * going to see a redist for the new entry.
			 */
			if (!new_selected || CHECK_FLAG(old_selected->status,
							ROUTE_ENTRY_REMOVED))
				redistribute_delete(rn, old_selected,
						    new_selected);

			if (old_selected != new_selected)
				UNSET_FLAG(old_selected->flags,
					   ZEBRA_FLAG_SELECTED);
		}
	}

	/*
	 * If zebra has a new_selected and a proto_re_changed
	 * entry that was not the old selected and the protocol
	 * is different, zebra should notify the upper level
	 * protocol that the sent down entry was not selected
	 */
	if (new_selected && proto_re_changed &&
	    proto_re_changed != old_selected &&
	    new_selected->type != proto_re_changed->type) {
		struct rib_table_info *info = srcdest_rnode_table_info(rn);

		zsend_route_notify_owner(rn, proto_re_changed,
					 ZAPI_ROUTE_BETTER_ADMIN_WON, info->afi,
					 info->safi);
	}

	/* Update fib according to selection results */
	if (new_fib && old_fib)
		rib_process_update_fib(zvrf, rn, old_fib, new_fib);
	else if (new_fib)
		rib_process_add_fib(zvrf, rn, new_fib);
	else if (old_fib)
		rib_process_del_fib(zvrf, rn, old_fib);

	/* Remove all RE entries queued for removal */
	RNODE_FOREACH_RE_SAFE (rn, re, next) {
		if (CHECK_FLAG(re->status, ROUTE_ENTRY_REMOVED)) {
			if (IS_ZEBRA_DEBUG_RIB) {
				rnode_debug(rn, vrf_id, "rn %p, removing re %p",
					    (void *)rn, (void *)re);
			}
			rib_unlink(rn, re);
		}
	}

	/*
	 * Check if the dest can be deleted now.
	 */
	rib_gc_dest(rn);
}

static void zebra_rib_evaluate_mpls(struct route_node *rn)
{
	rib_dest_t *dest = rib_dest_from_rnode(rn);
	struct zebra_vrf *zvrf = zebra_vrf_lookup_by_id(VRF_DEFAULT);

	if (!dest)
		return;

	if (CHECK_FLAG(dest->flags, RIB_DEST_UPDATE_LSPS)) {
		if (IS_ZEBRA_DEBUG_MPLS)
			zlog_debug(
				"%s(%u): Scheduling all LSPs upon RIB completion",
				zvrf_name(zvrf), zvrf_id(zvrf));
		zebra_mpls_lsp_schedule(zvrf);
		mpls_unmark_lsps_for_processing(rn);
	}
}

/*
 * Utility to match route with dplane context data
 */
static bool rib_route_match_ctx(const struct route_entry *re,
				const struct zebra_dplane_ctx *ctx,
				bool is_update, bool async)
{
	bool result = false;

	if (is_update) {
		/*
		 * In 'update' case, we test info about the 'previous' or
		 * 'old' route
		 */
		if ((re->type == dplane_ctx_get_old_type(ctx)) &&
		    (re->instance == dplane_ctx_get_old_instance(ctx))) {
			result = true;

			/* We use an extra test for statics, and another for
			 * kernel routes.
			 */
			if (re->type == ZEBRA_ROUTE_STATIC && !async &&
			    (re->distance != dplane_ctx_get_old_distance(ctx) ||
			     re->tag != dplane_ctx_get_old_tag(ctx))) {
				result = false;
			} else if (re->type == ZEBRA_ROUTE_KERNEL &&
				   re->metric != dplane_ctx_get_old_metric(ctx)) {
				result = false;
			}
		}

	} else {
		/*
		 * Ordinary, single-route case using primary context info
		 */
		if ((dplane_ctx_get_op(ctx) != DPLANE_OP_ROUTE_DELETE) &&
		    CHECK_FLAG(re->status, ROUTE_ENTRY_REMOVED)) {
			/* Skip route that's been deleted */
			goto done;
		}

		if ((re->type == dplane_ctx_get_type(ctx)) &&
		    (re->instance == dplane_ctx_get_instance(ctx))) {
			result = true;

			/* We use an extra test for statics, and another for
			 * kernel routes.
			 */
			if (re->type == ZEBRA_ROUTE_STATIC && !async &&
			    (re->distance != dplane_ctx_get_distance(ctx) ||
			     re->tag != dplane_ctx_get_tag(ctx))) {
				result = false;
			} else if (re->type == ZEBRA_ROUTE_KERNEL &&
				   re->metric != dplane_ctx_get_metric(ctx)) {
				result = false;
			} else if (re->type == ZEBRA_ROUTE_CONNECT ||
				   re->type == ZEBRA_ROUTE_LOCAL) {
				result = nexthop_group_equal_no_recurse(
					&re->nhe->nhg, dplane_ctx_get_ng(ctx));
			}
		}
	}

done:
	return result;
}

static void zebra_rib_fixup_system(struct route_node *rn)
{
	struct route_entry *re;

	RNODE_FOREACH_RE(rn, re) {
		struct nexthop *nhop;

		if (!RIB_SYSTEM_ROUTE(re))
			continue;

		if (CHECK_FLAG(re->status, ROUTE_ENTRY_REMOVED))
			continue;

		SET_FLAG(re->status, ROUTE_ENTRY_INSTALLED);
		UNSET_FLAG(re->status, ROUTE_ENTRY_QUEUED);
		UNSET_FLAG(re->status, ROUTE_ENTRY_ROUTE_REPLACING);

		for (ALL_NEXTHOPS(re->nhe->nhg, nhop)) {
			if (CHECK_FLAG(nhop->flags, NEXTHOP_FLAG_RECURSIVE))
				continue;

			SET_FLAG(nhop->flags, NEXTHOP_FLAG_FIB);
		}
	}
}

/* Route comparison logic, with various special cases. */
static bool rib_compare_routes(const struct route_entry *re1,
			       const struct route_entry *re2)
{
	if (re1->type != re2->type)
		return false;

	if (re1->instance != re2->instance)
		return false;

	if (re1->type == ZEBRA_ROUTE_KERNEL && re1->metric != re2->metric)
		return false;

	if (CHECK_FLAG(re1->flags, ZEBRA_FLAG_RR_USE_DISTANCE) &&
	    re1->distance != re2->distance)
		return false;

	/* We support multiple connected routes: this supports multiple
	 * v6 link-locals, and we also support multiple addresses in the same
	 * subnet on a single interface.
	 */
	if (re1->type == ZEBRA_ROUTE_CONNECT &&
	    (re1->nhe->nhg.nexthop->ifindex == re2->nhe->nhg.nexthop->ifindex))
		return true;

	if (re1->type != ZEBRA_ROUTE_CONNECT && re1->type != ZEBRA_ROUTE_LOCAL)
		return true;

	return false;
}

/*
 * Compare nexthop lists from a route and a dplane context; test whether
 * the list installed in the FIB matches the route's list.
 * Set 'changed_p' to 'true' if there were changes to the route's
 * installed nexthops.
 *
 * Return 'false' if any ACTIVE route nexthops are not mentioned in the FIB
 * list.
 */
static bool rib_update_nhg_from_ctx(struct nexthop_group *re_nhg,
				    const struct nexthop_group *ctx_nhg,
				    bool *changed_p)
{
	bool matched_p = true;
	struct nexthop *nexthop, *ctx_nexthop;

	/* Get the first `installed` one to check against.
	 * If the dataplane doesn't set these to be what was actually installed,
	 * it will just be whatever was in re->nhe->nhg?
	 */
	ctx_nexthop = ctx_nhg->nexthop;

	if (CHECK_FLAG(ctx_nexthop->flags, NEXTHOP_FLAG_RECURSIVE)
	    || !CHECK_FLAG(ctx_nexthop->flags, NEXTHOP_FLAG_ACTIVE))
		ctx_nexthop = nexthop_next_active_resolved(ctx_nexthop);

	for (ALL_NEXTHOPS_PTR(re_nhg, nexthop)) {

		if (CHECK_FLAG(nexthop->flags, NEXTHOP_FLAG_RECURSIVE))
			continue;

		if (!CHECK_FLAG(nexthop->flags, NEXTHOP_FLAG_ACTIVE))
			continue;

		if (CHECK_FLAG(nexthop->flags, NEXTHOP_FLAG_DUPLICATE))
			continue;

		/* Check for a FIB nexthop corresponding to the RIB nexthop */
		if (!nexthop_same(ctx_nexthop, nexthop)) {
			/* If the FIB doesn't know about the nexthop,
			 * it's not installed
			 */
			if (IS_ZEBRA_DEBUG_RIB_DETAILED ||
			    IS_ZEBRA_DEBUG_NHG_DETAIL) {
				zlog_debug("%s: no ctx match for rib nh %pNHv %s",
					   __func__, nexthop,
					   (CHECK_FLAG(nexthop->flags,
						       NEXTHOP_FLAG_FIB) ?
					    "(FIB)":""));
			}
			matched_p = false;

			if (CHECK_FLAG(nexthop->flags, NEXTHOP_FLAG_FIB))
				*changed_p = true;

			UNSET_FLAG(nexthop->flags, NEXTHOP_FLAG_FIB);

			/* Keep checking nexthops */
			continue;
		}

		if (CHECK_FLAG(ctx_nexthop->flags, NEXTHOP_FLAG_FIB)) {
			if (!CHECK_FLAG(nexthop->flags, NEXTHOP_FLAG_FIB)) {
				if (IS_ZEBRA_DEBUG_NHG_DETAIL)
					zlog_debug("%s: rib nh %pNHv -> installed",
						   __func__, nexthop);

				*changed_p = true;
			}

			SET_FLAG(nexthop->flags, NEXTHOP_FLAG_FIB);
		} else {
			if (CHECK_FLAG(nexthop->flags, NEXTHOP_FLAG_FIB)) {
				if (IS_ZEBRA_DEBUG_NHG_DETAIL)
					zlog_debug("%s: rib nh %pNHv -> uninstalled",
						   __func__, nexthop);

				*changed_p = true;
			}

			UNSET_FLAG(nexthop->flags, NEXTHOP_FLAG_FIB);
		}

		ctx_nexthop = nexthop_next_active_resolved(ctx_nexthop);
	}

	return matched_p;
}

/*
 * Update a route from a dplane context. This consolidates common code
 * that can be used in processing of results from FIB updates, and in
 * async notification processing.
 * The return is 'true' if the installed nexthops changed; 'false' otherwise.
 */
static bool rib_update_re_from_ctx(struct route_entry *re,
				   struct route_node *rn,
				   struct zebra_dplane_ctx *ctx)
{
	struct nexthop *nexthop;
	bool matched;
	const struct nexthop_group *ctxnhg;
	struct nexthop_group *re_nhg;
	bool is_selected = false; /* Is 're' currently the selected re? */
	bool changed_p = false; /* Change to nexthops? */
	rib_dest_t *dest;
	struct vrf *vrf;

	vrf = vrf_lookup_by_id(re->vrf_id);

	dest = rib_dest_from_rnode(rn);
	if (dest)
		is_selected = (re == dest->selected_fib);

	if (IS_ZEBRA_DEBUG_RIB_DETAILED)
		zlog_debug("update_from_ctx: %s(%u:%u):%pRN: %sSELECTED, re %p",
			   VRF_LOGNAME(vrf), re->vrf_id, re->table, rn,
			   (is_selected ? "" : "NOT "), re);

	/* Update zebra's nexthop FIB flag for each nexthop that was installed.
	 * If the installed set differs from the set requested by the rib/owner,
	 * we use the fib-specific nexthop-group to record the actual FIB
	 * status.
	 */
	matched = false;
	ctxnhg = dplane_ctx_get_ng(ctx);

	/* Check route's fib group and incoming notif group for equivalence.
	 *
	 * Let's assume the nexthops are ordered here to save time.
	 */
	/* TODO -- this isn't testing or comparing the FIB flags; we should
	 * do a more explicit loop, checking the incoming notification's flags.
	 */
	if (re->fib_ng.nexthop && ctxnhg->nexthop &&
	    nexthop_group_equal(&re->fib_ng, ctxnhg))
		matched = true;

	/* If the new FIB set matches the existing FIB set, we're done. */
	if (matched) {
		if (IS_ZEBRA_DEBUG_RIB)
			zlog_debug(
				"%s(%u:%u):%pRN update_from_ctx(): existing fib nhg, no change",
				VRF_LOGNAME(vrf), re->vrf_id, re->table, rn);
		goto check_backups;

	} else if (CHECK_FLAG(re->status, ROUTE_ENTRY_USE_FIB_NHG)) {
		/*
		 * Free stale fib list and move on to check the rib nhg.
		 */
		if (IS_ZEBRA_DEBUG_RIB)
			zlog_debug(
				"%s(%u:%u):%pRN update_from_ctx(): replacing fib nhg",
				VRF_LOGNAME(vrf), re->vrf_id, re->table, rn);
		nexthops_free(re->fib_ng.nexthop);
		re->fib_ng.nexthop = NULL;

		UNSET_FLAG(re->status, ROUTE_ENTRY_USE_FIB_NHG);

		/* Note that the installed nexthops have changed */
		changed_p = true;
	} else {
		if (IS_ZEBRA_DEBUG_RIB)
			zlog_debug(
				"%s(%u:%u):%pRN update_from_ctx(): no fib nhg",
				VRF_LOGNAME(vrf), re->vrf_id, re->table, rn);
	}

	/*
	 * Compare with the rib nexthop group. The comparison here is different:
	 * the RIB group may be a superset of the list installed in the FIB. We
	 * walk the RIB group, looking for the 'installable' candidate
	 * nexthops, and then check those against the set
	 * that is actually installed.
	 *
	 * Assume nexthops are ordered here as well.
	 */

	/* If nothing is installed, we can skip some of the checking/comparison
	 * of nexthops.
	 */
	if (ctxnhg->nexthop == NULL) {
		changed_p = true;
		goto no_nexthops;
	}

	matched = rib_update_nhg_from_ctx(&(re->nhe->nhg), ctxnhg, &changed_p);

	/* If all nexthops were processed, we're done */
	if (matched) {
		if (IS_ZEBRA_DEBUG_RIB)
			zlog_debug(
				"%s(%u:%u):%pRN update_from_ctx(): rib nhg matched, changed '%s'",
				VRF_LOGNAME(vrf), re->vrf_id, re->table, rn,
				(changed_p ? "true" : "false"));
		goto check_backups;
	}

no_nexthops:

	/* FIB nexthop set differs from the RIB set:
	 * create a fib-specific nexthop-group
	 */
	if (IS_ZEBRA_DEBUG_RIB)
		zlog_debug(
			"%s(%u:%u):%pRN update_from_ctx(): changed %s, adding new fib nhg%s",
			VRF_LOGNAME(vrf), re->vrf_id, re->table, rn,
			(changed_p ? "true" : "false"),
			ctxnhg->nexthop != NULL ? "" : " (empty)");

	/* Set the flag about the dedicated fib list */
	if (zrouter.asic_notification_nexthop_control) {
		SET_FLAG(re->status, ROUTE_ENTRY_USE_FIB_NHG);
		if (ctxnhg->nexthop)
			copy_nexthops(&(re->fib_ng.nexthop), ctxnhg->nexthop,
				      NULL);
	}

check_backups:

	/*
	 * Check the status of the route's backup nexthops, if any.
	 * The logic for backups is somewhat different: if any backup is
	 * installed, a new fib nhg will be attached to the route.
	 */
	re_nhg = zebra_nhg_get_backup_nhg(re->nhe);
	if (re_nhg == NULL)
		goto done;	/* No backup nexthops */

	/* First check the route's 'fib' list of backups, if it's present
	 * from some previous event.
	 */
	re_nhg = &re->fib_backup_ng;
	ctxnhg = dplane_ctx_get_backup_ng(ctx);

	matched = false;
	if (re_nhg->nexthop && ctxnhg && nexthop_group_equal(re_nhg, ctxnhg))
		matched = true;

	/* If the new FIB set matches an existing FIB set, we're done. */
	if (matched) {
		if (IS_ZEBRA_DEBUG_RIB)
			zlog_debug(
				"%s(%u):%pRN update_from_ctx(): existing fib backup nhg, no change",
				VRF_LOGNAME(vrf), re->vrf_id, rn);
		goto done;

	} else if (re->fib_backup_ng.nexthop) {
		/*
		 * Free stale fib backup list and move on to check
		 * the route's backups.
		 */
		if (IS_ZEBRA_DEBUG_RIB)
			zlog_debug(
				"%s(%u):%pRN update_from_ctx(): replacing fib backup nhg",
				VRF_LOGNAME(vrf), re->vrf_id, rn);
		nexthops_free(re->fib_backup_ng.nexthop);
		re->fib_backup_ng.nexthop = NULL;

		/* Note that the installed nexthops have changed */
		changed_p = true;
	} else {
		if (IS_ZEBRA_DEBUG_RIB)
			zlog_debug(
				"%s(%u):%pRN update_from_ctx(): no fib backup nhg",
				VRF_LOGNAME(vrf), re->vrf_id, rn);
	}

	/*
	 * If a FIB backup nexthop set exists, attach a copy
	 * to the route if any backup is installed
	 */
	if (ctxnhg && ctxnhg->nexthop) {

		for (ALL_NEXTHOPS_PTR(ctxnhg, nexthop)) {
			if (CHECK_FLAG(nexthop->flags, NEXTHOP_FLAG_FIB))
				break;
		}

		/* If no installed backups, we're done */
		if (nexthop == NULL)
			goto done;

		if (IS_ZEBRA_DEBUG_RIB)
			zlog_debug(
				"%s(%u):%pRN update_from_ctx(): changed %s, adding new backup fib nhg",
				VRF_LOGNAME(vrf), re->vrf_id, rn,
				(changed_p ? "true" : "false"));

		copy_nexthops(&(re->fib_backup_ng.nexthop), ctxnhg->nexthop,
			      NULL);
	}

done:

	return changed_p;
}

/*
 * Helper to locate a zebra route-node from a dplane context. This is used
 * when processing dplane results, e.g. Note well: the route-node is returned
 * with a ref held - route_unlock_node() must be called eventually.
 */
struct route_node *rib_find_rn_from_ctx(const struct zebra_dplane_ctx *ctx)
{
	struct route_table *table = NULL;
	struct route_node *rn = NULL;
	const struct prefix *dest_pfx, *src_pfx;

	/* Locate rn and re(s) from ctx */

	table = zebra_vrf_lookup_table_with_table_id(
		dplane_ctx_get_afi(ctx), dplane_ctx_get_safi(ctx),
		dplane_ctx_get_vrf(ctx), dplane_ctx_get_table(ctx));
	if (table == NULL) {
		if (IS_ZEBRA_DEBUG_DPLANE) {
			zlog_debug(
				"Failed to find route for ctx: no table for afi %d, safi %d, vrf %s(%u)",
				dplane_ctx_get_afi(ctx),
				dplane_ctx_get_safi(ctx),
				vrf_id_to_name(dplane_ctx_get_vrf(ctx)),
				dplane_ctx_get_vrf(ctx));
		}
		goto done;
	}

	dest_pfx = dplane_ctx_get_dest(ctx);
	src_pfx = dplane_ctx_get_src(ctx);

	rn = srcdest_rnode_get(table, dest_pfx,
			       src_pfx ? (struct prefix_ipv6 *)src_pfx : NULL);

done:
	return rn;
}



/*
 * Route-update results processing after async dataplane update.
 */
static void rib_process_result(struct zebra_dplane_ctx *ctx)
{
	struct zebra_vrf *zvrf = NULL;
	struct vrf *vrf;
	struct route_node *rn = NULL;
	struct route_entry *re = NULL, *old_re = NULL, *rib;
	bool is_update = false;
	enum dplane_op_e op;
	enum zebra_dplane_result status;
	uint32_t seq;
	rib_dest_t *dest;
	bool fib_changed = false;
	struct rib_table_info *info;
	bool rt_delete = false;

	zvrf = zebra_vrf_lookup_by_id(dplane_ctx_get_vrf(ctx));
	vrf = vrf_lookup_by_id(dplane_ctx_get_vrf(ctx));

	/* Locate rn and re(s) from ctx */
	rn = rib_find_rn_from_ctx(ctx);
	if (rn == NULL) {
		if (IS_ZEBRA_DEBUG_DPLANE) {
			zlog_debug(
				"Failed to process dplane results: no route for %s(%u):%pRN",
				VRF_LOGNAME(vrf), dplane_ctx_get_vrf(ctx), rn);
		}
		goto done;
	}

	dest = rib_dest_from_rnode(rn);
	info = srcdest_rnode_table_info(rn);

	op = dplane_ctx_get_op(ctx);
	status = dplane_ctx_get_status(ctx);

	if (IS_ZEBRA_DEBUG_DPLANE_DETAIL)
		zlog_debug(
			"%s(%u:%u):%pRN Processing dplane result ctx %p, op %s result %s",
			VRF_LOGNAME(vrf), dplane_ctx_get_vrf(ctx),
			dplane_ctx_get_table(ctx), rn, ctx, dplane_op2str(op),
			dplane_res2str(status));

	/*
	 * Update is a bit of a special case, where we may have both old and new
	 * routes to post-process.
	 */
	is_update = dplane_ctx_is_update(ctx);

	/*
	 * Take a pass through the routes, look for matches with the context
	 * info.
	 */
	RNODE_FOREACH_RE(rn, rib) {

		if (re == NULL) {
			if (rib_route_match_ctx(rib, ctx, false, false))
				re = rib;
		}

		/* Check for old route match */
		if (is_update && (old_re == NULL)) {
			if (rib_route_match_ctx(rib, ctx, true, false))
				old_re = rib;
		}

		/* Have we found the routes we need to work on? */
		if (re && ((!is_update || old_re)))
			break;
	}

	seq = dplane_ctx_get_seq(ctx);

	/*
	 * Check sequence number(s) to detect stale results before continuing
	 */
	if (re) {
		if (re->dplane_sequence != seq) {
			if (IS_ZEBRA_DEBUG_DPLANE_DETAIL)
				zlog_debug(
					"%s(%u):%pRN Stale dplane result for re %p",
					VRF_LOGNAME(vrf),
					dplane_ctx_get_vrf(ctx), rn, re);
		} else {
			if (!zrouter.asic_offloaded ||
			    (CHECK_FLAG(re->flags, ZEBRA_FLAG_OFFLOADED) ||
			     CHECK_FLAG(re->flags,
					ZEBRA_FLAG_OFFLOAD_FAILED))) {
				UNSET_FLAG(re->status,
					   ROUTE_ENTRY_ROUTE_REPLACING);
				UNSET_FLAG(re->status, ROUTE_ENTRY_QUEUED);
			}
		}
	}

	if (old_re) {
		if (old_re->dplane_sequence != dplane_ctx_get_old_seq(ctx)) {
			if (IS_ZEBRA_DEBUG_DPLANE_DETAIL)
				zlog_debug(
					"%s(%u:%u):%pRN Stale dplane result for old_re %p",
					VRF_LOGNAME(vrf),
					dplane_ctx_get_vrf(ctx), old_re->table,
					rn, old_re);
		} else
			UNSET_FLAG(old_re->status, ROUTE_ENTRY_QUEUED);
	}

	if (op == DPLANE_OP_ROUTE_INSTALL || op == DPLANE_OP_ROUTE_UPDATE) {
		if (status == ZEBRA_DPLANE_REQUEST_SUCCESS) {
			if (re) {
				UNSET_FLAG(re->status, ROUTE_ENTRY_FAILED);
				SET_FLAG(re->status, ROUTE_ENTRY_INSTALLED);
			}
			/*
			 * On an update operation from the same route type
			 * context retrieval currently has no way to know
			 * which was the old and which was the new.
			 * So don't unset our flags that we just set.
			 * We know redistribution is ok because the
			 * old_re in this case is used for nothing
			 * more than knowing whom to contact if necessary.
			 */
			if (old_re && old_re != re) {
				UNSET_FLAG(old_re->status, ROUTE_ENTRY_FAILED);
				UNSET_FLAG(old_re->status,
					   ROUTE_ENTRY_INSTALLED);
			}

			/* Update zebra route based on the results in
			 * the context struct.
			 */
			if (re) {
				fib_changed =
					rib_update_re_from_ctx(re, rn, ctx);

				if (!fib_changed) {
					if (IS_ZEBRA_DEBUG_DPLANE_DETAIL)
						zlog_debug(
							"%s(%u:%u):%pRN no fib change for re",
							VRF_LOGNAME(vrf),
							dplane_ctx_get_vrf(ctx),
							dplane_ctx_get_table(
								ctx),
							rn);
				}

				/* Redistribute if this is the selected re */
				if (dest && re == dest->selected_fib)
					redistribute_update(rn, re, old_re);
			}

			/*
			 * System routes are weird in that they
			 * allow multiple to be installed that match
			 * to the same prefix, so after we get the
			 * result we need to clean them up so that
			 * we can actually use them.
			 */
			if ((re && RIB_SYSTEM_ROUTE(re)) ||
			    (old_re && RIB_SYSTEM_ROUTE(old_re)))
				zebra_rib_fixup_system(rn);

			if (zvrf)
				zvrf->installs++;

			/* Notify route owner */
			if (zebra_router_notify_on_ack())
				zsend_route_notify_owner_ctx(ctx, ZAPI_ROUTE_INSTALLED);
			else {
				if (re) {
					if (CHECK_FLAG(re->flags,
						       ZEBRA_FLAG_OFFLOADED))
						zsend_route_notify_owner_ctx(
							ctx,
							ZAPI_ROUTE_INSTALLED);
					if (CHECK_FLAG(
						    re->flags,
						    ZEBRA_FLAG_OFFLOAD_FAILED))
						zsend_route_notify_owner_ctx(
							ctx,
							ZAPI_ROUTE_FAIL_INSTALL);
				}
			}
		} else {
			if (re) {
				SET_FLAG(re->status, ROUTE_ENTRY_FAILED);
				UNSET_FLAG(re->status, ROUTE_ENTRY_INSTALLED);
			} if (old_re)
				SET_FLAG(old_re->status, ROUTE_ENTRY_FAILED);
			if (re)
				zsend_route_notify_owner(
					rn, re, ZAPI_ROUTE_FAIL_INSTALL,
					info->afi, info->safi);

			zlog_warn("%s(%u:%u):%pRN: Route install failed",
				  VRF_LOGNAME(vrf), dplane_ctx_get_vrf(ctx),
				  dplane_ctx_get_table(ctx), rn);
		}
	} else if (op == DPLANE_OP_ROUTE_DELETE) {
		rt_delete = true;
		if (re)
			SET_FLAG(re->status, ROUTE_ENTRY_FAILED);
		/*
		 * In the delete case, the zebra core datastructs were
		 * updated (or removed) at the time the delete was issued,
		 * so we're just notifying the route owner.
		 */
		if (status == ZEBRA_DPLANE_REQUEST_SUCCESS) {
			if (re) {
				UNSET_FLAG(re->status, ROUTE_ENTRY_INSTALLED);
				UNSET_FLAG(re->status, ROUTE_ENTRY_FAILED);
			}
			zsend_route_notify_owner_ctx(ctx, ZAPI_ROUTE_REMOVED);

			if (zvrf)
				zvrf->removals++;
		} else {
			if (re)
				SET_FLAG(re->status, ROUTE_ENTRY_FAILED);
			zsend_route_notify_owner_ctx(ctx,
						     ZAPI_ROUTE_REMOVE_FAIL);

			zlog_warn("%s(%u:%u):%pRN: Route Deletion failure",
				  VRF_LOGNAME(vrf), dplane_ctx_get_vrf(ctx),
				  dplane_ctx_get_table(ctx), rn);
		}

		/*
		 * System routes are weird in that they
		 * allow multiple to be installed that match
		 * to the same prefix, so after we get the
		 * result we need to clean them up so that
		 * we can actually use them.
		 */
		if ((re && RIB_SYSTEM_ROUTE(re)) ||
		    (old_re && RIB_SYSTEM_ROUTE(old_re)))
			zebra_rib_fixup_system(rn);
	}

	zebra_rib_evaluate_rn_nexthops(rn, seq, rt_delete);
	zebra_rib_evaluate_mpls(rn);
done:

	if (rn)
		route_unlock_node(rn);
}

/*
 * Count installed/FIB nexthops
 */
static int rib_count_installed_nh(struct route_entry *re)
{
	int count = 0;
	struct nexthop *nexthop;
	struct nexthop_group *nhg;

	nhg = rib_get_fib_nhg(re);

	for (ALL_NEXTHOPS_PTR(nhg, nexthop)) {
		/* The meaningful flag depends on where the installed
		 * nexthops reside.
		 */
		if (nhg == &(re->fib_ng)) {
			if (CHECK_FLAG(nexthop->flags, NEXTHOP_FLAG_FIB))
				count++;
		} else {
			if (CHECK_FLAG(nexthop->flags, NEXTHOP_FLAG_ACTIVE))
				count++;
		}
	}

	nhg = rib_get_fib_backup_nhg(re);
	if (nhg) {
		for (ALL_NEXTHOPS_PTR(nhg, nexthop)) {
			if (CHECK_FLAG(nexthop->flags, NEXTHOP_FLAG_FIB))
				count++;
		}
	}

	return count;
}

/*
 * Handle notification from async dataplane: the dataplane has detected
 * some change to a route, and notifies zebra so that the control plane
 * can reflect that change.
 */
static void rib_process_dplane_notify(struct zebra_dplane_ctx *ctx)
{
	struct route_node *rn = NULL;
	struct route_entry *re = NULL;
	struct vrf *vrf;
	struct nexthop *nexthop;
	rib_dest_t *dest;
	bool fib_changed = false;
	bool debug_p = IS_ZEBRA_DEBUG_DPLANE | IS_ZEBRA_DEBUG_RIB;
	int start_count, end_count;

	vrf = vrf_lookup_by_id(dplane_ctx_get_vrf(ctx));

	/* Locate rn and re(s) from ctx */
	rn = rib_find_rn_from_ctx(ctx);
	if (rn == NULL) {
		if (debug_p) {
			zlog_debug(
				"Failed to process dplane notification: no routes for %s(%u:%u):%pRN",
				VRF_LOGNAME(vrf), dplane_ctx_get_vrf(ctx),
				dplane_ctx_get_table(ctx), rn);
		}
		goto done;
	}

	dest = rib_dest_from_rnode(rn);

	if (debug_p)
		zlog_debug("%s(%u:%u):%pRN Processing dplane notif ctx %p",
			   VRF_LOGNAME(vrf), dplane_ctx_get_vrf(ctx),
			   dplane_ctx_get_table(ctx), rn, ctx);

	/*
	 * Take a pass through the routes, look for matches with the context
	 * info.
	 */
	RNODE_FOREACH_RE(rn, re) {
		if (rib_route_match_ctx(re, ctx, false, true))
			break;
	}

	/* No match? Nothing we can do */
	if (re == NULL) {
		if (debug_p)
			zlog_debug(
				"%s(%u:%u):%pRN Unable to process dplane notification: no entry for type %s",
				VRF_LOGNAME(vrf), dplane_ctx_get_vrf(ctx),
				dplane_ctx_get_table(ctx), rn,
				zebra_route_string(dplane_ctx_get_type(ctx)));

		goto done;
	}

	/* Ensure we clear the QUEUED flag */
	UNSET_FLAG(re->status, ROUTE_ENTRY_QUEUED);
	UNSET_FLAG(re->status, ROUTE_ENTRY_ROUTE_REPLACING);

	/* Is this a notification that ... matters? We mostly care about
	 * the route that is currently selected for installation; we may also
	 * get an un-install notification, and handle that too.
	 */
	if (re != dest->selected_fib) {
		/*
		 * If we need to, clean up after a delete that was part of
		 * an update operation.
		 */
		end_count = 0;
		for (ALL_NEXTHOPS_PTR(dplane_ctx_get_ng(ctx), nexthop)) {
			if (CHECK_FLAG(nexthop->flags, NEXTHOP_FLAG_FIB))
				end_count++;
		}

		/* If no nexthops or none installed, ensure that this re
		 * gets its 'installed' flag cleared.
		 */
		if (end_count == 0) {
			if (CHECK_FLAG(re->status, ROUTE_ENTRY_INSTALLED))
				UNSET_FLAG(re->status, ROUTE_ENTRY_INSTALLED);
			if (debug_p)
				zlog_debug(
					"%s(%u:%u):%pRN dplane notif, uninstalled type %s route",
					VRF_LOGNAME(vrf),
					dplane_ctx_get_vrf(ctx),
					dplane_ctx_get_table(ctx), rn,
					zebra_route_string(
						dplane_ctx_get_type(ctx)));
		} else {
			/* At least report on the event. */
			if (debug_p)
				zlog_debug(
					"%s(%u:%u):%pRN dplane notif, but type %s not selected_fib",
					VRF_LOGNAME(vrf),
					dplane_ctx_get_vrf(ctx),
					dplane_ctx_get_table(ctx), rn,
					zebra_route_string(
						dplane_ctx_get_type(ctx)));
		}
		goto done;
	} else {
		uint32_t flags = dplane_ctx_get_flags(ctx);

		if (CHECK_FLAG(flags, ZEBRA_FLAG_OFFLOADED)) {
			UNSET_FLAG(re->flags, ZEBRA_FLAG_OFFLOAD_FAILED);
			SET_FLAG(re->flags, ZEBRA_FLAG_OFFLOADED);
		}
		if (CHECK_FLAG(flags, ZEBRA_FLAG_OFFLOAD_FAILED)) {
			UNSET_FLAG(re->flags, ZEBRA_FLAG_OFFLOADED);
			SET_FLAG(re->flags, ZEBRA_FLAG_OFFLOAD_FAILED);
		}
		if (CHECK_FLAG(flags, ZEBRA_FLAG_TRAPPED))
			SET_FLAG(re->flags, ZEBRA_FLAG_TRAPPED);
	}

	/* We'll want to determine whether the installation status of the
	 * route has changed: we'll check the status before processing,
	 * and then again if there's been a change.
	 */
	start_count = 0;

	if (CHECK_FLAG(re->status, ROUTE_ENTRY_INSTALLED))
		start_count = rib_count_installed_nh(re);

	/* Update zebra's nexthop FIB flags based on the context struct's
	 * nexthops.
	 */
	fib_changed = rib_update_re_from_ctx(re, rn, ctx);

	if (!fib_changed) {
		if (debug_p)
			zlog_debug(
				"%s(%u:%u):%pRN dplane notification: rib_update returns FALSE",
				VRF_LOGNAME(vrf), dplane_ctx_get_vrf(ctx),
				dplane_ctx_get_table(ctx), rn);
	}

	/*
	 * Perform follow-up work if the actual status of the prefix
	 * changed.
	 */
	end_count = rib_count_installed_nh(re);

	/* Various fib transitions: changed nexthops; from installed to
	 * not-installed; or not-installed to installed.
	 */
	if (zrouter.asic_notification_nexthop_control) {
		if (start_count > 0 && end_count > 0) {
			if (debug_p)
				zlog_debug(
					"%s(%u:%u):%pRN applied nexthop changes from dplane notification",
					VRF_LOGNAME(vrf),
					dplane_ctx_get_vrf(ctx),
					dplane_ctx_get_table(ctx), rn);

			/* Changed nexthops - update kernel/others */
			dplane_route_notif_update(rn, re,
						  DPLANE_OP_ROUTE_UPDATE, ctx);

		} else if (start_count == 0 && end_count > 0) {
			if (debug_p)
				zlog_debug(
					"%s(%u:%u):%pRN installed transition from dplane notification",
					VRF_LOGNAME(vrf),
					dplane_ctx_get_vrf(ctx),
					dplane_ctx_get_table(ctx), rn);

			/* We expect this to be the selected route, so we want
			 * to tell others about this transition.
			 */
			SET_FLAG(re->status, ROUTE_ENTRY_INSTALLED);

			/* Changed nexthops - update kernel/others */
			dplane_route_notif_update(rn, re,
						  DPLANE_OP_ROUTE_UPDATE, ctx);

			/* Redistribute, lsp, and nht update */
			redistribute_update(rn, re, NULL);

		} else if (start_count > 0 && end_count == 0) {
			if (debug_p)
				zlog_debug(
					"%s(%u:%u):%pRN un-installed transition from dplane notification",
					VRF_LOGNAME(vrf),
					dplane_ctx_get_vrf(ctx),
					dplane_ctx_get_table(ctx), rn);

			/* Transition from _something_ installed to _nothing_
			 * installed.
			 */
			/* We expect this to be the selected route, so we want
			 * to tell others about this transistion.
			 */
			UNSET_FLAG(re->status, ROUTE_ENTRY_INSTALLED);

			/* Changed nexthops - update kernel/others */
			dplane_route_notif_update(rn, re,
						  DPLANE_OP_ROUTE_DELETE, ctx);

			/* Redistribute, lsp, and nht update */
			redistribute_delete(rn, re, NULL);
		}
	}

	if (!zebra_router_notify_on_ack()) {
		if (CHECK_FLAG(re->flags, ZEBRA_FLAG_OFFLOADED))
			zsend_route_notify_owner_ctx(ctx, ZAPI_ROUTE_INSTALLED);
		if (CHECK_FLAG(re->flags, ZEBRA_FLAG_OFFLOAD_FAILED))
			zsend_route_notify_owner_ctx(ctx,
						     ZAPI_ROUTE_FAIL_INSTALL);
	}

	/* Make any changes visible for lsp and nexthop-tracking processing */
	zebra_rib_evaluate_rn_nexthops(rn, zebra_router_get_next_sequence(),
				       false);

	zebra_rib_evaluate_mpls(rn);

done:
	if (rn)
		route_unlock_node(rn);
}

/*
 * Process a node from the EVPN/VXLAN subqueue.
 */
static void process_subq_evpn(struct listnode *lnode)
{
	struct wq_evpn_wrapper *w;

	/* In general, the list node points to a wrapper object
	 * holding the info necessary to make some update.
	 */
	w = listgetdata(lnode);
	if (!w)
		return;

	if (w->type == WQ_EVPN_WRAPPER_TYPE_VRFROUTE) {
		if (w->add_p)
			zebra_vxlan_evpn_vrf_route_add(w->vrf_id, &w->macaddr,
						       &w->ip, &w->prefix);
		else
			zebra_vxlan_evpn_vrf_route_del(w->vrf_id, &w->ip,
						       &w->prefix);
	} else if (w->type == WQ_EVPN_WRAPPER_TYPE_REM_ES) {
		if (w->add_p)
			zebra_evpn_remote_es_add(&w->esi, w->ip.ipaddr_v4,
						 w->esr_rxed, w->df_alg,
						 w->df_pref);
		else
			zebra_evpn_remote_es_del(&w->esi, w->ip.ipaddr_v4);
	} else if (w->type == WQ_EVPN_WRAPPER_TYPE_REM_MACIP) {
		uint16_t ipa_len = 0;

		if (w->ip.ipa_type == IPADDR_V4)
			ipa_len = IPV4_MAX_BYTELEN;
		else if (w->ip.ipa_type == IPADDR_V6)
			ipa_len = IPV6_MAX_BYTELEN;

		if (w->add_p)
			zebra_evpn_rem_macip_add(w->vni, &w->macaddr, ipa_len,
						 &w->ip, w->flags, w->seq,
						 w->vtep_ip, &w->esi);
		else
			zebra_evpn_rem_macip_del(w->vni, &w->macaddr, ipa_len,
						 &w->ip, w->vtep_ip);
	} else if (w->type == WQ_EVPN_WRAPPER_TYPE_REM_VTEP) {
		if (w->add_p)
			zebra_vxlan_remote_vtep_add(w->vrf_id, w->vni,
						    w->vtep_ip, w->flags);
		else
			zebra_vxlan_remote_vtep_del(w->vrf_id, w->vni,
						    w->vtep_ip);
	}


	XFREE(MTYPE_WQ_WRAPPER, w);
}

/*
 * Process the nexthop-group workqueue subqueue
 */
static void process_subq_nhg(struct listnode *lnode)
{
	struct nhg_ctx *ctx;
	struct nhg_hash_entry *nhe, *newnhe, *oldnhe;
	struct wq_nhg_wrapper *w;
	uint8_t qindex = META_QUEUE_NHG;

	w = listgetdata(lnode);

	if (!w)
		return;

	/* Two types of object - an update from the local kernel, or
	 * an nhg update from a daemon.
	 */
	if (w->type == WQ_NHG_WRAPPER_TYPE_CTX) {
		ctx = w->u.ctx;

		if (IS_ZEBRA_DEBUG_RIB_DETAILED)
			zlog_debug(
				"NHG Context id=%u dequeued from sub-queue %s",
				ctx->id, subqueue2str(qindex));


		/* Process nexthop group updates coming 'up' from the OS */
		nhg_ctx_process(ctx);

	} else if (w->type == WQ_NHG_WRAPPER_TYPE_NHG) {
		nhe = w->u.nhe;

		if (IS_ZEBRA_DEBUG_RIB_DETAILED)
			zlog_debug("NHG %u dequeued from sub-queue %s", nhe->id,
				   subqueue2str(qindex));

		/* Process incoming nhg update, probably from a proto daemon */
		if (w->deletion) {
			/*
			 * Delete the received nhg id
			 */
			oldnhe = zebra_nhg_proto_del(nhe->id, nhe->type);
			if (oldnhe) {
				zsend_nhg_notify(nhe->type, nhe->zapi_instance,
						 nhe->zapi_session, nhe->id,
						 ZAPI_NHG_REMOVED);
				zebra_nhg_decrement_ref(oldnhe);
			} else
				zsend_nhg_notify(nhe->type, nhe->zapi_instance,
						 nhe->zapi_session, nhe->id,
						 ZAPI_NHG_REMOVE_FAIL);

		} else {
			newnhe = zebra_nhg_proto_add(nhe->id, nhe->type,
						     nhe->zapi_instance,
						     nhe->zapi_session,
						     &nhe->nhg, 0);

			/* Report error to daemon via ZAPI */
			if (newnhe == NULL)
				zsend_nhg_notify(nhe->type, nhe->zapi_instance,
						 nhe->zapi_session, nhe->id,
						 ZAPI_NHG_FAIL_INSTALL);
		}

		/* Free temp nhe - we own that memory. */
		zebra_nhg_free(nhe);
	}

	XFREE(MTYPE_WQ_WRAPPER, w);
}

static void process_subq_early_label(struct listnode *lnode)
{
	struct wq_label_wrapper *w = listgetdata(lnode);
	struct zebra_vrf *zvrf;

	if (!w)
		return;

	zvrf = zebra_vrf_lookup_by_id(w->vrf_id);
	if (!zvrf) {
		XFREE(MTYPE_WQ_WRAPPER, w);
		return;
	}

	switch (w->type) {
	case WQ_LABEL_FTN_UNINSTALL:
		zebra_mpls_ftn_uninstall(zvrf, w->ltype, &w->p, w->route_type,
					 w->route_instance);
		break;
	case WQ_LABEL_LABELS_PROCESS:
		zebra_mpls_zapi_labels_process(w->add_p, zvrf, &w->zl);
		break;
	}

	XFREE(MTYPE_WQ_WRAPPER, w);
}

static void process_subq_route(struct listnode *lnode, uint8_t qindex)
{
	struct route_node *rnode = NULL;
	rib_dest_t *dest = NULL;
	struct zebra_vrf *zvrf = NULL;

	rnode = listgetdata(lnode);
	dest = rib_dest_from_rnode(rnode);
	assert(dest);

	zvrf = rib_dest_vrf(dest);

	rib_process(rnode);

	if (IS_ZEBRA_DEBUG_RIB_DETAILED) {
		struct route_entry *re = NULL;

		/*
		 * rib_process may have freed the dest
		 * as part of the garbage collection.  Let's
		 * prevent stupidity from happening.
		 */
		dest = rib_dest_from_rnode(rnode);
		if (dest)
			re = re_list_first(&dest->routes);

		zlog_debug("%s(%u:%u):%pRN rn %p dequeued from sub-queue %s",
			   zvrf_name(zvrf), zvrf_id(zvrf), re ? re->table : 0,
			   rnode, rnode, subqueue2str(qindex));
	}

	if (rnode->info)
		UNSET_FLAG(rib_dest_from_rnode(rnode)->flags,
			   RIB_ROUTE_QUEUED(qindex));

	route_unlock_node(rnode);
}

static void rib_re_nhg_free(struct route_entry *re)
{
	if (re->nhe && re->nhe_id) {
		assert(re->nhe->id == re->nhe_id);
		route_entry_update_nhe(re, NULL);
	} else if (re->nhe && re->nhe->nhg.nexthop)
		nexthops_free(re->nhe->nhg.nexthop);

	nexthops_free(re->fib_ng.nexthop);
}

struct zebra_early_route {
	afi_t afi;
	safi_t safi;
	struct prefix p;
	struct prefix_ipv6 src_p;
	bool src_p_provided;
	struct route_entry *re;
	struct nhg_hash_entry *re_nhe;
	bool startup;
	bool deletion;
	bool fromkernel;
};

static void early_route_memory_free(struct zebra_early_route *ere)
{
	if (ere->re_nhe)
		zebra_nhg_free(ere->re_nhe);

	zebra_rib_route_entry_free(ere->re);
	XFREE(MTYPE_WQ_WRAPPER, ere);
}

static void process_subq_early_route_add(struct zebra_early_route *ere)
{
	struct route_entry *re = ere->re;
	struct route_table *table;
	struct nhg_hash_entry *nhe = NULL;
	struct route_node *rn;
	struct route_entry *same = NULL, *first_same = NULL;
	int same_count = 0;
	rib_dest_t *dest;

	/* Lookup table.  */
	table = zebra_vrf_get_table_with_table_id(ere->afi, ere->safi,
						  re->vrf_id, re->table);
	if (!table) {
		early_route_memory_free(ere);
		return;
	}

	if (re->nhe_id > 0) {
		nhe = zebra_nhg_lookup_id(re->nhe_id);

		if (!nhe) {
			/*
			 * We've received from the kernel a nexthop id
			 * that we don't have saved yet.  More than likely
			 * it has not been processed and is on the
			 * queue to be processed.  Let's stop what we
			 * are doing and cause the meta q to be processed
			 * storing this for later.
			 *
			 * This is being done this way because zebra
			 * runs with the assumption t
			 */
			flog_err(
				EC_ZEBRA_TABLE_LOOKUP_FAILED,
				"Zebra failed to find the nexthop hash entry for id=%u in a route entry %pFX",
				re->nhe_id, &ere->p);

			early_route_memory_free(ere);
			return;
		}
	} else {
		struct nexthop *tmp_nh;

		/* Lookup nhe from route information */
		nhe = zebra_nhg_rib_find_nhe(ere->re_nhe, ere->afi);
		if (!nhe) {
			char buf2[PREFIX_STRLEN] = "";

			flog_err(
				EC_ZEBRA_TABLE_LOOKUP_FAILED,
				"Zebra failed to find or create a nexthop hash entry for %pFX%s%s",
				&ere->p, ere->src_p_provided ? " from " : "",
				ere->src_p_provided
					? prefix2str(&ere->src_p, buf2,
						     sizeof(buf2))
					: "");

			early_route_memory_free(ere);
			return;
		}
		for (ALL_NEXTHOPS(nhe->nhg, tmp_nh)) {
			if (CHECK_FLAG(tmp_nh->flags, NEXTHOP_FLAG_EVPN)) {
				struct ipaddr vtep_ip = {};

				if (ere->afi == AFI_IP) {
					vtep_ip.ipa_type = IPADDR_V4;
					vtep_ip.ipaddr_v4 = tmp_nh->gate.ipv4;
				} else {
					vtep_ip.ipa_type = IPADDR_V6;
					vtep_ip.ipaddr_v6 = tmp_nh->gate.ipv6;
				}
				zebra_rib_queue_evpn_route_add(
					re->vrf_id, &tmp_nh->rmac, &vtep_ip,
					&ere->p);
			}
		}
	}

	/*
	 * Attach the re to the nhe's nexthop group.
	 *
	 * TODO: This will need to change when we start getting IDs from upper
	 * level protocols, as the refcnt might be wrong, since it checks
	 * if old_id != new_id.
	 */
	route_entry_update_nhe(re, nhe);

	/* Make it sure prefixlen is applied to the prefix. */
	apply_mask(&ere->p);
	if (ere->src_p_provided)
		apply_mask_ipv6(&ere->src_p);

	/* Lookup route node.*/
	rn = srcdest_rnode_get(table, &ere->p,
			       ere->src_p_provided ? &ere->src_p : NULL);

	/*
	 * If same type of route are installed, treat it as a implicit
	 * withdraw. If the user has specified the No route replace semantics
	 * for the install don't do a route replace.
	 */
	RNODE_FOREACH_RE (rn, same) {
		if (CHECK_FLAG(same->status, ROUTE_ENTRY_REMOVED)) {
			same_count++;
			continue;
		}

		/* Compare various route_entry properties */
		if (rib_compare_routes(re, same)) {
			same_count++;

			if (first_same == NULL)
				first_same = same;
		}
	}

	same = first_same;

	if (!ere->startup && (re->flags & ZEBRA_FLAG_SELFROUTE) &&
	    zrouter.asic_offloaded) {
		if (!same) {
			if (IS_ZEBRA_DEBUG_RIB)
				zlog_debug(
					"prefix: %pRN is a self route where we do not have an entry for it.  Dropping this update, it's useless",
					rn);
			/*
			 * We are not on startup, this is a self route
			 * and we have asic offload.  Which means
			 * we are getting a callback for a entry
			 * that was already deleted to the kernel
			 * but an earlier response was just handed
			 * back.  Drop it on the floor
			 */
			early_route_memory_free(ere);
			return;
		}
	}

	/* Set default distance by route type. */
	if (re->distance == 0) {
		if (same && !zebra_router_notify_on_ack())
			re->distance = same->distance;
		else
			re->distance = route_distance(re->type);
	}

	if (re->metric == ROUTE_INSTALLATION_METRIC &&
	    CHECK_FLAG(re->flags, ZEBRA_FLAG_SELFROUTE)) {
		if (same && !zebra_router_notify_on_ack())
			re->metric = same->metric;
		else
			re->metric = 0;
	}

	/* If this route is kernel/connected route, notify the dataplane. */
	if (RIB_SYSTEM_ROUTE(re)) {
		/* Notify dataplane */
		dplane_sys_route_add(rn, re);
	}

	/* Link new re to node.*/
	if (IS_ZEBRA_DEBUG_RIB) {
		rnode_debug(rn, re->vrf_id,
			    "Inserting route rn %p, re %p (%s/%s/%s) existing %p, same_count %d",
			    rn, re, zebra_route_string(re->type),
			    afi2str(ere->afi), safi2str(ere->safi), same,
			    same_count);

		if (IS_ZEBRA_DEBUG_RIB_DETAILED)
			route_entry_dump(
				&ere->p,
				ere->src_p_provided ? &ere->src_p : NULL, re);
	}

	SET_FLAG(re->status, ROUTE_ENTRY_CHANGED);
	rib_addnode(rn, re, 1);

	dest = rib_dest_from_rnode(rn);
	/* Free implicit route.*/
	if (same) {
		if (dest && same == dest->selected_fib)
			SET_FLAG(same->status, ROUTE_ENTRY_ROUTE_REPLACING);
		rib_delnode(rn, same);
	}

	/* See if we can remove some RE entries that are queued for
	 * removal, but won't be considered in rib processing.
	 */
	RNODE_FOREACH_RE_SAFE (rn, re, same) {
		if (CHECK_FLAG(re->status, ROUTE_ENTRY_REMOVED)) {
			/* If the route was used earlier, must retain it. */
			if (dest && re == dest->selected_fib)
				continue;

			if (IS_ZEBRA_DEBUG_RIB)
				rnode_debug(rn, re->vrf_id,
					    "rn %p, removing unneeded re %p",
					    rn, re);

			rib_unlink(rn, re);
		}
	}

	route_unlock_node(rn);
	if (ere->re_nhe)
		zebra_nhg_free(ere->re_nhe);
	XFREE(MTYPE_WQ_WRAPPER, ere);
}

static void process_subq_early_route_delete(struct zebra_early_route *ere)
{
	struct route_table *table;
	struct route_node *rn;
	struct route_entry *re;
	struct route_entry *fib = NULL;
	struct route_entry *same = NULL;
	struct nexthop *rtnh;
	char buf2[INET6_ADDRSTRLEN];
	rib_dest_t *dest;

	if (ere->src_p_provided)
		assert(!ere->src_p.prefixlen || ere->afi == AFI_IP6);

	/* Lookup table.  */
	table = zebra_vrf_lookup_table_with_table_id(
		ere->afi, ere->safi, ere->re->vrf_id, ere->re->table);
	if (!table) {
		early_route_memory_free(ere);
		return;
	}

	/* Apply mask. */
	apply_mask(&ere->p);
	if (ere->src_p_provided)
		apply_mask_ipv6(&ere->src_p);

	/* Lookup route node. */
	rn = srcdest_rnode_lookup(table, &ere->p,
				  ere->src_p_provided ? &ere->src_p : NULL);
	if (!rn) {
		if (IS_ZEBRA_DEBUG_RIB) {
			char src_buf[PREFIX_STRLEN];
			struct vrf *vrf = vrf_lookup_by_id(ere->re->vrf_id);

			if (ere->src_p_provided && ere->src_p.prefixlen)
				prefix2str(&ere->src_p, src_buf,
					   sizeof(src_buf));
			else
				src_buf[0] = '\0';

			zlog_debug("%s[%d]:%pRN%s%s doesn't exist in rib",
				   vrf->name, ere->re->table, rn,
				   (src_buf[0] != '\0') ? " from " : "",
				   src_buf);
		}
		early_route_memory_free(ere);
		return;
	}

	dest = rib_dest_from_rnode(rn);
	fib = dest->selected_fib;

	struct nexthop *nh = NULL;

	if (ere->re_nhe)
		nh = ere->re_nhe->nhg.nexthop;

	/* Lookup same type route. */
	RNODE_FOREACH_RE (rn, re) {
		if (CHECK_FLAG(re->status, ROUTE_ENTRY_REMOVED))
			continue;

		if (re->type != ere->re->type)
			continue;
		if (re->instance != ere->re->instance)
			continue;
		if (CHECK_FLAG(re->flags, ZEBRA_FLAG_RR_USE_DISTANCE) &&
		    ere->re->distance != re->distance)
			continue;

		if (re->type == ZEBRA_ROUTE_KERNEL &&
		    re->metric != ere->re->metric)
			continue;
		if ((re->type == ZEBRA_ROUTE_CONNECT ||
		     re->type == ZEBRA_ROUTE_LOCAL) &&
		    (rtnh = re->nhe->nhg.nexthop) &&
		    rtnh->type == NEXTHOP_TYPE_IFINDEX && nh) {
			if (rtnh->ifindex != nh->ifindex)
				continue;
			same = re;
			break;
		}

		/* Make sure that the route found has the same gateway. */
		if (ere->re->nhe_id && re->nhe_id == ere->re->nhe_id) {
			same = re;
			break;
		}

		if (nh == NULL) {
			same = re;
			break;
		}
		for (ALL_NEXTHOPS(re->nhe->nhg, rtnh)) {
			/*
			 * No guarantee all kernel send nh with labels
			 * on delete.
			 */
			if (nexthop_same_no_labels(rtnh, nh)) {
				same = re;
				break;
			}
		}

		if (same)
			break;
	}
	/*
	 * If same type of route can't be found and this message is from
	 * kernel.
	 */
	if (!same) {
		/*
		 * In the past(HA!) we could get here because
		 * we were receiving a route delete from the
		 * kernel and we're not marking the proto
		 * as coming from it's appropriate originator.
		 * Now that we are properly noticing the fact
		 * that the kernel has deleted our route we
		 * are not going to get called in this path
		 * I am going to leave this here because
		 * this might still work this way on non-linux
		 * platforms as well as some weird state I have
		 * not properly thought of yet.
		 * If we can show that this code path is
		 * dead then we can remove it.
		 */
		if (fib && CHECK_FLAG(ere->re->flags, ZEBRA_FLAG_SELFROUTE)) {
			if (IS_ZEBRA_DEBUG_RIB) {
				rnode_debug(
					rn, ere->re->vrf_id,
					"rn %p, re %p (%s) was deleted from kernel, adding",
					rn, fib, zebra_route_string(fib->type));
			}
			if (zrouter.allow_delete ||
			    CHECK_FLAG(dest->flags, RIB_ROUTE_ANY_QUEUED)) {
				UNSET_FLAG(fib->status, ROUTE_ENTRY_INSTALLED);
				/* Unset flags. */
				for (rtnh = fib->nhe->nhg.nexthop; rtnh;
				     rtnh = rtnh->next)
					UNSET_FLAG(rtnh->flags,
						   NEXTHOP_FLAG_FIB);

				/*
				 * This is a non FRR route
				 * as such we should mark
				 * it as deleted
				 */
				dest->selected_fib = NULL;
			} else {
				/*
				 * This means someone else, other than Zebra,
				 * has deleted a Zebra router from the kernel.
				 * We will add it back
				 */
				rib_install_kernel(rn, fib, NULL);
			}
		} else {
			if (IS_ZEBRA_DEBUG_RIB) {
				if (nh)
					rnode_debug(
						rn, ere->re->vrf_id,
						"via %s ifindex %d type %d doesn't exist in rib",
						inet_ntop(afi2family(ere->afi),
							  &nh->gate, buf2,
							  sizeof(buf2)),
						nh->ifindex, ere->re->type);
				else
					rnode_debug(
						rn, ere->re->vrf_id,
						"type %d doesn't exist in rib",
						ere->re->type);
			}
			route_unlock_node(rn);
			early_route_memory_free(ere);
			return;
		}
	}

	if (same) {
		struct nexthop *tmp_nh;

		if (ere->fromkernel &&
		    CHECK_FLAG(ere->re->flags, ZEBRA_FLAG_SELFROUTE) &&
		    !zrouter.allow_delete) {
			rib_install_kernel(rn, same, NULL);
			route_unlock_node(rn);

			early_route_memory_free(ere);
			return;
		}

		/* Special handling for IPv4 or IPv6 routes sourced from
		 * EVPN - the nexthop (and associated MAC) need to be
		 * uninstalled if no more refs.
		 */
		for (ALL_NEXTHOPS(re->nhe->nhg, tmp_nh)) {
			struct ipaddr vtep_ip;

			if (CHECK_FLAG(tmp_nh->flags, NEXTHOP_FLAG_EVPN)) {
				memset(&vtep_ip, 0, sizeof(struct ipaddr));
				if (ere->afi == AFI_IP) {
					vtep_ip.ipa_type = IPADDR_V4;
					memcpy(&(vtep_ip.ipaddr_v4),
					       &(tmp_nh->gate.ipv4),
					       sizeof(struct in_addr));
				} else {
					vtep_ip.ipa_type = IPADDR_V6;
					memcpy(&(vtep_ip.ipaddr_v6),
					       &(tmp_nh->gate.ipv6),
					       sizeof(struct in6_addr));
				}
				zebra_rib_queue_evpn_route_del(
					re->vrf_id, &vtep_ip, &ere->p);
			}
		}

		/* Notify dplane if system route changes */
		if (RIB_SYSTEM_ROUTE(re))
			dplane_sys_route_del(rn, same);

		rib_delnode(rn, same);
	}

	route_unlock_node(rn);

	early_route_memory_free(ere);
}

/*
 * When FRR receives a route we need to match the route up to
 * nexthop groups.  That we also may have just received
 * place the data on this queue so that this work of finding
 * the nexthop group entries for the route entry is always
 * done after the nexthop group has had a chance to be processed
 */
static void process_subq_early_route(struct listnode *lnode)
{
	struct zebra_early_route *ere = listgetdata(lnode);

	if (ere->deletion)
		process_subq_early_route_delete(ere);
	else
		process_subq_early_route_add(ere);
}

struct meta_q_gr_run {
	afi_t afi;
	vrf_id_t vrf_id;
	uint8_t proto;
	uint8_t instance;
	time_t restart_time;
};

static void process_subq_gr_run(struct listnode *lnode)
{
	struct meta_q_gr_run *gr_run = listgetdata(lnode);

	zebra_gr_process_client(gr_run->afi, gr_run->vrf_id, gr_run->proto,
				gr_run->instance, gr_run->restart_time);

	XFREE(MTYPE_WQ_WRAPPER, gr_run);
}

/*
 * Examine the specified subqueue; process one entry and return 1 if
 * there is a node, return 0 otherwise.
 */
static unsigned int process_subq(struct list *subq,
				 enum meta_queue_indexes qindex)
{
	struct listnode *lnode = listhead(subq);

	if (!lnode)
		return 0;

	switch (qindex) {
	case META_QUEUE_EVPN:
		process_subq_evpn(lnode);
		break;
	case META_QUEUE_NHG:
		process_subq_nhg(lnode);
		break;
	case META_QUEUE_EARLY_ROUTE:
		process_subq_early_route(lnode);
		break;
	case META_QUEUE_EARLY_LABEL:
		process_subq_early_label(lnode);
		break;
	case META_QUEUE_CONNECTED:
	case META_QUEUE_KERNEL:
	case META_QUEUE_STATIC:
	case META_QUEUE_NOTBGP:
	case META_QUEUE_BGP:
	case META_QUEUE_OTHER:
		process_subq_route(lnode, qindex);
		break;
	case META_QUEUE_GR_RUN:
		process_subq_gr_run(lnode);
		break;
	}

	list_delete_node(subq, lnode);

	return 1;
}

/* Dispatch the meta queue by picking and processing the next node from
 * a non-empty sub-queue with lowest priority. wq is equal to zebra->ribq and
 * data is pointed to the meta queue structure.
 */
static wq_item_status meta_queue_process(struct work_queue *dummy, void *data)
{
	struct meta_queue *mq = data;
	unsigned i;
	uint32_t queue_len, queue_limit;

	/* Ensure there's room for more dataplane updates */
	queue_limit = dplane_get_in_queue_limit();
	queue_len = dplane_get_in_queue_len();
	if (queue_len > queue_limit) {
		if (IS_ZEBRA_DEBUG_RIB_DETAILED)
			zlog_debug(
				"rib queue: dplane queue len %u, limit %u, retrying",
				queue_len, queue_limit);

		/* Ensure that the meta-queue is actually enqueued */
		if (work_queue_empty(zrouter.ribq))
			work_queue_add(zrouter.ribq, zrouter.mq);

		return WQ_QUEUE_BLOCKED;
	}

	for (i = 0; i < MQ_SIZE; i++)
		if (process_subq(mq->subq[i], i)) {
			mq->size--;
			break;
		}
	return mq->size ? WQ_REQUEUE : WQ_SUCCESS;
}


/*
 * Look into the RN and queue it into the highest priority queue
 * at this point in time for processing.
 *
 * We will enqueue a route node only once per invocation.
 *
 * There are two possibilities here that should be kept in mind.
 * If the original invocation has not been pulled off for processing
 * yet, A subsuquent invocation can have a route entry with a better
 * meta queue index value and we can have a situation where
 * we might have the same node enqueued 2 times.  Not necessarily
 * an optimal situation but it should be ok.
 *
 * The other possibility is that the original invocation has not
 * been pulled off for processing yet, A subsusquent invocation
 * doesn't have a route_entry with a better meta-queue and the
 * original metaqueue index value will win and we'll end up with
 * the route node enqueued once.
 */
static int rib_meta_queue_add(struct meta_queue *mq, void *data)
{
	struct route_node *rn = NULL;
	struct route_entry *re = NULL, *curr_re = NULL;
	uint8_t qindex = MQ_SIZE, curr_qindex = MQ_SIZE;

	rn = (struct route_node *)data;

	RNODE_FOREACH_RE (rn, curr_re) {
		curr_qindex = route_info[curr_re->type].meta_q_map;

		if (curr_qindex <= qindex) {
			re = curr_re;
			qindex = curr_qindex;
		}
	}

	if (!re)
		return -1;

	/* Invariant: at this point we always have rn->info set. */
	/* A route node must only be in one sub-queue at a time. */
	if (CHECK_FLAG(rib_dest_from_rnode(rn)->flags, MQ_BIT_MASK)) {
		if (IS_ZEBRA_DEBUG_RIB_DETAILED) {
			/*
			 * curr_qindex_bitmask is power of 2, because a route node must only be in one sub-queue at a time,
			 * so for getting current sub-queue index from bitmask we may use part of classic msb function
			 * (find most significant set bit).
			 */
			const uint32_t curr_qindex_bitmask = CHECK_FLAG(rib_dest_from_rnode(rn)->flags, MQ_BIT_MASK);
			static const uint8_t pos[32] = { 0, 1, 28, 2, 29, 14, 24, 3,
				30, 22, 20, 15, 25, 17, 4, 8, 31, 27, 13, 23, 21, 19,
				16, 7, 26, 12, 18, 6, 11, 5, 10, 9 };

			curr_qindex = pos[(uint32_t)(curr_qindex_bitmask * 0x077CB531UL) >> 27];

			rnode_debug(rn, re->vrf_id,
				    "rn %p is already queued in sub-queue %s",
				    (void *)rn, subqueue2str(curr_qindex));
		}

		return -1;
	}

	SET_FLAG(rib_dest_from_rnode(rn)->flags, RIB_ROUTE_QUEUED(qindex));
	listnode_add(mq->subq[qindex], rn);
	route_lock_node(rn);
	mq->size++;

	if (IS_ZEBRA_DEBUG_RIB_DETAILED)
		rnode_debug(rn, re->vrf_id, "queued rn %p into sub-queue %s",
			    (void *)rn, subqueue2str(qindex));

	return 0;
}

static int early_label_meta_queue_add(struct meta_queue *mq, void *data)
{
	listnode_add(mq->subq[META_QUEUE_EARLY_LABEL], data);
	mq->size++;
	return 0;
}

static int rib_meta_queue_nhg_ctx_add(struct meta_queue *mq, void *data)
{
	struct nhg_ctx *ctx = NULL;
	uint8_t qindex = META_QUEUE_NHG;
	struct wq_nhg_wrapper *w;

	ctx = (struct nhg_ctx *)data;

	if (!ctx)
		return -1;

	w = XCALLOC(MTYPE_WQ_WRAPPER, sizeof(struct wq_nhg_wrapper));

	w->type = WQ_NHG_WRAPPER_TYPE_CTX;
	w->u.ctx = ctx;

	listnode_add(mq->subq[qindex], w);
	mq->size++;

	if (IS_ZEBRA_DEBUG_RIB_DETAILED)
		zlog_debug("NHG Context id=%u queued into sub-queue %s",
			   ctx->id, subqueue2str(qindex));

	return 0;
}

static int rib_meta_queue_nhg_process(struct meta_queue *mq, void *data,
				      bool deletion)
{
	struct nhg_hash_entry *nhe = NULL;
	uint8_t qindex = META_QUEUE_NHG;
	struct wq_nhg_wrapper *w;

	nhe = (struct nhg_hash_entry *)data;

	if (!nhe)
		return -1;

	w = XCALLOC(MTYPE_WQ_WRAPPER, sizeof(struct wq_nhg_wrapper));

	w->type = WQ_NHG_WRAPPER_TYPE_NHG;
	w->u.nhe = nhe;
	w->deletion = deletion;

	listnode_add(mq->subq[qindex], w);
	mq->size++;

	if (IS_ZEBRA_DEBUG_RIB_DETAILED)
		zlog_debug("NHG id=%u queued into sub-queue %s", nhe->id,
			   subqueue2str(qindex));

	return 0;
}

static int rib_meta_queue_nhg_add(struct meta_queue *mq, void *data)
{
	return rib_meta_queue_nhg_process(mq, data, false);
}

static int rib_meta_queue_nhg_del(struct meta_queue *mq, void *data)
{
	return rib_meta_queue_nhg_process(mq, data, true);
}

static int rib_meta_queue_evpn_add(struct meta_queue *mq, void *data)
{
	listnode_add(mq->subq[META_QUEUE_EVPN], data);
	mq->size++;

	return 0;
}

static int mq_add_handler(void *data,
			  int (*mq_add_func)(struct meta_queue *mq, void *data))
{
	if (zrouter.ribq == NULL) {
		flog_err(EC_ZEBRA_WQ_NONEXISTENT,
			 "%s: work_queue does not exist!", __func__);
		return -1;
	}

	/*
	 * The RIB queue should normally be either empty or holding the only
	 * work_queue_item element. In the latter case this element would
	 * hold a pointer to the meta queue structure, which must be used to
	 * actually queue the route nodes to process. So create the MQ
	 * holder, if necessary, then push the work into it in any case.
	 * This semantics was introduced after 0.99.9 release.
	 */
	if (work_queue_empty(zrouter.ribq))
		work_queue_add(zrouter.ribq, zrouter.mq);

	return mq_add_func(zrouter.mq, data);
}

void mpls_ftn_uninstall(struct zebra_vrf *zvrf, enum lsp_types_t type,
			struct prefix *prefix, uint8_t route_type,
			uint8_t route_instance)
{
	struct wq_label_wrapper *w;

	w = XCALLOC(MTYPE_WQ_WRAPPER, sizeof(struct wq_label_wrapper));

	w->type = WQ_LABEL_FTN_UNINSTALL;
	w->vrf_id = zvrf->vrf->vrf_id;
	w->p = *prefix;
	w->ltype = type;
	w->route_type = route_type;
	w->route_instance = route_instance;

	if (IS_ZEBRA_DEBUG_RIB_DETAILED)
		zlog_debug("Early Label Handling for %pFX", prefix);

	mq_add_handler(w, early_label_meta_queue_add);
}

void mpls_zapi_labels_process(bool add_p, struct zebra_vrf *zvrf,
			      const struct zapi_labels *zl)
{
	struct wq_label_wrapper *w;

	w = XCALLOC(MTYPE_WQ_WRAPPER, sizeof(struct wq_label_wrapper));
	w->type = WQ_LABEL_LABELS_PROCESS;
	w->vrf_id = zvrf->vrf->vrf_id;
	w->add_p = add_p;
	w->zl = *zl;

	if (IS_ZEBRA_DEBUG_RIB_DETAILED)
		zlog_debug("Early Label Handling: Labels Process");

	mq_add_handler(w, early_label_meta_queue_add);
}

/* Add route_node to work queue and schedule processing */
int rib_queue_add(struct route_node *rn)
{
	assert(rn);

	/* Pointless to queue a route_node with no RIB entries to add or remove
	 */
	if (!rnode_to_ribs(rn)) {
		zlog_debug("%s: called for route_node (%p, %u) with no ribs",
			   __func__, (void *)rn, route_node_get_lock_count(rn));
		zlog_backtrace(LOG_DEBUG);
		return -1;
	}

	return mq_add_handler(rn, rib_meta_queue_add);
}

/*
 * Enqueue incoming nhg info from OS for processing
 */
int rib_queue_nhg_ctx_add(struct nhg_ctx *ctx)
{
	assert(ctx);

	return mq_add_handler(ctx, rib_meta_queue_nhg_ctx_add);
}

/*
 * Enqueue incoming nhg from proto daemon for processing
 */
int rib_queue_nhe_add(struct nhg_hash_entry *nhe)
{
	if (nhe == NULL)
		return -1;

	return mq_add_handler(nhe, rib_meta_queue_nhg_add);
}

/*
 * Enqueue incoming nhg from proto daemon for processing
 */
int rib_queue_nhe_del(struct nhg_hash_entry *nhe)
{
	if (nhe == NULL)
		return -1;

	return mq_add_handler(nhe, rib_meta_queue_nhg_del);
}

/*
 * Enqueue evpn route for processing
 */
int zebra_rib_queue_evpn_route_add(vrf_id_t vrf_id, const struct ethaddr *rmac,
				   const struct ipaddr *vtep_ip,
				   const struct prefix *host_prefix)
{
	struct wq_evpn_wrapper *w;

	w = XCALLOC(MTYPE_WQ_WRAPPER, sizeof(struct wq_evpn_wrapper));

	w->type = WQ_EVPN_WRAPPER_TYPE_VRFROUTE;
	w->add_p = true;
	w->vrf_id = vrf_id;
	w->macaddr = *rmac;
	w->ip = *vtep_ip;
	w->prefix = *host_prefix;

	if (IS_ZEBRA_DEBUG_RIB_DETAILED)
		zlog_debug("%s: (%u)%pIA, host prefix %pFX enqueued", __func__,
			   vrf_id, vtep_ip, host_prefix);

	return mq_add_handler(w, rib_meta_queue_evpn_add);
}

int zebra_rib_queue_evpn_route_del(vrf_id_t vrf_id,
				   const struct ipaddr *vtep_ip,
				   const struct prefix *host_prefix)
{
	struct wq_evpn_wrapper *w;

	w = XCALLOC(MTYPE_WQ_WRAPPER, sizeof(struct wq_evpn_wrapper));

	w->type = WQ_EVPN_WRAPPER_TYPE_VRFROUTE;
	w->add_p = false;
	w->vrf_id = vrf_id;
	w->ip = *vtep_ip;
	w->prefix = *host_prefix;

	if (IS_ZEBRA_DEBUG_RIB_DETAILED)
		zlog_debug("%s: (%u)%pIA, host prefix %pFX enqueued", __func__,
			   vrf_id, vtep_ip, host_prefix);

	return mq_add_handler(w, rib_meta_queue_evpn_add);
}

/* Enqueue EVPN remote ES for processing */
int zebra_rib_queue_evpn_rem_es_add(const esi_t *esi,
				    const struct in_addr *vtep_ip,
				    bool esr_rxed, uint8_t df_alg,
				    uint16_t df_pref)
{
	struct wq_evpn_wrapper *w;
	char buf[ESI_STR_LEN];

	w = XCALLOC(MTYPE_WQ_WRAPPER, sizeof(struct wq_evpn_wrapper));

	w->type = WQ_EVPN_WRAPPER_TYPE_REM_ES;
	w->add_p = true;
	w->esi = *esi;
	w->ip.ipa_type = IPADDR_V4;
	w->ip.ipaddr_v4 = *vtep_ip;
	w->esr_rxed = esr_rxed;
	w->df_alg = df_alg;
	w->df_pref = df_pref;

	if (IS_ZEBRA_DEBUG_RIB_DETAILED)
		zlog_debug("%s: vtep %pI4, esi %s enqueued", __func__, vtep_ip,
			   esi_to_str(esi, buf, sizeof(buf)));

	return mq_add_handler(w, rib_meta_queue_evpn_add);
}

int zebra_rib_queue_evpn_rem_es_del(const esi_t *esi,
				    const struct in_addr *vtep_ip)
{
	struct wq_evpn_wrapper *w;
	char buf[ESI_STR_LEN];

	w = XCALLOC(MTYPE_WQ_WRAPPER, sizeof(struct wq_evpn_wrapper));

	w->type = WQ_EVPN_WRAPPER_TYPE_REM_ES;
	w->add_p = false;
	w->esi = *esi;
	w->ip.ipa_type = IPADDR_V4;
	w->ip.ipaddr_v4 = *vtep_ip;

	if (IS_ZEBRA_DEBUG_RIB_DETAILED) {
		if (memcmp(esi, zero_esi, sizeof(esi_t)) != 0)
			esi_to_str(esi, buf, sizeof(buf));
		else
			strlcpy(buf, "-", sizeof(buf));

		zlog_debug("%s: vtep %pI4, esi %s enqueued", __func__, vtep_ip,
			   buf);
	}

	return mq_add_handler(w, rib_meta_queue_evpn_add);
}

/*
 * Enqueue EVPN remote macip update for processing
 */
int zebra_rib_queue_evpn_rem_macip_add(vni_t vni, const struct ethaddr *macaddr,
				       const struct ipaddr *ipaddr,
				       uint8_t flags, uint32_t seq,
				       struct in_addr vtep_ip, const esi_t *esi)
{
	struct wq_evpn_wrapper *w;
	char buf[ESI_STR_LEN];

	w = XCALLOC(MTYPE_WQ_WRAPPER, sizeof(struct wq_evpn_wrapper));

	w->type = WQ_EVPN_WRAPPER_TYPE_REM_MACIP;
	w->add_p = true;
	w->vni = vni;
	w->macaddr = *macaddr;
	w->ip = *ipaddr;
	w->flags = flags;
	w->seq = seq;
	w->vtep_ip = vtep_ip;
	w->esi = *esi;

	if (IS_ZEBRA_DEBUG_RIB_DETAILED) {
		if (memcmp(esi, zero_esi, sizeof(esi_t)) != 0)
			esi_to_str(esi, buf, sizeof(buf));
		else
			strlcpy(buf, "-", sizeof(buf));

		zlog_debug("%s: mac %pEA, vtep %pI4, esi %s enqueued", __func__,
			   macaddr, &vtep_ip, buf);
	}

	return mq_add_handler(w, rib_meta_queue_evpn_add);
}

int zebra_rib_queue_evpn_rem_macip_del(vni_t vni, const struct ethaddr *macaddr,
				       const struct ipaddr *ip,
				       struct in_addr vtep_ip)
{
	struct wq_evpn_wrapper *w;

	w = XCALLOC(MTYPE_WQ_WRAPPER, sizeof(struct wq_evpn_wrapper));

	w->type = WQ_EVPN_WRAPPER_TYPE_REM_MACIP;
	w->add_p = false;
	w->vni = vni;
	w->macaddr = *macaddr;
	w->ip = *ip;
	w->vtep_ip = vtep_ip;

	if (IS_ZEBRA_DEBUG_RIB_DETAILED)
		zlog_debug("%s: mac %pEA, vtep %pI4 enqueued", __func__,
			   macaddr, &vtep_ip);

	return mq_add_handler(w, rib_meta_queue_evpn_add);
}

/*
 * Enqueue remote VTEP address for processing
 */
int zebra_rib_queue_evpn_rem_vtep_add(vrf_id_t vrf_id, vni_t vni,
				      struct in_addr vtep_ip, int flood_control)
{
	struct wq_evpn_wrapper *w;

	w = XCALLOC(MTYPE_WQ_WRAPPER, sizeof(struct wq_evpn_wrapper));

	w->type = WQ_EVPN_WRAPPER_TYPE_REM_VTEP;
	w->add_p = true;
	w->vrf_id = vrf_id;
	w->vni = vni;
	w->vtep_ip = vtep_ip;
	w->flags = flood_control;

	if (IS_ZEBRA_DEBUG_RIB_DETAILED)
		zlog_debug("%s: vrf %u, vtep %pI4 enqueued", __func__, vrf_id,
			   &vtep_ip);

	return mq_add_handler(w, rib_meta_queue_evpn_add);
}

int zebra_rib_queue_evpn_rem_vtep_del(vrf_id_t vrf_id, vni_t vni,
				      struct in_addr vtep_ip)
{
	struct wq_evpn_wrapper *w;

	w = XCALLOC(MTYPE_WQ_WRAPPER, sizeof(struct wq_evpn_wrapper));

	w->type = WQ_EVPN_WRAPPER_TYPE_REM_VTEP;
	w->add_p = false;
	w->vrf_id = vrf_id;
	w->vni = vni;
	w->vtep_ip = vtep_ip;

	if (IS_ZEBRA_DEBUG_RIB_DETAILED)
		zlog_debug("%s: vrf %u, vtep %pI4 enqueued", __func__, vrf_id,
			   &vtep_ip);

	return mq_add_handler(w, rib_meta_queue_evpn_add);
}

/* Create new meta queue.
   A destructor function doesn't seem to be necessary here.
 */
static struct meta_queue *meta_queue_new(void)
{
	struct meta_queue *new;
	unsigned i;

	new = XCALLOC(MTYPE_WORK_QUEUE, sizeof(struct meta_queue));

	for (i = 0; i < MQ_SIZE; i++) {
		new->subq[i] = list_new();
		assert(new->subq[i]);
	}

	return new;
}

/* Clean up the EVPN meta-queue list */
static void evpn_meta_queue_free(struct meta_queue *mq, struct list *l,
				 struct zebra_vrf *zvrf)
{
	struct listnode *node, *nnode;
	struct wq_evpn_wrapper *w;

	/* Free the node wrapper object, and the struct it wraps */
	for (ALL_LIST_ELEMENTS(l, node, nnode, w)) {
		if (zvrf) {
			vrf_id_t vrf_id = zvrf->vrf->vrf_id;

			if (w->vrf_id != vrf_id)
				continue;
		}

		node->data = NULL;

		XFREE(MTYPE_WQ_WRAPPER, w);

		list_delete_node(l, node);
		mq->size--;
	}
}

/* Clean up the nhg meta-queue list */
static void nhg_meta_queue_free(struct meta_queue *mq, struct list *l,
				struct zebra_vrf *zvrf)
{
	struct wq_nhg_wrapper *w;
	struct listnode *node, *nnode;

	/* Free the node wrapper object, and the struct it wraps */
	for (ALL_LIST_ELEMENTS(l, node, nnode, w)) {
		if (zvrf) {
			vrf_id_t vrf_id = zvrf->vrf->vrf_id;

			if (w->type == WQ_NHG_WRAPPER_TYPE_CTX &&
			    w->u.ctx->vrf_id != vrf_id)
				continue;
			else if (w->type == WQ_NHG_WRAPPER_TYPE_NHG &&
				 w->u.nhe->vrf_id != vrf_id)
				continue;
		}
		if (w->type == WQ_NHG_WRAPPER_TYPE_CTX)
			nhg_ctx_free(&w->u.ctx);
		else if (w->type == WQ_NHG_WRAPPER_TYPE_NHG)
			zebra_nhg_free(w->u.nhe);

		node->data = NULL;
		XFREE(MTYPE_WQ_WRAPPER, w);

		list_delete_node(l, node);
		mq->size--;
	}
}

static void early_label_meta_queue_free(struct meta_queue *mq, struct list *l,
					struct zebra_vrf *zvrf)
{
	struct wq_label_wrapper *w;
	struct listnode *node, *nnode;

	for (ALL_LIST_ELEMENTS(l, node, nnode, w)) {
		if (zvrf && zvrf->vrf->vrf_id != w->vrf_id)
			continue;

		switch (w->type) {
		case WQ_LABEL_FTN_UNINSTALL:
		case WQ_LABEL_LABELS_PROCESS:
			break;
		}

		node->data = NULL;
		XFREE(MTYPE_WQ_WRAPPER, w);
		list_delete_node(l, node);
		mq->size--;
	}
}

static void rib_meta_queue_free(struct meta_queue *mq, struct list *l,
				struct zebra_vrf *zvrf)
{
	struct route_node *rnode;
	struct listnode *node, *nnode;

	for (ALL_LIST_ELEMENTS(l, node, nnode, rnode)) {
		rib_dest_t *dest = rib_dest_from_rnode(rnode);

		if (dest && rib_dest_vrf(dest) != zvrf)
			continue;

		route_unlock_node(rnode);
		node->data = NULL;
		list_delete_node(l, node);
		mq->size--;
	}
}

static void early_route_meta_queue_free(struct meta_queue *mq, struct list *l,
					const struct zebra_vrf *zvrf,
					uint8_t proto, uint8_t instance)
{
	struct zebra_early_route *ere;
	struct listnode *node, *nnode;

	for (ALL_LIST_ELEMENTS(l, node, nnode, ere)) {
		if (zvrf && ere->re->vrf_id != zvrf->vrf->vrf_id)
			continue;

		if (proto != ZEBRA_ROUTE_ALL &&
		    (proto != ere->re->type && instance != ere->re->instance))
			continue;

		early_route_memory_free(ere);
		node->data = NULL;
		list_delete_node(l, node);
		mq->size--;
	}
}

static void rib_meta_queue_gr_run_free(struct meta_queue *mq, struct list *l,
				       struct zebra_vrf *zvrf)
{
	struct meta_q_gr_run *gr_run;
	struct listnode *node, *nnode;

	for (ALL_LIST_ELEMENTS(l, node, nnode, gr_run)) {
		if (zvrf && zvrf->vrf->vrf_id != gr_run->vrf_id)
			continue;

		XFREE(MTYPE_WQ_WRAPPER, gr_run);
		node->data = NULL;
		list_delete_node(l, node);
		mq->size--;
	}
}

void meta_queue_free(struct meta_queue *mq, struct zebra_vrf *zvrf)
{
	enum meta_queue_indexes i;

	for (i = 0; i < MQ_SIZE; i++) {
		/* Some subqueues may need cleanup - nhgs for example */
		switch (i) {
		case META_QUEUE_NHG:
			nhg_meta_queue_free(mq, mq->subq[i], zvrf);
			break;
		case META_QUEUE_EVPN:
			evpn_meta_queue_free(mq, mq->subq[i], zvrf);
			break;
		case META_QUEUE_EARLY_ROUTE:
			early_route_meta_queue_free(mq, mq->subq[i], zvrf,
						    ZEBRA_ROUTE_ALL, 0);
			break;
		case META_QUEUE_EARLY_LABEL:
			early_label_meta_queue_free(mq, mq->subq[i], zvrf);
			break;
		case META_QUEUE_CONNECTED:
		case META_QUEUE_KERNEL:
		case META_QUEUE_STATIC:
		case META_QUEUE_NOTBGP:
		case META_QUEUE_BGP:
		case META_QUEUE_OTHER:
			rib_meta_queue_free(mq, mq->subq[i], zvrf);
			break;
		case META_QUEUE_GR_RUN:
			rib_meta_queue_gr_run_free(mq, mq->subq[i], zvrf);
			break;
		}
		if (!zvrf)
			list_delete(&mq->subq[i]);
	}

	if (!zvrf)
		XFREE(MTYPE_WORK_QUEUE, mq);
}

/* initialise zebra rib work queue */
static void rib_queue_init(void)
{
	if (!(zrouter.ribq = work_queue_new(zrouter.master,
					    "route_node processing"))) {
		flog_err(EC_ZEBRA_WQ_NONEXISTENT,
			 "%s: could not initialise work queue!", __func__);
		return;
	}

	/* fill in the work queue spec */
	zrouter.ribq->spec.workfunc = &meta_queue_process;
	zrouter.ribq->spec.completion_func = NULL;
	/* XXX: TODO: These should be runtime configurable via vty */
	zrouter.ribq->spec.max_retries = 3;
	zrouter.ribq->spec.hold = ZEBRA_RIB_PROCESS_HOLD_TIME;
	zrouter.ribq->spec.retry = ZEBRA_RIB_PROCESS_RETRY_TIME;

	if (!(zrouter.mq = meta_queue_new())) {
		flog_err(EC_ZEBRA_WQ_NONEXISTENT,
			 "%s: could not initialise meta queue!", __func__);
		return;
	}
	return;
}

rib_dest_t *zebra_rib_create_dest(struct route_node *rn)
{
	rib_dest_t *dest;

	dest = XCALLOC(MTYPE_RIB_DEST, sizeof(rib_dest_t));
	rnh_list_init(&dest->nht);
	re_list_init(&dest->routes);
	route_lock_node(rn); /* rn route table reference */
	rn->info = dest;
	dest->rnode = rn;

	return dest;
}

/* RIB updates are processed via a queue of pointers to route_nodes.
 *
 * The queue length is bounded by the maximal size of the routing table,
 * as a route_node will not be requeued, if already queued.
 *
 * REs are submitted via rib_addnode or rib_delnode which set minimal
 * state, or static_install_route (when an existing RE is updated)
 * and then submit route_node to queue for best-path selection later.
 * Order of add/delete state changes are preserved for any given RE.
 *
 * Deleted REs are reaped during best-path selection.
 *
 * rib_addnode
 * |-> rib_link or unset ROUTE_ENTRY_REMOVE      |->Update kernel with
 *       |-------->|                             |  best RE, if required
 *                 |                             |
 * static_install->|->rib_addqueue...... -> rib_process
 *                 |                             |
 *       |-------->|                             |-> rib_unlink
 *       |-> set ROUTE_ENTRY_REMOVE              |
 * rib_delnode                                  (RE freed)
 *
 * The 'info' pointer of a route_node points to a rib_dest_t
 * ('dest'). Queueing state for a route_node is kept on the dest. The
 * dest is created on-demand by rib_link() and is kept around at least
 * as long as there are ribs hanging off it (@see rib_gc_dest()).
 *
 * Refcounting (aka "locking" throughout the Zebra and FRR code):
 *
 * - route_nodes: refcounted by:
 *   - dest attached to route_node:
 *     - managed by: rib_link/rib_gc_dest
 *   - route_node processing queue
 *     - managed by: rib_addqueue, rib_process.
 *
 */

/* Add RE to head of the route node. */
static void rib_link(struct route_node *rn, struct route_entry *re, int process)
{
	rib_dest_t *dest;
	afi_t afi;
	const char *rmap_name;

	assert(re && rn);

	dest = rib_dest_from_rnode(rn);
	if (!dest) {
		if (IS_ZEBRA_DEBUG_RIB_DETAILED)
			rnode_debug(rn, re->vrf_id, "rn %p adding dest", rn);

		dest = zebra_rib_create_dest(rn);
	}

	re_list_add_head(&dest->routes, re);

	afi = (rn->p.family == AF_INET)
		      ? AFI_IP
		      : (rn->p.family == AF_INET6) ? AFI_IP6 : AFI_MAX;
	if (is_zebra_import_table_enabled(afi, re->vrf_id, re->table)) {
		struct zebra_vrf *zvrf = zebra_vrf_lookup_by_id(re->vrf_id);

		rmap_name = zebra_get_import_table_route_map(afi, re->table);
		zebra_add_import_table_entry(zvrf, rn, re, rmap_name);
	}

	if (process)
		rib_queue_add(rn);
}

static void rib_addnode(struct route_node *rn,
			struct route_entry *re, int process)
{
	/* RE node has been un-removed before route-node is processed.
	 * route_node must hence already be on the queue for processing..
	 */
	if (CHECK_FLAG(re->status, ROUTE_ENTRY_REMOVED)) {
		if (IS_ZEBRA_DEBUG_RIB)
			rnode_debug(rn, re->vrf_id, "rn %p, un-removed re %p",
				    (void *)rn, (void *)re);

		UNSET_FLAG(re->status, ROUTE_ENTRY_REMOVED);
		return;
	}
	rib_link(rn, re, process);
}

/*
 * rib_unlink
 *
 * Detach a rib structure from a route_node.
 *
 * Note that a call to rib_unlink() should be followed by a call to
 * rib_gc_dest() at some point. This allows a rib_dest_t that is no
 * longer required to be deleted.
 */
void rib_unlink(struct route_node *rn, struct route_entry *re)
{
	rib_dest_t *dest;

	assert(rn && re);

	if (IS_ZEBRA_DEBUG_RIB)
		rnode_debug(rn, re->vrf_id, "rn %p, re %p", (void *)rn,
			    (void *)re);

	dest = rib_dest_from_rnode(rn);

	re_list_del(&dest->routes, re);

	if (dest->selected_fib == re)
		dest->selected_fib = NULL;

	rib_re_nhg_free(re);

	zebra_rib_route_entry_free(re);
}

void rib_delnode(struct route_node *rn, struct route_entry *re)
{
	afi_t afi;

	if (IS_ZEBRA_DEBUG_RIB)
		rnode_debug(rn, re->vrf_id, "rn %p, re %p, removing",
			    (void *)rn, (void *)re);

	if (IS_ZEBRA_DEBUG_RIB_DETAILED)
		route_entry_dump(&rn->p, NULL, re);

	SET_FLAG(re->status, ROUTE_ENTRY_REMOVED);

	afi = (rn->p.family == AF_INET)
		      ? AFI_IP
		      : (rn->p.family == AF_INET6) ? AFI_IP6 : AFI_MAX;
	if (is_zebra_import_table_enabled(afi, re->vrf_id, re->table)) {
		struct zebra_vrf *zvrf = zebra_vrf_lookup_by_id(re->vrf_id);

		zebra_del_import_table_entry(zvrf, rn, re);
		/* Just clean up if non main table */
		if (IS_ZEBRA_DEBUG_RIB)
			zlog_debug("%s(%u):%pRN: Freeing route rn %p, re %p (%s)",
				   vrf_id_to_name(re->vrf_id), re->vrf_id, rn,
				   rn, re, zebra_route_string(re->type));
	}

	rib_queue_add(rn);
}

/*
 * Helper that debugs a single nexthop within a route-entry
 */
void route_entry_dump_nh(const struct route_entry *re, const char *straddr,
			 const struct vrf *re_vrf, const struct nexthop *nexthop)
{
	char nhname[PREFIX_STRLEN];
	char backup_str[50];
	char wgt_str[50];
	char temp_str[10];
	char label_str[MPLS_LABEL_STRLEN];
	int i;
	struct interface *ifp;
	struct vrf *vrf = vrf_lookup_by_id(nexthop->vrf_id);

	switch (nexthop->type) {
	case NEXTHOP_TYPE_BLACKHOLE:
		snprintf(nhname, sizeof(nhname), "Blackhole");
		break;
	case NEXTHOP_TYPE_IFINDEX:
		ifp = if_lookup_by_index(nexthop->ifindex, nexthop->vrf_id);
		snprintf(nhname, sizeof(nhname), "%s",
			 ifp ? ifp->name : "Unknown");
		break;
	case NEXTHOP_TYPE_IPV4:
	case NEXTHOP_TYPE_IPV4_IFINDEX:
		inet_ntop(AF_INET, &nexthop->gate, nhname, INET6_ADDRSTRLEN);
		break;
	case NEXTHOP_TYPE_IPV6:
	case NEXTHOP_TYPE_IPV6_IFINDEX:
		inet_ntop(AF_INET6, &nexthop->gate, nhname, INET6_ADDRSTRLEN);
		break;
	}

	/* Label stack */
	label_str[0] = '\0';
	if (nexthop->nh_label && nexthop->nh_label->num_labels > 0) {
		mpls_label2str(nexthop->nh_label->num_labels,
			       nexthop->nh_label->label, label_str,
			       sizeof(label_str), nexthop->nh_label_type,
			       0 /*pretty*/);
		strlcat(label_str, ", ", sizeof(label_str));
	}

	backup_str[0] = '\0';
	if (CHECK_FLAG(nexthop->flags, NEXTHOP_FLAG_HAS_BACKUP)) {
		snprintf(backup_str, sizeof(backup_str), "backup ");
		for (i = 0; i < nexthop->backup_num; i++) {
			snprintf(temp_str, sizeof(temp_str), "%d, ",
				 nexthop->backup_idx[i]);
			strlcat(backup_str, temp_str, sizeof(backup_str));
		}
	}

	wgt_str[0] = '\0';
	if (nexthop->weight)
		snprintf(wgt_str, sizeof(wgt_str), "wgt %d,", nexthop->weight);

	zlog_debug("%s(%s): %s %s[%u] %svrf %s(%u) %s%s with flags %s%s%s%s%s%s%s%s%s",
		   straddr, VRF_LOGNAME(re_vrf),
		   (nexthop->rparent ? "  NH" : "NH"), nhname, nexthop->ifindex,
		   label_str, vrf ? vrf->name : "Unknown", nexthop->vrf_id,
		   wgt_str, backup_str,
		   (CHECK_FLAG(nexthop->flags, NEXTHOP_FLAG_ACTIVE) ? "ACTIVE "
								    : ""),
		   (CHECK_FLAG(re->status, ROUTE_ENTRY_INSTALLED) ? "FIB " : ""),
		   (CHECK_FLAG(nexthop->flags, NEXTHOP_FLAG_RECURSIVE)
			    ? "RECURSIVE "
			    : ""),
		   (CHECK_FLAG(nexthop->flags, NEXTHOP_FLAG_ONLINK) ? "ONLINK "
								    : ""),
		   (CHECK_FLAG(nexthop->flags, NEXTHOP_FLAG_DUPLICATE)
			    ? "DUPLICATE "
			    : ""),
		   (CHECK_FLAG(nexthop->flags, NEXTHOP_FLAG_RNH_FILTERED)
			    ? "FILTERED "
			    : ""),
		   (CHECK_FLAG(nexthop->flags, NEXTHOP_FLAG_HAS_BACKUP)
			    ? "BACKUP "
			    : ""),
		   (CHECK_FLAG(nexthop->flags, NEXTHOP_FLAG_SRTE) ? "SRTE "
								  : ""),
		   (CHECK_FLAG(nexthop->flags, NEXTHOP_FLAG_EVPN) ? "EVPN "
								  : ""));
}

/* This function dumps the contents of a given RE entry into
 * standard debug log. Calling function name and IP prefix in
 * question are passed as 1st and 2nd arguments.
 */
void _route_entry_dump(const char *func, union prefixconstptr pp,
		       union prefixconstptr src_pp,
		       const struct route_entry *re)
{
	const struct prefix *src_p = src_pp.p;
	bool is_srcdst = src_p && src_p->prefixlen;
	char straddr[PREFIX_STRLEN];
	char srcaddr[PREFIX_STRLEN];
	char flags_buf[128];
	char status_buf[128];
	struct nexthop *nexthop;
	struct vrf *vrf = vrf_lookup_by_id(re->vrf_id);
	struct nexthop_group *nhg;

	prefix2str(pp, straddr, sizeof(straddr));

	zlog_debug("%s: dumping RE entry %p for %s%s%s vrf %s(%u)", func,
		   (const void *)re, straddr,
		   is_srcdst ? " from " : "",
		   is_srcdst ? prefix2str(src_pp, srcaddr, sizeof(srcaddr))
			     : "",
		   VRF_LOGNAME(vrf), re->vrf_id);
	zlog_debug("%s(%s): uptime == %lu, type == %u, instance == %d, table == %d",
		   straddr, VRF_LOGNAME(vrf), (unsigned long)re->uptime,
		   re->type, re->instance, re->table);
	zlog_debug("%s(%s): metric == %u, mtu == %u, distance == %u, flags == %sstatus == %s",
		   straddr, VRF_LOGNAME(vrf), re->metric, re->mtu, re->distance,
		   zclient_dump_route_flags(re->flags, flags_buf,
					    sizeof(flags_buf)),
		   _dump_re_status(re, status_buf, sizeof(status_buf)));
	zlog_debug("%s(%s): tag == %u, nexthop_num == %u, nexthop_active_num == %u",
		   straddr, VRF_LOGNAME(vrf), re->tag,
		   nexthop_group_nexthop_num(&(re->nhe->nhg)),
		   nexthop_group_active_nexthop_num(&(re->nhe->nhg)));

	/* Dump nexthops */
	for (ALL_NEXTHOPS(re->nhe->nhg, nexthop))
		route_entry_dump_nh(re, straddr, vrf, nexthop);

	if (zebra_nhg_get_backup_nhg(re->nhe)) {
		zlog_debug("%s(%s): backup nexthops:", straddr,
			   VRF_LOGNAME(vrf));

		nhg = zebra_nhg_get_backup_nhg(re->nhe);
		for (ALL_NEXTHOPS_PTR(nhg, nexthop))
			route_entry_dump_nh(re, straddr, vrf, nexthop);
	}

	zlog_debug("%s(%s): dump complete", straddr, VRF_LOGNAME(vrf));
}

static int rib_meta_queue_gr_run_add(struct meta_queue *mq, void *data)
{
	listnode_add(mq->subq[META_QUEUE_GR_RUN], data);
	mq->size++;

	if (IS_ZEBRA_DEBUG_RIB_DETAILED)
		zlog_debug("Graceful Run adding");

	return 0;
}

static int rib_meta_queue_early_route_add(struct meta_queue *mq, void *data)
{
	struct zebra_early_route *ere = data;

	listnode_add(mq->subq[META_QUEUE_EARLY_ROUTE], data);
	mq->size++;

	if (IS_ZEBRA_DEBUG_RIB_DETAILED) {
		struct vrf *vrf = vrf_lookup_by_id(ere->re->vrf_id);

		zlog_debug("Route %pFX(%s) (%s) queued for processing into sub-queue %s",
			   &ere->p, VRF_LOGNAME(vrf),
			   ere->deletion ? "delete" : "add",
			   subqueue2str(META_QUEUE_EARLY_ROUTE));
	}

	return 0;
}

int rib_add_gr_run(afi_t afi, vrf_id_t vrf_id, uint8_t proto, uint8_t instance,
		   time_t restart_time)
{
	struct meta_q_gr_run *gr_run;

	gr_run = XCALLOC(MTYPE_WQ_WRAPPER, sizeof(*gr_run));

	gr_run->afi = afi;
	gr_run->proto = proto;
	gr_run->vrf_id = vrf_id;
	gr_run->instance = instance;
	gr_run->restart_time = restart_time;

	return mq_add_handler(gr_run, rib_meta_queue_gr_run_add);
}

struct route_entry *zebra_rib_route_entry_new(vrf_id_t vrf_id, int type,
					      uint8_t instance, uint32_t flags,
					      uint32_t nhe_id,
					      uint32_t table_id,
					      uint32_t metric, uint32_t mtu,
					      uint8_t distance, route_tag_t tag)
{
	struct route_entry *re;

	re = XCALLOC(MTYPE_RE, sizeof(struct route_entry));
	re->type = type;
	re->instance = instance;
	re->distance = distance;
	re->flags = flags;
	re->metric = metric;
	re->mtu = mtu;
	re->table = table_id;
	re->vrf_id = vrf_id;
	re->uptime = monotime(NULL);
	re->tag = tag;
	re->nhe_id = nhe_id;

	return re;
}

void zebra_rib_route_entry_free(struct route_entry *re)
{
	zapi_re_opaque_free(re);
	XFREE(MTYPE_RE, re);
}

/*
 * Internal route-add implementation; there are a couple of different public
 * signatures. Callers in this path are responsible for the memory they
 * allocate: if they allocate a nexthop_group or backup nexthop info, they
 * must free those objects. If this returns < 0, an error has occurred and the
 * route_entry 're' has not been captured; the caller should free that also.
 *
 * -1 -> error
 *  0 -> Add
 *  1 -> update
 */
int rib_add_multipath_nhe(afi_t afi, safi_t safi, struct prefix *p,
			  struct prefix_ipv6 *src_p, struct route_entry *re,
			  struct nhg_hash_entry *re_nhe, bool startup)
{
	struct zebra_early_route *ere;

	if (!re)
		return -1;

	assert(!src_p || !src_p->prefixlen || afi == AFI_IP6);

	ere = XCALLOC(MTYPE_WQ_WRAPPER, sizeof(*ere));
	ere->afi = afi;
	ere->safi = safi;
	ere->p = *p;
	if (src_p)
		ere->src_p = *src_p;
	ere->src_p_provided = !!src_p;
	ere->re = re;
	ere->re_nhe = re_nhe;
	ere->startup = startup;

	return mq_add_handler(ere, rib_meta_queue_early_route_add);
}

/*
 * Add a single route.
 */
int rib_add_multipath(afi_t afi, safi_t safi, struct prefix *p,
		      struct prefix_ipv6 *src_p, struct route_entry *re,
		      struct nexthop_group *ng, bool startup)
{
	int ret;
	struct nhg_hash_entry nhe, *n;

	if (!re)
		return -1;

	/* We either need nexthop(s) or an existing nexthop id */
	if (ng == NULL && re->nhe_id == 0) {
		zebra_rib_route_entry_free(re);
		return -1;
	}

	/*
	 * Use a temporary nhe to convey info to the common/main api.
	 */
	zebra_nhe_init(&nhe, afi, (ng ? ng->nexthop : NULL));
	if (ng) {
		nhe.nhg.nexthop = ng->nexthop;

		if (re->type == ZEBRA_ROUTE_CONNECT ||
		    re->type == ZEBRA_ROUTE_LOCAL ||
		    re->type == ZEBRA_ROUTE_KERNEL)
			SET_FLAG(nhe.flags, NEXTHOP_GROUP_INITIAL_DELAY_INSTALL);
	} else if (re->nhe_id > 0)
		nhe.id = re->nhe_id;

	n = zebra_nhe_copy(&nhe, 0);

	if (re->type == ZEBRA_ROUTE_KERNEL) {
		struct interface *ifp;
		struct connected *connected;

		if (p->family == AF_INET6 &&
		    IN6_IS_ADDR_LINKLOCAL(&p->u.prefix6)) {
			zebra_nhg_free(n);
			zebra_rib_route_entry_free(re);
			return -1;
		}

		ifp = if_lookup_prefix(p, re->vrf_id);
		if (ifp) {
			connected = connected_lookup_prefix(ifp, p);

			if (connected && !CHECK_FLAG(connected->flags,
						     ZEBRA_IFA_NOPREFIXROUTE)) {
				zebra_nhg_free(n);
				zebra_rib_route_entry_free(re);
				return -1;
			}

			if (ng && ng->nexthop &&
			    ifp->ifindex == ng->nexthop->ifindex)
				re->type = ZEBRA_ROUTE_CONNECT;
		}
	}

	ret = rib_add_multipath_nhe(afi, safi, p, src_p, re, n, startup);

	/* In error cases, free the route also */
	if (ret < 0)
		zebra_rib_route_entry_free(re);

	return ret;
}

void rib_delete(afi_t afi, safi_t safi, vrf_id_t vrf_id, int type,
		unsigned short instance, uint32_t flags, const struct prefix *p,
		const struct prefix_ipv6 *src_p, const struct nexthop *nh,
		uint32_t nhe_id, uint32_t table_id, uint32_t metric,
		uint8_t distance, bool fromkernel)
{
	struct zebra_early_route *ere;
	struct route_entry *re = NULL;
	struct nhg_hash_entry *nhe = NULL;

	re = zebra_rib_route_entry_new(vrf_id, type, instance, flags, nhe_id,
				       table_id, metric, 0, distance, 0);

	if (nh) {
		nhe = zebra_nhg_alloc();
		nhe->nhg.nexthop = nexthop_dup(nh, NULL);
	}

	ere = XCALLOC(MTYPE_WQ_WRAPPER, sizeof(*ere));
	ere->afi = afi;
	ere->safi = safi;
	ere->p = *p;
	if (src_p)
		ere->src_p = *src_p;
	ere->src_p_provided = !!src_p;
	ere->re = re;
	ere->re_nhe = nhe;
	ere->startup = false;
	ere->deletion = true;
	ere->fromkernel = fromkernel;

	mq_add_handler(ere, rib_meta_queue_early_route_add);
}


int rib_add(afi_t afi, safi_t safi, vrf_id_t vrf_id, int type,
	    unsigned short instance, uint32_t flags, struct prefix *p,
	    struct prefix_ipv6 *src_p, const struct nexthop *nh,
	    uint32_t nhe_id, uint32_t table_id, uint32_t metric, uint32_t mtu,
	    uint8_t distance, route_tag_t tag, bool startup)
{
	struct route_entry *re = NULL;
	struct nexthop nexthop = {};
	struct nexthop_group ng = {};

	/* Allocate new route_entry structure. */
	re = zebra_rib_route_entry_new(vrf_id, type, instance, flags, nhe_id,
				       table_id, metric, mtu, distance, tag);

	/* If the owner of the route supplies a shared nexthop-group id,
	 * we'll use that. Otherwise, pass the nexthop along directly.
	 */
	if (!nhe_id) {
		/* Add nexthop. */
		nexthop = *nh;
		nexthop_group_add_sorted(&ng, &nexthop);
	}

	return rib_add_multipath(afi, safi, p, src_p, re, &ng, startup);
}

static const char *rib_update_event2str(enum rib_update_event event)
{
	const char *ret = "UNKNOWN";

	switch (event) {
	case RIB_UPDATE_INTERFACE_DOWN:
		ret = "RIB_UPDATE_INTERFACE_DOWN";
		break;
	case RIB_UPDATE_KERNEL:
		ret = "RIB_UPDATE_KERNEL";
		break;
	case RIB_UPDATE_RMAP_CHANGE:
		ret = "RIB_UPDATE_RMAP_CHANGE";
		break;
	case RIB_UPDATE_OTHER:
		ret = "RIB_UPDATE_OTHER";
		break;
	case RIB_UPDATE_MAX:
		break;
	}

	return ret;
}

/*
 * We now keep kernel routes, but we don't have any
 * trigger events for them when they are implicitly
 * deleted.  Since we are already walking the
 * entire table on a down event let's look at
 * the few kernel routes we may have
 */
static void
rib_update_handle_kernel_route_down_possibility(struct route_node *rn,
						struct route_entry *re)
{
	struct nexthop *nexthop = NULL;
	bool alive = false;

	for (ALL_NEXTHOPS(re->nhe->nhg, nexthop)) {
		struct interface *ifp = if_lookup_by_index(nexthop->ifindex,
							   nexthop->vrf_id);

		if (ifp && if_is_up(ifp)) {
			alive = true;
			break;
		}
	}

	if (!alive) {
		struct rib_table_info *rib_table = srcdest_rnode_table_info(rn);
		const struct prefix *p;
		const struct prefix_ipv6 *src_p;

		srcdest_rnode_prefixes(rn, &p, (const struct prefix **)&src_p);

		rib_delete(rib_table->afi, rib_table->safi, re->vrf_id,
			   re->type, re->instance, re->flags, p, src_p, NULL, 0,
			   re->table, re->metric, re->distance, true);
	}
}


/* Schedule route nodes to be processed if they match the type */
static void rib_update_route_node(struct route_node *rn, int type,
				  enum rib_update_event event)
{
	struct route_entry *re, *next;
	bool re_changed = false;

	RNODE_FOREACH_RE_SAFE (rn, re, next) {
		if (event == RIB_UPDATE_INTERFACE_DOWN && type == re->type &&
		    type == ZEBRA_ROUTE_KERNEL)
			rib_update_handle_kernel_route_down_possibility(rn, re);
		else if (type == ZEBRA_ROUTE_ALL || type == re->type) {
			SET_FLAG(re->status, ROUTE_ENTRY_CHANGED);
			re_changed = true;
		}
	}

	if (re_changed)
		rib_queue_add(rn);
}

/* Schedule routes of a particular table (address-family) based on event. */
void rib_update_table(struct route_table *table, enum rib_update_event event,
		      int rtype)
{
	struct route_node *rn;

	if (IS_ZEBRA_DEBUG_EVENT) {
		struct zebra_vrf *zvrf;
		struct vrf *vrf;

		zvrf = table->info
			       ? ((struct rib_table_info *)table->info)->zvrf
			       : NULL;
		vrf = zvrf ? zvrf->vrf : NULL;

		zlog_debug("%s: %s VRF %s Table %u event %s Route type: %s", __func__,
			   table->info ? afi2str(
				   ((struct rib_table_info *)table->info)->afi)
				       : "Unknown",
			   VRF_LOGNAME(vrf), zvrf ? zvrf->table_id : 0,
			   rib_update_event2str(event), zebra_route_string(rtype));
	}

	/* Walk all routes and queue for processing, if appropriate for
	 * the trigger event.
	 */
	for (rn = route_top(table); rn; rn = srcdest_route_next(rn)) {
		/*
		 * If we are looking at a route node and the node
		 * has already been queued  we don't
		 * need to queue it up again, unless it is
		 * an interface down event as that we need
		 * to process this no matter what.
		 */
		if (rn->info &&
		    CHECK_FLAG(rib_dest_from_rnode(rn)->flags,
			       RIB_ROUTE_ANY_QUEUED) &&
		    event != RIB_UPDATE_INTERFACE_DOWN)
			continue;

		switch (event) {
		case RIB_UPDATE_INTERFACE_DOWN:
		case RIB_UPDATE_KERNEL:
			rib_update_route_node(rn, ZEBRA_ROUTE_KERNEL, event);
			break;
		case RIB_UPDATE_RMAP_CHANGE:
		case RIB_UPDATE_OTHER:
			rib_update_route_node(rn, rtype, event);
			break;
		case RIB_UPDATE_MAX:
			break;
		}
	}
}

void rib_update_handle_vrf_all(enum rib_update_event event, int rtype)
{
	struct zebra_router_table *zrt;

	if (IS_ZEBRA_DEBUG_EVENT)
		zlog_debug("%s: Handling VRF (ALL) event %s", __func__,
			   rib_update_event2str(event));

	/* Just iterate over all the route tables, rather than vrf lookups */
	RB_FOREACH (zrt, zebra_router_table_head, &zrouter.tables)
		rib_update_table(zrt->table, event, rtype);
}

struct rib_update_ctx {
	enum rib_update_event event;
	vrf_id_t vrf_id;
};

static struct rib_update_ctx *rib_update_ctx_init(vrf_id_t vrf_id,
						  enum rib_update_event event)
{
	struct rib_update_ctx *ctx;

	ctx = XCALLOC(MTYPE_RIB_UPDATE_CTX, sizeof(struct rib_update_ctx));

	ctx->event = event;
	ctx->vrf_id = vrf_id;

	return ctx;
}

static void rib_update_ctx_fini(struct rib_update_ctx **ctx)
{
	XFREE(MTYPE_RIB_UPDATE_CTX, *ctx);
}

static void rib_update_handler(struct event *thread)
{
	struct rib_update_ctx *ctx;

	ctx = EVENT_ARG(thread);

	rib_update_handle_vrf_all(ctx->event, ZEBRA_ROUTE_ALL);

	rib_update_ctx_fini(&ctx);
}

/*
 * Thread list to ensure we don't schedule a ton of events
 * if interfaces are flapping for instance.
 */
static struct event *t_rib_update_threads[RIB_UPDATE_MAX];

void rib_update_finish(void)
{
	int i;

	for (i = RIB_UPDATE_KERNEL; i < RIB_UPDATE_MAX; i++) {
		if (event_is_scheduled(t_rib_update_threads[i])) {
			struct rib_update_ctx *ctx;

			ctx = EVENT_ARG(t_rib_update_threads[i]);

			rib_update_ctx_fini(&ctx);
			EVENT_OFF(t_rib_update_threads[i]);
		}
	}
}

/* Schedule a RIB update event for all vrfs */
void rib_update(enum rib_update_event event)
{
	struct rib_update_ctx *ctx;

	if (event_is_scheduled(t_rib_update_threads[event]))
		return;

	if (zebra_router_in_shutdown())
		return;

	ctx = rib_update_ctx_init(0, event);

	event_add_event(zrouter.master, rib_update_handler, ctx, 0,
			&t_rib_update_threads[event]);

	if (IS_ZEBRA_DEBUG_EVENT)
		zlog_debug("%s: Scheduled VRF (ALL), event %s", __func__,
			   rib_update_event2str(event));
}

/* Delete self installed routes after zebra is relaunched.  */
void rib_sweep_table(struct route_table *table)
{
	struct route_node *rn;
	struct route_entry *re;
	struct route_entry *next;
	struct nexthop *nexthop;

	if (!table)
		return;

	if (IS_ZEBRA_DEBUG_RIB)
		zlog_debug("%s: starting", __func__);

	for (rn = route_top(table); rn; rn = srcdest_route_next(rn)) {
		RNODE_FOREACH_RE_SAFE (rn, re, next) {

			if (IS_ZEBRA_DEBUG_RIB)
				route_entry_dump(&rn->p, NULL, re);

			if (CHECK_FLAG(re->status, ROUTE_ENTRY_REMOVED))
				continue;

			if (!CHECK_FLAG(re->flags, ZEBRA_FLAG_SELFROUTE))
				continue;

			/*
			 * If routes are older than startup_time then
			 * we know we read them in from the kernel.
			 * As such we can safely remove them.
			 */
			if (zrouter.startup_time < re->uptime)
				continue;

			/*
			 * So we are starting up and have received
			 * routes from the kernel that we have installed
			 * from a previous run of zebra but not cleaned
			 * up ( say a kill -9 )
			 * But since we haven't actually installed
			 * them yet( we received them from the kernel )
			 * we don't think they are active.
			 * So let's pretend they are active to actually
			 * remove them.
			 * In all honesty I'm not sure if we should
			 * mark them as active when we receive them
			 * This is startup only so probably ok.
			 *
			 * If we ever decide to move rib_sweep_table
			 * to a different spot (ie startup )
			 * this decision needs to be revisited
			 */
			SET_FLAG(re->status, ROUTE_ENTRY_INSTALLED);
			for (ALL_NEXTHOPS(re->nhe->nhg, nexthop))
				SET_FLAG(nexthop->flags, NEXTHOP_FLAG_FIB);

			rib_uninstall_kernel(rn, re);
			rib_delnode(rn, re);
		}
	}

	if (IS_ZEBRA_DEBUG_RIB)
		zlog_debug("%s: ends", __func__);
}

/* Sweep all RIB tables.  */
void rib_sweep_route(struct event *t)
{
	struct vrf *vrf;
	struct zebra_vrf *zvrf;

	zrouter.rib_sweep_time = monotime(NULL);
	/* TODO: Change to debug */
	zlog_info("Sweeping the RIB for stale routes...");

	RB_FOREACH (vrf, vrf_id_head, &vrfs_by_id) {
		if ((zvrf = vrf->info) == NULL)
			continue;

		rib_sweep_table(zvrf->table[AFI_IP][SAFI_UNICAST]);
		rib_sweep_table(zvrf->table[AFI_IP6][SAFI_UNICAST]);
	}

	zebra_router_sweep_route();
	zebra_router_sweep_nhgs();
}

/* Remove specific by protocol routes from 'table'. */
unsigned long rib_score_proto_table(uint8_t proto, unsigned short instance,
				    struct route_table *table)
{
	struct route_node *rn;
	struct route_entry *re;
	struct route_entry *next;
	unsigned long n = 0;

	if (table)
		for (rn = route_top(table); rn; rn = srcdest_route_next(rn))
			RNODE_FOREACH_RE_SAFE (rn, re, next) {
				if (CHECK_FLAG(re->status, ROUTE_ENTRY_REMOVED))
					continue;
				if (re->type == proto
				    && re->instance == instance) {
					rib_delnode(rn, re);
					n++;
				}
			}
	return n;
}

/* Remove specific by protocol routes. */
unsigned long rib_score_proto(uint8_t proto, unsigned short instance)
{
	struct vrf *vrf;
	struct zebra_vrf *zvrf;
	struct other_route_table *ort;
	unsigned long cnt = 0;

	RB_FOREACH (vrf, vrf_id_head, &vrfs_by_id) {
		zvrf = vrf->info;
		if (!zvrf)
			continue;

		early_route_meta_queue_free(zrouter.mq,
					    zrouter.mq->subq[META_QUEUE_EARLY_ROUTE],
					    zvrf, proto, instance);

		cnt += rib_score_proto_table(proto, instance,
					     zvrf->table[AFI_IP][SAFI_UNICAST])
		       + rib_score_proto_table(
			       proto, instance,
			       zvrf->table[AFI_IP6][SAFI_UNICAST]);

		frr_each(otable, &zvrf->other_tables, ort) cnt +=
			rib_score_proto_table(proto, instance, ort->table);
	}

	return cnt;
}

/* Close RIB and clean up kernel routes. */
void rib_close_table(struct route_table *table)
{
	struct route_node *rn;
	rib_dest_t *dest;

	if (!table)
		return;

	for (rn = route_top(table); rn; rn = srcdest_route_next(rn)) {
		dest = rib_dest_from_rnode(rn);

		if (dest && dest->selected_fib) {
			rib_uninstall_kernel(rn, dest->selected_fib);
			dest->selected_fib = NULL;
		}
	}
}

/*
 * Handle results from the dataplane system. Dequeue update context
 * structs, dispatch to appropriate internal handlers.
 */
static void rib_process_dplane_results(struct event *thread)
{
	struct zebra_dplane_ctx *ctx;
	struct dplane_ctx_list_head ctxlist;
	bool shut_p = false;

#ifdef HAVE_SCRIPTING
	char *script_name =
		frrscript_names_get_script_name(ZEBRA_ON_RIB_PROCESS_HOOK_CALL);

	int ret = 1;
	struct frrscript *fs = NULL;

	if (script_name) {
		fs = frrscript_new(script_name);
		if (fs)
			ret = frrscript_load(fs, ZEBRA_ON_RIB_PROCESS_HOOK_CALL,
					     NULL);
	}
#endif /* HAVE_SCRIPTING */

	/* Dequeue a list of completed updates with one lock/unlock cycle */

	do {
		dplane_ctx_q_init(&ctxlist);

		/* Take lock controlling queue of results */
		frr_with_mutex (&dplane_mutex) {
			/* Dequeue list of context structs */
			dplane_ctx_list_append(&ctxlist, &rib_dplane_q);
		}

		/* Dequeue context block */
		ctx = dplane_ctx_dequeue(&ctxlist);

		/* If we've emptied the results queue, we're done */
		if (ctx == NULL)
			break;

		/* If zebra is shutting down, avoid processing results,
		 * just drain the results queue.
		 */
		shut_p = atomic_load_explicit(&zrouter.in_shutdown,
					      memory_order_relaxed);
		if (shut_p) {
			while (ctx) {
				dplane_ctx_fini(&ctx);

				ctx = dplane_ctx_dequeue(&ctxlist);
			}

			continue;
		}

		while (ctx) {
#ifdef HAVE_SCRIPTING
			if (ret == 0)
				frrscript_call(fs,
					       ZEBRA_ON_RIB_PROCESS_HOOK_CALL,
					       ("ctx", ctx));
#endif /* HAVE_SCRIPTING */

			switch (dplane_ctx_get_op(ctx)) {
			case DPLANE_OP_ROUTE_INSTALL:
			case DPLANE_OP_ROUTE_UPDATE:
			case DPLANE_OP_ROUTE_DELETE:
			case DPLANE_OP_PIC_CONTEXT_INSTALL:
			case DPLANE_OP_PIC_CONTEXT_UPDATE:
			case DPLANE_OP_PIC_CONTEXT_DELETE:
				/* Bit of special case for route updates
				 * that were generated by async notifications:
				 * we don't want to continue processing these
				 * in the rib.
				 */
				if (dplane_ctx_get_notif_provider(ctx) == 0)
					rib_process_result(ctx);
				break;

			case DPLANE_OP_ROUTE_NOTIFY:
				rib_process_dplane_notify(ctx);
				break;

			case DPLANE_OP_NH_INSTALL:
			case DPLANE_OP_NH_UPDATE:
			case DPLANE_OP_NH_DELETE:
				zebra_nhg_dplane_result(ctx);
				break;

			case DPLANE_OP_LSP_INSTALL:
			case DPLANE_OP_LSP_UPDATE:
			case DPLANE_OP_LSP_DELETE:
				/* Bit of special case for LSP updates
				 * that were generated by async notifications:
				 * we don't want to continue processing these.
				 */
				if (dplane_ctx_get_notif_provider(ctx) == 0)
					zebra_mpls_lsp_dplane_result(ctx);
				break;

			case DPLANE_OP_LSP_NOTIFY:
				zebra_mpls_process_dplane_notify(ctx);
				break;

			case DPLANE_OP_PW_INSTALL:
			case DPLANE_OP_PW_UNINSTALL:
				zebra_pw_handle_dplane_results(ctx);
				break;

			case DPLANE_OP_SYS_ROUTE_ADD:
			case DPLANE_OP_SYS_ROUTE_DELETE:
				break;

			case DPLANE_OP_MAC_INSTALL:
			case DPLANE_OP_MAC_DELETE:
				zebra_vxlan_handle_result(ctx);
				break;

			case DPLANE_OP_RULE_ADD:
			case DPLANE_OP_RULE_DELETE:
			case DPLANE_OP_RULE_UPDATE:
			case DPLANE_OP_IPTABLE_ADD:
			case DPLANE_OP_IPTABLE_DELETE:
			case DPLANE_OP_IPSET_ADD:
			case DPLANE_OP_IPSET_DELETE:
			case DPLANE_OP_IPSET_ENTRY_ADD:
			case DPLANE_OP_IPSET_ENTRY_DELETE:
				zebra_pbr_dplane_result(ctx);
				break;

			case DPLANE_OP_INTF_ADDR_ADD:
			case DPLANE_OP_INTF_ADDR_DEL:
			case DPLANE_OP_INTF_INSTALL:
			case DPLANE_OP_INTF_UPDATE:
			case DPLANE_OP_INTF_DELETE:
			case DPLANE_OP_INTF_NETCONFIG:
				zebra_if_dplane_result(ctx);
				break;

			case DPLANE_OP_TC_QDISC_INSTALL:
			case DPLANE_OP_TC_QDISC_UNINSTALL:
			case DPLANE_OP_TC_CLASS_ADD:
			case DPLANE_OP_TC_CLASS_DELETE:
			case DPLANE_OP_TC_CLASS_UPDATE:
			case DPLANE_OP_TC_FILTER_ADD:
			case DPLANE_OP_TC_FILTER_DELETE:
			case DPLANE_OP_TC_FILTER_UPDATE:
				break;

			/* Some op codes not handled here */
			case DPLANE_OP_ADDR_INSTALL:
			case DPLANE_OP_ADDR_UNINSTALL:
			case DPLANE_OP_NEIGH_INSTALL:
			case DPLANE_OP_NEIGH_UPDATE:
			case DPLANE_OP_NEIGH_DELETE:
			case DPLANE_OP_NEIGH_IP_INSTALL:
			case DPLANE_OP_NEIGH_IP_DELETE:
			case DPLANE_OP_VTEP_ADD:
			case DPLANE_OP_VTEP_DELETE:
			case DPLANE_OP_NEIGH_DISCOVER:
			case DPLANE_OP_BR_PORT_UPDATE:
			case DPLANE_OP_NEIGH_TABLE_UPDATE:
			case DPLANE_OP_GRE_SET:
			case DPLANE_OP_SRV6_ENCAP_SRCADDR_SET:
			case DPLANE_OP_NONE:
				break;
			case DPLANE_OP_STARTUP_STAGE:
				zebra_ns_startup_continue(ctx);
				break;

			case DPLANE_OP_VLAN_INSTALL:
				zebra_vlan_dplane_result(ctx);
				break;
			} /* Dispatch by op code */

			dplane_ctx_fini(&ctx);
			ctx = dplane_ctx_dequeue(&ctxlist);
		}

	} while (1);

#ifdef HAVE_SCRIPTING
	if (fs)
		frrscript_delete(fs);
#endif
}

/*
 * Results are returned from the dataplane subsystem, in the context of
 * the dataplane pthread. We enqueue the results here for processing by
 * the main thread later.
 */
static int rib_dplane_results(struct dplane_ctx_list_head *ctxlist)
{
	/* Take lock controlling queue of results */
	frr_with_mutex (&dplane_mutex) {
		/* Enqueue context blocks */
		dplane_ctx_list_append(&rib_dplane_q, ctxlist);
	}

	/* Ensure event is signalled to zebra main pthread */
	event_add_event(zrouter.master, rib_process_dplane_results, NULL, 0,
			&t_dplane);

	return 0;
}

uint32_t zebra_rib_dplane_results_count(void)
{
	uint32_t count;

	frr_with_mutex (&dplane_mutex) {
		count = dplane_ctx_queue_count(&rib_dplane_q);
	}

	return count;
}

/*
 * Ensure there are no empty slots in the route_info array.
 * Every route type in zebra should be present there.
 */
static void check_route_info(void)
{
	int len = array_size(route_info);

	/*
	 * ZEBRA_ROUTE_SYSTEM is special cased since
	 * its key is 0 anyway.
	 *
	 * ZEBRA_ROUTE_ALL is also ignored.
	 */
	for (int i = 0; i < len; i++) {
		assert(route_info[i].key >= ZEBRA_ROUTE_SYSTEM &&
		       route_info[i].key < ZEBRA_ROUTE_MAX);
		assert(route_info[i].meta_q_map < MQ_SIZE);
	}
}

/* Routing information base initialize. */
void zebra_rib_init(void)
{
	check_route_info();

	rib_queue_init();

	/* Init dataplane, and register for results */
	pthread_mutex_init(&dplane_mutex, NULL);
	dplane_ctx_q_init(&rib_dplane_q);
	zebra_dplane_init(rib_dplane_results);
}

void zebra_rib_terminate(void)
{
	struct zebra_dplane_ctx *ctx;

	EVENT_OFF(t_dplane);

	ctx = dplane_ctx_dequeue(&rib_dplane_q);
	while (ctx) {
		dplane_ctx_fini(&ctx);

		ctx = dplane_ctx_dequeue(&rib_dplane_q);
	}
}

/*
 * vrf_id_get_next
 *
 * Get the first vrf id that is greater than the given vrf id if any.
 *
 * Returns true if a vrf id was found, false otherwise.
 */
static inline int vrf_id_get_next(vrf_id_t vrf_id, vrf_id_t *next_id_p)
{
	struct vrf *vrf;

	vrf = vrf_lookup_by_id(vrf_id);
	if (vrf) {
		vrf = RB_NEXT(vrf_id_head, vrf);
		if (vrf) {
			*next_id_p = vrf->vrf_id;
			return 1;
		}
	}

	return 0;
}

/*
 * rib_tables_iter_next
 *
 * Returns the next table in the iteration.
 */
struct route_table *rib_tables_iter_next(rib_tables_iter_t *iter)
{
	struct route_table *table;

	/*
	 * Array that helps us go over all AFI/SAFI combinations via one
	 * index.
	 */
	static const struct {
		afi_t afi;
		safi_t safi;
	} afi_safis[] = {
		{AFI_IP, SAFI_UNICAST},		{AFI_IP, SAFI_MULTICAST},
		{AFI_IP, SAFI_LABELED_UNICAST}, {AFI_IP6, SAFI_UNICAST},
		{AFI_IP6, SAFI_MULTICAST},      {AFI_IP6, SAFI_LABELED_UNICAST},
	};

	table = NULL;

	switch (iter->state) {

	case RIB_TABLES_ITER_S_INIT:
		iter->vrf_id = VRF_DEFAULT;
		iter->afi_safi_ix = -1;

		fallthrough;

	case RIB_TABLES_ITER_S_ITERATING:
		iter->afi_safi_ix++;
		while (1) {

			while (iter->afi_safi_ix
			       < (int)array_size(afi_safis)) {
				table = zebra_vrf_table(
					afi_safis[iter->afi_safi_ix].afi,
					afi_safis[iter->afi_safi_ix].safi,
					iter->vrf_id);
				if (table)
					break;

				iter->afi_safi_ix++;
			}

			/*
			 * Found another table in this vrf.
			 */
			if (table)
				break;

			/*
			 * Done with all tables in the current vrf, go to the
			 * next
			 * one.
			 */
			if (!vrf_id_get_next(iter->vrf_id, &iter->vrf_id))
				break;

			iter->afi_safi_ix = 0;
		}

		break;

	case RIB_TABLES_ITER_S_DONE:
		return NULL;
	}

	if (table)
		iter->state = RIB_TABLES_ITER_S_ITERATING;
	else
		iter->state = RIB_TABLES_ITER_S_DONE;

	return table;
}
