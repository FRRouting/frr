// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * zebra_srv6_vpws.c - VPWS End.DX2 dataplane install.
 *
 * For each VPWS instance:
 *   1. on LOCAL_ADD : create bridge `vpws-br-<name>`, enslave AC,
 *                     install End.DX2 decap with oif = AC ifindex.
 *   2. on REMOTE_ADD: create srl2 `vpws-srl2-<name>` with segs=peer_sid,
 *                     enslave it to the bridge with flood/learning flags set
 *                     for point-to-point operation.
 *   3. LOCAL_DEL / REMOTE_DEL: symmetric teardown.
 *
 * State is held in a small hash keyed by instance name. We do NOT touch
 * the ELAN bridge/br10 or any srl2-N / bum-srl2-N interface.
 */

#include <zebra.h>

#ifdef GNU_LINUX /* SRv6 L2 EVPN uses the Linux netlink/seg6 dataplane */

#include <linux/netlink.h>
#include <linux/if_link.h>
#include <linux/rtnetlink.h>
#include <linux/lwtunnel.h>
#include <linux/seg6_local.h>

#include "lib/hash.h"
#include "lib/typesafe.h"
#include "lib/memory.h"
#include "lib/log.h"
#include "lib/if.h"
#include "lib/prefix.h"
#include "lib/zclient.h"

#include "zebra/zserv.h"
#include "zebra/rt.h"
#include "zebra/rt_netlink.h"
#include "zebra/kernel_netlink.h"
#include "lib/netlink_parser.h" /* 10.6: nl_attr_put*, netlink_parse_rtattr* */
#include "zebra/interface.h"
#include "zebra/zebra_router.h"
#include "zebra/zebra_srl2.h" /* reuse srl2-create helpers */
#include "zebra/zebra_srv6_vpws.h"
#include "zebra/zebra_ns.h"

DEFINE_MTYPE_STATIC(ZEBRA, ZSRV6_VPWS, "SRv6 VPWS instance");

PREDECL_HASH(vpws_htab);

struct zsrv6_vpws {
	/* Intrusive linkage for the name-keyed typesafe hash (vpws_htab). */
	struct vpws_htab_item htab_item;

	char name[64];
	char ac_ifname[IFNAMSIZ];
	ifindex_t ac_ifindex;
	ifindex_t br_ifindex;
	ifindex_t srl2_ifindex;	   /* 0 until REMOTE_ADD */
	struct in6_addr local_sid; /* DX2 decap installed */
	struct in6_addr peer_sid;  /* srl2 encap dst */
	bool remote_present;
};

/* ---------- hash helpers ---------- */

static int vpws_htab_cmp(const struct zsrv6_vpws *a, const struct zsrv6_vpws *b)
{
	return strcmp(a->name, b->name);
}

static uint32_t vpws_htab_hash(const struct zsrv6_vpws *v)
{
	return string_hash_make(v->name);
}

DECLARE_HASH(vpws_htab, struct zsrv6_vpws, htab_item, vpws_htab_cmp, vpws_htab_hash);

static struct vpws_htab_head vpws_hash[1];
static bool vpws_inited;

static struct zsrv6_vpws *vpws_find(const char *name)
{
	struct zsrv6_vpws key = {};

	strlcpy(key.name, name, sizeof(key.name));
	return vpws_htab_find(vpws_hash, &key);
}


static struct zsrv6_vpws *vpws_get(const char *name)
{
	struct zsrv6_vpws *v = vpws_find(name);

	if (v)
		return v;
	v = XCALLOC(MTYPE_ZSRV6_VPWS, sizeof(*v));

	strlcpy(v->name, name, sizeof(v->name));
	vpws_htab_add(vpws_hash, v);
	return v;
}

void zebra_srv6_vpws_walk_encap(void (*cb)(const struct in6_addr *peer_sid, ifindex_t srl2_ifindex,
					   void *arg),
				void *arg)
{
	struct zsrv6_vpws *v;

	if (vpws_inited)
		frr_each (vpws_htab, vpws_hash, v)
			if (v->srl2_ifindex && v->remote_present)
				cb(&v->peer_sid, v->srl2_ifindex, arg);
}

/* ---------- peer-SID underlay /128 flush ----------
 *
 * Type-1 EAD processing installs an IPv6 /128 underlay route to the peer's
 * DX2 SID so the local vpws-srl2-<inst> encap can reach the remote endpoint.
 * Its lifecycle is normally tied to the remote EAD advertisement, so a local
 * `no vpws-instance` (peer still advertising) does not withdraw it, and a
 * kernel orphan left behind by an earlier locator-format change is not
 * cleared by the BGP RIB delete either. Since this /128 exists solely to
 * serve this pseudowire, delete it directly by destination on teardown. A
 * dst-only RTM_DELROUTE matches regardless of nexthop/metric, so it removes
 * both a zebra-owned route and a kernel orphan.
 */
static void vpws_flush_underlay_sid(const struct in6_addr *sid)
{
	struct zebra_ns *zns = zebra_ns_lookup(NS_DEFAULT);
	struct {
		struct nlmsghdr n;
		struct rtmsg r;
		char buf[256];
	} req = {};

	if (!zns || !sid || IN6_IS_ADDR_UNSPECIFIED(sid))
		return;

	req.n.nlmsg_len = NLMSG_LENGTH(sizeof(struct rtmsg));
	req.n.nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
	req.n.nlmsg_type = RTM_DELROUTE;
	req.r.rtm_family = AF_INET6;
	req.r.rtm_dst_len = 128;
	req.r.rtm_table = RT_TABLE_MAIN;
	req.r.rtm_scope = RT_SCOPE_NOWHERE; /* wildcard on delete */

	if (!nl_attr_put(&req.n, sizeof(req), RTA_DST, sid, sizeof(struct in6_addr)))
		return;

	zlog_debug("VPWS: flushing peer-SID underlay route %pI6/128", sid);
	netlink_talk(netlink_talk_filter, &req.n, &zns->netlink_cmd, zns, false, NULL, NULL);
}

/* ---------- local netlink helpers ----------
 * Bridge create + generic set/unset-master + (no-op) brport flags.
 * Kept local to this module to avoid disturbing rt_netlink.c.
 */

static int vpws_nl_link_delete(ifindex_t ifindex);

static int vpws_nl_bridge_create(const char *name, ifindex_t *out_ifindex)
{
	struct zebra_ns *zns = zebra_ns_lookup(NS_DEFAULT);
	struct {
		struct nlmsghdr n;
		struct ifinfomsg ifi;
		char buf[256];
	} req = {};
	struct rtattr *linkinfo;
	int rc;

	/*
	 * If a device with this name was left behind by a prior run, it is a
	 * stale orphan: vpws bridge/srl2 interfaces persist across an FRR
	 * restart while our in-memory state (v->br_ifindex) does not, and we
	 * only reach here when v->br_ifindex == 0.  Reusing such a leftover
	 * inherits its stale state (default MTU instead of 1422, admin-down,
	 * possibly not even a bridge), which makes the subsequent srl2 enslave
	 * fail with EINVAL.  Delete it first so we always build a clean bridge.
	 */
	{
		ifindex_t stale = if_nametoindex(name);

		if (stale != 0) {
			zlog_debug("VPWS: deleting stale orphan bridge %s (ifindex=%u) before recreate",
				   name, stale);
			vpws_nl_link_delete(stale);
		}
	}

	req.n.nlmsg_len = NLMSG_LENGTH(sizeof(struct ifinfomsg));
	req.n.nlmsg_flags = NLM_F_REQUEST | NLM_F_CREATE | NLM_F_EXCL | NLM_F_ACK;
	req.n.nlmsg_type = RTM_NEWLINK;
	req.ifi.ifi_family = AF_UNSPEC;

	if (!nl_attr_put(&req.n, sizeof(req), IFLA_IFNAME, name, strlen(name) + 1))
		return -1;
	linkinfo = nl_attr_nest(&req.n, sizeof(req), IFLA_LINKINFO);
	if (!linkinfo)
		return -1;
	if (!nl_attr_put(&req.n, sizeof(req), IFLA_INFO_KIND, "bridge", 7))
		return -1;
	nl_attr_nest_end(&req.n, linkinfo);

	rc = netlink_talk(netlink_talk_filter, &req.n, &zns->netlink_cmd, zns, false, NULL, NULL);


	/*
	 * Resolve the ifindex of the bridge we just created.  Use the kernel's
	 * if_nametoindex() as the primary source: it reflects the device that
	 * now exists in the kernel.  zebra's own interface table (if_lookup_by
	 * _name) lags the RTM_NEWLINK we just issued and — worse, right after a
	 * by-name orphan delete+recreate — can still hold the OLD, now-deleted
	 * ifindex.  Trusting that stale value makes the bring-up below target a
	 * non-existent device ("No such device") so the bridge never comes UP,
	 * and the later AC/srl2 enslave to it fails with EINVAL.  Fall back to
	 * zebra's table only if the kernel lookup somehow fails.
	 */
	{
		ifindex_t kidx = if_nametoindex(name);

		if (kidx != 0) {
			*out_ifindex = kidx;
		} else {
			struct interface *ifp = if_lookup_by_name(name, VRF_DEFAULT);

			*out_ifindex = ifp ? ifp->ifindex : 0;
		}
	}

	/*
	 * NLM_F_EXCL makes the create fail with EEXIST if a bridge with this
	 * name was leaked by an earlier run (e.g. a teardown that lost track
	 * of br_ifindex during a locator-format migration). Rather than abort
	 * the whole local_add - which would strand the stale DX2 route and
	 * srl2, and leave the bridge leaked forever - treat a pre-existing
	 * bridge as success and reuse it, as long as we can resolve its
	 * ifindex. Only a genuine failure (no such interface) is fatal.
	 */
	if (rc < 0) {
		if (*out_ifindex != 0) {
			zlog_debug("VPWS: bridge %s already exists (ifindex=%u), reusing", name,
				   *out_ifindex);
		} else {
			zlog_err("VPWS: bridge %s create failed and not present", name);
			return rc;
		}
	}

	/* Bring up the bridge. */
	{
		struct {
			struct nlmsghdr n;
			struct ifinfomsg ifi;
			char buf[64];
		} up = {};
		up.n.nlmsg_len = NLMSG_LENGTH(sizeof(struct ifinfomsg));
		up.n.nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
		up.n.nlmsg_type = RTM_NEWLINK;
		up.ifi.ifi_family = AF_UNSPEC;
		up.ifi.ifi_index = *out_ifindex;
		up.ifi.ifi_change = IFF_UP;
		up.ifi.ifi_flags = IFF_UP;
		netlink_talk(netlink_talk_filter, &up.n, &zns->netlink_cmd, zns, false, NULL, NULL);
	}
	return 0;
}

static int vpws_nl_link_delete(ifindex_t ifindex)
{
	struct zebra_ns *zns = zebra_ns_lookup(NS_DEFAULT);
	struct {
		struct nlmsghdr n;
		struct ifinfomsg ifi;
		char buf[64];
	} req = {};

	req.n.nlmsg_len = NLMSG_LENGTH(sizeof(struct ifinfomsg));
	req.n.nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
	req.n.nlmsg_type = RTM_DELLINK;
	req.ifi.ifi_family = AF_UNSPEC;
	req.ifi.ifi_index = ifindex;

	return netlink_talk(netlink_talk_filter, &req.n, &zns->netlink_cmd, zns, false, NULL, NULL);
}

/* Generic IFLA_MASTER set (0 = unset). */
static int vpws_nl_set_master(ifindex_t slave_ifindex, ifindex_t master_ifindex)
{
	struct zebra_ns *zns = zebra_ns_lookup(NS_DEFAULT);
	struct {
		struct nlmsghdr n;
		struct ifinfomsg ifi;
		char buf[64];
	} req = {};

	req.n.nlmsg_len = NLMSG_LENGTH(sizeof(struct ifinfomsg));
	req.n.nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
	req.n.nlmsg_type = RTM_SETLINK;
	req.ifi.ifi_family = AF_UNSPEC;
	req.ifi.ifi_index = slave_ifindex;

	if (!nl_attr_put32(&req.n, sizeof(req), IFLA_MASTER, master_ifindex))
		return -1;

	return netlink_talk(netlink_talk_filter, &req.n, &zns->netlink_cmd, zns, false, NULL, NULL);
}

/* ---------- public API ---------- */

int zebra_srv6_vpws_local_add(const struct zapi_vpws_local *api)
{
	struct zsrv6_vpws *v;
	struct interface *ac_ifp;
	char brname[IFNAMSIZ];
	int rc;

	if (!api || !api->instance_name[0] || !api->ac_ifname[0]) {
		zlog_warn("VPWS LOCAL_ADD: bad args");
		return -1;
	}

	ac_ifp = if_lookup_by_name(api->ac_ifname, VRF_DEFAULT);
	if (!ac_ifp || ac_ifp->ifindex == 0) {
		zlog_warn("VPWS %s: AC %s not present yet, will retry on if-up",
			  api->instance_name, api->ac_ifname);
		/* still record so the if-up hook can finish the install */
	}

	v = vpws_get(api->instance_name);
	strlcpy(v->ac_ifname, api->ac_ifname, sizeof(v->ac_ifname));
	v->ac_ifindex = ac_ifp ? ac_ifp->ifindex : 0;

	v->local_sid = api->local_sid;

	/* 1. dedicated bridge */
	if (snprintf(brname, sizeof(brname), "vpws-br-%s", v->name) >= (int)sizeof(brname)) {
		zlog_err("%s: VPWS instance name '%s' too long for bridge ifname", __func__,
			 v->name);
		return -1;
	}

	if (v->br_ifindex == 0) {
		rc = vpws_nl_bridge_create(brname, &v->br_ifindex);
		if (rc < 0) {
			zlog_err("VPWS %s: bridge %s create failed", v->name, brname);
			return -1;
		}
		zlog_debug("VPWS %s: bridge %s created (ifindex=%u)", v->name, brname,
			   v->br_ifindex);
	}

	/* 2. enslave AC to bridge */
	if (v->ac_ifindex) {
		rc = vpws_nl_set_master(v->ac_ifindex, v->br_ifindex);
		if (rc < 0)
			zlog_warn("VPWS %s: enslave AC %s to %s failed", v->name, v->ac_ifname,
				  brname);
		else
			zlog_debug("VPWS %s: AC %s enslaved to %s", v->name, v->ac_ifname, brname);
	}

	/* The local End.DX2 decap route is installed by bgpd through the RIB
	 * (zclient_send_localsid), the same way End.DT2U/DT2M are; zebra only
	 * sets up the srl2 encap / bridge / AC here.
	 */

	/* If a remote was learned before the local AC came up, finish it now. */
	if (v->remote_present && v->srl2_ifindex == 0) {
		struct zapi_vpws_remote r = {};

		strlcpy(r.instance_name, v->name, sizeof(r.instance_name));
		r.peer_sid = v->peer_sid;
		zebra_srv6_vpws_remote_add(&r);
	}
	return 0;
}

int zebra_srv6_vpws_local_del(const char *instance_name)
{
	struct zsrv6_vpws *v = vpws_find(instance_name);

	if (!v)
		return 0;

	/* tear remote first */
	if (v->srl2_ifindex) {
		netlink_srl2_if_del(v->srl2_ifindex);
		v->srl2_ifindex = 0;
	}
	/*
	 * Remove the peer-SID underlay /128 ONLY when the remote EAD is no
	 * longer present.  While the remote is still advertised, that /128 is
	 * a live BGP-owned RIB route (installed by
	 * bgp_evpn_program_srv6_ipv6_route on the remote EAD); a raw
	 * RTM_DELROUTE here would delete it from the kernel behind zebra's
	 * back, leaving the RIB marked Installed while the FIB has nothing -
	 * and BGP's idempotent re-add never repairs it.  This is exactly what
	 * happens during a local-SID churn (allocate->release->realloc, e.g. a
	 * per-instance locator correction): the transient LOCAL_DEL would strand
	 * the peer /128 and break DX2 forwarding.  Leave it to BGP's EAD
	 * withdraw (which removes it cleanly through the RIB); only flush a
	 * genuine orphan here, when no remote is present.
	 */
	if (!v->remote_present)
		vpws_flush_underlay_sid(&v->peer_sid);
	/* The End.DX2 decap route is bgpd-owned (RIB); bgpd removes it via
	 * zclient_send_localsid on VPWS teardown/SID-release.
	 */
	if (v->ac_ifindex)
		vpws_nl_set_master(v->ac_ifindex, 0);
	if (v->br_ifindex) {
		vpws_nl_link_delete(v->br_ifindex);
		v->br_ifindex = 0;
	}
	vpws_htab_del(vpws_hash, v);
	XFREE(MTYPE_ZSRV6_VPWS, v);
	zlog_debug("VPWS %s: local teardown complete", instance_name);
	return 0;
}

int zebra_srv6_vpws_remote_add(const struct zapi_vpws_remote *api)
{
	struct zsrv6_vpws *v;
	char ifname[IFNAMSIZ];
	int rc;

	if (!api || !api->instance_name[0])
		return -1;

	v = vpws_get(api->instance_name);
	v->remote_present = true;

	if (v->br_ifindex == 0) {
		/* Store the SID so we can finish when the local AC arrives. */
		v->peer_sid = api->peer_sid;
		zlog_debug("VPWS %s: remote received before local ready, deferring srl2 create",
			   v->name);
		return 0;
	}
	if (v->srl2_ifindex) {
		/* srl2 already exists - check if the peer SID has changed
		 * (e.g. normal->uSID locator migration).  If the SID is
		 * identical just skip; if it differs tear down the old srl2
		 * first so we create a fresh one with the new SID.
		 */
		if (memcmp(&v->peer_sid, &api->peer_sid, sizeof(v->peer_sid)) == 0) {
			zlog_debug("VPWS %s: srl2 already present with same SID (ifindex=%u), skipping",
				   v->name, v->srl2_ifindex);
			return 0;
		}
		zlog_debug("VPWS %s: peer SID changed (%pI6 -> %pI6), tearing down old srl2 (ifindex=%u) for re-create",
			   v->name, &v->peer_sid, &api->peer_sid, v->srl2_ifindex);
		netlink_srl2_if_del(v->srl2_ifindex);
		v->srl2_ifindex = 0;
	}

	/* Update stored peer SID to the incoming value before creating srl2. */
	v->peer_sid = api->peer_sid;

	/* 1. create srl2 with peer SID as encap dst */
	if (snprintf(ifname, sizeof(ifname), "vpws-srl2-%s", v->name) >= (int)sizeof(ifname)) {
		zlog_err("%s: VPWS instance name '%s' too long for srl2 ifname", __func__, v->name);
		return -1;
	}

	/*
	 * Defensive: if an srl2 interface with this name was leaked by an
	 * earlier run (untracked because v->srl2_ifindex was lost across a
	 * locator-format migration), netlink_srl2_if_add() - which uses
	 * NLM_F_EXCL - would fail with EEXIST and strand a srl2 pointing at
	 * the OLD peer SID. Delete any leftover by name first so the create
	 * below always starts clean with the new peer SID.
	 */
	{
		ifindex_t stale = if_nametoindex(ifname);

		if (stale != 0) {
			zlog_debug("VPWS %s: stale srl2 %s (ifindex=%u) found before create, deleting",
				   v->name, ifname, stale);
			netlink_srl2_if_del(stale);
		}
	}

	v->srl2_ifindex = netlink_srl2_if_add(ifname, &v->peer_sid);
	rc = (v->srl2_ifindex > 0) ? 0 : -1;
	if (rc < 0) {
		zlog_err("VPWS %s: srl2 create failed", v->name);
		return -1;
	}
	zlog_debug("VPWS %s: srl2 %s created (ifindex=%u, peer=%pI6)", v->name, ifname,
		   v->srl2_ifindex, &v->peer_sid);

	/* 2. enslave srl2 to the dedicated bridge */
	rc = netlink_srl2_if_set_master(v->srl2_ifindex, v->br_ifindex);
	if (rc < 0) {
		zlog_err("VPWS %s: srl2 enslave failed", v->name);
		return -1;
	}

	/*
	 * 3. bring the srl2 UP.  netlink_srl2_if_add() now creates the interface
	 * DOWN (the EVI path brings it up inside zebra_srl2_get_or_create after
	 * enslave + VLAN bind).  The VPWS bridge is not VLAN-aware, so there is
	 * no VLAN to bind — just bring the port up here, after enslave, or it
	 * stays DOWN/disabled and the pseudowire can't forward.
	 */
	rc = netlink_srl2_if_up(v->srl2_ifindex);
	if (rc < 0) {
		zlog_err("VPWS %s: srl2 bring-up failed", v->name);
		return -1;
	}

	return 0;
}

int zebra_srv6_vpws_remote_del(const char *instance_name)
{
	struct zsrv6_vpws *v = vpws_find(instance_name);

	if (!v)
		return 0;
	if (v->srl2_ifindex) {
		netlink_srl2_if_del(v->srl2_ifindex);
		v->srl2_ifindex = 0;
	}
	/* Remove the peer-SID underlay /128 before clearing the stored SID. */
	vpws_flush_underlay_sid(&v->peer_sid);
	v->remote_present = false;
	memset(&v->peer_sid, 0, sizeof(v->peer_sid));
	zlog_debug("VPWS %s: remote teardown complete", instance_name);
	return 0;
}

/* ---------- init/fini ---------- */

void zebra_srv6_vpws_init(void)
{
	vpws_htab_init(vpws_hash);
	vpws_inited = true;
}

/*
 * Delete every VPWS kernel interface (vpws-br-* bridge and vpws-srl2-* encap)
 * we created.  Called on graceful zebra shutdown (from zebra_finalize) BEFORE
 * the command netlink socket is closed, so these netdevs don't persist after
 * FRR stops.  SIGKILL can't run this; leftovers are reclaimed on next start.
 */
void zebra_srv6_vpws_delete_all_kernel(void)
{
	struct zsrv6_vpws *v;

	if (!vpws_inited)
		return;

	frr_each (vpws_htab, vpws_hash, v) {
		/* The End.DX2 decap route is bgpd-owned (RIB); zebra purges all
		 * bgpd routes when bgpd disconnects, so nothing dangles here.
		 */
		if (v->srl2_ifindex) {
			netlink_srl2_if_del(v->srl2_ifindex);
			v->srl2_ifindex = 0;
		}
		if (v->br_ifindex) {
			vpws_nl_link_delete(v->br_ifindex);
			v->br_ifindex = 0;
		}
	}
}

void zebra_srv6_vpws_fini(void)
{
	struct zsrv6_vpws *v;

	if (!vpws_inited)
		return;

	frr_each_safe (vpws_htab, vpws_hash, v) {
		vpws_htab_del(vpws_hash, v);
		XFREE(MTYPE_ZSRV6_VPWS, v);
	}
	vpws_htab_fini(vpws_hash);
	vpws_inited = false;
}

#else /* !GNU_LINUX - SRv6 L2 EVPN dataplane is netlink-only; stub out */

#include "zebra/zebra_srv6_vpws.h"

int zebra_srv6_vpws_local_add(const struct zapi_vpws_local *api)
{
	return 0;
}

int zebra_srv6_vpws_local_del(const char *instance_name)
{
	return 0;
}

int zebra_srv6_vpws_remote_add(const struct zapi_vpws_remote *api)
{
	return 0;
}

int zebra_srv6_vpws_remote_del(const char *instance_name)
{
	return 0;
}

void zebra_srv6_vpws_init(void)
{
}

void zebra_srv6_vpws_fini(void)
{
}

void zebra_srv6_vpws_walk_encap(void (*cb)(const struct in6_addr *peer_sid, ifindex_t srl2_ifindex,
					   void *arg),
				void *arg)
{
}

void zebra_srv6_vpws_delete_all_kernel(void)
{
}

#endif /* GNU_LINUX */
