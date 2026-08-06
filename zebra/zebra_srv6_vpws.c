// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * zebra_srv6_vpws.c - VPWS End.DX2 dataplane install.
 *
 * Copyright (C) 2026 Aviz Networks
 *
 * For each VPWS instance:
 *   1. on LOCAL_ADD : bind the operator-created bridge, enslave AC,
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
#include "zebra/if_netlink.h" /* netlink_srl2_* interface helpers */
#include "zebra/kernel_netlink.h"
#include "lib/netlink_parser.h" /* 10.6: nl_attr_put*, netlink_parse_rtattr* */
#include "zebra/interface.h"
#include "zebra/zebra_router.h"
#include "zebra/zebra_dplane.h" /* dplane_intf_set_master/link_delete */
#include "zebra/zebra_srl2.h"	/* reuse srl2-create helpers */
#include "zebra/zebra_srv6_vpws.h"
#include "zebra/zebra_ns.h"

DEFINE_MTYPE_STATIC(ZEBRA, ZSRV6_VPWS, "SRv6 VPWS instance");

PREDECL_HASH(vpws_htab);

struct zsrv6_vpws {
	/* Intrusive linkage for the name-keyed typesafe hash (vpws_htab). */
	struct vpws_htab_item htab_item;

	char name[64];
	char ac_ifname[IFNAMSIZ];
	char bridge_ifname[IFNAMSIZ]; /* operator-created bridge to bind to */
	ifindex_t ac_ifindex;
	ifindex_t br_ifindex;
	ifindex_t srl2_ifindex;	   /* 0 until REMOTE_ADD */
	bool srl2_pending;	   /* create queued via dplane, ifindex not yet known */
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

/* ---------- operator bridge / interface-add hook ----------
 *
 * Operator-created bridge model: zebra does NOT create a bridge for the
 * pseudowire.  The operator provisions a dedicated bridge and names it in the
 * `interface <ac> ... bridge <br>` CLI; zebra only enslaves the AC and the srl2
 * encap netdev to it, through the dataplane provider abstraction
 * (dplane_intf_set_master() / dplane_link_delete()), not private netlink
 * sockets.
 *
 * The bridge must be present and used EXCLUSIVELY by this instance.  It is
 * resolved synchronously in local_add() when already present; if the operator
 * creates it after configuring the VPWS, zebra_srv6_vpws_if_add() picks it up
 * when the interface-add notification for that name arrives.
 */

/*
 * Validate that @br_ifp is an operator bridge usable by this VPWS instance: it
 * must be a bridge and carry no slave port other than this instance's own AC /
 * srl2.  Returns true if usable; on failure logs why and returns false so the
 * caller refuses to bring the pseudowire up (the bridge must be dedicated).
 */
static bool vpws_bridge_usable(struct zsrv6_vpws *v, struct interface *br_ifp)
{
	struct vrf *vrf = vrf_lookup_by_id(VRF_DEFAULT);
	struct interface *ifp;

	if (!br_ifp || !IS_ZEBRA_IF_BRIDGE(br_ifp)) {
		zlog_err("VPWS %s: %s is not a bridge - cannot bind", v->name, v->bridge_ifname);
		return false;
	}
	if (!vrf)
		return false;

	FOR_ALL_INTERFACES (vrf, ifp) {
		struct zebra_if *zif = ifp->info;

		if (!zif || !IS_ZEBRA_IF_BRIDGE_SLAVE(ifp) ||
		    zif->brslave_info.bridge_ifindex != br_ifp->ifindex)
			continue;
		/* This instance's own ports are allowed; anything else means the
		 * bridge is shared and therefore not dedicated to this VPWS.
		 */
		if (ifp->ifindex == v->ac_ifindex || ifp->ifindex == v->srl2_ifindex)
			continue;
		zlog_err("VPWS %s: bridge %s already has port %s; a VPWS bridge must be used exclusively by one instance",
			 v->name, v->bridge_ifname, ifp->name);
		return false;
	}
	return true;
}

/*
 * The dedicated bridge is present (v->br_ifindex set): enslave the AC and finish
 * a remote that was learned before the bridge existed.  Called from local_add()
 * (bridge already present) and from the interface-add hook (bridge just
 * created).
 */
static void vpws_on_bridge_ready(struct zsrv6_vpws *v)
{
	if (v->ac_ifindex) {
		dplane_intf_set_master(v->ac_ifindex, v->br_ifindex);
		zlog_debug("VPWS %s: AC %s enslave queued to bridge ifindex %u", v->name,
			   v->ac_ifname, v->br_ifindex);
	}

	/* If a remote was learned before the local bridge came up, finish it. */
	if (v->remote_present && v->srl2_ifindex == 0 && !v->srl2_pending) {
		struct zapi_vpws_remote r = {};

		strlcpy(r.instance_name, v->name, sizeof(r.instance_name));
		r.peer_sid = v->peer_sid;
		zebra_srv6_vpws_remote_add(&r);
	}
}

/*
 * Interface-add notification from zebra's if_add_update() (see interface.c).
 * Resolves the operator bridge ifindex when it appears (VPWS config may precede
 * the bridge), validates it, and finishes the deferred enslave.  Also picks up
 * an AC that becomes available after the bridge.
 *
 * NOTE: the lib if_add hook fires at struct-creation time, BEFORE the ifindex is
 * assigned (ifindex == 0), and zebra never fires the if_real/if_up hooks (those
 * are for zapi clients).  So we are driven from if_add_update(), which runs from
 * the netlink interface-learn path with a valid ifindex.
 */
void zebra_srv6_vpws_if_add(struct interface *ifp)
{
	struct zsrv6_vpws *v;
	char srl2name[IFNAMSIZ];

	if (!vpws_inited || !ifp || ifp->ifindex == 0)
		return;

	frr_each (vpws_htab, vpws_hash, v) {
		/* Our operator bridge just appeared: validate + finish enslave. */
		if (v->br_ifindex == 0 && v->bridge_ifname[0] &&
		    strcmp(ifp->name, v->bridge_ifname) == 0) {
			if (!vpws_bridge_usable(v, ifp))
				continue; /* logged; leave br_ifindex unset */
			v->br_ifindex = ifp->ifindex;
			zlog_debug("VPWS %s: bridge %s added (ifindex=%u), finishing enslave",
				   v->name, v->bridge_ifname, v->br_ifindex);
			vpws_on_bridge_ready(v);
			continue;
		}

		/*
		 * The srl2 encap netdev appeared: (re)bind ifindex + program it.
		 * Match by name and (re)adopt whenever the kernel ifindex differs
		 * from what we track - not only when srl2_ifindex == 0.  If an
		 * earlier same-named netdev was deleted (churn) srl2_ifindex can be
		 * left pointing at the stale ifindex; keying on ifindex mismatch lets
		 * the freshly created netdev still be brought up and enslaved instead
		 * of being stranded DOWN.
		 */
		if (snprintfrr(srl2name, sizeof(srl2name), "vpws-srl2-%s", v->name) <
			    (int)sizeof(srl2name) &&
		    v->srl2_ifindex != ifp->ifindex && strcmp(ifp->name, srl2name) == 0) {
			v->srl2_ifindex = ifp->ifindex;
			v->srl2_pending = false;
			dplane_srl2_addrgenmode(ifp->ifindex);
			if (v->br_ifindex)
				dplane_intf_set_master(ifp->ifindex, v->br_ifindex);
			dplane_srl2_if_up(ifp->ifindex);
			zlog_debug("VPWS %s: srl2 %s added (ifindex=%u), programmed", v->name,
				   srl2name, ifp->ifindex);
			continue;
		}

		/* The AC appeared after the bridge: enslave it now. */
		if (v->br_ifindex != 0 && v->ac_ifindex == 0 && v->ac_ifname[0] &&
		    strcmp(ifp->name, v->ac_ifname) == 0) {
			v->ac_ifindex = ifp->ifindex;
			dplane_intf_set_master(v->ac_ifindex, v->br_ifindex);
			zlog_debug("VPWS %s: AC %s added (ifindex=%u), enslave queued", v->name,
				   v->ac_ifname, v->ac_ifindex);
		}
	}
}

/* ---------- public API ---------- */

int zebra_srv6_vpws_local_add(const struct zapi_vpws_local *api)
{
	struct zsrv6_vpws *v;
	struct interface *ac_ifp, *br_ifp;

	if (!api || !api->instance_name[0] || !api->ac_ifname[0] || !api->bridge_ifname[0]) {
		zlog_warn("VPWS LOCAL_ADD: bad args (need instance, AC and bridge)");
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
	strlcpy(v->bridge_ifname, api->bridge_ifname, sizeof(v->bridge_ifname));
	v->ac_ifindex = ac_ifp ? ac_ifp->ifindex : 0;
	v->local_sid = api->local_sid;

	/*
	 * Operator-created bridge model: zebra does not create the bridge - it
	 * binds to the operator's `bridge <br>`.  Resolve it now if present and
	 * validate it is a bridge used exclusively by this instance; if the
	 * operator has not created it yet, defer to zebra_srv6_vpws_if_add(),
	 * which resolves + validates it when the interface-add notification for
	 * that name arrives.
	 */
	if (v->br_ifindex == 0) {
		br_ifp = if_lookup_by_name(v->bridge_ifname, VRF_DEFAULT);
		if (!br_ifp || br_ifp->ifindex == 0) {
			zlog_warn("VPWS %s: bridge %s not present yet, deferring enslave to if-add",
				  v->name, v->bridge_ifname);
			return 0;
		}
		if (!vpws_bridge_usable(v, br_ifp))
			return -1; /* not a bridge, or not dedicated - refuse */
		v->br_ifindex = br_ifp->ifindex;
	}

	/*
	 * Bridge resolved: enslave the AC and finish any deferred remote.  The
	 * local End.DX2 decap route is installed by bgpd through the RIB
	 * (zclient_send_localsid), the same way End.DT2U/DT2M are; zebra only
	 * sets up the srl2 encap / AC enslave here.
	 */
	vpws_on_bridge_ready(v);
	return 0;
}

int zebra_srv6_vpws_local_del(const char *instance_name)
{
	struct zsrv6_vpws *v = vpws_find(instance_name);

	if (!v)
		return 0;

	/* tear remote first */
	if (v->srl2_ifindex) {
		dplane_link_delete(v->srl2_ifindex);
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
		dplane_intf_set_master(v->ac_ifindex, 0);
	/*
	 * The bridge is operator-owned in this model - do NOT delete it, only
	 * detach our ports.  The srl2 was deleted above; the AC was unenslaved
	 * just above.
	 */
	v->br_ifindex = 0;
	vpws_htab_del(vpws_hash, v);
	XFREE(MTYPE_ZSRV6_VPWS, v);
	zlog_debug("VPWS %s: local teardown complete", instance_name);
	return 0;
}

int zebra_srv6_vpws_remote_add(const struct zapi_vpws_remote *api)
{
	struct zsrv6_vpws *v;
	char ifname[IFNAMSIZ];

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
	/*
	 * A create for this instance is already in flight (srl2_pending, ifindex
	 * not yet learned) or already done (srl2_ifindex set).  If the desired
	 * peer SID is unchanged there is nothing to do.  This guard is critical
	 * during the async create window: without it a duplicate remote_add with
	 * the SAME SID falls through to the if_nametoindex() stale-delete below,
	 * which finds the in-flight kernel netdev and deletes+recreates it.  The
	 * recreated netdev then races the hook (srl2_ifindex still points at the
	 * deleted one) and is stranded DOWN/unenslaved.
	 */
	if ((v->srl2_pending || v->srl2_ifindex) &&
	    memcmp(&v->peer_sid, &api->peer_sid, sizeof(v->peer_sid)) == 0) {
		zlog_debug("VPWS %s: srl2 create already in-flight/done with same peer SID %pI6, skipping",
			   v->name, &v->peer_sid);
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
		dplane_link_delete(v->srl2_ifindex);
		v->srl2_ifindex = 0;
	}

	/* Update stored peer SID to the incoming value before creating srl2. */
	v->peer_sid = api->peer_sid;

	/* 1. create srl2 with peer SID as encap dst */
	if (snprintfrr(ifname, sizeof(ifname), "vpws-srl2-%s", v->name) >= (int)sizeof(ifname)) {
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
			dplane_link_delete(stale);
		}
	}

	/*
	 * Create the srl2 through the dataplane provider (fire-and-forget).  The
	 * kernel ifindex is unknown here; it stays 0 (srl2_pending set) until
	 * zebra_srv6_vpws_if_add() sees the netdev appear and queues
	 * addr-gen-mode -> enslave -> up.  The DX2 encap (walk_encap) is gated on
	 * srl2_ifindex != 0 and re-drives once the ifindex is known.
	 */
	v->srl2_ifindex = 0;
	v->srl2_pending = true;
	dplane_srl2_create(ifname, &v->peer_sid);
	zlog_debug("VPWS %s: srl2 %s create queued (peer=%pI6, ifindex pending)", v->name, ifname,
		   &v->peer_sid);

	return 0;
}

int zebra_srv6_vpws_remote_del(const char *instance_name)
{
	struct zsrv6_vpws *v = vpws_find(instance_name);

	if (!v)
		return 0;
	if (v->srl2_ifindex) {
		dplane_link_delete(v->srl2_ifindex);
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
 * Delete every VPWS srl2 encap interface (vpws-srl2-*) we created; the
 * operator-owned bridge is left untouched.  Called on graceful zebra shutdown
 * (from zebra_finalize) BEFORE
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
			dplane_link_delete(v->srl2_ifindex);
			v->srl2_ifindex = 0;
		}
		/* The bridge is operator-owned - never delete it here. */
		v->br_ifindex = 0;
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

void zebra_srv6_vpws_if_add(struct interface *ifp)
{
}

#endif /* GNU_LINUX */
