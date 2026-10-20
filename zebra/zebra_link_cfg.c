// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Zebra - configured (zebra-created) Linux links and interface masters.
 *
 * Configuration is declarative: zebra keeps the desired state per interface
 * and re-evaluates it ("realizes" it) whenever something relevant changes -
 * the configuration, or an interface appearing or disappearing - so config
 * ordering and startup races do not matter.  The kernel is only touched
 * through the dataplane (DPLANE_OP_LINK_*).
 */

#include <zebra.h>

#include "lib/if.h"
#include "lib/vrf.h"
#include "lib/log.h"
#include "lib/memory.h"
#include "lib/frrevent.h"

#include "monotime.h"
#include "zebra/zebra_router.h"
#include "zebra/ioctl.h"
#include "zebra/zebra_dplane.h"
#include "zebra/zebra_vrf.h"
#include "zebra/interface.h"
#include "zebra/debug.h"
#include "zebra/zebra_link_cfg_if.h"
#include "zebra/zebra_link_netlink.h"

DEFINE_MTYPE_STATIC(ZEBRA, ZEBRA_LINK_CFG, "Zebra configured link");

struct zebra_link_cfg {
	/* Desired kernel link */
	bool has_link;
	struct zebra_link_params params;
	bool create_pending;

	/* What the queued create asked for, to notice when it became unwanted */
	struct zebra_link_params create_params;
	/*
	 * A create that succeeded after the link-type was removed or changed.
	 * The link it made is deleted again once it shows up as an interface.
	 */
	bool create_stale;
	enum zebra_link_kind stale_kind;

	/* Desired master */
	bool has_master;
	char master[IFNAMSIZ];
	bool master_pending;
	/*
	 * Setting the master failed: not tried again for that master (interface
	 * index) until the configuration changes.  A master that was removed and
	 * comes back has a new index, so it is tried again.
	 */
	bool master_failed;
	ifindex_t master_failed_ifindex;
	/* ifindex of the master we last successfully enslaved to, or 0 */
	ifindex_t master_applied;

	/*
	 * A link zebra created is brought up administratively once it exists and its
	 * settings are in (tried once per kernel link; not forced again later).
	 */
	bool up_done;
	/* The same for the other end of a veth pair, which has its own configuration */
	bool peer_up_done;

	/* Address installation was held back until the master is applied */
	bool addr_held;

	/* When the link-type or master was last changed (monotonic), to let a burst settle */
	struct timeval changed;
};

static struct event *t_link_cfg_kick;
static struct event *t_link_cfg_settle;

/*
 * Every CLI command is a transaction of its own, so the link-type of an
 * interface and its master usually arrive one after the other.  A link that is
 * created is not brought up before the configuration of that interface has
 * been quiet for this long, so it comes up with its master in place.
 */
#define LINK_CFG_SETTLE_MSEC 1000

static void link_cfg_realize_all(struct event *event);

static inline bool ifp_is_real(const struct interface *ifp)
{
	return ifp->ifindex != IFINDEX_INTERNAL;
}

static struct zebra_link_cfg *link_cfg_get(struct interface *ifp, bool create)
{
	struct zebra_if *zif = ifp->info;

	if (!zif)
		return NULL;
	if (!zif->link_cfg && create)
		zif->link_cfg = XCALLOC(MTYPE_ZEBRA_LINK_CFG, sizeof(*zif->link_cfg));
	return zif->link_cfg;
}

static void link_cfg_addr_retry(struct interface *ifp, struct zebra_link_cfg *cfg);

/* Drop the state object once nothing is configured any more. */
static void link_cfg_release_if_empty(struct interface *ifp)
{
	struct zebra_if *zif = ifp->info;
	struct zebra_link_cfg *cfg = zif ? zif->link_cfg : NULL;

	/* Keep it alive while a request is outstanding; the result handler
	 * will look at it.
	 */
	if (!cfg || cfg->has_link || cfg->has_master || cfg->create_pending || cfg->create_stale ||
	    cfg->master_pending)
		return;

	/* Addresses held back for the master must not be lost with the state */
	link_cfg_addr_retry(ifp, cfg);

	XFREE(MTYPE_ZEBRA_LINK_CFG, zif->link_cfg);
}

/*
 * Find an interface by name.  With the netns backend interface names are only
 * unique per vrf; otherwise a name identifies exactly one interface, whatever
 * vrf (l3mdev) it is enslaved to.
 */
static struct interface *link_cfg_lookup(const struct interface *ref, const char *name)
{
	struct interface *ifp;
	struct vrf *vrf;

	if (vrf_is_backend_netns())
		return if_lookup_by_name(name, ref->vrf->vrf_id);

	RB_FOREACH (vrf, vrf_name_head, &vrfs_by_name) {
		ifp = if_lookup_by_name_vrf(name, vrf);
		if (ifp)
			return ifp;
	}
	return NULL;
}

static bool link_matches_kind(struct interface *ifp, enum zebra_link_kind kind)
{
	if (!ifp->info)
		return false;

	switch (kind) {
	case ZEBRA_LINK_BRIDGE:
		return IS_ZEBRA_IF_BRIDGE(ifp);
	case ZEBRA_LINK_VETH:
		return IS_ZEBRA_IF_VETH(ifp);
	case ZEBRA_LINK_VLAN:
		return IS_ZEBRA_IF_VLAN(ifp);
	case ZEBRA_LINK_GRE:
		return IS_ZEBRA_IF_GRE(ifp);
	case ZEBRA_LINK_DUMMY:
		return IS_ZEBRA_IF_DUMMY(ifp);
	case ZEBRA_LINK_NONE:
	case ZEBRA_LINK_KIND_MAX:
		break;
	}
	return false;
}

/*
 * A new Linux link starts administratively down, and nothing else in zebra
 * brings it up unless an address is configured on it.  A link that zebra was
 * asked to create is meant to be used, so it is brought up, unless "shutdown"
 * is configured.  This waits for what the kernel wants to be done on a down
 * link (bond settings such as ad-select cannot be changed on a bond that is
 * up) and for the master to be set, and is done once per kernel link: if
 * somebody sets it down afterwards, that is left alone.
 */
static bool link_cfg_shutdown_configured(const struct interface *ifp)
{
	const struct zebra_if *zif = ifp->info;

	return zif && zif->shutdown == IF_ZEBRA_DATA_ON;
}

static void link_cfg_set_up(struct interface *ifp)
{
	if (if_is_up(ifp))
		return;

	if (if_set_flags(ifp, IFF_UP | IFF_RUNNING) < 0) {
		zlog_warn("Unable to bring up %s", ifp->name);
		return;
	}
	if_refresh(ifp);
	/* IPv6 addresses are removed when a link goes down; add them again */
	if_addr_wakeup(ifp);
}

/*
 * Is the configured master (if any) in place?  A link that is to be enslaved
 * to a bridge or VRF must not come up before that, or its addresses would be
 * activated in the wrong routing context.  A master that cannot be applied
 * (it failed, or it is the interface itself) does not hold the link back.
 */
static bool link_cfg_master_ready(struct interface *ifp, struct zebra_link_cfg *cfg)
{
	struct zebra_if *zif = ifp->info;
	struct interface *master_ifp;

	if (!cfg->has_master)
		return true;

	master_ifp = link_cfg_lookup(ifp, cfg->master);
	if (!master_ifp || !ifp_is_real(master_ifp))
		return false; /* its arrival runs another pass */
	if (master_ifp == ifp)
		return true;

	return cfg->master_applied == master_ifp->ifindex ||
	       zif->brslave_info.bridge_ifindex == master_ifp->ifindex;
}

/*
 * Addresses must not be activated (nor the interface raised for them) before
 * the interface is in its master, or they would live in the wrong routing
 * context.  Callers that would do so ask here; when told to hold off, the
 * pass that applies the master gets them going again.
 */
bool zebra_link_cfg_hold_addresses(struct interface *ifp)
{
	struct zebra_if *zif = ifp->info;
	struct zebra_link_cfg *cfg = zif ? zif->link_cfg : NULL;

	if (!cfg || !cfg->has_master)
		return false;
	if (!cfg->master_pending && link_cfg_master_ready(ifp, cfg))
		return false;

	cfg->addr_held = true;
	return true;
}

/* Install the addresses that were held back, if they may go now */
static void link_cfg_addr_retry(struct interface *ifp, struct zebra_link_cfg *cfg)
{
	struct zebra_if *zif = ifp->info;

	if (!cfg->addr_held || !ifp_is_real(ifp) || cfg->master_pending ||
	    !link_cfg_master_ready(ifp, cfg))
		return;

	cfg->addr_held = false;
	if (CHECK_FLAG(ifp->status, ZEBRA_INTERFACE_ACTIVE) && zif->shutdown != IF_ZEBRA_DATA_ON)
		if_addr_wakeup(ifp);
}

static void link_cfg_touch(struct zebra_link_cfg *cfg)
{
	monotime(&cfg->changed);
}

/* Has the configuration of this link been quiet long enough?  If not, look again. */
static bool link_cfg_settled(const struct zebra_link_cfg *cfg)
{
	int64_t msec;

	if (!cfg->changed.tv_sec && !cfg->changed.tv_usec)
		return true;

	msec = monotime_since(&cfg->changed, NULL) / 1000;
	if (msec >= LINK_CFG_SETTLE_MSEC)
		return true;

	if (!zebra_router_in_shutdown())
		event_add_timer_msec(zrouter.master, link_cfg_realize_all, NULL,
				     LINK_CFG_SETTLE_MSEC - msec + 1, &t_link_cfg_settle);
	return false;
}

/*
 * Is everything that must come first in place for this end of a link?  'cfg'
 * is NULL for an interface with no configuration of its own, such as the peer
 * of a veth pair that has no master.
 */
static bool link_cfg_endpoint_ready(struct interface *ifp, struct zebra_link_cfg *cfg)
{
	if (!cfg)
		return true;

	if (cfg->create_pending || cfg->master_pending)
		return false;

	/* The master goes first, the interface may move to another VRF with it */
	if (!link_cfg_master_ready(ifp, cfg))
		return false;

	/* Another command for this interface may be on its way */
	return link_cfg_settled(cfg);
}

/* Is there an end of this link that is still to be brought up? */
static bool link_cfg_up_pending(const struct zebra_link_cfg *cfg)
{
	return !cfg->up_done || (cfg->params.kind == ZEBRA_LINK_VETH && !cfg->peer_up_done);
}

/* Is PEER, as far as the kernel has told us, the other end of the veth IFP? */
static bool link_cfg_is_veth_peer(const struct interface *ifp, const struct interface *peer)
{
	const struct zebra_if *zif = ifp->info;
	const struct zebra_if *pzif = peer->info;

	if (!zif || !pzif || !IS_ZEBRA_IF_VETH(ifp) || !IS_ZEBRA_IF_VETH(peer))
		return false;

	return zif->link_ifindex == peer->ifindex || pzif->link_ifindex == ifp->ifindex;
}

/* Do we know enough about the two to say whether they are a pair? */
static bool link_cfg_veth_link_known(const struct interface *ifp, const struct interface *peer)
{
	const struct zebra_if *zif = ifp->info;
	const struct zebra_if *pzif = peer->info;

	if (!zif || !pzif)
		return false;
	if (!IS_ZEBRA_IF_VETH(ifp) || !IS_ZEBRA_IF_VETH(peer))
		return true; /* not a veth at all: known not to be its peer */

	return zif->link_ifindex != IFINDEX_INTERNAL && pzif->link_ifindex != IFINDEX_INTERNAL;
}

/*
 * Each end of a link is brought up on its own terms: its own "shutdown", its
 * own master and its own configuration having settled.  A pair needs both up,
 * but one end waiting does not hold the other back, and is tried again when
 * what it waits for arrives.
 */
static void link_cfg_admin_up(struct interface *ifp, struct zebra_link_cfg *cfg)
{
	struct interface *peer;

	if (!link_matches_kind(ifp, cfg->params.kind))
		return;

	if (!cfg->up_done) {
		if (link_cfg_shutdown_configured(ifp)) {
			cfg->up_done = true;
		} else if (link_cfg_endpoint_ready(ifp, cfg)) {
			cfg->up_done = true;
			link_cfg_set_up(ifp);
		}
	}

	if (cfg->params.kind != ZEBRA_LINK_VETH || cfg->peer_up_done)
		return;

	peer = link_cfg_lookup(ifp, cfg->params.u.veth.peer_name);
	if (!peer || !ifp_is_real(peer))
		return; /* its arrival re-evaluates this */

	/*
	 * The name in the configuration is only a claim: raise it only if the
	 * kernel says the two are a pair.  A veth's link is its other end.
	 */
	if (!link_cfg_is_veth_peer(ifp, peer)) {
		if (!link_cfg_veth_link_known(ifp, peer))
			return; /* the kernel has not told us yet */
		zlog_warn("%s: %s is not the peer of %s, not bringing it up", __func__, peer->name,
			  ifp->name);
		cfg->peer_up_done = true;
		return;
	}

	if (link_cfg_shutdown_configured(peer)) {
		cfg->peer_up_done = true;
	} else if (link_cfg_endpoint_ready(peer, link_cfg_get(peer, false))) {
		cfg->peer_up_done = true;
		link_cfg_set_up(peer);
	}
}

/*
 * A create that succeeded after its link-type was removed or changed made a
 * link nobody wants.  Delete it, once it is known as an interface and only if
 * it is what we created.  (A changed definition is created again afterwards.)
 */
static void link_cfg_drop_stale(struct interface *ifp, struct zebra_link_cfg *cfg)
{
	if (!cfg->create_stale || !ifp_is_real(ifp))
		return;

	cfg->create_stale = false;
	if (link_matches_kind(ifp, cfg->stale_kind)) {
		zlog_info("%s: removing %s, its link configuration changed while it was being created",
			  __func__, ifp->name);
		dplane_link_delete(ifp);
	}
}

/*
 * Bring the kernel in line with the desired state of one interface.  Safe to
 * call at any time and as often as needed.
 */
static void link_cfg_realize(struct interface *ifp)
{
	struct zebra_if *zif = ifp->info;
	struct zebra_link_cfg *cfg = zif ? zif->link_cfg : NULL;
	struct interface *dep_ifp, *master_ifp;
	struct zebra_vrf *zvrf;
	const char *dep, *err;
	ifindex_t link_ifindex;

	if (!cfg)
		return;

	/* --- undo a create that is no longer wanted --- */
	link_cfg_drop_stale(ifp, cfg);

	/* --- create --- */
	if (cfg->has_link && !ifp_is_real(ifp) && !cfg->create_pending) {
		link_ifindex = 0;
		dep = zebra_link_params_dependency(&cfg->params);
		dep_ifp = dep ? link_cfg_lookup(ifp, dep) : NULL;
		zvrf = ifp->vrf ? ifp->vrf->info : NULL;

		if (vrf_is_backend_netns() && (!zvrf || !zvrf->zns)) {
			/* Never create it in another namespace: wait for this one */
			if (IS_ZEBRA_DEBUG_KERNEL)
				zlog_debug("%s: %s: waiting for the namespace of vrf %s", __func__,
					   ifp->name, ifp->vrf ? ifp->vrf->name : "?");
		} else if (dep && (!dep_ifp || !ifp_is_real(dep_ifp))) {
			if (IS_ZEBRA_DEBUG_KERNEL)
				zlog_debug("%s: %s: waiting for %s to exist", __func__, ifp->name,
					   dep);
		} else {
			err = zebra_link_params_validate(ifp->name, &cfg->params);
			if (err)
				zlog_warn("%s: not creating %s link %s: %s", __func__,
					  zebra_link_kind2str(cfg->params.kind), ifp->name, err);
			else {
				if (dep_ifp)
					link_ifindex = dep_ifp->ifindex;

				cfg->create_pending = true;
				memcpy(&cfg->create_params, &cfg->params, sizeof(cfg->params));
				if (dplane_link_create(ifp, &cfg->params, link_ifindex) !=
				    ZEBRA_DPLANE_REQUEST_QUEUED) {
					cfg->create_pending = false;
					zlog_warn("%s: unable to queue creation of %s link %s", __func__,
						  zebra_link_kind2str(cfg->params.kind), ifp->name);
				}
			}
		}
	}

	/* --- master --- */
	if (cfg->has_master && ifp_is_real(ifp) && !cfg->master_pending) {
		master_ifp = link_cfg_lookup(ifp, cfg->master);

		if (!master_ifp || !ifp_is_real(master_ifp)) {
			if (IS_ZEBRA_DEBUG_KERNEL)
				zlog_debug("%s: %s: waiting for master %s to exist", __func__,
					   ifp->name, cfg->master);
		} else if (master_ifp == ifp) {
			zlog_warn("%s: interface %s cannot be its own master", __func__, ifp->name);
		} else if (cfg->master_failed && cfg->master_failed_ifindex == master_ifp->ifindex) {
			if (IS_ZEBRA_DEBUG_KERNEL)
				zlog_debug("%s: %s: not setting master %s again, it failed",
					   __func__, ifp->name, cfg->master);
		} else if (cfg->master_applied != master_ifp->ifindex ||
			   (zif->brslave_info.bridge_ifindex &&
			    zif->brslave_info.bridge_ifindex != master_ifp->ifindex)) {
			/*
			 * Not known to be enslaved to the right master (or the
			 * kernel reports a different bridge): (re)apply.
			 */
			cfg->master_failed = false;
			cfg->master_pending = true;
			if (dplane_link_master_set(ifp, master_ifp->ifindex) !=
			    ZEBRA_DPLANE_REQUEST_QUEUED) {
				cfg->master_pending = false;
				zlog_warn("%s: unable to queue master %s for %s", __func__,
					  cfg->master, ifp->name);
			}
		}
	}
	/* --- addresses that waited for the master --- */
	link_cfg_addr_retry(ifp, cfg);

	/* --- admin up, after everything above has had its say --- */
	if (cfg->has_link && ifp_is_real(ifp) && link_cfg_up_pending(cfg))
		link_cfg_admin_up(ifp, cfg);
}

static void link_cfg_realize_all(struct event *event)
{
	struct vrf *vrf;
	struct interface *ifp;
	struct zebra_if *zif;

	RB_FOREACH (vrf, vrf_name_head, &vrfs_by_name) {
		FOR_ALL_INTERFACES (vrf, ifp) {
			zif = ifp->info;
			if (zif && zif->link_cfg)
				link_cfg_realize(ifp);
		}
	}
}

/*
 * Re-evaluate every configured interface from the main loop, so we never act
 * in the middle of processing a kernel notification.
 */
static void link_cfg_kick(void)
{
	/* Never create (or delete) anything while zebra is going away */
	if (zebra_router_in_shutdown())
		return;

	event_add_event(zrouter.master, link_cfg_realize_all, NULL, 0, &t_link_cfg_kick);
}

/* ---- configuration API ---- */

void zebra_link_cfg_set_link(struct interface *ifp, const struct zebra_link_params *params)
{
	struct zebra_link_cfg *cfg = link_cfg_get(ifp, true);

	if (!cfg)
		return;

	if (cfg->has_link && memcmp(&cfg->params, params, sizeof(*params)) == 0) {
		/* nothing changed */
		link_cfg_realize(ifp);
		return;
	}

	/*
	 * Parameters changed.  A link zebra can recognise as the old type is
	 * removed so the new definition can be created; the creation follows
	 * from the interface-deleted event.  If the existing interface is not
	 * recognisably of the old type we leave it alone.
	 */
	if (cfg->has_link && ifp_is_real(ifp) && link_matches_kind(ifp, cfg->params.kind)) {
		zlog_info("%s: link configuration of %s changed, re-creating it", __func__,
			  ifp->name);
		dplane_link_delete(ifp);
	}

	memcpy(&cfg->params, params, sizeof(*params));
	cfg->has_link = true;
	link_cfg_touch(cfg);

	link_cfg_realize(ifp);
}

void zebra_link_cfg_unset_link(struct interface *ifp)
{
	struct zebra_link_cfg *cfg = link_cfg_get(ifp, false);

	if (!cfg || !cfg->has_link)
		return;

	/* Only ever delete something we can positively identify */
	if (ifp_is_real(ifp) && link_matches_kind(ifp, cfg->params.kind))
		dplane_link_delete(ifp);

	cfg->has_link = false;
	link_cfg_touch(cfg);
	memset(&cfg->params, 0, sizeof(cfg->params));
	link_cfg_release_if_empty(ifp);

	/* A veth peer may have been waiting on this end */
	link_cfg_kick();
}

void zebra_link_cfg_set_master(struct interface *ifp, const char *master)
{
	struct zebra_link_cfg *cfg = link_cfg_get(ifp, true);

	if (!cfg)
		return;

	if (!cfg->has_master || strcmp(cfg->master, master) != 0)
		cfg->master_applied = 0;
	cfg->master_failed = false;

	strlcpy(cfg->master, master, sizeof(cfg->master));
	cfg->has_master = true;
	link_cfg_touch(cfg);

	link_cfg_realize(ifp);
}

void zebra_link_cfg_unset_master(struct interface *ifp)
{
	struct zebra_link_cfg *cfg = link_cfg_get(ifp, false);
	struct zebra_if *zif = ifp->info;
	struct interface *master_ifp;

	if (!cfg || !cfg->has_master)
		return;

	/*
	 * Release the interface only if it is (as far as we know) enslaved to
	 * the master we configured; never clear a master someone else set.
	 */
	if (ifp_is_real(ifp)) {
		master_ifp = link_cfg_lookup(ifp, cfg->master);
		if (master_ifp && ifp_is_real(master_ifp) &&
		    (cfg->master_applied == master_ifp->ifindex ||
		     zif->brslave_info.bridge_ifindex == master_ifp->ifindex))
			dplane_link_master_set(ifp, 0);
	}

	/*
	 * If the assignment is still in flight there is nothing to undo yet:
	 * the result handler releases the interface when it completes.
	 */
	cfg->has_master = false;
	link_cfg_touch(cfg);
	cfg->master[0] = '\0';
	cfg->master_applied = 0;
	cfg->master_failed = false;
	link_cfg_release_if_empty(ifp);

	/*
	 * Dropping the requirement can be what an interface (or a veth peer
	 * waiting on it) was held back for; nothing else may happen to wake
	 * it, so run another pass.
	 */
	link_cfg_kick();
}

const struct zebra_link_params *zebra_link_cfg_get_link(const struct interface *ifp)
{
	const struct zebra_if *zif = ifp->info;

	if (zif && zif->link_cfg && zif->link_cfg->has_link)
		return &zif->link_cfg->params;
	return NULL;
}

const char *zebra_link_cfg_get_master(const struct interface *ifp)
{
	const struct zebra_if *zif = ifp->info;

	if (zif && zif->link_cfg && zif->link_cfg->has_master)
		return zif->link_cfg->master;
	return NULL;
}

/* ---- events from the interface code ---- */

void zebra_link_cfg_if_added(struct interface *ifp)
{
	/*
	 * Something new exists: this interface may now be creatable or
	 * enslavable, and other interfaces may have been waiting for it.
	 */
	link_cfg_kick();
}

void zebra_link_cfg_if_master_update(struct interface *ifp, ifindex_t master_ifindex)
{
	struct zebra_link_cfg *cfg = link_cfg_get(ifp, false);

	/*
	 * If the kernel no longer has the interface in the master we enslaved it
	 * to (someone ran "nomaster", say), forget the assignment so the next
	 * pass applies the configured master again.  While our own assignment
	 * is in flight the report may predate it.
	 */
	if (!cfg || !cfg->has_master || !cfg->master_applied || cfg->master_pending ||
	    master_ifindex == cfg->master_applied)
		return;

	if (IS_ZEBRA_DEBUG_KERNEL)
		zlog_debug("%s: %s is no longer in master ifindex %u (now %u)", __func__,
			   ifp->name, cfg->master_applied, master_ifindex);
	cfg->master_applied = 0;
	link_cfg_kick();
}

void zebra_link_cfg_vrf_enabled(void)
{
	/* A namespace became available: a link waiting for it can be created */
	link_cfg_kick();
}

void zebra_link_cfg_if_deleted(struct interface *ifp)
{
	struct zebra_link_cfg *cfg = link_cfg_get(ifp, false);

	if (cfg) {
		/* The kernel state we recorded is gone */
		cfg->create_pending = false;
		cfg->create_stale = false;
		cfg->master_pending = false;
		cfg->master_failed = false;
		cfg->master_applied = 0;
		cfg->up_done = false;
		cfg->peer_up_done = false;
		cfg->addr_held = false;
	}

	/*
	 * A changed link definition is re-created from here, once the old
	 * interface is gone.  If the link was removed behind our back it is
	 * re-created as well, which is what a declarative config means.
	 */
	link_cfg_kick();
}

void zebra_link_cfg_if_free(struct interface *ifp)
{
	struct zebra_if *zif = ifp->info;

	if (zif && zif->link_cfg)
		XFREE(MTYPE_ZEBRA_LINK_CFG, zif->link_cfg);
}

/* ---- dataplane results ---- */

/*
 * The interface a result is about.  It may have changed VRF since the request
 * was made (enslaving it to a VRF device moves it), so it is found by its
 * index in the namespace first, and by name in the VRF it was in only if that
 * is not possible (it has no index before it is created).
 */
static struct interface *link_cfg_result_ifp(const struct zebra_dplane_ctx *ctx)
{
	const char *name = dplane_ctx_get_ifname(ctx);
	ifindex_t idx = dplane_ctx_get_ifindex(ctx);
	struct interface *ifp = NULL;

	if (idx != IFINDEX_INTERNAL) {
		ifp = if_lookup_by_index_per_nsid(dplane_ctx_get_ns_id(ctx), idx);
		if (ifp && strcmp(ifp->name, name) != 0)
			ifp = NULL;
	}
	if (!ifp)
		ifp = if_lookup_by_name(name, dplane_ctx_get_vrf(ctx));
	return ifp;
}

void zebra_link_cfg_dplane_result(struct zebra_dplane_ctx *ctx)
{
	enum dplane_op_e op = dplane_ctx_get_op(ctx);
	bool ok = dplane_ctx_get_status(ctx) == ZEBRA_DPLANE_REQUEST_SUCCESS;
	enum zebra_link_kind kind;
	const char *name = dplane_ctx_get_ifname(ctx);
	struct interface *ifp = link_cfg_result_ifp(ctx);
	struct zebra_link_cfg *cfg = ifp ? link_cfg_get(ifp, false) : NULL;

	if (IS_ZEBRA_DEBUG_KERNEL || IS_ZEBRA_DEBUG_DPLANE_DETAIL)
		zlog_debug("%s: %s %s: %s", __func__, dplane_op2str(op), name,
			   ok ? "success" : "failure");

	if (op == DPLANE_OP_LINK_CREATE) {
		kind = dplane_ctx_link_get_params(ctx)->kind;
		if (cfg) {
			cfg->create_pending = false;
			/* Wanted when it was queued, but not any more? */
			if (ok && (!cfg->has_link || memcmp(&cfg->params, &cfg->create_params,
							    sizeof(cfg->params)) != 0)) {
				cfg->create_stale = true;
				cfg->stale_kind = kind;
				/* Or later, when the interface appears */
				link_cfg_drop_stale(ifp, cfg);
			}
		}
		if (!ok)
			zlog_warn("Failed to create %s link %s in the kernel",
				  zebra_link_kind2str(kind), name);
		/* On success the kernel notification brings the interface in */
	} else if (op == DPLANE_OP_LINK_MASTER_SET) {
		ifindex_t master_ifindex = dplane_ctx_link_get_master_ifindex(ctx);

		/* Releasing a port (master 0) is not tracked as pending */
		if (cfg && master_ifindex) {
			cfg->master_pending = false;
			if (!ok) {
				/* Not tried again by itself, but the rest goes on */
				cfg->master_failed = true;
				cfg->master_failed_ifindex = master_ifindex;
			} else if (!cfg->has_master) {
				/* The master was removed from the configuration meanwhile */
				cfg->master_applied = 0;
				if (ifp && ifp_is_real(ifp))
					dplane_link_master_set(ifp, 0);
			} else {
				cfg->master_applied = master_ifindex;
			}
		}
		if (!ok)
			zlog_warn("Failed to set master of %s (master ifindex %d)", name,
				  dplane_ctx_link_get_master_ifindex(ctx));
	} else if (op == DPLANE_OP_LINK_DELETE) {
		if (!ok)
			zlog_warn("Failed to delete link %s in the kernel", name);
	}

	if (ifp)
		link_cfg_release_if_empty(ifp);
}
