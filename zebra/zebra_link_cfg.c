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

	/* Desired master */
	bool has_master;
	char master[IFNAMSIZ];
	bool master_pending;
	/* ifindex of the master we last successfully enslaved to, or 0 */
	ifindex_t master_applied;

	/*
	 * A link zebra created is brought up administratively once it exists and its
	 * settings are in (tried once per kernel link; not forced again later).
	 */
	bool up_done;
};

static struct event *t_link_cfg_kick;

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

/* Drop the state object once nothing is configured any more. */
static void link_cfg_release_if_empty(struct interface *ifp)
{
	struct zebra_if *zif = ifp->info;
	struct zebra_link_cfg *cfg = zif ? zif->link_cfg : NULL;

	/* Keep it alive while a request is outstanding; the result handler
	 * will look at it.
	 */
	if (!cfg || cfg->has_link || cfg->has_master || cfg->create_pending || cfg->master_pending)
		return;

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

static void link_cfg_admin_up(struct interface *ifp, struct zebra_link_cfg *cfg)
{
	struct interface *peer = NULL;

	if (!link_matches_kind(ifp, cfg->params.kind))
		return;

	if (cfg->create_pending || cfg->master_pending)
		return;

	if (link_cfg_shutdown_configured(ifp)) {
		cfg->up_done = true;
		return;
	}

	/* Both ends of a veth pair are ours, and a pair needs both up */
	if (cfg->params.kind == ZEBRA_LINK_VETH) {
		peer = link_cfg_lookup(ifp, cfg->params.u.veth.peer_name);
		if (!peer || !ifp_is_real(peer))
			return; /* its arrival re-evaluates this */
	}

	cfg->up_done = true;
	link_cfg_set_up(ifp);
	if (peer && !link_cfg_shutdown_configured(peer))
		link_cfg_set_up(peer);
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
	const char *dep, *err;
	ifindex_t link_ifindex;

	if (!cfg)
		return;

	/* --- create --- */
	if (cfg->has_link && !ifp_is_real(ifp) && !cfg->create_pending) {
		link_ifindex = 0;
		dep = zebra_link_params_dependency(&cfg->params);
		dep_ifp = dep ? link_cfg_lookup(ifp, dep) : NULL;

		if (dep && (!dep_ifp || !ifp_is_real(dep_ifp))) {
			if (IS_ZEBRA_DEBUG_KERNEL)
				zlog_debug("%s: %s: waiting for %s to exist", __func__, ifp->name,
					   dep);
		} else if ((err = zebra_link_params_validate(ifp->name, &cfg->params))) {
			zlog_warn("%s: not creating %s link %s: %s", __func__,
				  zebra_link_kind2str(cfg->params.kind), ifp->name, err);
		} else {
			if (dep_ifp)
				link_ifindex = dep_ifp->ifindex;

			cfg->create_pending = true;
			if (dplane_link_create(ifp, &cfg->params, link_ifindex) !=
			    ZEBRA_DPLANE_REQUEST_QUEUED) {
				cfg->create_pending = false;
				zlog_warn("%s: unable to queue creation of %s link %s", __func__,
					  zebra_link_kind2str(cfg->params.kind), ifp->name);
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
		} else if (cfg->master_applied != master_ifp->ifindex ||
			   (zif->brslave_info.bridge_ifindex &&
			    zif->brslave_info.bridge_ifindex != master_ifp->ifindex)) {
			/*
			 * Not known to be enslaved to the right master (or the
			 * kernel reports a different bridge): (re)apply.
			 */
			cfg->master_pending = true;
			if (dplane_link_master_set(ifp, master_ifp->ifindex) !=
			    ZEBRA_DPLANE_REQUEST_QUEUED) {
				cfg->master_pending = false;
				zlog_warn("%s: unable to queue master %s for %s", __func__,
					  cfg->master, ifp->name);
			}
		}
	}
	/* --- admin up, after everything above has had its say --- */
	if (cfg->has_link && ifp_is_real(ifp) && !cfg->up_done)
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
	memset(&cfg->params, 0, sizeof(cfg->params));
	link_cfg_release_if_empty(ifp);
}

void zebra_link_cfg_set_master(struct interface *ifp, const char *master)
{
	struct zebra_link_cfg *cfg = link_cfg_get(ifp, true);

	if (!cfg)
		return;

	if (!cfg->has_master || strcmp(cfg->master, master) != 0)
		cfg->master_applied = 0;

	strlcpy(cfg->master, master, sizeof(cfg->master));
	cfg->has_master = true;

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

	cfg->has_master = false;
	cfg->master[0] = '\0';
	cfg->master_applied = 0;
	link_cfg_release_if_empty(ifp);
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

void zebra_link_cfg_if_deleted(struct interface *ifp)
{
	struct zebra_link_cfg *cfg = link_cfg_get(ifp, false);

	if (cfg) {
		/* The kernel state we recorded is gone */
		cfg->create_pending = false;
		cfg->master_pending = false;
		cfg->master_applied = 0;
		cfg->up_done = false;
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

void zebra_link_cfg_dplane_result(struct zebra_dplane_ctx *ctx)
{
	enum dplane_op_e op = dplane_ctx_get_op(ctx);
	bool ok = dplane_ctx_get_status(ctx) == ZEBRA_DPLANE_REQUEST_SUCCESS;
	enum zebra_link_kind kind;
	const char *name = dplane_ctx_get_ifname(ctx);
	struct interface *ifp = if_lookup_by_name(name, dplane_ctx_get_vrf(ctx));
	struct zebra_link_cfg *cfg = ifp ? link_cfg_get(ifp, false) : NULL;

	if (IS_ZEBRA_DEBUG_KERNEL || IS_ZEBRA_DEBUG_DPLANE_DETAIL)
		zlog_debug("%s: %s %s: %s", __func__, dplane_op2str(op), name,
			   ok ? "success" : "failure");

	if (op == DPLANE_OP_LINK_CREATE) {
		kind = dplane_ctx_link_get_params(ctx)->kind;
		if (cfg)
			cfg->create_pending = false;
		if (!ok)
			zlog_warn("Failed to create %s link %s in the kernel",
				  zebra_link_kind2str(kind), name);
		/* On success the kernel notification brings the interface in */
	} else if (op == DPLANE_OP_LINK_MASTER_SET) {
		if (cfg) {
			cfg->master_pending = false;
			if (ok)
				cfg->master_applied = dplane_ctx_link_get_master_ifindex(ctx);
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
