// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Zebra NS header
 * Copyright (C) 2016 Cumulus Networks, Inc.
 *                    Donald Sharp
 */
#if !defined(__ZEBRA_NS_H__)
#define __ZEBRA_NS_H__

#include <lib/ns.h>
#include <lib/vrf.h>

#include "zebra/rib.h"
#include "zebra/zebra_vrf.h"

#ifdef __cplusplus
extern "C" {
#endif

#ifdef HAVE_NETLINK
#include <linux/netlink.h>

/* Socket interface to kernel */
struct nlsock {
	int sock;
	int seq;
	struct sockaddr_nl snl;
	char name[64];

	uint8_t *buf;
	size_t buflen;
};
#endif

/* Tree of interfaces: external linkage struct, and rbtree */
PREDECL_RBTREE_UNIQ(ifp_tree);

struct ifp_tree_link {
	struct ifp_tree_item link;

	ifindex_t ifindex;

	struct interface *ifp;

	/* Backpointer */
	struct zebra_ns *zns;
};

struct zebra_ns {
	/* net-ns name.  */
	char name[VRF_NAMSIZ];

	/* Identifier. */
	ns_id_t ns_id;

#ifdef HAVE_NETLINK
	struct nlsock netlink;        /* kernel messages */
	struct nlsock netlink_cmd;    /* command channel */

	/* dplane system's channels: one for outgoing programming,
	 * for the FIB e.g., and one for incoming events from the OS.
	 */
	struct nlsock netlink_dplane_out;
	struct nlsock netlink_dplane_in;
	struct event *t_netlink;

	struct nlsock ge_netlink_cmd; /* command channel for generic netlink */
#endif

	/* Tree of interfaces in this ns */
	struct ifp_tree_head ifp_tree;

	/* Back pointer */
	struct ns *ns;
};

struct zebra_ns *zebra_ns_lookup(ns_id_t ns_id);

/* Manage collection of ifps per-NS */
void zebra_ns_link_ifp(struct zebra_ns *zns, struct interface *ifp);
void zebra_ns_unlink_ifp(struct interface *ifp);
struct interface *zebra_ns_lookup_ifp(struct zebra_ns *zns, uint32_t ifindex);
struct interface *zebra_ns_lookup_ifp_name(struct zebra_ns *zns, const char *ifname);

/* Iterate collection of ifps, calling application's callback. Callback uses
 * return semantics from lib/ns.h: return NS_WALK_STOP to stop the iteration.
 * Caller's 'arg' is included in each callback.
 * The iterator returns STOP or CONTINUE also.
 */
int zebra_ns_ifp_walk(struct zebra_ns *zns,
		      int (*func)(struct interface *ifp, void *arg), void *arg);

/* Walk all NSes, and all ifps for each NS. */
void zebra_ns_ifp_walk_all(int (*func)(struct interface *ifp, void *arg), void *arg);

int zebra_ns_init(void);
int zebra_ns_enable(ns_id_t ns_id, void **info);
int zebra_ns_disabled(struct ns *ns);
int zebra_ns_early_shutdown(struct ns *ns,
			    void *param_in __attribute__((unused)),
			    void **param_out __attribute__((unused)));
int zebra_ns_final_shutdown(struct ns *ns,
			    void *param_in __attribute__((unused)),
			    void **param_out __attribute__((unused)));
int zebra_ns_kernel_shutdown(struct ns *ns, void *param_in __attribute__((unused)),
			     void **param_out __attribute__((unused)));

void zebra_ns_startup_continue(struct zebra_dplane_ctx *ctx);

#ifdef __cplusplus
}
#endif

#endif
