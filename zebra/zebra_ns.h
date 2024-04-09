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

	struct route_table *if_table;

	/* Back pointer */
	struct ns *ns;
};

struct zebra_ns *zebra_ns_lookup(ns_id_t ns_id);

int zebra_ns_init(void);
int zebra_ns_enable(ns_id_t ns_id, void **info);
int zebra_ns_disabled(struct ns *ns);
int zebra_ns_early_shutdown(struct ns *ns,
			    void *param_in __attribute__((unused)),
			    void **param_out __attribute__((unused)));
int zebra_ns_final_shutdown(struct ns *ns,
			    void *param_in __attribute__((unused)),
			    void **param_out __attribute__((unused)));

void zebra_ns_startup_continue(struct zebra_dplane_ctx *ctx);

#ifdef __cplusplus
}
#endif

#endif
