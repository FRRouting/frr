/*
 * Zebra NS header
 * Copyright (C) 2016 Cumulus Networks, Inc.
 *                    Donald Sharp
 *
 * This file is part of Quagga.
 *
 * Quagga is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2, or (at your option) any
 * later version.
 *
 * Quagga is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; see the file COPYING; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA
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
/* Socket interface to kernel */
struct nlsock {
	int sock;
	int seq;
	struct sockaddr_nl snl;
	char name[64];
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
	struct nlsock netlink_dplane; /* dataplane channel */
	struct thread *t_netlink;
#endif

	struct route_table *if_table;

	/* Back pointer */
	struct ns *ns;
};

struct zebra_ns *zebra_ns_lookup(ns_id_t ns_id);

int zebra_ns_init(const char *optional_default_name);
int zebra_ns_enable(ns_id_t ns_id, void **info);
int zebra_ns_disabled(struct ns *ns);
int zebra_ns_early_shutdown(struct ns *ns,
			    void *param_in __attribute__((unused)),
			    void **param_out __attribute__((unused)));
int zebra_ns_final_shutdown(struct ns *ns,
			    void *param_in __attribute__((unused)),
			    void **param_out __attribute__((unused)));
int zebra_ns_config_write(struct vty *vty, struct ns *ns);

#ifdef __cplusplus
}
#endif

#endif
