// SPDX-License-Identifier: GPL-2.0-or-later
/* Zebra L2VPN Service (VPLS, VPWS) code
 * Copyright (C) 2016 Volta Networks, Inc.
 * Copyright 2026 6WIND S.A.
 */

#ifndef zebra_l2vpn_svc_H_
#define zebra_l2vpn_svc_H_

#include <stdint.h>
#include <net/if.h>
#include <netinet/in.h>

#include "lib/hook.h"
#include "lib/qobj.h"
#include "lib/if.h"
#include "lib/l2vpn.h"
#include "lib/nexthop.h"
#include "lib/openbsd-tree.h"

#ifdef __cplusplus
extern "C" {
#endif

struct zebra_dplane_ctx;
struct zebra_vrf;

#define L2VPN_INSTALL_RETRY_INTERVAL 30

struct zebra_l2vpn_svc {
	RB_ENTRY(zebra_l2vpn_svc) svc_entry, static_svc_entry;
	vrf_id_t vrf_id;
	char ifname[IFNAMSIZ];
	ifindex_t ifindex;
	int type;
	int af;
	union g_addr nexthop;
	uint32_t local_label;
	uint32_t remote_label;
	uint8_t flags;
	union l2vpn_protocol_fields data;
	int enabled;
	int status;
	uint8_t protocol;
	struct zserv *client;
	struct rnh *rnh;
	struct event *install_retry_timer;
	QOBJ_FIELDS;
};
DECLARE_QOBJ_TYPE(zebra_l2vpn_svc);

RB_HEAD(zebra_l2vpn_svc_head, zebra_l2vpn_svc);
RB_PROTOTYPE(zebra_l2vpn_svc_head, zebra_l2vpn_svc, svc_entry, l2vpn_svc_compare);

RB_HEAD(zstatic_l2vpn_svc_head, zebra_l2vpn_svc);
RB_PROTOTYPE(zstatic_l2vpn_svc_head, zebra_l2vpn_svc, static_svc_entry, l2vpn_svc_compare);

DECLARE_HOOK(l2vpn_svc_install, (struct zebra_l2vpn_svc *svc), (svc));
DECLARE_HOOK(l2vpn_svc_uninstall, (struct zebra_l2vpn_svc *svc), (svc));

struct zebra_l2vpn_svc *zebra_l2vpn_svc_add(struct zebra_vrf *zvrf, const char *ifname,
					    uint8_t protocol, union l2vpn_protocol_fields data,
					    struct zserv *client);
void zebra_l2vpn_svc_del(struct zebra_vrf *zvrf, struct zebra_l2vpn_svc *svc);
void zebra_l2vpn_svc_change(struct zebra_l2vpn_svc *svc, ifindex_t ifindex, int type, int af,
			    union g_addr *nexthop, uint32_t local_label, uint32_t remote_label,
			    uint8_t flags, union l2vpn_protocol_fields *data);
struct zebra_l2vpn_svc *zebra_l2vpn_svc_find(struct zebra_vrf *zvrf, const char *ifname);
void zebra_l2vpn_svc_update(struct zebra_l2vpn_svc *svc);
void zebra_l2vpn_svc_install_failure(struct zebra_l2vpn_svc *svc, int svcstatus);
void zebra_l2vpn_svc_init_vrf(struct zebra_vrf *zvrf);
void zebra_l2vpn_svc_exit_vrf(struct zebra_vrf *zvrf);
void zebra_l2vpn_svc_terminate(void);
void zebra_pw_vty_init(void);
void zebra_l2vpn_svc_handle_dplane_results(struct zebra_dplane_ctx *ctx);

#ifdef __cplusplus
}
#endif

#endif /* zebra_l2vpn_svc_H_ */
