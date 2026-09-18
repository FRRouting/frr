// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * zebra_srv6_vpws.h: zebra-side SRv6 EVPN-VPWS (End.DX2) dataplane API.
 *
 * Declares the entry points that program a single-homed VPWS cross-connect in
 * the kernel from the ZAPI VPWS local/remote messages sent by bgpd: the
 * per-instance vpws-br bridge, the End.DX2 local decap (oif = attachment
 * circuit), and the vpws-srl2 encap netdev toward the remote peer's SID.
 *
 * Copyright (C) 2026 Aviz Networks
 */
#ifndef _ZEBRA_SRV6_VPWS_H
#define _ZEBRA_SRV6_VPWS_H

#include <zebra.h>
#include "lib/if.h"

struct zapi_vpws_local;
struct zapi_vpws_remote;

extern int zebra_srv6_vpws_local_add(const struct zapi_vpws_local *api);
extern int zebra_srv6_vpws_local_del(const char *instance_name);
extern int zebra_srv6_vpws_remote_add(const struct zapi_vpws_remote *api);
extern int zebra_srv6_vpws_remote_del(const char *instance_name);

extern void zebra_srv6_vpws_init(void);
extern void zebra_srv6_vpws_fini(void);

/*
 * Interface-add notification (called from zebra's if_add_update()): resolves the
 * asynchronously-created vpws-br-<name> bridge ifindex (dplane BR_CREATE does
 * not return one) and finishes the deferred AC/srl2 enslave.
 */
extern void zebra_srv6_vpws_if_add(struct interface *ifp);

extern void zebra_srv6_vpws_walk_encap(void (*cb)(const struct in6_addr *peer_sid,
						  ifindex_t srl2_ifindex, void *arg),
				       void *arg);

/* Live-apply the device-wide srl2 MTU to every VPWS srl2 encap interface. */
extern void zebra_srv6_vpws_apply_mtu(uint32_t mtu);

/* Delete every vpws-br-*vpws-srl2-* kernel interface (graceful-shutdown
 * cleanup); call while the command netlink socket is still open.
 */
extern void zebra_srv6_vpws_delete_all_kernel(void);

#endif
