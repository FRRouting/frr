// SPDX-License-Identifier: GPL-2.0-or-later
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

extern void zebra_srv6_vpws_walk_encap(void (*cb)(const struct in6_addr *peer_sid,
						  ifindex_t srl2_ifindex, void *arg),
				       void *arg);

/* Delete every vpws-br-*vpws-srl2-* kernel interface (graceful-shutdown
 * cleanup); call while the command netlink socket is still open.
 */
extern void zebra_srv6_vpws_delete_all_kernel(void);

#endif
