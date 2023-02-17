// SPDX-License-Identifier: GPL-2.0-or-later
/* zebra_mroute.h
 * Copyright (C) 2016 Cumulus Networks, Inc.
 * Donald Sharp
 */

#ifndef __ZEBRA_MROUTE_H__
#define __ZEBRA_MROUTE_H__

#include "zebra/zserv.h"

#ifdef __cplusplus
extern "C" {
#endif

struct mcast_route_data {
	int family;
	struct ipaddr src;
	struct ipaddr grp;
	unsigned int ifindex;
	unsigned long long lastused;
};

void zebra_ipmr_route_stats(ZAPI_HANDLER_ARGS);

#ifdef __cplusplus
}
#endif

#endif
