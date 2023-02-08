// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * SHARP - code to track globals
 * Copyright (C) 2019 Cumulus Networks, Inc.
 *               Donald Sharp
 */
#ifndef __SHARP_GLOBAL_H__
#define __SHARP_GLOBAL_H__

#include "lib/srv6.h"

DECLARE_MGROUP(SHARPD);

struct sharp_routes {
	/* The original prefix for route installation */
	struct prefix orig_prefix;

	/* The nexthop info we are using for installation */
	struct nexthop nhop;
	struct nexthop backup_nhop;
	uint32_t nhgid;
	struct nexthop_group nhop_group;
	struct nexthop_group backup_nhop_group;

	uint32_t total_routes;
	uint32_t installed_routes;
	uint32_t removed_routes;
	int32_t repeat;

	/* ZAPI_ROUTE's flag */
	uint32_t flags;

	uint8_t inst;
	vrf_id_t vrf_id;

	struct timeval t_start;
	struct timeval t_end;

	char opaque[ZAPI_MESSAGE_OPAQUE_LENGTH];
};

struct sharp_srv6_locator {
	/* name of locator */
	char name[SRV6_LOCNAME_SIZE];

	/* list of struct prefix_ipv6 */
	struct list *chunks;
};

struct sharp_global {
	/* Global data about route install/deletions */
	struct sharp_routes r;

	/* The list of nexthops that we are watching and data about them */
	struct list *nhs;

	/* Traffic Engineering Database */
	struct ls_ted *ted;

	/* list of sharp_srv6_locator */
	struct list *srv6_locators;
};

extern struct sharp_global sg;
#endif
