// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Zebra Policy Based Routing (PBR) interaction with the kernel using
 * netlink.
 * Copyright (C) 2018  Cumulus Networks, Inc.
 *                     Donald Sharp
 */

#include <zebra.h>

#ifndef HAVE_NETLINK

#include "if.h"
#include "prefix.h"
#include "vrf.h"
#include "lib_errors.h"

#include "zebra/zserv.h"
#include "zebra/zebra_ns.h"
#include "zebra/zebra_vrf.h"
#include "zebra/rt.h"
#include "zebra/interface.h"
#include "zebra/debug.h"
#include "zebra/rtadv.h"
#include "zebra/kernel_netlink.h"
#include "zebra/rule_netlink.h"
#include "zebra/zebra_pbr.h"
#include "zebra/zebra_errors.h"

enum zebra_dplane_result kernel_pbr_rule_update(struct zebra_dplane_ctx *ctx)
{
	flog_err(EC_LIB_UNAVAILABLE, "%s not Implemented for this platform",
		 __func__);
	return ZEBRA_DPLANE_REQUEST_FAILURE;
}

#endif
