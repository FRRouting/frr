// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Zebra Interface interaction with the kernel using socket.
 * Copyright (C) 2022  NVIDIA CORPORATION & AFFILIATES
 *                     Stephen Worley
 */

#include <zebra.h>

#ifndef HAVE_NETLINK

#include "lib_errors.h"

#include "zebra/rt.h"
#include "zebra/zebra_dplane.h"
#include "zebra/zebra_errors.h"

enum zebra_dplane_result kernel_intf_update(struct zebra_dplane_ctx *ctx)
{
	flog_err(EC_LIB_UNAVAILABLE, "%s not Implemented for this platform",
		 __func__);
	return ZEBRA_DPLANE_REQUEST_FAILURE;
}

enum zebra_dplane_result
kernel_intf_netconf_update(struct zebra_dplane_ctx *ctx)
{
	const char *ifname = dplane_ctx_get_ifname(ctx);
	enum dplane_netconf_status_e mpls_on = dplane_ctx_get_netconf_mpls(ctx);

	zlog_warn("%s:  Unable to set kernel mpls state for interface %s(%d)",
		  __func__, ifname, mpls_on);

	return ZEBRA_DPLANE_REQUEST_SUCCESS;
}
#endif
