// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright (C) 2016 by Open Source Routing.
 */

#include <zebra.h>
#include "zebra/rt.h"
#include "zebra/zebra_mpls.h"

#if !defined(HAVE_NETLINK) && !defined(OPEN_BSD)

int mpls_kernel_init(void)
{
	return -1;
};

/*
 * Pseudowire update api - note that the default has been
 * to report 'success' for pw updates on unsupported platforms.
 */
enum zebra_dplane_result kernel_pw_update(struct zebra_dplane_ctx *ctx)
{
	return ZEBRA_DPLANE_REQUEST_SUCCESS;
}

enum zebra_dplane_result kernel_lsp_update(struct zebra_dplane_ctx *ctx)
{
	return ZEBRA_DPLANE_REQUEST_FAILURE;
}

#endif /* !defined(HAVE_NETLINK) && !defined(OPEN_BSD) */
