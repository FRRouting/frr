// SPDX-License-Identifier: GPL-2.0-or-later
/* MPLS forwarding table updates using netlink over GNU/Linux system.
 * Copyright (C) 2016  Cumulus Networks, Inc.
 */

#include <zebra.h>
#include <sys/stat.h>

#ifdef HAVE_NETLINK

#include <linux/netlink.h>
#include <linux/rtnetlink.h>

#include "zebra/debug.h"
#include "zebra/rt.h"
#include "zebra/rt_netlink.h"
#include "zebra/zebra_mpls.h"
#include "zebra/kernel_netlink.h"

ssize_t netlink_lsp_msg_encoder(struct zebra_dplane_ctx *ctx, void *buf,
				size_t buflen)
{
	int cmd;

	/* Call to netlink layer based on type of update */
	if (dplane_ctx_get_op(ctx) == DPLANE_OP_LSP_DELETE) {
		cmd = RTM_DELROUTE;
	} else if (dplane_ctx_get_op(ctx) == DPLANE_OP_LSP_INSTALL ||
		   dplane_ctx_get_op(ctx) == DPLANE_OP_LSP_UPDATE) {

		/* Validate */
		if (dplane_ctx_get_best_nhlfe(ctx) == NULL) {
			if (IS_ZEBRA_DEBUG_KERNEL || IS_ZEBRA_DEBUG_MPLS)
				zlog_debug("LSP in-label %u: update fails, no best NHLFE",
					   dplane_ctx_get_in_label(ctx));
			return -1;
		}

		cmd = RTM_NEWROUTE;
	} else
		/* Invalid op? */
		return -1;

	return netlink_mpls_multipath_msg_encode(cmd, ctx, buf, buflen);
}

enum netlink_msg_status netlink_put_lsp_update_msg(struct nl_batch *bth,
						   struct zebra_dplane_ctx *ctx)
{
	return netlink_batch_add_msg(bth, ctx, netlink_lsp_msg_encoder, false);
}

/*
 * Pseudowire update api - not supported by netlink as of 12/18,
 * but note that the default has been to report 'success' for pw updates
 * on unsupported platforms.
 */
enum netlink_msg_status netlink_put_pw_update_msg(struct nl_batch *bth,
						  struct zebra_dplane_ctx *ctx)
{
	return FRR_NETLINK_SUCCESS;
}

int mpls_kernel_init(void)
{
	struct stat st;

	/*
	 * Check if the MPLS module is loaded in the kernel.
	 */
	if (stat("/proc/sys/net/mpls", &st) != 0)
		return -1;

	return 0;
};

#endif /* HAVE_NETLINK */
