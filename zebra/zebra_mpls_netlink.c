/* MPLS forwarding table updates using netlink over GNU/Linux system.
 * Copyright (C) 2016  Cumulus Networks, Inc.
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

#include <zebra.h>

#ifdef HAVE_NETLINK

#include "zebra/debug.h"
#include "zebra/rt.h"
#include "zebra/rt_netlink.h"
#include "zebra/zebra_mpls.h"
#include "zebra/kernel_netlink.h"

/*
 * LSP forwarding update using dataplane context information.
 */
enum zebra_dplane_result kernel_lsp_update(struct zebra_dplane_ctx *ctx)
{
	uint8_t nl_pkt[NL_PKT_BUF_SIZE];
	ssize_t ret = -1;
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
			goto done;
		}

		cmd = RTM_NEWROUTE;
	} else
		/* Invalid op? */
		goto done;

	ret = netlink_mpls_multipath_msg_encode(cmd, ctx, nl_pkt,
						sizeof(nl_pkt));
	if (ret <= 0)
		return ZEBRA_DPLANE_REQUEST_FAILURE;

	ret = netlink_talk_info(netlink_talk_filter, (struct nlmsghdr *)nl_pkt,
				dplane_ctx_get_ns(ctx), 0);

done:

	return (ret == 0 ?
		ZEBRA_DPLANE_REQUEST_SUCCESS : ZEBRA_DPLANE_REQUEST_FAILURE);
}

/*
 * Pseudowire update api - not supported by netlink as of 12/18,
 * but note that the default has been to report 'success' for pw updates
 * on unsupported platforms.
 */
enum zebra_dplane_result kernel_pw_update(struct zebra_dplane_ctx *ctx)
{
	return ZEBRA_DPLANE_REQUEST_SUCCESS;
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
