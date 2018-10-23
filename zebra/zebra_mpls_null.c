/*
 * Copyright (C) 2016 by Open Source Routing.
 *
 * This file is part of GNU Zebra.
 *
 * GNU Zebra is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2, or (at your option) any
 * later version.
 *
 * GNU Zebra is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; see the file COPYING; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA
 */

#include <zebra.h>
#include "zebra/rt.h"
#include "zebra/zebra_mpls.h"

#if !defined(HAVE_NETLINK) && !defined(OPEN_BSD)

enum zebra_dplane_result kernel_add_lsp(zebra_lsp_t *lsp)
{
	return ZEBRA_DPLANE_REQUEST_SUCCESS;
}

enum zebra_dplane_result kernel_upd_lsp(zebra_lsp_t *lsp)
{
	return ZEBRA_DPLANE_REQUEST_SUCCESS;
}

enum zebra_dplane_result kernel_del_lsp(zebra_lsp_t *lsp)
{
	return ZEBRA_DPLANE_REQUEST_SUCCESS;
}

int mpls_kernel_init(void)
{
	return -1;
};

enum zebra_dplane_result kernel_lsp_update(struct zebra_dplane_ctx *ctx)
{
	return ZEBRA_DPLANE_REQUEST_FAILURE;
}

#endif /* !defined(HAVE_NETLINK) && !defined(OPEN_BSD) */
