/* Triggered SRTE config
 *
 * Copyright 2022 6WIND S.A.
 *
 * This file is part of FRRouting.
 *
 * FRRouting is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2, or (at your option) any
 * later version.
 *
 * FRRouting is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; see the file COPYING; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA
 */
#include "zebra.h"
#include "stream.h"
#include "zclient.h"
#include "srte.h"
#include "zapi_triggered_srte.h"

#include "pathd/path_tsrte.h"

extern struct zclient *zclient;

int path_zebra_handle_tsrte_bgp_ready(struct zclient *zclient,
				      struct stream *s)
{
	zlog_debug("%s(): received BGP_TE_READY, sending back reply", __func__);
	zapi_tsrte_client_ready_send(zclient, SRTE_ORIGIN_UNDEFINED);
	return 0;
}
