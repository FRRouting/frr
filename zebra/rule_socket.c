/*
 * Zebra Policy Based Routing (PBR) interaction with the kernel using
 * netlink.
 * Copyright (C) 2018  Cumulus Networks, Inc.
 *                     Donald Sharp
 *
 * This file is part of FRR.
 *
 * FRR is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2, or (at your option) any
 * later version.
 *
 * FRR is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with FRR; see the file COPYING.  If not, write to the Free
 * Software Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA
 * 02111-1307, USA.
 */

#include <zebra.h>

#ifndef HAVE_NETLINK

#include "if.h"
#include "prefix.h"
#include "vrf.h"

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

enum dp_req_result kernel_add_pbr_rule(struct zebra_pbr_rule *rule)
{
	zlog_err("%s not Implemented for this platform", __PRETTY_FUNCTION__);
	return DP_REQUEST_FAILURE;
}

enum dp_req_result kernel_del_pbr_rule(struct zebra_pbr_rule *rule)
{
	zlog_err("%s not Implemented for this platform", __PRETTY_FUNCTION__);
	return DP_REQUEST_FAILURE;
}

#endif
