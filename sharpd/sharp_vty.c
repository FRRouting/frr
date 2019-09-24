/*
 * SHARP - vty code
 * Copyright (C) Cumulus Networks, Inc.
 *               Donald Sharp
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
 * You should have received a copy of the GNU General Public License along
 * with this program; see the file COPYING; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA
 */
#include <zebra.h>

#include "vty.h"
#include "command.h"
#include "prefix.h"
#include "nexthop.h"
#include "log.h"
#include "vrf.h"
#include "zclient.h"
#include "nexthop_group.h"

#include "sharpd/sharp_globals.h"
#include "sharpd/sharp_zebra.h"
#include "sharpd/sharp_nht.h"
#include "sharpd/sharp_vty.h"
#ifndef VTYSH_EXTRACT_PL
#include "sharpd/sharp_vty_clippy.c"
#endif

DEFPY(watch_nexthop_v6, watch_nexthop_v6_cmd,
      "sharp watch [vrf NAME$vrf_name] <nexthop$n X:X::X:X$nhop|import$import X:X::X:X/M$inhop>  [connected$connected]",
      "Sharp routing Protocol\n"
      "Watch for changes\n"
      "The vrf we would like to watch if non-default\n"
      "The NAME of the vrf\n"
      "Watch for nexthop changes\n"
      "The v6 nexthop to signal for watching\n"
      "Watch for import check changes\n"
      "The v6 prefix to signal for watching\n"
      "Should the route be connected\n")
{
	struct vrf *vrf;
	struct prefix p;
	bool type_import;

	if (!vrf_name)
		vrf_name = VRF_DEFAULT_NAME;
	vrf = vrf_lookup_by_name(vrf_name);
	if (!vrf) {
		vty_out(vty, "The vrf NAME specified: %s does not exist\n",
			vrf_name);
		return CMD_WARNING;
	}

	memset(&p, 0, sizeof(p));

	if (n) {
		type_import = false;
		p.prefixlen = 128;
		memcpy(&p.u.prefix6, &nhop, 16);
		p.family = AF_INET6;
	} else {
		type_import = true;
		p = *(const struct prefix *)inhop;
	}

	sharp_nh_tracker_get(&p);
	sharp_zebra_nexthop_watch(&p, vrf->vrf_id, type_import,
				  true, !!connected);

	return CMD_SUCCESS;
}

DEFPY(watch_nexthop_v4, watch_nexthop_v4_cmd,
      "sharp watch [vrf NAME$vrf_name] <nexthop$n A.B.C.D$nhop|import$import A.B.C.D/M$inhop> [connected$connected]",
      "Sharp routing Protocol\n"
      "Watch for changes\n"
      "The vrf we would like to watch if non-default\n"
      "The NAME of the vrf\n"
      "Watch for nexthop changes\n"
      "The v4 address to signal for watching\n"
      "Watch for import check changes\n"
      "The v4 prefix for import check to watch\n"
      "Should the route be connected\n")
{
	struct vrf *vrf;
	struct prefix p;
	bool type_import;

	if (!vrf_name)
		vrf_name = VRF_DEFAULT_NAME;
	vrf = vrf_lookup_by_name(vrf_name);
	if (!vrf) {
		vty_out(vty, "The vrf NAME specified: %s does not exist\n",
			vrf_name);
		return CMD_WARNING;
	}

	memset(&p, 0, sizeof(p));

	if (n) {
		type_import = false;
		p.prefixlen = 32;
		p.u.prefix4 = nhop;
		p.family = AF_INET;
	}
	else {
		type_import = true;
		p = *(const struct prefix *)inhop;
	}

	sharp_nh_tracker_get(&p);
	sharp_zebra_nexthop_watch(&p, vrf->vrf_id, type_import,
				  true, !!connected);

	return CMD_SUCCESS;
}

DEFPY(sharp_nht_data_dump,
      sharp_nht_data_dump_cmd,
      "sharp data nexthop",
      "Sharp routing Protocol\n"
      "Nexthop information\n"
      "Data Dump\n")
{
	sharp_nh_tracker_dump(vty);

	return CMD_SUCCESS;
}

DEFPY (install_routes_data_dump,
       install_routes_data_dump_cmd,
       "sharp data route",
       "Sharp routing Protocol\n"
       "Data about what is going on\n"
       "Route Install/Removal Information\n")
{
	char buf[PREFIX_STRLEN];
	struct timeval r;

	timersub(&sg.r.t_end, &sg.r.t_start, &r);
	vty_out(vty, "Prefix: %s Total: %u %u %u Time: %jd.%ld\n",
		prefix2str(&sg.r.orig_prefix, buf, sizeof(buf)),
		sg.r.total_routes,
		sg.r.installed_routes,
		sg.r.removed_routes,
		(intmax_t)r.tv_sec, (long)r.tv_usec);

	return CMD_SUCCESS;
}

DEFPY (install_routes,
       install_routes_cmd,
       "sharp install routes [vrf NAME$vrf_name] <A.B.C.D$start4|X:X::X:X$start6> <nexthop <A.B.C.D$nexthop4|X:X::X:X$nexthop6>|nexthop-group NHGNAME$nexthop_group> (1-1000000)$routes [instance (0-255)$instance] [repeat (2-1000)$rpt]",
       "Sharp routing Protocol\n"
       "install some routes\n"
       "Routes to install\n"
       "The vrf we would like to install into if non-default\n"
       "The NAME of the vrf\n"
       "v4 Address to start /32 generation at\n"
       "v6 Address to start /32 generation at\n"
       "Nexthop to use(Can be an IPv4 or IPv6 address)\n"
       "V4 Nexthop address to use\n"
       "V6 Nexthop address to use\n"
       "Nexthop-Group to use\n"
       "The Name of the nexthop-group\n"
       "How many to create\n"
       "Instance to use\n"
       "Instance\n"
       "Should we repeat this command\n"
       "How many times to repeat this command\n")
{
	struct vrf *vrf;
	struct prefix prefix;
	uint32_t rts;

	sg.r.total_routes = routes;
	sg.r.installed_routes = 0;

	if (rpt >= 2)
		sg.r.repeat = rpt * 2;
	else
		sg.r.repeat = 0;

	memset(&prefix, 0, sizeof(prefix));
	memset(&sg.r.orig_prefix, 0, sizeof(sg.r.orig_prefix));
	memset(&sg.r.nhop, 0, sizeof(sg.r.nhop));
	memset(&sg.r.nhop_group, 0, sizeof(sg.r.nhop_group));

	if (start4.s_addr != 0) {
		prefix.family = AF_INET;
		prefix.prefixlen = 32;
		prefix.u.prefix4 = start4;
	} else {
		prefix.family = AF_INET6;
		prefix.prefixlen = 128;
		prefix.u.prefix6 = start6;
	}
	sg.r.orig_prefix = prefix;

	if (!vrf_name)
		vrf_name = VRF_DEFAULT_NAME;

	vrf = vrf_lookup_by_name(vrf_name);
	if (!vrf) {
		vty_out(vty, "The vrf NAME specified: %s does not exist\n",
			vrf_name);
		return CMD_WARNING;
	}

	if (nexthop_group) {
		struct nexthop_group_cmd *nhgc = nhgc_find(nexthop_group);
		if (!nhgc) {
			vty_out(vty,
				"Specified Nexthop Group: %s does not exist\n",
				nexthop_group);
			return CMD_WARNING;
		}

		sg.r.nhop_group.nexthop = nhgc->nhg.nexthop;
	} else {
		if (nexthop4.s_addr != INADDR_ANY) {
			sg.r.nhop.gate.ipv4 = nexthop4;
			sg.r.nhop.type = NEXTHOP_TYPE_IPV4;
		} else {
			sg.r.nhop.gate.ipv6 = nexthop6;
			sg.r.nhop.type = NEXTHOP_TYPE_IPV6;
		}

		sg.r.nhop.vrf_id = vrf->vrf_id;
		sg.r.nhop_group.nexthop = &sg.r.nhop;
	}

	sg.r.inst = instance;
	sg.r.vrf_id = vrf->vrf_id;
	rts = routes;
	sharp_install_routes_helper(&prefix, sg.r.vrf_id,
				    sg.r.inst, &sg.r.nhop_group, rts);

	return CMD_SUCCESS;
}

DEFPY(vrf_label, vrf_label_cmd,
      "sharp label <ip$ipv4|ipv6$ipv6> vrf NAME$vrf_name label (0-100000)$label",
      "Sharp Routing Protocol\n"
      "Give a vrf a label\n"
      "Pop and forward for IPv4\n"
      "Pop and forward for IPv6\n"
      VRF_CMD_HELP_STR
      "The label to use, 0 specifies remove the label installed from previous\n"
      "Specified range to use\n")
{
	struct vrf *vrf;
	afi_t afi = (ipv4) ? AFI_IP : AFI_IP6;

	if (strcmp(vrf_name, "default") == 0)
		vrf = vrf_lookup_by_id(VRF_DEFAULT);
	else
		vrf = vrf_lookup_by_name(vrf_name);

	if (!vrf) {
		vty_out(vty, "Unable to find vrf you silly head");
		return CMD_WARNING_CONFIG_FAILED;
	}

	if (label == 0)
		label = MPLS_LABEL_NONE;

	vrf_label_add(vrf->vrf_id, afi, label);
	return CMD_SUCCESS;
}

DEFPY (remove_routes,
       remove_routes_cmd,
       "sharp remove routes [vrf NAME$vrf_name] <A.B.C.D$start4|X:X::X:X$start6> (1-1000000)$routes [instance (0-255)$instance]",
       "Sharp Routing Protocol\n"
       "Remove some routes\n"
       "Routes to remove\n"
       "The vrf we would like to remove from if non-default\n"
       "The NAME of the vrf\n"
       "v4 Starting spot\n"
       "v6 Starting spot\n"
       "Routes to uninstall\n"
       "instance to use\n"
       "Value of instance\n")
{
	struct vrf *vrf;
	struct prefix prefix;

	sg.r.total_routes = routes;
	sg.r.removed_routes = 0;
	uint32_t rts;

	memset(&prefix, 0, sizeof(prefix));

	if (start4.s_addr != 0) {
		prefix.family = AF_INET;
		prefix.prefixlen = 32;
		prefix.u.prefix4 = start4;
	} else {
		prefix.family = AF_INET6;
		prefix.prefixlen = 128;
		prefix.u.prefix6 = start6;
	}

	vrf = vrf_lookup_by_name(vrf_name ? vrf_name : VRF_DEFAULT_NAME);
	if (!vrf) {
		vty_out(vty, "The vrf NAME specified: %s does not exist\n",
			vrf_name ? vrf_name : VRF_DEFAULT_NAME);
		return CMD_WARNING;
	}

	sg.r.inst = instance;
	sg.r.vrf_id = vrf->vrf_id;
	rts = routes;
	sharp_remove_routes_helper(&prefix, sg.r.vrf_id,
				   sg.r.inst, rts);

	return CMD_SUCCESS;
}

DEFUN_NOSH (show_debugging_sharpd,
	    show_debugging_sharpd_cmd,
	    "show debugging [sharp]",
	    SHOW_STR
	    DEBUG_STR
	    "Sharp Information\n")
{
	vty_out(vty, "Sharp debugging status\n");

	return CMD_SUCCESS;
}

void sharp_vty_init(void)
{
	install_element(ENABLE_NODE, &install_routes_data_dump_cmd);
	install_element(ENABLE_NODE, &install_routes_cmd);
	install_element(ENABLE_NODE, &remove_routes_cmd);
	install_element(ENABLE_NODE, &vrf_label_cmd);
	install_element(ENABLE_NODE, &sharp_nht_data_dump_cmd);
	install_element(ENABLE_NODE, &watch_nexthop_v6_cmd);
	install_element(ENABLE_NODE, &watch_nexthop_v4_cmd);

	install_element(VIEW_NODE, &show_debugging_sharpd_cmd);

	return;
}
