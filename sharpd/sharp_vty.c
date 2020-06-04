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
       "sharp install routes [vrf NAME$vrf_name]\
	  <A.B.C.D$start4|X:X::X:X$start6>\
	  <nexthop <A.B.C.D$nexthop4|X:X::X:X$nexthop6>|\
	   nexthop-group NHGNAME$nexthop_group>\
	  [backup$backup <A.B.C.D$backup_nexthop4|X:X::X:X$backup_nexthop6>] \
	  (1-1000000)$routes [instance (0-255)$instance] [repeat (2-1000)$rpt]",
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
       "Backup nexthop to use(Can be an IPv4 or IPv6 address)\n"
       "Backup V4 Nexthop address to use\n"
       "Backup V6 Nexthop address to use\n"
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
	memset(&sg.r.backup_nhop, 0, sizeof(sg.r.nhop));
	memset(&sg.r.backup_nhop_group, 0, sizeof(sg.r.nhop_group));

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

	/* Explicit backup not available with named nexthop-group */
	if (backup && nexthop_group) {
		vty_out(vty, "%% Invalid: cannot specify both nexthop-group and backup\n");
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

		/* Use group's backup nexthop info if present */
		if (nhgc->backup_list_name[0]) {
			struct nexthop_group_cmd *bnhgc =
				nhgc_find(nhgc->backup_list_name);

			if (!bnhgc) {
				vty_out(vty, "%% Backup group %s not found for group %s\n",
					nhgc->backup_list_name,
					nhgc->name);
				return CMD_WARNING;
			}

			sg.r.backup_nhop.vrf_id = vrf->vrf_id;
			sg.r.backup_nhop_group.nexthop = bnhgc->nhg.nexthop;
		}
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

	/* Use single backup nexthop if specified */
	if (backup) {
		/* Set flag and index in primary nexthop */
		SET_FLAG(sg.r.nhop.flags, NEXTHOP_FLAG_HAS_BACKUP);
		sg.r.nhop.backup_idx = 0;

		if (backup_nexthop4.s_addr != INADDR_ANY) {
			sg.r.backup_nhop.gate.ipv4 = backup_nexthop4;
			sg.r.backup_nhop.type = NEXTHOP_TYPE_IPV4;
		} else {
			sg.r.backup_nhop.gate.ipv6 = backup_nexthop6;
			sg.r.backup_nhop.type = NEXTHOP_TYPE_IPV6;
		}

		sg.r.backup_nhop.vrf_id = vrf->vrf_id;
		sg.r.backup_nhop_group.nexthop = &sg.r.backup_nhop;
	}

	sg.r.inst = instance;
	sg.r.vrf_id = vrf->vrf_id;
	rts = routes;
	sharp_install_routes_helper(&prefix, sg.r.vrf_id, sg.r.inst,
				    &sg.r.nhop_group, &sg.r.backup_nhop_group,
				    rts);

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
	vty_out(vty, "Sharp debugging status:\n");

	return CMD_SUCCESS;
}

DEFPY(sharp_lsp_prefix_v4, sharp_lsp_prefix_v4_cmd,
      "sharp lsp (0-100000)$inlabel\
        nexthop-group NHGNAME$nhgname\
        [prefix A.B.C.D/M$pfx\
       " FRR_IP_REDIST_STR_ZEBRA "$type_str [instance (0-255)$instance]]",
      "Sharp Routing Protocol\n"
      "Add an LSP\n"
      "The ingress label to use\n"
      "Use nexthops from a nexthop-group\n"
      "The nexthop-group name\n"
      "Label a prefix\n"
      "The v4 prefix to label\n"
      FRR_IP_REDIST_HELP_STR_ZEBRA
      "Instance to use\n"
      "Instance\n")
{
	struct nexthop_group_cmd *nhgc = NULL;
	struct nexthop_group_cmd *backup_nhgc = NULL;
	struct nexthop_group *backup_nhg = NULL;
	struct prefix p = {};
	int type = 0;

	/* We're offered a v4 prefix */
	if (pfx->family > 0 && type_str) {
		p.family = pfx->family;
		p.prefixlen = pfx->prefixlen;
		p.u.prefix4 = pfx->prefix;

		type = proto_redistnum(AFI_IP, type_str);
		if (type < 0) {
			vty_out(vty, "%%  Unknown route type '%s'\n", type_str);
			return CMD_WARNING;
		}
	} else if (pfx->family > 0 || type_str) {
		vty_out(vty, "%%  Must supply both prefix and type\n");
		return CMD_WARNING;
	}

	nhgc = nhgc_find(nhgname);
	if (!nhgc) {
		vty_out(vty, "%%  Nexthop-group '%s' does not exist\n",
			nhgname);
		return CMD_WARNING;
	}

	if (nhgc->nhg.nexthop == NULL) {
		vty_out(vty, "%%  Nexthop-group '%s' is empty\n", nhgname);
		return CMD_WARNING;
	}

	/* Use group's backup nexthop info if present */
	if (nhgc->backup_list_name[0]) {
		backup_nhgc = nhgc_find(nhgc->backup_list_name);

		if (!backup_nhgc) {
			vty_out(vty,
				"%% Backup group %s not found for group %s\n",
				nhgc->backup_list_name,
				nhgname);
			return CMD_WARNING;
		}
		backup_nhg = &(backup_nhgc->nhg);
	}

	if (sharp_install_lsps_helper(true, pfx->family > 0 ? &p : NULL,
				      type, instance, inlabel,
				      &(nhgc->nhg), backup_nhg) == 0)
		return CMD_SUCCESS;
	else {
		vty_out(vty, "%% LSP install failed!\n");
		return CMD_WARNING;
	}
}

DEFPY(sharp_remove_lsp_prefix_v4, sharp_remove_lsp_prefix_v4_cmd,
      "sharp remove lsp \
        (0-100000)$inlabel\
        [nexthop-group NHGNAME$nhgname] \
        [prefix A.B.C.D/M$pfx\
       " FRR_IP_REDIST_STR_SHARPD "$type_str [instance (0-255)$instance]]",
      "Sharp Routing Protocol\n"
      "Remove data\n"
      "Remove an LSP\n"
      "The ingress label\n"
      "Use nexthops from a nexthop-group\n"
      "The nexthop-group name\n"
      "Specify a v4 prefix\n"
      "The v4 prefix to label\n"
      FRR_IP_REDIST_HELP_STR_SHARPD
      "Routing instance\n"
      "Instance to use\n")
{
	struct nexthop_group_cmd *nhgc = NULL;
	struct prefix p = {};
	int type = 0;
	struct nexthop_group *nhg = NULL;

	/* We're offered a v4 prefix */
	if (pfx->family > 0 && type_str) {
		p.family = pfx->family;
		p.prefixlen = pfx->prefixlen;
		p.u.prefix4 = pfx->prefix;

		type = proto_redistnum(AFI_IP, type_str);
		if (type < 0) {
			vty_out(vty, "%%  Unknown route type '%s'\n", type_str);
			return CMD_WARNING;
		}
	} else if (pfx->family > 0 || type_str) {
		vty_out(vty, "%%  Must supply both prefix and type\n");
		return CMD_WARNING;
	}

	if (nhgname) {
		nhgc = nhgc_find(nhgname);
		if (!nhgc) {
			vty_out(vty, "%%  Nexthop-group '%s' does not exist\n",
				nhgname);
			return CMD_WARNING;
		}

		if (nhgc->nhg.nexthop == NULL) {
			vty_out(vty, "%%  Nexthop-group '%s' is empty\n",
				nhgname);
			return CMD_WARNING;
		}
		nhg = &(nhgc->nhg);
	}

	if (sharp_install_lsps_helper(false, pfx->family > 0 ? &p : NULL,
				      type, instance, inlabel, nhg, NULL) == 0)
		return CMD_SUCCESS;
	else {
		vty_out(vty, "%% LSP remove failed!\n");
		return CMD_WARNING;
	}
}

DEFPY (logpump,
       logpump_cmd,
       "sharp logpump duration (1-60) frequency (1-1000000) burst (1-1000)",
       "Sharp Routing Protocol\n"
       "Generate bulk log messages for testing\n"
       "Duration of run (s)\n"
       "Duration of run (s)\n"
       "Frequency of bursts (s^-1)\n"
       "Frequency of bursts (s^-1)\n"
       "Number of log messages per each burst\n"
       "Number of log messages per each burst\n")
{
	sharp_logpump_run(vty, duration, frequency, burst);
	return CMD_SUCCESS;
}

DEFPY (send_opaque,
       send_opaque_cmd,
       "sharp send opaque type (1-255) (1-1000)$count",
       SHARP_STR
       "Send messages for testing\n"
       "Send opaque messages\n"
       "Type code to send\n"
       "Type code to send\n"
       "Number of messages to send\n")
{
	sharp_opaque_send(type, count);
	return CMD_SUCCESS;
}

DEFPY (send_opaque_reg,
       send_opaque_reg_cmd,
       "sharp send opaque <reg$reg | unreg> \
       " FRR_IP_REDIST_STR_ZEBRA "$proto_str \
        [{instance (0-1000) | session (1-1000)}] type (1-1000)",
       SHARP_STR
       "Send messages for testing\n"
       "Send opaque messages\n"
       "Send opaque registration\n"
       "Send opaque unregistration\n"
       FRR_IP_REDIST_HELP_STR_ZEBRA
       "Daemon instance\n"
       "Daemon instance\n"
       "Session ID\n"
       "Session ID\n"
       "Opaque sub-type code\n"
       "Opaque sub-type code\n")
{
	int proto;

	proto = proto_redistnum(AFI_IP, proto_str);

	sharp_opaque_reg_send((reg != NULL), proto, instance, session, type);
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
	install_element(ENABLE_NODE, &sharp_lsp_prefix_v4_cmd);
	install_element(ENABLE_NODE, &sharp_remove_lsp_prefix_v4_cmd);
	install_element(ENABLE_NODE, &logpump_cmd);
	install_element(ENABLE_NODE, &send_opaque_cmd);
	install_element(ENABLE_NODE, &send_opaque_reg_cmd);

	install_element(VIEW_NODE, &show_debugging_sharpd_cmd);

	return;
}
