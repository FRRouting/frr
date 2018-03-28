/* Zebra MPLS VTY functions
 * Copyright (C) 2002 Kunihiro Ishiguro
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

#include "memory.h"
#include "if.h"
#include "prefix.h"
#include "command.h"
#include "table.h"
#include "rib.h"
#include "nexthop.h"
#include "vrf.h"
#include "mpls.h"
#include "lib/json.h"

#include "zebra/zserv.h"
#include "zebra/zebra_vrf.h"
#include "zebra/zebra_mpls.h"
#include "zebra/zebra_rnh.h"
#include "zebra/redistribute.h"
#include "zebra/zebra_routemap.h"
#include "zebra/zebra_static.h"

static int zebra_mpls_transit_lsp(struct vty *vty, int add_cmd,
				  const char *inlabel_str, const char *gate_str,
				  const char *outlabel_str,
				  const char *flag_str)
{
	struct zebra_vrf *zvrf;
	int ret;
	enum nexthop_types_t gtype;
	union g_addr gate;
	mpls_label_t label;
	mpls_label_t in_label, out_label;

	if (!mpls_enabled) {
		vty_out(vty,
			"%% MPLS not turned on in kernel, ignoring command\n");
		return CMD_WARNING_CONFIG_FAILED;
	}

	zvrf = vrf_info_lookup(VRF_DEFAULT);
	if (!zvrf) {
		vty_out(vty, "%% Default VRF does not exist\n");
		return CMD_WARNING_CONFIG_FAILED;
	}

	if (!inlabel_str) {
		vty_out(vty, "%% No Label Information\n");
		return CMD_WARNING_CONFIG_FAILED;
	}

	out_label = MPLS_LABEL_IMPLICIT_NULL; /* as initialization */
	label = atoi(inlabel_str);
	if (!IS_MPLS_UNRESERVED_LABEL(label)) {
		vty_out(vty, "%% Invalid label\n");
		return CMD_WARNING_CONFIG_FAILED;
	}

	if (add_cmd) {
		if (!gate_str) {
			vty_out(vty, "%% No Nexthop Information\n");
			return CMD_WARNING_CONFIG_FAILED;
		}
		if (!outlabel_str) {
			vty_out(vty, "%% No Outgoing label Information\n");
			return CMD_WARNING_CONFIG_FAILED;
		}
	}

	in_label = label;
	gtype = NEXTHOP_TYPE_BLACKHOLE; /* as initialization */

	if (gate_str) {
		/* Gateway is a IPv4 or IPv6 nexthop. */
		ret = inet_pton(AF_INET6, gate_str, &gate.ipv6);
		if (ret)
			gtype = NEXTHOP_TYPE_IPV6;
		else {
			ret = inet_pton(AF_INET, gate_str, &gate.ipv4);
			if (ret)
				gtype = NEXTHOP_TYPE_IPV4;
			else {
				vty_out(vty, "%% Invalid nexthop\n");
				return CMD_WARNING_CONFIG_FAILED;
			}
		}
	}

	if (outlabel_str) {
		if (outlabel_str[0] == 'i')
			out_label = MPLS_LABEL_IMPLICIT_NULL;
		else if (outlabel_str[0] == 'e' && gtype == NEXTHOP_TYPE_IPV4)
			out_label = MPLS_LABEL_IPV4_EXPLICIT_NULL;
		else if (outlabel_str[0] == 'e' && gtype == NEXTHOP_TYPE_IPV6)
			out_label = MPLS_LABEL_IPV6_EXPLICIT_NULL;
		else
			out_label = atoi(outlabel_str);
	}

	if (add_cmd) {
#if defined(HAVE_CUMULUS)
		/* Check that label value is consistent. */
		if (!zebra_mpls_lsp_label_consistent(zvrf, in_label, out_label,
						     gtype, &gate, 0)) {
			vty_out(vty, "%% Label value not consistent\n");
			return CMD_WARNING_CONFIG_FAILED;
		}
#endif /* HAVE_CUMULUS */

		ret = zebra_mpls_static_lsp_add(zvrf, in_label, out_label,
						gtype, &gate, 0);
	} else
		ret = zebra_mpls_static_lsp_del(zvrf, in_label, gtype, &gate,
						0);

	if (ret) {
		vty_out(vty, "%% LSP cannot be %s\n",
			add_cmd ? "added" : "deleted");
		return CMD_WARNING_CONFIG_FAILED;
	}

	return CMD_SUCCESS;
}

DEFUN (mpls_transit_lsp,
       mpls_transit_lsp_cmd,
       "mpls lsp (16-1048575) <A.B.C.D|X:X::X:X> <(16-1048575)|explicit-null|implicit-null>",
       MPLS_STR
       "Establish label switched path\n"
       "Incoming MPLS label\n"
       "IPv4 gateway address\n"
       "IPv6 gateway address\n"
       "Outgoing MPLS label\n"
       "Use Explicit-Null label\n"
       "Use Implicit-Null label\n")
{
	return zebra_mpls_transit_lsp(vty, 1, argv[2]->arg, argv[3]->arg,
				      argv[4]->arg, NULL);
}

DEFUN (no_mpls_transit_lsp,
       no_mpls_transit_lsp_cmd,
       "no mpls lsp (16-1048575) <A.B.C.D|X:X::X:X>",
       NO_STR
       MPLS_STR
       "Establish label switched path\n"
       "Incoming MPLS label\n"
       "IPv4 gateway address\n"
       "IPv6 gateway address\n")
{
	return zebra_mpls_transit_lsp(vty, 0, argv[3]->arg, argv[4]->arg, NULL,
				      NULL);
}

ALIAS(no_mpls_transit_lsp, no_mpls_transit_lsp_out_label_cmd,
      "no mpls lsp (16-1048575) <A.B.C.D|X:X::X:X> <(16-1048575)|explicit-null|implicit-null>",
      NO_STR MPLS_STR
      "Establish label switched path\n"
      "Incoming MPLS label\n"
      "IPv4 gateway address\n"
      "IPv6 gateway address\n"
      "Outgoing MPLS label\n"
      "Use Explicit-Null label\n"
      "Use Implicit-Null label\n")

DEFUN (no_mpls_transit_lsp_all,
       no_mpls_transit_lsp_all_cmd,
       "no mpls lsp (16-1048575)",
       NO_STR
       MPLS_STR
       "Establish label switched path\n"
       "Incoming MPLS label\n")
{
	return zebra_mpls_transit_lsp(vty, 0, argv[3]->arg, NULL, NULL, NULL);
}

static int zebra_mpls_bind(struct vty *vty, int add_cmd, const char *prefix,
			   const char *label_str)
{
	struct zebra_vrf *zvrf;
	struct prefix p;
	uint32_t label;
	int ret;

	zvrf = vrf_info_lookup(VRF_DEFAULT);
	if (!zvrf) {
		vty_out(vty, "%% Default VRF does not exist\n");
		return CMD_WARNING_CONFIG_FAILED;
	}

	memset(&p, 0, sizeof(struct prefix));
	ret = str2prefix(prefix, &p);
	if (ret <= 0) {
		vty_out(vty, "%% Malformed address\n");
		return CMD_WARNING_CONFIG_FAILED;
	}

	if (add_cmd) {
		if (!label_str) {
			vty_out(vty, "%% No label binding specified\n");
			return CMD_WARNING_CONFIG_FAILED;
		}

		if (!strcmp(label_str, "implicit-null"))
			label = MPLS_LABEL_IMPLICIT_NULL;
		else if (!strcmp(label_str, "explicit-null")) {
			if (p.family == AF_INET)
				label = MPLS_LABEL_IPV4_EXPLICIT_NULL;
			else
				label = MPLS_LABEL_IPV6_EXPLICIT_NULL;
		} else {
			label = atoi(label_str);
			if (!IS_MPLS_UNRESERVED_LABEL(label)) {
				vty_out(vty, "%% Invalid label\n");
				return CMD_WARNING_CONFIG_FAILED;
			}
			if (zebra_mpls_label_already_bound(zvrf, label)) {
				vty_out(vty,
					"%% Label already bound to a FEC\n");
				return CMD_WARNING_CONFIG_FAILED;
			}
		}

		ret = zebra_mpls_static_fec_add(zvrf, &p, label);
	} else
		ret = zebra_mpls_static_fec_del(zvrf, &p);

	if (ret) {
		vty_out(vty, "%% FEC to label binding cannot be %s\n",
			add_cmd ? "added" : "deleted");
		return CMD_WARNING_CONFIG_FAILED;
	}

	return CMD_SUCCESS;
}

DEFUN (mpls_label_bind,
       mpls_label_bind_cmd,
       "mpls label bind <A.B.C.D/M|X:X::X:X/M> <(16-1048575)|implicit-null|explicit-null>",
       MPLS_STR
       "Label configuration\n"
       "Establish FEC to label binding\n"
       "IPv4 prefix\n"
       "IPv6 prefix\n"
       "MPLS Label to bind\n"
       "Use Implicit-Null Label\n"
       "Use Explicit-Null Label\n")
{
	return zebra_mpls_bind(vty, 1, argv[3]->arg, argv[4]->arg);
}

DEFUN (no_mpls_label_bind,
       no_mpls_label_bind_cmd,
       "no mpls label bind <A.B.C.D/M|X:X::X:X/M> [<(16-1048575)|implicit-null>]",
       NO_STR
       MPLS_STR
       "Label configuration\n"
       "Establish FEC to label binding\n"
       "IPv4 prefix\n"
       "IPv6 prefix\n"
       "MPLS Label to bind\n"
       "Use Implicit-Null Label\n")
{
	return zebra_mpls_bind(vty, 0, argv[4]->arg, NULL);
}

/* MPLS LSP configuration write function. */
static int zebra_mpls_config(struct vty *vty)
{
	int write = 0;
	struct zebra_vrf *zvrf;

	zvrf = vrf_info_lookup(VRF_DEFAULT);
	if (!zvrf)
		return 0;

	write += zebra_mpls_write_lsp_config(vty, zvrf);
	write += zebra_mpls_write_fec_config(vty, zvrf);
	write += zebra_mpls_write_label_block_config(vty, zvrf);
	return write;
}

DEFUN (show_mpls_fec,
       show_mpls_fec_cmd,
       "show mpls fec [<A.B.C.D/M|X:X::X:X/M>]",
       SHOW_STR
       MPLS_STR
       "MPLS FEC table\n"
       "FEC to display information about\n"
       "FEC to display information about\n")
{
	struct zebra_vrf *zvrf;
	struct prefix p;
	int ret;

	zvrf = vrf_info_lookup(VRF_DEFAULT);
	if (!zvrf)
		return 0;

	if (argc == 3)
		zebra_mpls_print_fec_table(vty, zvrf);
	else {
		memset(&p, 0, sizeof(struct prefix));
		ret = str2prefix(argv[3]->arg, &p);
		if (ret <= 0) {
			vty_out(vty, "%% Malformed address\n");
			return CMD_WARNING;
		}
		zebra_mpls_print_fec(vty, zvrf, &p);
	}

	return CMD_SUCCESS;
}

DEFUN (show_mpls_table,
       show_mpls_table_cmd,
       "show mpls table [json]",
       SHOW_STR
       MPLS_STR
       "MPLS table\n"
       JSON_STR)
{
	struct zebra_vrf *zvrf;
	uint8_t uj = use_json(argc, argv);

	zvrf = vrf_info_lookup(VRF_DEFAULT);
	zebra_mpls_print_lsp_table(vty, zvrf, uj);
	return CMD_SUCCESS;
}

DEFUN (show_mpls_table_lsp,
       show_mpls_table_lsp_cmd,
       "show mpls table (16-1048575) [json]",
       SHOW_STR
       MPLS_STR
       "MPLS table\n"
       "LSP to display information about\n"
       JSON_STR)
{
	uint32_t label;
	struct zebra_vrf *zvrf;
	uint8_t uj = use_json(argc, argv);

	zvrf = vrf_info_lookup(VRF_DEFAULT);
	label = atoi(argv[3]->arg);
	zebra_mpls_print_lsp(vty, zvrf, label, uj);
	return CMD_SUCCESS;
}

DEFUN (show_mpls_status,
       show_mpls_status_cmd,
       "show mpls status",
       SHOW_STR
       "MPLS information\n"
       "MPLS status\n")
{
	vty_out(vty, "MPLS support enabled: %s\n",
		(mpls_enabled) ? "yes"
			       : "no (mpls kernel extensions not detected)");
	return CMD_SUCCESS;
}

static int zebra_mpls_global_block(struct vty *vty, int add_cmd,
				   const char *start_label_str,
				   const char *end_label_str)
{
	int ret;
	uint32_t start_label;
	uint32_t end_label;
	struct zebra_vrf *zvrf;

	zvrf = zebra_vrf_lookup_by_id(VRF_DEFAULT);
	if (!zvrf) {
		vty_out(vty, "%% Default VRF does not exist\n");
		return CMD_WARNING_CONFIG_FAILED;
	}

	if (add_cmd) {
		if (!start_label_str || !end_label_str) {
			vty_out(vty, "%% Labels not specified\n");
			return CMD_WARNING_CONFIG_FAILED;
		}

		start_label = atoi(start_label_str);
		end_label = atoi(end_label_str);
		if (!IS_MPLS_UNRESERVED_LABEL(start_label)
		    || !IS_MPLS_UNRESERVED_LABEL(end_label)) {
			vty_out(vty, "%% Invalid label\n");
			return CMD_WARNING_CONFIG_FAILED;
		}
		if (end_label < start_label) {
			vty_out(vty, "%% End label is less than Start label\n");
			return CMD_WARNING_CONFIG_FAILED;
		}

		ret = zebra_mpls_label_block_add(zvrf, start_label, end_label);
	} else
		ret = zebra_mpls_label_block_del(zvrf);

	if (ret) {
		vty_out(vty, "%% Global label block could not be %s\n",
			add_cmd ? "added" : "deleted");
		return CMD_WARNING_CONFIG_FAILED;
	}

	return CMD_SUCCESS;
}

DEFUN (mpls_label_global_block,
       mpls_label_global_block_cmd,
       "mpls label global-block (16-1048575) (16-1048575)",
       MPLS_STR
       "Label configuration\n"
       "Configure global label block\n"
       "Start label\n"
       "End label\n")
{
	return zebra_mpls_global_block(vty, 1, argv[3]->arg, argv[4]->arg);
}

DEFUN (no_mpls_label_global_block,
       no_mpls_label_global_block_cmd,
       "no mpls label global-block [(16-1048575) (16-1048575)]",
       NO_STR
       MPLS_STR
       "Label configuration\n"
       "Configure global label block\n"
       "Start label\n"
       "End label\n")
{
	return zebra_mpls_global_block(vty, 0, NULL, NULL);
}

/* MPLS node for MPLS LSP. */
static struct cmd_node mpls_node = {MPLS_NODE, "", 1};

/* MPLS VTY.  */
void zebra_mpls_vty_init(void)
{
	install_element(VIEW_NODE, &show_mpls_status_cmd);

	install_node(&mpls_node, zebra_mpls_config);

	install_element(CONFIG_NODE, &mpls_transit_lsp_cmd);
	install_element(CONFIG_NODE, &no_mpls_transit_lsp_cmd);
	install_element(CONFIG_NODE, &no_mpls_transit_lsp_out_label_cmd);
	install_element(CONFIG_NODE, &no_mpls_transit_lsp_all_cmd);

	install_element(CONFIG_NODE, &mpls_label_bind_cmd);
	install_element(CONFIG_NODE, &no_mpls_label_bind_cmd);

	install_element(CONFIG_NODE, &mpls_label_global_block_cmd);
	install_element(CONFIG_NODE, &no_mpls_label_global_block_cmd);

	install_element(VIEW_NODE, &show_mpls_table_cmd);
	install_element(VIEW_NODE, &show_mpls_table_lsp_cmd);
	install_element(VIEW_NODE, &show_mpls_fec_cmd);
}
