/*
 * PBR - vty code
 * Copyright (C) 2018 Cumulus Networks, Inc.
 *               Donald Sharp
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
#include "vrf.h"
#include "nexthop.h"
#include "nexthop_group.h"
#include "log.h"
#include "debug.h"
#include "pbr.h"

#include "pbrd/pbr_nht.h"
#include "pbrd/pbr_map.h"
#include "pbrd/pbr_zebra.h"
#include "pbrd/pbr_vty.h"
#include "pbrd/pbr_debug.h"
#ifndef VTYSH_EXTRACT_PL
#include "pbrd/pbr_vty_clippy.c"
#endif

DEFUN_NOSH(pbr_map, pbr_map_cmd, "pbr-map WORD seq (1-700)",
	   "Create pbr-map or enter pbr-map command mode\n"
	   "The name of the PBR MAP\n"
	   "Sequence to insert in existing pbr-map entry\n"
	   "Sequence number\n")
{
	const char *pbrm_name = argv[1]->arg;
	uint32_t seqno = atoi(argv[3]->arg);
	struct pbr_map_sequence *pbrms;

	pbrms = pbrms_get(pbrm_name, seqno);
	VTY_PUSH_CONTEXT(PBRMAP_NODE, pbrms);

	return CMD_SUCCESS;
}

DEFUN_NOSH(no_pbr_map, no_pbr_map_cmd, "no pbr-map WORD [seq (1-700)]",
	   NO_STR
	   "Delete pbr-map\n"
	   "The name of the PBR MAP\n"
	   "Sequence to delete from existing pbr-map entry\n"
	   "Sequence number\n")
{
	const char *pbrm_name = argv[2]->arg;
	uint32_t seqno = 0;
	struct pbr_map *pbrm = pbrm_find(pbrm_name);
	struct pbr_map_sequence *pbrms;
	struct listnode *node, *next_node;

	if (argc > 3)
		seqno = atoi(argv[4]->arg);

	if (!pbrm) {
		vty_out(vty, "pbr-map %s not found\n", pbrm_name);
		return CMD_SUCCESS;
	}

	for (ALL_LIST_ELEMENTS(pbrm->seqnumbers, node, next_node, pbrms)) {
		if (seqno && pbrms->seqno != seqno)
			continue;

		pbr_map_delete(pbrms);
	}

	return CMD_SUCCESS;
}

DEFPY(pbr_set_table_range,
      pbr_set_table_range_cmd,
      "[no] pbr table range (10000-4294966272)$lb (10000-4294966272)$ub",
      NO_STR
      PBR_STR
      "Set table ID range\n"
      "Set table ID range\n"
      "Lower bound for table ID range\n"
      "Upper bound for table ID range\n")
{
	/* upper bound is 2^32 - 2^10 */
	int ret = CMD_WARNING;
	const int minrange = 1000;

	/* validate given bounds */
	if (lb > ub)
		vty_out(vty, "%% Lower bound must be less than upper bound\n");
	else if (ub - lb < minrange)
		vty_out(vty, "%% Range breadth must be at least %d\n", minrange);
	else {
		ret = CMD_SUCCESS;
		pbr_nht_set_tableid_range((uint32_t) lb, (uint32_t) ub);
	}

	return ret;
}


DEFPY(pbr_map_match_src, pbr_map_match_src_cmd,
	"[no] match src-ip <A.B.C.D/M|X:X::X:X/M>$prefix",
	NO_STR
	"Match the rest of the command\n"
	"Choose the src ip or ipv6 prefix to use\n"
	"v4 Prefix\n"
	"v6 Prefix\n")
{
	struct pbr_map_sequence *pbrms = VTY_GET_CONTEXT(pbr_map_sequence);

	pbrms->family = prefix->family;

	if (!no) {
		if (prefix_same(pbrms->src, prefix))
			return CMD_SUCCESS;

		if (!pbrms->src)
			pbrms->src = prefix_new();
		prefix_copy(pbrms->src, prefix);
	} else {
		prefix_free(pbrms->src);
		pbrms->src = 0;
	}

	pbr_map_check(pbrms);

	return CMD_SUCCESS;
}

DEFPY(pbr_map_match_dst, pbr_map_match_dst_cmd,
	"[no] match dst-ip <A.B.C.D/M|X:X::X:X/M>$prefix",
	NO_STR
	"Match the rest of the command\n"
	"Choose the src ip or ipv6 prefix to use\n"
	"v4 Prefix\n"
	"v6 Prefix\n")
{
	struct pbr_map_sequence *pbrms = VTY_GET_CONTEXT(pbr_map_sequence);

	pbrms->family = prefix->family;

	if (!no) {
		if (prefix_same(pbrms->dst, prefix))
			return CMD_SUCCESS;

		if (!pbrms->dst)
			pbrms->dst = prefix_new();
		prefix_copy(pbrms->dst, prefix);
	} else {
		prefix_free(pbrms->dst);
		pbrms->dst = NULL;
	}

	pbr_map_check(pbrms);

	return CMD_SUCCESS;
}

DEFPY(pbr_map_nexthop_group, pbr_map_nexthop_group_cmd,
	"[no] set nexthop-group NAME$name",
	NO_STR
	"Set for the PBR-MAP\n"
	"nexthop-group to use\n"
	"The name of the nexthop-group\n")
{
	struct pbr_map_sequence *pbrms = VTY_GET_CONTEXT(pbr_map_sequence);
	struct nexthop_group_cmd *nhgc;

	if (pbrms->nhg) {
		vty_out(vty,
			"A `set nexthop XX` command already exists, please remove that first\n");
		return CMD_WARNING_CONFIG_FAILED;
	}

	nhgc = nhgc_find(name);
	if (!nhgc) {
		vty_out(vty, "Specified nexthop-group %s does not exist\n",
			name);
		vty_out(vty, "PBR-MAP will not be applied until it is created\n");
	}

	if (no) {
		if (pbrms->nhgrp_name && strcmp(name, pbrms->nhgrp_name) == 0)
			pbr_map_delete_nexthop_group(pbrms);
		else {
			vty_out(vty,
				"Nexthop Group specified: %s does not exist to remove",
				name);
			return CMD_WARNING_CONFIG_FAILED;
		}
	} else {
		if (pbrms->nhgrp_name) {
			if (strcmp(name, pbrms->nhgrp_name) != 0) {
				vty_out(vty,
					"Please delete current nexthop group before modifying current one");
				return CMD_WARNING_CONFIG_FAILED;
			}

			return CMD_SUCCESS;
		}
		pbrms->nhgrp_name = XSTRDUP(MTYPE_TMP, name);
		pbr_map_check(pbrms);
	}

	return CMD_SUCCESS;
}

DEFPY(pbr_map_nexthop, pbr_map_nexthop_cmd,
      "[no] set nexthop <A.B.C.D|X:X::X:X>$addr [INTERFACE]$intf [nexthop-vrf NAME$name]",
      NO_STR
      "Set for the PBR-MAP\n"
      "Specify one of the nexthops in this map\n"
      "v4 Address\n"
      "v6 Address\n"
      "Interface to use\n"
      "If the nexthop is in a different vrf tell us\n"
      "The nexthop-vrf Name\n")
{
	struct pbr_map_sequence *pbrms = VTY_GET_CONTEXT(pbr_map_sequence);
	struct vrf *vrf;
	struct nexthop nhop;
	struct nexthop *nh;

	if (pbrms->nhgrp_name) {
		vty_out(vty,
			"Please unconfigure the nexthop group before adding an individual nexthop");
		return CMD_WARNING_CONFIG_FAILED;
	}

	if (name)
		vrf = vrf_lookup_by_name(name);
	else
		vrf = vrf_lookup_by_id(VRF_DEFAULT);

	if (!vrf) {
		vty_out(vty, "Specified: %s is non-existent\n", name);
		return CMD_WARNING_CONFIG_FAILED;
	}

	memset(&nhop, 0, sizeof(nhop));
	nhop.vrf_id = vrf->vrf_id;

	/*
	 * Make SA happy.  CLIPPY is not going to give us a NULL
	 * addr.
	 */
	assert(addr);
	if (addr->sa.sa_family == AF_INET) {
		nhop.gate.ipv4.s_addr = addr->sin.sin_addr.s_addr;
		if (intf) {
			nhop.type = NEXTHOP_TYPE_IPV4_IFINDEX;
			nhop.ifindex = ifname2ifindex(intf, vrf->vrf_id);
			if (nhop.ifindex == IFINDEX_INTERNAL) {
				vty_out(vty,
					"Specified Intf %s does not exist in vrf: %s\n",
					intf, vrf->name);
				return CMD_WARNING_CONFIG_FAILED;
			}
		} else
			nhop.type = NEXTHOP_TYPE_IPV4;
	} else {
		memcpy(&nhop.gate.ipv6, &addr->sin6.sin6_addr, 16);
		if (intf) {
			nhop.type = NEXTHOP_TYPE_IPV6_IFINDEX;
			nhop.ifindex = ifname2ifindex(intf, vrf->vrf_id);
			if (nhop.ifindex == IFINDEX_INTERNAL) {
				vty_out(vty,
					"Specified Intf %s does not exist in vrf: %s\n",
					intf, vrf->name);
				return CMD_WARNING_CONFIG_FAILED;
			}
		} else {
			if (IN6_IS_ADDR_LINKLOCAL(&nhop.gate.ipv6)) {
				vty_out(vty,
					"Specified a v6 LL with no interface, rejecting\n");
				return CMD_WARNING_CONFIG_FAILED;
			}
			nhop.type = NEXTHOP_TYPE_IPV6;
		}
	}

	if (pbrms->nhg)
		nh = nexthop_exists(pbrms->nhg, &nhop);
	else {
		char buf[PBR_NHC_NAMELEN];

		if (no) {
			vty_out(vty, "No nexthops to delete");
			return CMD_WARNING_CONFIG_FAILED;
		}

		pbrms->nhg = nexthop_group_new();
		pbrms->internal_nhg_name =
			XSTRDUP(MTYPE_TMP,
				pbr_nht_nexthop_make_name(pbrms->parent->name,
							  PBR_NHC_NAMELEN,
							  pbrms->seqno,
							  buf));
		nh = NULL;
	}

	if (no) {
		if (nh)
			pbr_nht_delete_individual_nexthop(pbrms);
	} else if (!nh) {

		if (pbrms->nhg->nexthop) {
			vty_out(vty,
				"If you would like more than one nexthop please use nexthop-groups");
			return CMD_WARNING_CONFIG_FAILED;
		}

		/* must be adding new nexthop since !no and !nexthop_exists */
		nh = nexthop_new();

		memcpy(nh, &nhop, sizeof(nhop));
		nexthop_add(&pbrms->nhg->nexthop, nh);

		pbr_nht_add_individual_nexthop(pbrms);
		pbr_map_check(pbrms);
	}

	return CMD_SUCCESS;
}

DEFPY (pbr_policy,
	pbr_policy_cmd,
	"[no] pbr-policy NAME$mapname",
	NO_STR
	"Policy to use\n"
	"Name of the pbr-map to apply\n")
{
	VTY_DECLVAR_CONTEXT(interface, ifp);
	struct pbr_map *pbrm, *old_pbrm;
	struct pbr_interface *pbr_ifp = ifp->info;

	pbrm = pbrm_find(mapname);

	if (!pbr_ifp) {
		/* we don't want one and we don't have one, so... */
		if (no)
			return CMD_SUCCESS;

		/* Some one could have fat fingered the interface name */
		pbr_ifp = pbr_if_new(ifp);
	}

	if (no) {
		if (strcmp(pbr_ifp->mapname, mapname) == 0) {
			pbr_ifp->mapname[0] = '\0';
			if (pbrm)
				pbr_map_interface_delete(pbrm, ifp);
		}
	} else {
		if (strcmp(pbr_ifp->mapname, "") != 0) {
			old_pbrm = pbrm_find(pbr_ifp->mapname);
			if (old_pbrm)
				pbr_map_interface_delete(old_pbrm, ifp);
		}
		snprintf(pbr_ifp->mapname, sizeof(pbr_ifp->mapname),
			 "%s", mapname);
		if (pbrm)
			pbr_map_add_interface(pbrm, ifp);
	}

	return CMD_SUCCESS;
}

DEFPY (show_pbr,
	show_pbr_cmd,
	"show pbr",
	SHOW_STR
	PBR_STR)
{
	pbr_nht_write_table_range(vty);
	pbr_nht_write_rule_range(vty);

	return CMD_SUCCESS;
}

DEFPY (show_pbr_map,
	show_pbr_map_cmd,
	"show pbr map [NAME$name] [detail$detail]",
	SHOW_STR
	PBR_STR
	"PBR Map\n"
	"PBR Map Name\n"
	"Detailed information\n")
{
	struct pbr_map_sequence *pbrms;
	struct pbr_map *pbrm;
	struct listnode *node;
	char buf[PREFIX_STRLEN];
	char rbuf[64];

	RB_FOREACH (pbrm, pbr_map_entry_head, &pbr_maps) {
		if (name && strcmp(name, pbrm->name) != 0)
			continue;

		vty_out(vty, "  pbr-map %s valid: %d\n", pbrm->name,
			pbrm->valid);

		for (ALL_LIST_ELEMENTS_RO(pbrm->seqnumbers, node, pbrms)) {
			if (pbrms->reason)
				pbr_map_reason_string(pbrms->reason, rbuf,
						      sizeof(rbuf));
			vty_out(vty,
				"    Seq: %u rule: %u Installed: %" PRIu64 "(%u) Reason: %s\n",
				pbrms->seqno, pbrms->ruleno, pbrms->installed,
				pbrms->unique, pbrms->reason ? rbuf : "Valid");

			if (pbrms->src)
				vty_out(vty, "\tSRC Match: %s\n",
					prefix2str(pbrms->src, buf,
						   sizeof(buf)));
			if (pbrms->dst)
				vty_out(vty, "\tDST Match: %s\n",
					prefix2str(pbrms->dst, buf,
						   sizeof(buf)));

			if (pbrms->nhgrp_name) {
				vty_out(vty,
					"\tNexthop-Group: %s(%u) Installed: %u(%d)\n",
					pbrms->nhgrp_name,
					pbr_nht_get_table(pbrms->nhgrp_name),
					pbrms->nhs_installed,
					pbr_nht_get_installed(
						pbrms->nhgrp_name));
			} else if (pbrms->nhg) {
				vty_out(vty, "     ");
				nexthop_group_write_nexthop(
					vty, pbrms->nhg->nexthop);
				vty_out(vty,
					"\tInstalled: %u(%d) Tableid: %d\n",
					pbrms->nhs_installed,
					pbr_nht_get_installed(
						pbrms->internal_nhg_name),
					pbr_nht_get_table(
						pbrms->internal_nhg_name));
			} else {
				vty_out(vty,
					"\tNexthop-Group: Unknown Installed: 0(0)\n");
			}
		}
	}
	return CMD_SUCCESS;
}

DEFPY(show_pbr_nexthop_group,
      show_pbr_nexthop_group_cmd,
      "show pbr nexthop-groups [WORD$word]",
      SHOW_STR
      PBR_STR
      "Nexthop Groups\n"
      "Optional Name of the nexthop group\n")
{
	pbr_nht_show_nexthop_group(vty, word);

	return CMD_SUCCESS;
}

DEFPY (show_pbr_interface,
	show_pbr_interface_cmd,
	"show pbr interface [NAME$name]",
	SHOW_STR
	PBR_STR
	"PBR Interface\n"
	"PBR Interface Name\n")
{
	struct interface *ifp;
	struct vrf *vrf;
	struct pbr_interface *pbr_ifp;

	RB_FOREACH(vrf, vrf_name_head, &vrfs_by_name) {
		FOR_ALL_INTERFACES(vrf, ifp) {
			struct pbr_map *pbrm;

			if (!ifp->info)
				continue;

			if (name && strcmp(ifp->name, name) != 0)
				continue;

			pbr_ifp = ifp->info;

			if (strcmp(pbr_ifp->mapname, "") == 0)
				continue;

			pbrm = pbrm_find(pbr_ifp->mapname);
			vty_out(vty, "  %s(%d) with pbr-policy %s", ifp->name,
				ifp->ifindex, pbr_ifp->mapname);
			if (!pbrm)
				vty_out(vty, " (map doesn't exist)");
			vty_out(vty, "\n");
		}
	}

	return CMD_SUCCESS;
}

/* PBR debugging CLI ------------------------------------------------------- */

static struct cmd_node debug_node = {DEBUG_NODE, "", 1};

DEFPY(debug_pbr,
      debug_pbr_cmd,
      "[no] debug pbr [{map$map|zebra$zebra|nht$nht|events$events}]",
      NO_STR
      DEBUG_STR
      PBR_STR
      "Policy maps\n"
      "PBRD <-> Zebra communications\n"
      "Nexthop tracking\n"
      "Events\n")
{
	uint32_t mode = DEBUG_NODE2MODE(vty->node);

	if (map)
		DEBUG_MODE_SET(&pbr_dbg_map, mode, !no);
	if (zebra)
		DEBUG_MODE_SET(&pbr_dbg_zebra, mode, !no);
	if (nht)
		DEBUG_MODE_SET(&pbr_dbg_nht, mode, !no);
	if (events)
		DEBUG_MODE_SET(&pbr_dbg_event, mode, !no);

	/* no specific debug --> act on all of them */
	if (strmatch(argv[argc - 1]->text, "pbr"))
		pbr_debug_set_all(mode, !no);

	return CMD_SUCCESS;
}

DEFUN_NOSH(show_debugging_pbr,
	   show_debugging_pbr_cmd,
	   "show debugging [pbr]",
	   SHOW_STR
	   DEBUG_STR
	   PBR_STR)
{
	vty_out(vty, "PBR debugging status:\n");

	pbr_debug_config_write_helper(vty, false);

	return CMD_SUCCESS;
}

/* ------------------------------------------------------------------------- */


static struct cmd_node interface_node = {
	INTERFACE_NODE, "%s(config-if)# ", 1 /* vtysh ? yes */
};

static int pbr_interface_config_write(struct vty *vty)
{
	struct interface *ifp;
	struct vrf *vrf;

	RB_FOREACH (vrf, vrf_name_head, &vrfs_by_name) {
		FOR_ALL_INTERFACES (vrf, ifp) {
			if (vrf->vrf_id == VRF_DEFAULT)
				vty_frame(vty, "interface %s\n", ifp->name);
			else
				vty_frame(vty, "interface %s vrf %s\n",
					  ifp->name, vrf->name);

			pbr_map_write_interfaces(vty, ifp);

			vty_endframe(vty, "!\n");
		}
	}

	return 1;
}

/* PBR map node structure. */
static struct cmd_node pbr_map_node = {PBRMAP_NODE, "%s(config-pbr-map)# ", 1};

static int pbr_vty_map_config_write_sequence(struct vty *vty,
					     struct pbr_map *pbrm,
					     struct pbr_map_sequence *pbrms)
{
	char buff[PREFIX_STRLEN];

	vty_out(vty, "pbr-map %s seq %u\n", pbrm->name, pbrms->seqno);

	if (pbrms->src)
		vty_out(vty, "  match src-ip %s\n",
			prefix2str(pbrms->src, buff, sizeof(buff)));

	if (pbrms->dst)
		vty_out(vty, "  match dst-ip %s\n",
			prefix2str(pbrms->dst, buff, sizeof(buff)));

	if (pbrms->nhgrp_name)
		vty_out(vty, "  set nexthop-group %s\n", pbrms->nhgrp_name);

	if (pbrms->nhg) {
		vty_out(vty, "  set ");
		nexthop_group_write_nexthop(vty, pbrms->nhg->nexthop);
	}

	vty_out(vty, "!\n");
	return 1;
}

static int pbr_vty_map_config_write(struct vty *vty)
{
	struct pbr_map *pbrm;

	pbr_nht_write_table_range(vty);
	pbr_nht_write_rule_range(vty);

	RB_FOREACH(pbrm, pbr_map_entry_head, &pbr_maps) {
		struct pbr_map_sequence *pbrms;
		struct listnode *node;

		for (ALL_LIST_ELEMENTS_RO(pbrm->seqnumbers, node, pbrms))
			pbr_vty_map_config_write_sequence(vty, pbrm, pbrms);
	}

	return 1;
}

void pbr_vty_init(void)
{
	install_node(&interface_node,
		     pbr_interface_config_write);
	if_cmd_init();

	install_node(&pbr_map_node,
		     pbr_vty_map_config_write);

	/* debug */
	install_node(&debug_node, pbr_debug_config_write);
	install_element(VIEW_NODE, &debug_pbr_cmd);
	install_element(CONFIG_NODE, &debug_pbr_cmd);
	install_element(VIEW_NODE, &show_debugging_pbr_cmd);

	install_default(PBRMAP_NODE);

	install_element(CONFIG_NODE, &pbr_map_cmd);
	install_element(CONFIG_NODE, &no_pbr_map_cmd);
	install_element(CONFIG_NODE, &pbr_set_table_range_cmd);
	install_element(INTERFACE_NODE, &pbr_policy_cmd);
	install_element(PBRMAP_NODE, &pbr_map_match_src_cmd);
	install_element(PBRMAP_NODE, &pbr_map_match_dst_cmd);
	install_element(PBRMAP_NODE, &pbr_map_nexthop_group_cmd);
	install_element(PBRMAP_NODE, &pbr_map_nexthop_cmd);
	install_element(VIEW_NODE, &show_pbr_cmd);
	install_element(VIEW_NODE, &show_pbr_map_cmd);
	install_element(VIEW_NODE, &show_pbr_interface_cmd);
	install_element(VIEW_NODE, &show_pbr_nexthop_group_cmd);
}
