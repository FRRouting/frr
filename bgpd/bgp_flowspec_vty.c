/* BGP FlowSpec VTY
 * Copyright (C) 2018 6WIND
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

#include <zebra.h>
#include "command.h"

#include "bgpd/bgpd.h"
#include "bgpd/bgp_table.h"
#include "bgpd/bgp_attr.h"
#include "bgpd/bgp_ecommunity.h"
#include "bgpd/bgp_vty.h"
#include "bgpd/bgp_route.h"
#include "bgpd/bgp_aspath.h"
#include "bgpd/bgp_flowspec.h"
#include "bgpd/bgp_flowspec_util.h"
#include "bgpd/bgp_flowspec_private.h"
#include "bgpd/bgp_debug.h"
#include "bgpd/bgp_pbr.h"

/* Local Structures and variables declarations
 * This code block hosts the struct declared that host the flowspec rules
 * as well as some structure used to convert to stringx
 */

static const struct message bgp_flowspec_display_large[] = {
	{FLOWSPEC_DEST_PREFIX, "Destination Address"},
	{FLOWSPEC_SRC_PREFIX, "Source Address"},
	{FLOWSPEC_IP_PROTOCOL, "IP Protocol"},
	{FLOWSPEC_PORT, "Port"},
	{FLOWSPEC_DEST_PORT, "Destination Port"},
	{FLOWSPEC_SRC_PORT, "Source Port"},
	{FLOWSPEC_ICMP_TYPE, "ICMP Type"},
	{FLOWSPEC_ICMP_CODE, "ICMP Code"},
	{FLOWSPEC_TCP_FLAGS, "TCP Flags"},
	{FLOWSPEC_PKT_LEN, "Packet Length"},
	{FLOWSPEC_DSCP, "DSCP field"},
	{FLOWSPEC_FRAGMENT, "Packet Fragment"},
	{0}
};

static const struct message bgp_flowspec_display_min[] = {
	{FLOWSPEC_DEST_PREFIX, "to"},
	{FLOWSPEC_SRC_PREFIX, "from"},
	{FLOWSPEC_IP_PROTOCOL, "proto"},
	{FLOWSPEC_PORT, "port"},
	{FLOWSPEC_DEST_PORT, "dstp"},
	{FLOWSPEC_SRC_PORT, "srcp"},
	{FLOWSPEC_ICMP_TYPE, "type"},
	{FLOWSPEC_ICMP_CODE, "code"},
	{FLOWSPEC_TCP_FLAGS, "tcp"},
	{FLOWSPEC_PKT_LEN, "pktlen"},
	{FLOWSPEC_DSCP, "dscp"},
	{FLOWSPEC_FRAGMENT, "pktfrag"},
	{0}
};

#define	FS_STRING_UPDATE(count, ptr, format, remaining_len) do {	\
		int _len_written;					\
									\
		if (((format) == NLRI_STRING_FORMAT_DEBUG) && (count)) {\
			_len_written = snprintf((ptr), (remaining_len),	\
						", ");			\
			(remaining_len) -= _len_written;		\
			(ptr) += _len_written;				\
		} else if (((format) == NLRI_STRING_FORMAT_MIN) 	\
			   && (count)) {				\
			_len_written = snprintf((ptr), (remaining_len),	\
						" ");			\
			(remaining_len) -= _len_written;		\
			(ptr) += _len_written;				\
		}							\
		count++;						\
	} while (0)

/* Parse FLOWSPEC NLRI
 * passed return_string string has assumed length
 * BGP_FLOWSPEC_STRING_DISPLAY_MAX
 */
void bgp_fs_nlri_get_string(unsigned char *nlri_content, size_t len,
			    char *return_string, int format,
			    json_object *json_path)
{
	uint32_t offset = 0;
	int type;
	int ret = 0, error = 0;
	char *ptr = return_string;
	char local_string[BGP_FLOWSPEC_STRING_DISPLAY_MAX];
	int count = 0;
	char extra[2] = "";
	char pre_extra[2] = "";
	const struct message *bgp_flowspec_display;
	enum bgp_flowspec_util_nlri_t type_util;
	int len_string = BGP_FLOWSPEC_STRING_DISPLAY_MAX;
	int len_written;

	if (format == NLRI_STRING_FORMAT_LARGE) {
		snprintf(pre_extra, sizeof(pre_extra), "\t");
		snprintf(extra, sizeof(extra), "\n");
		bgp_flowspec_display = bgp_flowspec_display_large;
	} else
		bgp_flowspec_display = bgp_flowspec_display_min;
	/* if needed. type_util can be set to other values */
	type_util = BGP_FLOWSPEC_RETURN_STRING;
	error = 0;
	while (offset < len-1 && error >= 0) {
		type = nlri_content[offset];
		offset++;
		switch (type) {
		case FLOWSPEC_DEST_PREFIX:
		case FLOWSPEC_SRC_PREFIX:
			ret = bgp_flowspec_ip_address(
						type_util,
						nlri_content+offset,
						len - offset,
						local_string, &error);
			if (ret <= 0)
				break;
			if (json_path) {
				json_object_string_add(json_path,
				     lookup_msg(bgp_flowspec_display, type, ""),
				     local_string);
				break;
			}
			FS_STRING_UPDATE(count, ptr, format, len_string);
			len_written = snprintf(ptr, len_string, "%s%s %s%s",
					pre_extra,
					lookup_msg(bgp_flowspec_display,
						   type, ""),
					local_string, extra);
			len_string -= len_written;
			ptr += len_written;
			break;
		case FLOWSPEC_IP_PROTOCOL:
		case FLOWSPEC_PORT:
		case FLOWSPEC_DEST_PORT:
		case FLOWSPEC_SRC_PORT:
		case FLOWSPEC_ICMP_TYPE:
		case FLOWSPEC_ICMP_CODE:
			ret = bgp_flowspec_op_decode(type_util,
						     nlri_content+offset,
						     len - offset,
						     local_string, &error);
			if (ret <= 0)
				break;
			if (json_path) {
				json_object_string_add(json_path,
				     lookup_msg(bgp_flowspec_display, type, ""),
				     local_string);
				break;
			}
			FS_STRING_UPDATE(count, ptr, format, len_string);
			len_written = snprintf(ptr, len_string, "%s%s %s%s",
					pre_extra,
					lookup_msg(bgp_flowspec_display,
					type, ""),
				     local_string, extra);
			len_string -= len_written;
			ptr += len_written;
			break;
		case FLOWSPEC_TCP_FLAGS:
			ret = bgp_flowspec_bitmask_decode(
					      type_util,
					      nlri_content+offset,
					      len - offset,
					      local_string, &error);
			if (ret <= 0)
				break;
			if (json_path) {
				json_object_string_add(json_path,
				     lookup_msg(bgp_flowspec_display,
						type, ""),
				     local_string);
				break;
			}
			FS_STRING_UPDATE(count, ptr, format, len_string);
			len_written = snprintf(ptr, len_string, "%s%s %s%s",
					pre_extra,
					lookup_msg(bgp_flowspec_display,
						   type, ""),
					local_string, extra);
			len_string -= len_written;
			ptr += len_written;
			break;
		case FLOWSPEC_PKT_LEN:
		case FLOWSPEC_DSCP:
			ret = bgp_flowspec_op_decode(
						type_util,
						nlri_content + offset,
						len - offset, local_string,
						&error);
			if (ret <= 0)
				break;
			if (json_path) {
				json_object_string_add(json_path,
				    lookup_msg(bgp_flowspec_display, type, ""),
				    local_string);
				break;
			}
			FS_STRING_UPDATE(count, ptr, format, len_string);
			len_written = snprintf(ptr, len_string, "%s%s %s%s",
					pre_extra,
					lookup_msg(bgp_flowspec_display,
					type, ""),
				     local_string, extra);
			len_string -= len_written;
			ptr += len_written;
			break;
		case FLOWSPEC_FRAGMENT:
			ret = bgp_flowspec_bitmask_decode(
					      type_util,
					      nlri_content+offset,
					      len - offset,
					      local_string, &error);
			if (ret <= 0)
				break;
			if (json_path) {
				json_object_string_add(json_path,
				    lookup_msg(bgp_flowspec_display,
					       type, ""),
				    local_string);
				break;
			}
			FS_STRING_UPDATE(count, ptr, format, len_string);
			len_written = snprintf(ptr, len_string, "%s%s %s%s",
					pre_extra,
					lookup_msg(bgp_flowspec_display,
					type, ""),
					local_string, extra);
			len_string -= len_written;
			ptr += len_written;
			break;
		default:
			error = -1;
			break;
		}
		offset += ret;
	}
}

void route_vty_out_flowspec(struct vty *vty, struct prefix *p,
			    struct bgp_path_info *path, int display,
			    json_object *json_paths)
{
	struct attr *attr;
	char return_string[BGP_FLOWSPEC_STRING_DISPLAY_MAX];
	char *s;
	json_object *json_nlri_path = NULL;
	json_object *json_ecom_path = NULL;
	json_object *json_time_path = NULL;
	char timebuf[BGP_UPTIME_LEN];

	/* Print prefix */
	if (p != NULL) {
		if (p->family != AF_FLOWSPEC)
			return;
		if (json_paths) {
			if (display == NLRI_STRING_FORMAT_JSON)
				json_nlri_path = json_object_new_object();
			else
				json_nlri_path = json_paths;
		}
		if (display == NLRI_STRING_FORMAT_LARGE && path)
			vty_out(vty, "BGP flowspec entry: (flags 0x%x)\n",
				path->flags);
		bgp_fs_nlri_get_string((unsigned char *)
				       p->u.prefix_flowspec.ptr,
				       p->u.prefix_flowspec.prefixlen,
				       return_string,
				       display,
				       json_nlri_path);
		if (display == NLRI_STRING_FORMAT_LARGE)
			vty_out(vty, "%s", return_string);
		else if (display == NLRI_STRING_FORMAT_DEBUG)
			vty_out(vty, "%s", return_string);
		else if (display == NLRI_STRING_FORMAT_MIN)
			vty_out(vty, " %-30s", return_string);
		else if (json_paths && display == NLRI_STRING_FORMAT_JSON)
			json_object_array_add(json_paths, json_nlri_path);
	}
	if (!path)
		return;
	if (path->attr->ecommunity) {
		/* Print attribute */
		attr = path->attr;
		s = ecommunity_ecom2str(attr->ecommunity,
					ECOMMUNITY_FORMAT_ROUTE_MAP, 0);
		if (!s)
			return;
		if (display == NLRI_STRING_FORMAT_LARGE)
			vty_out(vty, "\t%s\n", s);
		else if (display == NLRI_STRING_FORMAT_MIN)
			vty_out(vty, "%s", s);
		else if (json_paths) {
			json_ecom_path = json_object_new_object();
			json_object_string_add(json_ecom_path,
				       "ecomlist", s);
			if (display == NLRI_STRING_FORMAT_JSON)
				json_object_array_add(json_paths,
						      json_ecom_path);
		}
		if (attr->nexthop.s_addr != 0 &&
		    display == NLRI_STRING_FORMAT_LARGE)
			vty_out(vty, "\tNLRI NH %-16s\n",
				inet_ntoa(attr->nexthop));
		XFREE(MTYPE_ECOMMUNITY_STR, s);
	}
	peer_uptime(path->uptime, timebuf, BGP_UPTIME_LEN, 0, NULL);
	if (display == NLRI_STRING_FORMAT_LARGE) {
		vty_out(vty, "\treceived for %8s\n", timebuf);
	} else if (json_paths) {
		json_time_path = json_object_new_object();
		json_object_string_add(json_time_path,
				       "time", timebuf);
		if (display == NLRI_STRING_FORMAT_JSON)
			json_object_array_add(json_paths, json_time_path);
	}
	if (display == NLRI_STRING_FORMAT_LARGE) {
		struct bgp_path_info_extra *extra =
			bgp_path_info_extra_get(path);
		bool list_began = false;

		if (extra->bgp_fs_pbr && listcount(extra->bgp_fs_pbr)) {
			struct listnode *node;
			struct bgp_pbr_match_entry *bpme;
			struct bgp_pbr_match *bpm;
			struct list *list_bpm;

			list_bpm = list_new();
			vty_out(vty, "\tinstalled in PBR");
			for (ALL_LIST_ELEMENTS_RO(extra->bgp_fs_pbr,
						  node, bpme)) {
				bpm = bpme->backpointer;
				if (listnode_lookup(list_bpm, bpm))
					continue;
				listnode_add(list_bpm, bpm);
				if (!list_began) {
					vty_out(vty, " (");
					list_began = true;
				} else
					vty_out(vty, ", ");
				vty_out(vty, "%s", bpm->ipset_name);
			}
			list_delete(&list_bpm);
		}
		if (extra->bgp_fs_iprule && listcount(extra->bgp_fs_iprule)) {
			struct listnode *node;
			struct bgp_pbr_rule *bpr;

			if (!list_began)
				vty_out(vty, "\tinstalled in PBR");
			for (ALL_LIST_ELEMENTS_RO(extra->bgp_fs_iprule,
						  node, bpr)) {
				if (!bpr->action)
					continue;
				if (!list_began) {
					vty_out(vty, " (");
					list_began = true;
				} else
					vty_out(vty, ", ");
				vty_out(vty, "-ipv4-rule %d action lookup %u-",
					bpr->priority,
					bpr->action->table_id);
			}
			if (list_began)
				vty_out(vty, ")");
			vty_out(vty, "\n");
		}
		if (!list_began)
			vty_out(vty, "\tnot installed in PBR\n");
	}
}

int bgp_show_table_flowspec(struct vty *vty, struct bgp *bgp, afi_t afi,
			    struct bgp_table *table, enum bgp_show_type type,
			    void *output_arg, bool use_json, int is_last,
			    unsigned long *output_cum, unsigned long *total_cum)
{
	struct bgp_path_info *pi;
	struct bgp_node *rn;
	unsigned long total_count = 0;
	json_object *json_paths = NULL;
	int display = NLRI_STRING_FORMAT_LARGE;

	if (type != bgp_show_type_detail)
		return CMD_SUCCESS;

	for (rn = bgp_table_top(table); rn; rn = bgp_route_next(rn)) {
		pi = bgp_node_get_bgp_path_info(rn);
		if (pi == NULL)
			continue;
		if (use_json) {
			json_paths = json_object_new_array();
			display = NLRI_STRING_FORMAT_JSON;
		}
		for (; pi; pi = pi->next) {
			total_count++;
			route_vty_out_flowspec(vty, &rn->p, pi, display,
					       json_paths);
		}
		if (use_json) {
			vty_out(vty, "%s\n",
				json_object_to_json_string_ext(
						json_paths,
						JSON_C_TO_STRING_PRETTY));
			json_object_free(json_paths);
			json_paths = NULL;
		}
	}
	if (total_count && !use_json)
		vty_out(vty,
			"\nDisplayed  %ld flowspec entries\n",
			total_count);
	return CMD_SUCCESS;
}

DEFUN (debug_bgp_flowspec,
       debug_bgp_flowspec_cmd,
       "debug bgp flowspec",
       DEBUG_STR
       BGP_STR
       "BGP allow flowspec debugging entries\n")
{
	if (vty->node == CONFIG_NODE)
		DEBUG_ON(flowspec, FLOWSPEC);
	else {
		TERM_DEBUG_ON(flowspec, FLOWSPEC);
		vty_out(vty, "BGP flowspec debugging is on\n");
	}
	return CMD_SUCCESS;
}

DEFUN (no_debug_bgp_flowspec,
       no_debug_bgp_flowspec_cmd,
       "no debug bgp flowspec",
       NO_STR
       DEBUG_STR
       BGP_STR
       "BGP allow flowspec debugging entries\n")
{
	if (vty->node == CONFIG_NODE)
		DEBUG_OFF(flowspec, FLOWSPEC);
	else {
		TERM_DEBUG_OFF(flowspec, FLOWSPEC);
		vty_out(vty, "BGP flowspec debugging is off\n");
	}
	return CMD_SUCCESS;
}

int bgp_fs_config_write_pbr(struct vty *vty, struct bgp *bgp,
			    afi_t afi, safi_t safi)
{
	struct bgp_pbr_interface *pbr_if;
	bool declare_node = false;
	struct bgp_pbr_config *bgp_pbr_cfg = bgp->bgp_pbr_cfg;
	struct bgp_pbr_interface_head *head;
	bool bgp_pbr_interface_any;

	if (!bgp_pbr_cfg || safi != SAFI_FLOWSPEC || afi != AFI_IP)
		return 0;
	head = &(bgp_pbr_cfg->ifaces_by_name_ipv4);
	bgp_pbr_interface_any = bgp_pbr_cfg->pbr_interface_any_ipv4;
	if (!RB_EMPTY(bgp_pbr_interface_head, head) ||
	     !bgp_pbr_interface_any)
		declare_node = true;
	RB_FOREACH (pbr_if, bgp_pbr_interface_head, head) {
		vty_out(vty, "  local-install %s\n", pbr_if->name);
	}
	return declare_node ? 1 : 0;
}

static int bgp_fs_local_install_interface(struct bgp *bgp,
					  const char *no, const char *ifname)
{
	struct bgp_pbr_interface *pbr_if;
	struct bgp_pbr_config *bgp_pbr_cfg = bgp->bgp_pbr_cfg;
	struct bgp_pbr_interface_head *head;
	bool *bgp_pbr_interface_any;

	if (!bgp_pbr_cfg)
		return CMD_SUCCESS;
	head = &(bgp_pbr_cfg->ifaces_by_name_ipv4);
	bgp_pbr_interface_any = &(bgp_pbr_cfg->pbr_interface_any_ipv4);
	if (no) {
		if (!ifname) {
			if (*bgp_pbr_interface_any) {
				*bgp_pbr_interface_any = false;
				/* remove all other interface list */
				bgp_pbr_reset(bgp, AFI_IP);
			}
			return CMD_SUCCESS;
		}
		pbr_if = bgp_pbr_interface_lookup(ifname, head);
		if (!pbr_if)
			return CMD_SUCCESS;
		RB_REMOVE(bgp_pbr_interface_head, head, pbr_if);
		return CMD_SUCCESS;
	}
	if (ifname) {
		pbr_if = bgp_pbr_interface_lookup(ifname, head);
		if (pbr_if)
			return CMD_SUCCESS;
		pbr_if = XCALLOC(MTYPE_TMP,
				 sizeof(struct bgp_pbr_interface));
		strlcpy(pbr_if->name, ifname, INTERFACE_NAMSIZ);
		RB_INSERT(bgp_pbr_interface_head, head, pbr_if);
		*bgp_pbr_interface_any = false;
	} else {
		/* set to default */
		if (!*bgp_pbr_interface_any) {
			/* remove all other interface list
			 */
			bgp_pbr_reset(bgp, AFI_IP);
			*bgp_pbr_interface_any = true;
		}
	}
	return CMD_SUCCESS;
}

DEFUN (bgp_fs_local_install_ifname,
	bgp_fs_local_install_ifname_cmd,
	"[no] local-install INTERFACE",
	NO_STR
	"Apply local policy routing\n"
	"Interface name\n")
{
	struct bgp *bgp = VTY_GET_CONTEXT(bgp);
	int idx = 0;
	const char *no = strmatch(argv[0]->text, "no") ? "no" : NULL;
	char *ifname = argv_find(argv, argc, "INTERFACE", &idx) ?
		argv[idx]->arg : NULL;

	return bgp_fs_local_install_interface(bgp, no, ifname);
}

extern int bgp_flowspec_display_match_per_ip(afi_t afi, struct bgp_table *rib,
					     struct prefix *match,
					     int prefix_check, struct vty *vty,
					     bool use_json,
					     json_object *json_paths)
{
	struct bgp_node *rn;
	struct prefix *prefix;
	int display = 0;

	for (rn = bgp_table_top(rib); rn; rn = bgp_route_next(rn)) {
		prefix = &rn->p;

		if (prefix->family != AF_FLOWSPEC)
			continue;

		if (bgp_flowspec_contains_prefix(prefix, match, prefix_check)) {
			route_vty_out_flowspec(
				vty, &rn->p, bgp_node_get_bgp_path_info(rn),
				use_json ? NLRI_STRING_FORMAT_JSON
					 : NLRI_STRING_FORMAT_LARGE,
				json_paths);
			display++;
		}
	}
	return display;
}

void bgp_flowspec_vty_init(void)
{
	install_element(ENABLE_NODE, &debug_bgp_flowspec_cmd);
	install_element(CONFIG_NODE, &debug_bgp_flowspec_cmd);
	install_element(ENABLE_NODE, &no_debug_bgp_flowspec_cmd);
	install_element(CONFIG_NODE, &no_debug_bgp_flowspec_cmd);
	install_element(BGP_FLOWSPECV4_NODE, &bgp_fs_local_install_ifname_cmd);
}
