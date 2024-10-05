// SPDX-License-Identifier: GPL-2.0-or-later
/* BGP FlowSpec VTY
 * Copyright (C) 2018 6WIND
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
	{FLOWSPEC_FLOW_LABEL, "Packet Flow Label"},
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
	{FLOWSPEC_FLOW_LABEL, "flwlbl"},
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
			    json_object *json_path,
			    afi_t afi)
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
						local_string, &error,
						afi, NULL);
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
		case FLOWSPEC_FLOW_LABEL:
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

void route_vty_out_flowspec(struct vty *vty, const struct prefix *p,
			    struct bgp_path_info *path, int display,
			    json_object *json_paths)
{
	struct attr *attr;
	char return_string[BGP_FLOWSPEC_STRING_DISPLAY_MAX];
	char *s1 = NULL, *s2 = NULL;
	json_object *json_nlri_path = NULL;
	json_object *json_ecom_path = NULL;
	json_object *json_time_path = NULL;
	char timebuf[BGP_UPTIME_LEN];
	struct ecommunity *ipv6_ecomm = NULL;

	if (p == NULL || p->family != AF_FLOWSPEC)
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
			       json_nlri_path,
			       family2afi(p->u.prefix_flowspec
					  .family));
	if (display == NLRI_STRING_FORMAT_LARGE)
		vty_out(vty, "%s", return_string);
	else if (display == NLRI_STRING_FORMAT_DEBUG)
		vty_out(vty, "%s", return_string);
	else if (display == NLRI_STRING_FORMAT_MIN)
		vty_out(vty, " %-30s", return_string);
	else if (json_paths && display == NLRI_STRING_FORMAT_JSON)
		json_object_array_add(json_paths, json_nlri_path);
	if (!path)
		return;

	if (path->attr)
		ipv6_ecomm = bgp_attr_get_ipv6_ecommunity(path->attr);

	if (path->attr && (bgp_attr_get_ecommunity(path->attr) || ipv6_ecomm)) {
		/* Print attribute */
		attr = path->attr;
		if (bgp_attr_get_ecommunity(attr))
			s1 = ecommunity_ecom2str(bgp_attr_get_ecommunity(attr),
						 ECOMMUNITY_FORMAT_ROUTE_MAP,
						 0);
		if (ipv6_ecomm)
			s2 = ecommunity_ecom2str(
				ipv6_ecomm, ECOMMUNITY_FORMAT_ROUTE_MAP, 0);
		if (!s1 && !s2)
			return;
		if (display == NLRI_STRING_FORMAT_LARGE)
			vty_out(vty, "\t%s%s%s\n", s1 ? s1 : "",
				s2 && s1 ? " " : "", s2 ? s2 : "");
		else if (display == NLRI_STRING_FORMAT_MIN)
			vty_out(vty, "%s%s", s1 ? s1 : "", s2 ? s2 : "");
		else if (json_paths) {
			json_ecom_path = json_object_new_object();
			if (s1)
				json_object_string_add(json_ecom_path,
						       "ecomlist", s1);
			if (s2)
				json_object_string_add(json_ecom_path,
						       "ecom6list", s2);
			if (display == NLRI_STRING_FORMAT_JSON)
				json_object_array_add(json_paths,
						      json_ecom_path);
		}
		if (display == NLRI_STRING_FORMAT_LARGE) {
			char local_buff[INET6_ADDRSTRLEN];

			local_buff[0] = '\0';
			if (p->u.prefix_flowspec.family == AF_INET
			    && attr->nexthop.s_addr != INADDR_ANY)
				inet_ntop(AF_INET, &attr->nexthop.s_addr,
					  local_buff, sizeof(local_buff));
			else if (p->u.prefix_flowspec.family == AF_INET6 &&
				 attr->mp_nexthop_len != 0 &&
				 attr->mp_nexthop_len != BGP_ATTR_NHLEN_IPV4 &&
				 attr->mp_nexthop_len != BGP_ATTR_NHLEN_VPNV4)
				inet_ntop(AF_INET6, &attr->mp_nexthop_global,
					  local_buff, sizeof(local_buff));
			if (local_buff[0] != '\0')
				vty_out(vty, "\tNLRI NH %s\n",
					local_buff);
		}
		XFREE(MTYPE_ECOMMUNITY_STR, s1);
		XFREE(MTYPE_ECOMMUNITY_STR, s2);
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

		if (extra->flowspec && extra->flowspec->bgp_fs_pbr &&
		    listcount(extra->flowspec->bgp_fs_pbr)) {
			struct listnode *node;
			struct bgp_pbr_match_entry *bpme;
			struct bgp_pbr_match *bpm;
			struct list *list_bpm;

			list_bpm = list_new();
			vty_out(vty, "\tinstalled in PBR");
			for (ALL_LIST_ELEMENTS_RO(extra->flowspec->bgp_fs_pbr, node,
						  bpme)) {
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
		if (extra->flowspec && extra->flowspec->bgp_fs_iprule &&
		    listcount(extra->flowspec->bgp_fs_iprule)) {
			struct listnode *node;
			struct bgp_pbr_rule *bpr;

			if (!list_began)
				vty_out(vty, "\tinstalled in PBR");
			for (ALL_LIST_ELEMENTS_RO(extra->flowspec->bgp_fs_iprule,
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
		}
		if (list_began)
			vty_out(vty, ")\n");
		else
			vty_out(vty, "\tnot installed in PBR\n");
	}
}

int bgp_show_table_flowspec(struct vty *vty, struct bgp *bgp, afi_t afi,
			    struct bgp_table *table, enum bgp_show_type type,
			    void *output_arg, bool use_json, int is_last,
			    unsigned long *output_cum, unsigned long *total_cum)
{
	struct bgp_path_info *pi;
	struct bgp_dest *dest;
	unsigned long total_count = 0;
	json_object *json_paths = NULL;
	int display = NLRI_STRING_FORMAT_LARGE;

	if (type != bgp_show_type_detail)
		return CMD_SUCCESS;

	for (dest = bgp_table_top(table); dest; dest = bgp_route_next(dest)) {
		pi = bgp_dest_get_bgp_path_info(dest);
		if (pi == NULL)
			continue;
		if (use_json) {
			json_paths = json_object_new_array();
			display = NLRI_STRING_FORMAT_JSON;
		}
		for (; pi; pi = pi->next) {
			total_count++;
			route_vty_out_flowspec(vty, bgp_dest_get_prefix(dest),
					       pi, display, json_paths);
		}
		if (use_json) {
			vty_json(vty, json_paths);
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

	if (!bgp_pbr_cfg || safi != SAFI_FLOWSPEC)
		return 0;
	if (afi == AFI_IP) {
		head = &(bgp_pbr_cfg->ifaces_by_name_ipv4);
		bgp_pbr_interface_any = bgp_pbr_cfg->pbr_interface_any_ipv4;
	} else if (afi == AFI_IP6) {
		head = &(bgp_pbr_cfg->ifaces_by_name_ipv6);
		bgp_pbr_interface_any = bgp_pbr_cfg->pbr_interface_any_ipv6;
	} else {
		return 0;
	}
	if (!RB_EMPTY(bgp_pbr_interface_head, head) ||
	     !bgp_pbr_interface_any)
		declare_node = true;
	RB_FOREACH (pbr_if, bgp_pbr_interface_head, head) {
		vty_out(vty, "  local-install %s\n", pbr_if->name);
	}
	return declare_node ? 1 : 0;
}

static int bgp_fs_local_install_interface(struct bgp *bgp,
					  const char *no, const char *ifname,
					  afi_t afi)
{
	struct bgp_pbr_interface *pbr_if;
	struct bgp_pbr_config *bgp_pbr_cfg = bgp->bgp_pbr_cfg;
	struct bgp_pbr_interface_head *head;
	bool *bgp_pbr_interface_any;

	if (!bgp_pbr_cfg)
		return CMD_SUCCESS;
	if (afi == AFI_IP) {
		head = &(bgp_pbr_cfg->ifaces_by_name_ipv4);
		bgp_pbr_interface_any = &(bgp_pbr_cfg->pbr_interface_any_ipv4);
	} else {
		head = &(bgp_pbr_cfg->ifaces_by_name_ipv6);
		bgp_pbr_interface_any = &(bgp_pbr_cfg->pbr_interface_any_ipv6);
	}
	if (no) {
		if (!ifname) {
			if (*bgp_pbr_interface_any) {
				*bgp_pbr_interface_any = false;
				/* remove all other interface list */
				bgp_pbr_reset(bgp, afi);
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
		strlcpy(pbr_if->name, ifname, IFNAMSIZ);
		RB_INSERT(bgp_pbr_interface_head, head, pbr_if);
		*bgp_pbr_interface_any = false;
	} else {
		/* set to default */
		if (!*bgp_pbr_interface_any) {
			/* remove all other interface list
			 */
			bgp_pbr_reset(bgp, afi);
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

	return bgp_fs_local_install_interface(bgp, no, ifname,
					      bgp_node_afi(vty));
}

extern int bgp_flowspec_display_match_per_ip(afi_t afi, struct bgp_table *rib,
					     struct prefix *match,
					     int prefix_check, struct vty *vty,
					     bool use_json,
					     json_object *json_paths)
{
	struct bgp_dest *dest;
	const struct prefix *prefix;
	int display = 0;

	for (dest = bgp_table_top(rib); dest; dest = bgp_route_next(dest)) {
		prefix = bgp_dest_get_prefix(dest);

		if (prefix->family != AF_FLOWSPEC)
			continue;

		if (bgp_flowspec_contains_prefix(prefix, match, prefix_check)) {
			route_vty_out_flowspec(
				vty, prefix, bgp_dest_get_bgp_path_info(dest),
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
	install_element(BGP_FLOWSPECV6_NODE, &bgp_fs_local_install_ifname_cmd);
}
