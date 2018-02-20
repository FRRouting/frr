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
	{FLOWSPEC_TCP_FLAGS, "flags"},
	{FLOWSPEC_PKT_LEN, "pktlen"},
	{FLOWSPEC_DSCP, "dscp"},
	{FLOWSPEC_FRAGMENT, "pktfrag"},
	{0}
};

#define	FS_STRING_UPDATE(count, ptr, format) do {			      \
		if (((format) == NLRI_STRING_FORMAT_DEBUG) && (count)) {      \
			(ptr) += sprintf((ptr), ", ");                        \
		} else if (((format) == NLRI_STRING_FORMAT_MIN) && (count)) { \
			(ptr) += sprintf((ptr), " ");                         \
		}                                                             \
		count++;			                              \
	} while (0)

/* Parse FLOWSPEC NLRI*/
void bgp_fs_nlri_get_string(unsigned char *nlri_content, size_t len,
			    char *return_string, int format)
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

	if (format == NLRI_STRING_FORMAT_LARGE) {
		snprintf(pre_extra, sizeof(pre_extra), "\t");
		snprintf(extra, sizeof(extra), "\n");
		bgp_flowspec_display = bgp_flowspec_display_large;
	} else
		bgp_flowspec_display = bgp_flowspec_display_min;
	error = 0;
	while (offset < len-1 && error >= 0) {
		type = nlri_content[offset];
		offset++;
		switch (type) {
		case FLOWSPEC_DEST_PREFIX:
		case FLOWSPEC_SRC_PREFIX:
			ret = bgp_flowspec_ip_address(
						BGP_FLOWSPEC_RETURN_STRING,
						nlri_content+offset,
						len - offset,
						local_string, &error);
			if (ret <= 0)
				break;
			FS_STRING_UPDATE(count, ptr, format);
			ptr += sprintf(ptr, "%s%s %s%s", pre_extra,
				     lookup_msg(bgp_flowspec_display, type, ""),
				     local_string, extra);
			break;
		case FLOWSPEC_IP_PROTOCOL:
		case FLOWSPEC_PORT:
		case FLOWSPEC_DEST_PORT:
		case FLOWSPEC_SRC_PORT:
		case FLOWSPEC_ICMP_TYPE:
		case FLOWSPEC_ICMP_CODE:
			ret = bgp_flowspec_op_decode(BGP_FLOWSPEC_RETURN_STRING,
						     nlri_content+offset,
						     len - offset,
						     local_string, &error);
			if (ret <= 0)
				break;
			FS_STRING_UPDATE(count, ptr, format);
			ptr += sprintf(ptr, "%s%s %s%s", pre_extra,
				     lookup_msg(bgp_flowspec_display,
						type, ""),
				     local_string, extra);
			break;
		case FLOWSPEC_TCP_FLAGS:
			ret = bgp_flowspec_tcpflags_decode(
					      BGP_FLOWSPEC_RETURN_STRING,
					      nlri_content+offset,
					      len - offset,
					      local_string, &error);
			if (ret <= 0)
				break;
			FS_STRING_UPDATE(count, ptr, format);
			ptr += sprintf(ptr, "%s%s %s%s", pre_extra,
				     lookup_msg(bgp_flowspec_display, type, ""),
				     local_string, extra);
			break;
		case FLOWSPEC_PKT_LEN:
		case FLOWSPEC_DSCP:
			ret = bgp_flowspec_op_decode(
						BGP_FLOWSPEC_RETURN_STRING,
						nlri_content + offset,
						len - offset, local_string,
						&error);
			if (ret <= 0)
				break;
			FS_STRING_UPDATE(count, ptr, format);
			ptr += sprintf(ptr, "%s%s %s%s", pre_extra,
				     lookup_msg(bgp_flowspec_display,
						type, ""),
				     local_string, extra);
			break;
		case FLOWSPEC_FRAGMENT:
			ret = bgp_flowspec_fragment_type_decode(
						BGP_FLOWSPEC_RETURN_STRING,
						nlri_content + offset,
						len - offset, local_string,
						&error);
			if (ret <= 0)
				break;
			FS_STRING_UPDATE(count, ptr, format);
			ptr += sprintf(ptr, "%s%s %s%s", pre_extra,
				     lookup_msg(bgp_flowspec_display,
						type, ""),
				     local_string, extra);
			break;
		default:
			error = -1;
			break;
		}
		offset += ret;
	}
}

void route_vty_out_flowspec(struct vty *vty, struct prefix *p,
			    struct bgp_info *binfo,
			    int display, json_object *json_paths)
{
	struct attr *attr;
	char return_string[BGP_FLOWSPEC_STRING_DISPLAY_MAX];
	char *s;

	/* Print prefix */
	if (p != NULL) {
		if (p->family != AF_FLOWSPEC)
			return;
		if (display == NLRI_STRING_FORMAT_LARGE)
			vty_out(vty, "BGP flowspec entry: (flags 0x%x)\n",
				binfo->flags);
		bgp_fs_nlri_get_string((unsigned char *)
				       p->u.prefix_flowspec.ptr,
				       p->u.prefix_flowspec.prefixlen,
				       return_string,
				       display);
		if (display == NLRI_STRING_FORMAT_LARGE)
			vty_out(vty, "%s", return_string);
		else if (display == NLRI_STRING_FORMAT_DEBUG)
			vty_out(vty, "%s", return_string);
		else
			vty_out(vty, " %-30s", return_string);
	}
	if (!binfo)
		return;
	if (binfo->attr && binfo->attr->ecommunity) {
		/* Print attribute */
		attr = binfo->attr;
		s = ecommunity_ecom2str(attr->ecommunity,
					ECOMMUNITY_FORMAT_ROUTE_MAP, 0);
		if (!s)
			return;
		if (display == NLRI_STRING_FORMAT_LARGE)
			vty_out(vty, "\t%s\n", s);
		else
			vty_out(vty, "%s", s);
		XFREE(MTYPE_ECOMMUNITY_STR, s);
	}
	if (display == NLRI_STRING_FORMAT_LARGE) {
		char timebuf[BGP_UPTIME_LEN];

		vty_out(vty, "\tup for %8s\n",
			peer_uptime(binfo->uptime, timebuf, BGP_UPTIME_LEN,
				    0, NULL));
	}

}

int bgp_show_table_flowspec(struct vty *vty, struct bgp *bgp, afi_t afi,
			    struct bgp_table *table, enum bgp_show_type type,
			    void *output_arg, uint8_t use_json,
			    int is_last, unsigned long *output_cum,
			    unsigned long *total_cum)
{
	struct bgp_info *ri;
	struct bgp_node *rn;
	unsigned long total_count = 0;
	json_object *json_paths = NULL;
	int display;

	if (type != bgp_show_type_detail)
		return CMD_SUCCESS;

	display = NLRI_STRING_FORMAT_LARGE;
	if (use_json) /* XXX */
		return CMD_SUCCESS;
	for (rn = bgp_table_top(table); rn; rn = bgp_route_next(rn)) {
		if (rn->info == NULL)
			continue;
		for (ri = rn->info; ri; ri = ri->next) {
			total_count++;
			route_vty_out_flowspec(vty, &rn->p,
					       ri, display,
					       json_paths);

		}
	}
	if (total_count)
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

void bgp_flowspec_vty_init(void)
{
	install_element(ENABLE_NODE, &debug_bgp_flowspec_cmd);
	install_element(CONFIG_NODE, &debug_bgp_flowspec_cmd);
	install_element(ENABLE_NODE, &no_debug_bgp_flowspec_cmd);
	install_element(CONFIG_NODE, &no_debug_bgp_flowspec_cmd);
}
