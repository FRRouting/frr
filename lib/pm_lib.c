/*
 * PM Echo - Path Monitoring lib functions
 * Copyright (C) 6WIND 2019
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

#include "command.h"
#include "memory.h"
#include "prefix.h"
#include "thread.h"
#include "stream.h"
#include "zclient.h"
#include "table.h"
#include "vty.h"
#include "pm_lib.h"

DEFINE_MTYPE_STATIC(LIB, PM_INFO, "PM info")

int pm_debug = 0;
struct pm_gbl pm_gbl;

/*
 * pm_gbl_init - Initialize the PM global structure
 */
void pm_gbl_init(void)
{
	memset(&pm_gbl, 0, sizeof(struct pm_gbl));
}

/*
 * pm_gbl_exit - Called when daemon exits
 */
void pm_gbl_exit(void)
{
	SET_FLAG(pm_gbl.flags, PM_GBL_FLAG_IN_SHUTDOWN);
}

/*
 * pm_info_create - Allocate the PM information
 */
struct pm_info *pm_info_create(void)
{
	struct pm_info *pm_info;

	pm_info = XCALLOC(MTYPE_PM_INFO, sizeof(struct pm_info));
	assert(pm_info);

	pm_info->status = PM_STATUS_UNKNOWN;
	pm_info->last_update = 0;
	return pm_info;
}

/*
 * pm_info_free - Free the PM information.
 */
void pm_info_free(struct pm_info **pm_info)
{
	if (*pm_info) {
		XFREE(MTYPE_PM_INFO, *pm_info);
		*pm_info = NULL;
	}
}

/*
 * pm_set_param - Set the configured PM paramter values
 */
void pm_set_param(struct pm_info **pm_info, uint32_t interval,
		  uint32_t timeout, uint16_t packet_size,
		  uint8_t tos_val, int *command)
{
	if (!*pm_info) {
		*pm_info = pm_info_create();
		*command = ZEBRA_PM_DEST_REGISTER;
	} else {
		if (((*pm_info)->interval != interval)
		    || ((*pm_info)->timeout != timeout)
		    || ((*pm_info)->packet_size != packet_size)
		    || ((*pm_info)->tos_val != tos_val))
			*command = ZEBRA_PM_DEST_UPDATE;
	}

	if (*command) {
		(*pm_info)->interval = interval;
		(*pm_info)->timeout = timeout;
		(*pm_info)->packet_size = packet_size;
		(*pm_info)->tos_val = tos_val;
	}
}

/*
 * pm_peer_sendmsg - Format and send a peer register/Unregister
 *                    command to Zebra to be forwarded to PM
 */
void pm_peer_sendmsg(struct zclient *zclient, struct pm_info *pm_info,
		     int family, void *dst_ip, void *src_ip, void *nh,
		     char *if_name, int command,
		     int set_flag, vrf_id_t vrf_id)
{
	struct stream *s;
	int ret, len;

	/* Individual reg/dereg messages are suppressed during shutdown. */
	if (CHECK_FLAG(pm_gbl.flags, PM_GBL_FLAG_IN_SHUTDOWN)) {
		if (pm_debug)
			zlog_debug(
				"%s: Suppressing PM peer reg/dereg messages",
				__FUNCTION__);
		return;
	}

	/* Check socket. */
	if (!zclient || zclient->sock < 0) {
		if (pm_debug)
			zlog_debug(
				"%s: Can't send PM peer register, Zebra client not "
				"established",
				__FUNCTION__);
		return;
	}

	s = zclient->obuf;
	stream_reset(s);
	zclient_create_header(s, command, vrf_id);

	stream_putl(s, getpid());

	stream_putw(s, family);
	switch (family) {
	case AF_INET:
		stream_put_in_addr(s, (struct in_addr *)dst_ip);
		break;
	case AF_INET6:
		stream_put(s, dst_ip, 16);
		break;
	default:
		break;
	}

	if (command != ZEBRA_PM_DEST_DEREGISTER) {
		stream_putl(s, pm_info->interval);
		stream_putl(s, pm_info->timeout);
		stream_putw(s, pm_info->packet_size);
		stream_putc(s, pm_info->tos_val);
	}
	if (src_ip) {
		stream_putw(s, family);
		if (family == AF_INET6)
			stream_put(s, src_ip, 16);
		else
			stream_put_in_addr(s, (struct in_addr *)src_ip);
	} else
		stream_putw(s, 0);
	if (if_name) {
		len = strlen(if_name);
		stream_putc(s, len);
		stream_put(s, if_name, len);
	} else
		stream_putc(s, 0);

	if (nh) {
		stream_putw(s, family);
		if (family == AF_INET6)
			stream_put(s, nh, 16);
		else
			stream_put_in_addr(s, (struct in_addr *)nh);
	} else
		stream_putw(s, 0);

	stream_putw_at(s, 0, stream_get_endp(s));

	ret = zclient_send_message(zclient);

	if (ret < 0) {
		if (pm_debug)
			zlog_debug(
				"pm_peer_sendmsg: zclient_send_message() failed");
		return;
	}

	if (set_flag) {
		if (command == ZEBRA_PM_DEST_REGISTER)
			SET_FLAG(pm_info->flags, PM_FLAG_PM_REG);
		else if (command == ZEBRA_PM_DEST_DEREGISTER)
			UNSET_FLAG(pm_info->flags, PM_FLAG_PM_REG);
	}

	return;
}

/*
 * pm_get_command_dbg_str - Convert command to a debug string.
 */
const char *pm_get_command_dbg_str(int command)
{
	switch (command) {
	case ZEBRA_PM_DEST_REGISTER:
		return "Register";
	case ZEBRA_PM_DEST_DEREGISTER:
		return "Deregister";
	case ZEBRA_PM_DEST_UPDATE:
		return "Update";
	default:
		return "Unknown";
	}
}

/*
 * pm_get_peer_info - Extract the Peer information for which the PM session
 *                     went down from the message sent from Zebra to clients.
 */
struct interface *pm_get_peer_info(struct stream *s, struct prefix *dp,
				   struct prefix *sp, int *status, vrf_id_t vrf_id)
{
	unsigned int ifindex;
	struct interface *ifp = NULL;
	int plen;

	/* Get interface index. */
	ifindex = stream_getl(s);

	/* Lookup index. */
	if (ifindex != 0) {
		ifp = if_lookup_by_index(ifindex, vrf_id);
		if (ifp == NULL) {
			if (pm_debug)
				zlog_debug(
					"zebra_interface_pm_read: "
					"Can't find interface by ifindex: %d ",
					ifindex);
			return NULL;
		}
	}

	/* Fetch destination address. */
	dp->family = stream_getw(s);
	plen = prefix_blen(dp);
	stream_get(&dp->u.prefix, s, plen);
	dp->prefixlen = stream_getc(s);

	/* Get PM status. */
	*status = stream_getl(s);

	if (sp) {
		sp->family = stream_getw(s);

		if (sp->family == AF_INET ||
		    sp->family == AF_INET6) {
			plen = prefix_blen(sp);
			stream_get(&sp->u.prefix, s, plen);
			sp->prefixlen = stream_getc(s);
		} else
			memset(sp, 0, sizeof(struct prefix));
	}
	return ifp;
}

/*
 * pm_get_status_str - Convert PM status to a display string.
 */
const char *pm_get_status_str(int status)
{
	switch (status) {
	case PM_STATUS_DOWN:
		return "Down";
	case PM_STATUS_UP:
		return "Up";
	case PM_STATUS_UNKNOWN:
	default:
		return "Unknown";
	}
}

/*
 * pm_last_update - Calculate the last PM update time and convert it
 *                   into a dd:hh:mm:ss display format.
 */
static void pm_last_update(time_t last_update, char *buf, size_t len)
{
	time_t curr;
	time_t diff;
	struct tm *tm;
	struct timeval tv;

	/* If no PM satatus update has ever been received, print `never'. */
	if (last_update == 0) {
		snprintf(buf, len, "never");
		return;
	}

	/* Get current time. */
	monotime(&tv);
	curr = tv.tv_sec;
	diff = curr - last_update;
	tm = gmtime(&diff);

	snprintf(buf, len, "%d:%02d:%02d:%02d", tm->tm_yday, tm->tm_hour,
		 tm->tm_min, tm->tm_sec);
}

/*
 * pm_show_param - Show the PM parameter information.
 */
static void pm_show_param(struct vty *vty, struct pm_info *pm_info,
			  int extra_space, bool use_json, json_object *json_obj)
{
	json_object *json_pm = NULL;

	if (!pm_info)
		return;

	if (use_json) {
		json_pm = json_obj;

		json_object_int_add(json_pm, "interval",
				    pm_info->interval);
		json_object_int_add(json_pm, "timeout",
				    pm_info->timeout);
		json_object_int_add(json_pm, "packet_size",
				    pm_info->packet_size);
		json_object_int_add(json_pm, "tos_val",
				    pm_info->tos_val);
	} else {
		vty_out(vty,
			"  %s  Interval: %d, Timeout: %d"
			" Packet Size: %d, Tos val: %d\n",
			(extra_space) ? "  " : "",
			pm_info->interval, pm_info->timeout,
			pm_info->packet_size, pm_info->tos_val);
	}
}

/*
 * pm_show_status - Show the PM status information.
 */
static void pm_show_status(struct vty *vty, struct pm_info *pm_info,
			   int extra_space, bool use_json,
			   json_object *json_pm)
{
	char time_buf[32];

	if (!pm_info)
		return;

	pm_last_update(pm_info->last_update, time_buf, 32);
	if (use_json) {
		json_object_string_add(json_pm, "status",
				       pm_get_status_str(pm_info->status));
		json_object_string_add(json_pm, "lastUpdate", time_buf);
	} else {
		vty_out(vty, "  %s  Status: %s, Last update: %s\n",
			(extra_space) ? "  " : "",
			pm_get_status_str(pm_info->status), time_buf);
	}
}

/*
 * pm_show_info - Show the PM information.
 */
void pm_show_info(struct vty *vty, struct pm_info *pm_info,
		   int extra_space, bool use_json, json_object *json_obj)
{
	json_object *json_pm = NULL;

	if (!pm_info)
		return;

	pm_show_param(vty, pm_info, extra_space, use_json, json_pm);
	pm_show_status(vty, pm_info, extra_space, use_json, json_pm);

	if (use_json)
		json_object_object_add(json_obj, "peerPmInfo", json_pm);
	else
		vty_out(vty, "\n");
}

/*
 * pm_client_sendmsg - Format and send a client register
 *                    command to Zebra to be forwarded to PM
 */
void pm_client_sendmsg(struct zclient *zclient, int command,
			vrf_id_t vrf_id)
{
	struct stream *s;
	int ret;

	/* Check socket. */
	if (!zclient || zclient->sock < 0) {
		if (pm_debug)
			zlog_debug(
				"%s: Can't send PM client register, Zebra client not "
				"established",
				__FUNCTION__);
		return;
	}

	s = zclient->obuf;
	stream_reset(s);
	zclient_create_header(s, command, vrf_id);

	stream_putl(s, getpid());

	stream_putw_at(s, 0, stream_get_endp(s));

	ret = zclient_send_message(zclient);

	if (ret < 0) {
		if (pm_debug)
			zlog_debug(
				"pm_client_sendmsg %ld: zclient_send_message() failed",
				(long)getpid());
		return;
	}

	return;
}
