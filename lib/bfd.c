/**
 * bfd.c: BFD handling routines
 *
 * @copyright Copyright (C) 2015 Cumulus Networks, Inc.
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

#include "command.h"
#include "memory.h"
#include "prefix.h"
#include "thread.h"
#include "stream.h"
#include "zclient.h"
#include "table.h"
#include "vty.h"
#include "bfd.h"

DEFINE_MTYPE_STATIC(LIB, BFD_INFO, "BFD info")

static int bfd_debug = 0;
static struct bfd_gbl bfd_gbl;

/*
 * bfd_gbl_init - Initialize the BFD global structure
 */
void bfd_gbl_init(void)
{
	memset(&bfd_gbl, 0, sizeof(struct bfd_gbl));
}

/*
 * bfd_gbl_exit - Called when daemon exits
 */
void bfd_gbl_exit(void)
{
	SET_FLAG(bfd_gbl.flags, BFD_GBL_FLAG_IN_SHUTDOWN);
}

/*
 * bfd_info_create - Allocate the BFD information
 */
struct bfd_info *bfd_info_create(void)
{
	struct bfd_info *bfd_info;

	bfd_info = XCALLOC(MTYPE_BFD_INFO, sizeof(struct bfd_info));
	assert(bfd_info);

	bfd_info->status = BFD_STATUS_UNKNOWN;
	bfd_info->type = BFD_TYPE_NOT_CONFIGURED;
	bfd_info->last_update = 0;
	return bfd_info;
}

/*
 * bfd_info_free - Free the BFD information.
 */
void bfd_info_free(struct bfd_info **bfd_info)
{
	XFREE(MTYPE_BFD_INFO, *bfd_info);
}

/*
 * bfd_validate_param - Validate the BFD paramter information.
 */
int bfd_validate_param(struct vty *vty, const char *dm_str, const char *rx_str,
		       const char *tx_str, uint8_t *dm_val, uint32_t *rx_val,
		       uint32_t *tx_val)
{
	*dm_val = strtoul(dm_str, NULL, 10);
	*rx_val = strtoul(rx_str, NULL, 10);
	*tx_val = strtoul(tx_str, NULL, 10);
	return CMD_SUCCESS;
}

/*
 * bfd_set_param - Set the configured BFD paramter values
 */
void bfd_set_param(struct bfd_info **bfd_info, uint32_t min_rx, uint32_t min_tx,
		   uint8_t detect_mult, int defaults, int *command)
{
	if (!*bfd_info) {
		*bfd_info = bfd_info_create();
		*command = ZEBRA_BFD_DEST_REGISTER;
	} else {
		if (((*bfd_info)->required_min_rx != min_rx)
		    || ((*bfd_info)->desired_min_tx != min_tx)
		    || ((*bfd_info)->detect_mult != detect_mult))
			*command = ZEBRA_BFD_DEST_UPDATE;
	}

	if (*command) {
		(*bfd_info)->required_min_rx = min_rx;
		(*bfd_info)->desired_min_tx = min_tx;
		(*bfd_info)->detect_mult = detect_mult;
	}

	if (!defaults)
		SET_FLAG((*bfd_info)->flags, BFD_FLAG_PARAM_CFG);
	else
		UNSET_FLAG((*bfd_info)->flags, BFD_FLAG_PARAM_CFG);
}

/*
 * bfd_peer_sendmsg - Format and send a peer register/Unregister
 *                    command to Zebra to be forwarded to BFD
 */
void bfd_peer_sendmsg(struct zclient *zclient, struct bfd_info *bfd_info,
		      int family, void *dst_ip, void *src_ip, char *if_name,
		      int ttl, int multihop, int cbit, int command,
		      int set_flag, vrf_id_t vrf_id)
{
	struct bfd_session_arg args = {};
	size_t addrlen;

	/* Individual reg/dereg messages are suppressed during shutdown. */
	if (CHECK_FLAG(bfd_gbl.flags, BFD_GBL_FLAG_IN_SHUTDOWN)) {
		if (bfd_debug)
			zlog_debug(
				"%s: Suppressing BFD peer reg/dereg messages",
				__func__);
		return;
	}

	/* Check socket. */
	if (!zclient || zclient->sock < 0) {
		if (bfd_debug)
			zlog_debug(
				"%s: Can't send BFD peer register, Zebra client not "
				"established",
				__func__);
		return;
	}

	/* Fill in all arguments. */
	args.ttl = ttl;
	args.cbit = cbit;
	args.family = family;
	args.mhop = multihop;
	args.vrf_id = vrf_id;
	args.command = command;
	args.set_flag = set_flag;
	args.bfd_info = bfd_info;
	args.min_rx = bfd_info->required_min_rx;
	args.min_tx = bfd_info->desired_min_tx;
	args.detection_multiplier = bfd_info->detect_mult;

	addrlen = family == AF_INET ? sizeof(struct in_addr)
				    : sizeof(struct in6_addr);
	memcpy(&args.dst, dst_ip, addrlen);
	if (src_ip)
		memcpy(&args.src, src_ip, addrlen);

	if (if_name)
		args.ifnamelen =
			strlcpy(args.ifname, if_name, sizeof(args.ifname));

	zclient_bfd_command(zclient, &args);
}

/*
 * bfd_get_command_dbg_str - Convert command to a debug string.
 */
const char *bfd_get_command_dbg_str(int command)
{
	switch (command) {
	case ZEBRA_BFD_DEST_REGISTER:
		return "Register";
	case ZEBRA_BFD_DEST_DEREGISTER:
		return "Deregister";
	case ZEBRA_BFD_DEST_UPDATE:
		return "Update";
	default:
		return "Unknown";
	}
}

/*
 * bfd_get_peer_info - Extract the Peer information for which the BFD session
 *                     went down from the message sent from Zebra to clients.
 */
struct interface *bfd_get_peer_info(struct stream *s, struct prefix *dp,
				    struct prefix *sp, int *status,
				    int *remote_cbit,
				    vrf_id_t vrf_id)
{
	unsigned int ifindex;
	struct interface *ifp = NULL;
	int plen;
	int local_remote_cbit;

	/* Get interface index. */
	ifindex = stream_getl(s);

	/* Lookup index. */
	if (ifindex != 0) {
		ifp = if_lookup_by_index(ifindex, vrf_id);
		if (ifp == NULL) {
			if (bfd_debug)
				zlog_debug(
					"zebra_interface_bfd_read: "
					"Can't find interface by ifindex: %d ",
					ifindex);
			return NULL;
		}
	}

	/* Fetch destination address. */
	dp->family = stream_getc(s);

	plen = prefix_blen(dp);
	stream_get(&dp->u.prefix, s, plen);
	dp->prefixlen = stream_getc(s);

	/* Get BFD status. */
	*status = stream_getl(s);

	if (sp) {
		sp->family = stream_getc(s);

		plen = prefix_blen(sp);
		stream_get(&sp->u.prefix, s, plen);
		sp->prefixlen = stream_getc(s);
	}
	local_remote_cbit = stream_getc(s);
	if (remote_cbit)
		*remote_cbit = local_remote_cbit;
	return ifp;
}

/*
 * bfd_get_status_str - Convert BFD status to a display string.
 */
const char *bfd_get_status_str(int status)
{
	switch (status) {
	case BFD_STATUS_DOWN:
		return "Down";
	case BFD_STATUS_UP:
		return "Up";
	case BFD_STATUS_ADMIN_DOWN:
		return "Admin Down";
	case BFD_STATUS_UNKNOWN:
	default:
		return "Unknown";
	}
}

/*
 * bfd_last_update - Calculate the last BFD update time and convert it
 *                   into a dd:hh:mm:ss display format.
 */
static void bfd_last_update(time_t last_update, char *buf, size_t len)
{
	time_t curr;
	time_t diff;
	struct tm tm;
	struct timeval tv;

	/* If no BFD satatus update has ever been received, print `never'. */
	if (last_update == 0) {
		snprintf(buf, len, "never");
		return;
	}

	/* Get current time. */
	monotime(&tv);
	curr = tv.tv_sec;
	diff = curr - last_update;
	gmtime_r(&diff, &tm);

	snprintf(buf, len, "%d:%02d:%02d:%02d", tm.tm_yday, tm.tm_hour,
		 tm.tm_min, tm.tm_sec);
}

/*
 * bfd_show_param - Show the BFD parameter information.
 */
void bfd_show_param(struct vty *vty, struct bfd_info *bfd_info, int bfd_tag,
		    int extra_space, bool use_json, json_object *json_obj)
{
	json_object *json_bfd = NULL;

	if (!bfd_info)
		return;

	if (use_json) {
		if (bfd_tag)
			json_bfd = json_object_new_object();
		else
			json_bfd = json_obj;

		json_object_int_add(json_bfd, "detectMultiplier",
				    bfd_info->detect_mult);
		json_object_int_add(json_bfd, "rxMinInterval",
				    bfd_info->required_min_rx);
		json_object_int_add(json_bfd, "txMinInterval",
				    bfd_info->desired_min_tx);
		if (bfd_tag)
			json_object_object_add(json_obj, "peerBfdInfo",
					       json_bfd);
	} else {
		vty_out(vty,
			"  %s%sDetect Multiplier: %d, Min Rx interval: %d,"
			" Min Tx interval: %d\n",
			(extra_space) ? "  " : "", (bfd_tag) ? "BFD: " : "  ",
			bfd_info->detect_mult, bfd_info->required_min_rx,
			bfd_info->desired_min_tx);
	}
}

/*
 * bfd_show_status - Show the BFD status information.
 */
static void bfd_show_status(struct vty *vty, struct bfd_info *bfd_info,
			    int bfd_tag, int extra_space, bool use_json,
			    json_object *json_bfd)
{
	char time_buf[32];

	if (!bfd_info)
		return;

	bfd_last_update(bfd_info->last_update, time_buf, 32);
	if (use_json) {
		json_object_string_add(json_bfd, "status",
				       bfd_get_status_str(bfd_info->status));
		json_object_string_add(json_bfd, "lastUpdate", time_buf);
	} else {
		vty_out(vty, "  %s%sStatus: %s, Last update: %s\n",
			(extra_space) ? "  " : "", (bfd_tag) ? "BFD: " : "  ",
			bfd_get_status_str(bfd_info->status), time_buf);
	}
}

/*
 * bfd_show_info - Show the BFD information.
 */
void bfd_show_info(struct vty *vty, struct bfd_info *bfd_info, int multihop,
		   int extra_space, bool use_json, json_object *json_obj)
{
	json_object *json_bfd = NULL;

	if (!bfd_info)
		return;

	if (use_json) {
		json_bfd = json_object_new_object();
		if (multihop)
			json_object_string_add(json_bfd, "type", "multi hop");
		else
			json_object_string_add(json_bfd, "type", "single hop");
	} else {
		vty_out(vty, "  %sBFD: Type: %s\n", (extra_space) ? "  " : "",
			(multihop) ? "multi hop" : "single hop");
	}

	bfd_show_param(vty, bfd_info, 0, extra_space, use_json, json_bfd);
	bfd_show_status(vty, bfd_info, 0, extra_space, use_json, json_bfd);

	if (use_json)
		json_object_object_add(json_obj, "peerBfdInfo", json_bfd);
	else
		vty_out(vty, "\n");
}

/*
 * bfd_client_sendmsg - Format and send a client register
 *                    command to Zebra to be forwarded to BFD
 */
void bfd_client_sendmsg(struct zclient *zclient, int command,
			vrf_id_t vrf_id)
{
	struct stream *s;
	int ret;

	/* Check socket. */
	if (!zclient || zclient->sock < 0) {
		if (bfd_debug)
			zlog_debug(
				"%s: Can't send BFD client register, Zebra client not "
				"established",
				__func__);
		return;
	}

	s = zclient->obuf;
	stream_reset(s);
	zclient_create_header(s, command, vrf_id);

	stream_putl(s, getpid());

	stream_putw_at(s, 0, stream_get_endp(s));

	ret = zclient_send_message(zclient);

	if (ret < 0) {
		if (bfd_debug)
			zlog_debug(
				"bfd_client_sendmsg %ld: zclient_send_message() failed",
				(long)getpid());
		return;
	}

	return;
}

int zclient_bfd_command(struct zclient *zc, struct bfd_session_arg *args)
{
	struct stream *s;
	size_t addrlen;

	/* Check socket. */
	if (!zc || zc->sock < 0) {
		if (bfd_debug)
			zlog_debug("%s: zclient unavailable", __func__);
		return -1;
	}

	s = zc->obuf;
	stream_reset(s);

	/* Create new message. */
	zclient_create_header(s, args->command, args->vrf_id);
	stream_putl(s, getpid());

	/* Encode destination address. */
	stream_putw(s, args->family);
	addrlen = (args->family == AF_INET) ? sizeof(struct in_addr)
					    : sizeof(struct in6_addr);
	stream_put(s, &args->dst, addrlen);

	/* Encode timers if this is a registration message. */
	if (args->command != ZEBRA_BFD_DEST_DEREGISTER) {
		stream_putl(s, args->min_rx);
		stream_putl(s, args->min_tx);
		stream_putc(s, args->detection_multiplier);
	}

	if (args->mhop) {
		/* Multi hop indicator. */
		stream_putc(s, 1);

		/* Multi hop always sends the source address. */
		stream_putw(s, args->family);
		stream_put(s, &args->src, addrlen);

		/* Send the expected TTL. */
		stream_putc(s, args->ttl);
	} else {
		/* Multi hop indicator. */
		stream_putc(s, 0);

		/* Single hop only sends the source address when IPv6. */
		if (args->family == AF_INET6) {
			stream_putw(s, args->family);
			stream_put(s, &args->src, addrlen);
		}

		/* Send interface name if any. */
		stream_putc(s, args->ifnamelen);
		if (args->ifnamelen)
			stream_put(s, args->ifname, args->ifnamelen);
	}

	/* Send the C bit indicator. */
	stream_putc(s, args->cbit);

	/* `ptm-bfd` doesn't support profiles yet. */
#if HAVE_BFDD > 0
	/* Send profile name if any. */
	stream_putc(s, args->profilelen);
	if (args->profilelen)
		stream_put(s, args->profile, args->profilelen);
#endif /* HAVE_BFDD */

	/* Finish the message by writing the size. */
	stream_putw_at(s, 0, stream_get_endp(s));

	/* Send message to zebra. */
	if (zclient_send_message(zc) == -1) {
		if (bfd_debug)
			zlog_debug("%s: zclient_send_message failed", __func__);
		return -1;
	}

	/* Write registration indicator into data structure. */
	if (args->set_flag) {
		if (args->command == ZEBRA_BFD_DEST_REGISTER)
			SET_FLAG(args->bfd_info->flags, BFD_FLAG_BFD_REG);
		else if (args->command == ZEBRA_BFD_DEST_DEREGISTER)
			UNSET_FLAG(args->bfd_info->flags, BFD_FLAG_BFD_REG);
	}

	return 0;
}
