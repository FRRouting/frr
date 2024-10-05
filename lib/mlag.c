// SPDX-License-Identifier: GPL-2.0-or-later
/* mlag generic code.
 * Copyright (C) 2018 Cumulus Networks, Inc.
 *                    Donald Sharp
 */
#include <zebra.h>

#include <mlag.h>

char *mlag_role2str(enum mlag_role role, char *buf, size_t size)
{
	switch (role) {
	case MLAG_ROLE_NONE:
		snprintf(buf, size, "NONE");
		break;
	case MLAG_ROLE_PRIMARY:
		snprintf(buf, size, "PRIMARY");
		break;
	case MLAG_ROLE_SECONDARY:
		snprintf(buf, size, "SECONDARY");
		break;
	}

	return buf;
}

char *mlag_lib_msgid_to_str(enum mlag_msg_type msg_type, char *buf, size_t size)
{
	switch (msg_type) {
	case MLAG_REGISTER:
		snprintf(buf, size, "Register");
		break;
	case MLAG_DEREGISTER:
		snprintf(buf, size, "De-Register");
		break;
	case MLAG_MROUTE_ADD:
		snprintf(buf, size, "Mroute add");
		break;
	case MLAG_MROUTE_DEL:
		snprintf(buf, size, "Mroute del");
		break;
	case MLAG_DUMP:
		snprintf(buf, size, "Mlag Replay");
		break;
	case MLAG_MROUTE_ADD_BULK:
		snprintf(buf, size, "Mroute Add Batch");
		break;
	case MLAG_MROUTE_DEL_BULK:
		snprintf(buf, size, "Mroute Del Batch");
		break;
	case MLAG_STATUS_UPDATE:
		snprintf(buf, size, "Mlag Status");
		break;
	case MLAG_VXLAN_UPDATE:
		snprintf(buf, size, "Mlag vxlan update");
		break;
	case MLAG_PEER_FRR_STATUS:
		snprintf(buf, size, "Mlag Peer FRR Status");
		break;
	case MLAG_PIM_CFG_DUMP:
		snprintf(buf, size, "Mlag Pim Configuration Dump");
		break;
	case MLAG_MSG_NONE:
		snprintf(buf, size, "Unknown %d", msg_type);
		break;
	}
	return buf;
}


int mlag_lib_decode_mlag_hdr(struct stream *s, struct mlag_msg *msg,
			     size_t *length)
{
#define LIB_MLAG_HDR_LENGTH 8
	if (s == NULL || msg == NULL)
		return -1;

	*length = stream_get_endp(s);

	if (*length < LIB_MLAG_HDR_LENGTH)
		return -1;

	*length -= LIB_MLAG_HDR_LENGTH;

	STREAM_GETL(s, msg->msg_type);
	STREAM_GETW(s, msg->data_len);
	STREAM_GETW(s, msg->msg_cnt);

	return 0;
stream_failure:
	return -1;
}

#define MLAG_MROUTE_ADD_LENGTH                                                 \
	(VRF_NAMSIZ + IFNAMSIZ + 4 + 4 + 4 + 4 + 1 + 1 + 4)

int mlag_lib_decode_mroute_add(struct stream *s, struct mlag_mroute_add *msg,
			       size_t *length)
{
	if (s == NULL || msg == NULL || *length < MLAG_MROUTE_ADD_LENGTH)
		return -1;

	STREAM_GET(msg->vrf_name, s, VRF_NAMSIZ);
	STREAM_GETL(s, msg->source_ip);
	STREAM_GETL(s, msg->group_ip);
	STREAM_GETL(s, msg->cost_to_rp);
	STREAM_GETL(s, msg->owner_id);
	STREAM_GETC(s, msg->am_i_dr);
	STREAM_GETC(s, msg->am_i_dual_active);
	STREAM_GETL(s, msg->vrf_id);
	STREAM_GET(msg->intf_name, s, IFNAMSIZ);

	return 0;
stream_failure:
	return -1;
}

#define MLAG_MROUTE_DEL_LENGTH (VRF_NAMSIZ + IFNAMSIZ + 4 + 4 + 4 + 4)

int mlag_lib_decode_mroute_del(struct stream *s, struct mlag_mroute_del *msg,
			       size_t *length)
{
	if (s == NULL || msg == NULL || *length < MLAG_MROUTE_DEL_LENGTH)
		return -1;

	STREAM_GET(msg->vrf_name, s, VRF_NAMSIZ);
	STREAM_GETL(s, msg->source_ip);
	STREAM_GETL(s, msg->group_ip);
	STREAM_GETL(s, msg->owner_id);
	STREAM_GETL(s, msg->vrf_id);
	STREAM_GET(msg->intf_name, s, IFNAMSIZ);

	return 0;
stream_failure:
	return -1;
}

int mlag_lib_decode_mlag_status(struct stream *s, struct mlag_status *msg)
{
	if (s == NULL || msg == NULL)
		return -1;

	STREAM_GET(msg->peerlink_rif, s, IFNAMSIZ);
	STREAM_GETL(s, msg->my_role);
	STREAM_GETL(s, msg->peer_state);
	return 0;
stream_failure:
	return -1;
}

int mlag_lib_decode_vxlan_update(struct stream *s, struct mlag_vxlan *msg)
{
	if (s == NULL || msg == NULL)
		return -1;

	STREAM_GETL(s, msg->anycast_ip);
	STREAM_GETL(s, msg->local_ip);
	return 0;

stream_failure:
	return -1;
}

int mlag_lib_decode_frr_status(struct stream *s, struct mlag_frr_status *msg)
{
	if (s == NULL || msg == NULL)
		return -1;

	STREAM_GETL(s, msg->frr_state);
	return 0;
stream_failure:
	return -1;
}
