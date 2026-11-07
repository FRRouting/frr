// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * EVPN bridge-port protection FPM wire codec.
 *
 * Copyright (C) 2026 Cisco Systems, Inc.
 */

#ifndef _FRR_FPM_BPP_H
#define _FRR_FPM_BPP_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <sys/types.h>

#include <linux/netlink.h>
#include <netinet/in.h>

#define FPM_BPP_ESI_LEN		10U
#define FPM_BPP_MAX_MEMBERS	510U
#define FPM_BPP_MEMBER_TYPE_L3	1U
#define FPM_BPP_NH_TYPE		4U
#define FPM_BPP_NHG_TYPE	8U
#define FPM_BPP_ID_TYPE(id)	(((uint32_t)(id) >> 28) & 0xfU)
#define FPM_BPP_MSG_BINDING_ADD 147U
#define FPM_BPP_MSG_BINDING_DEL 148U
#define FPM_BPP_MSG_MEMBER_ADD	149U
#define FPM_BPP_MSG_MEMBER_DEL	150U
#define FPM_BPP_MSG_GROUP_ADD	151U
#define FPM_BPP_MSG_GROUP_DEL	152U
#define FPM_BPP_MSG_REPLAY_DONE 153U

struct fpm_bpp_member {
	uint32_t nh_id;
	uint8_t type;
	uint8_t family;
	union {
		struct in_addr ip4;
		struct in6_addr ip6;
	} vtep;
	uint8_t rmac[6];
};

struct fpm_bpp_group {
	uint32_t nhg_id;
	uint32_t count;
	uint8_t esi[FPM_BPP_ESI_LEN];
	struct fpm_bpp_member members[];
};

struct fpm_bpp_binding {
	int ifindex;
	uint32_t backup_nhg_id;
};

#ifdef __cplusplus
#define FPM_BPP_STATIC_ASSERT static_assert
#else
#define FPM_BPP_STATIC_ASSERT _Static_assert
#endif

FPM_BPP_STATIC_ASSERT(sizeof(struct fpm_bpp_member) == 32, "FPM BPP Member ABI size");
FPM_BPP_STATIC_ASSERT(offsetof(struct fpm_bpp_member, type) == 4, "FPM BPP Member type offset");
FPM_BPP_STATIC_ASSERT(offsetof(struct fpm_bpp_member, family) == 5, "FPM BPP Member family offset");
FPM_BPP_STATIC_ASSERT(offsetof(struct fpm_bpp_member, vtep) == 8, "FPM BPP Member VTEP offset");
FPM_BPP_STATIC_ASSERT(offsetof(struct fpm_bpp_member, rmac) == 24, "FPM BPP Member RMAC offset");
FPM_BPP_STATIC_ASSERT(sizeof(struct fpm_bpp_group) == 20, "FPM BPP Group ABI size");
FPM_BPP_STATIC_ASSERT(offsetof(struct fpm_bpp_group, count) == 4, "FPM BPP Group count offset");
FPM_BPP_STATIC_ASSERT(offsetof(struct fpm_bpp_group, esi) == 8, "FPM BPP Group ESI offset");
FPM_BPP_STATIC_ASSERT(offsetof(struct fpm_bpp_group, members) == 20, "FPM BPP Group Member offset");
FPM_BPP_STATIC_ASSERT(sizeof(int) == 4 && sizeof(struct fpm_bpp_binding) == 8,
		      "FPM BPP Binding ABI size");

static inline size_t fpm_bpp_group_length(uint32_t count)
{
	return sizeof(struct fpm_bpp_group) + (size_t)count * sizeof(struct fpm_bpp_member);
}

static inline ssize_t fpm_bpp_encode(uint16_t message_type, const void *payload,
				     size_t payload_length, void *buffer, size_t buffer_length)
{
	struct nlmsghdr *header = buffer;
	size_t message_length = NLMSG_SPACE(payload_length);

	if (message_length > buffer_length)
		return 0;

	memset(buffer, 0, message_length);
	header->nlmsg_len = NLMSG_LENGTH(payload_length);
	header->nlmsg_flags = NLM_F_CREATE | NLM_F_REQUEST;
	header->nlmsg_type = message_type;
	if (payload_length)
		memcpy(NLMSG_DATA(header), payload, payload_length);

	return message_length;
}

static inline ssize_t fpm_bpp_encode_member(uint16_t message_type, bool is_delete,
					    const struct fpm_bpp_member *member, void *buffer,
					    size_t buffer_length)
{
	struct fpm_bpp_member payload = {};

	if (!member || FPM_BPP_ID_TYPE(member->nh_id) != FPM_BPP_NH_TYPE)
		return -1;

	payload.nh_id = member->nh_id;
	if (!is_delete)
		payload = *member;

	return fpm_bpp_encode(message_type, &payload, sizeof(payload), buffer, buffer_length);
}

static inline ssize_t fpm_bpp_encode_group(uint16_t message_type, bool is_delete, uint32_t nhg_id,
					   const uint8_t esi[FPM_BPP_ESI_LEN],
					   const struct fpm_bpp_member *members, uint32_t count,
					   void *buffer, size_t buffer_length)
{
	struct fpm_bpp_group *payload;
	uint8_t payload_buffer[sizeof(struct fpm_bpp_group) +
			       FPM_BPP_MAX_MEMBERS * sizeof(struct fpm_bpp_member)] = {};
	size_t payload_length;
	uint32_t i;

	if (FPM_BPP_ID_TYPE(nhg_id) != FPM_BPP_NHG_TYPE)
		return -1;
	if (!is_delete && (!esi || !members || !count))
		return -1;
	if (count > FPM_BPP_MAX_MEMBERS)
		return -1;

	if (is_delete)
		count = 0;
	payload_length = fpm_bpp_group_length(count);
	payload = (struct fpm_bpp_group *)payload_buffer;
	payload->nhg_id = nhg_id;
	payload->count = count;
	if (!is_delete) {
		memcpy(payload->esi, esi, FPM_BPP_ESI_LEN);
		for (i = 0; i < count; i++) {
			if (FPM_BPP_ID_TYPE(members[i].nh_id) != FPM_BPP_NH_TYPE)
				return -1;
			if (i && members[i - 1].nh_id >= members[i].nh_id)
				return -1;
		}
		memcpy(payload->members, members, (size_t)count * sizeof(*members));
	}

	return fpm_bpp_encode(message_type, payload, payload_length, buffer, buffer_length);
}

static inline ssize_t fpm_bpp_encode_binding(uint16_t message_type, int ifindex,
					     uint32_t backup_nhg_id, void *buffer,
					     size_t buffer_length)
{
	struct fpm_bpp_binding payload = {
		.ifindex = ifindex,
		.backup_nhg_id = backup_nhg_id,
	};

	if (backup_nhg_id && FPM_BPP_ID_TYPE(backup_nhg_id) != FPM_BPP_NHG_TYPE)
		return -1;

	return fpm_bpp_encode(message_type, &payload, sizeof(payload), buffer, buffer_length);
}

static inline ssize_t fpm_bpp_encode_replay_done(uint16_t message_type, void *buffer,
						 size_t buffer_length)
{
	return fpm_bpp_encode(message_type, NULL, 0, buffer, buffer_length);
}

#undef FPM_BPP_STATIC_ASSERT

#endif /* _FRR_FPM_BPP_H */
