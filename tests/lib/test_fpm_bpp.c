// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * EVPN bridge-port protection FPM wire codec tests.
 *
 * Copyright (C) 2026 Cisco Systems, Inc.
 */

#include <zebra.h>

#include "fpm/fpm.h"
#include "fpm/fpm_bpp.h"

enum {
	FPM_BPP_BINDING_ADD = 147,
	FPM_BPP_BINDING_DEL = 148,
	FPM_BPP_MEMBER_ADD = 149,
	FPM_BPP_MEMBER_DEL = 150,
	FPM_BPP_GROUP_ADD = 151,
	FPM_BPP_GROUP_DEL = 152,
	FPM_BPP_REPLAY_DONE = 153,
};

struct sonic_bpp_standin {
	struct fpm_bpp_member members[4];
	size_t member_count;
	uint32_t group_id;
	uint32_t group_members[4];
	size_t group_member_count;
	uint32_t pending_group_id;
	uint32_t pending_group_members[4];
	size_t pending_group_member_count;
	int ifindex;
	uint32_t binding_group_id;
	int pending_ifindex;
	uint32_t pending_binding_group_id;
	uint32_t replay_done_count;
};

static size_t fpm_frame(const void *netlink, size_t netlink_length, uint8_t *frame,
			size_t frame_length)
{
	fpm_msg_hdr_t *header = (fpm_msg_hdr_t *)frame;
	size_t length = FPM_MSG_HDR_LEN + netlink_length;

	assert(length <= frame_length);
	header->version = FPM_PROTO_VERSION;
	header->msg_type = FPM_MSG_TYPE_NETLINK;
	header->msg_len = htons(length);
	memcpy(fpm_msg_data(header), netlink, netlink_length);
	return length;
}

static struct fpm_bpp_member *standin_member(struct sonic_bpp_standin *state, uint32_t id)
{
	size_t i;

	for (i = 0; i < state->member_count; i++)
		if (state->members[i].nh_id == id)
			return &state->members[i];
	return NULL;
}

static void standin_reconcile(struct sonic_bpp_standin *state)
{
	size_t i;

	if (state->pending_group_id) {
		for (i = 0; i < state->pending_group_member_count; i++)
			if (!standin_member(state, state->pending_group_members[i]))
				break;
		if (i == state->pending_group_member_count) {
			state->group_id = state->pending_group_id;
			state->group_member_count = state->pending_group_member_count;
			memcpy(state->group_members, state->pending_group_members,
			       i * sizeof(state->group_members[0]));
			state->pending_group_id = 0;
			state->pending_group_member_count = 0;
		}
	}

	if (state->pending_binding_group_id == state->group_id) {
		state->ifindex = state->pending_ifindex;
		state->binding_group_id = state->pending_binding_group_id;
		state->pending_ifindex = 0;
		state->pending_binding_group_id = 0;
	}
}

static int standin_apply(struct sonic_bpp_standin *state, const uint8_t *frame, size_t frame_length)
{
	const fpm_msg_hdr_t *fpm = (const fpm_msg_hdr_t *)frame;
	const struct nlmsghdr *netlink;
	const void *payload;
	size_t payload_length;
	const struct fpm_bpp_member *member;
	const struct fpm_bpp_group *group;
	const struct fpm_bpp_binding *binding;
	struct fpm_bpp_member *current;
	size_t i;

	if (!fpm_msg_ok(fpm, frame_length) || fpm->version != FPM_PROTO_VERSION ||
	    fpm->msg_type != FPM_MSG_TYPE_NETLINK)
		return -1;
	netlink = fpm_msg_data((fpm_msg_hdr_t *)fpm);
	if (fpm_msg_data_len(fpm) < sizeof(*netlink) ||
	    netlink->nlmsg_len > fpm_msg_data_len(fpm) || netlink->nlmsg_len < NLMSG_HDRLEN)
		return -1;
	payload = NLMSG_DATA(netlink);
	payload_length = NLMSG_PAYLOAD(netlink, 0);

	switch (netlink->nlmsg_type) {
	case FPM_BPP_MEMBER_ADD:
		if (payload_length != sizeof(*member))
			return -1;
		member = payload;
		if (FPM_BPP_ID_TYPE(member->nh_id) != FPM_BPP_NH_TYPE ||
		    member->type != FPM_BPP_MEMBER_TYPE_L3 ||
		    (member->family != AF_INET && member->family != AF_INET6))
			return -1;
		current = standin_member(state, member->nh_id);
		if (!current) {
			if (state->member_count == array_size(state->members))
				return -1;
			current = &state->members[state->member_count++];
		}
		*current = *member;
		standin_reconcile(state);
		return 0;
	case FPM_BPP_MEMBER_DEL:
		if (payload_length != sizeof(*member))
			return -1;
		member = payload;
		for (i = 0; i < state->group_member_count; i++)
			if (state->group_members[i] == member->nh_id)
				return -1;
		current = standin_member(state, member->nh_id);
		if (!current)
			return -1;
		i = current - state->members;
		state->members[i] = state->members[--state->member_count];
		return 0;
	case FPM_BPP_GROUP_ADD:
		if (payload_length < sizeof(*group))
			return -1;
		group = payload;
		if (!group->count || group->count > array_size(state->group_members) ||
		    payload_length != fpm_bpp_group_length(group->count) ||
		    FPM_BPP_ID_TYPE(group->nhg_id) != FPM_BPP_NHG_TYPE)
			return -1;
		for (i = 0; i < group->count; i++) {
			if (i && group->members[i - 1].nh_id >= group->members[i].nh_id)
				return -1;
			state->pending_group_members[i] = group->members[i].nh_id;
		}
		state->pending_group_id = group->nhg_id;
		state->pending_group_member_count = group->count;
		standin_reconcile(state);
		return 0;
	case FPM_BPP_GROUP_DEL:
		if (payload_length != sizeof(*group))
			return -1;
		group = payload;
		if (group->nhg_id != state->group_id || group->count ||
		    state->binding_group_id == group->nhg_id)
			return -1;
		state->group_id = 0;
		state->group_member_count = 0;
		return 0;
	case FPM_BPP_BINDING_ADD:
		if (payload_length != sizeof(*binding))
			return -1;
		binding = payload;
		if (FPM_BPP_ID_TYPE(binding->backup_nhg_id) != FPM_BPP_NHG_TYPE)
			return -1;
		state->pending_ifindex = binding->ifindex;
		state->pending_binding_group_id = binding->backup_nhg_id;
		standin_reconcile(state);
		return 0;
	case FPM_BPP_BINDING_DEL:
		if (payload_length != sizeof(*binding))
			return -1;
		binding = payload;
		if (binding->ifindex != state->ifindex || binding->backup_nhg_id)
			return -1;
		state->ifindex = 0;
		state->binding_group_id = 0;
		if (binding->ifindex == state->pending_ifindex) {
			state->pending_ifindex = 0;
			state->pending_binding_group_id = 0;
		}
		return 0;
	case FPM_BPP_REPLAY_DONE:
		if (payload_length || state->pending_group_id || state->pending_binding_group_id)
			return -1;
		state->replay_done_count++;
		return 0;
	default:
		return -1;
	}
}

static size_t encode_frame(ssize_t encoded, const uint8_t *netlink, uint8_t *frame)
{
	assert(encoded > 0);
	return fpm_frame(netlink, encoded, frame, FPM_MAX_MSG_LEN);
}

static void init_member(struct fpm_bpp_member *member, uint32_t id, const char *vtep,
			const uint8_t rmac[6])
{
	memset(member, 0, sizeof(*member));
	member->nh_id = id;
	member->type = FPM_BPP_MEMBER_TYPE_L3;
	member->family = strchr(vtep, ':') ? AF_INET6 : AF_INET;
	assert(inet_pton(member->family, vtep, &member->vtep) == 1);
	memcpy(member->rmac, rmac, sizeof(member->rmac));
}

static void test_codec_and_standin(void)
{
	const uint8_t rmac1[6] = { 0x02, 0, 0, 0, 0, 1 };
	const uint8_t rmac2[6] = { 0x02, 0, 0, 0, 0, 2 };
	const uint8_t rmac3[6] = { 0x02, 0, 0, 0, 0, 3 };
	const uint8_t esi[FPM_BPP_ESI_LEN] = { 3, 0x44, 0x38, 0x39, 0xff, 0xff, 1, 0, 0, 1 };
	struct fpm_bpp_member members[2];
	struct sonic_bpp_standin state = {};
	struct nlmsghdr *header;
	struct fpm_bpp_member *wire_member;
	uint8_t netlink[FPM_MAX_MSG_LEN] = {};
	uint8_t frame[FPM_MAX_MSG_LEN] = {};
	const uint32_t member1_id = 0x40000011;
	const uint32_t member2_id = 0x40000022;
	const uint32_t group_id = 0x80000033;
	ssize_t encoded;
	size_t framed;

	init_member(&members[0], member1_id, "192.0.2.1", rmac1);
	init_member(&members[1], member2_id, "2001:db8::2", rmac2);

	encoded = fpm_bpp_encode_member(FPM_BPP_MEMBER_ADD, false, &members[0], netlink,
					sizeof(netlink));
	framed = encode_frame(encoded, netlink, frame);
	header = (struct nlmsghdr *)fpm_msg_data((fpm_msg_hdr_t *)frame);
	assert(header->nlmsg_type == FPM_BPP_MEMBER_ADD);
	assert(header->nlmsg_len == NLMSG_LENGTH(sizeof(struct fpm_bpp_member)));
	wire_member = NLMSG_DATA(header);
	assert(!memcmp(wire_member, &members[0], sizeof(*wire_member)));
	assert(standin_apply(&state, frame, framed) == 0);

	encoded = fpm_bpp_encode_member(FPM_BPP_MEMBER_ADD, false, &members[1], netlink,
					sizeof(netlink));
	framed = encode_frame(encoded, netlink, frame);
	assert(standin_apply(&state, frame, framed) == 0);

	encoded = fpm_bpp_encode_group(FPM_BPP_GROUP_ADD, false, group_id, esi, members,
				       array_size(members), netlink, sizeof(netlink));
	framed = encode_frame(encoded, netlink, frame);
	assert(standin_apply(&state, frame, framed) == 0);
	assert(state.group_id == group_id);
	assert(state.group_member_count == 2);
	assert(state.group_members[0] == member1_id);
	assert(state.group_members[1] == member2_id);

	encoded = fpm_bpp_encode_binding(FPM_BPP_BINDING_ADD, 42, group_id, netlink,
					 sizeof(netlink));
	framed = encode_frame(encoded, netlink, frame);
	assert(standin_apply(&state, frame, framed) == 0);
	assert(state.ifindex == 42);
	assert(state.binding_group_id == group_id);

	encoded = fpm_bpp_encode_replay_done(FPM_BPP_REPLAY_DONE, netlink, sizeof(netlink));
	framed = encode_frame(encoded, netlink, frame);
	assert(standin_apply(&state, frame, framed) == 0);
	assert(state.replay_done_count == 1);

	memcpy(members[0].rmac, rmac3, sizeof(members[0].rmac));
	encoded = fpm_bpp_encode_member(FPM_BPP_MEMBER_ADD, false, &members[0], netlink,
					sizeof(netlink));
	framed = encode_frame(encoded, netlink, frame);
	assert(standin_apply(&state, frame, framed) == 0);
	assert(!memcmp(standin_member(&state, member1_id)->rmac, rmac3, sizeof(rmac3)));

	encoded = fpm_bpp_encode_binding(FPM_BPP_BINDING_DEL, 42, 0, netlink, sizeof(netlink));
	framed = encode_frame(encoded, netlink, frame);
	assert(standin_apply(&state, frame, framed) == 0);

	encoded = fpm_bpp_encode_group(FPM_BPP_GROUP_DEL, true, group_id, NULL, NULL, 0, netlink,
				       sizeof(netlink));
	framed = encode_frame(encoded, netlink, frame);
	assert(standin_apply(&state, frame, framed) == 0);

	encoded = fpm_bpp_encode_member(FPM_BPP_MEMBER_DEL, true, &members[0], netlink,
					sizeof(netlink));
	framed = encode_frame(encoded, netlink, frame);
	assert(standin_apply(&state, frame, framed) == 0);
	encoded = fpm_bpp_encode_member(FPM_BPP_MEMBER_DEL, true, &members[1], netlink,
					sizeof(netlink));
	framed = encode_frame(encoded, netlink, frame);
	assert(standin_apply(&state, frame, framed) == 0);
	assert(state.member_count == 0);
}

enum delivery_step {
	DELIVER_BINDING,
	DELIVER_GROUP,
	DELIVER_MEMBERS,
};

struct encoded_frame {
	uint8_t data[FPM_MAX_MSG_LEN];
	size_t length;
};

static void test_out_of_order_delivery(void)
{
	static const enum delivery_step orders[][3] = {
		{ DELIVER_BINDING, DELIVER_GROUP, DELIVER_MEMBERS },
		{ DELIVER_BINDING, DELIVER_MEMBERS, DELIVER_GROUP },
		{ DELIVER_GROUP, DELIVER_BINDING, DELIVER_MEMBERS },
		{ DELIVER_GROUP, DELIVER_MEMBERS, DELIVER_BINDING },
		{ DELIVER_MEMBERS, DELIVER_BINDING, DELIVER_GROUP },
		{ DELIVER_MEMBERS, DELIVER_GROUP, DELIVER_BINDING },
	};
	const uint8_t rmac[6] = { 0x02, 0, 0, 0, 0, 1 };
	const uint8_t esi[FPM_BPP_ESI_LEN] = { 3, 0x44, 0x38, 0x39, 0xff, 0xff, 1, 0, 0, 1 };
	const uint32_t group_id = 0x80000033;
	struct encoded_frame member_frames[2] = {};
	struct encoded_frame group_frame = {};
	struct encoded_frame binding_frame = {};
	struct encoded_frame replay_frame = {};
	struct fpm_bpp_member members[2];
	uint8_t netlink[FPM_MAX_MSG_LEN] = {};
	struct sonic_bpp_standin state;
	ssize_t encoded;
	size_t order;
	size_t step;
	size_t i;

	init_member(&members[0], 0x40000011, "192.0.2.1", rmac);
	init_member(&members[1], 0x40000022, "2001:db8::2", rmac);
	for (i = 0; i < array_size(members); i++) {
		encoded = fpm_bpp_encode_member(FPM_BPP_MEMBER_ADD, false, &members[i], netlink,
						sizeof(netlink));
		member_frames[i].length = encode_frame(encoded, netlink, member_frames[i].data);
	}
	encoded = fpm_bpp_encode_group(FPM_BPP_GROUP_ADD, false, group_id, esi, members,
				       array_size(members), netlink, sizeof(netlink));
	group_frame.length = encode_frame(encoded, netlink, group_frame.data);
	encoded = fpm_bpp_encode_binding(FPM_BPP_BINDING_ADD, 42, group_id, netlink,
					 sizeof(netlink));
	binding_frame.length = encode_frame(encoded, netlink, binding_frame.data);
	encoded = fpm_bpp_encode_replay_done(FPM_BPP_REPLAY_DONE, netlink, sizeof(netlink));
	replay_frame.length = encode_frame(encoded, netlink, replay_frame.data);

	for (order = 0; order < array_size(orders); order++) {
		memset(&state, 0, sizeof(state));
		for (step = 0; step < array_size(orders[order]); step++) {
			switch (orders[order][step]) {
			case DELIVER_BINDING:
				assert(standin_apply(&state, binding_frame.data,
						     binding_frame.length) == 0);
				break;
			case DELIVER_GROUP:
				assert(standin_apply(&state, group_frame.data,
						     group_frame.length) == 0);
				break;
			case DELIVER_MEMBERS:
				for (i = 0; i < array_size(member_frames); i++) {
					size_t index = order % 2 ? i : 1 - i;

					assert(standin_apply(&state, member_frames[index].data,
							     member_frames[index].length) == 0);
				}
				break;
			}
			if (step + 1 < array_size(orders[order]))
				assert(state.binding_group_id == 0);
		}
		assert(state.member_count == 2);
		assert(state.group_id == group_id);
		assert(state.group_member_count == 2);
		assert(state.ifindex == 42);
		assert(state.binding_group_id == group_id);
		assert(state.pending_group_id == 0);
		assert(state.pending_binding_group_id == 0);
		assert(standin_apply(&state, replay_frame.data, replay_frame.length) == 0);
		assert(state.replay_done_count == 1);
	}
}

static void test_rejections(void)
{
	const uint8_t rmac[6] = { 0x02, 0, 0, 0, 0, 1 };
	const uint8_t esi[FPM_BPP_ESI_LEN] = { 1 };
	struct fpm_bpp_member members[2];
	uint8_t netlink[FPM_MAX_MSG_LEN] = {};

	init_member(&members[0], 0x40000022, "192.0.2.1", rmac);
	init_member(&members[1], 0x40000011, "192.0.2.2", rmac);

	assert(fpm_bpp_encode_member(FPM_BPP_MEMBER_ADD, false, &members[0], netlink,
				     sizeof(struct nlmsghdr)) == 0);
	members[0].nh_id = 0x10000022;
	assert(fpm_bpp_encode_member(FPM_BPP_MEMBER_ADD, false, &members[0], netlink,
				     sizeof(netlink)) < 0);
	members[0].nh_id = 0x40000022;

	assert(fpm_bpp_encode_group(FPM_BPP_GROUP_ADD, false, 0x80000001, esi, members,
				    array_size(members), netlink, sizeof(netlink)) < 0);
	assert(fpm_bpp_encode_group(FPM_BPP_GROUP_ADD, false, 0x80000001, esi, members, 0, netlink,
				    sizeof(netlink)) < 0);
	assert(fpm_bpp_encode_group(FPM_BPP_GROUP_ADD, false, 0x20000001, esi, members, 1, netlink,
				    sizeof(netlink)) < 0);
	assert(fpm_bpp_encode_binding(FPM_BPP_BINDING_ADD, 42, 0x20000001, netlink,
				      sizeof(netlink)) < 0);
}

int main(void)
{
	test_codec_and_standin();
	test_out_of_order_delivery();
	test_rejections();
	return 0;
}
