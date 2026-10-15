// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Split Horizon Filter implementation
 * Copyright (c) 2026 VyOS Inc
 * Kyrylo Yatsenko
 */

#include <zebra.h>

#ifdef HAVE_NETLINK

#include "zebra/zebra_split_horizon_filter.h"
#include "zebra/kernel_netlink.h"
#include "zebra/zebra_dplane.h"

#ifdef HAVE_SPLIT_HORIZON_FILTER
#include <lib/ipaddr.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include "zebra/zebra_split_horizon_filter.bpf.h"
#include "zebra/zebra_split_horizon_filter.bpf.skel.h"
#include "zebra/debug.h"

extern struct zebra_privs_t zserv_privs;

static struct zebra_split_horizon_filter_bpf *sph_skel;

static int sph_links_cnt;

static ifindex_t sph_uplink_ifindexes[MAX_UPLINK_CNT];
static struct bpf_link *sph_uplink_links[MAX_UPLINK_CNT];

static ifindex_t sph_bond_ifindexes[MAX_ES_CNT];
static struct bpf_link *sph_bond_links[MAX_ES_CNT];

static uint32_t last_vtep_id;

/* Count of VTEP id usage, 0 - unused VTEP id */
static int vtep_id_usage_cnt[MAX_VTEP_CNT + 1];
static __be32 vtep_key_by_id[MAX_VTEP_CNT + 1];

static int sph_skel_init(void);
static void sph_check_cleanup(void);

static int get_idx_by_ifindex(ifindex_t ifindex, ifindex_t *ifindexes_array, int num);

static int get_uplink_idx(ifindex_t ifindex);
static int get_bond_idx(ifindex_t ifindex);

enum ret_value_get_or_create_vtep_id_by_ip {
	ERR_NO_SKEL = -2,
	ERR_UNSUPPORTED_IP = -3,
	ERR_FAIL_UPDATE = -4,
	ERR_NO_FREE_IDS = -5,
};

/* Returns found/created id or return code from above */
static int get_or_create_vtep_id_by_ip(const struct ipaddr *ip);

static void remove_vtep_id(uint32_t vtep_id);

static int sph_skel_init(void)
{
	if (sph_skel)
		return 0;

	frr_with_privs(&zserv_privs) {
		sph_skel = zebra_split_horizon_filter_bpf__open_and_load();
	}

	if (!sph_skel) {
		zlog_warn("%s: Split Horizon Filter: failed to open and load tcx skeleton", __func__);
		return 1;
	}

	sph_links_cnt = 0;

	return 0;
}

static void sph_check_cleanup(void)
{
	if (sph_links_cnt)
		return;

	if (!sph_skel)
		return;

	/* No bond or uplink links left, clean up everything */
	frr_with_privs(&zserv_privs) {
		zebra_split_horizon_filter_bpf__destroy(sph_skel);
	}
	sph_skel = NULL;

	last_vtep_id = 0;
	memset(vtep_id_usage_cnt, 0, sizeof(vtep_id_usage_cnt));
}

static int get_idx_by_ifindex(ifindex_t ifindex, ifindex_t *ifindexes_array, int num)
{
	for (int idx = 0; idx < num; idx++)
		if (ifindexes_array[idx] == ifindex)
			return idx;
	return -1;
}

static int get_uplink_idx(ifindex_t ifindex)
{
	return get_idx_by_ifindex(ifindex, sph_uplink_ifindexes, MAX_UPLINK_CNT);
}
static int get_bond_idx(ifindex_t ifindex)
{
	return get_idx_by_ifindex(ifindex, sph_bond_ifindexes, MAX_ES_CNT);
}

static int get_or_create_vtep_id_by_ip(const struct ipaddr *ip)
{
	uint32_t vtep_id;
	int err;

	if (!sph_skel)
		return ERR_NO_SKEL;

	if (!IS_IPADDR_V4(ip))
		return ERR_UNSUPPORTED_IP;

	/* First check if it is in map already */
	if (!bpf_map__lookup_elem(sph_skel->maps.ip_to_vtep_id,
					&ip->ip._v4_addr.s_addr,
					sizeof(__be32),
					&vtep_id,
					sizeof(uint32_t),
					0)) {
		return (int)vtep_id;
	}

	/* Select free vtep_id */
	vtep_id = last_vtep_id + 1;

	for (; vtep_id <= MAX_VTEP_CNT; vtep_id++)
		if (!vtep_id_usage_cnt[vtep_id])
			break;

	/* continue search from beginning... */
	if (vtep_id == MAX_VTEP_CNT + 1) {
		for (vtep_id = 1; vtep_id <= last_vtep_id; vtep_id++)
			if (!vtep_id_usage_cnt[vtep_id])
				break;

		if (vtep_id == last_vtep_id + 1)
			return ERR_NO_FREE_IDS;
	}

	/* Now add to map... */
	frr_with_privs(&zserv_privs) {
		err = bpf_map__update_elem(
				sph_skel->maps.ip_to_vtep_id,
				&ip->ip._v4_addr.s_addr,
				sizeof(__be32),
				&vtep_id,
				sizeof(uint32_t),
				BPF_ANY
				);
	}
	if (err) {
		zlog_warn("%s: Split Horizon Filter: failed to insert value into ip_to_vtep_id: %s", __func__, strerror(-err));
		return ERR_FAIL_UPDATE;
	}
	if (IS_ZEBRA_DEBUG_EVPN_MH_SPH)
		zlog_debug("%s: added VTEP %pIA as %"PRIu32" to ip_to_vtep_id", __func__, ip, vtep_id);

	last_vtep_id = vtep_id;
	vtep_key_by_id[vtep_id] = ip->ip._v4_addr.s_addr;
	/* vtep_id_usage_cnt[last_vtep_id] is unchanged here, it is incremented
	 * in `sph_process_br_port_msg` both for new vtep_ids and for already
	 * used
	 */
	return vtep_id;
}

static void remove_vtep_id(uint32_t vtep_id)
{
	int err;

	if (!sph_skel)
		return;

	frr_with_privs(&zserv_privs) {
		err = bpf_map__delete_elem(
			sph_skel->maps.ip_to_vtep_id,
			&vtep_key_by_id[vtep_id],
			sizeof(__be32),
			0
			);
	}
	if (err) {
		zlog_warn("%s: Split Horizon Filter: failed to delete element from ip_to_vtep_id: %s", __func__, strerror(-err));
	} else {
		if (IS_ZEBRA_DEBUG_EVPN_MH_SPH)
			zlog_debug("%s: removed VTEP ID %"PRIu32, __func__, vtep_id);
	}
}

#endif /* HAVE_SPLIT_HORIZON_FILTER */

enum netlink_msg_status
sph_process_br_port_msg(struct nl_batch *bth,
			struct zebra_dplane_ctx *ctx)
{
#ifdef HAVE_SPLIT_HORIZON_FILTER
	int err;
	int err2;
	int idx;
	uint32_t cnt;
	ifindex_t ifindex = dplane_ctx_get_ifindex(ctx);
	uint8_t is_df;
	const struct ipaddr *sph_filters;

	if (!ifindex)
		return FRR_NETLINK_SUCCESS;

	cnt = dplane_ctx_get_br_port_sph_filter_cnt(ctx);
	is_df = (dplane_ctx_get_br_port_flags(ctx) & DPLANE_BR_PORT_NON_DF) ? 0 : 1;
	sph_filters = dplane_ctx_get_br_port_sph_filters(ctx);

	if (IS_ZEBRA_DEBUG_EVPN_MH_SPH) {
		zlog_debug("%s: ifindex: %d, ifname: %s, count: %"PRIu32, __func__, dplane_ctx_get_ifindex(ctx), dplane_ctx_get_ifname(ctx), cnt);
		for (uint32_t i = 0; i < cnt; i++)
			zlog_debug("%s: sph_filters[%"PRIu32"]: %pIA", __func__, i, &sph_filters[i]);
	}

	if (!sph_skel)
		if (sph_skel_init())
			return FRR_NETLINK_ERROR;

	idx = get_bond_idx(ifindex);

	if (idx == -1) {
		idx = get_bond_idx(0);
		if (idx == -1) {
			zlog_warn("%s: Split Horizon Filter: bond number limit reached, maximum: %d, no filter will be installed for %s",
					__func__, MAX_ES_CNT, dplane_ctx_get_ifname(ctx));
			sph_check_cleanup();
			return FRR_NETLINK_ERROR;
		}

		frr_with_privs(&zserv_privs) {
			sph_bond_links[idx] = bpf_program__attach_tcx(sph_skel->progs.split_horizon_filter_bond,
								ifindex, NULL);
			err = -errno;
		}
		if (!sph_bond_links[idx]) {
			zlog_warn("%s: Split Horizon Filter: failed to attach eBPF program to %s: %s",
				__func__, dplane_ctx_get_ifname(ctx), strerror(-err));
			sph_check_cleanup();
			return FRR_NETLINK_ERROR;
		}
		sph_bond_ifindexes[idx] = ifindex;
		sph_links_cnt++;

		if (IS_ZEBRA_DEBUG_EVPN_MH_SPH)
			zlog_debug("%s: Attached bond filter to %s", __func__, dplane_ctx_get_ifname(ctx));
	}

	/* Update `is_df_on_bond`*/
	frr_with_privs(&zserv_privs) {
		err = bpf_map__update_elem(
				sph_skel->maps.is_df_on_bond,
				&ifindex,
				sizeof(ifindex),
				&is_df,
				sizeof(uint8_t),
				BPF_ANY
				);
	}
	if (IS_ZEBRA_DEBUG_EVPN_MH_SPH)
		zlog_debug("%s: setting is_df to %d for interface %d, %s", __func__, is_df, ifindex, dplane_ctx_get_ifname(ctx));
	if (err)
		zlog_warn("%s: Split Horizon Filter: failed to update element of is_df_on_bond: %s", __func__, strerror(-err));

	/* First add all new VTEP ids to vtep_bond_set */
	uint8_t dummy_val = 0;
	uint32_t vtep_ids[ES_VTEP_MAX_CNT];
	struct vtep_ifindex_pair vip;
	struct vtep_ifindex_pair cur_vip;
	struct vtep_ifindex_pair *cur_pvip = NULL;
	uint32_t i;
	int id;

	vip.ifindex = ifindex;
	for (i = 0; i < cnt; i++) {
		vtep_ids[i] = 0;

		id = get_or_create_vtep_id_by_ip(&sph_filters[i]);

		if (id < 0) {
			switch ((enum ret_value_get_or_create_vtep_id_by_ip) id) {
			case ERR_UNSUPPORTED_IP:
				if (IS_ZEBRA_DEBUG_EVPN_MH_SPH)
					zlog_debug("%s: ignoring %pIA - not IPv4", __func__, &sph_filters[i]);
				continue;
			case ERR_NO_FREE_IDS:
				zlog_warn("%s: Split Horizon Filter: max number of ids reached: %d, traffic from VTEP %pIA won't be filtered", __func__, MAX_VTEP_CNT, &sph_filters[i]);
				continue;
			case ERR_FAIL_UPDATE:
			/* For ERR_FAIL_UPDATE message already issued in get_or_create_vtep_id_by_ip */
			case ERR_NO_SKEL:
			/* Shouldn't be possible here */
			default:
				continue;
			}
		}

		vip.vtep_id = (uint32_t) id;
		vtep_ids[i] = vip.vtep_id;

		frr_with_privs(&zserv_privs) {
			err = bpf_map__update_elem(
					sph_skel->maps.vtep_bond_set,
					&vip,
					sizeof(struct vtep_ifindex_pair),
					&dummy_val,
					sizeof(uint8_t),
					BPF_NOEXIST
					);
		}
		/* We are ok with pair already existing in set */
		if (err && err != -EEXIST) {
			zlog_warn("%s: Split Horizon Filter: failed to insert value into vtep_bond_set: %s", __func__, strerror(-err));
			/* Failed to insert just created VTEP id, clean it */
			if (!vtep_id_usage_cnt[id])
				remove_vtep_id(id);
		}
		if (!err)
			vtep_id_usage_cnt[id]++;
	}

	/* Now clear all (ifindex, vtep_id) pairs that are stale */
	while (true) {
		frr_with_privs(&zserv_privs) {
			err = bpf_map__get_next_key(
					sph_skel->maps.vtep_bond_set,
					cur_pvip,
					&vip,
					sizeof(struct vtep_ifindex_pair)
					);
		}
		if (cur_pvip && cur_pvip->ifindex == ifindex) {
			for (i = 0; i < cnt; i++)
				if (cur_pvip->vtep_id == vtep_ids[i])
					break;

			/* vtep_id not up-to-date, delete pair */
			if (i == cnt) {
				frr_with_privs(&zserv_privs) {
					err2 = bpf_map__delete_elem(
						sph_skel->maps.vtep_bond_set,
						cur_pvip,
						sizeof(struct vtep_ifindex_pair),
						0
						);
				}
				if (err2) {
					zlog_warn("%s: Split Horizon Filter: failed to delete element from vtep_bond_set: %s", __func__, strerror(-err2));
				} else {
					vtep_id_usage_cnt[cur_pvip->vtep_id]--;
					if (!vtep_id_usage_cnt[cur_pvip->vtep_id])
						remove_vtep_id(cur_pvip->vtep_id);
				}
			}
		}
		if (err == -ENOENT)
			break;
		if (err) {
			zlog_warn("%s: Split Horizon Filter: failed to get next key in vtep_bond_set: %s", __func__, strerror(-err));
			break;
		}
		cur_pvip = &cur_vip;
		cur_vip = vip;
	}

#endif /* HAVE_SPLIT_HORIZON_FILTER */

	return FRR_NETLINK_SUCCESS;
}

enum netlink_msg_status
sph_process_uplink_add_msg(struct nl_batch *bth,
			   struct zebra_dplane_ctx *ctx)
{
#ifdef HAVE_SPLIT_HORIZON_FILTER
	ifindex_t ifindex = dplane_ctx_get_ifindex(ctx);
	int idx;
	int err;

	if (!ifindex)
		return FRR_NETLINK_SUCCESS;

	idx = get_uplink_idx(ifindex);
	if (idx != -1)
		return FRR_NETLINK_SUCCESS;

	/* find empty slot */
	idx = get_uplink_idx(0);
	if (idx == -1) {
		zlog_warn("%s: Split Horizon Filter: uplink number limit reached, maximum: %d, no filter will be installed for %s",
				__func__, MAX_UPLINK_CNT, dplane_ctx_get_ifname(ctx));
		return FRR_NETLINK_ERROR;
	}

	if (!sph_skel)
		if (sph_skel_init())
			return FRR_NETLINK_ERROR;

	frr_with_privs(&zserv_privs) {
		sph_uplink_links[idx] = bpf_program__attach_tcx(sph_skel->progs.split_horizon_filter_uplink,
							ifindex, NULL);
		err = -errno;
	}
	if (!sph_uplink_links[idx]) {
		zlog_warn("%s: Split Horizon Filter: failed to attach eBPF program to %s: %s",
			__func__, dplane_ctx_get_ifname(ctx), strerror(-err));
		sph_check_cleanup();
		return FRR_NETLINK_ERROR;
	}
	sph_uplink_ifindexes[idx] = ifindex;
	sph_links_cnt++;

	if (IS_ZEBRA_DEBUG_EVPN_MH_SPH)
		zlog_debug("%s: Attached uplink filter to %s", __func__, dplane_ctx_get_ifname(ctx));
#endif /* HAVE_SPLIT_HORIZON_FILTER */

	return FRR_NETLINK_SUCCESS;
}

enum netlink_msg_status
sph_process_uplink_delete_msg(struct nl_batch *bth,
			     struct zebra_dplane_ctx *ctx)
{
#ifdef HAVE_SPLIT_HORIZON_FILTER
	ifindex_t ifindex = dplane_ctx_get_ifindex(ctx);

	if (!ifindex)
		return FRR_NETLINK_SUCCESS;

	int idx = get_uplink_idx(ifindex);

	if (idx == -1)
		return FRR_NETLINK_SUCCESS;

	/* Destroy TCX uplink link */
	frr_with_privs(&zserv_privs) {
		bpf_link__destroy(sph_uplink_links[idx]);
	}
	sph_uplink_links[idx] = NULL;
	sph_uplink_ifindexes[idx] = 0;
	sph_links_cnt--;

	if (IS_ZEBRA_DEBUG_EVPN_MH_SPH)
		zlog_debug("%s: Detached uplink filter from %s", __func__, dplane_ctx_get_ifname(ctx));

	sph_check_cleanup();
#endif /* HAVE_SPLIT_HORIZON_FILTER */

	return FRR_NETLINK_SUCCESS;
}

enum netlink_msg_status
sph_process_es_delete_msg(struct nl_batch *bth,
			 struct zebra_dplane_ctx *ctx)
{
#ifdef HAVE_SPLIT_HORIZON_FILTER
	ifindex_t ifindex = dplane_ctx_get_ifindex(ctx);

	if (!ifindex)
		return FRR_NETLINK_SUCCESS;

	int idx = get_bond_idx(ifindex);
	struct vtep_ifindex_pair vip;
	struct vtep_ifindex_pair cur_vip;
	struct vtep_ifindex_pair *cur_pvip = NULL;
	int err;
	int err2;

	if (idx == -1)
		return FRR_NETLINK_SUCCESS;

	/* clear vtep_bond_set from ifindex */
	while (true) {
		frr_with_privs(&zserv_privs) {
			err = bpf_map__get_next_key(
					sph_skel->maps.vtep_bond_set,
					cur_pvip,
					&vip,
					sizeof(struct vtep_ifindex_pair)
					);
		}
		if (cur_pvip && cur_pvip->ifindex == ifindex) {
			frr_with_privs(&zserv_privs) {
				err2 = bpf_map__delete_elem(
					sph_skel->maps.vtep_bond_set,
					cur_pvip,
					sizeof(struct vtep_ifindex_pair),
					0
					);
			}
			if (err2) {
				zlog_warn("%s: Split Horizon Filter: failed to delete element from vtep_bond_set: %s", __func__, strerror(-err2));
			} else {
				vtep_id_usage_cnt[cur_pvip->vtep_id]--;
				if (!vtep_id_usage_cnt[cur_pvip->vtep_id])
					remove_vtep_id(cur_pvip->vtep_id);
			}
		}
		if (err == -ENOENT)
			break;
		if (err) {
			zlog_warn("%s: Split Horizon Filter: failed to get next key in vtep_bond_set: %s", __func__, strerror(-err));
			break;
		}
		cur_pvip = &cur_vip;
		cur_vip = vip;
	}

	/* Delete from is_df_on_bond */
	frr_with_privs(&zserv_privs) {
		err = bpf_map__delete_elem(
			sph_skel->maps.is_df_on_bond,
			&ifindex,
			sizeof(ifindex),
			0
			);
	}

	if (err)
		zlog_warn("%s: Split Horizon Filter: failed to delete element from is_df_on_bond: %s", __func__, strerror(-err));

	/* Destroy TCX bond link */
	frr_with_privs(&zserv_privs) {
		bpf_link__destroy(sph_bond_links[idx]);
	}
	sph_bond_links[idx] = NULL;
	sph_bond_ifindexes[idx] = 0;
	sph_links_cnt--;

	if (IS_ZEBRA_DEBUG_EVPN_MH_SPH)
		zlog_debug("%s: Detached bond filter from %s", __func__, dplane_ctx_get_ifname(ctx));

	sph_check_cleanup();
#endif /* HAVE_SPLIT_HORIZON_FILTER */

	return FRR_NETLINK_SUCCESS;
}

#endif /* HAVE_NETLINK */
