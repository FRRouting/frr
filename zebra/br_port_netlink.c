// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Split Horizon Filter implementation
 * Copyright (c) 2026 VyOS Inc
 * Kyrylo Yatsenko
 */

#include <zebra.h>

#include <lib/if.h>

#include "zebra/br_port_netlink.h"
#include "zebra/zebra_tc.h"
#include "zebra/interface.h"
#include "zebra/zebra_evpn_mh.h"

extern struct zebra_privs_t zserv_privs;

#ifdef HAVE_SPLIT_HORIZON_FILTER
static struct interface *if_lookup_by_index_all_vrf(ifindex_t ifindex);
static struct interface *if_lookup_by_ifindex(ifindex_t ifindex,
					      vrf_id_t vrf_id);

/* Used only internally to check within VRF only */
static struct interface *if_lookup_by_ifindex(ifindex_t ifindex,
					      vrf_id_t vrf_id)
{
	struct vrf *vrf;
	struct interface if_tmp;

	vrf = vrf_lookup_by_id(vrf_id);
	if (!vrf)
		return NULL;

	if_tmp.ifindex = ifindex;
	return RB_FIND(if_index_head, &vrf->ifaces_by_index, &if_tmp);
}
static struct interface *if_lookup_by_index_all_vrf(ifindex_t ifindex)
{
	struct vrf *vrf;
	struct interface *ifp;

	if (ifindex == IFINDEX_INTERNAL)
		return NULL;

	RB_FOREACH (vrf, vrf_id_head, &vrfs_by_id) {
		ifp = if_lookup_by_ifindex(ifindex, vrf->vrf_id);
		if (ifp)
			return ifp;
	}

	return NULL;
}
#endif // HAVE_SPLIT_HORIZON_FILTER

struct vtep_ifindex_pair  {
    uint32_t vtep_id;
    int32_t ifindex;
};

extern enum netlink_msg_status
netlink_put_br_port_msg(struct nl_batch *bth,
			      struct zebra_dplane_ctx *ctx)
{
#ifdef HAVE_SPLIT_HORIZON_FILTER
	ifindex_t ifindex = dplane_ctx_get_ifindex(ctx);

	zlog_info("%s: HEDROK ifindex: %d, ifname: %s", __func__, dplane_ctx_get_ifindex(ctx), dplane_ctx_get_ifname(ctx));
	zlog_info("%s: HEDROK count: %d", __func__, dplane_ctx_get_br_port_sph_filter_cnt(ctx));

	uint8_t is_df = (dplane_ctx_get_br_port_flags(ctx) & DPLANE_BR_PORT_NON_DF) ? 0 : 1;

	const struct ipaddr *sph_filters = dplane_ctx_get_br_port_sph_filters(ctx);
	for (uint32_t i = 0; i < dplane_ctx_get_br_port_sph_filter_cnt(ctx); i++) {
		zlog_info("%s: HEDROK IP: %pIA", __func__, &sph_filters[i]);
	}

	struct interface *ifp = if_lookup_by_index_all_vrf(dplane_ctx_get_ifindex(ctx));
	if (!ifp) {
		zlog_info("%s: HEDROK couldn't find interface...", __func__);
		return FRR_NETLINK_SUCCESS;
	}
	struct zebra_if *zif = ifp->info;
	struct zebra_evpn_es *esp = zif->es_info.es;

	if (!esp) {
		zlog_info("%s: HEDROK zif->es_info.es == NULL...", __func__);
		return FRR_NETLINK_SUCCESS;
	};
	zlog_info("%s: HEDROK ESI: %s", __func__, esp->esi_str);

	if (!zmh_info->sph_skel) {
		zebra_evpn_mh_sph_skel_init();
	}

	struct zebra_split_horizon_filter_bpf *skel = zmh_info->sph_skel;
	int err;
	int err2;

	if (!esp->sph_bond_link) {
		frr_with_privs(&zserv_privs) {
			esp->sph_bond_link = bpf_program__attach_tcx(skel->progs.split_horizon_filter_bond,
								ifindex, NULL);
		}
		err = libbpf_get_error(esp->sph_bond_link);
		if (err) {
			zlog_warn("%s: failed to attach split horizon filter: %s to bond interface %s",
				__func__, strerror(-err), ifp->name);
			esp->sph_bond_link = NULL;
			return FRR_NETLINK_ERROR;
		}
		zlog_info("%s: HEDROK Attached bond filter to %s", __func__, ifp->name);
	}
	if (!esp->sph_bond_link_ingress) {
		frr_with_privs(&zserv_privs) {
			esp->sph_bond_link_ingress = bpf_program__attach_tcx(skel->progs.split_horizon_filter_bond_ingress,
								ifindex, NULL);
		}
		err = libbpf_get_error(esp->sph_bond_link_ingress);
		if (err) {
			zlog_warn("%s: failed to attach split horizon filter: %s to bond interface %s, ingress",
				__func__, strerror(-err), ifp->name);
			esp->sph_bond_link = NULL;
			return FRR_NETLINK_ERROR;
		}
		zlog_info("%s: HEDROK Attached ingress bond filter to %s", __func__, ifp->name);
	}

	/* Update `is_df_on_bond`*/
	frr_with_privs(&zserv_privs) {
		err = bpf_map__update_elem(
				skel->maps.is_df_on_bond,
				&ifindex,
				sizeof(ifindex),
				&is_df,
				sizeof(uint8_t),
				BPF_ANY
				);
		zlog_info("%s: HEDROK setting is_df to %d for interface %u", __func__, is_df, ifindex);
	}
	if (err){
		zlog_warn("%s: HEDROK err inserting value (is_df_on_bond): %s", __func__, strerror(errno));
	}

	struct vtep_ifindex_pair vip;
	struct vtep_ifindex_pair cur_vip;
	struct vtep_ifindex_pair *cur_pvip = NULL;
	while (true) {
		frr_with_privs(&zserv_privs) {
			err = bpf_map__get_next_key(
					skel->maps.vtep_bond_set,
					cur_pvip,
					&vip,
					sizeof(struct vtep_ifindex_pair)
					);
		}
		if (cur_pvip && cur_pvip->ifindex == ifindex) {
			frr_with_privs(&zserv_privs) {
				err2 = bpf_map__delete_elem(
					skel->maps.vtep_bond_set,
					cur_pvip,
					sizeof(struct vtep_ifindex_pair),
					0
					);
			}
			if (err2) {
				zlog_warn("%s: HEDROK err couldn't delete element from vtep_bond_set: %s", __func__, strerror(errno));
			}
		}
		if (err == -ENOENT) {
			break;
		}
		if (err) {
			zlog_warn("%s: HEDROK err getting next key in vtep_bond_set: %s", __func__, strerror(errno));
			break;
		}
		cur_pvip = &cur_vip;
		cur_vip = vip;
	}

	/* For now: fill `ip_to_vtep_id` with all IPs, VTEP id = IP */
	/* Maps VTEP IPv4 addresses to VTEP ids*/
	/* TODO remove deleted VTEPs */
	/* TODO Support IPv6 (add some real ids) */
	vip.ifindex = ifindex;
	uint8_t dummy_val = 0;
	for (uint32_t i = 0; i < dplane_ctx_get_br_port_sph_filter_cnt(ctx); i++) {
		zlog_info("%s: HEDROK ip_to_vtep_id, adding: 0x%x", __func__, sph_filters[i].ip._v4_addr.s_addr);
		vip.vtep_id = sph_filters[i].ip._v4_addr.s_addr;
		frr_with_privs(&zserv_privs) {
			err = bpf_map__update_elem(
					skel->maps.ip_to_vtep_id,
					&sph_filters[i].ip._v4_addr.s_addr,
					sizeof(__be32),
					&vip.vtep_id,
					sizeof(uint32_t),
					BPF_ANY
					);
		}
		if (err){
			zlog_warn("%s: HEDROK err inserting value into ip_to_vtep_id: %s", __func__, strerror(errno));
		}

		frr_with_privs(&zserv_privs) {
			err = bpf_map__update_elem(
					skel->maps.vtep_bond_set,
					&vip,
					sizeof(struct vtep_ifindex_pair),
					&dummy_val,
					sizeof(uint8_t),
					BPF_ANY
					);
		}
		if (err){
			zlog_warn("%s: HEDROK err inserting value into vtep_bond_set: %s", __func__, strerror(errno));
		}
	}

#endif // HAVE_SPLIT_HORIZON_FILTER

	return FRR_NETLINK_SUCCESS;
}
