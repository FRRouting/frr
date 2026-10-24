// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Split Horizon Filter implementation
 * Copyright (c) 2026 VyOS Inc
 * Kyrylo Yatsenko
 */

#include <stddef.h>
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/ip.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

#include "zebra_split_horizon_filter.bpf.h"

#ifndef TCX_NEXT
#define TCX_NEXT -1
#endif

#ifndef TCX_DROP
#define TCX_DROP 2
#endif

/* #define BPF_DEBUG */

char LICENSE[] SEC("license") = "GPL";

__u32 fwmark_from_uplink_mask = FWMARK_DEFAULT_UPLINK_BIT_MASK;
__u32 fwmark_vtep_id_mask_shifted = FWMARK_DEFAULT_VTEP_ID_MASK_SHIFTED;
__u32 fwmark_vtep_id_shift = FWMARK_DEFAULT_VTEP_ID_SHIFT;

static inline __u8 fwmark_is_from_uplink(__u32 fwmark)
{
	return (fwmark & fwmark_from_uplink_mask) ? 1 : 0;
}
static inline __u32 fwmark_get_vtep_id(__u32 fwmark)
{
	return (fwmark & fwmark_vtep_id_mask_shifted) >> fwmark_vtep_id_shift;
}
static inline void fwmark_set_from_uplink(__u32 *fwmark)
{
	*fwmark |= fwmark_from_uplink_mask;
}
static inline void fwmark_set_vtep_id(__u32 *fwmark, __u32 vtep_id)
{
	*fwmark =
		(*fwmark & ~fwmark_vtep_id_mask_shifted)
		| ((vtep_id << fwmark_vtep_id_shift) & fwmark_vtep_id_mask_shifted);
}

/**
 * Maps VTEP IPv4 addresses to VTEP ids
 */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, __be32);
	__type(value, __u32);
	__uint(max_entries, MAX_VTEP_CNT);
} ip_to_vtep_id SEC(".maps");

/**
 * Map (VTEP id, ifindex) -> u8
 * We need set here, but it is not supported by BPF, so waste a byte per entry.
 * If (VTEP, ifindex) pair is in this set, the VTEP is peer in ES of bond with ifindex
 */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, struct vtep_ifindex_pair);
	__type(value, __u8);
	__uint(max_entries, MAX_VTEP_BOND_CONNECTIONS_CNT);
} vtep_bond_set SEC(".maps");

/**
 * Map ifindex -> u8
 * For each bond 1 if we are DF on it and 0 if not
 */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, __u32);
	__type(value, __u8);
	__uint(max_entries, MAX_ES_CNT);
} is_df_on_bond SEC(".maps");

/**
 * Split Horizon Filter, should be attached to each uplink interface
 *
 * 1. Check if it is IPv4 (IPv6 TODO)
 * 2. (TODO) If so, check that transport protocol is UDP with VXLAN data
 * 3. Then set mark with uplink bit and VTEP id (or 0 if unknown)
 */
SEC("tcx/ingress")
int split_horizon_filter_uplink(struct __sk_buff *skb)
{
	__be32 ipv4_saddr;
	__u32 *pval;

	switch (skb->protocol) {
	case bpf_htons(ETH_P_IP):
		bpf_skb_load_bytes_relative(
			skb,
			offsetof(struct iphdr, saddr),
			&ipv4_saddr,
			sizeof(__be32),
			BPF_HDR_START_NET);
		pval = bpf_map_lookup_elem(&ip_to_vtep_id, &ipv4_saddr);
		fwmark_set_from_uplink(&skb->mark);
		fwmark_set_vtep_id(&skb->mark, pval ? *pval : 0);
		break;
	}
	return TCX_NEXT;
}

/**
 * Split Horizon Filter, should be attached to bond interface
 *
 * If we are non-DF: filter any BUM traffic except originated from local hosts
 * If we are DF: filter any BUM traffic from peer VTEPs on this ES
 */
SEC("tcx/egress")
int split_horizon_filter_bond(struct __sk_buff *skb)
{
	/* We are interested in BUM only */
	/* TODO Unknown Unicast case */
	if (skb->pkt_type != PACKET_BROADCAST && skb->pkt_type != PACKET_MULTICAST) {
#ifdef BPF_DEBUG
		bpf_printk("%s: ifindex: %u, not BUM, passing", __func__, skb->ifindex);
#endif
		return TCX_NEXT;
	}

	/* Packets from non-uplink shouldn't be filtered (local bias) */
	if (!fwmark_is_from_uplink(skb->mark)) {
#ifdef BPF_DEBUG
		bpf_printk("%s: ifindex: %u, not from uplink, passing", __func__, skb->ifindex);
#endif
		return TCX_NEXT;
	}

	__u8 *pis_df;
	/* When using skb->ifindex directly eBPF verifier fails */
	__u32 key_ifindex = skb->ifindex;

	pis_df = bpf_map_lookup_elem(&is_df_on_bond, &key_ifindex);
	if (!pis_df) {
#ifdef BPF_DEBUG
		bpf_printk("%s: WARNING Unknown DF!!! We shouldn't be here, ifindex: %u", __func__, skb->ifindex);
#endif
		return TCX_NEXT;
	}

	__u8 is_df = *pis_df;

	if (!is_df) {
#ifdef BPF_DEBUG
		bpf_printk("%s: !DF, ifindex: %u, from_uplink: %d, vtep_id: %d, pkt_type: %d, verdict: TCX_DROP", __func__, skb->ifindex, fwmark_is_from_uplink(skb->mark), fwmark_get_vtep_id(skb->mark), skb->pkt_type);
#endif
		/* We need to pass packets from non-uplink (local bias), this
		 * is done in check of fwmark_is_from_uplink at the beginning
		 * of function
		 */
		return TCX_DROP;
	}

	struct vtep_ifindex_pair vip = {.ifindex = skb->ifindex, .vtep_id = fwmark_get_vtep_id(skb->mark)};
	__u8 *p = bpf_map_lookup_elem(&vtep_bond_set, &vip);

#ifdef BPF_DEBUG
	bpf_printk("%s: DF, ifindex: %u, from_uplink: %d, vtep_id: %d, pkt_type: %d, verdict: %s\n", __func__, skb->ifindex, fwmark_is_from_uplink(skb->mark), fwmark_get_vtep_id(skb->mark), skb->pkt_type,
			p ? "TCX_DROP" : "TCX_NEXT");
#endif
	return p ? TCX_DROP : TCX_NEXT;
}
